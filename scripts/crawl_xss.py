#!/usr/bin/env python3
"""Incremental public-only XSS crawler for Bugcrowd, Intigriti, and YesWeHack.

Reads candidate URLs from stdin (newline-separated), dedupes against state/xss_state.json,
fetches public pages, extracts best-effort details, writes one JSON per new item under
reports/<platform>/ and one 1200x675 PNG card under cards/<platform>/, then prints a JSON
summary to stdout.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
import textwrap
from dataclasses import dataclass
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import requests

ROOT = Path(__file__).resolve().parents[1]
STATE_DIR = ROOT / "state"
STATE_PATH = STATE_DIR / "xss_state.json"
REPORTS_DIR = ROOT / "reports"
CARDS_DIR = ROOT / "cards"
USER_AGENT = "Mozilla/5.0 (compatible; bug-bounty-reports-xss-bot/1.0; +https://github.com/0x7anshan/bug-bounty-reports)"
XSS_TERMS = (
    "xss",
    "cross-site scripting",
    "cross site scripting",
    "cwe-79",
    "dom-based xss",
    "stored xss",
    "reflected xss",
    "blind xss",
)


class TextExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.parts: list[str] = []
        self.skip = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in {"script", "style", "noscript"}:
            self.skip += 1
        if tag in {"p", "br", "li", "h1", "h2", "h3", "h4", "h5", "h6", "pre", "code", "div", "section", "article"}:
            self.parts.append("\n")

    def handle_endtag(self, tag: str) -> None:
        if tag in {"script", "style", "noscript"}:
            self.skip = max(0, self.skip - 1)
        if tag in {"p", "li", "pre", "div", "section", "article"}:
            self.parts.append("\n")

    def handle_data(self, data: str) -> None:
        if not self.skip and data:
            self.parts.append(data)

    def get_text(self) -> str:
        s = "".join(self.parts)
        s = s.replace("\r", "\n")
        s = re.sub(r"[\t\f\v ]+", " ", s)
        s = re.sub(r"\n{3,}", "\n\n", s)
        return s.strip()


@dataclass
class Report:
    title: str
    platform: str
    report_url: str
    submitted_at: str | None
    target_site: str | None
    report_body: str
    payloads: list[str]
    affected_urls: list[str]
    http_status: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": "bbreport.xss.v1",
            "title": self.title,
            "vuln_type": "xss",
            "vuln_type_raw": None,
            "submitted_at": self.submitted_at,
            "platform": self.platform,
            "report_url": self.report_url,
            "target_site": self.target_site,
            "report_body": self.report_body,
            "discovered_at": now_iso(),
            "source": {
                "fetched_at": now_iso(),
                "http_status": self.http_status,
            },
            "extracted": {
                "payloads": self.payloads,
                "affected_urls": self.affected_urls,
            },
        }


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def now_stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")


def canonicalize(url: str) -> str:
    p = urlparse(url.strip())
    return p._replace(fragment="").geturl()


def slug_for(url: str) -> str:
    return hashlib.sha1(url.encode("utf-8")).hexdigest()[:10]


def platform_for(url: str) -> str | None:
    u = canonicalize(url)
    host = urlparse(u).netloc.lower()
    path = urlparse(u).path.lower()
    if "bugcrowd.com" in host and "/disclosures/" in path:
        return "bugcrowd"
    if "intigriti.com" in host:
        return "intigriti"
    if "yeswehack.com" in host and any(seg in path for seg in ("/community/", "/dojo/", "/learn-bug-bounty/")):
        return "yeswehack"
    return None


def load_state() -> dict[str, Any]:
    if STATE_PATH.exists():
        try:
            return json.loads(STATE_PATH.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {"seen": {}, "last_run": None}


def save_state(state: dict[str, Any]) -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    STATE_PATH.write_text(json.dumps(state, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def extract_jsonld(html: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for m in re.finditer(r"<script[^>]+type=['\"]application/ld\+json['\"][^>]*>(.*?)</script>", html, flags=re.I | re.S):
        raw = m.group(1).strip()
        if not raw:
            continue
        try:
            data = json.loads(raw)
        except Exception:
            continue
        objs = [data] if isinstance(data, dict) else [x for x in data if isinstance(x, dict)] if isinstance(data, list) else []
        for obj in objs:
            kind = str(obj.get("@type") or "").lower()
            if kind not in {"article", "blogposting", "newsarticle", "webpage"}:
                continue
            if not out.get("title"):
                out["title"] = str(obj.get("headline") or obj.get("name") or "").strip()
            if not out.get("body"):
                out["body"] = str(obj.get("articleBody") or obj.get("description") or "").strip()
            if not out.get("published"):
                out["published"] = str(obj.get("datePublished") or obj.get("dateCreated") or "").strip()
    return out


def extract_title(html: str, jsonld: dict[str, str]) -> str:
    if jsonld.get("title"):
        return jsonld["title"]
    for pattern in [
        r'<meta[^>]+property=["\']og:title["\'][^>]+content=["\']([^"\']+)["\']',
        r'<meta[^>]+name=["\']twitter:title["\'][^>]+content=["\']([^"\']+)["\']',
        r"<title>(.*?)</title>",
    ]:
        m = re.search(pattern, html, flags=re.I | re.S)
        if m:
            return re.sub(r"\s+", " ", m.group(1)).strip()
    return "Untitled XSS report"


def extract_body(html: str, jsonld: dict[str, str]) -> str:
    body = (jsonld.get("body") or "").strip()
    if body:
        return body
    te = TextExtractor()
    te.feed(html)
    return te.get_text()


def extract_submitted_at(html: str, jsonld: dict[str, str]) -> str | None:
    for pattern in [
        r'<meta[^>]+property=["\']article:published_time["\'][^>]+content=["\']([^"\']+)["\']',
        r'<meta[^>]+name=["\']pubdate["\'][^>]+content=["\']([^"\']+)["\']',
        r'<time[^>]+datetime=["\']([^"\']+)["\']',
    ]:
        m = re.search(pattern, html, flags=re.I)
        if m:
            return m.group(1).strip()
    published = (jsonld.get("published") or "").strip()
    return published or None


def looks_like_xss(text: str) -> bool:
    low = text.lower()
    return any(term in low for term in XSS_TERMS)


def extract_payloads(text: str, max_items: int = 12) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for line in text.splitlines():
        s = line.strip()
        if not s:
            continue
        sl = s.lower()
        if any(h in sl for h in ("<script", "</script", "onerror=", "onload=", "javascript:", "alert(", "prompt(", "confirm(")) or "payload" in sl or "poc" in sl:
            s = s[:400] + ("…" if len(s) > 400 else "")
            if s not in seen:
                seen.add(s)
                out.append(s)
        if len(out) >= max_items:
            break
    return out


def extract_urls(text: str, max_items: int = 12) -> list[str]:
    urls: list[str] = []
    for m in re.finditer(r"https?://[^\s\)\]\}\>\"']+", text):
        u = m.group(0)
        if len(u) <= 300:
            urls.append(u)
        if len(urls) >= max_items:
            break
    return list(dict.fromkeys(urls))


def choose_target_site(report_url: str, body: str, affected_urls: list[str]) -> str | None:
    bad = ("bugcrowd.com", "intigriti.com", "yeswehack.com")
    for u in affected_urls:
        host = urlparse(u).netloc.lower()
        if host and not any(b in host for b in bad):
            return host
    m = re.search(r"\b([a-z0-9.-]+\.[a-z]{2,})\b", body.lower())
    if m:
        host = m.group(1)
        if not any(b in host for b in bad):
            return host
    host = urlparse(report_url).netloc.lower()
    return None if any(b in host for b in bad) else host


def has_enough_details(body: str, payloads: list[str], affected_urls: list[str]) -> tuple[bool, list[str]]:
    reasons: list[str] = []
    if len(body.strip()) < 700:
        reasons.append("body_too_short")
    signals = 0
    if payloads:
        signals += 1
    if affected_urls:
        signals += 1
    if re.search(r"\b(step|steps|reproduce|reproduction|proof of concept|poc|payload|vector|sink|source|parameter|exploit)\b", body, flags=re.I):
        signals += 1
    if signals < 2:
        reasons.append("insufficient_technical_detail")
    return not reasons, reasons


def fetch_report(url: str, session: requests.Session) -> tuple[Report | None, str | None]:
    r = session.get(url, timeout=40)
    if r.status_code != 200:
        return None, f"http_{r.status_code}"
    html = r.text
    jsonld = extract_jsonld(html)
    title = extract_title(html, jsonld)
    body = extract_body(html, jsonld)
    submitted_at = extract_submitted_at(html, jsonld)
    if not looks_like_xss(title + "\n" + body):
        return None, "not_xss"
    payloads = extract_payloads(body)
    affected_urls = extract_urls(body)
    ok, reasons = has_enough_details(body, payloads, affected_urls)
    if not ok:
        return None, "+".join(reasons)
    report = Report(
        title=title,
        platform=platform_for(url) or "unknown",
        report_url=canonicalize(url),
        submitted_at=submitted_at,
        target_site=choose_target_site(url, body, affected_urls),
        report_body=body,
        payloads=payloads,
        affected_urls=affected_urls,
        http_status=r.status_code,
    )
    return report, None


def make_card(report: Report, output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    title = textwrap.fill(report.title.strip(), width=38)
    body_excerpt = re.sub(r"\s+", " ", report.report_body).strip()
    body_excerpt = textwrap.shorten(body_excerpt, width=300, placeholder="…")
    body_excerpt = textwrap.fill(body_excerpt, width=52)
    meta = [
        f"Platform: {report.platform}",
        f"Target: {report.target_site or 'unknown'}",
        f"Published: {report.submitted_at or 'unknown'}",
        f"URL: {report.report_url}",
    ]
    meta_text = "\n".join(textwrap.fill(m, width=64, subsequent_indent="    ") for m in meta)
    blurb = f"{body_excerpt}\n\n{meta_text}"
    cmd = [
        "convert",
        "-size", "1200x675",
        "xc:#0f172a",
        "-fill", "#38bdf8",
        "-font", "DejaVu-Sans-Bold",
        "-pointsize", "30",
        "-gravity", "northwest",
        "-annotate", "+60+55", "NEW XSS DISCLOSURE",
        "-fill", "#f8fafc",
        "-font", "DejaVu-Sans-Bold",
        "-pointsize", "44",
        "-annotate", "+60+110", title,
        "-fill", "#cbd5e1",
        "-font", "DejaVu-Sans",
        "-pointsize", "24",
        "-annotate", "+60+270", blurb,
        str(output_path),
    ]
    subprocess.run(cmd, check=True)


def write_artifacts(report: Report) -> tuple[Path, Path]:
    stamp = now_stamp()
    slug = slug_for(report.report_url)
    base = f"{stamp}_xss_{report.platform}_{slug}"
    json_path = REPORTS_DIR / report.platform / f"{base}.json"
    png_path = CARDS_DIR / report.platform / f"{base}.png"
    json_path.parent.mkdir(parents=True, exist_ok=True)
    png_path.parent.mkdir(parents=True, exist_ok=True)
    json_path.write_text(json.dumps(report.to_dict(), ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    make_card(report, png_path)
    return json_path, png_path


def main() -> None:
    state = load_state()
    seen: dict[str, Any] = state.setdefault("seen", {})

    candidates: list[str] = []
    for raw in sys.stdin.read().splitlines():
        url = raw.strip()
        if not url:
            continue
        canonical = canonicalize(url)
        platform = platform_for(canonical)
        if not platform:
            continue
        candidates.append(canonical)
    candidates = list(dict.fromkeys(candidates))

    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT})

    new_items: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []

    for url in candidates:
        if url in seen:
            skipped.append({"url": url, "reason": "already_seen"})
            continue
        try:
            report, reason = fetch_report(url, session)
        except Exception as e:
            report, reason = None, f"fetch_error:{type(e).__name__}"
        if not report:
            seen[url] = {"seen_at": now_iso(), "ingested": False, "reason": reason}
            skipped.append({"url": url, "reason": reason})
            continue
        try:
            json_path, png_path = write_artifacts(report)
        except Exception as e:
            seen[url] = {"seen_at": now_iso(), "ingested": False, "reason": f"write_error:{type(e).__name__}"}
            skipped.append({"url": url, "reason": f"write_error:{type(e).__name__}"})
            continue
        seen[url] = {
            "seen_at": now_iso(),
            "xss": True,
            "json": str(json_path.relative_to(ROOT)),
            "card": str(png_path.relative_to(ROOT)),
        }
        new_items.append(
            {
                "platform": report.platform,
                "title": report.title,
                "url": report.report_url,
                "json": str(json_path),
                "card": str(png_path),
            }
        )

    state["last_run"] = now_iso()
    save_state(state)
    summary = {
        "discovered_urls": len(candidates),
        "new_xss": len(new_items),
        "items": new_items,
        "skipped": skipped,
    }
    print(json.dumps(summary, ensure_ascii=False))


if __name__ == "__main__":
    main()
