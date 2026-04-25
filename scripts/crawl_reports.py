#!/usr/bin/env python3
"""Public-only bug bounty report crawler.

Goals (per user requirements):
- Multi-vuln architecture (but you can run only XSS for now)
- Store each report as JSON with:
  title, vuln_type, submitted_time, platform, report_url, target_site, report_body
- Only ingest reports with *real vulnerability detail* (otherwise skip)
- Generate a human-readable MD summary per JSON (AI if configured; rule fallback)

Guardrails:
- Public pages/endpoints only; respect robots/rate limiting.
- No login.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlparse

import requests


ROOT = Path(__file__).resolve().parents[1]
# Storage layout (per user): classify by vuln_type, not by platform.
REPORTS_DIR = ROOT / "reports"
EXPLANATIONS_DIR = ROOT / "explanations"  # Markdown explanations generated from JSON
STATE_DIR = ROOT / "state"
STATE_PATH = STATE_DIR / "crawler_state.json"  # kept local via .gitignore (should be ignored)

DEFAULT_UA = "Mozilla/5.0 (compatible; bug-bounty-reports-bot/2.0; +https://github.com/0x7anshan/bug-bounty-reports)"


# ------------------------
# Utilities
# ------------------------

def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def sha1(s: str) -> str:
    return hashlib.sha1(s.encode("utf-8")).hexdigest()


def canonical_url(url: str) -> str:
    # Drop fragment; keep query (some reports use it).
    p = urlparse(url)
    return p._replace(fragment="").geturl()


def safe_slug_from_url(url: str) -> str:
    return sha1(url)[:10]


def is_intigriti_bug_bytes(url: str, title: str) -> bool:
    """Intigriti 'Bug Bytes' is newsletter-style content (high noise for this repo).

    User requirement: do not ingest Bug Bytes even if it mentions XSS.
    """

    u = (url or "").lower()
    t = (title or "").lower()

    if "bug bytes" in t:
        return True

    # Common slug pattern on Intigriti.
    if "/bug-bytes" in u or "bug-bytes" in u:
        return True

    return False


class TextExtractor(HTMLParser):
    """Very conservative HTML -> text extractor."""

    def __init__(self):
        super().__init__()
        self._chunks: list[str] = []
        self._skip = 0

    def handle_starttag(self, tag, attrs):
        if tag in {"script", "style", "noscript"}:
            self._skip += 1
        if tag in {"p", "br", "li", "h1", "h2", "h3", "h4", "h5", "h6", "pre", "code"}:
            self._chunks.append("\n")

    def handle_endtag(self, tag):
        if tag in {"script", "style", "noscript"}:
            self._skip = max(0, self._skip - 1)
        if tag in {"p", "li", "pre"}:
            self._chunks.append("\n")

    def handle_data(self, data):
        if self._skip:
            return
        if data:
            self._chunks.append(data)

    def get_text(self) -> str:
        s = "".join(self._chunks)
        s = s.replace("\r", "\n")
        s = re.sub(r"[\t\f\v ]+", " ", s)
        s = re.sub(r"\n{3,}", "\n\n", s)
        return s.strip()


def http_get(url: str, session: requests.Session, *, allow_redirects: bool = True) -> requests.Response:
    r = session.get(url, timeout=40, allow_redirects=allow_redirects)
    return r


def parse_xml_locs(xml_text: str) -> list[str]:
    # Works for both urlset and sitemapindex.
    locs: list[str] = []
    try:
        root = ET.fromstring(xml_text)
    except Exception:
        return locs

    # Namespaces are annoying; match by suffix.
    for el in root.iter():
        if el.tag.endswith("loc") and el.text:
            locs.append(el.text.strip())
    return locs


def extract_jsonld_best_effort(html: str) -> dict[str, str]:
    """Extract structured content from JSON-LD when sites are SPA-ish or noisy.

    Returns keys: title, body, published_time (any may be missing).
    """

    out: dict[str, str] = {}
    for m in re.finditer(
        r"<script[^>]+type=['\"]application/ld\+json['\"][^>]*>(.*?)</script>",
        html,
        flags=re.I | re.S,
    ):
        raw = m.group(1).strip()
        if not raw:
            continue
        # Some sites embed multiple JSON objects or invalid JSON with trailing commas.
        # We keep it strict: if it doesn't parse, skip.
        try:
            data = json.loads(raw)
        except Exception:
            continue

        candidates: list[dict[str, Any]] = []
        if isinstance(data, dict):
            candidates = [data]
        elif isinstance(data, list):
            candidates = [x for x in data if isinstance(x, dict)]

        for obj in candidates:
            t = str(obj.get("@type") or "").lower()
            if t not in {"article", "blogposting", "newsarticle"}:
                continue

            title = (obj.get("headline") or obj.get("name") or "")
            body = (obj.get("articleBody") or obj.get("description") or "")
            published = obj.get("datePublished") or obj.get("dateCreated")

            if isinstance(title, str) and title and "title" not in out:
                out["title"] = title.strip()
            if isinstance(body, str) and body and "body" not in out:
                out["body"] = body.strip()
            if isinstance(published, str) and published and "published_time" not in out:
                out["published_time"] = published.strip()

        if out.get("body"):
            break

    return out


# ------------------------
# Normalized schema
# ------------------------

@dataclass
class NormalizedReport:
    title: str
    vuln_type: str
    vuln_type_raw: str | None

    # User requirement: include the platform-native submission/publish timestamp.
    # (Best-effort; may be null if platform doesn't expose it.)
    platform_submitted_at: str | None

    # Kept for backward compatibility / general use. For now we set it equal to platform_submitted_at.
    submitted_at: str | None

    platform: str
    report_url: str
    target_site: str | None
    report_body: str

    # extra (helpful but not strictly required)
    discovered_at: str
    fetched_at: str
    http_status: int
    payloads: list[str]
    affected_urls: list[str]

    def to_json(self) -> dict[str, Any]:
        return {
            "schema": "bbreport.v1",
            "title": self.title,
            "vuln_type": self.vuln_type,
            "vuln_type_raw": self.vuln_type_raw,
            "platform_submitted_at": self.platform_submitted_at,
            "submitted_at": self.submitted_at,
            "platform": self.platform,
            "report_url": self.report_url,
            "target_site": self.target_site,
            "report_body": self.report_body,
            "discovered_at": self.discovered_at,
            "source": {
                "fetched_at": self.fetched_at,
                "http_status": self.http_status,
            },
            "extracted": {
                "payloads": self.payloads,
                "affected_urls": self.affected_urls,
            },
        }


# ------------------------
# Vuln type handling (multi-type ready)
# ------------------------

VULN_ALIASES = {
    "xss": ["xss", "cross-site scripting", "cross site scripting", "cwe-79", "cwe 79", "dom xss", "stored xss", "reflected xss", "blind xss"],
    # future: ssrf, sqli, idor, rce, etc.
}


def normalize_vuln_type(v: str) -> str:
    v = (v or "").strip().lower()
    v = v.replace("cross site scripting", "cross-site scripting")
    if v in VULN_ALIASES:
        return v
    # crude mapping
    if "xss" in v or "cross-site scripting" in v or "cwe-79" in v:
        return "xss"
    return v or "unknown"


def looks_like_vuln(text: str, vuln_type: str) -> bool:
    if not text:
        return False
    keys = VULN_ALIASES.get(vuln_type, [vuln_type])
    t = text.lower()
    return any(k in t for k in keys)


# ------------------------
# Extraction helpers
# ------------------------

PAYLOAD_HINTS = [
    "<script",
    "</script",
    "onerror=",
    "onload=",
    "javascript:",
    "alert(",
    "prompt(",
    "%3cscript",
]


def extract_payloads(text: str, *, max_items: int = 12) -> list[str]:
    out: list[str] = []
    seen = set()
    for line in text.split("\n"):
        l = line.strip()
        if not l:
            continue
        ll = l.lower()
        if any(h in ll for h in PAYLOAD_HINTS) or "payload" in ll or "poc" in ll or "proof of concept" in ll:
            l = l[:400] + ("…" if len(l) > 400 else "")
            if l not in seen:
                seen.add(l)
                out.append(l)
        if len(out) >= max_items:
            break
    return out


def extract_urls(text: str, *, max_items: int = 12) -> list[str]:
    out: list[str] = []
    for m in re.finditer(r"https?://[^\s\)\]\}\>\"']+", text):
        u = m.group(0)
        if len(u) > 300:
            continue
        out.append(u)
        if len(out) >= max_items:
            break
    # de-dupe preserving order
    return list(dict.fromkeys(out))


def choose_target_site(report_url: str, body: str, affected_urls: list[str]) -> str | None:
    """Best-effort affected asset host.

    Heuristics:
    - Prefer hosts from affected_urls.
    - Avoid common shorteners and platform domains.
    - Fall back to a domain mentioned in body.
    - Finally fall back to report_url host.
    """

    def _bad_host(h: str) -> bool:
        h = (h or "").lower().strip()
        if not h:
            return True
        # shorteners / trackers
        if h in {"t.co", "bit.ly", "tinyurl.com"}:
            return True
        # platform domains (not the affected asset)
        if any(p in h for p in ("hackerone.com", "bugcrowd.com", "intigriti.com", "yeswehack.com")):
            return True
        return False

    for u in affected_urls:
        try:
            h = urlparse(u).netloc
            if h and not _bad_host(h):
                return h
        except Exception:
            pass

    m = re.search(r"\b([a-z0-9.-]+\.[a-z]{2,})\b", (body or "").lower())
    if m and m.group(1) and not _bad_host(m.group(1)):
        return m.group(1)

    try:
        h = urlparse(report_url).netloc
        return None if _bad_host(h) else h
    except Exception:
        return None


def has_enough_details(body: str, payloads: list[str], affected_urls: list[str]) -> tuple[bool, list[str]]:
    reasons: list[str] = []
    if not body or len(body.strip()) < 700:
        reasons.append("body_too_short")
    # Require at least one signal of technical detail
    signals = 0
    if payloads:
        signals += 1
    if affected_urls:
        signals += 1
    if re.search(r"\b(step|steps|reproduce|reproduction|poc|payload|vector|sink|source|parameter)\b", body, flags=re.I):
        signals += 1
    if signals < 2:
        reasons.append("insufficient_technical_detail")
    return (len(reasons) == 0), reasons


# ------------------------
# Platform-specific fetch
# ------------------------

H1_REPORT_RE = re.compile(r"https?://hackerone\.com/reports/(\d+)")
BC_REPORT_RE = re.compile(r"https?://bugcrowd\.com/disclosures/([0-9a-f-]{20,})/[^\s]+", re.I)


def fetch_hackerone(report_url: str, session: requests.Session, vuln_type: str) -> NormalizedReport | None:
    m = H1_REPORT_RE.search(report_url)
    if not m:
        return None
    report_id = m.group(1)
    json_url = f"https://hackerone.com/reports/{report_id}.json"

    r = http_get(json_url, session)
    if r.status_code != 200:
        return None
    data = r.json()

    title = (data.get("title") or "").strip()
    body = (data.get("vulnerability_information") or "").strip()

    vuln_raw = None
    weakness = data.get("weakness") or {}
    if isinstance(weakness, dict):
        vuln_raw = weakness.get("name") or weakness.get("description")
        # sometimes there is cwe
        cwe = weakness.get("cwe")
        if isinstance(cwe, dict) and cwe.get("id"):
            vuln_raw = (vuln_raw or "") + f" (CWE-{cwe.get('id')})"
            vuln_raw = vuln_raw.strip() or None

    # User requirement: keep the platform-native submission time when exposed.
    # Prefer submitted_at (when present), then created_at, then disclosed_at as a last-resort fallback.
    platform_submitted_at = data.get("submitted_at") or data.get("created_at") or data.get("disclosed_at")
    platform_submitted_at = platform_submitted_at if isinstance(platform_submitted_at, str) else None

    # Back-compat/general: for now treat submitted_at == platform_submitted_at.
    submitted_at = platform_submitted_at

    # filter by vuln type
    if not looks_like_vuln((title + "\n" + (vuln_raw or "") + "\n" + body), vuln_type):
        return None

    payloads = extract_payloads(body)
    affected_urls = extract_urls(body)
    target_site = choose_target_site(report_url, body, affected_urls)

    ok, _reasons = has_enough_details(body, payloads, affected_urls)
    if not ok:
        return None

    return NormalizedReport(
        title=title,
        vuln_type=vuln_type,
        vuln_type_raw=vuln_raw,
        platform_submitted_at=platform_submitted_at,
        submitted_at=submitted_at,
        platform="hackerone",
        report_url=canonical_url(report_url),
        target_site=target_site,
        report_body=body,
        discovered_at=now_iso(),
        fetched_at=now_iso(),
        http_status=r.status_code,
        payloads=payloads,
        affected_urls=affected_urls,
    )


def fetch_html_report(platform: str, report_url: str, session: requests.Session, vuln_type: str) -> NormalizedReport | None:
    r = http_get(report_url, session)
    if r.status_code != 200:
        return None
    html = r.text

    jsonld = extract_jsonld_best_effort(html)

    # title (prefer structured JSON-LD; fall back to meta/title)
    title = (jsonld.get("title") or "").strip()
    if not title:
        m = re.search(r"<meta[^>]+property=\"og:title\"[^>]+content=\"([^\"]+)\"", html, flags=re.I)
        if m:
            title = m.group(1).strip()
    if not title:
        m = re.search(r"<title>(.*?)</title>", html, flags=re.I | re.S)
        if m:
            title = re.sub(r"\s+", " ", m.group(1)).strip()

    # body text (prefer structured JSON-LD; HTML-to-text fallback)
    text = (jsonld.get("body") or "").strip()
    if not text:
        te = TextExtractor()
        te.feed(html)
        text = te.get_text()

    if not looks_like_vuln(title + "\n" + text, vuln_type):
        return None

    # Intigriti 'Bug Bytes' is newsletter-style content (noise). Do not ingest.
    if platform == "intigriti" and is_intigriti_bug_bytes(report_url, title):
        return None

    # platform submitted/published time (best-effort from meta)
    platform_submitted_at = None
    m = re.search(
        r"<meta[^>]+property=['\"]article:published_time['\"][^>]+content=['\"]([^'\"]+)['\"]",
        html,
        flags=re.I,
    )
    if m:
        platform_submitted_at = m.group(1).strip()

    if not platform_submitted_at:
        platform_submitted_at = (jsonld.get("published_time") or "").strip() or None

    submitted_at = platform_submitted_at

    payloads = extract_payloads(text)
    affected_urls = extract_urls(text)
    target_site = choose_target_site(report_url, text, affected_urls)

    ok, _reasons = has_enough_details(text, payloads, affected_urls)
    if not ok:
        return None

    return NormalizedReport(
        title=title,
        vuln_type=vuln_type,
        vuln_type_raw=None,
        platform_submitted_at=platform_submitted_at,
        submitted_at=submitted_at,
        platform=platform,
        report_url=canonical_url(report_url),
        target_site=target_site,
        report_body=text,
        discovered_at=now_iso(),
        fetched_at=now_iso(),
        http_status=r.status_code,
        payloads=payloads,
        affected_urls=affected_urls,
    )


def fetch_report(report_url: str, session: requests.Session, vuln_type: str) -> NormalizedReport | None:
    url = canonical_url(report_url)
    host = urlparse(url).netloc.lower()

    if "hackerone.com" in host:
        return fetch_hackerone(url, session, vuln_type)
    if "bugcrowd.com" in host:
        return fetch_html_report("bugcrowd", url, session, vuln_type)
    if "intigriti.com" in host:
        return fetch_html_report("intigriti", url, session, vuln_type)
    if "yeswehack.com" in host:
        return fetch_html_report("yeswehack", url, session, vuln_type)
    return None


# ------------------------
# Discovery (not just search)
# ------------------------

def discover_hackerone_hacktivity(session: requests.Session, *, pages: int = 3) -> list[str]:
    out: list[str] = []
    for page in range(1, pages + 1):
        url = f"https://hackerone.com/hacktivity/overview?page={page}"
        r = http_get(url, session)
        if r.status_code != 200:
            continue
        html = r.text
        for m in re.finditer(r"https?://hackerone\.com/reports/\d+", html):
            out.append(m.group(0))
        time.sleep(0.4)
    return list(dict.fromkeys(out))


def discover_sitemap(session: requests.Session, sitemap_url: str, *, url_filter: re.Pattern[str] | None = None, max_urls: int = 2000) -> list[str]:
    r = http_get(sitemap_url, session)
    if r.status_code != 200:
        return []
    locs = parse_xml_locs(r.text)

    # if this is an index, expand children
    child_urls: list[str] = []
    if any(u.endswith(".xml") for u in locs) and ("sitemapindex" in r.text[:2000]):
        for u in locs[:60]:  # keep bounded
            child_urls.extend(discover_sitemap(session, u, url_filter=url_filter, max_urls=max_urls))
            if len(child_urls) >= max_urls:
                break
        locs = child_urls

    if url_filter:
        locs = [u for u in locs if url_filter.search(u)]

    return list(dict.fromkeys(locs))[:max_urls]


def discover_urls(session: requests.Session, platforms: list[str], *, max_urls: int, hacktivity_pages: int) -> list[str]:
    urls: list[str] = []

    if "hackerone" in platforms:
        # non-search source
        urls.extend(discover_hackerone_hacktivity(session, pages=hacktivity_pages))

    if "bugcrowd" in platforms:
        # sitemap source
        urls.extend(discover_sitemap(session, "https://bugcrowd.com/sitemap.xml", url_filter=re.compile(r"/disclosures/"), max_urls=max_urls))

    # intigriti: their public pages are all blog/hackademy/marketing content,
    # not real bug bounty disclosures.  Actual reports are behind login at
    # app.intigriti.com.  Skip intigriti entirely until a proper discovery
    # source is found.

    # yeswehack is SPA; no known public sitemap; leave for future extension.

    # de-dupe
    urls = [canonical_url(u) for u in urls]
    urls = list(dict.fromkeys(urls))
    return urls[:max_urls]


# ------------------------
# MD writeup generation (AI via Hermes Agent config by default)
# ------------------------

_HERMES_MODEL_CACHE: dict[str, str] | None = None


def _strip_quotes(s: str) -> str:
    s = s.strip()
    if (s.startswith("\"") and s.endswith("\"")) or (s.startswith("'") and s.endswith("'")):
        return s[1:-1]
    return s


def _hermes_home() -> Path:
    # Prefer explicit HERMES_HOME so profiles work; fall back to ~/.hermes
    hh = os.getenv("HERMES_HOME")
    if hh:
        return Path(hh)
    return Path.home() / ".hermes"


def _load_hermes_model_config() -> dict[str, str]:
    """Best-effort parse of ~/.hermes/config.yaml.

    We intentionally avoid adding PyYAML as a dependency for this repo.
    We only need a few keys under `model:`.
    """

    global _HERMES_MODEL_CACHE
    if _HERMES_MODEL_CACHE is not None:
        return _HERMES_MODEL_CACHE

    out: dict[str, str] = {}
    p = _hermes_home() / "config.yaml"
    if not p.exists():
        _HERMES_MODEL_CACHE = {}
        return {}

    current = None
    try:
        for raw in p.read_text(encoding="utf-8").splitlines():
            line = raw.rstrip("\n")
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            if re.match(r"^[A-Za-z0-9_]+:\s*$", line):
                current = line.split(":", 1)[0].strip()
                continue
            if current != "model":
                continue
            m = re.match(r"^\s{2}([A-Za-z0-9_]+):\s*(.*)$", line)
            if not m:
                continue
            k = m.group(1)
            v = _strip_quotes(m.group(2))
            out[k] = v
    except Exception:
        out = {}

    _HERMES_MODEL_CACHE = out
    return out


def llm_enabled() -> bool:
    # User override
    if os.getenv("BBREPORT_NO_AI") == "1":
        return False

    # Explicit API env vars (optional)
    if os.getenv("OPENAI_API_KEY"):
        return True

    # Default: reuse Hermes Agent config (~/.hermes/config.yaml)
    cfg = _load_hermes_model_config()
    return bool(cfg.get("api_key") and cfg.get("base_url") and cfg.get("default"))


def llm_chat(prompt: str) -> str:
    """OpenAI-compatible chat call.

    This repo does NOT require per-project API configuration.

    Priority order:
    1) If OPENAI_API_KEY is set: use OPENAI_BASE_URL (default: api.openai.com)
    2) Else: use Hermes Agent config (~/.hermes/config.yaml): model.default + model.base_url + model.api_key

    Optional override:
    - LLM_MODEL: force a specific model name
    """

    model = os.getenv("LLM_MODEL")

    if os.getenv("OPENAI_API_KEY"):
        api_key = os.getenv("OPENAI_API_KEY") or ""
        base_url = os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1")
        if not model:
            # fall back to Hermes default model if present
            cfg = _load_hermes_model_config()
            model = cfg.get("default")
    else:
        cfg = _load_hermes_model_config()
        api_key = cfg.get("api_key", "")
        base_url = cfg.get("base_url", "")
        if not model:
            model = cfg.get("default")

    if not (api_key and base_url and model):
        raise RuntimeError(
            "LLM is not configured. Expected either OPENAI_API_KEY or Hermes Agent config at $HERMES_HOME/config.yaml with model.default/base_url/api_key."
        )

    url = base_url.rstrip("/") + "/chat/completions"
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }

    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": "You are a senior security engineer. Be concrete and technical."},
            {"role": "user", "content": prompt},
        ],
        "temperature": 0.2,
    }

    r = requests.post(url, headers=headers, data=json.dumps(payload), timeout=60)
    r.raise_for_status()
    data = r.json()
    return (data.get("choices", [{}])[0].get("message", {}).get("content") or "").strip()


def generate_md(report: dict[str, Any]) -> str:
    """Return markdown content — concise Chinese analysis of trigger URL + exploitation method.

    Instead of pasting the raw report body, we scan the text to extract:
    - What URL/endpoint is vulnerable (trigger URL)
    - How the vulnerability works and how to reproduce it (exploitation method)

    Falls back to rule-based extraction when AI is not configured.
    """

    title = report.get("title") or ""
    platform = report.get("platform") or ""
    vuln_type = report.get("vuln_type") or ""
    report_url = report.get("report_url") or ""
    target_site = report.get("target_site") or ""
    body = report.get("report_body") or ""
    payloads = (report.get("extracted") or {}).get("payloads") or []
    affected_urls = (report.get("extracted") or {}).get("affected_urls") or []

    if llm_enabled():
        report_for_llm = dict(report)
        rb = (report_for_llm.get("report_body") or "")
        if isinstance(rb, str) and len(rb) > 8000:
            report_for_llm["report_body"] = rb[:8000] + "\n…(truncated)…"

        prompt = f"""
你是一位资深安全研究员。请阅读下面的公开漏洞报告 JSON，然后用中文写出一份精炼的分析，只聚焦两件事：

1) 触发 URL — 漏洞出现在哪个 URL / 端点 / 参数？尽量具体。列出 top 5。
2) 利用方法 — 这个漏洞是怎么触发的？请用自己的话说明复现思路（哪个参数注入了什么，服务器如何未过滤/未转义），并列出关键 payload。不要照抄原文，要理解后总结。

如果信息不足，写"信息不足"，不要编造。

输出结构：
# {title}
## 触发 URL
- ...
## 利用方法
...

JSON：
{json.dumps(report_for_llm, ensure_ascii=False)}
""".strip()
        return llm_chat(prompt)

    # ---- Rule-based fallback (no AI) ----
    lines: list[str] = []
    lines.append(f"# {title}")

    if target_site:
        lines.append(f"目标站点: {target_site}")
    if report_url:
        lines.append(f"报告地址: {report_url}")

    # --- Trigger URL ---
    lines.append("")
    lines.append("## 触发 URL")
    if affected_urls:
        for u in affected_urls[:5]:
            lines.append(f"- {u}")
    elif target_site:
        # Try to extract URL-like fragments from the body
        url_frags = re.findall(r'https?://[^\s<>"\']+', body)
        seen = set()
        for u in url_frags:
            u = u.rstrip(".,;:)]}")
            if u not in seen and target_site.replace("www.", "").split("//")[-1].split("/")[0] in u:
                seen.add(u)
                lines.append(f"- {u}")
                if len(seen) >= 5:
                    break
        if not seen:
            lines.append(f"- {target_site}（具体路径见原文）")
    else:
        lines.append("- 信息不足")

    # --- Exploitation method ---
    lines.append("")
    lines.append("## 利用方法")

    # Try to auto-summarize the exploitation from the body text
    method_found = False

    # Look for XSS-specific patterns in body to build a short explanation
    body_lower = body.lower()

    # Detect XSS sub-type
    xss_type = ""
    if "stored xss" in body_lower or "persistent xss" in body_lower:
        xss_type = "存储型 XSS (Stored)"
    elif "reflected xss" in body_lower or "reflection" in body_lower:
        xss_type = "反射型 XSS (Reflected)"
    elif "dom-based" in body_lower or "dom xss" in body_lower:
        xss_type = "DOM 型 XSS"
    elif "blind xss" in body_lower:
        xss_type = "盲打 XSS (Blind)"

    # Try to find the injection point description
    injection_hints = []
    # Pattern: "injected into X" / "X was reflected" / "parameter X"
    for pat in [
        r'(?:injected|injection|reflect|enter|input|submit|inject).*?(?:param|parameter|field|input|variable|query)\s*[=:]\s*["\']?(\w+)',
        r'(?:param|parameter|field|input|variable|query)\s*[=:]\s*["\']?(\w+).*?(?:inject|reflect|xss|vuln)',
        r'(?:via|through|in|on)\s+(?:the\s+)?(?:URL\s+)?(?:path|parameter|query|endpoint|field|input)\s*["\']?(\w+)["\']?',
    ]:
        for m in re.finditer(pat, body, flags=re.I):
            hint = m.group(1).strip()
            if hint and len(hint) < 40 and hint not in injection_hints:
                injection_hints.append(hint)

    if xss_type:
        lines.append(f"漏洞类型: {xss_type}")
        method_found = True

    if injection_hints:
        lines.append(f"注入参数: {', '.join(injection_hints[:5])}")
        method_found = True

    # Look for key action sentences in body (short sentences containing exploit verbs)
    exploit_sentences = []
    for sentence in re.split(r'[.\n]', body):
        s = sentence.strip()
        if len(s) < 20 or len(s) > 300:
            continue
        sl = s.lower()
        if any(kw in sl for kw in ["inject", "payload", "execut", "alert(", "onerror", "<script", "reflected", "stored", "dom-b"]):
            if s not in exploit_sentences:
                exploit_sentences.append(s)
            if len(exploit_sentences) >= 3:
                break

    if exploit_sentences:
        lines.append("关键描述:")
        for s in exploit_sentences[:3]:
            lines.append(f"- {s}")
        method_found = True

    if payloads:
        lines.append("关键 Payload:")
        for p in payloads[:5]:
            lines.append(f"- `{p}`")
        method_found = True

    if not method_found:
        lines.append("- 信息不足")

    return "\n".join(lines) + "\n"


# ------------------------
# Main crawl loop
# ------------------------

def load_state() -> dict[str, Any]:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    if STATE_PATH.exists():
        try:
            return json.loads(STATE_PATH.read_text(encoding="utf-8"))
        except Exception:
            return {"seen": {}}
    return {"seen": {}}


def save_state(state: dict[str, Any]) -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    STATE_PATH.write_text(json.dumps(state, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def write_report_files(nr: NormalizedReport) -> tuple[Path, Path]:
    # User requirement: filename timestamp should keep only YYYYMMDD (no HHMMSS)
    ts = datetime.now(timezone.utc).astimezone().strftime("%Y%m%d")
    slug = safe_slug_from_url(nr.report_url)

    json_name = f"{ts}_{nr.vuln_type}_{nr.platform}_{slug}.json"
    md_name = f"{ts}_{nr.vuln_type}_{nr.platform}_{slug}.md"

    out_json = REPORTS_DIR / nr.vuln_type / json_name
    out_md = EXPLANATIONS_DIR / nr.vuln_type / md_name

    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_md.parent.mkdir(parents=True, exist_ok=True)

    obj = nr.to_json()
    out_json.write_text(json.dumps(obj, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    md = generate_md(obj)
    out_md.write_text(md, encoding="utf-8")

    return out_json, out_md


def render_existing_reports() -> dict[str, Any]:
    """Generate explanations from existing JSONs (no network)."""

    paths = sorted(REPORTS_DIR.glob("**/*.json"))
    rendered = 0
    skipped = 0

    for p in paths:
        try:
            obj = json.loads(p.read_text(encoding="utf-8"))
        except Exception:
            skipped += 1
            continue
        if obj.get("schema") != "bbreport.v1":
            skipped += 1
            continue

        vt = (obj.get("vuln_type") or "unknown").strip().lower() or "unknown"
        out_md = EXPLANATIONS_DIR / vt / (p.stem + ".md")
        out_md.parent.mkdir(parents=True, exist_ok=True)

        md = generate_md(obj)
        out_md.write_text(md, encoding="utf-8")
        rendered += 1

    return {"total": len(paths), "rendered": rendered, "skipped": skipped}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--vuln", default="xss", help="vulnerability type (xss for now)")
    ap.add_argument("--platforms", default="hackerone,bugcrowd", help="comma-separated")
    ap.add_argument("--max-urls", type=int, default=120)
    ap.add_argument("--hacktivity-pages", type=int, default=3)
    ap.add_argument("--sleep", type=float, default=0.6)
    ap.add_argument("--no-ai", action="store_true", help="disable AI and force rule-based explanations")
    ap.add_argument(
        "--render-existing",
        action="store_true",
        help="render Markdown explanations from existing reports/**/*.json (no crawling)",
    )
    args = ap.parse_args()

    vuln_type = normalize_vuln_type(args.vuln)
    platforms = [p.strip().lower() for p in args.platforms.split(",") if p.strip()]

    session = requests.Session()
    session.headers.update({"User-Agent": os.getenv("CRAWLER_UA", DEFAULT_UA)})

    if args.no_ai:
        # Hard disable AI regardless of Hermes/OpenAI env/config.
        os.environ["BBREPORT_NO_AI"] = "1"

    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    EXPLANATIONS_DIR.mkdir(parents=True, exist_ok=True)

    if args.render_existing:
        result = render_existing_reports()
        print(json.dumps({"mode": "render_existing", **result}, ensure_ascii=False))
        return

    state = load_state()
    seen: dict[str, Any] = state.setdefault("seen", {})

    urls = discover_urls(session, platforms, max_urls=args.max_urls, hacktivity_pages=args.hacktivity_pages)

    new_items: list[dict[str, str]] = []
    skipped: list[dict[str, str]] = []

    for url in urls:
        url = canonical_url(url)
        if seen.get(url):
            continue

        nr = None
        try:
            nr = fetch_report(url, session, vuln_type)
        except Exception:
            nr = None

        if not nr:
            seen[url] = {"seen_at": now_iso(), "ingested": False}
            skipped.append({"url": url, "reason": "not_ingested"})
            time.sleep(args.sleep)
            continue

        try:
            out_json, out_md = write_report_files(nr)
        except Exception:
            # don't mark seen as ingested if we failed to write
            seen[url] = {"seen_at": now_iso(), "ingested": False, "reason": "write_failed"}
            time.sleep(args.sleep)
            continue

        seen[url] = {"seen_at": now_iso(), "ingested": True, "json": str(out_json), "md": str(out_md)}
        new_items.append({"url": url, "json": str(out_json), "md": str(out_md)})
        time.sleep(args.sleep)

    state["last_run"] = now_iso()
    save_state(state)

    print(json.dumps({"vuln": vuln_type, "discovered_urls": len(urls), "new": len(new_items), "items": new_items, "skipped": len(skipped)}, ensure_ascii=False))


if __name__ == "__main__":
    main()
