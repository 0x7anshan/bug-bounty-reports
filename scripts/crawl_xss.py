#!/usr/bin/env python3
# Public-only crawler for bug bounty disclosures/writeups related to XSS.
# Platforms: Bugcrowd, Intigriti, YesWeHack
# Output: per-report JSON + PNG summary card.

import json
import os
import re
import time
import hashlib
from dataclasses import dataclass
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import requests


RUN_TS = datetime.now(timezone.utc).astimezone().strftime("%Y%m%d_%H%M%S")
VULN_NAME = "xss"  # fixed per user

ROOT = Path(__file__).resolve().parents[1]
STATE_DIR = ROOT / "state"
REPORTS_DIR = ROOT / "reports"
CARDS_DIR = ROOT / "cards"

STATE_PATH = STATE_DIR / "xss_state.json"

UA = "Mozilla/5.0 (compatible; bug-bounty-reports-bot/1.0; +https://github.com/0x7anshan/bug-bounty-reports)"


class TextExtractor(HTMLParser):
    def __init__(self):
        super().__init__()
        self._chunks = []
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


def http_get(url: str, session: requests.Session) -> requests.Response:
    r = session.get(url, timeout=40)
    r.raise_for_status()
    return r


def canonical_url(url: str) -> str:
    # Basic canonicalization: drop fragment.
    p = urlparse(url)
    return p._replace(fragment="").geturl()


def sha1(s: str) -> str:
    return hashlib.sha1(s.encode("utf-8")).hexdigest()


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def is_xss(text: str) -> bool:
    if not text:
        return False
    t = text.lower()
    keys = [
        "xss",
        "cross-site scripting",
        "cross site scripting",
        "cwe-79",
        "cwe 79",
        "dom xss",
        "stored xss",
        "reflected xss",
        "blind xss",
        "onerror=",
        "onload=",
        "<script",
        "%3cscript",
    ]
    return any(k in t for k in keys)


def extract_title(html: str) -> str:
    # Prefer og:title
    m = re.search(r"<meta[^>]+property=\"og:title\"[^>]+content=\"([^\"]+)\"", html, flags=re.I)
    if m:
        return m.group(1).strip()
    m = re.search(r"<title>(.*?)</title>", html, flags=re.I | re.S)
    if m:
        return re.sub(r"\s+", " ", m.group(1)).strip()
    return ""


def extract_payload_lines(text: str, max_items: int = 6) -> list[str]:
    out = []
    seen = set()
    for line in text.split("\n"):
        l = line.strip()
        if not l:
            continue
        ll = l.lower()
        if any(tok in ll for tok in ["poc", "proof of concept", "payload", "onerror", "onload", "<script", "%3cscript", "javascript:", "alert(", "prompt("]):
            l = l[:220] + ("…" if len(l) > 220 else "")
            if l not in seen:
                seen.add(l)
                out.append(l)
        if len(out) >= max_items:
            break
    return out


def extract_how_to_find(text: str, max_items: int = 3) -> list[str]:
    # Try to capture steps-ish lines: bullets or numbered.
    out = []
    for line in text.split("\n"):
        l = line.strip()
        if not l:
            continue
        if re.match(r"^(-|\*|\d+\.)\s+", l):
            l = re.sub(r"^(-|\*|\d+\.)\s+", "", l)
            l = l[:220] + ("…" if len(l) > 220 else "")
            out.append(l)
        if len(out) >= max_items:
            break
    if out:
        return out
    # fallback: first paragraph-ish
    paras = [p.strip() for p in re.split(r"\n\n+", text) if p.strip()]
    if paras:
        return [paras[0][:220] + ("…" if len(paras[0]) > 220 else "")]
    return []


@dataclass
class FoundURL:
    platform: str
    url: str
    query: str


def discover_urls() -> list[FoundURL]:
    # We use DuckDuckGo via Hermes web_search in the agent normally, but here we run pure python.
    # So: do lightweight discovery using search engine HTML endpoints is brittle.
    # Instead: this script expects the surrounding runner to supply URLs.
    raise RuntimeError("Discovery is handled by Hermes web_search in cron prompt; this script is fetch+extract only.")


def to_card_png(card_text: str, out_path: Path) -> None:
    """Generate a simple PNG card using ImageMagick.

    NOTE: We intentionally do NOT use ImageMagick '@file' syntax because many
    environments ship with a security policy that blocks it.
    """
    import subprocess

    out_path.parent.mkdir(parents=True, exist_ok=True)

    # ImageMagick handles literal newlines in the annotate string.
    # Keep text reasonably short to avoid pathological render times.
    card_text = card_text.strip()
    if len(card_text) > 3000:
        card_text = card_text[:2990] + "…"

    args = [
        "convert",
        "-size",
        "1200x675",
        "xc:#0b1020",
        "-fill",
        "#e5e7eb",
        "-font",
        "DejaVu-Sans",
        "-pointsize",
        "28",
        "-gravity",
        "NorthWest",
        "-interline-spacing",
        "6",
        "-annotate",
        "+48+48",
        card_text,
        "-fill",
        "#6b7280",
        "-pointsize",
        "18",
        "-gravity",
        "SouthEast",
        "-annotate",
        "+36+24",
        "bug-bounty-reports",
        str(out_path),
    ]

    subprocess.check_call(args)


def main():
    session = requests.Session()
    session.headers.update({"User-Agent": UA})

    STATE_DIR.mkdir(parents=True, exist_ok=True)
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    CARDS_DIR.mkdir(parents=True, exist_ok=True)

    state = {"seen": {}, "last_run": None}
    if STATE_PATH.exists():
        state = json.loads(STATE_PATH.read_text(encoding="utf-8"))

    # Input: newline-separated URLs via stdin
    in_urls = [canonical_url(l.strip()) for l in os.sys.stdin.read().splitlines() if l.strip()]
    in_urls = list(dict.fromkeys(in_urls))

    new_items = []

    for idx, url in enumerate(in_urls, 1):
        # platform infer by hostname
        host = urlparse(url).netloc.lower()
        if "bugcrowd.com" in host:
            platform = "bugcrowd"
        elif "intigriti.com" in host:
            platform = "intigriti"
        elif "yeswehack.com" in host:
            platform = "yeswehack"
        else:
            continue

        if state.get("seen", {}).get(url):
            continue

        try:
            r = http_get(url, session)
            html = r.text
        except Exception as e:
            # mark as seen to avoid repeated failure storms? no.
            continue

        title = extract_title(html)
        te = TextExtractor()
        te.feed(html)
        text = te.get_text()

        if not is_xss(title + "\n" + text):
            state.setdefault("seen", {})[url] = {"seen_at": now_iso(), "xss": False}
            time.sleep(0.5)
            continue

        # Derive a stable id/slug
        slug = sha1(url)[:10]

        # Save JSON
        ts = datetime.now(timezone.utc).astimezone().strftime("%Y%m%d_%H%M%S")
        fname = f"{ts}_{VULN_NAME}_{platform}_{slug}.json"
        out_json = REPORTS_DIR / platform / fname
        out_json.parent.mkdir(parents=True, exist_ok=True)

        how = extract_how_to_find(text, max_items=3)
        payloads = extract_payload_lines(text, max_items=6)

        obj: dict[str, Any] = {
            "platform": platform,
            "vuln": VULN_NAME,
            "url": url,
            "title": title,
            "discovered_at": now_iso(),
            "how_to_find": how,
            "payloads_or_poc": payloads,
            "source": {
                "fetched_at": now_iso(),
                "http_status": r.status_code,
            },
        }

        out_json.write_text(json.dumps(obj, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

        # Card text
        lines = []
        lines.append(f"{platform.upper()}  |  XSS")
        lines.append("")
        lines.append(title[:90] + ("…" if len(title) > 90 else ""))
        lines.append("")
        lines.append("How discovered:")
        for h in how[:3]:
            lines.append(f"- {h}")
        if payloads:
            lines.append("")
            lines.append("Payload / POC:")
            for p in payloads[:3]:
                lines.append(f"- {p}")
        lines.append("")
        lines.append(url)

        card_text = "\n".join(lines)
        out_png = CARDS_DIR / platform / fname.replace(".json", ".png")
        to_card_png(card_text, out_png)

        new_items.append({"json": str(out_json), "card": str(out_png), "title": title, "url": url, "platform": platform})

        state.setdefault("seen", {})[url] = {"seen_at": now_iso(), "xss": True, "json": str(out_json)}
        time.sleep(0.6)

    state["last_run"] = now_iso()
    STATE_PATH.write_text(json.dumps(state, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    # Emit a machine-readable summary
    print(json.dumps({"run_ts": RUN_TS, "input_urls": len(in_urls), "new_xss": len(new_items), "items": new_items}, ensure_ascii=False))


if __name__ == "__main__":
    main()
