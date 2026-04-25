#!/usr/bin/env python3
"""Migrate legacy report JSONs to schema bbreport.v1.

- Reads existing `reports/**.json`
- Fetches full body from the original report URL (public-only)
- Rewrites JSON in-place using the normalized v1 schema
- Generates/updates a matching Markdown explanation under `explanations/<vuln_type>/` (AI if configured)

This is intentionally best-effort: if a URL is no longer reachable or lacks detail,
we skip it and leave the original file unchanged.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import requests

# Reuse logic from crawl_reports.py (kept as a script; import via path)
import importlib.util


ROOT = Path(__file__).resolve().parents[1]
REPORTS_DIR = ROOT / "reports"
EXPLANATIONS_DIR = ROOT / "explanations"


def load_crawler_module():
    p = ROOT / "scripts" / "crawl_reports.py"
    spec = importlib.util.spec_from_file_location("crawl_reports", p)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)

    # Important: dataclasses relies on sys.modules[__module__] existing.
    import sys

    sys.modules["crawl_reports"] = mod
    spec.loader.exec_module(mod)  # type: ignore
    return mod


def main() -> None:
    mod = load_crawler_module()

    session = requests.Session()
    session.headers.update({"User-Agent": os.getenv("CRAWLER_UA", mod.DEFAULT_UA)})

    paths = sorted(REPORTS_DIR.glob("*/*.json"))

    updated = 0
    skipped = 0

    for p in paths:
        try:
            old = json.loads(p.read_text(encoding="utf-8"))
        except Exception:
            skipped += 1
            continue

        if old.get("schema") == "bbreport.v1":
            continue

        url = old.get("report_url") or old.get("url")
        platform = old.get("platform")
        vuln = old.get("vuln_type") or old.get("vuln") or "xss"
        vuln = mod.normalize_vuln_type(vuln)

        if not url or not platform:
            skipped += 1
            continue

        nr = None
        try:
            nr = mod.fetch_report(url, session, vuln)
        except Exception:
            nr = None

        if not nr:
            # keep original; it may have been a partial capture
            skipped += 1
            continue

        # preserve original discovered_at if present
        discovered_at = old.get("discovered_at") or nr.discovered_at
        nr.discovered_at = discovered_at

        obj = nr.to_json()
        p.write_text(json.dumps(obj, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

        # MD writeup path uses filename timestamp+slug; keep aligned with JSON filename
        vt = (obj.get("vuln_type") or vuln or "unknown").strip().lower() or "unknown"
        md_path = EXPLANATIONS_DIR / vt / p.name.replace(".json", ".md")
        md_path.parent.mkdir(parents=True, exist_ok=True)
        md = mod.generate_md(obj)
        md_path.write_text(md, encoding="utf-8")

        updated += 1

    print(json.dumps({"total": len(paths), "updated": updated, "skipped": skipped}, ensure_ascii=False))


if __name__ == "__main__":
    main()
