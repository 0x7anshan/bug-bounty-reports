# bug-bounty-reports

Automated collection of public bug bounty disclosures/writeups.

## What this repo contains
- `reports/` — per-report JSON files (timestamped), grouped by vuln type (e.g. `reports/xss/`)
- `explanations/` — per-report Markdown explanations generated from JSON (grouped by vuln type; NOT by platform)
- `state/` — local crawler state (seen URLs/IDs) for incremental runs (NOT committed)
- `scripts/` — crawler + extractors

## Naming
Each new report is saved as:
- `reports/<vuln_type>/YYYYMMDD_<vuln_type>_<platform>_<slug>.json`
- `explanations/<vuln_type>/YYYYMMDD_<vuln_type>_<platform>_<slug>.md`

## Platforms (current)
- HackerOne (public disclosed reports via `/reports/<id>.json`)
- Bugcrowd (public disclosure pages discovered via sitemap)
- Intigriti (researchers blog/writeups discovered via sitemap)

## Crawler
Primary entrypoint:
- `scripts/crawl_reports.py`

Discovery is *not* limited to search engines:
- HackerOne: Hacktivity pages
- Bugcrowd: sitemap.xml
- Intigriti: sitemap.xml (filtered to researchers blog)

## AI explanations
By default, `scripts/crawl_reports.py` reuses the Hermes Agent model config from:
- `$HERMES_HOME/config.yaml` (or `~/.hermes/config.yaml`)

You can disable AI and force rule-based explanations:
- `python3 scripts/crawl_reports.py --no-ai`

You can (re)render explanations from existing JSONs without crawling:
- `python3 scripts/crawl_reports.py --render-existing`

## Quality gate
Reports are only ingested if they contain sufficient technical detail (body length + payload/steps/affected URLs). Low-detail pages are skipped.

## Notes
- Public pages only. No login.
- Respect robots and rate limits.
