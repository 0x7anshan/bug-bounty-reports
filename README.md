# bug-bounty-reports

Automated collection of public bug bounty disclosures/writeups.

## What this repo contains
- `reports/` — per-report JSON files (timestamped)
- `writeups/` — per-report Markdown writeups generated from JSON (AI if configured)
- `cards/` — PNG summary cards (legacy; optional)
- `state/` — local crawler state (seen URLs/IDs) for incremental runs (NOT committed)
- `scripts/` — crawler + extractors

## Naming
Each new report is saved as:
- `reports/<platform>/YYYYMMDD_HHMMSS_<vuln_type>_<platform>_<slug>.json`
- `writeups/<platform>/YYYYMMDD_HHMMSS_<vuln_type>_<platform>_<slug>.md`

Cards (legacy/optional):
- `cards/<platform>/YYYYMMDD_HHMMSS_<vuln_type>_<platform>_<slug>.png`

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

## AI writeups (optional but recommended)
If you want AI-generated markdown explanations, set env vars when running:
- `OPENROUTER_API_KEY` (or `OPENAI_API_KEY`)
- `LLM_MODEL` (OpenAI-compatible model id)

If AI is not configured, the script falls back to a rule-based writeup.

## Quality gate
Reports are only ingested if they contain sufficient technical detail (body length + payload/steps/affected URLs). Low-detail pages are skipped.

## Notes
- Public pages only. No login.
- Respect robots and rate limits.
