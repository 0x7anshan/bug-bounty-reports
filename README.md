# bug-bounty-reports

Automated collection of public bug bounty disclosures/writeups.

## What this repo contains
- `reports/` — per-report JSON files (timestamped)
- `cards/` — PNG summary cards generated from each JSON
- `state/` — crawler state (seen URLs/IDs) to support incremental runs
- `scripts/` — crawler + card generator

## Naming
Each new report is saved as:
- `reports/<platform>/YYYYMMDD_HHMMSS_xss_<platform>_<id-or-slug>.json`

Cards:
- `cards/<platform>/YYYYMMDD_HHMMSS_xss_<platform>_<id-or-slug>.png`

## Platforms (initial)
- Bugcrowd (public disclosures)
- Intigriti (public writeups/advisories)
- YesWeHack (public disclosures)

## Notes
- Public pages only. No login.
- Respect rate limits.
