# VulnScope Cinematic v2.2 — Four-vendor version matching review

This release updates **all four vendor paths**. It is not a certification that all published CVEs will be discovered.

## What changed

| Vendor | Primary version evidence | Improvements in v2.2 |
|---|---|---|
| Check Point | Check Point CNA's NVD `affected` records (Gateway + Management), and R82 Jumbo Hotfix notes | Retains JHF Take-aware matching and strict R82/R82.10 separation; blocks unrelated legacy Firewall-1 and wildcard-only versions; rejects invalid Take strings. |
| Fortinet FortiOS | Fortinet CNA's NVD `affected` records + exact/ranged NVD CPE; FortiGuard PSIRT RSS for detail/context only | Queries `psirt@fortinet.com` so newly received CVEs without analyzed CPE can be found; interprets exact versions, affected ranges and branch rules; filters out FortiManager/FortiProxy; preserves affected vs fixed distinction. |
| Palo Alto PAN-OS | Palo Alto official JSON condensed feed and CVE JSON + NVD CPE | Retains v2.1 official `ID` and `baseScore` parser; evaluates **all** applicable CVE-JSON affected blocks; guards against conflicting version/hotfix input. |
| Juniper Junos OS | Juniper CNA's NVD `affected` records + exact/ranged NVD CPE | Queries `sirt@juniper.net`; compares Junos R/S service releases including `23.4R2-S3`; separates Junos OS from Junos OS Evolved; rejects unsupported version strings. |

## Important limitations

- **Version Matched** means the software release matched a published *structured affected-version predicate*. It is not confirmation of device exposure or applicability to a specific hardware model or feature.
- NVD may not yet contain the vendor CNA structured `affected` data, especially immediately after a CVE publishes. Successful upstream HTTP responses are **not** proof of complete coverage.
- FortiGuard RSS is rolling and the HTML cannot always reliably distinguish an affected-version table from a fixed-version table. These rows remain `review` unless supported by precise CNA/NVD evidence; the UI intentionally shows only `version_match`.
- Juniper has no directly connected SIRT advisory feed in this build. Data is sourced from Juniper's structured **CNA information through NVD** plus the NVD CPE; official JSA references remain linked.
- Check Point JHF fix coverage is limited to the release notes and the documented dated snapshot fallback. Independent/private hotfixes and device state are not tested. R82 fixed-take evidence must not be applied to R82.10.
- NVD requests may be rate-limited or truncated. The UI reports partial coverage. **Zero results is not evidence of safety.**
- `Seen/Updated` records are stored in SQLite; Render Free without a persistent database can lose them on restart. The in-process watchlist pauses when Render Free spins down.

## Example version regressions

- PAN-OS `11.2.7-h20` -> vendor affected rule for `CVE-2026-0322` matches; `11.2.7-h21` does not.
- Junos OS `23.4R2-S3` matches a structured rule `23.4` to `< 23.4R2-S6`; `23.4R2-S6` does not.
- FortiOS `7.4.8` matches a structured rule `7.4.0` to `< 7.4.9`; `7.4.9` does not.
- Check Point R82 Take 126 matches `R82 ... Take 126 or below` but Take 127 does not. Unrelated legacy Firewall-1 is rejected.

These are **regression tests using fixtures modeled on vendor/NVD schemas**, not external API end-to-end validation. Run `pytest -q` after making changes.

## Updating the currently deployed Render site

1. In the existing GitHub repo, replace `app.py` with the file in this package (or commit all changed files).
2. Trigger **Render -> Manual Deploy -> Deploy latest commit** if auto-deploy is not enabled.
3. Re-test each vendor from the UI. Keep an eye on **Advisory Coverage** at the bottom of the results, and compare a couple of CVEs to official advisories.
4. No new password or database variables are needed beyond the existing v2.x cloud settings.

Do **not** commit `.env`, credentials or a local `data/*.sqlite3` database.
