# VulnScope Cinematic v2.3 — Palo Alto Coverage + Exact Version Fix

This release fixes two independently verified flaws exposed by the user when searching PAN-OS `11.2.7-h20` on Render:

1. **False positive: CVE-2024-8686**. Official vendor advisory states PAN-OS `11.2.2` affected and `>= 11.2.3` unaffected. The previous CVE 5.0 parser treated an unbounded `version: 11.2.2` rule as if it affected *all later versions*. It now treats an explicit version as exact unless the rule includes `lessThan`, `lessThanOrEqual`, or change boundaries.
2. **False negative: CVE-2026-0322**. Official vendor advisory lists `PAN-OS 11.2.7-h20` as affected, with fix in `11.2.7-h21`. The previous code trusted a single vendor version-filtered list: any CVE absent from that list was never considered. The new code cross-checks both the exact-version and the PAN-OS product-wide PSIRT JSON advisory lists, deduplicates by CVE ID, then checks each advisory's own version rules. Unresolved advisories may be checked using their full JSON, subject to a conservative 48-detail ceiling, request timeouts, and coverage notes.

## What did not change
- UI, Login, Seen/Updated SQLite tracker, CSV export, and the Check Point/Fortinet/Juniper parsers are retained from v2.2.
- Search results are **candidates** backed by version evidence, not device scans.
- The web app still cannot guarantee 100% coverage; some vendor indexes may omit advisories, some full detail requests can time out, and upstream sources can fail.

## Testing

- `pytest -q` passed **55 tests**, including synthetic cases for a missing indexed CVE, an incorrect older exact-version CVE, deduplication, hotfix boundary, a failed source, and the existing other-vendor tests.
- **The tests use simulated upstream responses**. The build environment cannot connect directly to the public API, so neither complete live coverage nor Render behavior is proven. Inspect `Advisory Coverage` after deployment.

## Updating existing Render app
1. Replace **only `app.py`** in the existing GitHub repository and commit, or upload the root contents of the provided ZIP for a full replacement.
2. On Render, **Manual Deploy → Deploy latest commit**. Leave the existing Environment Variables in Render; do not upload passwords or `.env` secrets to GitHub.
3. Search `Palo Alto` / `11.2.7-h20` with High + Medium selected. Check for `CVE-2026-0322` (HIGH 8.6), and ensure `CVE-2024-8686` is not shown as Version Matched. Compare with vendor advisories.
4. Search `11.2.7-h21`. `CVE-2026-0322` should no longer be Version Matched.
5. If either check still fails, copy the `Palo Alto PSIRT` and `NVD` lines in the **Advisory Coverage** section. Do not send credentials.

Official sources:
- https://security.paloaltonetworks.com/CVE-2026-0322
- https://security.paloaltonetworks.com/CVE-2024-8686
- https://security.paloaltonetworks.com/api

On free cloud instances, local SQLite tracking state is not durable without a persistent database. Preserve/upgrade storage before relying on Seen state.
