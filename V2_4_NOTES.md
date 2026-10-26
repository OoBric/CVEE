# VulnScope v2.4: CVE discovery repair (26 Oct 2026)

## What changed

1. Palo Alto PSIRT is now queried via **three independent endpoints**, including the official **unfiltered `GET /json`**. The unfiltered index is cached in memory for one hour. This reduces false negatives caused by version-filtered API results omitting CVEs.
2. NVD queries now also request Palo Alto's `sourceIdentifier=psirt@paloaltonetworks.com` rather than only a PAN-OS CPE match. CVEs with CNA affected-version data but no NVD CPE can be discovered.
3. PAN-OS CNA affected-version data from NVD is treated conservatively: no `Version Matched` for generic branch coverage unless a specific maintenance version or hotfix condition supports it.
4. Empty/failing upstream indexes are reported as partial coverage. An API HTTP 200 is not a completeness guarantee.
5. Fixed targeted regressions for `CVE-2026-0322` and `CVE-2024-8686`. No CVE IDs are injected into the live search results.
6. Check Point, Fortinet and Juniper code and UI are retained from v2.3. This patch does not guarantee their live completeness.

## Validation performed

- `python -m pytest -q`: **62 passed** using synthetic vendor-format records and an ASGI HTTP search integration test.
- `python -m py_compile app.py cloud_app.py`: Passed.
- Official Palo Alto API documentation and the authoritative CVE-2026-0322 affected-version matrix were inspected online.
- **NOT** end-to-end verified against live API responses from the Python environment due to blocked external DNS/network access. Must not be described as fully live verified.

## After deployment

Use the same repository and environment variables. Commit the new `app.py` and (optionally) `scripts/verify_live_api.py` plus this file, then redeploy. No database migration required.

For a live smoke check from a machine with internet, install the existing `requirements.txt` and run:

```sh
python scripts/verify_live_api.py --base-url https://YOUR-SERVICE.onrender.com
```

For an authenticated site set `VULNSCOPE_USERNAME` and `VULNSCOPE_PASSWORD` in the local shell environment (do not commit credentials).

Expected: `CVE-2026-0322` matches PAN-OS `11.2.7-h20` with a score of 8.6; does not match `11.2.7-h21`; `CVE-2024-8686` does not match `11.2.7-h20`. If the smoke test fails, do **not** treat the results as comprehensive or correct.

`/api/search` still intentionally reports `complete: false`. A successful smoke check is a limited regression check, not a guarantee every CVE is present.
