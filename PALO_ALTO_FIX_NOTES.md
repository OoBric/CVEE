# Palo Alto Version Matching Fix — VulnScope Cinematic v2.1

## What was broken

The live Palo Alto `/json?product=PAN-OS&version=...` endpoint returns a condensed record format with **`ID`**, **`baseScore`**, parallel **`version[]`** / **`affected[]`**, **`problem[]`**, **`solution[]`** and **`work_around[]`** fields. The previous parser expected `cve_id` and `cvss_score` instead, so it silently threw away valid Palo Alto advisories while NVD still returned a few results.

## Fix

- Parse the real condensed Palo Alto record format, including uppercase `ID` and `baseScore`.
- Check affected thresholds for the exact PAN-OS maintenance version, including hotfix level (for example, `11.2.7-h20 < 11.2.7-h21`).
- Enrich results from full CVE 5.0 detail records where available; handle version-table `changes` and preserve validated summary evidence when the full response cannot resolve it.
- Query the canonical `palo_alto_networks` CPE vendor spelling in NVD.
- Mark source enrichment failures as partial instead of silently declaring complete success.
- Keep the Cinematic UI, Check Point/Fortinet/Juniper integrations, and Seen/Updated database semantics unchanged.

## Regression checks

The mock API tests verify that `CVE-2026-0322` is a **High (8.6)** `version_match` for PAN-OS **11.2.7-h20** and not a match for **11.2.7-h21**, including a complete `/api/search` aggregation test. Total: **39 Python tests passed** with mocked network responses. Tests do **not** verify live vendor connectivity on Render.

## Deploy to existing Render Web Service

1. Extract this ZIP. `Dockerfile`, `app.py`, and `static/` are at the ZIP root (no enclosing project folder).
2. Replace the corresponding files in your **existing** private GitHub repository, including `app.py`. Keep the Render service connected to the same repository, and leave its Root Directory blank if this is your repo structure.
3. Commit/push the changes; Render can auto-deploy the new commit, or choose **Manual Deploy → Deploy latest commit**.
4. Keep `VULNSCOPE_USERNAME` and `VULNSCOPE_PASSWORD` in **Render Environment**. Never commit credentials.
5. When deployment succeeds, search Palo Alto `11.2.7-h20`. Confirm **CVE-2026-0322** appears with High severity. If it doesn't, inspect **Source Status** for Palo Alto PSIRT and share the latest service logs.

Caution: Free Render instances have ephemeral storage; local SQLite Seen/Updated marks may disappear after redeploy unless stored in a persistent external database or on a paid persistent disk. This ZIP does **not** solve that separate limitation.
