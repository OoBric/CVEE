# Deploy VulnScope Cinematic v2.0 to Railway

This package contains an actual FastAPI backend and a new cinematic responsive UI, not only a static design. You **must** deploy the backend and connect a persistent volume for Seen/Updated tracking to survive redeploys. Does not require buying a domain.

## Step 1 — Put these files in GitHub

1. Unzip the package; open the folder `VulnScope-Cinematic-v2.0`.
2. Create a **private** GitHub repo and upload the **contents** of that folder at repo root, including `Dockerfile`, `railway.json`, `app.py`, `cloud_app.py`, `tracking.py`, `m365_sync.py`, `requirements.txt`, and `static/index.html`.
3. Do **not** upload `.env`, actual credentials, API keys, `data/`, or the SQLite database.

## Step 2 — Create an online web service

1. Go to [railway.com](https://railway.com) → **New Project** → **Deploy from GitHub Repo** → select your repo.
2. The `Dockerfile` is detected and the `railway.json` defines the health check at `/api/health`.
3. Under the service **Variables**, add at least:

   | Variable | Example / purpose |
   |---|---|
   | `VULNSCOPE_USERNAME` | `admin` |
   | `VULNSCOPE_PASSWORD` | a unique secret **14+ characters**; prefer 20+ |
   | `VULNSCOPE_DB_PATH` | `/data/cve_tracking.sqlite3` |
   | `NVD_API_KEY` | optional key obtained directly from NVD |
   | `VULNSCOPE_WATCHLIST_JSON` | optional JSON with vendors/versions you monitor |
   | `VULNSCOPE_SCAN_INTERVAL_SECONDS` | `10800` for every 3 hours, optional |

4. Add a **Volume attached to the same web service**, mounted at **`/data`**, **before** saving Seen flags. The SQLite file lives at `/data/cve_tracking.sqlite3`. This is critical: files only in the container are ephemeral.
5. Keep **1 replica / 1 Uvicorn worker** when using SQLite on a Railway volume.
6. Choose **Settings → Networking → Public Networking → Generate Domain**. Visit the HTTPS domain and enter the username/password in your browser's HTTP Basic login prompt.

Railway documentation: [FastAPI](https://docs.railway.com/guides/fastapi) · [Volumes](https://docs.railway.com/volumes) · [Networking](https://docs.railway.com/guides/public-networking) · [Health checks](https://docs.railway.com/deployments/healthchecks).

## Step 3 — Verify before sharing

- Visit `/api/health`: JSON should include `"ok":true`.
- Check one firmware version; click a CVE and **Mark as seen**.
- Refresh; the Seen state should remain.
- Restart/redeploy the service and confirm it is still Seen. If not, check the volume and DB path.
- Review Source Status for NVD/vendor failures and rate limits. **Zero matched CVEs does NOT mean safe.**
- Change a monitored CVE's saved advisory only if the source changes; `UPDATED` is triggered after a new search/refresher sees changed source data.

## Optional: automatic CVE refresh without keeping a laptop open

Set `VULNSCOPE_WATCHLIST_JSON` to a JSON array (one line):

```json
[{"vendor":"checkpoint","version":"R82","hotfix":"Take 127"},
 {"vendor":"paloalto","version":"11.2.7-h20","hotfix":""}]
```

Set `VULNSCOPE_SCAN_INTERVAL_SECONDS=10800`. An in-process watcher searches these versions about every 3 hours **while the Railway web service is running**. It stores snapshots for Seen/Updated tracking in SQLite. This starter version does **not** automatically send Teams alerts, and it does not display watchlist-wide results on the homepage. View one saved firmware at a time by searching it. If your hosting plan sleeps the service, scheduled checks stop while it sleeps. For large/team deployments use a managed Postgres DB and an external scheduler instead.

## Migrating existing v1.5/v1.6 Seen data

Local Seen statuses reside in `data/cve_tracking.sqlite3` (or in a custom path in `VULNSCOPE_DB_PATH`). **Do not replace or delete the old database when upgrading.** The Railway cloud will start with a fresh database unless you explicitly transfer the old one to the Railway volume using an authorized admin workflow. Never upload it through a public dashboard endpoint.

## Security and limits

- Protects the website and APIs using **HTTP Basic Authentication over Railway HTTPS**. This is for one trusted operator, not a multi-user enterprise security system. If used for a company/customer, get approval and add Microsoft Entra ID SSO/RBAC.
- Keep GitHub repo private, use unique secrets, avoid customer IPs and credentials, and enable volume backups if supported by the chosen plan.
- This is an advisory version matcher; it is **not** a live firewall scanner and is not guaranteed complete or accurate. NVD and vendor feeds can be partial, inaccessible, or rate-limited.
- The Microsoft Lists integration is **optional** and needs organization permission; it does not edit native Microsoft Loop tables.
- The website is not deployed by downloading this ZIP; deployment still requires your GitHub/Railway account and permissions. Railway may charge for compute/volume/network usage.
