# VulnScope v1.4 — Microsoft 365 automatic list sync

## What this actually does

After each successful `Search Live CVEs`, if Microsoft 365 integration is configured, the UI automatically POSTs to `/api/m365/sync`. The backend **independently reruns/reuses the server-side version search** and writes only `status=version_match` items of the risk levels selected in the UI to a **Microsoft List (SharePoint List)**. It does not write to a Microsoft Loop page or to a native Loop table. Paste a link to that List into your existing Loop page once, so coworkers can open the continuously updated tracker from Loop.

This is **on-search automatic synchronization**, not a background 24/7 watcher. The user's computer/server must be on and the search initiated for data to refresh. Cached CVE data may be up to 15 minutes old. The sync never deletes an item because it disappeared from results; missing upstream data must not silently mark issues as fixed. CVE coverage and affected-version matching are not guaranteed complete.

## 1. Create the destination Microsoft List

Create a List in your organization's SharePoint site (for example, **Firewall CVE Tracker**). Keep **Title** and set **Enforce unique values = Yes** under the Title column settings to prevent duplicates (also indexes the column). Create the following custom columns **using the exact internal names** below (create without spaces or Thai characters in the column names; display names may be changed afterward). Recommended data types:

| Column internal name | Type | Updated by VulnScope? |
| --- | --- | --- |
| Title | Single line of text, unique | Create-only key: Vendor + Version + Hotfix + CVE |
| CVE | Single line text | Yes |
| Vendor | Single line text | Yes |
| OSVersion | Single line text | Yes |
| Hotfix | Single line text | Yes |
| Severity | Single line text | Yes |
| CVSS | Number | Yes |
| Scope | Single line text | Yes |
| AdvisoryURL | Single line text | Yes (URLs >255 chars truncated) |
| CVEDescription | Multiple lines text | Yes |
| KnownExploited | Yes/No | Yes |
| LastSeenUTC | Single line text | Yes |
| Status | Single line text | **Initially set to `To Review`, then NEVER overwritten** |
| Owner | Single line text | **Never overwritten** |
| Remark | Multiple lines text | **Never overwritten** |

Keep the real Microsoft List link in Loop (for example a page section called `Firewall Vulnerability Tracker`). Loop link previews and embedded experiences vary by tenant/client, so **do not assume an editable live Loop table**. Opening the List link always shows its actual data.

## 2. Give VulnScope write permission (requires an authorized Microsoft 365 admin)

Ask your Entra / SharePoint administrator to:

1. Register an Entra application dedicated to VulnScope; provision a client secret (dev/test) and rotate it. For production use certificate authentication/secret vault rather than a plaintext local secret.
2. Grant Microsoft Graph **Application** permission `Sites.Selected` with admin consent. Separately grant that application **write** access to the particular SharePoint site that holds the List. Avoid broad `Sites.ReadWrite.All` whenever possible.
3. Provide the tenant ID, application/client ID, site ID and list ID. **Do not paste the secret into the frontend, a public repository, or this chat.**

Microsoft's Sites.Selected site-grant guidance: https://learn.microsoft.com/en-us/sharepoint/dev/sp-add-ins-modernize/understanding-rsc-for-msgraph-and-sharepoint-online
Graph list-item endpoints: https://learn.microsoft.com/en-us/graph/api/listitem-create?view=graph-rest-1.0 and https://learn.microsoft.com/en-us/graph/api/listitem-update?view=graph-rest-1.0

## 3. Configure Windows local mode

Copy `m365.local.env.example` to `m365.local.env`, fill in the IDs/secret, then start with `START_M365_WINDOWS.bat`. The config remains on your device and is gitignored. **Never send this file to anyone.** Alternatively, set the six environment variables in the shell and start `START_WINDOWS.bat`.

Start at http://127.0.0.1:8000, click Search Live CVEs. The results remain version-matched-only. A notification below the search form indicates `Microsoft Lists auto-sync: N new, M updated ...`, or a clear error. If not configured, no write is attempted and the notice stays hidden.

Check `GET http://127.0.0.1:8000/api/m365/status` to see whether the integration is enabled/configured. It exposes booleans only; it never returns a credential.

## 4. Safety / data handling

- Sync fails closed if the SharePoint List is so large that it cannot be enumerated safely (5,000 records cap). Do not assume that a partial enumeration implies records are absent.
- Composite key = vendor | version | hotfix | CVE, case/whitespace normalized. Same CVE on a different version is tracked separately. Configure Title unique to handle concurrent writers.
- Backend ignores rows supplied by browsers and searches official sources itself, then selects only `version_match` and chosen risk levels.
- Existing manually edited Status, Owner and Remark are preserved during every subsequent sync.
- There is no delete/auto-close. If a CVE is fixed later, an existing tracker row stays open for human review.
- Keep server listening on 127.0.0.1. If deploying anywhere accessible from other machines, add authentication, authorization, HTTPS, network restrictions, rate limits, encrypted secret storage and audit logs before exposing the sync endpoint.
- App-only Graph credentials are powerful. Review organizational data handling policies, especially for customer-related records; the default schema contains **no asset hostname/IP or personal information**.
- Graph / vendor connections cannot be end-to-end tested from the offline build environment. Local mocked tests check idempotency and workflow preservation, but a real Microsoft 365 tenant integration still needs validation.

## 5. Why it is not direct Loop-table sync

As checked 2026-10-25, Microsoft's official Loop Power Automate connector is marked **deprecated**, with only deprecated rule/webhook operations—not `Create row in Loop table`. The public, supported Graph list-item API targets SharePoint/Microsoft Lists, not editable Loop page blocks. Do not rely on reverse-engineered internal Loop endpoints for corporate vulnerability workflow data.

Microsoft connector reference: https://learn.microsoft.com/en-us/connectors/microsoftloop/

## 6. Optional: unattended CVE checks every 3 hours

If you want CVEs pushed into the List even when you don't open the browser, copy `watchlist.example.json` to `watchlist.json`, edit it to the specific Vendor + Version + Hotfix combinations you monitor, then test by double-clicking `RUN_WATCHLIST_WINDOWS.bat` once. It performs one check and exits. Configure Windows Task Scheduler to run that BAT file every 3 hours, while the PC is on and connected to your organization network. This does not require the VulnScope web server to be running, but the first-time Python environment setup should already have been completed with `START_WINDOWS.bat`.

This is **scheduled polling**, not a vendor push feed or a server-side guaranteed notification. If the PC is off, nothing runs. For genuinely 24/7 updates host the service with properly secured credentials and a scheduler. Watchlist syncing is limited to 50 targets per run and will be subject to NVD/vendor API rate limits; configure an NVD key where possible.
