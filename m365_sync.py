"""Optional Microsoft Lists / SharePoint synchronization for VulnScope.

IMPORTANT: This does NOT write into Microsoft Loop pages or Loop tables.
The supported destination is a SharePoint/Microsoft List linked from Loop.
All credentials are kept server-side in environment variables.
"""
from __future__ import annotations

import asyncio
import os
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from urllib.parse import quote, urlparse

import httpx

GRAPH = "https://graph.microsoft.com/v1.0"
SYNC_LOCK = asyncio.Lock()
MATCHED_STATUSES = {"version_match"}
VALID_SEVERITIES = {"Critical", "High", "Medium"}


@dataclass(frozen=True)
class Config:
    tenant: str
    client_id: str
    secret: str
    site_id: str
    list_id: str
    enabled: bool

    @classmethod
    def from_env(cls):
        return cls(
            tenant=os.getenv("M365_TENANT_ID", "").strip(),
            client_id=os.getenv("M365_CLIENT_ID", "").strip(),
            secret=os.getenv("M365_CLIENT_SECRET", "").strip(),
            site_id=os.getenv("M365_SITE_ID", "").strip(),
            list_id=os.getenv("M365_LIST_ID", "").strip(),
            enabled=os.getenv("M365_SYNC_ENABLED", "").lower() in {"true", "1", "yes"},
        )

    def ready(self):
        return self.enabled and all([self.tenant, self.client_id, self.secret, self.site_id, self.list_id])


class SyncError(RuntimeError):
    """A controlled sync failure; never attach secret-bearing token responses."""


def safe_short(v, max_len=255):
    return str(v or "").strip()[:max_len]


def record_key(vendor: str, version: str, hotfix: str, cve: str) -> str:
    # Stable across case/space variations, distinct by vendor/version/hotfix.
    # The list Title field must be configured with Enforce unique values = Yes.
    norm = lambda s: re.sub(r"\s+", " ", str(s or "").strip()).upper()
    return "|".join([norm(vendor), norm(version), norm(hotfix), norm(cve)])


def build_fields(vendor: str, version: str, hotfix: str, row: dict, timestamp: str):
    cid = safe_short(row.get("id")).upper()
    if not re.fullmatch(r"CVE-\d{4}-\d{4,}", cid):
        raise SyncError("Invalid CVE id")
    key = record_key(vendor, version, hotfix, cid)
    if len(key) > 255:
        raise SyncError("Composite record key exceeds SharePoint Title length limit")
    cvss = row.get("cvss")
    if cvss is not None and (not isinstance(cvss, (int, float)) or not 0 <= cvss <= 10):
        cvss = None
    url = str(row.get("source_url") or row.get("nvd_url") or "")
    if not url.startswith("https://"):
        url = ""
    return {
        "Title": key,
        "CVE": cid,
        "Vendor": vendor,
        "OSVersion": safe_short(version),
        "Hotfix": safe_short(hotfix),
        "Severity": row.get("severity") if row.get("severity") in VALID_SEVERITIES else "",
        "CVSS": cvss,
        "Scope": safe_short(row.get("scope")),
        "AdvisoryURL": safe_short(url),
        "CVEDescription": safe_short(row.get("description"), 4000),
        "KnownExploited": bool(row.get("known_exploited")),
        "LastSeenUTC": timestamp,
    }


def permitted_rows(rows: list[dict], severity_filter=None):
    severity_filter = VALID_SEVERITIES if severity_filter is None else (set(severity_filter) & VALID_SEVERITIES)
    seen = set()
    filtered = []
    for row in rows:
        cid = row.get("id", "")
        if row.get("status") not in MATCHED_STATUSES or row.get("severity") not in severity_filter:
            continue
        if not re.fullmatch(r"CVE-\d{4}-\d{4,}", str(cid), flags=re.I) or cid.upper() in seen:
            continue
        seen.add(cid.upper())
        filtered.append(row)
    return filtered


class GraphClient:
    def __init__(self, config: Config, http: httpx.AsyncClient):
        self.conf = config
        self.http = http
        self._token = None

    def list_url(self):
        # IDs from configuration, not user-input or browser-provided URL.
        return f"{GRAPH}/sites/{quote(self.conf.site_id, safe=',')}/lists/{quote(self.conf.list_id, safe='')}"

    async def token(self):
        if self._token:
            return self._token
        if not re.fullmatch(r"[a-zA-Z0-9._-]+", self.conf.tenant):
            raise SyncError("Invalid tenant ID")
        url = f"https://login.microsoftonline.com/{self.conf.tenant}/oauth2/v2.0/token"
        try:
            response = await self.http.post(url, data={
                "client_id": self.conf.client_id,
                "client_secret": self.conf.secret,
                "scope": "https://graph.microsoft.com/.default",
                "grant_type": "client_credentials",
            })
            response.raise_for_status()
            self._token = response.json()["access_token"]
        except (httpx.HTTPError, KeyError, ValueError):
            raise SyncError("Microsoft 365 token request failed: verify app permissions and tenant credentials") from None
        return self._token

    async def request(self, method, url, **kwargs):
        token = await self.token()
        headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
        if "json" in kwargs:
            headers["Content-Type"] = "application/json"
        try:
            res = await self.http.request(method, url, headers=headers, **kwargs)
            res.raise_for_status()
            return res.json() if res.content else {}
        except httpx.HTTPStatusError as exc:
            raise SyncError(f"Microsoft Graph returned HTTP {exc.response.status_code} (check site/list IDs, access and column internal names)") from None
        except (httpx.HTTPError, ValueError):
            raise SyncError("Microsoft Graph connection or response failed") from None

    async def list_items(self, max_items=5000):
        url = self.list_url() + "/items?$expand=fields&$top=200"
        results = []
        while url:
            parsed = urlparse(url)
            if parsed.scheme != "https" or parsed.hostname != "graph.microsoft.com":
                raise SyncError("Microsoft Graph pagination returned an invalid host")
            data = await self.request("GET", url)
            results.extend(data.get("value", []))
            if len(results) > max_items:
                raise SyncError("SharePoint List exceeds 5,000 records; sync stopped to prevent duplicate creation")
            url = data.get("@odata.nextLink")
        return results

    async def upsert(self, row, existing):
        url = self.list_url() + "/items"
        key = row["Title"]
        if key in existing:
            record = existing[key]
            item_id = record["id"]
            old = record.get("fields", {})
            # Intentionally NEVER update user workflow fields such as Status, Owner, Remark.
            changes = {k: v for k, v in row.items() if k != "Title" and v != old.get(k)}
            if not changes:
                return "unchanged"
            await self.request("PATCH", f"{url}/{quote(str(item_id), safe='')}/fields", json=changes)
            return "updated"
        created = await self.request("POST", url, json={"fields": {**row, "Status": "To Review"}})
        existing[key] = {"id": created.get("id", ""), "fields": row}
        return "created"


async def sync_to_list(
    vendor: str, version: str, hotfix: str, rows: list[dict],
    severities=None, config: Config | None = None, client: httpx.AsyncClient | None = None,
):
    conf = config or Config.from_env()
    if not conf.ready():
        raise SyncError("Microsoft Lists sync is not configured/enabled")
    selected = permitted_rows(rows, severities)
    if not selected:
        return {"created": 0, "updated": 0, "unchanged": 0, "matched": 0, "destination": "Microsoft List"}
    owns_client = client is None
    if owns_client:
        client = httpx.AsyncClient(timeout=30.0)
    try:
        async with SYNC_LOCK:
            graph = GraphClient(conf, client)
            existing = {}
            for record in await graph.list_items():
                key = record.get("fields", {}).get("Title")
                if key:
                    existing[key] = record
            stamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
            summary = {"created": 0, "updated": 0, "unchanged": 0, "matched": len(selected), "destination": "Microsoft List"}
            for r in selected:
                fields = build_fields(vendor, version, hotfix, r, stamp)
                state = await graph.upsert(fields, existing)
                summary[state] += 1
            return summary
    finally:
        if owns_client:
            await client.aclose()
