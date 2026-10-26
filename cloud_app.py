"""VulnScope cloud entrypoint: password-protected personal deployment.

Authentication is HTTP Basic over hosting provider HTTPS, not multi-user SSO.
Optional personal watchlist scans run on this *single* ASGI worker every N seconds.
For production/team access, use SSO, a managed DB and an external scheduler.
"""
import asyncio
import base64
import binascii
import json
import logging
import os
import secrets
from contextlib import suppress
from typing import Any

from fastapi import Request, FastAPI
from fastapi.responses import JSONResponse

from app import SOURCES, app as core_app, search

# Wrap the local app instead of mutating an already-started FastAPI instance.
# This also keeps cloud auth middleware independent of local-mode tests.
app = FastAPI(title="VulnScope Cloud Gateway", docs_url=None, redoc_url=None, openapi_url=None)
app.mount("/", core_app)

logger = logging.getLogger("vulnscope-cloud")
USERNAME = os.getenv("VULNSCOPE_USERNAME", "").strip()
PASSWORD = os.getenv("VULNSCOPE_PASSWORD", "")
if not USERNAME or len(PASSWORD) < 14:
    raise RuntimeError("Set VULNSCOPE_USERNAME and a VULNSCOPE_PASSWORD of 14+ characters in Railway Variables")


@app.middleware("http")
async def require_auth(request: Request, call_next):
    # Non-sensitive health endpoint for Railway liveness checks only.
    if request.url.path == "/api/health":
        return await call_next(request)
    authorization = request.headers.get("authorization", "")
    valid = False
    if authorization.startswith("Basic "):
        try:
            raw = base64.b64decode(authorization[6:], validate=True).decode("utf-8")
            user, pwd = raw.split(":", 1)
            valid = secrets.compare_digest(user, USERNAME) and secrets.compare_digest(pwd, PASSWORD)
        except (ValueError, UnicodeDecodeError, binascii.Error):
            pass
    if not valid:
        return JSONResponse(
            {"detail": "Authentication required"}, status_code=401,
            headers={"WWW-Authenticate": 'Basic realm="VulnScope"', "Cache-Control": "no-store"},
        )
    response = await call_next(request)
    response.headers["Cache-Control"] = "no-store"
    return response


def load_watchlist() -> list[dict[str, Any]]:
    raw = os.getenv("VULNSCOPE_WATCHLIST_JSON", "").strip()
    if not raw:
        return []
    try:
        arr = json.loads(raw)
    except json.JSONDecodeError:
        logger.error("Invalid VULNSCOPE_WATCHLIST_JSON (must be a JSON array)")
        return []
    if not isinstance(arr, list) or len(arr) > 30:
        logger.error("Watchlist must contain at most 30 items")
        return []
    output = []
    for row in arr:
        if not isinstance(row, dict):
            continue
        vendor = row.get("vendor")
        version = str(row.get("version") or "").strip()
        hotfix = str(row.get("hotfix") or "").strip()
        if vendor in SOURCES and 0 < len(version) <= 80 and len(hotfix) <= 60:
            output.append({"vendor": vendor, "version": version, "hotfix": hotfix})
    return output


async def watchlist_loop():
    # The original app.search() records matched CVEs in SQLite through tracking.observe().
    targets = load_watchlist()
    if not targets:
        logger.info("Automatic watchlist disabled; configure VULNSCOPE_WATCHLIST_JSON to enable")
        return
    try:
        interval = max(900, int(os.getenv("VULNSCOPE_SCAN_INTERVAL_SECONDS", "10800")))
    except ValueError:
        interval = 10800
    logger.info("Watching %d version targets every %d seconds", len(targets), interval)
    await asyncio.sleep(5)
    while True:
        for target in targets:
            try:
                result = await search(target['vendor'], target['version'], target['hotfix'])
                sources = result.get('sources', [])
                partial = any((not x.get('ok')) or x.get('partial') for x in sources)
                matched = sum(r.get('status') == 'version_match' for r in result.get('rows', []))
                logger.info("CVE refresh vendor=%s version=%s matched=%d partial=%s",
                            target['vendor'], target['version'], matched, partial)
            except Exception as exc:
                logger.warning("CVE refresh failed vendor=%s version=%s error=%s",
                               target['vendor'], target['version'], type(exc).__name__)
            await asyncio.sleep(2)
        await asyncio.sleep(interval)


@app.on_event("startup")
async def start_watchlist():
    app.state.watchlist_task = asyncio.create_task(watchlist_loop())


@app.on_event("shutdown")
async def stop_watchlist():
    task = getattr(app.state, 'watchlist_task', None)
    if task:
        task.cancel()
        with suppress(asyncio.CancelledError):
            await task
