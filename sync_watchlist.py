"""One-shot CVE watchlist sync; schedule this with Windows Task Scheduler if desired.

This writes to a Microsoft List, not directly into Microsoft Loop tables.
"""
import asyncio
import json
import sys
from pathlib import Path

from app import search
from m365_sync import Config, SyncError, sync_to_list

ROOT = Path(__file__).parent
VALID_VENDORS = {"checkpoint", "paloalto", "fortinet", "juniper"}


async def main():
    conf = Config.from_env()
    if not conf.ready():
        print("Microsoft Lists integration not enabled/configured. See MICROSOFT_365_SETUP.md")
        return 2
    path = ROOT / "watchlist.json"
    if not path.exists():
        print("Missing watchlist.json. Copy watchlist.example.json, then edit the desired vendor/version/takes.")
        return 2
    try:
        targets = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        print("Invalid watchlist JSON:", type(exc).__name__)
        return 2
    if not isinstance(targets, list) or not 1 <= len(targets) <= 50:
        print("Watchlist must contain between 1 and 50 version targets")
        return 2
    failed = 0
    for entry in targets:
        if not isinstance(entry, dict):
            failed += 1
            continue
        vendor = str(entry.get("vendor") or "").strip()
        version = str(entry.get("version") or "").strip()
        hotfix = str(entry.get("hotfix") or "").strip()
        risks = entry.get("severities", ["Critical", "High", "Medium"])
        if vendor not in VALID_VENDORS or not version or not isinstance(risks, list):
            print("Skipping invalid watchlist target")
            failed += 1
            continue
        try:
            result = await search(vendor, version, hotfix)
            summary = await sync_to_list(vendor, version, hotfix, result["rows"], risks, conf)
            coverage = " (SOURCES PARTIAL)" if any(not x.get("ok") or x.get("partial") for x in result.get("sources", [])) else ""
            print(f"{vendor} {version} {hotfix}: {summary['created']} created, {summary['updated']} updated, {summary['matched']} matched{coverage}")
        except Exception as exc:
            # No secrets or source HTTP response bodies in output.
            print(f"{vendor} {version}: ERROR {type(exc).__name__}: {exc if isinstance(exc, SyncError) else 'CVEs not synced'}")
            failed += 1
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
