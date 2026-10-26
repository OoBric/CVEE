"""VulnScope Live v1.5: version-matched CVEs with persistent Seen/Updated tracking.
Run: uvicorn app:app --host 127.0.0.1 --port 8000
"""
import asyncio
import os
import re
import time
import json
from datetime import datetime, timezone
from functools import cmp_to_key
from html import unescape
from pathlib import Path
from urllib.parse import urlparse
import xml.etree.ElementTree as ET
from typing import Optional

import httpx
from bs4 import BeautifulSoup
from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from m365_sync import Config as M365Config, SyncError, sync_to_list
import tracking

ROOT = Path(__file__).parent
USER_AGENT = "VulnScopeLive/1.0 (security-advisory-comparison; local self-hosted)"
NVD = "https://services.nvd.nist.gov/rest/json/cves/2.0"
PAN_JSON = "https://security.paloaltonetworks.com/json"
FORTI_RSS = "https://filestore.fortinet.com/fortiguard/rss/ir.xml"
KEV = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
CP_R82_RELEASE_NOTES = "https://sc1.checkpoint.com/documents/Jumbo_HFA/R82/All_Resolved_Issues.html"
# Fallback verified against the Check Point R82 Jumbo Hotfix release notes on
# 2026-10-25. Clearly marked as a dated snapshot when direct fetch fails.
# This is NOT a comprehensive security-fix database; it only backs these CVEs.
CP_R82_VERIFIED_SNAPSHOT = {
    "CVE-2026-93616": 127,
    "CVE-2026-91843": 127,
    "CVE-2026-85102": 126,
    "CVE-2026-85103": 126,
}
# CPE is intentionally broad for Check Point: includes Security Gateway AND Management.
SOURCES = {
    "checkpoint": {"label": "Check Point (Gateway + Management)", "cpe": ["cpe:2.3:*:checkpoint:*"], "default_version": "R82", "default_hotfix": "Take 126"},
    "fortinet": {"label": "Fortinet FortiOS", "cpe": ["cpe:2.3:o:fortinet:fortios"], "default_version": "7.4.8", "default_hotfix": ""},
    "paloalto": {"label": "Palo Alto PAN-OS", "cpe": ["cpe:2.3:o:palo_alto_networks:pan-os"], "default_version": "11.2.7-h20", "default_hotfix": ""},
    "juniper": {"label": "Juniper Junos OS", "cpe": ["cpe:2.3:o:juniper:junos", "cpe:2.3:o:juniper:junos_os"], "default_version": "23.4R2-S3", "default_hotfix": ""},
}
# Vendor-owned domains for identifying reference links.
VENDOR_DOMAINS = {
    "checkpoint": ("checkpoint.com", "support.checkpoint.com"),
    "fortinet": ("fortiguard.com", "fortinet.com"),
    "paloalto": ("paloaltonetworks.com",),
    "juniper": ("juniper.net",),
}

app = FastAPI(title="VulnScope Live", version="2.2.0", description="Live vulnerability lookup with explicit source status")
app.mount("/static", StaticFiles(directory=str(ROOT / "static")), name="static")
_CACHE: dict[str, tuple[float, object]] = {}
_LOCKS: dict[str, asyncio.Lock] = {}


@app.get("/")
def home():
    return FileResponse(ROOT / "static" / "index.html")


@app.get("/api/health")
def health():
    return {"ok": True, "mode": "LIVE", "providers": list(SOURCES), "nvd_api_key": bool(os.getenv("NVD_API_KEY"))}


async def cached(key, ttl, factory):
    saved = _CACHE.get(key)
    if saved and time.monotonic() - saved[0] < ttl:
        return saved[1]
    lock = _LOCKS.setdefault(key, asyncio.Lock())
    async with lock:
        saved = _CACHE.get(key)
        if saved and time.monotonic() - saved[0] < ttl:
            return saved[1]
        result = await factory()
        _CACHE[key] = (time.monotonic(), result)
        return result


async def request_json(client: httpx.AsyncClient, url: str, params: dict | None = None):
    res = await client.get(url, params=params)
    res.raise_for_status()
    return res.json()


def tokenize_version(version: str):
    """Vendor-neutral natural version comparator. Never relies on lexicographic ordering."""
    parts = re.findall(r"\d+|[a-zA-Z]+", str(version or "").lower())
    return tuple((0, int(x)) if x.isdigit() else (1, x) for x in parts)


def cmp_version(a: str, b: str) -> int:
    av, bv = tokenize_version(a), tokenize_version(b)
    for x, y in zip(av, bv):
        if x != y:
            return (x > y) - (x < y)
    return (len(av) > len(bv)) - (len(av) < len(bv))


def compare_panos(a: str, b: str) -> int:
    """PAN-OS hotfix suffix -hN follows base release, within same maintenance build."""
    def parse(v):
        m = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)(?:-h(\d+))?", v.strip().lower())
        if not m:
            return None
        return tuple(map(int, m.group(1, 2, 3))) + (int(m.group(4) or 0),)
    av, bv = parse(a), parse(b)
    return (av > bv) - (av < bv) if av and bv else cmp_version(a, b)


def compare(vendor: str, a: str, b: str) -> int:
    if vendor == "paloalto":
        return compare_panos(a, b)
    return cmp_version(a, b)


def version_in_cpe_match(m: dict, version: str, vendor: str):
    """CPE evidence: 1=explicit version match, 0=excluded, -1=not enough precision.

    An unversioned wildcard CPE is never a version match. Explicit CPE
    updates and ranges must not silently override a mismatch.
    """
    cpe = str(m.get("criteria", "")).lower().split(":")
    if len(cpe) < 6:
        return -1
    exact, update = cpe[5], cpe[6] if len(cpe) > 6 else "*"
    target = version.strip().lower().removeprefix("v")
    bounds = ("versionStartIncluding", "versionStartExcluding", "versionEndIncluding", "versionEndExcluding")
    has_bounds = any(k in m for k in bounds)
    # On PAN-OS, the CPE update identifies the hotfix. On Junos it can
    # identify R/S service-release components. Do not ignore the update.
    if vendor == "paloalto" and update.startswith("h") and update[1:].isdigit():
        exact = exact + "-" + update if exact not in ("*", "-", "") else exact
    elif vendor == "juniper" and re.fullmatch(r"r\d+(?:[_-]?s\d+)?", update):
        exact = exact + update.replace("_", "-") if exact not in ("*", "-", "") else exact
    elif vendor in ("paloalto", "juniper", "fortinet") and update not in ("*", "-", ""):
        return -1
    elif vendor == "checkpoint" and update not in ("*", "-", ""):
        return -1
    if exact not in ("*", "-", ""):
        # PAN-OS update wildcard does NOT necessarily mean a concrete hotfix
        # is affected; prefer vendor affected table for maintenance hotfixes.
        if vendor == "paloalto" and update in ("*", "") and target.startswith(exact + "-h"):
            return -1
        if vendor == "juniper" and update in ("*", "") and target.startswith(exact + "r"):
            return -1
        if exact != target:
            if not has_bounds:
                return 0
            # Exact CPE criterion is not interchangeable with a range for an
            # entirely different version. Continue only if wildcarded.
            return 0
    for name in ("versionStartIncluding", "versionStartExcluding"):
        if name in m:
            comparison = compare(vendor, target, str(m[name]))
            if comparison < 0 or (name == "versionStartExcluding" and comparison == 0):
                return 0
    for name in ("versionEndIncluding", "versionEndExcluding"):
        if name in m:
            comparison = compare(vendor, target, str(m[name]))
            if comparison > 0 or (name == "versionEndExcluding" and comparison == 0):
                return 0
    if exact not in ("*", "-", "") or has_bounds:
        return 1
    return -1


def matches_vendor_cpe(cpe: str, vendor: str) -> bool:
    parts = cpe.lower().split(":")
    if len(parts) < 5:
        return False
    v, p = parts[3], parts[4]
    if vendor == "checkpoint":
        return v in ("checkpoint", "check_point_software_technologies")
    if vendor == "juniper":
        return v in ("juniper", "juniper_networks") and ("junos" in p)
    if vendor == "fortinet":
        return v == "fortinet" and p in ("fortios", "fortigate_firmware")
    return v in ("paloaltonetworks", "palo_alto_networks") and p in ("pan-os", "pan_os")


def score_nvd_configuration(cve: dict, vendor: str, version: str, hotfix: str):
    best = 0
    cited = []
    configurations = cve.get("configurations") or []
    for config in configurations:
        pending = list(config.get("nodes") or [])
        while pending:
            node = pending.pop()
            pending.extend(node.get("children") or [])
            for m in node.get("cpeMatch") or []:
                if not m.get("vulnerable", False) or not matches_vendor_cpe(m.get("criteria", ""), vendor):
                    continue
                status = (cpe_cp_relevance(m, version, hotfix) if vendor == "checkpoint"
                          else version_in_cpe_match(m, version, vendor))
                if status == 0:
                    continue
                score = 2 if status == 1 else 1
                if vendor == "checkpoint":
                    update = str(m.get("criteria", "")).lower().split(":")
                    take_match = re.search(r"take[_-](\d+)", update[6]) if len(update) > 6 else None
                    user_take = re.search(r"(?:take\s*)?(\d+)", hotfix.lower()) if hotfix else None
                    if take_match and user_take and int(take_match.group(1)) != int(user_take.group(1)):
                        continue  # Explicit CPE Take is different; skip this criterion.
                    if hotfix or take_match:
                        score = 1  # Do not assert vulnerability or patch inclusion based on take alone.
                if score > best:
                    best = score
                cited.append({k: m[k] for k in ("criteria", "versionStartIncluding", "versionStartExcluding", "versionEndIncluding", "versionEndExcluding") if k in m})
    return best, cited[:6]


# Only these modern Check Point product families may be considered. Generic
# vendor matching includes legacy Firewall-1 (e.g. 2004 CVEs) and is unsafe.
CHECKPOINT_PRODUCTS = (
    "quantum_security_gateway", "quantum_security_management", "security_gateway",
    "security_management", "security_management_server", "multi-domain_security_management",
    "gaia", "gaia_os", "maestro", "maestro_orchestrator", "vsx",
    "quantum_security_gateway_software", "checkpoint_security_gateway",
)


def cp_release(v):
    m = re.fullmatch(r"r?(\d+)(?:\.(\d+))?", str(v).strip().lower())
    if not m:
        return None
    return (int(m.group(1)), int(m.group(2) or 0))


def cp_take(hotfix):
    m = re.fullmatch(r"\s*(?:take\s*[-_ ]?\s*)?(\d+)\s*", str(hotfix), re.I)
    return int(m.group(1)) if m else None


def checkpoint_version_evidence(text, version, take):
    """0=excluded, 1=review, 2=explicit affected match. Not an exposure assessment.

    Accepts concise *Check Point CNA* version descriptions such as:
      R82 with Jumbo Hotfix Take 125 or below
      R82.10 with Jumbo Hotfix Take 43 or below
    Never conflates R82 and R82.10 or applies lexical Hotfix comparisons.
    """
    raw = str(text).strip()
    target = cp_release(version)
    if not target:
        return 0
    versions = re.findall(r"(?<![\w.])r\d+(?:\.\d+)?(?![\w.])", raw, re.I)
    if not any(cp_release(v) == target for v in versions):
        return 0
    # Descriptions mentioning multiple releases require review (e.g. a range).
    if any(cp_release(v) != target for v in versions):
        return 1
    if re.search(r"\bno\s+(?:jumbo\s+)?hotfix\b", raw, re.I):
        return 0 if take is not None else 1
    upper = re.search(r"(?:jumbo\s+(?:hotfix|hfa)\s+)?take\s*(\d+)\s*(?:or\s*)?(?:below|lower|earlier|less)(?:\s+than)?", raw, re.I)
    lower = re.search(r"(?:jumbo\s+(?:hotfix|hfa)\s+)?take\s*(\d+)\s*(?:or\s*)?(?:above|higher|later|greater)", raw, re.I)
    exact = re.search(r"(?:jumbo\s+(?:hotfix|hfa)\s+)?take\s*(\d+)(?!\s*(?:or|and))", raw, re.I)
    if upper:
        return (2 if take <= int(upper.group(1)) else 0) if take is not None else 1
    if lower:
        return (2 if take >= int(lower.group(1)) else 0) if take is not None else 1
    if exact and not re.search(r"\b(?:below|above|between|through)\b", raw, re.I):
        return (2 if take == int(exact.group(1)) else 0) if take is not None else 1
    # R82 named but no hotfix data; a JHF user cannot be pronounced affected.
    return 1


def vendor_affected_blocks(cve):
    """NVD 2026 CVE-affected extension (separate from NVD CPE configurations)."""
    found = []
    for item in cve.get("affected") or []:
        if isinstance(item, dict):
            found.extend(item.get("affectedData") or [])
    return [x for x in found if isinstance(x, dict)]


def checkpoint_cna_match(cve, version, hotfix):
    """Check Point CNA version evidence, including releases past affected Take.

    2=Take in an explicitly affected range, 1=release with unknown Take impact,
    3=Take beyond a stated affected bound (NOT independently confirmed patched),
    0=no matching release. Official Jumbo release notes decide 'fixed' separately.
    """
    blocks = [x for x in vendor_affected_blocks(cve)
              if str(x.get("vendor", "")).lower().replace(" ", "") in
              ("checkpoint", "checkpointsoftwaretechnologiesltd.", "check_point")]
    if not blocks:
        return None
    take = cp_take(hotfix) if hotfix else None
    target = cp_release(version)
    product_results = []
    for item in blocks:
        product = str(item.get("product", ""))
        pl = product.lower()
        if not any(word in pl for word in ("gateway", "management", "maestro", "gaia", "vsx", "log server", "smartevent")):
            continue
        evidences = []
        for v in item.get("versions") or []:
            if str(v.get("status", "")).lower() != "affected":
                continue
            raw = str(v.get("version", ""))
            releases = re.findall(r"(?<![\w.])r\d+(?:\.\d+)?(?![\w.])", raw, re.I)
            if not target or not any(cp_release(x) == target for x in releases):
                continue
            detail = checkpoint_version_evidence(raw, version, take)
            upper = re.search(r"(?:jumbo\s+(?:hotfix|hfa)\s+)?take\s*(\d+)\s*(?:or\s*)?(?:below|lower|earlier|less)(?:\s+than)?", raw, re.I)
            # If release is R82, and installed Take is beyond vendor's
            # affected upper bound, retain the advisory as out_of_range.
            # An unrelated generic 'R82' row must not override this bound.
            if not detail and upper and take is not None and take > int(upper.group(1)):
                detail = 3
            if detail:
                evidences.append((detail, raw))
        if not evidences:
            continue
        priority = {2: 3, 3: 2, 1: 1}
        best = max(evidences, key=lambda x: priority[x[0]])
        scope = set()
        if "management" in pl or "log server" in pl or "smartevent" in pl:
            scope.add("Management")
        if any(word in pl for word in ("gateway", "maestro", "gaia", "vsx")):
            scope.add("Gateway")
        product_results.append((best[0], product, best[1], scope))
    if not product_results:
        return 0, [], "Unspecified"
    # A possible affected product always takes precedence over a patched
    # component when both Gateway and Management are searched together.
    priority = {2: 3, 1: 2, 3: 1}
    outcome = max((x[0] for x in product_results), key=lambda x: priority[x])
    relevant = [x for x in product_results if x[0] == outcome]
    scopes = set().union(*(x[3] for x in relevant))
    scope = "Gateway + Management" if len(scopes) == 2 else next(iter(scopes), "Unspecified")
    evidence = [p + ": " + v for _, p, v, _ in relevant]
    return outcome, evidence[:12], scope


def affected_product_matches(item, vendor, version):
    """Only accept the requested OS family, not unrelated vendor products."""
    brand = re.sub(r"[^a-z0-9]", "", str(item.get("vendor", "")).lower())
    product = re.sub(r"[^a-z0-9]", "", str(item.get("product", "")).lower())
    if vendor == "fortinet":
        return brand == "fortinet" and product in ("fortios", "fortigatefirmware")
    if vendor == "juniper":
        is_evolved = "evo" in version.lower()
        products = ("junososevolved", "junosevolved") if is_evolved else ("junosos", "junos")
        return brand in ("juniper", "junipernetworks") and product in products
    return False


def cna_version_rule(rule, version, vendor):
    """Interpret a single structured CNA version rule without text guesswork.

    Returns (matches, specificity), with unrecognized formats considered
    unresolved rather than explicitly unaffected.
    """
    if not isinstance(rule, dict):
        return False, 0
    low = str(rule.get("version", "")).strip()
    target = str(version).strip()
    if not low:
        return False, 0
    if low.lower() in ("all", "*"):
        return True, 0
    lt, le = rule.get("lessThan"), rule.get("lessThanOrEqual")
    if lt or le:
        if low not in ("0", "0.0", "-") and compare(vendor, target, low) < 0:
            return False, 0
        bound = str(lt or le)
        diff = compare(vendor, target, bound)
        return (diff < 0 if lt else diff <= 0), 2
    if compare(vendor, target, low) == 0:
        return True, 3
    # A CNA version such as '7.4' means an entire named maintenance branch,
    # but NOT 7.40 or a different Junos train. More precise bounds win.
    if re.fullmatch(r"\d+\.\d+", low):
        if target.lower().startswith(low.lower() + ".") or (vendor == "juniper" and target.lower().startswith(low.lower() + "r")):
            return True, 1
    return False, 0


def vendor_cna_match(cve, vendor, version):
    """Use CVE Program CNA affected data exposed through NVD for Junos/FortiOS.

    2=affected, 0=vendor says unaffected, 1=unknown / not decisive.
    None=there is no relevant vendor affected table (try NVD CPE).
    """
    if vendor not in ("fortinet", "juniper"):
        return None
    products = [p for p in vendor_affected_blocks(cve) if affected_product_matches(p, vendor, version)]
    if not products:
        return None
    candidates = []
    evidence = []
    for product in products:
        product_name = str(product.get("product", ""))
        for item in product.get("versions") or []:
            matched, specificity = cna_version_rule(item, version, vendor)
            if not matched:
                continue
            status = str(item.get("status", "unknown")).lower()
            if status not in ("affected", "unaffected"):
                continue
            candidates.append((specificity, status, item))
        evidence.append(product_name)
    if candidates:
        # Most specific rule wins. On equally specific conflicting CNA rules,
        # treat 'unaffected' as precedence instead of inventing exposure.
        candidates.sort(key=lambda x: (x[0], x[1] == "unaffected"), reverse=True)
        specificity, status, rule = candidates[0]
        rule_string = " ".join(str(rule.get(k, "")) for k in ("version", "lessThan", "lessThanOrEqual") if rule.get(k))
        return (2 if status == "affected" else 0), [f"{evidence[0]}: {rule_string} [{status}]"], ""
    if products and all(str(p.get("defaultStatus", "unknown")).lower() == "unaffected" for p in products):
        return 0, [f"{evidence[0]}: no affected rule matches {version}; CNA default is unaffected"], ""
    return 1, [f"{evidence[0]}: vendor version table does not establish {version}"], ""


def cpe_cp_relevance(m, version, hotfix, cve_description=""):
    """Discard legacy/unversioned Check Point records; never 'match' by vendor name."""
    parts = str(m.get("criteria", "")).lower().split(":")
    if len(parts) < 6 or not any(part in parts[4] for part in CHECKPOINT_PRODUCTS):
        return 0
    exact = parts[5]
    check = cp_release(version)
    if not check:
        return 0
    # CPE can use r82.00 as an alias for R82, but not r82.10.
    if exact not in ("*", "-"):
        release = cp_release(exact)
        if release is not None and release != check:
            return 0
        if release is not None:
            return 1 # CPE lacks reliable cumulative Take inclusion semantics.
        return 0
    # Ranged CPE can be evaluated only when its bounds are parseable.
    bounds = [(k,m[k]) for k in ("versionStartIncluding","versionStartExcluding","versionEndIncluding","versionEndExcluding") if k in m]
    if bounds:
        for k,v in bounds:
            val=cp_release(v)
            if val is None:
                return 0
            if k == "versionStartIncluding" and check < val: return 0
            if k == "versionStartExcluding" and check <= val: return 0
            if k == "versionEndIncluding" and check > val: return 0
            if k == "versionEndExcluding" and check >= val: return 0
        return 1
    # Product-wide wildcard without release evidence is NOT a candidate.
    # Deliberately do not match even if the vendor name or a current keyword appears.
    return 0

def get_metric(cve: dict):
    metrics = cve.get("metrics") or {}
    for kind in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(kind) or []
        if entries:
            entry = next((x for x in entries if x.get("type") == "Primary"), entries[0])
            data = entry.get("cvssData") or {}
            score = data.get("baseScore")
            return (float(score) if score is not None else None,
                    str(data.get("baseSeverity") or entry.get("baseSeverity") or "").upper())
    return None, ""


def severity_of(score, s=""):
    # The numeric CVSS score always wins over inconsistent source-provided labels.
    # CVSS v3/v4 9.0–10.0 = Critical, 7.0–8.9 = High, 4.0–6.9 = Medium.
    if score is not None:
        return "Critical" if score >= 9 else "High" if score >= 7 else "Medium" if score >= 4 else "Low" if score > 0 else "None"
    return s.upper().title() if s.upper() in ("CRITICAL", "HIGH", "MEDIUM", "LOW") else "Unknown"


def best_text(entries):
    if isinstance(entries, str):
        return entries.strip()
    if not isinstance(entries, list):
        return ""
    for entry in entries:
        if isinstance(entry, dict) and entry.get("lang", "en").lower() in ("en", "eng", "en-us"):
            return (entry.get("value") or "").strip()
    return str(entries[0].get("value", "")) if entries and isinstance(entries[0], dict) else ""


def official_reference(cve: dict, vendor: str):
    refs = [x.get("url", "") for x in cve.get("references") or []]
    for link in refs:
        host = urlparse(link).hostname or ""
        if any(host == d or host.endswith("." + d) for d in VENDOR_DOMAINS[vendor]):
            return link
    return refs[0] if refs else "https://nvd.nist.gov/vuln/detail/" + cve.get("id", "")


def determine_checkpoint_scope(cve: dict):
    content = (" ".join([best_text(cve.get("descriptions")), " ".join(x.get("criteria", "") for conf in cve.get("configurations", []) for node in conf.get("nodes", []) for x in node.get("cpeMatch", []))])).lower()
    gateway = any(x in content for x in ("security gateway", "gateway", "vpn", "gaia", "spark", "firewall"))
    management = any(x in content for x in ("management", "smartconsole", "smartevent", "log server", "multi-domain"))
    return "Gateway + Management" if gateway and management else "Management" if management else "Gateway" if gateway else "Unspecified"


def normalize_nvd(item: dict, vendor: str, version: str, hotfix: str):
    cve = item.get("cve", item)
    if cve.get("vulnStatus", "").lower() == "rejected":
        return None
    structured = (checkpoint_cna_match(cve, version, hotfix) if vendor == "checkpoint" else
                  vendor_cna_match(cve, vendor, version) if vendor in ("fortinet", "juniper") else None)
    if structured is not None:
        # A vendor-supplied affected table is more authoritative than a broad NVD CPE.
        match, predicates, scope = structured
        predicates = [{"CNA affected": x} for x in predicates]
        if match == 0:
            return None
        # Unknown CNA evidence can still be supplemented by a precise NVD
        # CPE, but it must never become a version match merely by existence.
        if match == 1:
            cpe_status, cpe_evidence = score_nvd_configuration(cve, vendor, version, hotfix)
            if cpe_status == 2:
                match, predicates = cpe_status, cpe_evidence
    else:
        match, predicates = score_nvd_configuration(cve, vendor, version, hotfix)
        if not match:
            return None
        scope = determine_checkpoint_scope(cve) if vendor == "checkpoint" else ""
    score, raw_severity = get_metric(cve)
    detail = best_text(cve.get("descriptions"))
    return {
        "id": cve.get("id", ""), "title": detail.split(". ")[0][:145] if detail else cve.get("id", ""),
        "description": detail, "severity": severity_of(score, raw_severity), "cvss": score,
        "published": cve.get("published", ""), "updated": cve.get("lastModified", ""),
        "source": "NVD", "source_url": official_reference(cve, vendor),
        "nvd_url": "https://nvd.nist.gov/vuln/detail/" + cve.get("id", ""),
        "status": "version_match" if match == 2 else "outside_affected" if match == 3 else "review",
        "status_reason": (
            "Release matches the advisory, but this Jumbo Take is above the vendor's stated affected range. Not independently verified patched; check official release notes."
            if structured is not None and match == 3 else
            "Check Point CNA explicitly lists this release and Jumbo Take in its affected-version table; device configuration not checked"
            if structured is not None and vendor == "checkpoint" and match == 2 else
            "Vendor CNA affected-version table matches this OS version; model/configuration conditions not assessed"
            if structured is not None and match == 2 else
            "Vendor CNA lists this product, but version applicability needs review"
            if structured is not None else
            "NVD vulnerable CPE version/range matches; device conditions are not checked"
            if match == 2 else
            "NVD mentions the matching release, but Take applicability is unverified; inspect vendor advisory"),
        "scope": scope, "affected": "; ".join(" ".join(str(x) for x in d.values()) for d in predicates)[:1100],
        "fixed": "Not encoded as a trustworthy fixed version in this source. Review official advisory.",
        "workaround": "Not included in NVD structured fields. Open vendor advisory.",
        "vendor_direct": False,
    }


async def fetch_nvd(client, vendor, version, hotfix):
    matches = {}
    diagnostics = []
    limited = False
    sources = SOURCES[vendor]["cpe"]
    # Check Point CNA-published CVEs may have NO NVD CPE because they are
    # Awaiting Analysis. The sourceIdentifier query retrieves their CNA affected
    # tables, including detailed JHF Take thresholds.
    source_ids = {"checkpoint": "cve@checkpoint.com", "fortinet": "psirt@fortinet.com", "juniper": "sirt@juniper.net"}
    searches = ([{"sourceIdentifier": source_ids[vendor]}] if vendor in source_ids else []) + [
        {"virtualMatchString": cpe} for cpe in sources
    ]
    for idx, query in enumerate(searches):
        params = {**query, "resultsPerPage": 2000, "startIndex": 0, "noRejected": ""}
        if os.getenv("NVD_API_KEY"):
            client.headers["apiKey"] = os.environ["NVD_API_KEY"]
        try:
            # 2 pages maximum; partial coverage is prominently displayed if truncated.
            for page in range(2):
                params["startIndex"] = page * 2000
                response = await request_json(client, NVD, params)
                batch = response.get("vulnerabilities") or []
                total = int(response.get("totalResults", len(batch)))
                for item in batch:
                    norm = normalize_nvd(item, vendor, version, hotfix)
                    if norm and norm["id"]:
                        old = matches.get(norm["id"])
                        if not old or (old["status"] == "review" and norm["status"] == "version_match"):
                            matches[norm["id"]] = norm
                if (page + 1) * 2000 >= total or len(batch) < 2000:
                    break
                if page == 1:
                    limited = True
                    diagnostics.append(f"NVD query returned {total} records; only first 4,000 were considered.")
                else:
                    await asyncio.sleep(1 if os.getenv("NVD_API_KEY") else 6)
            diagnostics.append(f"NVD query {idx+1}/{len(searches)} responded ({query}).")
        except Exception as exc:
            diagnostics.append("NVD error for " + str(query) + ": " + clean_error(exc))
            limited = True
        if idx < len(searches) - 1:
            await asyncio.sleep(1 if os.getenv("NVD_API_KEY") else 6)
    return {"rows": list(matches.values()), "ok": any("responded" in x for x in diagnostics),
            "partial": limited, "notes": diagnostics}


def clean_error(exc):
    if isinstance(exc, httpx.HTTPStatusError):
        return f"HTTP {exc.response.status_code}"
    return f"{type(exc).__name__}: {str(exc)[:100]}"


def flatten_pan(raw):
    """Official PAN JSON may return a list, a wrapper, or a CVE 5.0 object."""
    if isinstance(raw, list):
        return raw
    if not isinstance(raw, dict):
        return []
    if raw.get("cveMetadata") or raw.get("cve_id") or raw.get("cve"):
        return [raw]
    for field in ("items", "advisories", "results", "data", "vulnerabilities"):
        data = raw.get(field)
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            return flatten_pan(data)
    return []


def pan_cve5_status(cna, version):
    """Match all PAN-OS CVE 5 affected blocks; never exit on first block.

    Prefer precise PAN-OS version predicates to generic defaultStatus. When
    no rule fits, a CNA 'unaffected' default is respected.
    """
    candidates = []
    defaults = []
    for block in cna.get("affected", []):
        if str(block.get("product", "")).lower() not in ("pan-os", "pan_os"):
            continue
        defaults.append(str(block.get("defaultStatus", "unknown")).lower())
        for v in block.get("versions", []):
            base = str(v.get("version", "")).strip()
            status = str(v.get("status", "unknown")).lower()
            if base.lower() == "all":
                candidates.append(((0, ()), status))
                continue
            if not re.fullmatch(r"\d+\.\d+\.\d+(?:-h\d+)?", base, re.I):
                continue
            end = v.get("lessThan") or v.get("lessThanOrEqual")
            if compare_panos(version, base) < 0:
                continue
            if end and (compare_panos(version, end) >= 0 if v.get("lessThan") else compare_panos(version, end) > 0):
                continue
            for change in sorted(v.get("changes") or [], key=lambda x: tokenize_version(str(x.get("at", "")))):
                at = str(change.get("at", ""))
                if at and compare_panos(version, at) >= 0:
                    status = str(change.get("status", status)).lower()
            candidates.append(((2, tokenize_version(base)), status))
    if candidates:
        candidates.sort(key=lambda x: (x[0], x[1] == "unaffected"), reverse=True)
        return candidates[0][1]
    if defaults and all(x == "unaffected" for x in defaults):
        return "unaffected"
    return "unknown"


def pan_summary_status(rec, version):
    """Read PAN's *real* condensed JSON shape: ID, baseScore, version[], affected[].

    Require a threshold for the SAME maintenance train (e.g. 11.2.7) before
    claiming a hotfix is version matched; other train thresholds are not proof.
    """
    version_labels = rec.get("version") or []
    affected = rec.get("affected") or []
    if not isinstance(version_labels, list) or not isinstance(affected, list):
        return "unknown", ""
    prefix = ".".join(version.lower().split("-h")[0].split(".")[:2])
    base = version.lower().split("-h")[0]
    for label, affected_text in zip(version_labels, affected):
        if str(label).strip().lower() != f"pan-os {prefix}":
            continue
        description = str(affected_text)
        thresholds = re.findall(r"(?<![\w])(?:<=|<|>=|>)\s*(\d+\.\d+\.\d+(?:-h\d+)?)", description, re.I)
        # An affected column usually has '<' constraints. Ignore 'None'.
        same_train = [x for x in thresholds if x.lower().split("-h")[0] == base]
        if not same_train:
            return "unknown", description
        for raw in re.split(r"[,;\n]+", description):
            match = re.search(r"(<=|<|>=|>)\s*(\d+\.\d+\.\d+(?:-h\d+)?)", raw.strip(), re.I)
            if not match or match.group(2).lower().split("-h")[0] != base:
                continue
            sign, bound = match.groups()
            comparison = compare_panos(version, bound)
            correct = (comparison < 0 if sign == "<" else comparison <= 0 if sign == "<=" else
                       comparison > 0 if sign == ">" else comparison >= 0)
            return ("affected" if correct else "unaffected"), raw.strip()
        return "unknown", description
    return "unknown", ""


def normalize_pan(rec, version):
    if "cveMetadata" in rec:
        cna = (rec.get("containers") or {}).get("cna") or {}
        cveid = (rec.get("cveMetadata") or {}).get("cveId", "")
        status = pan_cve5_status(cna, version)
        if status not in ("affected", "unknown"):
            return None
        cvss, sev = None, ""
        for metric in cna.get("metrics", []):
            for kind in ("cvssV4_0", "cvssV3_1", "cvssV3_0"):
                m = metric.get(kind)
                if m:
                    cvss, sev = m.get("baseScore"), m.get("baseSeverity", "")
                    break
            if cvss is not None:
                break
        description = best_text(cna.get("descriptions"))
        return {"id": cveid, "title": cna.get("title") or description[:125],
                "description": description, "severity": severity_of(cvss, sev), "cvss": cvss,
                "published": cna.get("datePublic", ""), "updated": rec.get("cveMetadata", {}).get("dateUpdated", ""),
                "source": "Palo Alto PSIRT", "source_url": f"https://security.paloaltonetworks.com/{cveid}",
                "nvd_url": f"https://nvd.nist.gov/vuln/detail/{cveid}",
                "status": "version_match" if status == "affected" else "review",
                "status_reason": "Official PAN-OS affected-version entry matches" if status == "affected" else "Official PAN-OS applicability not resolved",
                "scope": "", "affected": "; ".join(str(v.get("versions")) for v in cna.get("affected", []) if str(v.get("product", "")).lower() == "pan-os")[:1200],
                "fixed": best_text(cna.get("solutions")) or "Refer to vendor advisory",
                "workaround": best_text(cna.get("workarounds")) or "Refer to vendor advisory",
                "vendor_direct": True}
    # Condensed PSIRT response uses uppercase ID and baseScore (not cve_id/cvss_score).
    cveid = str(rec.get("ID") or rec.get("cve_id") or rec.get("cve") or rec.get("id") or "")
    if not re.fullmatch(r"CVE-\d{4}-\d{4,}", cveid, flags=re.I):
        return None
    raw_score = rec.get("baseScore", rec.get("cvss_score", rec.get("cvss")))
    try:
        score = float(raw_score)
    except (TypeError, ValueError):
        score = None
    status, evidence = pan_summary_status(rec, version)
    if status == "unaffected":
        return None
    text = best_text(rec.get("problem")) or str(rec.get("description") or "See official advisory")
    solution = best_text(rec.get("solution")) or str(rec.get("fixed_versions") or "Refer to advisory")
    workaround = best_text(rec.get("work_around")) or str(rec.get("workarounds") or "Refer to advisory")
    return {"id": cveid, "title": str(rec.get("title") or cveid),
            "description": text, "severity": severity_of(score, str(rec.get("baseSeverity") or rec.get("severity", ""))), "cvss": score,
            "published": str(rec.get("date") or rec.get("published_date") or rec.get("datePublic") or ""),
            "updated": str(rec.get("updated") or rec.get("last_modified_date") or ""), "source": "Palo Alto PSIRT",
            "source_url": f"https://security.paloaltonetworks.com/{cveid}", "nvd_url": f"https://nvd.nist.gov/vuln/detail/{cveid}",
            "status": "version_match" if status == "affected" else "review",
            "status_reason": "PAN PSIRT affected threshold: " + evidence if status == "affected" else "Vendor summary does not establish exact maintenance/hotfix applicability",
            "scope": "", "affected": evidence[:1200] if evidence else "Version applicability not resolved",
            "fixed": solution[:1200], "workaround": workaround[:1200], "vendor_direct": True}


async def fetch_palo(client, version):
    try:
        raw = await request_json(client, PAN_JSON, {"product": "PAN-OS", "version": "PAN-OS " + version})
        items = flatten_pan(raw)
        candidate_rows = [x for x in (normalize_pan(rec, version) for rec in items if isinstance(rec, dict)) if x]
        # Fetch full vendor advisories; the condensed response has less precise
        # affected-version information. Preserve a precisely matched summary if
        # the detail endpoint times out, and expose incomplete enrichment.
        sem = asyncio.Semaphore(4)
        failures = 0
        async def enrich(row):
            nonlocal failures
            async with sem:
                try:
                    obj = await request_json(client, PAN_JSON + "/" + row["id"])
                    detail = normalize_pan(obj, version)
                    if detail is None:
                        # A full CVE JSON may contain a differently structured
                        # version table. An explicit "unaffected" result takes
                        # precedence; an unparseable record does not erase a
                        # independently verified maintenance-train threshold.
                        if isinstance(obj, dict) and "cveMetadata" in obj:
                            cna = (obj.get("containers") or {}).get("cna") or {}
                            if pan_cve5_status(cna, version) == "unknown":
                                return row
                        return None
                    if row["status"] == "version_match" and detail["status"] == "review":
                        detail["status"] = "version_match"
                        detail["status_reason"] = row["status_reason"]
                        detail["affected"] = row["affected"]
                    return detail
                except Exception:
                    failures += 1
                    return row
        enriched = await asyncio.gather(*(enrich(r) for r in candidate_rows[:65]))
        rows = [x for x in enriched if x] + candidate_rows[65:]
        return {"rows": rows, "ok": True, "partial": failures > 0 or len(candidate_rows) > 65,
                "notes": [f"Official PAN PSIRT JSON: {len(items)} condensed advisories, {len(candidate_rows)} parsed, {len(rows)} retained; {failures} full-advisory requests failed; first 65 rechecked."]}
    except Exception as exc:
        return {"rows": [], "ok": False, "partial": True, "notes": ["Palo Alto PSIRT unavailable: " + clean_error(exc)]}


def forti_rss_items(xml):
    root = ET.fromstring(xml)
    items = []
    for el in root.findall(".//item"):
        title = (el.findtext("title") or "").strip()
        link = (el.findtext("link") or "").strip()
        if not link.startswith("https://"):
            continue
        if not any((urlparse(link).hostname or "").endswith(domain) for domain in ("fortiguard.com", "fortinet.com")):
            continue
        items.append({"title": title, "link": link, "date": (el.findtext("pubDate") or "").strip()})
    return items


def forti_advisory_html(html, link, version):
    soup = BeautifulSoup(html, "html.parser")
    for x in soup(["script", "style", "nav", "footer", "header"]):
        x.decompose()
    full = soup.get_text(" ", strip=True)
    cves = list(dict.fromkeys(re.findall(r"CVE-\d{4}-\d{4,}", full)))
    if not cves:
        return []
    # Version is matched as whole sequence; not random substring (e.g. 7.4.8 vs 7.4.80).
    variant = rf"(?<!\d){re.escape(version)}(?![\d.])"
    if not re.search(r"FortiOS", full, re.I):
        return []
    contains_version = bool(re.search(variant, full, re.I))
    score = None
    metric = re.search(r"CVSS(?:v[34](?:\.\d)?)?\s*(?:Base\s*)?Score\s*[:\s]+(\d+(?:\.\d+)?)", full, re.I)
    if metric:
        score = float(metric.group(1))
    sev_match = re.search(r"\b(Critical|High|Medium|Low)\s+Severity\b", full, re.I)
    sev = severity_of(score, sev_match.group(1) if sev_match else "")
    # Workaround and solution are extracted from the advisory text, not generated.
    def section(key):
        m = re.search(rf"\b{key}\b\s*[:\-]?\s*(.{{0,900}}?)(?=\b(?:Timeline|References|Affected Products|Solution|Workaround|Description|Summary|Acknowledgement|Acknowledgment)\b|$)", full, re.I)
        return (m.group(1).strip() if m else "")[:800]
    desc = section("Description") or full[:700]
    fixed = section("Solution") or "Open official PSIRT advisory for fixed versions"
    workaround = section("Workaround") or "Open official PSIRT advisory for mitigation"
    title = soup.title.get_text(" ", strip=True) if soup.title else "Fortinet PSIRT advisory"
    return [{"id": cve, "title": title[:145], "description": desc[:1500],
             "severity": sev, "cvss": score, "published": "", "updated": "", "source": "Fortinet PSIRT RSS",
             "source_url": link, "nvd_url": f"https://nvd.nist.gov/vuln/detail/{cve}",
             "status": "review", "status_reason": "Version string found on advisory page; affected vs fixed context requires review" if contains_version else "PSIRT advisory mentions FortiOS but exact version not resolved",
             "scope": "", "affected": f"FortiOS; version {version} mentioned" if contains_version else "FortiOS applicability requires review",
             "fixed": fixed, "workaround": workaround, "vendor_direct": True}
            for cve in cves] if contains_version else []


async def fetch_fortinet(client, version):
    try:
        resp = await client.get(FORTI_RSS)
        resp.raise_for_status()
        items = forti_rss_items(resp.text)
    except Exception as exc:
        return {"rows": [], "ok": False, "partial": True,
                "notes": ["Fortinet RSS unavailable: " + clean_error(exc)]}
    results = []
    errors = 0
    # RSS is a rolling feed, not a complete CVE database. NVD supplies historical results.
    for item in items[:15]:
        try:
            resp = await client.get(item["link"], timeout=7)
            resp.raise_for_status()
            parsed = forti_advisory_html(resp.text, item["link"], version)
            for row in parsed:
                row["published"] = item["date"]
            results.extend(parsed)
        except Exception:
            errors += 1
        # Do not hammer vendor PSIRT.
        await asyncio.sleep(0.15)
    return {"rows": results, "ok": True, "partial": errors > 0 or len(items) > 15,
            "notes": [f"Fortinet rolling RSS: checked {min(15, len(items))}/{len(items)} advisory links; {errors} failed. Not a historical inventory."]}


async def fetch_kev(client):
    try:
        obj = await request_json(client, KEV)
        return {str(row.get("cveID", "")) for row in obj.get("vulnerabilities", [])}
    except Exception:
        return set()


def parse_checkpoint_r82_fixed_takes(html):
    """Extract CVE fixes grouped by Jumbo Take from Check Point's release notes.

    Count only 'Resolved CVE-ID' entries under an explicit 'Take N Released on'
    section. This is a positive evidence source, not a general CVE scraper.
    """
    soup = BeautifulSoup(html, "html.parser")
    for tag in soup(["script", "style", "nav", "footer", "header"]):
        tag.decompose()
    text = soup.get_text(" ", strip=True)
    boundaries = list(re.finditer(r"\bTake\s+(\d+)\s+Released on\s+\d{1,2}\s+[A-Za-z]+\s+\d{4}", text, re.I))
    fixed = {}
    for idx, boundary in enumerate(boundaries):
        take = int(boundary.group(1))
        section = text[boundary.end():(boundaries[idx+1].start() if idx+1 < len(boundaries) else len(text))]
        for match in re.finditer(r"\bResolved\s+(CVE-\d{4}-\d{4,})\b", section, re.I):
            cid = match.group(1).upper()
            # If an entry appears in more than one take, keep the first fix.
            if cid not in fixed or take < fixed[cid]:
                fixed[cid] = take
    return fixed


async def fetch_checkpoint_fixes(client, version):
    """Live Check Point JHF fix registry plus explicit dated snapshot fallback."""
    if cp_release(version) != (82, 0):
        return {"fixes": {}, "url": "", "ok": False, "partial": True,
                "notes": ["R82 Jumbo fix notes cannot be applied to a different Check Point release."]}
    try:
        resp = await client.get(CP_R82_RELEASE_NOTES)
        resp.raise_for_status()
        fixes = parse_checkpoint_r82_fixed_takes(resp.text)
        if not fixes:
            raise ValueError("No verified 'Resolved CVE' entries found in vendor release notes")
        return {"fixes": fixes, "url": CP_R82_RELEASE_NOTES, "ok": True, "partial": True,
                "notes": [f"Official R82 Jumbo release notes parsed ({len(fixes)} CVE fixes). May omit separate hotfixes and non-Jumbo fixes."]}
    except Exception as exc:
        return {"fixes": dict(CP_R82_VERIFIED_SNAPSHOT), "url": CP_R82_RELEASE_NOTES,
                "ok": False, "partial": True, "snapshot": True,
                "notes": ["Check Point release-notes fetch failed (" + clean_error(exc) + "). Using a limited vendor-verified snapshot dated 2026-10-25; not a complete or current fix index."]}


def apply_checkpoint_fix_evidence(rows, fixes_result, hotfix):
    """Patch a release-relevant row only with positive cumulative Take evidence."""
    take = cp_take(hotfix)
    if take is None:
        return rows
    for row in rows:
        fixed_take = fixes_result.get("fixes", {}).get(row.get("id", "").upper())
        if fixed_take is None:
            continue
        row["fixed"] = f"R82 Jumbo Hotfix Take {fixed_take} or newer (same R82 JHF line); consult Check Point release notes."
        row["fix_evidence_url"] = fixes_result.get("url", CP_R82_RELEASE_NOTES)
        row["fix_evidence_source"] = "dated 2026-10-25 snapshot" if fixes_result.get("snapshot") else "live Check Point Jumbo release notes"
        if take >= fixed_take:
            row["status"] = "fixed_by_hotfix"
            row["status_reason"] = (f"R82 Take {take} includes the CVE fix first listed in Jumbo Take {fixed_take}. "
                                    f"Evidence: {row['fix_evidence_source']}. This assumes the specified Jumbo Take is installed on the relevant product; special private hotfixes/configuration not inspected.")
        elif row.get("status") == "outside_affected":
            row["status"] = "review"
            row["status_reason"] = (f"R82 Take {take} is older than the resolved Take {fixed_take}, but source affected-version rule conflicts. Review vendor advisory.")
    return rows


def merge_rows(parts):
    ordered = {}
    for entry in parts:
        for row in entry.get("rows", []):
            id = row.get("id", "").upper()
            if not re.fullmatch(r"CVE-\d{4}-\d{4,}", id):
                continue
            row["id"] = id
            if id not in ordered:
                ordered[id] = row
                continue
            old = ordered[id]
            vendor_row = row if row.get("vendor_direct") else old if old.get("vendor_direct") else None
            if vendor_row:
                other = old if vendor_row is row else row
                combined = dict(other)
                for key, value in vendor_row.items():
                    if value not in (None, ""):
                        combined[key] = value
                # Conservative: don't override a strong NVD range match with a less-specific page mention.
                if other.get("status") == "version_match" and vendor_row.get("status") == "review":
                    combined["status"] = "version_match"
                    combined["status_reason"] = "NVD CPE version match; vendor PSIRT advisory available"
                ordered[id] = combined
            elif row.get("status") == "version_match":
                ordered[id] = row
    return list(ordered.values())


@app.get("/api/vendors")
def vendors():
    return SOURCES


@app.get("/api/search")
async def search(
    vendor: str = Query(...),
    version: str = Query(..., min_length=1, max_length=80),
    hotfix: str = Query("", max_length=60),
):
    if vendor not in SOURCES:
        raise HTTPException(400, detail="Unsupported vendor")
    if not re.fullmatch(r"[a-zA-Z0-9._\- ]+", version) or not re.fullmatch(r"[a-zA-Z0-9._\- ]*", hotfix):
        raise HTTPException(400, detail="Invalid version or hotfix format")
    version, hotfix = version.strip(), hotfix.strip()
    valid_versions = {
        "checkpoint": r"R\d+(?:\.\d+)?",
        "fortinet": r"\d+\.\d+\.\d+",
        "paloalto": r"\d+\.\d+\.\d+(?:-h\d+)?",
        "juniper": r"\d+\.\d+[Rr]\d+(?:-[Ss]\d+(?:\.\d+)?)?(?:-[Ee][Vv][Oo])?",
    }
    if not re.fullmatch(valid_versions[vendor], version, re.I):
        raise HTTPException(400, detail=f"Invalid {vendor} OS version format")
    if vendor == "checkpoint":
        if hotfix and cp_take(hotfix) is None:
            raise HTTPException(400, detail="Check Point Hotfix must look like Take 126")
    elif vendor == "paloalto" and hotfix:
        value = hotfix.lower().lstrip("-")
        if not re.fullmatch(r"h\d+", value):
            raise HTTPException(400, detail="PAN-OS hotfix must look like h21")
        installed = re.search(r"-h(\d+)$", version, re.I)
        if installed and int(installed.group(1)) != int(value[1:]):
            raise HTTPException(400, detail="PAN-OS version and Hotfix field disagree")
        if not installed:
            version += "-" + value
    elif vendor == "juniper" and hotfix:
        value = hotfix.upper().lstrip("-")
        if not re.fullmatch(r"S\d+(?:\.\d+)?", value):
            raise HTTPException(400, detail="Junos service release must look like S3")
        if re.search(r"-S\d+", version, re.I):
            if not re.search(r"-"+re.escape(value)+r"(?:-EVO)?$", version, re.I):
                raise HTTPException(400, detail="Junos version and service release disagree")
        else:
            version = re.sub(r"(-EVO)?$", lambda m: "-"+value+(m.group(1) or ""), version, flags=re.I)
    elif vendor == "fortinet" and hotfix:
        raise HTTPException(400, detail="FortiOS build/hotfix is not supported separately. Use the full FortiOS version; don't infer build patch status.")
    key = f"search:{vendor}:{version}:{hotfix}"
    async def run():
        async with httpx.AsyncClient(timeout=httpx.Timeout(22, connect=8),
                                     headers={"User-Agent": USER_AGENT, "Accept": "application/json, text/html, application/xml, text/xml"},
                                     follow_redirects=True) as client:
            work = [fetch_nvd(client, vendor, version, hotfix)]
            if vendor == "paloalto":
                work.append(fetch_palo(client, version))
            if vendor == "fortinet":
                work.append(fetch_fortinet(client, version))
            if vendor == "checkpoint":
                work.append(cached("cp_r82_fixes:" + version, 3600, lambda: fetch_checkpoint_fixes(client, version)))
            work.append(cached("kev", 3600, lambda: fetch_kev(client)))
            all_items = await asyncio.gather(*work, return_exceptions=True)
            kev = all_items[-1] if isinstance(all_items[-1], set) else set()
            fix_info = (all_items[-2] if vendor == "checkpoint" and isinstance(all_items[-2], dict) else {})
            names = ["NVD"] + (["Palo Alto PSIRT"] if vendor == "paloalto" else ["Fortinet PSIRT"] if vendor == "fortinet" else [])
            named_parts = [(name, item if isinstance(item, dict) else {"rows": [], "ok": False, "partial": True, "notes": ["Source task failed: " + clean_error(item)]}) for name, item in zip(names, all_items[:-1])]
            parts = [item for _, item in named_parts]
            rows = merge_rows(parts)
            if vendor == "checkpoint":
                rows = apply_checkpoint_fix_evidence(rows, fix_info, hotfix)
            for row in rows:
                row["known_exploited"] = row["id"] in kev
            rows.sort(key=lambda x: (-(x["cvss"] if x["cvss"] is not None else -1), x.get("id", "")))
            return {
                "mode": "LIVE", "vendor": vendor, "version": version, "hotfix": hotfix,
                "checked_at": datetime.now(timezone.utc).isoformat(),
                "rows": rows,
                "sources": [{"name": name, **{k: v for k, v in part.items() if k != "rows"}} for name, part in named_parts]
                + ([{"name": "Check Point R82 Jumbo release notes", "ok": bool(fix_info.get("ok")),
                     "partial": bool(fix_info.get("partial", True)), "notes": fix_info.get("notes", ["No release notes data"])}]
                   if vendor == "checkpoint" else []),
                "kev_loaded": bool(kev),
                "complete": False,  # CVE coverage cannot be proven by successful HTTP requests.
                "notice": "Advisory candidates only. Check Point 'Fixed by JHF' uses published cumulative Take evidence; it does not verify device state. Zero results never means safe. API coverage is incomplete.",
            }
    result = await cached(key, 900, run)
    # Cached search objects must not be mutated by per-user/persistent read status.
    # CVEs outside version_match remain excluded from the personal tracker.
    from copy import deepcopy
    response = deepcopy(result)
    annotations = tracking.observe(vendor, response['version'], response['hotfix'], response['rows'])
    for row in response['rows']:
        if row['id'] in annotations:
            row.update(annotations[row['id']])
    return response


class TrackingMarkRequest(BaseModel):
    vendor: str
    version: str = Field(min_length=1, max_length=80)
    hotfix: str = Field(default='', max_length=60)
    cve_ids: list[str] = Field(min_length=1, max_length=250)
    seen: bool = True


@app.post('/api/tracking/mark')
def tracking_mark(request: TrackingMarkRequest):
    if request.vendor not in SOURCES:
        raise HTTPException(status_code=400, detail='Unsupported vendor')
    try:
        items = tracking.mark(request.vendor, request.version, request.hotfix, request.cve_ids, request.seen)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from None
    return {'updated': items, 'count': len(items)}


# Microsoft 365 integration: sync to a MICROSOFT LIST / SHAREPOINT LIST, not a Loop table.
# Disabled by default; requires site-scoped Microsoft Graph permissions.
class M365SyncRequest(BaseModel):
    vendor: str
    version: str
    hotfix: str = ""
    severities: list[str] = Field(default_factory=lambda: ["Critical", "High", "Medium"])


@app.get("/api/m365/status")
def m365_status():
    config = M365Config.from_env()
    return {
        "enabled": config.enabled,
        "configured": config.ready(),
        "destination": "Microsoft List (linked from Loop; NOT a Loop table)",
        "automatic": config.ready(),
    }


@app.post("/api/m365/sync")
async def m365_sync(request: M365SyncRequest):
    conf = M365Config.from_env()
    if not conf.ready():
        raise HTTPException(status_code=503, detail="Microsoft Lists sync is not configured/enabled")
    # Reuse existing server-side CVE search; never trust browser-supplied rows.
    # In particular, only version_match rows are written; fixed/review are excluded.
    result = await search(request.vendor, request.version, request.hotfix)
    try:
        sync = await sync_to_list(
            request.vendor, request.version, request.hotfix,
            result["rows"], severities=request.severities, config=conf,
        )
    except SyncError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from None
    return {
        **sync,
        "coverage_partial": any(not src.get("ok") or src.get("partial") for src in result["sources"]),
        "checked_at": result["checked_at"],
        "notice": "Only confirmed version-match candidates synced. CVE coverage cannot be guaranteed. Existing Owner/Status/Remark columns are preserved.",
    }
