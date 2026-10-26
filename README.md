# VulnScope Cinematic v2.3

> See **V2_3_FIX_NOTES.md** for critical fixes to PAN-OS version comparison and advisory coverage. Tested with 55 simulated tests; live completeness not guaranteed.

# VulnScope Cinematic v2.2 — All Vendor Matching Update

**Four vendors. One command center.** A redesigned version-first firewall CVE lookup built on the existing tested VulnScope backend.

**Important:** v2.2 revises Check Point, Fortinet, Palo Alto and Juniper matching logic. Read `ALL_VENDOR_FIX_NOTES.md` for source coverage, vendor-specific behavior and limitations. This does not guarantee detection of every CVE.

## What changed

- Cinematic dark look based on palette **#06141B · #11212D · #253745 · #4A5C6A · #9BA8AB · #CCD0CF**, cyan/pink accent `#06B6D4 → #EC4899`, subtle violet ambience.
- 3D rotating four-face vendor cube with `perspective: 2000px`; rotation pauses on hover; respects reduced-motion preferences.
- Fixed blended navigation, bold uppercase editorial type, glass panels, responsive scanner dashboard, detailed CVE drawer.
- Preserved existing **live-source** API queries for Check Point (Gateway + Management), Fortinet, Palo Alto, Juniper.
- Retained only `version_match` records in the UI; Critical / High / Medium filters, keyword/sorting, CSV export.
- Retained **NEW / UPDATED / SEEN** tracker in SQLite, and optional Microsoft Lists sync (not native Loop).
- Retained single-user cloud HTTP Basic login and optional in-process watchlist refresh.
- Fixed a pre-existing cloud integration test issue by wrapping the local FastAPI app instead of attaching cloud middleware to an already-started instance.

## Deploy online

**Read [`RAILWAY_DEPLOY.md`](RAILWAY_DEPLOY.md)**. The repo has everything needed for a Railway Docker build: `Dockerfile`, `railway.json`, Python backend, static frontend, and startup command. Deploy via a private GitHub repo, set password variables and attach persistent `/data` volume.

## Run on a Windows laptop

Install Python 3.10+ and double-click `START_WINDOWS.bat`. Then open http://127.0.0.1:8000. Local mode only binds to loopback and doesn't require cloud login. For Linux/macOS run `sh START_MAC_LINUX.sh`. This is useful for preview, but does **not** deploy the site online.

## Testing

```bash
pip install -r requirements.txt -r requirements-dev.txt
pytest -q
```

Tested: 49 Python regression tests passing (including mock CNA/NVD schemas across all four vendors); browser UI smoke tests with mock API responses exercised search, CVE detail, severity counters, Seen tab and Mark Seen. **No external live NVD/vendor API end-to-end validation in this packaging environment**. Treat upstream errors as incomplete results, not no vulnerabilities. This is *not* a certified patch/exposure assessment.

## Other docs

- `SEEN_TRACKING_GUIDE.md` — tracker persistence, read states and backup.
- `MICROSOFT_365_SETUP.md` — optional Microsoft Lists sync.
- `ALL_VENDOR_FIX_NOTES.md` — four-vendor matching changes and limits.
- `m365.local.env.example` — optional M365 config template.
