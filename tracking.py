"""Persistent personal read/updated flags for version-matched CVEs.

Local single-instance sqlite store. It is not an authenticated multi-user service.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

DEFAULT_DB_PATH = Path(__file__).resolve().parent / 'data' / 'cve_tracking.sqlite3'
TRACKED_FIELDS = ('title', 'description', 'severity', 'cvss', 'affected', 'fixed',
                  'workaround', 'updated', 'known_exploited', 'scope', 'source_url')
CVE_RE = re.compile(r'^CVE-\d{4}-\d{4,}$', re.I)


def database_path():
    return Path(os.getenv('VULNSCOPE_DB_PATH') or str(DEFAULT_DB_PATH))


def connect():
    path = database_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    cx = sqlite3.connect(str(path), timeout=10)
    cx.row_factory = sqlite3.Row
    cx.execute('PRAGMA busy_timeout=10000')
    cx.execute('''CREATE TABLE IF NOT EXISTS cve_read_state (
        vendor TEXT NOT NULL, version TEXT NOT NULL, hotfix TEXT NOT NULL,
        cve_id TEXT NOT NULL, first_detected TEXT NOT NULL,
        last_detected TEXT NOT NULL, current_digest TEXT NOT NULL,
        acknowledged_digest TEXT, acknowledged_at TEXT,
        ever_seen INTEGER NOT NULL DEFAULT 0,
        manual_unread INTEGER NOT NULL DEFAULT 0,
        PRIMARY KEY (vendor, version, hotfix, cve_id)
    )''')
    return cx


def normalize_key(vendor, version, hotfix, cve_id):
    v = str(vendor).strip().lower()
    ver = ' '.join(str(version).strip().lower().split())
    h = ' '.join(str(hotfix or '').strip().lower().split())
    cve = str(cve_id).strip().upper()
    if not CVE_RE.fullmatch(cve):
        raise ValueError('Invalid CVE ID')
    if not ver or len(ver) > 80 or len(h) > 60 or len(v) > 40:
        raise ValueError('Invalid version, hotfix or vendor')
    return v, ver, h, cve


def content_digest(row):
    """Changes only for source advisory content, never for fetch time / UI order.

    Normalizing whitespace prevents spurious alerts on HTML/source formatting.
    """
    def stable(x):
        if isinstance(x, str):
            return ' '.join(x.split())
        return x
    tracked = {field: stable(row.get(field)) for field in TRACKED_FIELDS}
    serialized = json.dumps(tracked, ensure_ascii=False, sort_keys=True, separators=(',', ':'), default=str)
    return hashlib.sha256(serialized.encode('utf-8')).hexdigest()


def read_status(row):
    if row['acknowledged_digest'] is not None:
        return 'seen' if row['acknowledged_digest'] == row['current_digest'] else 'updated'
    return 'unread' if row['ever_seen'] or row['manual_unread'] else 'new'


def observe(vendor, version, hotfix, rows):
    """Register version-matched CVEs only and annotate them with persisted flags.

    Never delete records when upstream is incomplete or a CVE stops matching.
    """
    now = datetime.now(timezone.utc).isoformat()
    with connect() as cx:
        output = {}
        for row in rows:
            if row.get('status') != 'version_match':
                continue
            key = normalize_key(vendor, version, hotfix, row['id'])
            digest = content_digest(row)
            old = cx.execute('''SELECT * FROM cve_read_state WHERE vendor=? AND version=? AND hotfix=? AND cve_id=?''', key).fetchone()
            if old is None:
                cx.execute('''INSERT INTO cve_read_state (
                    vendor, version, hotfix, cve_id, first_detected, last_detected, current_digest)
                    VALUES (?, ?, ?, ?, ?, ?, ?)''', (*key, now, now, digest))
            else:
                cx.execute('''UPDATE cve_read_state SET last_detected=?, current_digest=?
                    WHERE vendor=? AND version=? AND hotfix=? AND cve_id=?''', (now, digest, *key))
            current = cx.execute('''SELECT * FROM cve_read_state WHERE vendor=? AND version=? AND hotfix=? AND cve_id=?''', key).fetchone()
            output[row['id']] = {
                'read_state': read_status(current),
                'first_detected': current['first_detected'],
                'acknowledged_at': current['acknowledged_at'],
            }
    return output


def mark(vendor, version, hotfix, cve_ids, seen):
    if len(cve_ids) > 250:
        raise ValueError('Maximum 250 CVEs per request')
    if not cve_ids:
        raise ValueError('Provide at least one CVE ID')
    now = datetime.now(timezone.utc).isoformat()
    unique = list(dict.fromkeys(str(x).upper() for x in cve_ids))
    updated = {}
    with connect() as cx:
        for cve_id in unique:
            key = normalize_key(vendor, version, hotfix, cve_id)
            row = cx.execute('''SELECT * FROM cve_read_state WHERE vendor=? AND version=? AND hotfix=? AND cve_id=?''', key).fetchone()
            if row is None:
                raise ValueError(f'{cve_id} has not been observed for this version')
        for cve_id in unique:
            key = normalize_key(vendor, version, hotfix, cve_id)
            if seen:
                cx.execute('''UPDATE cve_read_state SET acknowledged_digest=current_digest,
                    acknowledged_at=?, ever_seen=1, manual_unread=0
                    WHERE vendor=? AND version=? AND hotfix=? AND cve_id=?''', (now, *key))
            else:
                cx.execute('''UPDATE cve_read_state SET acknowledged_digest=NULL,
                    manual_unread=1 WHERE vendor=? AND version=? AND hotfix=? AND cve_id=?''', key)
            current = cx.execute('''SELECT * FROM cve_read_state WHERE vendor=? AND version=? AND hotfix=? AND cve_id=?''', key).fetchone()
            updated[cve_id] = {'read_state': read_status(current),
                               'first_detected': current['first_detected'],
                               'acknowledged_at': current['acknowledged_at']}
    return updated
