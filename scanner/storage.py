"""SQLite persistence: scan history (for history/diff/monitoring) and a WHOIS cache."""
import json
import os
import sqlite3
import time
from contextlib import contextmanager

import config

_SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id TEXT PRIMARY KEY,
    url TEXT NOT NULL,
    host TEXT,
    batch_id TEXT,
    created_at REAL NOT NULL,
    status TEXT NOT NULL,
    risk_score INTEGER,
    verdict TEXT,
    grade TEXT,
    options_json TEXT,
    progress_json TEXT,
    result_json TEXT
);
CREATE INDEX IF NOT EXISTS idx_scans_url ON scans(url, created_at);
CREATE INDEX IF NOT EXISTS idx_scans_batch ON scans(batch_id);
CREATE TABLE IF NOT EXISTS batches (
    id TEXT PRIMARY KEY,
    created_at REAL NOT NULL,
    meta_json TEXT
);
CREATE TABLE IF NOT EXISTS whois_cache (
    domain TEXT PRIMARY KEY,
    fetched_at REAL NOT NULL,
    data_json TEXT NOT NULL
);
"""
_initialised = set()
WHOIS_TTL = 24 * 3600


@contextmanager
def _db():
    path = config.DB_PATH
    if path not in _initialised:
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    conn = sqlite3.connect(path, timeout=15)
    conn.row_factory = sqlite3.Row
    try:
        if path not in _initialised:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript(_SCHEMA)
            _initialised.add(path)
        yield conn
        conn.commit()
    finally:
        conn.close()


def create_scan(scan_id, url, host="", options=None, batch_id=None):
    with _db() as c:
        c.execute("INSERT INTO scans (id, url, host, batch_id, created_at, status, options_json, progress_json) "
                  "VALUES (?, ?, ?, ?, ?, 'running', ?, '{}')",
                  (scan_id, url, host, batch_id, time.time(), json.dumps(options or {})))


def create_batch(batch_id, meta=None):
    """A group of scans submitted together; meta holds e.g. the parsed e-mail they came from."""
    with _db() as c:
        c.execute("INSERT INTO batches (id, created_at, meta_json) VALUES (?, ?, ?)",
                  (batch_id, time.time(), json.dumps(meta or {}, default=str)))


def get_batch(batch_id):
    with _db() as c:
        r = c.execute("SELECT id, created_at, meta_json FROM batches WHERE id=?", (batch_id,)).fetchone()
    if r is None:
        return None
    return {"id": r["id"], "created_at": r["created_at"], "meta": json.loads(r["meta_json"] or "{}")}


def mark_stale_running(max_age=900):
    """Scans left 'running' by a restarted process will never finish; close them as errors."""
    with _db() as c:
        rows = c.execute("SELECT id, url FROM scans WHERE status='running' AND created_at<?",
                         (time.time() - max_age,)).fetchall()
        for r in rows:
            result = {"id": r["id"], "url": r["url"], "error": "scan was interrupted (server restarted)",
                      "verdict": "Error", "risk_score": None, "grade": "N/A", "findings": [], "sections": {}}
            c.execute("UPDATE scans SET status='error', verdict='Error', grade='N/A', result_json=? WHERE id=?",
                      (json.dumps(result), r["id"]))
        return len(rows)


def update_progress(scan_id, progress):
    with _db() as c:
        c.execute("UPDATE scans SET progress_json=? WHERE id=?", (json.dumps(progress), scan_id))


def save_result(scan_id, result):
    status = "error" if result.get("error") else "done"
    with _db() as c:
        cur = c.execute("UPDATE scans SET status=?, risk_score=?, verdict=?, grade=?, result_json=?, url=?, host=? "
                        "WHERE id=?",
                        (status, result.get("risk_score"), result.get("verdict"), result.get("grade"),
                         json.dumps(result, default=str), result["url"], result.get("host", ""), scan_id))
        if cur.rowcount == 0:
            c.execute("INSERT INTO scans (id, url, host, created_at, status, risk_score, verdict, grade, "
                      "options_json, progress_json, result_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, '{}', ?)",
                      (scan_id, result["url"], result.get("host", ""), time.time(), status, result.get("risk_score"),
                       result.get("verdict"), result.get("grade"), json.dumps(result.get("options", {})),
                       json.dumps(result, default=str)))


def _row(r):
    if r is None:
        return None
    d = dict(r)
    for k in ("options_json", "progress_json", "result_json"):
        v = d.pop(k, None)
        d[k[:-5]] = json.loads(v) if v else None
    return d


def get_scan(scan_id):
    with _db() as c:
        return _row(c.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone())


def list_scans(limit=100, query="", batch_id=None):
    sql = ("SELECT id, url, host, batch_id, created_at, status, risk_score, verdict, grade, options_json, "
           "NULL AS progress_json, NULL AS result_json FROM scans")
    where, args = [], []
    if query:
        where.append("(url LIKE ? OR host LIKE ?)")
        args += [f"%{query}%", f"%{query}%"]
    if batch_id:
        where.append("batch_id = ?")
        args.append(batch_id)
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY created_at DESC LIMIT ?"
    args.append(limit)
    with _db() as c:
        return [_row(r) for r in c.execute(sql, args).fetchall()]


def previous_scan(url, before_created_at):
    with _db() as c:
        return _row(c.execute("SELECT * FROM scans WHERE url=? AND created_at<? AND status='done' "
                              "ORDER BY created_at DESC LIMIT 1", (url, before_created_at)).fetchone())


def latest_scans_for(url, n=2):
    with _db() as c:
        return [_row(r) for r in c.execute("SELECT * FROM scans WHERE url=? AND status='done' "
                                           "ORDER BY created_at DESC LIMIT ?", (url, n)).fetchall()]


def host_stats(host, exclude=None):
    """How often this host was scanned before (completed scans only, current scan excluded)."""
    empty = {"count": 0, "first": None, "last": None}
    if not host:
        return empty
    try:
        with _db() as c:
            r = c.execute("SELECT COUNT(*) AS n, MIN(created_at) AS first, MAX(created_at) AS last "
                          "FROM scans WHERE host=? AND status='done' AND id<>?", (host, exclude or "")).fetchone()
    except sqlite3.Error:
        return empty
    return {"count": r["n"], "first": r["first"], "last": r["last"]}


def whois_cache_get(domain):
    try:
        with _db() as c:
            r = c.execute("SELECT fetched_at, data_json FROM whois_cache WHERE domain=?", (domain,)).fetchone()
    except sqlite3.Error:
        return None
    if r and time.time() - r["fetched_at"] < WHOIS_TTL:
        return json.loads(r["data_json"])
    return None


def whois_cache_set(domain, info):
    try:
        with _db() as c:
            c.execute("INSERT OR REPLACE INTO whois_cache (domain, fetched_at, data_json) VALUES (?, ?, ?)",
                      (domain, time.time(), json.dumps(info, default=str)))
    except sqlite3.Error:
        pass
