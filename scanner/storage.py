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
CREATE TABLE IF NOT EXISTS emails (
    msgid TEXT PRIMARY KEY,
    account TEXT,
    folder TEXT,
    batch_id TEXT,
    received_at REAL,
    scanned_at REAL NOT NULL,
    scanner_version TEXT,
    from_addr TEXT,
    subject TEXT,
    risk_score INTEGER,
    verdict TEXT,
    deep_scanned INTEGER DEFAULT 0,
    label_applied TEXT DEFAULT '',
    label_error TEXT DEFAULT '',
    result_json TEXT
);
CREATE INDEX IF NOT EXISTS idx_emails_scanned ON emails(scanned_at);
CREATE TABLE IF NOT EXISTS jobs (
    name TEXT PRIMARY KEY,
    running INTEGER NOT NULL DEFAULT 0,
    what TEXT DEFAULT '',
    message TEXT DEFAULT '',
    error TEXT DEFAULT '',
    updated_at REAL
);
CREATE TABLE IF NOT EXISTS mail_state (
    account TEXT NOT NULL,
    folder TEXT NOT NULL,
    uidvalidity INTEGER,
    last_uid INTEGER,
    updated_at REAL,
    PRIMARY KEY (account, folder)
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


# --- e-mail (scanner.mail) -------------------------------------------------------------------
# Everything stored here has already been through scanner.mail.redact: no bodies, no URL tokens.

def save_email_bundle(batch_id, meta, link_scans, email):
    """Atomically store one analysed message: its batch, its link scans and its `emails` row (upserted
    by message id, so a re-scan updates the row while older batches stay as history)."""
    now = time.time()
    with _db() as c:
        c.execute("INSERT INTO batches (id, created_at, meta_json) VALUES (?, ?, ?)",
                  (batch_id, now, json.dumps(meta or {}, default=str)))
        for r in link_scans:
            status = "error" if r.get("error") else "done"
            c.execute("INSERT INTO scans (id, url, host, batch_id, created_at, status, risk_score, verdict, grade, "
                      "options_json, progress_json, result_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, '{}', ?)",
                      (r["id"], r["url"], r.get("host", ""), batch_id, now, status, r.get("risk_score"),
                       r.get("verdict"), r.get("grade"), json.dumps(r.get("options", {})),
                       json.dumps(r, default=str)))
        if email.get("msgid"):
            c.execute(
                "INSERT INTO emails (msgid, account, folder, batch_id, received_at, scanned_at, scanner_version, "
                "from_addr, subject, risk_score, verdict, deep_scanned, result_json) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
                "ON CONFLICT(msgid) DO UPDATE SET account=excluded.account, folder=excluded.folder, "
                "batch_id=excluded.batch_id, received_at=COALESCE(excluded.received_at, received_at), "
                "scanned_at=excluded.scanned_at, scanner_version=excluded.scanner_version, "
                "from_addr=excluded.from_addr, subject=excluded.subject, risk_score=excluded.risk_score, "
                "verdict=excluded.verdict, deep_scanned=MAX(deep_scanned, excluded.deep_scanned), "
                "result_json=excluded.result_json",
                (email["msgid"], email.get("account", ""), email.get("folder", ""), batch_id,
                 email.get("received_at"), now, email.get("scanner_version", ""), email.get("from_addr", ""),
                 email.get("subject", ""), email.get("risk_score"), email.get("verdict"),
                 int(bool(email.get("deep_scanned"))), json.dumps(email.get("result") or {}, default=str)))


def _email_row(r):
    if r is None:
        return None
    d = dict(r)
    d["result"] = json.loads(d.pop("result_json") or "{}")
    return d


def get_email(msgid):
    with _db() as c:
        return _email_row(c.execute("SELECT * FROM emails WHERE msgid=?", (msgid,)).fetchone())


def email_seen(msgid):
    with _db() as c:
        return c.execute("SELECT 1 FROM emails WHERE msgid=?", (msgid,)).fetchone() is not None


def list_emails(limit=100, verdict="", account="", query=""):
    sql = ("SELECT msgid, account, folder, batch_id, received_at, scanned_at, from_addr, subject, risk_score, "
           "verdict, deep_scanned, label_applied, label_error FROM emails")
    where, args = [], []
    if verdict:
        where.append("verdict = ?")
        args.append(verdict)
    if account:
        where.append("account = ?")
        args.append(account)
    if query:
        where.append("(subject LIKE ? ESCAPE '\\' OR from_addr LIKE ? ESCAPE '\\')")
        like = "%" + query.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
        args += [like, like]
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY COALESCE(received_at, scanned_at) DESC LIMIT ?"
    args.append(limit)
    with _db() as c:
        return [dict(r) for r in c.execute(sql, args).fetchall()]


def mail_stats():
    """Totals for the mail dashboard: {'total', 'by_verdict': {...}, 'labelled', 'label_errors', 'last_scan'}."""
    with _db() as c:
        rows = c.execute("SELECT verdict, COUNT(*) AS n FROM emails GROUP BY verdict").fetchall()
        r = c.execute("SELECT COUNT(*) AS total, SUM(label_applied <> '') AS labelled, "
                      "SUM(label_error <> '') AS label_errors, MAX(scanned_at) AS last_scan FROM emails").fetchone()
    return {"total": r["total"] or 0, "by_verdict": {x["verdict"]: x["n"] for x in rows},
            "labelled": r["labelled"] or 0, "label_errors": r["label_errors"] or 0, "last_scan": r["last_scan"]}


def scan_stats():
    """Totals for the home page: completed URL scans per verdict."""
    with _db() as c:
        rows = c.execute("SELECT verdict, COUNT(*) AS n FROM scans WHERE status='done' GROUP BY verdict").fetchall()
    return {x["verdict"]: x["n"] for x in rows}


def set_email_label(msgid, label_applied, label_error=""):
    with _db() as c:
        c.execute("UPDATE emails SET label_applied=?, label_error=? WHERE msgid=?",
                  (label_applied, label_error[:300], msgid))


# --- background jobs (shared by every web worker process) ------------------------------------
JOB_STALE = 1800  # a "running" job not heard from for this long died with its worker


def claim_job(name, what):
    """Atomically mark job `name` as running. Returns False if it already runs (in any process)."""
    now = time.time()
    with _db() as c:
        c.execute("INSERT OR IGNORE INTO jobs (name, running, updated_at) VALUES (?, 0, ?)", (name, now))
        cur = c.execute("UPDATE jobs SET running=1, what=?, message='', error='', updated_at=? "
                        "WHERE name=? AND (running=0 OR updated_at<?)", (what, now, name, now - JOB_STALE))
        return cur.rowcount == 1


def finish_job(name, message="", error=""):
    with _db() as c:
        c.execute("UPDATE jobs SET running=0, message=?, error=?, updated_at=? WHERE name=?",
                  (message[:500], error[:500], time.time(), name))


def get_job(name):
    with _db() as c:
        r = c.execute("SELECT running, what, message, error, updated_at FROM jobs WHERE name=?", (name,)).fetchone()
    if r is None:
        return {"running": False, "what": "", "message": "", "error": ""}
    running = bool(r["running"]) and time.time() - (r["updated_at"] or 0) < JOB_STALE
    return {"running": running, "what": r["what"] or "", "message": r["message"] or "", "error": r["error"] or ""}


def get_mail_state(account, folder):
    with _db() as c:
        r = c.execute("SELECT uidvalidity, last_uid FROM mail_state WHERE account=? AND folder=?",
                      (account, folder)).fetchone()
    return (r["uidvalidity"], r["last_uid"]) if r else (None, None)


def set_mail_state(account, folder, uidvalidity, last_uid):
    with _db() as c:
        c.execute("INSERT INTO mail_state (account, folder, uidvalidity, last_uid, updated_at) VALUES (?, ?, ?, ?, ?) "
                  "ON CONFLICT(account, folder) DO UPDATE SET uidvalidity=excluded.uidvalidity, "
                  "last_uid=excluded.last_uid, updated_at=excluded.updated_at",
                  (account, folder, uidvalidity, last_uid, time.time()))


def whois_cache_set(domain, info):
    try:
        with _db() as c:
            c.execute("INSERT OR REPLACE INTO whois_cache (domain, fetched_at, data_json) VALUES (?, ?, ?)",
                      (domain, time.time(), json.dumps(info, default=str)))
    except sqlite3.Error:
        pass
