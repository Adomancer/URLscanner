"""Flask web UI + small JSON API for the OSINT URL Scanner.

Scans run in a background thread pool; the browser polls /api/scan/<id> for live progress.
No login/accounts, so CSRF is handled with a per-session token (no extra dependency).
"""
import hashlib
import io
import secrets
import threading
import time
from collections import defaultdict, deque
from concurrent.futures import ThreadPoolExecutor
from functools import wraps

from flask import (Flask, abort, g, jsonify, redirect, render_template, request,
                   send_file, send_from_directory, session, url_for)

import config
from scanner import report, storage
from scanner.core import new_scan_id, scan_url
from scanner.extract import decode_qr, extract_urls, parse_eml, qr_available
from scanner.checks.sandbox import available as sandbox_available

app = Flask(__name__)
app.config.update(SECRET_KEY=config.SECRET_KEY, MAX_CONTENT_LENGTH=8 * 1024 * 1024,
                  SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax", JSON_SORT_KEYS=False)

_pool = ThreadPoolExecutor(max_workers=4, thread_name_prefix="scan")
_rate = defaultdict(lambda: deque(maxlen=30))
_rate_lock = threading.Lock()
RATE_LIMIT, RATE_WINDOW = 20, 60  # 20 scans / minute / IP
LOGIN_LIMIT = 10                  # 10 login attempts / minute / IP

try:
    storage.mark_stale_running()
except Exception:  # never block start-up on housekeeping
    pass


# --- helpers ------------------------------------------------------------------------------

def csrf_token():
    if "csrf" not in session:
        session["csrf"] = secrets.token_urlsafe(32)
    return session["csrf"]


app.jinja_env.globals["csrf_token"] = csrf_token
app.jinja_env.globals["sandbox_available"] = sandbox_available
app.jinja_env.globals["qr_available"] = qr_available
app.jinja_env.globals["active_allowed"] = lambda: config.WEB_ACTIVE
app.jinja_env.globals["auth_enabled"] = lambda: bool(config.ACCESS_TOKEN)


@app.template_filter("defang")
def _defang(value):
    from scanner.utils import defang
    return defang(value or "")


@app.template_filter("ts")
def _ts(value):
    import datetime as dt
    try:
        return dt.datetime.fromtimestamp(float(value)).strftime("%Y-%m-%d %H:%M")
    except (TypeError, ValueError):
        return ""


def check_csrf():
    if g.get("bearer"):  # API clients authenticated by header: no ambient cookie, so no CSRF risk
        return
    sent = request.headers.get("X-CSRF-Token") or request.form.get("csrf_token")
    if not sent or not secrets.compare_digest(sent, session.get("csrf", "")):
        abort(400, "Invalid or missing CSRF token. Reload the page and try again.")


def _token_ok(sent):
    return bool(sent) and secrets.compare_digest(sent.encode("utf-8"), config.ACCESS_TOKEN.encode("utf-8"))


def _token_tag():
    """Stored in the session instead of a bare flag, so changing the token logs everyone out."""
    return hashlib.sha256(config.ACCESS_TOKEN.encode("utf-8")).hexdigest()[:16]


def _safe_next(target):
    return target if target and target.startswith("/") and not target.startswith("//") else url_for("index")


@app.before_request
def require_token():
    if not config.ACCESS_TOKEN or request.endpoint in ("login", "static"):
        return None
    if session.get("authed") == _token_tag():
        return None
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer ") and _token_ok(auth[7:].strip()):
        g.bearer = True
        return None
    if request.path.startswith("/api/"):
        return jsonify(error="authentication required"), 401
    return redirect(url_for("login", next=request.full_path if request.method == "GET" else None))


def client_ip():
    if config.TRUST_PROXY:
        xff = request.headers.get("X-Forwarded-For", "")
        if xff:
            return xff.split(",")[-1].strip()  # the hop our own proxy saw; earlier entries are client-supplied
    return request.remote_addr or "?"


def rate_limited(bucket="scan", limit=RATE_LIMIT):
    now = time.time()
    with _rate_lock:
        for k in [k for k, q in _rate.items() if not q or now - q[-1] > RATE_WINDOW]:
            del _rate[k]
        hits = _rate[(bucket, client_ip())]
        while hits and now - hits[0] > RATE_WINDOW:
            hits.popleft()
        if len(hits) >= limit:
            return True
        hits.append(now)
        return False


def start_scan(url, options, batch_id=None):
    scan_id = new_scan_id()
    storage.create_scan(scan_id, url, options=options, batch_id=batch_id)

    def job():
        try:
            scan_url(url, active=options.get("active"), authorized=options.get("authorized"),
                     browser=options.get("browser"), scan_id=scan_id,
                     progress=lambda p: storage.update_progress(scan_id, p))
        except Exception as e:
            storage.save_result(scan_id, {"id": scan_id, "url": url, "error": f"internal error: {e}",
                                          "verdict": "Error", "risk_score": None, "grade": "N/A",
                                          "findings": [], "sections": {}})
    _pool.submit(job)
    return scan_id


def parse_options(src):
    active = config.WEB_ACTIVE and src.get("active") in ("1", "true", "on", True)
    return {"active": active, "authorized": active and src.get("authorized") in ("1", "true", "on", True),
            "browser": src.get("browser") in ("1", "true", "on", True)}


# --- pages --------------------------------------------------------------------------------

@app.route("/")
def index():
    return render_template("scan.html")


@app.route("/scan", methods=["POST"])
def scan_submit():
    check_csrf()
    if rate_limited():
        abort(429, "Too many scans; please wait a moment.")
    options = parse_options(request.form)
    mode = request.form.get("mode", "single")
    urls = []
    meta = {}

    if mode == "file" and "file" in request.files and request.files["file"].filename:
        f = request.files["file"]
        raw = f.read(8 * 1024 * 1024)
        name = f.filename.lower()
        if name.endswith(".eml") or raw[:5] in (b"From ", b"Retur", b"Date:"):
            info = parse_eml(raw)
            urls = [l["url"] for l in info["links"]]
            meta["eml"] = {"subject": info["subject"], "from": info["from"], "warnings": info["warnings"],
                           "auth": info["auth"], "links": info["links"]}
        elif name.endswith((".png", ".jpg", ".jpeg", ".bmp", ".gif", ".webp")):
            if not qr_available():
                abort(400, "QR decoding is not installed on the server.")
            found = decode_qr(raw)
            urls = [u for v in found for u in (extract_urls(v) or ([v] if "://" in v else []))]
            if not urls:
                abort(400, "No URL found in the QR code.")
        else:
            urls = extract_urls(raw.decode("utf-8", "replace"))
    elif mode == "bulk":
        urls = extract_urls(request.form.get("urls", "")) or \
            [l.strip() for l in request.form.get("urls", "").splitlines() if l.strip()]
    else:
        u = request.form.get("url", "").strip()
        if u:
            urls = [u]

    urls = list(dict.fromkeys(urls))[:50]
    if not urls and not meta:
        abort(400, "No URL to scan.")
    if len(urls) == 1 and not meta:
        return redirect(url_for("scan_result", scan_id=start_scan(urls[0], options)))
    # Several URLs, or an e-mail: group them so the batch page can show them (and the e-mail) together.
    batch_id = new_scan_id()
    storage.create_batch(batch_id, meta)
    for u in urls:
        start_scan(u, options, batch_id)
    return redirect(url_for("batch_view", b=batch_id))


@app.route("/scan/<scan_id>")
def scan_result(scan_id):
    row = storage.get_scan(scan_id)
    if not row:
        abort(404)
    return render_template("result.html", scan=row, result=row.get("result"))


@app.route("/batch")
def batch_view():
    batch = storage.get_batch(request.args.get("b", ""))
    if batch:
        rows = storage.list_scans(limit=50, batch_id=batch["id"])[::-1]  # submission order
    else:  # older links: /batch?id=...&id=...
        rows = [r for r in (storage.get_scan(i) for i in request.args.getlist("id")) if r]
    if not batch and not rows:
        abort(404)
    eml = (batch or {}).get("meta", {}).get("eml")
    return render_template("batch.html", rows=rows, ids=[r["id"] for r in rows], eml=eml)


@app.route("/login", methods=["GET", "POST"])
def login():
    if not config.ACCESS_TOKEN:
        return redirect(url_for("index"))
    error = None
    if request.method == "POST":
        check_csrf()
        if rate_limited("login", LOGIN_LIMIT):
            abort(429, "Too many login attempts; please wait a minute.")
        if _token_ok(request.form.get("token", "")):
            session["authed"] = _token_tag()
            return redirect(_safe_next(request.form.get("next")))
        error = "Wrong access token."
    return render_template("login.html", error=error, next=request.values.get("next", "")), 401 if error else 200


@app.route("/logout")
def logout():
    session.pop("authed", None)
    return redirect(url_for("login") if config.ACCESS_TOKEN else url_for("index"))


@app.route("/history")
def history():
    q = request.args.get("q", "").strip()
    rows = storage.list_scans(limit=200, query=q)
    return render_template("history.html", rows=rows, query=q)


@app.route("/diff")
def diff_view():
    url = request.args.get("url", "")
    rows = storage.latest_scans_for(url, 2)
    d = report.diff(rows[1]["result"], rows[0]["result"]) if len(rows) >= 2 else None
    return render_template("diff.html", url=url, rows=rows, d=d)


@app.route("/scan/<scan_id>/export/<fmt>")
def export(scan_id, fmt):
    row = storage.get_scan(scan_id)
    if not row or not row.get("result"):
        abort(404)
    if fmt not in report.FORMATTERS:
        abort(404)
    body = report.render(fmt, row["result"])
    mime = {"json": "application/json", "csv": "text/csv", "html": "text/html",
            "md": "text/markdown", "sarif": "application/json"}[fmt]
    domain = (row["result"].get("registered_domain") or "scan").replace(":", "_")
    fname = f"{domain}_{scan_id}.{report.EXT[fmt]}"
    return send_file(io.BytesIO(body.encode("utf-8")), mimetype=mime, as_attachment=True, download_name=fname)


@app.route("/screenshot/<scan_id>.jpg")
def screenshot(scan_id):
    row = storage.get_scan(scan_id)
    shot = ((row or {}).get("result") or {}).get("sections", {}).get("sandbox", {}).get("screenshot")
    if not shot:
        abort(404)
    return send_from_directory(config.SCREENSHOT_DIR, f"{scan_id}.jpg", max_age=3600)


# --- JSON API -----------------------------------------------------------------------------

@app.route("/api/scan", methods=["POST"])
def api_scan():
    check_csrf()
    if rate_limited():
        return jsonify(error="rate limited"), 429
    data = request.get_json(silent=True) or request.form
    url = (data.get("url") or "").strip()
    if not url:
        return jsonify(error="url required"), 400
    scan_id = start_scan(url, parse_options(data))
    return jsonify(id=scan_id, status="running", poll=url_for("api_scan_status", scan_id=scan_id))


@app.route("/api/scan/<scan_id>")
def api_scan_status(scan_id):
    row = storage.get_scan(scan_id)
    if not row:
        return jsonify(error="not found"), 404
    body = {"id": scan_id, "status": row["status"], "url": row["url"], "progress": row.get("progress") or {}}
    if row["status"] in ("done", "error") and row.get("result"):
        body["result"] = row["result"]
    return jsonify(body)


@app.errorhandler(400)
@app.errorhandler(401)
@app.errorhandler(404)
@app.errorhandler(429)
def handle_error(e):
    if request.path.startswith("/api/"):
        return jsonify(error=getattr(e, "description", str(e))), e.code
    return render_template("error.html", code=e.code, message=getattr(e, "description", str(e))), e.code


@app.after_request
def security_headers(resp):
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("Referrer-Policy", "no-referrer")
    resp.headers.setdefault("Content-Security-Policy",
                            "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "
                            "script-src 'self'; base-uri 'none'; form-action 'self'")
    return resp


if __name__ == "__main__":
    app.run(debug=config.FLASK_DEBUG, host="127.0.0.1", port=5000)
