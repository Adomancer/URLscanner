"""Analyse one raw e-mail end to end.

parse -> collect URLs (links, unwrapped redirectors, QR codes, attachments) -> scan them passively ->
analyse attachments -> score -> redact. Nothing here writes to the database; persist() does that with
the already-redacted result.
"""
import datetime as dt
import logging
import re
import time
from concurrent.futures import ThreadPoolExecutor, wait
from urllib.parse import parse_qsl, urlsplit

from .. import __version__, data, filescan, storage
from ..checks.content import analyze_html
from ..core import InvalidURL, new_scan_id, normalize_url, scan_url
from ..extract import RISKY_ATTACHMENT, decode_qr, extract_urls, parse_eml, qr_available, unwrap_redirector
from ..htmlutil import js_redirects, meta_refresh, soup_of
from ..utils import registered_domain
from . import limits
from .analyze import analyze_email
from .redact import Redactor

log = logging.getLogger(__name__)

_PDF_URI = re.compile(rb"/URI\s*\(([^)]{4,2000})\)")
_HTML_NAME = re.compile(r"\.(html?|shtml|xhtml|svg)$", re.I)
# actions a single click performs (and so can use up); a plain /login page is not one of them
_TOKEN_PATH = re.compile(r"reset|verif|confirm|activat|unsubscribe|opt-?out|magic|invite|approve|password|passwd|"
                         r"one-?time|otp", re.I)
_TOKEN_KEY = re.compile(r"^(?:token|tok|key|code|sig|signature|auth|session|sess|ticket|hash|otp|nonce|secret|"
                        r"magic|reset|confirm|verify)$|token|_key$|_code$", re.I)


def looks_like_token_link(url):
    """Opening this link could use up a one-time token (password reset, magic login, unsubscribe...)."""
    try:
        p = urlsplit(url)
    except ValueError:
        return False
    if _TOKEN_PATH.search(p.path):
        return True
    for k, v in parse_qsl(p.query, keep_blank_values=True):
        if _TOKEN_KEY.search(k) and len(v) >= 4:
            return True
        if len(v) >= 20 and any(c.isdigit() for c in v) and any(c.isalpha() for c in v):
            return True
    return any(len(seg) >= 24 and any(c.isdigit() for c in seg) and any(c.isalpha() for c in seg)
               for seg in p.path.split("/"))


def _trusted(reg, host):
    return reg in data.trusted_domains() and not data.abused_platform(host)


def _hrefs(html, base):
    soup = soup_of(html)
    out = [a.get("href", "") for a in soup.find_all("a")] + [f.get("action", "") for f in soup.find_all("form")]
    mr = meta_refresh(soup, base)
    if mr and mr.get("url"):
        out.append(mr["url"])
    out += js_redirects(soup, base)
    return [h.strip() for h in out if h and h.strip().lower().startswith(("http://", "https://"))]


def _analyse_attachment(a, candidates):
    """Static analysis of one attachment or inline image; URLs found inside go to `candidates`."""
    payload = a.pop("data", b"") or b""
    fn, ctype = a.get("filename") or "", a.get("type") or ""
    rec = {"filename": fn, "type": ctype, "size": a.get("size", len(payload)), "inline": bool(a.get("inline")),
           "risky_type": bool(RISKY_ATTACHMENT.search(fn))}
    is_html = bool(_HTML_NAME.search(fn)) or ctype in ("text/html", "image/svg+xml")
    if not rec["inline"]:
        rep = filescan.analyze(payload, url_name=fn, content_type=ctype)
        rec.update(kind=rep["type"], sha256=rep.get("sha256", ""), flags=filescan.flags(rep))
        if rep.get("archive"):
            rec["archive"] = {k: rep["archive"][k] for k in ("entries", "names", "encrypted", "ratio")}
        if rep["type"] == "PDF":
            for m in _PDF_URI.findall(payload)[:50]:
                u = m.decode("latin-1", "replace").strip()
                if u.lower().startswith(("http://", "https://")):
                    candidates.append({"url": u, "source": "attachment", "text": f"in {fn}"})
    if is_html:
        html = payload.decode("utf-8", "replace")[:2_000_000]
        s = analyze_html(html, "https://attachment.invalid/", "attachment.invalid")
        rec["html_findings"] = [f.to_dict() for f in s.findings]
        rec["html_password"] = bool(s.data.get("has_password"))
        for h in _hrefs(html, "https://attachment.invalid/")[:50]:
            candidates.append({"url": h, "source": "attachment", "text": f"in {fn}"})
    elif ctype.startswith("image/") and qr_available():
        values = decode_qr(payload)
        if values:
            rec["qr"] = values[:5]
            for v in values:
                for u in extract_urls(v) or ([v] if "://" in v else []):
                    candidates.append({"url": u, "source": "qr", "text": f"QR code in {fn or 'an image'}"})
    return rec


def _headers_only(raw):
    for sep in (b"\r\n\r\n", b"\n\n"):
        if sep in raw:
            return raw.split(sep, 1)[0] + sep
    return raw[:64 * 1024]


def scan_message(raw, *, trusted_source=False, deep=False, deep_links=None, network="dns", seen_before=None,
                 link_cache=None, budget=None):
    """Analyse one raw RFC 822 message. Returns a redacted, JSON-serialisable dict.

    trusted_source -- fetched straight from Gmail (its top Authentication-Results header is Gmail's)
    deep           -- the user explicitly asked to open links (never set automatically)
    deep_links     -- with deep: 1-based link numbers to open (None = every untrusted link)
    network        -- "dns" (DNS + WHOIS allowed) or "none" (no connection at all during analysis)
    seen_before    -- optional callable(address) -> True / False / None
    link_cache     -- dict shared across messages of one run, so a URL is scanned once per run
    """
    started = time.monotonic()
    deadline = started + (limits.TIME_BUDGET_SECONDS if budget is None else budget)
    notes = []
    if len(raw) > limits.MAX_MESSAGE_BYTES:
        notes.append(f"message is {len(raw) // (1024 * 1024)} MB: only its headers were analysed")
        raw = _headers_only(raw)
    try:
        parsed = parse_eml(raw, include_payloads=True, trusted_source=trusted_source)
    except Exception as e:  # hostile MIME must not crash a whole inbox run
        log.warning("could not parse message: %s", type(e).__name__)
        return {"kind": "email", "version": __version__, "error": f"could not parse message ({type(e).__name__})",
                "risk_score": None, "verdict": "Error", "label": "", "links": [], "attachments": [],
                "findings": [], "reasons": [], "notes": notes}

    # ---- collect URLs -------------------------------------------------------------------
    candidates = [{"url": l["url"], "source": "link", "text": l["text"], "mismatch": l["mismatch"],
                   "shown_domain": l["shown_domain"]} for l in parsed["links"]]
    attachments = []
    items = [dict(a) for a in parsed["attachments"]] + [dict(i, inline=True) for i in parsed["inline_images"]]
    total = 0
    for a in items[:limits.MAX_ATTACHMENTS]:
        size = a.get("size", 0)
        if size > limits.MAX_ATTACHMENT_BYTES or total + size > limits.MAX_TOTAL_ATTACHMENT_BYTES:
            a.pop("data", None)
            attachments.append({**a, "skipped": "too large to analyse"})
            continue
        if time.monotonic() > deadline:
            a.pop("data", None)
            attachments.append({**a, "skipped": "time budget reached"})
            continue
        total += size
        try:
            attachments.append(_analyse_attachment(a, candidates))
        except Exception as e:
            a.pop("data", None)
            attachments.append({**a, "error": f"analysis failed ({type(e).__name__})"})
    if len(items) > limits.MAX_ATTACHMENTS:
        notes.append(f"only the first {limits.MAX_ATTACHMENTS} of {len(items)} attachments were analysed")

    for c in list(candidates):
        chain = unwrap_redirector(c["url"], limits.MAX_UNWRAP_DEPTH)
        for inner in chain:
            shown = c.get("shown_domain", "")
            candidates.append({"url": inner, "source": c["source"] if c["source"] != "link" else "unwrapped",
                               "text": c.get("text", ""), "via": c["url"], "shown_domain": shown,
                               "mismatch": bool(shown) and registered_domain(inner) != shown})
        if chain:
            c["mismatch"] = False  # judged on the real destination instead

    links, by_url = [], {}
    for c in candidates:
        try:
            n = normalize_url(c["url"])
        except InvalidURL:
            continue
        if n in by_url:
            prev = by_url[n]
            prev["mismatch"] = prev.get("mismatch") or c.get("mismatch", False)
            continue
        host = (urlsplit(n).hostname or "").lower()
        reg = registered_domain(host)
        item = {"url": n, "raw": c["url"], "via": c.get("via", ""), "host": host, "registered_domain": reg,
                "source": c["source"], "text": (c.get("text") or "")[:200], "mismatch": bool(c.get("mismatch")),
                "shown_domain": c.get("shown_domain", ""), "trusted": _trusted(reg, host),
                "token_like": looks_like_token_link(n)}
        by_url[n] = item
        links.append(item)
    links.sort(key=lambda l: l["trusted"])  # untrusted first (stable), so the cap drops the boring ones
    if len(links) > limits.MAX_URLS:
        notes.append(f"only {limits.MAX_URLS} of {len(links)} distinct links were analysed")
        links = links[:limits.MAX_URLS]
    for i, l in enumerate(links, 1):
        l["n"] = i

    # ---- scan links (passive unless the user asked for a deep scan) ----------------------
    cache = {} if link_cache is None else link_cache
    net_mode = "none" if network == "none" else "dns"

    def run(u, deep_this):
        key = (u, "deep" if deep_this else "passive", net_mode)
        if key not in cache:
            cache[key] = scan_url(u, passive=not deep_this, network=net_mode, store=False)
        return cache[key]

    pool = ThreadPoolExecutor(max_workers=limits.LINK_WORKERS)
    futures = {}
    for l in links:
        l["mode"] = "deep" if (deep and not l["trusted"] and (deep_links is None or l["n"] in deep_links)) \
            else "passive"
        futures[pool.submit(run, l["url"], l["mode"] == "deep")] = l
    sender_domain = (parsed.get("from_address") or "").rsplit("@", 1)[-1].lower() \
        if "@" in (parsed.get("from_address") or "") else ""
    if registered_domain(sender_domain) in data.freemail_domains():
        sender_domain = ""  # gmail.com tells us nothing about the person using it
    sender_future = pool.submit(run, f"https://{sender_domain}/", False) if sender_domain else None
    pending = list(futures) + ([sender_future] if sender_future else [])
    _, not_done = wait(pending, timeout=max(0.0, deadline - time.monotonic()))
    for f in not_done:
        f.cancel()
    pool.shutdown(wait=False, cancel_futures=True)
    for f, l in futures.items():
        if f in not_done:
            l["result"] = None
            l["error"] = "not analysed: time budget reached"
            continue
        try:
            l["result"] = f.result()
        except Exception as e:
            l["result"] = None
            l["error"] = f"scan failed ({type(e).__name__})"
    if not_done:
        notes.append(f"analysis truncated: time budget reached ({len(not_done)} scan(s) unfinished)")
    sender_scan = None
    if sender_future is not None and sender_future not in not_done:
        try:
            sender_scan = sender_future.result()
        except Exception:
            sender_scan = None

    seen = None
    if seen_before and parsed.get("from_address"):
        try:
            seen = seen_before(parsed["from_address"])
        except Exception:
            seen = None  # unknown is not "new": a failed lookup must never count against the sender

    analysis = analyze_email(parsed, links, attachments, sender_scan=sender_scan, seen_before=seen, notes=notes)

    # ---- redact & shape -----------------------------------------------------------------
    red = Redactor()
    for l in parsed["links"]:
        red.add(l["url"])
    for l in links:
        for u in (l["raw"], l["url"], l["via"], (l.get("result") or {}).get("final_url")):
            red.add(u)
    out_links, link_scans = [], []
    for l in links:
        r = l.get("result") or {}
        out_links.append({
            "n": l["n"], "url": l["url"], "host": l["host"], "registered_domain": l["registered_domain"],
            "source": l["source"], "via": l["via"], "text": l["text"], "mismatch": l["mismatch"],
            "shown_domain": l["shown_domain"], "trusted": l["trusted"], "token_like": l["token_like"],
            "mode": l["mode"], "risk_score": r.get("risk_score"), "verdict": r.get("verdict") or "Not analysed",
            "reasons": (r.get("reasons") or [])[:3], "scan_id": r.get("id", ""),
            "error": l.get("error") or r.get("error") or "",
        })
        if r:
            link_scans.append(r)
    result = {
        "kind": "email", "version": __version__,
        "analysed_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "trusted_source": trusted_source, "network": net_mode, "deep": bool(deep),
        "subject": parsed["subject"], "from": parsed["from"], "from_name": parsed["from_name"],
        "from_address": parsed["from_address"], "reply_to": parsed["reply_to"],
        "return_path": parsed["return_path"], "date": parsed["date"], "message_id": parsed["message_id"],
        "received_hops": parsed["received_hops"], "auth": parsed["auth"], "auth_info": parsed["auth_info"],
        "warnings": parsed["warnings"], "links": out_links, "attachments": attachments,
        **analysis,
        "duration_ms": int((time.monotonic() - started) * 1000),
        "link_scans": link_scans,
        "error": None,
    }
    return red.value(result)


def persist(result, *, account="", folder="", msgid="", received_at=None):
    """Store an analysed (already redacted) message: one batch holding its link scans, plus a row in
    `emails` keyed by Gmail's message id. Returns the batch id. One transaction; re-scans add a new
    batch (history is kept) and point the e-mail row at it."""
    batch_id = new_scan_id()
    # a URL scanned once per run can appear in several messages: every stored copy gets its own id
    ids, scans = {}, []
    for r in result.get("link_scans") or []:
        ids[r["id"]] = new_scan_id()
        scans.append(dict(r, id=ids[r["id"]]))
    result = dict(result, links=[dict(l, scan_id=ids.get(l.get("scan_id"), "")) for l in result.get("links", [])])
    summary = {k: v for k, v in result.items() if k not in ("link_scans",)}
    meta = {"source": "gmail" if account else "file", "msgid": msgid, "account": account, "folder": folder,
            "eml": summary}
    storage.save_email_bundle(batch_id, meta, scans, {
        "msgid": msgid, "account": account, "folder": folder, "received_at": received_at,
        "from_addr": result.get("from_address", ""), "subject": result.get("subject", ""),
        "risk_score": result.get("risk_score"), "verdict": result.get("verdict"),
        "deep_scanned": bool(result.get("deep")), "scanner_version": result.get("version", __version__),
        "result": {k: v for k, v in result.items() if k != "link_scans"},
    })
    return batch_id
