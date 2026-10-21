"""Security-header grading: parses CSP/HSTS/cookies/CORS instead of only checking presence."""
import re
from urllib.parse import urlsplit

from .. import net
from ..models import Section
from . import check

_SESSIONISH = re.compile(r"sess|sid|token|auth|login|jwt|remember", re.I)
_CORS_PROBE_ORIGIN = "https://cors-probe.urlscanner.invalid"


def parse_csp(value):
    out = {}
    for part in value.split(";"):
        bits = part.strip().split()
        if bits:
            out[bits[0].lower()] = [b.lower() for b in bits[1:]]
    return out


def parse_cookie(raw):
    parts = [p.strip() for p in raw.split(";")]
    name = parts[0].split("=", 1)[0].strip()
    attrs = {}
    for p in parts[1:]:
        k, _, v = p.partition("=")
        attrs[k.strip().lower()] = v.strip()
    return {"name": name, "secure": "secure" in attrs, "httponly": "httponly" in attrs,
            "samesite": attrs.get("samesite", "").lower(), "domain": attrs.get("domain", ""),
            "path": attrs.get("path", ""), "expires": attrs.get("expires", attrs.get("max-age", ""))}


def grade_headers(headers, https):
    """Return (rows, findings-as-tuples). Pure function, easy to unit test."""
    h = {k.lower(): v for k, v in headers.items()}
    rows, flags = [], []

    def row(name, status, note=""):
        rows.append({"name": name, "value": headers.get(name, h.get(name.lower(), ""))[:300],
                     "status": status, "note": note})

    # HSTS
    hsts = h.get("strict-transport-security", "")
    if not https:
        row("Strict-Transport-Security", "na", "only meaningful over HTTPS")
    elif not hsts:
        row("Strict-Transport-Security", "missing")
        flags.append(("headers.no_hsts", "HSTS header missing", "medium", 12,
                      "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains'."))
    else:
        m = re.search(r"max-age\s*=\s*\"?(\d+)", hsts, re.I)
        age = int(m.group(1)) if m else 0
        if age < 15552000:
            row("Strict-Transport-Security", "warn", f"max-age {age}s is under 180 days")
            flags.append(("headers.hsts_short", "HSTS max-age is too short", "low", 4, "Use max-age of at least 1 year."))
        else:
            note = "preload" if "preload" in hsts.lower() else ("includeSubDomains" if "includesubdomains" in hsts.lower() else "")
            row("Strict-Transport-Security", "ok", note)

    # CSP
    csp_raw = h.get("content-security-policy", "")
    csp_ro = h.get("content-security-policy-report-only", "")
    csp = parse_csp(csp_raw) if csp_raw else {}
    if not csp_raw:
        row("Content-Security-Policy", "missing", "report-only policy present" if csp_ro else "")
        flags.append(("headers.no_csp", "Content-Security-Policy missing", "medium", 12,
                      "A CSP is the strongest defence against XSS. Start with default-src 'self'."))
    else:
        issues = []
        script = csp.get("script-src", csp.get("default-src", []))
        if "script-src" not in csp and "default-src" not in csp:
            issues.append("no script-src / default-src")
            flags.append(("headers.csp_no_script_policy", "CSP does not restrict scripts", "medium", 8,
                          "Add script-src (or default-src); without it the policy gives no XSS protection."))
        if "'unsafe-inline'" in script and not any(x.startswith(("'nonce-", "'sha256-", "'sha384-", "'sha512-", "'strict-dynamic'")) for x in script):
            issues.append("script-src allows 'unsafe-inline'")
            flags.append(("headers.csp_unsafe_inline", "CSP allows inline scripts ('unsafe-inline')", "medium", 6,
                          "Use nonces or hashes instead of 'unsafe-inline'."))
        if "'unsafe-eval'" in script:
            issues.append("'unsafe-eval'")
            flags.append(("headers.csp_unsafe_eval", "CSP allows eval ('unsafe-eval')", "low", 4, ""))
        if any(x in ("*", "http:", "https:", "data:") for x in script):
            issues.append("wildcard script source")
            flags.append(("headers.csp_wildcard", "CSP script-src allows any host", "medium", 6, ""))
        if "object-src" not in csp and csp.get("default-src") != ["'none'"]:
            issues.append("no object-src")
            flags.append(("headers.csp_object", "CSP lacks object-src 'none'", "info", 1, ""))
        row("Content-Security-Policy", "warn" if issues else "ok", "; ".join(issues))

    # Clickjacking
    xfo = h.get("x-frame-options", "")
    if xfo:
        row("X-Frame-Options", "ok" if xfo.upper() in ("DENY", "SAMEORIGIN") else "warn")
    elif "frame-ancestors" in csp:
        row("X-Frame-Options", "ok", "covered by CSP frame-ancestors")
    else:
        row("X-Frame-Options", "missing")
        flags.append(("headers.no_xfo", "No clickjacking protection", "medium", 8,
                      "Send 'X-Frame-Options: DENY' or CSP 'frame-ancestors'."))

    xcto = h.get("x-content-type-options", "")
    if xcto.lower() == "nosniff":
        row("X-Content-Type-Options", "ok")
    else:
        row("X-Content-Type-Options", "missing" if not xcto else "warn")
        flags.append(("headers.no_xcto", "X-Content-Type-Options: nosniff missing", "low", 5, ""))

    rp = h.get("referrer-policy", "")
    if not rp:
        row("Referrer-Policy", "missing")
        flags.append(("headers.no_referrer_policy", "Referrer-Policy missing", "low", 3,
                      "Use 'strict-origin-when-cross-origin' or stricter."))
    elif "unsafe-url" in rp.lower():
        row("Referrer-Policy", "warn", "unsafe-url leaks full URLs")
        flags.append(("headers.referrer_unsafe", "Referrer-Policy leaks full URLs (unsafe-url)", "low", 4, ""))
    else:
        row("Referrer-Policy", "ok")

    if h.get("permissions-policy"):
        row("Permissions-Policy", "ok")
    else:
        row("Permissions-Policy", "missing")
        flags.append(("headers.no_permissions_policy", "Permissions-Policy missing", "info", 2, ""))

    for name in ("Cross-Origin-Opener-Policy", "Cross-Origin-Resource-Policy", "Cross-Origin-Embedder-Policy"):
        row(name, "ok" if h.get(name.lower()) else "optional")

    # Information disclosure
    server = h.get("server", "")
    if re.search(r"\d", server):
        row("Server", "warn", "version disclosed")
        flags.append(("headers.server_version", "Server header discloses software version", "low", 3,
                      "Hide version numbers (e.g. nginx 'server_tokens off')."))
    elif server:
        row("Server", "ok")
    for name in ("X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version", "X-Generator"):
        if h.get(name.lower()):
            row(name, "warn", "technology disclosed")
            flags.append((f"headers.disclosure.{name.lower()}", f"{name} header discloses technology", "low", 2,
                          f"Remove the {name} header."))

    # CORS
    acao = h.get("access-control-allow-origin", "")
    acac = h.get("access-control-allow-credentials", "").lower() == "true"
    if acao:
        bad = acao == "*" and acac
        row("Access-Control-Allow-Origin", "warn" if acao == "*" else "ok", "with credentials" if acac else "")
        if bad:
            flags.append(("headers.cors_wildcard_creds", "CORS allows any origin with credentials", "high", 10, ""))
    return rows, flags


@check("headers", "Security headers", stage=2, requires="http")
def run(ctx):
    s = Section()
    f = ctx.fetch
    https = urlsplit(f.final_url).scheme == "https"
    rows, flags = grade_headers(f.headers, https)
    for fid, title, sev, pen, fix in flags:
        s.flag(fid, title, sev, penalty=pen, fix=fix)

    cookies = [parse_cookie(c) for c in f.set_cookies]
    no_secure = [c["name"] for c in cookies if https and not c["secure"]]
    no_http = [c["name"] for c in cookies if not c["httponly"] and _SESSIONISH.search(c["name"])]
    none_insecure = [c["name"] for c in cookies if c["samesite"] == "none" and not c["secure"]]
    if no_secure:
        s.flag("headers.cookie_no_secure", f"{len(no_secure)} cookie(s) without the Secure flag", "low",
               penalty=min(3 * len(no_secure), 9), evidence=", ".join(no_secure[:10]))
    if no_http:
        s.flag("headers.cookie_no_httponly", "Session-like cookie readable by JavaScript (no HttpOnly)", "medium",
               penalty=min(4 * len(no_http), 8), evidence=", ".join(no_http[:10]))
    if none_insecure:
        s.flag("headers.cookie_samesite_none", "SameSite=None cookie without Secure", "low", penalty=3,
               evidence=", ".join(none_insecure[:10]))

    # CORS origin reflection probe (one ordinary GET with an Origin header)
    reflected = False
    try:
        probe = net.safe_fetch(f.final_url, headers={"Origin": _CORS_PROBE_ORIGIN}, max_redirects=0,
                               max_bytes=4096, timeout=6)
        ph = {k.lower(): v for k, v in probe.headers.items()}
        if ph.get("access-control-allow-origin") == _CORS_PROBE_ORIGIN:
            reflected = True
            creds = ph.get("access-control-allow-credentials", "").lower() == "true"
            s.flag("headers.cors_reflect", "CORS reflects arbitrary origins" + (" with credentials" if creds else ""),
                   "high" if creds else "medium", penalty=20 if creds else 6,
                   evidence=f"Origin: {_CORS_PROBE_ORIGIN} was echoed back",
                   fix="Only allow an explicit list of trusted origins.")
    except Exception:
        pass

    s.data.update({"rows": rows, "cookies": cookies, "cors_reflects": reflected,
                   "raw": {k: v[:500] for k, v in f.headers.items()}})
    return s
