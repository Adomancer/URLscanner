"""Input helpers: refang IOCs, pull URLs out of text / e-mails (.eml) / QR-code images."""
import email
import email.policy
import importlib.util
import re
from email.utils import parseaddr

from bs4 import BeautifulSoup

_REFANG = [
    (re.compile(r"\bh(?:xx|\*\*|tt)p(s?)\b", re.I), r"http\1"),
    (re.compile(r"\[\s*(?:\.|dot)\s*\]|\(\s*(?:\.|dot)\s*\)|\{\s*(?:\.|dot)\s*\}", re.I), "."),
    (re.compile(r"\[\s*:\s*\]"), ":"),
    (re.compile(r"\[\s*://\s*\]"), "://"),
    (re.compile(r"\[\s*(?:@|at)\s*\]|\(\s*at\s*\)", re.I), "@"),
    (re.compile(r"\\\."), "."),
]
_URL = re.compile(r"\b(?:https?://|www\.)[^\s<>\"'`]{3,2000}", re.I)
_TRAILING = ".,;:!?)]}>'\""


def refang(text):
    for rx, rep in _REFANG:
        text = rx.sub(rep, text)
    return text


def extract_urls(text, limit=500):
    """Find URLs in free text (handles defanged forms). Returns unique URLs in order."""
    out = []
    for m in _URL.finditer(refang(text or "")):
        u = m.group(0).rstrip(_TRAILING)
        if u.lower().startswith("www."):
            u = "https://" + u
        if u not in out:
            out.append(u)
        if len(out) >= limit:
            break
    return out


def _domain(u):
    from .utils import registered_domain
    return registered_domain(u if "://" in u else "https://" + u)


GMAIL_AUTHSERV = "mx.google.com"
_AUTH_METHOD = re.compile(r"\b(spf|dkim|dmarc)\s*=\s*([a-z]+)", re.I)
_HEADER_FROM = re.compile(r"\bheader\.from\s*=\s*([^\s;()]+)", re.I)
RISKY_ATTACHMENT = re.compile(r"\.(exe|scr|com|pif|js|jse|vbs|vbe|wsf|hta|iso|img|vhdx?|lnk|bat|cmd|ps1|msi|jar|apk|"
                              r"html?|svg|zip|rar|7z|docm|xlsm|pptm)$", re.I)


def parse_auth_results(msg, trusted_source=False):
    """SPF/DKIM/DMARC as recorded by the receiving server.

    Only the topmost Authentication-Results header counts: the receiving server adds its own on top, so
    anything below it came with the message and can be forged by the sender. Results are "verified" only
    when that top header is Gmail's and the message was fetched straight from Gmail (trusted_source);
    for an uploaded file nobody can tell who wrote the headers.
    """
    headers = msg.get_all("Authentication-Results", []) or []
    out = {"spf": "", "dkim": "", "dmarc": "", "server": "", "dmarc_from": "", "verified": False}
    if not headers:
        return out
    top = " ".join(str(headers[0]).split())
    server = top.split(";", 1)[0].strip().split()[0].lower() if top.strip() else ""
    out["server"] = server
    for method, result in _AUTH_METHOD.findall(top):
        method = method.lower()
        if not out[method]:  # first result per method (a message can carry several DKIM signatures)
            out[method] = result.lower()
        elif method == "dkim" and result.lower() == "pass":
            out["dkim"] = "pass"
    m = _HEADER_FROM.search(top)
    out["dmarc_from"] = m.group(1).lower().strip(".") if m else ""
    out["verified"] = bool(trusted_source and server == GMAIL_AUTHSERV)
    return out


def _decode_text(part):
    try:
        body = part.get_content()
    except (LookupError, ValueError, KeyError):
        body = None
    if isinstance(body, str):
        return body
    return (part.get_payload(decode=True) or b"").decode("utf-8", "replace")


def parse_eml(raw_bytes, include_payloads=False, trusted_source=False):
    """Parse an e-mail and report its links, including text/href mismatches (a classic phishing tell).

    include_payloads -- also return attachment / inline-image bytes and the decoded bodies
                        (for scanner.mail; these must never be stored)
    trusted_source   -- the message came straight from Gmail over IMAP, so its top
                        Authentication-Results header is Gmail's own
    """
    msg = email.message_from_bytes(raw_bytes, policy=email.policy.default)
    html_parts, text_parts = [], []
    attachments, inline_images = [], []
    for part in msg.walk():
        if part.is_multipart():
            continue
        ctype = part.get_content_type()
        disp = (part.get("Content-Disposition") or "").lower()
        try:
            filename = part.get_filename() or ""
        except (ValueError, LookupError):
            filename = ""
        is_attachment = "attachment" in disp or (filename and not ctype.startswith("image/"))
        if is_attachment or ctype.startswith("image/"):
            payload = part.get_payload(decode=True) or b""
            item = {"filename": filename, "type": ctype, "size": len(payload)}
            if include_payloads:
                item["data"] = payload
            (attachments if is_attachment else inline_images).append(item)
            continue
        if ctype == "text/html":
            html_parts.append(_decode_text(part))
        elif ctype == "text/plain":
            text_parts.append(_decode_text(part))

    links = []
    seen = set()
    for html in html_parts:
        soup = BeautifulSoup(html, "lxml")
        for a in soup.find_all("a", href=True):
            href = a["href"].strip()
            if not href.lower().startswith(("http://", "https://")):
                continue
            text = a.get_text(" ", strip=True)[:200]
            shown = extract_urls(text)
            shown_domain = _domain(shown[0]) if shown else ""
            if not shown_domain and re.fullmatch(r"(?:[\w-]+\.)+[a-z]{2,}", text.lower()):
                shown_domain = _domain(text)
            mismatch = bool(shown_domain) and shown_domain != _domain(href)
            if (href, text) not in seen:
                seen.add((href, text))
                links.append({"url": href, "text": text, "mismatch": mismatch, "shown_domain": shown_domain,
                              "domain": _domain(href)})
    for text in text_parts:
        for u in extract_urls(text):
            if not any(l["url"] == u for l in links):
                links.append({"url": u, "text": "", "mismatch": False, "shown_domain": "", "domain": _domain(u)})

    from_name, from_addr = parseaddr(_header(msg, "From"))
    _, reply_addr = parseaddr(_header(msg, "Reply-To"))
    _, return_path = parseaddr(_header(msg, "Return-Path"))
    auth_info = parse_auth_results(msg, trusted_source)
    results = {k: auth_info[k] for k in ("spf", "dkim", "dmarc")}
    note = "" if auth_info["verified"] else " (as reported in the file, not verified)"
    warnings = []
    if reply_addr and from_addr and _domain(reply_addr.split("@")[-1]) != _domain(from_addr.split("@")[-1]):
        warnings.append(f"Reply-To ({reply_addr}) differs from From ({from_addr})")
    if return_path and from_addr and _domain(return_path.split("@")[-1]) != _domain(from_addr.split("@")[-1]):
        warnings.append(f"Return-Path domain ({return_path}) differs from From")
    for k, v in results.items():
        if v in ("fail", "softfail", "permerror", "none"):
            warnings.append(f"{k.upper()} result: {v}{note}")
    if any(l["mismatch"] for l in links):
        warnings.append("Some links display one address but point to another")
    for a in attachments:
        if RISKY_ATTACHMENT.search(a["filename"]):
            warnings.append(f"Risky attachment type: {a['filename']}")

    out = {
        "subject": _header(msg, "Subject")[:300],
        "from": _header(msg, "From")[:200], "from_name": from_name, "from_address": from_addr,
        "reply_to": reply_addr, "return_path": return_path, "to": _header(msg, "To")[:300],
        "date": _header(msg, "Date"), "message_id": _header(msg, "Message-ID")[:200],
        "received_hops": len(msg.get_all("Received", []) or []),
        "auth": results, "auth_info": auth_info, "links": links[:200], "attachments": attachments,
        "inline_images": inline_images, "warnings": warnings,
    }
    if include_payloads:
        out["body_text"] = "\n".join(text_parts)[:1_000_000]
        out["body_html"] = "\n".join(html_parts)[:2_000_000]
    return out


def _header(msg, name):
    """A header as text; malformed headers must not abort parsing of a hostile message."""
    try:
        return str(msg.get(name, "") or "")
    except Exception:  # the stdlib header parser can raise on crafted input
        return ""


_REDIRECTORS = [
    # (host test, path test, query parameter holding the real destination)
    (lambda h: re.fullmatch(r"(?:www\.)?google\.[a-z.]{2,8}", h), lambda p: p == "/url", ("q", "url")),
    (lambda h: h.endswith("safelinks.protection.outlook.com"), lambda p: True, ("url",)),
    (lambda h: h in ("l.facebook.com", "lm.facebook.com", "l.instagram.com"), lambda p: p == "/l.php", ("u",)),
    (lambda h: h in ("www.youtube.com", "youtube.com"), lambda p: p == "/redirect", ("q",)),
    (lambda h: h == "slack-redir.net", lambda p: p == "/link", ("url",)),
]


def _unwrap_once(url):
    from urllib.parse import parse_qs, unquote, urlsplit
    p = urlsplit(url)
    host, path = (p.hostname or "").lower(), p.path or "/"
    if host == "urldefense.proofpoint.com" and path.startswith("/v2/url"):
        u = parse_qs(p.query).get("u", [""])[0]
        return unquote(u.replace("-", "%").replace("_", "/")) if u else ""
    if host == "urldefense.com" and path.startswith("/v3/__"):
        m = re.match(r"https?://urldefense\.com/v3/__(.+?)__;", url)
        return m.group(1) if m else ""
    for host_ok, path_ok, params in _REDIRECTORS:
        if host_ok(host) and path_ok(path):
            q = parse_qs(p.query)
            for k in params:
                if q.get(k):
                    return q[k][0]
    return ""


def unwrap_redirector(url, max_depth=3):
    """Offline unwrapping of well-known redirect wrappers (Google /url?q=, Outlook SafeLinks,
    Proofpoint URL Defense, Facebook l.php, ...). Never fetches anything.

    Returns the chain of destinations found inside `url` (not including `url` itself); each one has
    passed core.normalize_url, so it is a well-formed http(s) URL.
    """
    from .core import InvalidURL, normalize_url
    chain, current = [], url
    for _ in range(max_depth):
        inner = _unwrap_once(current)
        if not inner:
            break
        try:
            inner = normalize_url(inner)
        except InvalidURL:
            break
        if inner == current or inner in chain:
            break
        chain.append(inner)
        current = inner
    return chain


def qr_available():
    return importlib.util.find_spec("cv2") is not None


def decode_qr(image_bytes):
    """Decode every QR code in an image (needs opencv-python-headless). Returns a list of strings."""
    if not qr_available():
        raise RuntimeError("QR decoding needs OpenCV: pip install -r requirements-qr.txt")
    import cv2
    import numpy as np
    img = cv2.imdecode(np.frombuffer(image_bytes, np.uint8), cv2.IMREAD_COLOR)
    if img is None:
        raise ValueError("Not a readable image.")
    det = cv2.QRCodeDetector()
    ok, values, _, _ = det.detectAndDecodeMulti(img)
    found = [v for v in (values if ok else []) if v]
    if not found:
        v, _, _ = det.detectAndDecode(img)
        if v:
            found = [v]
    return list(dict.fromkeys(found))
