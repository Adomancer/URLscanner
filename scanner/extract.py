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


def parse_eml(raw_bytes):
    """Parse an e-mail and report its links, including text/href mismatches (a classic phishing tell)."""
    msg = email.message_from_bytes(raw_bytes, policy=email.policy.default)
    html_parts, text_parts = [], []
    attachments = []
    for part in msg.walk():
        if part.is_multipart():
            continue
        ctype = part.get_content_type()
        disp = (part.get("Content-Disposition") or "").lower()
        if "attachment" in disp or part.get_filename():
            attachments.append({"filename": part.get_filename() or "", "type": ctype,
                                "size": len(part.get_payload(decode=True) or b"")})
            continue
        try:
            body = part.get_content()
        except (LookupError, ValueError):
            body = (part.get_payload(decode=True) or b"").decode("utf-8", "replace")
        if ctype == "text/html":
            html_parts.append(body)
        elif ctype == "text/plain":
            text_parts.append(body)

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

    from_name, from_addr = parseaddr(str(msg.get("From", "")))
    _, reply_addr = parseaddr(str(msg.get("Reply-To", "")))
    _, return_path = parseaddr(str(msg.get("Return-Path", "")))
    auth = " ".join(str(h) for h in msg.get_all("Authentication-Results", []) or [])
    results = {k: (re.search(rf"\b{k}=(\w+)", auth, re.I).group(1).lower()
                   if re.search(rf"\b{k}=(\w+)", auth, re.I) else "") for k in ("spf", "dkim", "dmarc")}
    warnings = []
    if reply_addr and from_addr and _domain(reply_addr.split("@")[-1]) != _domain(from_addr.split("@")[-1]):
        warnings.append(f"Reply-To ({reply_addr}) differs from From ({from_addr})")
    if return_path and from_addr and _domain(return_path.split("@")[-1]) != _domain(from_addr.split("@")[-1]):
        warnings.append(f"Return-Path domain ({return_path}) differs from From")
    for k, v in results.items():
        if v in ("fail", "softfail", "permerror", "none"):
            warnings.append(f"{k.upper()} result: {v}")
    if any(l["mismatch"] for l in links):
        warnings.append("Some links display one address but point to another")
    risky_ext = re.compile(r"\.(exe|scr|js|vbs|hta|iso|img|lnk|html?|zip|rar|7z|docm|xlsm)$", re.I)
    for a in attachments:
        if risky_ext.search(a["filename"]):
            warnings.append(f"Risky attachment type: {a['filename']}")

    return {
        "subject": str(msg.get("Subject", ""))[:300],
        "from": str(msg.get("From", ""))[:200], "from_name": from_name, "from_address": from_addr,
        "reply_to": reply_addr, "return_path": return_path, "to": str(msg.get("To", ""))[:300],
        "date": str(msg.get("Date", "")), "message_id": str(msg.get("Message-ID", ""))[:200],
        "received_hops": len(msg.get_all("Received", []) or []),
        "auth": results, "links": links[:200], "attachments": attachments, "warnings": warnings,
    }


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
