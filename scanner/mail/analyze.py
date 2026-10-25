"""Score a whole e-mail from its parsed parts plus the results for its links and attachments.

Pure: no network and no database access, so it can be tested and re-run cheaply. Every point of the
score is a Finding with evidence; no single weak signal can make a message "Dangerous".
"""
import html as html_lib
import re

from .. import data
from ..checks.content import analyze_html
from ..checks.osint import extract_pivots
from ..htmlutil import soup_of, visible_text
from ..models import Finding
from ..scoring import score
from ..utils import registered_domain

# E-mail verdicts are calibrated separately from URL verdicts (see `cli.py gmail eval`).
EMAIL_VERDICTS = [(70, "Dangerous"), (35, "Suspicious"), (10, "Low risk"), (0, "No signals found")]
LABELS = {"Dangerous": "URLscanner/Dangerous", "Suspicious": "URLscanner/Suspicious"}

_EXEC_ATTACH = re.compile(r"\.(exe|scr|com|pif|js|jse|vbs|vbe|wsf|hta|lnk|bat|cmd|ps1|msi|jar|apk)$", re.I)
_DISK_IMAGE = re.compile(r"\.(iso|img|vhdx?)$", re.I)
_HTML_ATTACH = re.compile(r"\.(html?|shtml|xhtml|svg)$", re.I)
_MACRO_DOC = re.compile(r"\.(docm|xlsm|pptm)$", re.I)
_ARCHIVE = re.compile(r"\.(zip|rar|7z|gz|tar|cab)$", re.I)
_ZERO_WIDTH = re.compile("[A-Za-z][​‍⁠﻿]+[A-Za-z]")
_WHATSAPP = re.compile(r"^https?://(?:wa\.me|api\.whatsapp\.com|chat\.whatsapp\.com)/", re.I)
_EMAIL_IN_NAME = re.compile(r"[\w.+-]+@([\w-]+(?:\.[\w-]+)+)")
_HIDDEN_STYLE = re.compile(r"display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0(?![.\d])", re.I)
# content-analysis findings that still mean something inside an e-mail body or attachment
_KEEP_CONTENT = ("form_mailto", "card_form", "seed_phrase", "iframe_data", "hidden_iframe", "obfuscation",
                 "cryptominer", "wallet_drainer", "tech_support_scam", "exec_download", "brand_login",
                 "form_offsite", "hotlink_brand")


def _domain_of(address):
    return registered_domain(address.rsplit("@", 1)[-1]) if address and "@" in address else ""


def sender_identity(parsed):
    """Who sent this, and does Gmail vouch for it? verified_aligned means Gmail itself reported DMARC
    pass for the same domain as the visible From address -- the only case a sender cannot be forged."""
    addr = (parsed.get("from_address") or "").lower()
    domain = _domain_of(addr)
    auth = parsed.get("auth_info") or {}
    dmarc_from = registered_domain(auth.get("dmarc_from") or "") if auth.get("dmarc_from") else domain
    aligned = bool(auth.get("verified") and auth.get("dmarc") == "pass" and domain and dmarc_from == domain)
    return {"address": addr, "domain": domain, "verified_aligned": aligned,
            "trusted_domain": domain in data.trusted_domains() and domain not in data.freemail_domains(),
            "freemail": domain in data.freemail_domains()}


def is_allowlisted(identity):
    allow = data.mail_allowlist()
    return identity["verified_aligned"] and (identity["address"] in allow or identity["domain"] in allow)


def brand_claim(display_name):
    """The brand a display name claims to be ("BCA Support", "PayPal Service"), if any.
    Short initialisms like "BRI" only count in capitals, so a person called "Bri" is not a bank."""
    name = display_name or ""
    for b in data.brands():
        for n in b["names"]:
            flags = 0 if len(n) <= 4 else re.I
            if re.search(rf"(?<![\w&]){re.escape(n)}(?![\w&])", name, flags):
                return b
    return None


def scam_categories(text):
    """{category: [phrases]} of scam wording, ignoring sentences that warn *against* scams
    ("jangan berikan kode OTP kepada siapa pun") -- real banks write those in every e-mail."""
    lists = data.lists()
    safe = lists.get("email_safe_phrases", [])
    sentences = re.split(r"(?<=[.!?])\s+|\n+", re.sub(r"[​-‍⁠﻿]", "", text or "").lower())
    kept = " \n ".join(s for s in sentences if not any(p in s for p in safe))
    kept = re.sub(r"\s+", " ", kept)
    out = {}
    for cat, phrases in lists.get("email_scam_phrases", {}).items():
        hits = [p for p in phrases if re.search(rf"(?<![\w]){re.escape(p)}(?![\w])", kept)]
        if hits:
            out[cat] = hits
    return out


def email_verdict(risk):
    return next(v for t, v in EMAIL_VERDICTS if risk >= t)


def analyze_email(parsed, link_results=(), attachment_results=(), sender_scan=None, seen_before=None,
                  notes=()):
    """Score one message.

    parsed             -- extract.parse_eml(..., include_payloads=True) output
    link_results       -- [{url, host, registered_domain, source, mismatch, shown_domain, result}]
    attachment_results -- [{filename, type, flags, html_findings, html_password, qr, skipped}]
    sender_scan        -- passive scan_url() result for the sender's domain (or None)
    seen_before        -- True / False / None (None = unknown; never counted as a signal)
    """
    findings = []

    def add(fid, title, severity, weight, evidence=""):
        findings.append(Finding(fid, title, severity, weight=round(weight, 3), evidence=str(evidence)[:600],
                                category="mail"))

    ident = sender_identity(parsed)
    from_reg = ident["domain"]
    auth = parsed.get("auth_info") or {}
    verified = bool(auth.get("verified"))
    trusted_sender = ident["verified_aligned"] and ident["trusted_domain"]
    owned_by = data.brand_sender_domains()

    # ---- authentication -----------------------------------------------------------------
    # A forger would claim "pass", never "fail", so failures count even when unverified.
    dmarc, spf, dkim = auth.get("dmarc", ""), auth.get("spf", ""), auth.get("dkim", "")
    src = "Gmail" if verified else "the file's headers (unverified)"
    if dmarc == "fail":
        add("mail.auth.dmarc_fail", "Sender failed DMARC: the From address may be forged", "high",
            0.3 if verified else 0.2, f"dmarc=fail for {auth.get('dmarc_from') or from_reg}, per {src}")
    if spf in ("fail", "softfail"):
        add("mail.auth.spf_fail", f"SPF {spf}: sent from a server the domain does not authorise", "medium",
            0.12 if spf == "fail" else 0.06, f"per {src}")
    if dkim == "fail":
        add("mail.auth.dkim_fail", "DKIM signature is invalid (message altered or forged)", "medium", 0.1,
            f"per {src}")
    if auth.get("server") and spf in ("none", "") and dkim in ("none", "") and dmarc in ("none", ""):
        add("mail.auth.none", "Sender domain uses no e-mail authentication at all", "low", 0.05)

    reply = parsed.get("reply_to") or ""
    if reply and from_reg and _domain_of(reply) != from_reg:
        if _domain_of(reply) in data.freemail_domains() and not ident["freemail"]:
            add("mail.reply_to.freemail", "Replies go to a free-mail address, not the sender's organisation",
                "medium", 0.2, reply)
        else:
            add("mail.reply_to.mismatch", "Reply-To points to a different domain", "low", 0.06, reply)
    rp = parsed.get("return_path") or ""
    if rp and from_reg and _domain_of(rp) != from_reg:
        # normal for newsletters sent through a mailing service, so it barely counts
        add("mail.return_path.mismatch", "Envelope sender (Return-Path) is another domain", "info", 0.02, rp)

    # ---- sender identity ----------------------------------------------------------------
    claim = brand_claim(parsed.get("from_name"))
    if claim:
        owned = {d for d, b in owned_by.items() if b == claim["brand"]}
        if from_reg not in owned or ident["freemail"]:
            add("mail.sender.display_brand", f"Display name claims to be {claim['brand']} but the mail comes "
                f"from {from_reg or 'an unknown domain'}", "high", 0.45 if ident["freemail"] else 0.4,
                parsed.get("from", ""))
    m = _EMAIL_IN_NAME.search(parsed.get("from_name") or "")
    if m and registered_domain(m.group(1)) != from_reg:
        add("mail.sender.display_address", "Display name shows a different e-mail address than the real sender",
            "high", 0.35, parsed.get("from", ""))

    if sender_scan and not sender_scan.get("error") and not ident["freemail"]:
        for f in sender_scan.get("findings", []):
            fid, w = f["id"], f.get("weight", 0)
            if fid.startswith("lexical.brand.") or fid in ("lexical.homograph", "lexical.mixed_script"):
                add(f"mail.sender.{fid.split('.', 1)[1]}", f"Sender domain: {f['title']}", f["severity"],
                    min(w, 0.6), f.get("evidence", ""))
            elif fid == "lexical.tld":
                add("mail.sender.tld", f"Sender domain: {f['title']}", "low", 0.05, f.get("evidence", ""))
            elif fid == "whois.new_domain":
                add("mail.sender.new_domain", f"Sender domain is brand new ({f['title'].split('(')[-1].rstrip(')')})",
                    "high", 0.35, f.get("evidence", ""))
            elif fid == "whois.young_domain":
                add("mail.sender.young_domain", f"Sender domain is young ({f['title'].split('(')[-1].rstrip(')')})",
                    "medium", 0.15, f.get("evidence", ""))
            elif fid.startswith("blocklist."):
                add("mail.sender.blocklisted", "Sender domain is listed in a threat feed", "critical", 0.85,
                    f.get("evidence", ""))
            elif fid in ("dns.no_zone", "whois.unregistered"):
                add("mail.sender.no_domain", "Sender domain does not exist", "medium", 0.2, from_reg)
    if seen_before is False:
        add("mail.sender.first_contact", "First message ever received from this sender", "info", 0.03,
            ident["address"])

    # ---- text ---------------------------------------------------------------------------
    body_html = parsed.get("body_html") or ""
    body_text = parsed.get("body_text") or ""
    text = f"{parsed.get('subject', '')}\n{body_text}\n{visible_text(body_html) if body_html else ''}"
    cats = scam_categories(text)
    if len(cats) >= 2:
        w = 0.3 if len(cats) == 2 else 0.45
        if trusted_sender:
            w *= 0.25  # e.g. a real bank's own security notice
        add("mail.text.scam", f"Scam-style wording ({', '.join(sorted(cats))})", "high" if len(cats) >= 3 else "medium",
            w, "; ".join(f"{c}: “{p[0]}”" for c, p in sorted(cats.items())))
    pivots = extract_pivots(body_html + "<pre>" + html_lib.escape(body_text) + "</pre>", "https://mail.invalid/")
    if pivots["wallets"] and not trusted_sender:
        w = 0.3 if cats.keys() & {"money", "investment", "prize"} else 0.15
        add("mail.text.crypto_wallet", f"Contains a {pivots['wallets'][0]['coin']} wallet address", "high", w,
            pivots["wallets"][0]["address"])
    if any(_WHATSAPP.match(l.get("url", "")) for l in link_results) and not trusted_sender:
        add("mail.text.whatsapp", "Moves the conversation to WhatsApp", "low", 0.08)
    zw = _ZERO_WIDTH.findall(body_text + body_html)
    if len(zw) >= 3:
        add("mail.text.zero_width", "Invisible characters split words (spam-filter evasion)", "medium", 0.15,
            f"{len(zw)} occurrences")

    # ---- HTML body ----------------------------------------------------------------------
    if body_html:
        soup = soup_of(body_html)
        forms = soup.find_all("form")
        if forms:
            pw = any(f.find("input", attrs={"type": re.compile("^password$", re.I)}) for f in forms)
            add("mail.html.form", "The e-mail itself contains a form asking for a password" if pw else
                "The e-mail itself contains a fill-in form", "high" if pw else "medium", 0.45 if pw else 0.2)
        hidden = [t.get_text(" ", strip=True) for t in soup.find_all(style=_HIDDEN_STYLE)]
        hidden_len = sum(len(h) for h in hidden)
        if hidden_len > 300:  # preheader snippets are ~100 chars; text stuffing is far longer
            add("mail.html.hidden_text", "Large block of hidden text (spam-filter evasion)", "low", 0.1,
                f"{hidden_len} hidden characters")
        s = analyze_html(body_html, f"https://{from_reg or 'mail.invalid'}/", from_reg, trusted=trusted_sender)
        for f in s.findings:
            short = f.id.split(".", 1)[1]
            if short.split(".")[0] in _KEEP_CONTENT and f.weight > 0:
                add(f"mail.html.{short}", f.title, f.severity, f.weight, f.evidence)

    # ---- links --------------------------------------------------------------------------
    brand_owned = data.brand_domains()
    mismatches, platforms = [], []
    for l in link_results:
        reg = l.get("registered_domain", "")
        if l.get("mismatch"):
            shown_brand = brand_owned.get(l.get("shown_domain", ""))
            # a brand's own verified newsletter routes its links through click-tracking services
            own_tracking = bool(shown_brand) and ident["verified_aligned"] and owned_by.get(from_reg) == shown_brand
            if shown_brand and brand_owned.get(reg) != shown_brand and not own_tracking:
                add("mail.link.fake_brand_text", f"Link text shows {l['shown_domain']} but it goes to {reg}", "high",
                    0.4, l.get("text", ""))
            else:
                mismatches.append(l)
        platform = data.abused_platform(l.get("host", ""))
        if platform:
            same_owner = reg == from_reg or (owned_by.get(reg) and owned_by.get(reg) == owned_by.get(from_reg))
            if not (ident["verified_aligned"] and same_owner):
                platforms.append(platform)
    if mismatches:
        add("mail.link.mismatch", "Some links show one address but go to another", "low", 0.1,
            f"{mismatches[0].get('shown_domain')} → {mismatches[0].get('registered_domain')}")
    if platforms:
        add("mail.link.abused_platform", f"Links to a platform where anyone can publish ({platforms[0]})", "medium",
            0.15, ", ".join(sorted(set(platforms))[:4]))
    if any(l.get("source") == "qr" for l in link_results):
        add("mail.qr.link", "A QR code in the message leads to a website (quishing)", "low", 0.08)

    ranked = sorted((l for l in link_results if (l.get("result") or {}).get("risk_score")),
                    key=lambda l: -l["result"]["risk_score"])
    flagged_domains = set()
    for l in ranked:
        r = l["result"]
        risk = r["risk_score"]
        reg = l.get("registered_domain", "")
        if risk < 20 or reg in flagged_domains:
            continue
        first = not flagged_domains
        if not first and risk < 50:
            break
        flagged_domains.add(reg)
        why = "; ".join(x["title"] for x in (r.get("reasons") or [])[:3])
        origin = {"qr": " (from a QR code)", "attachment": " (inside an attachment)"}.get(l.get("source"), "")
        sev = "critical" if risk >= 80 else "high" if risk >= 50 else "medium"
        add("mail.link.risky" if first else "mail.link.risky_more",
            f"Link to {l.get('host') or reg}{origin} rated {r.get('verdict')} ({risk}/100)", sev,
            min(risk / 100, 0.9) * (1 if first else 0.5), why)
        if len(flagged_domains) >= 2:
            break

    # ---- attachments --------------------------------------------------------------------
    for a in attachment_results:
        fn = a.get("filename") or ""
        if not a.get("inline"):
            if _EXEC_ATTACH.search(fn):
                apk = fn.lower().endswith(".apk")
                add("mail.attach.executable", f"Executable attachment: {fn}" +
                    (" (Android app sent by e-mail: a common Indonesian scam)" if apk else ""), "critical",
                    0.55, fn)
            elif _DISK_IMAGE.search(fn):
                add("mail.attach.disk_image", f"Disk-image attachment: {fn}", "high", 0.4, fn)
            elif _HTML_ATTACH.search(fn):
                add("mail.attach.html", f"HTML/SVG attachment opens a local web page: {fn}", "medium", 0.2, fn)
            elif _MACRO_DOC.search(fn):
                add("mail.attach.macro_doc", f"Macro-enabled Office document: {fn}", "high", 0.25, fn)
            elif _ARCHIVE.search(fn):
                add("mail.attach.archive", f"Archive attachment: {fn}", "info", 0.03, fn)
        if a.get("html_password"):
            add("mail.attach.html_login", f"Attachment {fn} is a login page", "critical", 0.6, fn)
        for fl in a.get("flags") or []:
            add(f"mail.attach.{fl['id'].split('.', 1)[1]}", f"{fn}: {fl['title']}", fl["severity"], fl["weight"],
                fl.get("evidence", ""))
        for f in a.get("html_findings") or []:
            short = f["id"].split(".", 1)[1]
            if short.split(".")[0] in _KEEP_CONTENT and f.get("weight", 0) > 0:
                add(f"mail.attach.html.{short}", f"{fn}: {f['title']}", f["severity"], f["weight"],
                    f.get("evidence", ""))

    # ---- correlation: weak alone, strong together ----------------------------------------
    ids = {f.id for f in findings}
    spoof = "mail.sender.display_brand" in ids or any(
        i.startswith("mail.sender.brand.") or i in ("mail.sender.homograph", "mail.sender.mixed_script") for i in ids)
    asks = sorted(cats.keys() & {"money", "credentials"})
    if seen_before is False and asks:
        add("mail.corr.first_contact_request", f"First-time sender asks for {' and '.join(asks)}", "high", 0.3)
    if spoof and asks:
        add("mail.corr.brand_request", f"Impersonates a brand and asks for {' and '.join(asks)}", "high", 0.3)
    if dmarc == "fail" and spoof:
        add("mail.corr.forged_brand", "Forged sender pretending to be a known brand", "critical", 0.4)
    if claim and "mail.sender.display_brand" in ids:
        owned = {d for d, b in brand_owned.items() if b == claim["brand"]}
        elsewhere = sorted({l.get("registered_domain") for l in link_results
                            if l.get("registered_domain") and l["registered_domain"] not in owned
                            and l["registered_domain"] not in data.trusted_domains()})
        if elsewhere:
            add("mail.corr.brand_link", f"Claims to be {claim['brand']} but links to {elsewhere[0]}", "high", 0.3,
                ", ".join(elsewhere[:4]))

    # one finding per id (the strongest), so ten macro attachments do not count ten times
    best = {}
    for f in findings:
        if f.id not in best or f.weight > best[f.id].weight:
            best[f.id] = f
    findings = sorted(best.values(), key=lambda f: -f.weight)
    sc = score(findings, fetched=False)
    verdict = email_verdict(sc["risk_score"])
    allow = is_allowlisted(ident)
    return {
        "risk_score": sc["risk_score"],
        "verdict": verdict,
        "reasons": sc["reasons"],
        "findings": [f.to_dict() for f in findings],
        "sender": ident,
        "seen_before": seen_before,
        "brand_claim": claim["brand"] if claim else "",
        "scam_categories": {k: v[:5] for k, v in cats.items()},
        "allowlisted": allow,
        "label": "" if allow else LABELS.get(verdict, ""),
        "notes": list(notes),
    }
