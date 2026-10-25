"""Phase A of the Gmail scanner: whole-message analysis, passive link scanning, redaction. No network."""
import io
import json
import socket
import sqlite3
import time
import zipfile
from email.message import EmailMessage

import pytest

import config
from scanner import data, net, report, storage
from scanner.checks import ScanContext, dns_checks, whois_age
from scanner.core import scan_url
from scanner.extract import parse_eml, unwrap_redirector
from scanner.mail import pipeline
from scanner.mail.analyze import analyze_email, scam_categories
from scanner.mail.pipeline import looks_like_token_link, persist, scan_message
from scanner.mail.redact import Redactor
from scanner.utils import split_host

GMAIL_PASS = "mx.google.com; dkim=pass header.i=@{d}; spf=pass smtp.mailfrom={d}; dmarc=pass header.from={d}"
GMAIL_FAIL = "mx.google.com; spf=fail smtp.mailfrom={d}; dmarc=fail (p=NONE) header.from={d}"


def make_mail(sender, subject="Hello", text="", html="", auth=(), reply_to="", attachments=()):
    m = EmailMessage()
    m["From"] = sender
    m["To"] = "me@gmail.com"
    m["Subject"] = subject
    if reply_to:
        m["Reply-To"] = reply_to
    for a in auth:  # first one ends up on top, like the receiving server's own header
        m["Authentication-Results"] = a
    m.set_content(text or "(no text)")
    if html:
        m.add_alternative(html, subtype="html")
    for name, ctype, payload in attachments:
        maintype, subtype = ctype.split("/")
        m.add_attachment(payload, maintype=maintype, subtype=subtype, filename=name)
    return m.as_bytes()


def offline(raw, **kw):
    kw.setdefault("network", "none")
    return scan_message(raw, **kw)


def ids(r):
    return {f["id"] for f in r["findings"]}


# --- sender identity -------------------------------------------------------------------------

def test_display_name_brand_from_freemail():
    r = offline(make_mail("BCA <bca.official@gmail.com>", text="Halo nasabah"))
    assert "mail.sender.display_brand" in ids(r)
    assert r["brand_claim"] == "Bank Central Asia"


def test_short_brand_names_are_case_sensitive():
    r = offline(make_mail("Bri Larson <bri@example.org>"))
    assert "mail.sender.display_brand" not in ids(r)


def test_display_name_with_other_address():
    r = offline(make_mail('"service@paypal.com" <x@mailer.example>'))
    assert "mail.sender.display_address" in ids(r)


# --- scam wording ----------------------------------------------------------------------------

def test_one_scam_category_is_not_enough():
    assert len(scam_categories("Akun anda akan diblokir dalam waktu 24 jam.")) == 1
    r = offline(make_mail("Shop <news@shop.example>", text="Akun anda akan diblokir dalam waktu 24 jam."))
    assert "mail.text.scam" not in ids(r)


def test_two_scam_categories_trigger():
    text = "Selamat anda memenangkan undian berhadiah! Transfer ke rekening kami untuk biaya admin."
    assert {"prize", "money"} <= scam_categories(text).keys()
    r = offline(make_mail("Panitia <hadiah@undian.example>", text=text))
    assert "mail.text.scam" in ids(r)


def test_real_bank_warning_is_not_scam():
    text = ("Transaksi anda berhasil. Jangan berikan kode OTP kepada siapa pun. BCA tidak pernah meminta "
            "PIN atau kata sandi anda. Waspada penipuan yang mengatasnamakan BCA, jangan kirimkan kode OTP.")
    raw = make_mail("BCA <info@bca.co.id>", text=text, auth=[GMAIL_PASS.format(d="bca.co.id")])
    r = offline(raw, trusted_source=True)
    assert "mail.text.scam" not in ids(r)
    assert "mail.sender.display_brand" not in ids(r)
    assert r["verdict"] in ("No signals found", "Low risk")
    assert r["label"] == ""


# --- authentication trust boundary -----------------------------------------------------------

def test_forged_auth_header_below_gmail_is_ignored():
    raw = make_mail("Pay <a@pay-secure.example>", auth=[
        GMAIL_FAIL.format(d="pay-secure.example"),
        "mx.google.com; spf=pass; dkim=pass; dmarc=pass header.from=pay-secure.example",  # added by the sender
    ])
    info = parse_eml(raw, trusted_source=True)
    assert info["auth"]["dmarc"] == "fail" and info["auth_info"]["verified"] is True


def test_top_header_not_from_gmail_is_unverified():
    raw = make_mail("a <a@x.example>", auth=["evil.example; spf=pass; dmarc=pass header.from=x.example"])
    assert parse_eml(raw, trusted_source=True)["auth_info"]["verified"] is False


def test_uploaded_file_auth_is_unverified():
    raw = make_mail("a <a@x.example>", auth=[GMAIL_PASS.format(d="x.example")])
    info = parse_eml(raw)  # trusted_source defaults to False: nobody knows who wrote the file
    assert info["auth"]["dmarc"] == "pass" and info["auth_info"]["verified"] is False


def test_allowlist_needs_verified_dmarc(monkeypatch):
    monkeypatch.setattr(data, "mail_allowlist", lambda: frozenset({"partner.example"}))
    good = offline(make_mail("P <boss@partner.example>", auth=[GMAIL_PASS.format(d="partner.example")]),
                   trusted_source=True)
    assert good["allowlisted"] is True and good["label"] == ""
    forged = offline(make_mail("P <boss@partner.example>", auth=[GMAIL_FAIL.format(d="partner.example")]),
                     trusted_source=True)
    assert forged["allowlisted"] is False
    unverified = offline(make_mail("P <boss@partner.example>", auth=[GMAIL_PASS.format(d="partner.example")]))
    assert unverified["allowlisted"] is False


def test_unknown_first_contact_is_not_a_signal():
    raw = make_mail("x <x@new.example>", text="Kirimkan kode OTP anda dan transfer ke rekening kami.")
    unknown = offline(raw, seen_before=lambda a: None)
    assert "mail.sender.first_contact" not in ids(unknown)
    assert "mail.corr.first_contact_request" not in ids(unknown)
    failing = offline(raw, seen_before=lambda a: 1 / 0)
    assert failing["seen_before"] is None
    new = offline(raw, seen_before=lambda a: False)
    assert "mail.corr.first_contact_request" in ids(new)


# --- public suffixes (Indonesian second-level domains) ---------------------------------------

@pytest.mark.parametrize("host,reg", [
    ("klik.bca.co.id", "bca.co.id"), ("djponline.pajak.go.id", "pajak.go.id"),
    ("toko-murah.web.id", "toko-murah.web.id"), ("a.promo.my.id", "promo.my.id"),
    ("www.sman1.sch.id", "sman1.sch.id"),
])
def test_indonesian_registered_domains(host, reg):
    assert split_host(host)[3] == reg


# --- links -----------------------------------------------------------------------------------

def test_unwrap_nested_redirectors():
    inner = "https%253A%252F%252Fevil.example%252Flogin"
    url = ("https://www.google.com/url?q=https%3A%2F%2Feur01.safelinks.protection.outlook.com%2F%3Furl%3D"
           + inner)
    chain = unwrap_redirector(url)
    assert chain[-1] == "https://evil.example/login"
    assert len(chain) == 2


def test_unwrap_ignores_normal_links():
    assert unwrap_redirector("https://example.com/url?q=https://evil.example/") == []


def test_google_forms_gets_no_trust_damping():
    assert ScanContext("https://www.google.com/").trusted is True
    assert ScanContext("https://docs.google.com/forms/d/e/abc/viewform").trusted is False


def test_google_share_notification_is_not_penalised():
    link = '<a href="https://docs.google.com/document/d/1AbCdEfGhIjKlMnOpQrStUv/edit">Open</a>'
    shared = make_mail("Budi (via Google Docs) <drive-shares-dm-noreply@google.com>", html=link,
                       auth=[GMAIL_PASS.format(d="google.com")])
    assert "mail.link.abused_platform" not in ids(offline(shared, trusted_source=True))
    stranger = make_mail("Budi <budi@random.example>", html=link)
    assert "mail.link.abused_platform" in ids(offline(stranger))


def test_fake_brand_link_text():
    html = '<a href="https://klikbca-login.example/x">https://www.klikbca.com</a>'
    r = offline(make_mail("Info <info@news.example>", html=html))
    assert "mail.link.fake_brand_text" in ids(r)


def test_verified_brand_newsletter_tracking_links_are_not_fake():
    html = '<a href="https://u123.ct.sendgrid.net/ls/click?upn=x">https://shopee.co.id/flash-sale</a>'
    real = make_mail("Shopee <info@shopee.co.id>", html=html, auth=[GMAIL_PASS.format(d="shopee.co.id")])
    r = offline(real, trusted_source=True)
    assert "mail.link.fake_brand_text" not in ids(r) and "mail.link.mismatch" in ids(r)
    forged = make_mail("Shopee <info@shopee-promo.xyz>", html=html)
    assert "mail.link.fake_brand_text" in ids(offline(forged))


@pytest.mark.parametrize("url,token", [
    ("https://accounts.example.com/reset-password?t=abc", True),
    ("https://shop.example/unsubscribe?u=1", True),
    ("https://x.example/a?id=8f3b2c9d1e4a7b6c5d0e9f8a", True),
    ("https://news.example/2024/10/article-title", False),
    ("https://phish.example/login", False),           # a login *page* is not a one-click action
    ("https://app.example/login?token=abcd1234", True),
])
def test_token_like_links(url, token):
    assert looks_like_token_link(url) is token


def test_links_are_never_opened_unless_deep(monkeypatch):
    calls = []

    def fake_scan(url, passive=False, network="dns", store=True):
        calls.append((url, passive))
        return {"id": f"s{len(calls)}", "url": url, "risk_score": 0, "verdict": "Unverified", "reasons": [],
                "findings": [], "error": None}

    monkeypatch.setattr(pipeline, "scan_url", fake_scan)
    html = ('<a href="https://one.example/a">1</a> <a href="https://two.example/b">2</a> '
            '<a href="https://www.google.com/">g</a>')
    raw = make_mail("x <x@sender.example>", html=html)
    scan_message(raw)
    assert calls and all(passive for _, passive in calls)
    calls.clear()
    r = scan_message(raw, deep=True, deep_links={1})
    opened = [u for u, passive in calls if not passive]
    assert opened == ["https://one.example/a"]
    assert [l["mode"] for l in r["links"] if l["host"] == "www.google.com"] == ["passive"]


# --- attachments -----------------------------------------------------------------------------

def test_apk_attachment():
    r = offline(make_mail("Kurir <kurir@paket.example>", text="Cek resi paket anda",
                          attachments=[("resi.apk", "application/vnd.android.package-archive", b"PK\x03\x04x")]))
    assert "mail.attach.executable" in ids(r)
    assert r["verdict"] in ("Suspicious", "Dangerous")


def test_html_attachment_login_page():
    page = b"<html><title>Sign in</title><form action='https://collect.example/p'>" \
           b"<input name=u><input type=password name=p></form></html>"
    r = offline(make_mail("x <x@a.example>", attachments=[("invoice.html", "text/html", page)]))
    assert {"mail.attach.html_login", "mail.attach.html"} <= ids(r)
    assert any(l["source"] == "attachment" and l["host"] == "collect.example" for l in r["links"])


def test_high_ratio_zip_is_not_decompressed(monkeypatch):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("big.bin", b"\0" * (2 * 1024 * 1024))
    reads = []
    monkeypatch.setattr(zipfile.ZipFile, "read", lambda self, *a, **k: reads.append(a) or b"")
    t0 = time.monotonic()
    r = offline(make_mail("x <x@a.example>", attachments=[("data.zip", "application/zip", buf.getvalue())]))
    att = r["attachments"][0]
    assert att["archive"]["ratio"] > 100
    assert reads == [] and time.monotonic() - t0 < 5


def test_qr_code_in_image(monkeypatch):
    monkeypatch.setattr(pipeline, "qr_available", lambda: True)
    monkeypatch.setattr(pipeline, "decode_qr", lambda b: ["https://qr-phish.example/login"])
    r = offline(make_mail("x <x@a.example>", attachments=[("scan.png", "image/png", b"\x89PNG....")]))
    assert any(l["source"] == "qr" for l in r["links"])
    assert "mail.qr.link" in ids(r)


# --- robustness ------------------------------------------------------------------------------

def test_garbage_and_deeply_nested_mime_do_not_crash():
    assert isinstance(offline(b"\x00\xff garbage \r\n\r\n\xfe"), dict)
    nested = b"From: a@b.example\r\nSubject: deep\r\n"
    for i in range(400):
        nested += f'Content-Type: multipart/mixed; boundary="b{i}"\r\n\r\n--b{i}\r\n'.encode()
    r = offline(nested + b"Content-Type: text/plain\r\n\r\nhi\r\n")
    assert isinstance(r, dict) and "verdict" in r


def test_time_budget_returns_partial_result(monkeypatch):
    def slow(url, **kw):
        time.sleep(3)
        return {"id": "x", "url": url, "risk_score": 0, "verdict": "Unverified", "reasons": [], "findings": []}

    monkeypatch.setattr(pipeline, "scan_url", slow)
    t0 = time.monotonic()
    r = scan_message(make_mail("x <x@a.example>", html='<a href="https://slow.example/">x</a>'), budget=0.3)
    assert time.monotonic() - t0 < 2
    assert any("time budget" in n for n in r["notes"])
    assert r["links"][0]["verdict"] == "Not analysed"


# --- passive scanning never touches the target ------------------------------------------------

@pytest.fixture
def no_target_contact(monkeypatch):
    seen = {"fetch": [], "resolve": [], "connect": [], "dns": [], "whois": []}

    def record(kind, ret=None):
        def fn(*a, **k):
            seen[kind].append(a[0] if a else k)
            if ret is not None:
                return ret
            raise net.BlockedTarget("network disabled in test")
        return fn

    monkeypatch.setattr(net, "safe_fetch", record("fetch"))
    monkeypatch.setattr(net, "resolve", record("resolve"))
    monkeypatch.setattr(net, "connect_public", record("connect"))
    monkeypatch.setattr(socket, "create_connection", record("connect"))
    monkeypatch.setattr(dns_checks, "query", record("dns", ([], None)))
    monkeypatch.setattr(dns_checks, "nxdomain", lambda name: seen["dns"].append(name) or False)
    monkeypatch.setattr(whois_age, "lookup", record("whois", {"error": "offline test"}))
    monkeypatch.setattr(storage, "whois_cache_get", lambda d: None)
    return seen


def test_passive_scan_never_contacts_target(no_target_contact):
    # (a real suffix: ".example" is not a public suffix, so its registered domain would be the whole host)
    r = scan_url("https://abc123.tracker-mail.xyz/open?id=99", passive=True, store=False)
    seen = no_target_contact
    assert seen["fetch"] == [] and seen["resolve"] == [] and seen["connect"] == []
    assert seen["dns"] and all("abc123" not in n for n in seen["dns"])  # registered domain only
    assert r["verdict"] in ("Unverified", "Suspicious", "Likely malicious", "Malicious")
    assert r["verdict"] != "Clean"


def test_network_none_makes_no_dns_or_whois(no_target_contact):
    scan_url("https://quiet.example/", passive=True, network="none", store=False)
    seen = no_target_contact
    assert all(not v for v in seen.values()), seen


def test_passive_low_score_is_unverified(no_target_contact):
    r = scan_url("https://quiet.example/", passive=True, network="none", store=False)
    assert r["risk_score"] < 20 and r["verdict"] == "Unverified"


# --- redaction -------------------------------------------------------------------------------

SECRET = "SECRET123tok9876zz"


def test_tokens_never_reach_db_exports_or_logs(caplog):
    caplog.set_level("DEBUG")
    html = (f'<a href="https://reset.example/account/reset?token={SECRET}&u=me%40gmail.com">reset</a>'
            f'<a href="https://evil.example/p/{SECRET}">x</a>')
    r = offline(make_mail("x <x@a.example>", html=html, text=f"https://other.example/?t={SECRET}"))
    batch = persist(r, account="me@gmail.com", folder="INBOX", msgid="t-redact-1")
    assert SECRET not in json.dumps(r)
    con = sqlite3.connect(config.DB_PATH)
    dump = "\n".join(con.iterdump())
    con.close()
    assert SECRET not in dump and "me%40gmail.com" not in dump
    rows = storage.list_scans(batch_id=batch)
    assert rows
    for row in rows:
        full = storage.get_scan(row["id"])["result"]
        for fmt in ("json", "md", "html"):
            assert SECRET not in report.render(fmt, full)
    assert SECRET not in caplog.text


def test_truncated_secret_is_masked():
    red = Redactor()
    red.add(f"https://x.example/r?token={SECRET}")
    assert red.text(f"evidence: https://x.example/r?token={SECRET[:9]}…") == "evidence: https://x.example/r?token=***…"
    assert SECRET[:9] not in red.text(f"...{SECRET[:9]}")


def test_rescan_updates_without_duplicates():
    raw = make_mail("x <x@a.example>", html='<a href="https://dup.example/">x</a>')
    first = persist(offline(raw), account="me@gmail.com", folder="INBOX", msgid="t-dup-1")
    second = persist(offline(raw), account="me@gmail.com", folder="INBOX", msgid="t-dup-1")
    rows = [e for e in storage.list_emails(limit=500) if e["msgid"] == "t-dup-1"]
    assert len(rows) == 1 and rows[0]["batch_id"] == second != first
    assert storage.get_batch(first) is not None  # history is kept


def test_parse_eml_default_output_unchanged():
    info = parse_eml(make_mail("a <a@b.example>", attachments=[("x.pdf", "application/pdf", b"%PDF-1.4")]))
    assert "body_text" not in info and "data" not in info["attachments"][0]
    assert set(info) >= {"subject", "from", "auth", "links", "attachments", "warnings"}


def test_analyze_email_is_pure():
    parsed = parse_eml(make_mail("a <a@b.example>", text="hi"), include_payloads=True)
    r = analyze_email(parsed)
    assert r["verdict"] == "No signals found" and r["risk_score"] == 0
