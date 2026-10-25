"""Phase D: the /mail pages (token required, Host check, CSRF, attacker-controlled text escaped)."""
from email.message import EmailMessage

import pytest

import config
import webapp
from scanner.mail.pipeline import persist, scan_message

EVIL_SUBJECT = '<script>alert(1)</script> Akun anda diblokir'


def stored_mail(msgid="w-1"):
    m = EmailMessage()
    m["From"] = '"<img src=x onerror=alert(2)>" <x@evil-bank.xyz>'
    m["To"] = "me@gmail.com"
    m["Subject"] = EVIL_SUBJECT
    m.set_content("hi")
    m.add_alternative('<a href="https://evil-bank.xyz/login?t=abcdef123456">https://www.klikbca.com</a>',
                      subtype="html")
    r = scan_message(m.as_bytes(), network="none")
    persist(r, account="me@gmail.com", folder="INBOX", msgid=msgid)
    return r


@pytest.fixture
def client(monkeypatch, tmp_path):
    monkeypatch.setattr(config, "DB_PATH", str(tmp_path / "web.db"))
    monkeypatch.setattr(config, "ACCESS_TOKEN", "s3cret")
    monkeypatch.setattr(config, "ALLOWED_HOSTS", set())
    monkeypatch.setattr(config, "GMAIL_ADDRESS", "me@gmail.com")
    monkeypatch.setattr(config, "GMAIL_APP_PASSWORD", "x")
    webapp._rate.clear()
    c = webapp.app.test_client()
    with c.session_transaction() as sess:
        sess["csrf"] = "t"
        sess["authed"] = webapp._token_tag()
    return c


def test_mail_pages_need_access_token(client, monkeypatch):
    monkeypatch.setattr(config, "ACCESS_TOKEN", "")
    assert client.get("/mail").status_code == 403
    assert b"/mail" not in client.get("/").data  # no nav link either


def test_foreign_host_rejected(client, monkeypatch):
    # bearer auth, so the Host check itself is what is being tested (cookies are per host anyway)
    auth = {"Authorization": "Bearer s3cret"}
    assert client.get("/mail", base_url="http://localhost:5000", headers=auth).status_code == 200
    assert client.get("/mail", base_url="http://attacker.example", headers=auth).status_code == 403
    monkeypatch.setattr(config, "ALLOWED_HOSTS", {"scanner.lan"})
    assert client.get("/mail", base_url="http://scanner.lan", headers=auth).status_code == 200


def test_scan_now_needs_csrf(client, monkeypatch):
    started = []
    monkeypatch.setattr(webapp, "start_mail_job", lambda what, fn: started.append(what) or True)
    assert client.post("/mail/scan", data={"days": "1"}).status_code == 400
    assert client.post("/mail/scan", data={"days": "1", "csrf_token": "t"}).status_code == 302
    assert started == ["scan"]


def test_deep_scan_needs_explicit_confirmation(client, monkeypatch):
    stored_mail()
    started = []
    monkeypatch.setattr(webapp, "start_mail_job", lambda what, fn: started.append(what) or True)
    assert client.post("/mail/w-1/deep", data={"csrf_token": "t", "link": "1"}).status_code == 400
    assert client.post("/mail/w-1/deep", data={"csrf_token": "t", "link": "1", "understand": "on"}).status_code == 302
    assert started == ["deep"]


def test_mail_csv_export_neutralises_formulas(client):
    m = EmailMessage()
    m["From"] = "x@evil.xyz"
    m["Subject"] = '=HYPERLINK("http://evil.xyz","click")'
    m.set_content("hi")
    persist(scan_message(m.as_bytes(), network="none"), account="me@gmail.com", folder="INBOX", msgid="csv-1")
    body = client.get("/mail/export.csv").get_data(as_text=True)
    assert "'=HYPERLINK" in body and "\n=HYPERLINK" not in body and ",=HYPERLINK" not in body


def test_url_csv_report_neutralises_formulas():
    from scanner import report
    out = report.to_csv({"url": "=cmd|' /C calc'!A0", "error": "bad", "findings": [], "reasons": []})
    assert "'=cmd" in out


def test_job_status_api_and_dashboard_stats(client):
    stored_mail("w-2")
    assert client.get("/api/mail/job").get_json()["running"] is False
    page = client.get("/mail?q=Akun").get_data(as_text=True)
    assert "1 messages analysed" in page or "messages analysed" in page
    assert "Akun anda diblokir" in page
    assert "Akun anda diblokir" not in client.get("/mail?q=nothing-matches").get_data(as_text=True)


def test_only_one_gmail_job_across_workers(client):
    from scanner import storage
    assert storage.claim_job("t-job", "scan") is True
    assert storage.claim_job("t-job", "scan") is False      # e.g. a second gunicorn worker
    storage.finish_job("t-job", "done")
    assert storage.get_job("t-job") == {"running": False, "what": "scan", "message": "done", "error": ""}
    assert storage.claim_job("t-job", "deep") is True


def test_every_page_renders(client):
    """Smoke test: a template error anywhere shows up here, not in a user's browser."""
    from scanner.core import scan_url
    r = scan_url("https://paypa1-login.xyz/verify", passive=True, network="none")
    stored_mail("w-3")
    broken = "w-err"
    persist({"kind": "email", "error": "could not parse message (RecursionError)", "verdict": "Error",
             "risk_score": None, "links": [], "attachments": [], "findings": [], "reasons": [], "notes": []},
            account="me@gmail.com", folder="INBOX", msgid=broken)
    for path in ("/", "/guide", "/history", "/history?q=paypa1", f"/scan/{r['id']}", "/mail", "/mail/w-3",
                 f"/mail/{broken}", "/mail?verdict=Dangerous", f"/diff?url={r['url']}", "/api/mail/job"):
        assert client.get(path).status_code == 200, path
    assert client.get("/nope").status_code == 404


def test_attacker_text_is_escaped_and_links_defanged(client):
    stored_mail()
    for path in ("/mail", "/mail/w-1"):
        page = client.get(path).get_data(as_text=True)
        assert "<script>alert(1)" not in page and "&lt;script&gt;" in page
        assert "<img src=x" not in page
    detail = client.get("/mail/w-1").get_data(as_text=True)
    assert 'href="https://evil-bank' not in detail and "hxxps://evil-bank[.]xyz" in detail
    assert "abcdef123456" not in detail  # token redacted
