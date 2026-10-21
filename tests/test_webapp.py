import io

import pytest

import config
import webapp


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setattr(config, "ACCESS_TOKEN", "")
    monkeypatch.setattr(config, "WEB_ACTIVE", False)
    monkeypatch.setattr(config, "TRUST_PROXY", False)
    monkeypatch.setattr(webapp, "scan_url", lambda *a, **k: None)  # never touch the network from tests
    webapp._rate.clear()
    c = webapp.app.test_client()
    with c.session_transaction() as sess:
        sess["csrf"] = "t"
    return c


def test_token_protects_pages_and_api(client, monkeypatch):
    monkeypatch.setattr(config, "ACCESS_TOKEN", "s3cret")
    r = client.get("/")
    assert r.status_code == 302 and "/login" in r.headers["Location"]
    assert client.get("/api/scan/nope").status_code == 401
    assert client.get("/", headers={"Authorization": "Bearer s3cret"}).status_code == 200
    assert client.get("/", headers={"Authorization": "Bearer wrong"}).status_code == 302


def test_login_flow(client, monkeypatch):
    monkeypatch.setattr(config, "ACCESS_TOKEN", "s3cret")
    assert client.post("/login", data={"csrf_token": "t", "token": "nope"}).status_code == 401
    r = client.post("/login", data={"csrf_token": "t", "token": "s3cret", "next": "//evil.test/"})
    assert r.status_code == 302 and r.headers["Location"] == "/"  # no open redirect off-site
    assert client.get("/").status_code == 200


def test_bearer_api_needs_no_csrf(client, monkeypatch):
    monkeypatch.setattr(config, "ACCESS_TOKEN", "s3cret")
    r = client.post("/api/scan", json={"url": "https://example.com"}, headers={"Authorization": "Bearer s3cret"})
    assert r.status_code == 200 and r.get_json()["status"] == "running"


def test_active_scan_off_in_web_by_default(client, monkeypatch):
    assert webapp.parse_options({"active": "1", "authorized": "1"})["active"] is False
    assert b"opt-active" not in client.get("/").data
    monkeypatch.setattr(config, "WEB_ACTIVE", True)
    assert webapp.parse_options({"active": "1", "authorized": "1"}) == {"active": True, "authorized": True,
                                                                        "browser": False}
    assert b"opt-active" in client.get("/").data


def test_eml_summary_shown_on_batch_page(client):
    raw = (b"From: Bank <alerts@bank.test>\r\nSubject: Verify your account now\r\n"
           b"Content-Type: text/html\r\n\r\n<a href='https://evil.test/login'>https://bank.test</a>")
    r = client.post("/scan", data={"csrf_token": "t", "mode": "file", "file": (io.BytesIO(raw), "msg.eml")},
                    content_type="multipart/form-data")
    assert r.status_code == 302 and "/batch?b=" in r.headers["Location"]
    page = client.get(r.headers["Location"]).get_data(as_text=True)
    assert "Verify your account now" in page
    assert "evil[.]test" in page and "text ≠ link" in page


def test_rate_limit_ignores_spoofed_forwarded_for(client):
    for i in range(webapp.RATE_LIMIT):
        with webapp.app.test_request_context(headers={"X-Forwarded-For": f"10.0.0.{i}"},
                                             environ_base={"REMOTE_ADDR": "198.51.100.7"}):
            assert webapp.rate_limited() is False
    with webapp.app.test_request_context(headers={"X-Forwarded-For": "10.9.9.9"},
                                         environ_base={"REMOTE_ADDR": "198.51.100.7"}):
        assert webapp.rate_limited() is True


def test_trusted_proxy_uses_last_forwarded_hop(monkeypatch):
    monkeypatch.setattr(config, "TRUST_PROXY", True)
    with webapp.app.test_request_context(headers={"X-Forwarded-For": "1.2.3.4, 203.0.113.9"}):
        assert webapp.client_ip() == "203.0.113.9"
