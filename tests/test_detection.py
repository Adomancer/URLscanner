import pytest

from scanner.checks import ScanContext
from scanner.checks.lexical import run as lexical_run


def ids(url):
    return {f.id for f in lexical_run(ScanContext(url)).findings}


def titles(url):
    return " ".join(f.title for f in lexical_run(ScanContext(url)).findings)


def test_homograph_cyrillic_paypal():
    # xn--pypal-4ve.com decodes to "pаypal.com" with a Cyrillic 'а'
    found = ids("https://xn--pypal-4ve.com/")
    assert "lexical.homograph" in found or "lexical.mixed_script" in found


@pytest.mark.parametrize("url,brand", [
    ("https://paypa1.com/login", "PayPal"),
    ("https://micros0ft-account.xyz/", "Microsoft"),
    ("https://amaz0n-security.top/", "Amazon"),
])
def test_typo_and_homoglyph(url, brand):
    assert brand.split()[0].lower() in titles(url).lower()


def test_brand_in_subdomain():
    found = ids("https://paypal.com.secure-login.tk/signin")
    assert any("brand.subdomain" in f for f in found)


def test_userinfo_trick():
    assert "lexical.userinfo" in ids("https://paypal.com@evil.example/")


def test_ip_host_flagged():
    assert "lexical.ip_host" in ids("http://93.184.216.34/admin")


def test_legit_domains_clean():
    for url in ["https://www.google.com/", "https://github.com/x", "https://en.wikipedia.org/"]:
        fs = lexical_run(ScanContext(url)).findings
        assert not [f for f in fs if f.weight >= 0.3], url


def test_shortener_and_suspicious_tld():
    assert "lexical.shortener" in ids("https://bit.ly/abc")
    assert "lexical.tld" in ids("https://whatever.tk/")
