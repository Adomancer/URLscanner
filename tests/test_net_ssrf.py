import pytest

from scanner import net
from scanner.core import InvalidURL, normalize_url


@pytest.mark.parametrize("ip,public", [
    ("8.8.8.8", True), ("1.1.1.1", True), ("93.184.216.34", True),
    ("127.0.0.1", False), ("10.0.0.1", False), ("172.16.5.4", False), ("172.31.255.255", False),
    ("192.168.1.1", False), ("169.254.169.254", False), ("100.64.0.1", False), ("0.0.0.0", False),
    ("::1", False), ("fc00::1", False), ("fe80::1", False), ("::ffff:127.0.0.1", False),
    ("224.0.0.1", False), ("2606:4700:4700::1111", True),
])
def test_is_public_ip(ip, public):
    assert net.is_public_ip(ip) is public


@pytest.mark.parametrize("host", ["127.0.0.1", "10.0.0.5", "0.0.0.0", "169.254.169.254", "[::1]"])
def test_resolve_public_blocks_private_literals(host):
    with pytest.raises(net.BlockedTarget):
        net.resolve_public(host.strip("[]"), 80)


@pytest.mark.parametrize("raw", [
    "not a url", "ftp://example.com", "javascript:alert(1)", "http://localhost",
    "http:// example.com", "", "http://2130706433/",
])
def test_normalize_rejects_bad(raw):
    with pytest.raises(InvalidURL):
        normalize_url(raw)


@pytest.mark.parametrize("raw,expect_host", [
    ("example.com", "example.com"),
    ("example.com/path?x=1", "example.com"),
    ("hxxps://bad[.]example[.]com/login", "bad.example.com"),
    ("HTTP://Example.COM/", "example.com"),
])
def test_normalize_ok(raw, expect_host):
    from urllib.parse import urlsplit
    out = normalize_url(raw)
    assert urlsplit(out).hostname == expect_host
    assert out.startswith(("http://", "https://"))


def test_normalize_idn_punycode():
    out = normalize_url("https://münchen.de/")
    from urllib.parse import urlsplit
    assert urlsplit(out).hostname == "xn--mnchen-3ya.de"
