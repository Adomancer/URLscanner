import base64
import hashlib
import math
import re
from collections import Counter
from functools import lru_cache
from urllib.parse import urlsplit

import tldextract

# Offline public-suffix parsing: the bundled PSL snapshot, never fetched over the network.
# Private suffixes are on so that e.g. "evil.github.io" is treated as its own site.
_EXTRACT = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None, include_psl_private_domains=True)


@lru_cache(maxsize=4096)
def split_host(host):
    """Return (subdomain, domain_label, suffix, registered_domain) for a hostname."""
    host = (host or "").lower().strip(".")
    ext = _EXTRACT(host)
    if not ext.suffix:  # IP literal, localhost, unknown TLD
        return "", host, "", host
    registered = f"{ext.domain}.{ext.suffix}" if ext.domain else host
    return ext.subdomain, ext.domain, ext.suffix, registered


def registered_domain(host_or_url):
    host = host_or_url
    if "://" in (host_or_url or ""):
        host = urlsplit(host_or_url).hostname or ""
    return split_host(host)[3]


def to_unicode_host(host):
    try:
        return host.encode("ascii").decode("idna")
    except (UnicodeError, ValueError):
        return host


def to_ascii_host(host):
    try:
        return host.encode("idna").decode("ascii")
    except (UnicodeError, ValueError):
        return host


def shannon_entropy(s):
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def murmur3_32(data, seed=0):
    """MurmurHash3 x86_32, signed result (identical to mmh3.hash)."""
    c1, c2 = 0xCC9E2D51, 0x1B873593
    h = seed & 0xFFFFFFFF
    n = len(data)
    rounded = n - (n % 4)
    for i in range(0, rounded, 4):
        k = int.from_bytes(data[i:i + 4], "little")
        k = (k * c1) & 0xFFFFFFFF
        k = ((k << 15) | (k >> 17)) & 0xFFFFFFFF
        k = (k * c2) & 0xFFFFFFFF
        h ^= k
        h = ((h << 13) | (h >> 19)) & 0xFFFFFFFF
        h = (h * 5 + 0xE6546B64) & 0xFFFFFFFF
    tail = data[rounded:]
    k = 0
    if len(tail) >= 3:
        k ^= tail[2] << 16
    if len(tail) >= 2:
        k ^= tail[1] << 8
    if tail:
        k ^= tail[0]
        k = (k * c1) & 0xFFFFFFFF
        k = ((k << 15) | (k >> 17)) & 0xFFFFFFFF
        k = (k * c2) & 0xFFFFFFFF
        h ^= k
    h ^= n
    h ^= h >> 16
    h = (h * 0x85EBCA6B) & 0xFFFFFFFF
    h ^= h >> 13
    h = (h * 0xC2B2AE35) & 0xFFFFFFFF
    h ^= h >> 16
    return h - 0x100000000 if h & 0x80000000 else h


def favicon_hash(data):
    """Shodan-compatible favicon hash: mmh3 over base64 with 76-char line breaks."""
    return murmur3_32(base64.encodebytes(data))


def version_tuple(v):
    return tuple(int(x) for x in re.findall(r"\d+", str(v))[:4])


def defang(url):
    if not url:
        return url
    out = re.sub(r"^http", "hxxp", url, flags=re.I)
    parts = urlsplit(out)
    if parts.netloc:
        out = out.replace(parts.netloc, parts.netloc.replace(".", "[.]"), 1)
    return out


def sha256_hex(data):
    return hashlib.sha256(data).hexdigest()


# --- crypto wallet address validation (to avoid regex false positives) -------------------

_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def base58check_ok(s, versions=None):
    try:
        n = 0
        for c in s:
            n = n * 58 + _B58.index(c)
    except ValueError:
        return False
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    raw = b"\x00" * (len(s) - len(s.lstrip("1"))) + raw
    if len(raw) != 25:
        return False
    if versions is not None and raw[0] not in versions:
        return False
    return hashlib.sha256(hashlib.sha256(raw[:-4]).digest()).digest()[:4] == raw[-4:]


_BECH32 = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def bech32_ok(addr):
    addr = addr.lower()
    if "1" not in addr:
        return False
    hrp, data = addr.rsplit("1", 1)
    if hrp != "bc" or len(data) < 6 or any(c not in _BECH32 for c in data):
        return False
    values = [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp] + [_BECH32.find(c) for c in data]
    gen = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)
    chk = 1
    for v in values:
        top = chk >> 25
        chk = ((chk & 0x1FFFFFF) << 5) ^ v
        for i in range(5):
            if (top >> i) & 1:
                chk ^= gen[i]
    return chk in (1, 0x2BC830A3)  # bech32 / bech32m
