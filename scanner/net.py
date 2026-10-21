"""SSRF-safe networking.

Every outbound connection made on behalf of a scan goes through this module:
  * all resolved addresses must be globally routable (no loopback, RFC1918, link-local,
    CGNAT, cloud metadata, multicast, IPv6 ULA, IPv4-mapped tricks, ...)
  * redirects are followed manually and every hop is re-validated
  * after the TCP connect, the *actual* peer address is checked again, which defeats
    DNS rebinding between validation and connection
  * response bodies are streamed with a hard size cap
"""
import ipaddress
import socket
import time
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlsplit

import requests
import urllib3
from requests.adapters import HTTPAdapter
from urllib3.connection import HTTPConnection, HTTPSConnection
from urllib3.connectionpool import HTTPConnectionPool, HTTPSConnectionPool

import config

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class BlockedTarget(Exception):
    """The target (or a redirect hop) points at a non-public address."""


class ResolveError(Exception):
    """The hostname does not resolve."""


def is_public_ip(ip):
    try:
        addr = ipaddress.ip_address(str(ip).split("%")[0])
    except ValueError:
        return False
    if isinstance(addr, ipaddress.IPv6Address):
        if addr.ipv4_mapped:
            addr = addr.ipv4_mapped
        elif addr.sixtofour:
            addr = addr.sixtofour
        elif addr.teredo:
            return False
    return addr.is_global and not addr.is_multicast


def _peer_allowed(ip):
    return config.ALLOW_PRIVATE_TARGETS or is_public_ip(ip)


def resolve(host, port=443):
    """Return every address the host resolves to (IP literals are returned as-is)."""
    if not host:
        raise ResolveError("missing hostname")
    host = host.strip("[]")
    try:
        ipaddress.ip_address(host)
        return [host]
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except (socket.gaierror, UnicodeError) as e:
        raise ResolveError(f"{host} does not resolve ({e})") from None
    ips = []
    for info in infos:
        ip = info[4][0]
        if ip not in ips:
            ips.append(ip)
    if not ips:
        raise ResolveError(f"{host} has no addresses")
    return ips


def resolve_public(host, port=443):
    """Resolve and require every address to be public, else raise BlockedTarget."""
    ips = resolve(host, port)
    for ip in ips:
        if not _peer_allowed(ip):
            raise BlockedTarget(f"{host} resolves to non-public address {ip} (blocked to prevent SSRF)")
    return ips


# --- connection classes that re-check the peer address after connect ---------------------

class _PeerGuard:
    def _new_conn(self):
        sock = super()._new_conn()
        try:
            peer = sock.getpeername()[0]
        except OSError:
            peer = None
        if peer is None or not _peer_allowed(peer):
            sock.close()
            raise BlockedTarget(f"connection to non-public address {peer} blocked (DNS rebinding?)")
        return sock


class _GuardedHTTPConnection(_PeerGuard, HTTPConnection):
    pass


class _GuardedHTTPSConnection(_PeerGuard, HTTPSConnection):
    pass


class _GuardedHTTPPool(HTTPConnectionPool):
    ConnectionCls = _GuardedHTTPConnection


class _GuardedHTTPSPool(HTTPSConnectionPool):
    ConnectionCls = _GuardedHTTPSConnection


class _GuardedAdapter(HTTPAdapter):
    def init_poolmanager(self, *args, **kwargs):
        super().init_poolmanager(*args, **kwargs)
        self.poolmanager.pool_classes_by_scheme = {"http": _GuardedHTTPPool, "https": _GuardedHTTPSPool}


def new_session():
    s = requests.Session()
    s.trust_env = False  # never route scans through env proxies (would hide the real peer)
    adapter = _GuardedAdapter(max_retries=0)
    s.mount("http://", adapter)
    s.mount("https://", adapter)
    return s


# --- fetching ------------------------------------------------------------------------------

@dataclass
class Hop:
    url: str
    status: int
    location: str = ""
    server: str = ""
    elapsed_ms: int = 0


@dataclass
class FetchResult:
    url: str
    final_url: str
    status: int = 0
    headers: dict = field(default_factory=dict)
    set_cookies: list = field(default_factory=list)
    body: bytes = b""
    truncated: bool = False
    chain: list = field(default_factory=list)  # list[Hop]
    elapsed_ms: int = 0
    cert_error: str = ""
    stopped_reason: str = ""

    @property
    def content_type(self):
        return self.headers.get("Content-Type", self.headers.get("content-type", "")).lower()

    @property
    def is_html(self):
        ct = self.content_type
        if "html" in ct or "xml" in ct:
            return True
        return not ct and self.body[:512].lstrip().lower().startswith((b"<!doctype html", b"<html"))

    @property
    def text(self):
        enc = "utf-8"
        ct = self.content_type
        if "charset=" in ct:
            enc = ct.split("charset=", 1)[1].split(";")[0].strip().strip("\"'") or "utf-8"
        try:
            return self.body.decode(enc, errors="replace")
        except LookupError:
            return self.body.decode("utf-8", errors="replace")


def _read_capped(resp, max_bytes):
    chunks, total = [], 0
    for chunk in resp.iter_content(chunk_size=65536):
        chunks.append(chunk)
        total += len(chunk)
        if total > max_bytes:
            return b"".join(chunks)[:max_bytes], True
    return b"".join(chunks), False


def safe_fetch(url, *, user_agent=None, headers=None, max_redirects=None, max_bytes=None,
               timeout=None, session=None, method="GET"):
    """Fetch a URL with SSRF protection on every hop. Never raises for HTTP errors.

    Raises BlockedTarget / ResolveError / requests.RequestException for network-level failures
    of the first hop; later-hop failures stop the chain and are recorded in stopped_reason.
    """
    max_redirects = config.MAX_REDIRECTS if max_redirects is None else max_redirects
    max_bytes = config.MAX_BODY_BYTES if max_bytes is None else max_bytes
    timeout = config.HTTP_TIMEOUT if timeout is None else timeout
    sess = session or new_session()
    req_headers = {"User-Agent": user_agent or config.USER_AGENT,
                   "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                   "Accept-Language": "en-US,en;q=0.9"}
    if headers:
        req_headers.update(headers)

    result = FetchResult(url=url, final_url=url)
    current = url
    verify = True
    started = time.monotonic()
    try:
        for hop_no in range(max_redirects + 1):
            parts = urlsplit(current)
            if parts.scheme not in ("http", "https"):
                result.stopped_reason = f"redirect to unsupported scheme '{parts.scheme}:'"
                break
            try:
                try:
                    port = parts.port or (443 if parts.scheme == "https" else 80)
                except ValueError:  # e.g. a redirect to https://host:99999/
                    raise ResolveError(f"invalid port in {current[:200]}") from None
                resolve_public(parts.hostname, port)
            except (BlockedTarget, ResolveError) as e:
                if hop_no == 0:
                    raise
                result.stopped_reason = str(e)
                break

            t0 = time.monotonic()
            try:
                resp = sess.request(method, current, headers=req_headers, allow_redirects=False,
                                    stream=True, timeout=timeout, verify=verify)
            except requests.exceptions.SSLError as e:
                # Keep analysing sites with broken TLS; the TLS check reports the cert problem.
                if not verify:
                    raise
                result.cert_error = str(e)[:300]
                verify = False
                resp = sess.request(method, current, headers=req_headers, allow_redirects=False,
                                    stream=True, timeout=timeout, verify=False)
            except (requests.RequestException, BlockedTarget) as e:
                if hop_no == 0:
                    raise
                result.stopped_reason = f"hop failed: {e}"
                break
            try:
                body, truncated = _read_capped(resp, max_bytes) if method != "HEAD" else (b"", False)
            finally:
                resp.close()

            location = resp.headers.get("Location", "")
            result.chain.append(Hop(url=current, status=resp.status_code, location=location,
                                    server=resp.headers.get("Server", ""),
                                    elapsed_ms=int((time.monotonic() - t0) * 1000)))
            result.final_url = current
            result.status = resp.status_code
            result.headers = dict(resp.headers)
            try:
                result.set_cookies = list(resp.raw.headers.getlist("Set-Cookie"))
            except AttributeError:
                result.set_cookies = [resp.headers["Set-Cookie"]] if "Set-Cookie" in resp.headers else []
            result.body, result.truncated = body, truncated

            if resp.is_redirect and location:
                if hop_no == max_redirects:
                    result.stopped_reason = f"stopped after {max_redirects} redirects"
                    break
                current = urljoin(current, location)
                continue
            break
    finally:
        if session is None:
            sess.close()
    result.elapsed_ms = int((time.monotonic() - started) * 1000)
    return result


def connect_public(host, port, timeout=5.0, ips=None):
    """Open a TCP socket to the first public address of host (used by TLS / port checks)."""
    last = None
    for ip in ips or resolve_public(host, port):
        try:
            sock = socket.create_connection((ip, port), timeout=timeout)
        except OSError as e:
            last = e
            continue
        if not _peer_allowed(sock.getpeername()[0]):
            sock.close()
            raise BlockedTarget(f"connection to non-public address {ip} blocked")
        return sock, ip
    raise last or OSError(f"could not connect to {host}:{port}")
