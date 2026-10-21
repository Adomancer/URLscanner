"""TLS certificate and protocol analysis using only the standard library + cryptography."""
import datetime as dt
import socket
import ssl
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlsplit

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
from cryptography.x509.oid import ExtensionOID, NameOID

from .. import net
from ..models import Section
from . import check

_POLICY_TYPES = {"2.23.140.1.2.1": "DV", "2.23.140.1.2.2": "OV", "2.23.140.1.2.3": "IV", "2.23.140.1.1": "EV"}
_FREE_CAS = ("Let's Encrypt", "ZeroSSL", "Buypass", "Google Trust Services", "SSL.com")
_LEGACY = "DEFAULT:@SECLEVEL=0"  # lets this client offer TLS 1.0/1.1 and old ciphers for testing
_PROTOCOLS = [("TLSv1", ssl.TLSVersion.TLSv1), ("TLSv1.1", ssl.TLSVersion.TLSv1_1),
              ("TLSv1.2", ssl.TLSVersion.TLSv1_2), ("TLSv1.3", ssl.TLSVersion.TLSv1_3)]
_WEAK_CIPHERS = {"RC4": "RC4", "3DES": "3DES", "NULL": "eNULL", "EXPORT": "EXP", "anonymous": "aNULL"}
# Failures raised by this machine's OpenSSL before the server had any say.
_LOCAL_REASONS = {"NO_PROTOCOLS_AVAILABLE", "NO_CIPHERS_AVAILABLE", "NO_CIPHER_MATCH"}


def _name(n, oid):
    try:
        attrs = n.get_attributes_for_oid(oid)
        return attrs[0].value if attrs else ""
    except Exception:
        return ""


def _context(verify, min_v=None, max_v=None, ciphers=None):
    if verify:
        c = ssl.create_default_context()
    else:
        c = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        c.check_hostname = False
        c.verify_mode = ssl.CERT_NONE
    if min_v:
        c.minimum_version = min_v
    if max_v:
        c.maximum_version = max_v
    if ciphers:
        c.set_ciphers(ciphers)
    return c


def _handshake(host, port, ip, verify, min_v=None, max_v=None, ciphers=None, timeout=6):
    c = _context(verify, min_v, max_v, ciphers)
    sock, _ = net.connect_public(host, port, timeout=timeout, ips=[ip])
    try:
        with c.wrap_socket(sock, server_hostname=host) as ss:
            return ss.getpeercert(binary_form=True), ss.version(), ss.cipher()
    finally:
        sock.close()


def _accepts(host, port, ip, min_v=None, max_v=None, ciphers=None):
    """True if the server completes a handshake with these settings, False if it refuses them,
    None if it cannot be tested (this machine's OpenSSL lacks the protocol/cipher, or a timeout)."""
    try:
        _context(False, min_v, max_v, ciphers)
    except (ssl.SSLError, ValueError):
        return None
    try:
        _handshake(host, port, ip, verify=False, min_v=min_v, max_v=max_v, ciphers=ciphers, timeout=4)
        return True
    except ssl.SSLError as e:
        return None if getattr(e, "reason", "") in _LOCAL_REASONS else False
    except socket.timeout:
        return None
    except OSError:  # connection reset / closed: the server hung up on the offer
        return False


def probe_protocols(host, port, ip):
    """Which TLS versions and known-weak cipher families the server accepts (one handshake each)."""
    jobs = {name: dict(min_v=v, max_v=v, ciphers=_LEGACY if v < ssl.TLSVersion.TLSv1_2 else None)
            for name, v in _PROTOCOLS}
    jobs.update({f"cipher:{label}": dict(max_v=ssl.TLSVersion.TLSv1_2, ciphers=f"{spec}:@SECLEVEL=0")
                 for label, spec in _WEAK_CIPHERS.items()})
    with ThreadPoolExecutor(max_workers=len(jobs)) as pool:
        futures = {k: pool.submit(_accepts, host, port, ip, **kw) for k, kw in jobs.items()}
        res = {k: f.result() for k, f in futures.items()}
    protocols = {name: res[name] for name, _ in _PROTOCOLS}
    weak = {label: res[f"cipher:{label}"] for label in _WEAK_CIPHERS}
    return protocols, weak


@check("tls", "TLS certificate", stage=2, requires="resolved")
def run(ctx):
    s = Section()
    target = ctx.url
    if ctx.scheme != "https":
        if ctx.fetch and urlsplit(ctx.fetch.final_url).scheme == "https":
            target = ctx.fetch.final_url
        else:
            s.data["applicable"] = False
            return s
    parts = urlsplit(target)
    host = parts.hostname
    port = parts.port or 443
    try:
        ip = ctx.ips[0] if host == ctx.host and ctx.ips else net.resolve_public(host, port)[0]
        try:
            der, version, cipher = _handshake(host, port, ip, verify=False)
        except ssl.SSLError:  # maybe a legacy-only server: retry offering TLS 1.0+ and old ciphers
            der, version, cipher = _handshake(host, port, ip, verify=False, min_v=ssl.TLSVersion.TLSv1,
                                              ciphers=_LEGACY)
    except Exception as e:
        s.data["error"] = str(e)[:200]
        s.flag("tls.handshake_failed", "TLS handshake failed", "medium", weight=0.05, penalty=20, evidence=str(e)[:200])
        return s

    cert = x509.load_der_x509_certificate(der)
    now = dt.datetime.now(dt.timezone.utc)
    nb, na = cert.not_valid_before_utc, cert.not_valid_after_utc
    try:
        sans = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        sans = []
    try:
        cert.extensions.get_extension_for_oid(ExtensionOID.PRECERT_SIGNED_CERTIFICATE_TIMESTAMPS)
        has_sct = True
    except x509.ExtensionNotFound:
        has_sct = False
    vtype = ""
    try:
        for p in cert.extensions.get_extension_for_oid(ExtensionOID.CERTIFICATE_POLICIES).value:
            vtype = _POLICY_TYPES.get(p.policy_identifier.dotted_string, vtype)
    except x509.ExtensionNotFound:
        pass

    key = cert.public_key()
    if isinstance(key, rsa.RSAPublicKey):
        key_desc, key_bits = f"RSA {key.key_size}", key.key_size
    elif isinstance(key, ec.EllipticCurvePublicKey):
        key_desc, key_bits = f"ECDSA {key.curve.name}", key.curve.key_size
    elif isinstance(key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
        key_desc, key_bits = type(key).__name__.replace("PublicKey", ""), 256
    elif isinstance(key, dsa.DSAPublicKey):
        key_desc, key_bits = f"DSA {key.key_size}", key.key_size
    else:
        key_desc, key_bits = type(key).__name__, 0
    sig = cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else "n/a"
    issuer_o = _name(cert.issuer, NameOID.ORGANIZATION_NAME)
    issuer_cn = _name(cert.issuer, NameOID.COMMON_NAME)
    age_days = (now - nb).days
    days_left = (na - now).days

    s.data.update({
        "applicable": True,
        "host": host,
        "subject": _name(cert.subject, NameOID.COMMON_NAME),
        "issuer": issuer_cn,
        "issuer_org": issuer_o,
        "not_before": nb.isoformat(),
        "not_after": na.isoformat(),
        "age_days": age_days,
        "days_left": days_left,
        "lifetime_days": (na - nb).days,
        "sans": sans[:50],
        "san_count": len(sans),
        "serial": format(cert.serial_number, "x"),
        "sha256": cert.fingerprint(hashes.SHA256()).hex(),
        "key": key_desc,
        "signature": sig,
        "validation": vtype or "unknown",
        "sct": has_sct,
        "protocol": version,
        "cipher": cipher[0] if cipher else "",
        "free_ca": any(c.lower() in f"{issuer_o} {issuer_cn}".lower() for c in _FREE_CAS),
    })

    # Trust validation with the OS trust store
    try:
        _handshake(host, port, ip, verify=True)
        s.data["trusted"] = True
    except ssl.SSLCertVerificationError as e:
        reason = getattr(e, "verify_message", "") or str(e)
        s.data["trusted"] = False
        s.data["verify_error"] = reason
        low = reason.lower()
        if "expired" in low:
            s.flag("tls.expired", "Certificate has expired", "high", weight=0.2, penalty=30,
                   evidence=f"expired {na:%Y-%m-%d}", fix="Renew the certificate (automate it with ACME).")
        elif "self-signed" in low or "self signed" in low:
            s.flag("tls.self_signed", "Self-signed certificate", "high", weight=0.25, penalty=30, evidence=reason)
        elif "hostname" in low or "ip address mismatch" in low:
            s.flag("tls.hostname_mismatch", "Certificate does not match the hostname", "high", weight=0.25, penalty=30,
                   evidence=f"{host} not in {', '.join(sans[:5]) or s.data['subject']}")
        else:
            s.flag("tls.untrusted", "Certificate is not trusted", "high", weight=0.2, penalty=25, evidence=reason)
    except Exception as e:
        s.data["trusted"] = None
        s.data["verify_error"] = str(e)[:200]

    if 0 <= days_left < 14:
        s.flag("tls.expiring", f"Certificate expires in {days_left} days", "low", penalty=5)
    if 0 <= age_days < 7 and not ctx.trusted:
        s.flag("tls.fresh", f"Certificate issued only {age_days} day(s) ago", "low", weight=0.08,
               evidence=f"{issuer_cn} on {nb:%Y-%m-%d}",
               fix="Brand-new certificates on unknown domains are typical of freshly launched phishing sites.")
    if key_bits and key_desc.startswith("RSA") and key_bits < 2048:
        s.flag("tls.weak_key", f"Weak RSA key ({key_bits} bits)", "high", penalty=15)
    if sig in ("sha1", "md5"):
        s.flag("tls.weak_signature", f"Certificate signed with {sig.upper()}", "high", penalty=15)
    if not has_sct and s.data.get("trusted"):
        s.flag("tls.no_sct", "No embedded Certificate Transparency proof", "info", penalty=2)

    # Protocol / cipher support (a handful of extra handshakes, like any TLS client would make)
    protocols, weak = probe_protocols(host, port, ip)
    s.data["protocols"] = protocols
    s.data["weak_ciphers"] = weak
    s.data["tls13"] = protocols["TLSv1.3"]
    if version in ("TLSv1", "TLSv1.1", "SSLv3"):  # the best the server could negotiate
        s.flag("tls.old_protocol", f"Server only supports obsolete {version}", "high", penalty=20,
               fix="Enable TLS 1.2 and 1.3; disable TLS 1.0/1.1 and SSLv3.")
    for name, label, fid, pen in (("TLSv1", "TLS 1.0", "tls.supports_tls10", 6),
                                  ("TLSv1.1", "TLS 1.1", "tls.supports_tls11", 4)):
        if protocols[name]:
            s.flag(fid, f"Server still accepts {label}", "medium", penalty=pen,
                   evidence=f"{host}:{port} completed a {name} handshake",
                   fix="Disable TLS 1.0 and 1.1 (deprecated by RFC 8996); allow only TLS 1.2+.")
    accepted = [label for label, ok in weak.items() if ok]
    if accepted:
        s.flag("tls.weak_cipher", f"Server accepts weak cipher suites ({', '.join(accepted)})", "high", penalty=15,
               evidence=", ".join(accepted), fix="Allow only AEAD suites (AES-GCM, ChaCha20-Poly1305).")
    if protocols["TLSv1.3"] is False:
        s.flag("tls.no_tls13", "TLS 1.3 is not supported", "info", penalty=2,
               fix="Enable TLS 1.3 for faster, safer handshakes.")
    return s
