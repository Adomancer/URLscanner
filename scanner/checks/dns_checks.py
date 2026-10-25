"""DNS records, e-mail authentication (SPF/DMARC), CAA, DNSSEC and fast-flux heuristics."""
import ipaddress

import dns.exception
import dns.resolver
import dns.reversename

from ..models import Section
from . import check

_TYPES_HOST = ("A", "AAAA", "CNAME")
_TYPES_DOMAIN = ("NS", "MX", "TXT", "CAA", "SOA")


def _resolver():
    r = dns.resolver.Resolver()
    r.lifetime = 4.0
    r.timeout = 2.0
    return r


def query(name, rtype, resolver=None):
    """Return (records, ttl). Empty list for NXDOMAIN / no answer / timeout."""
    r = resolver or _resolver()
    try:
        ans = r.resolve(name, rtype, raise_on_no_answer=False)
    except (dns.exception.DNSException, ValueError):
        return [], None
    if ans.rrset is None:
        return [], None
    recs = []
    for rd in ans:
        if rtype == "TXT":
            recs.append(b"".join(rd.strings).decode("utf-8", "replace"))
        else:
            recs.append(rd.to_text().rstrip("."))
    return recs, ans.rrset.ttl


def nxdomain(name):
    try:
        _resolver().resolve(name, "A")
        return False
    except dns.resolver.NXDOMAIN:
        return True
    except Exception:
        return False


@check("dns", "DNS & e-mail security", passive=True)
def run(ctx):
    s = Section()
    r = _resolver()
    host, domain = ctx.host, ctx.registered_domain
    if ctx.options.get("passive"):
        # a per-recipient subdomain (abc123.track.example) would tell its nameserver the mail was read
        host = domain
    try:
        ipaddress.ip_address(host.strip("[]"))
        s.data["applicable"] = False
        return s
    except ValueError:
        pass

    records, ttls = {}, {}
    for t in _TYPES_HOST:
        records[t], ttls[t] = query(host, t, r)
    for t in _TYPES_DOMAIN:
        records[t], ttls[t] = query(domain, t, r)
    dmarc = [x for x in query(f"_dmarc.{domain}", "TXT", r)[0] if x.lower().startswith("v=dmarc1")]
    spf = [x for x in records["TXT"] if x.lower().startswith("v=spf1")]

    dnssec = False
    try:
        ds, _ = query(domain, "DS", r)
        dnssec = bool(ds)
    except Exception:
        pass

    ptr = ""
    if ctx.ips:
        try:
            ptr = query(dns.reversename.from_address(ctx.ips[0]).to_text(), "PTR", r)[0][:1]
            ptr = ptr[0] if ptr else ""
        except Exception:
            ptr = ""

    s.data.update({"records": records, "ttl": ttls, "spf": spf, "dmarc": dmarc, "dnssec": dnssec, "ptr": ptr,
                   "registered_domain": domain})

    # e-mail authentication of the registered domain
    if records["MX"] or spf:
        if not spf:
            s.flag("dns.no_spf", "No SPF record (domain can be spoofed in e-mail)", "low", penalty=3,
                   fix="Publish a TXT record like 'v=spf1 include:<provider> -all'.")
        elif len(spf) > 1:
            s.flag("dns.multi_spf", "Multiple SPF records (invalid, ignored by receivers)", "low", penalty=3)
        elif "+all" in spf[0].lower():
            s.flag("dns.spf_pass_all", "SPF allows any server to send mail (+all)", "high", penalty=10, evidence=spf[0])
        elif "?all" in spf[0].lower():
            s.flag("dns.spf_neutral", "SPF ends in neutral '?all'", "low", penalty=2, evidence=spf[0])
        if not dmarc:
            s.flag("dns.no_dmarc", "No DMARC policy", "low", penalty=3,
                   fix="Publish _dmarc TXT 'v=DMARC1; p=quarantine; rua=mailto:...'.")
        elif "p=none" in dmarc[0].replace(" ", "").lower():
            s.flag("dns.dmarc_none", "DMARC policy is 'none' (monitor only)", "info", penalty=1, evidence=dmarc[0])
    if records["SOA"] and not records["CAA"]:
        s.flag("dns.no_caa", "No CAA record (any CA may issue certificates)", "info", penalty=1)

    # fast-flux heuristic: many A records, low TTL, spread across networks
    a = records["A"]
    if len(a) >= 5 and (ttls["A"] or 9999) < 300:
        nets = {".".join(ip.split(".")[:2]) for ip in a}
        if len(nets) >= 3:
            s.flag("dns.fast_flux", "Fast-flux DNS pattern (many short-lived IPs across networks)", "high", weight=0.3,
                   evidence=f"{len(a)} A records, TTL {ttls['A']}s, {len(nets)} /16 networks")
    # empty answers can also mean a resolver timeout, so only a definitive NXDOMAIN counts
    if not records["NS"] and not records["SOA"] and not a and nxdomain(domain):
        s.flag("dns.no_zone", "Domain has no DNS zone (unregistered or suspended)", "medium", weight=0.2,
               evidence=domain)
    return s
