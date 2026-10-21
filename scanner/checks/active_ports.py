"""ACTIVE (opt-in, authorised targets only): TCP connect scan of common ports + passive banner read."""
import socket
from concurrent.futures import ThreadPoolExecutor

from .. import data, net
from ..models import Section
from . import check

_BANNER_PORTS = {21, 22, 25, 110, 143, 3306, 5900}


def _probe(ip, port, timeout=1.2):
    try:
        sock = socket.create_connection((ip, port), timeout=timeout)
    except OSError:
        return None
    banner = ""
    try:
        if not net._peer_allowed(sock.getpeername()[0]):
            return None
        if port in _BANNER_PORTS:
            sock.settimeout(1.5)
            try:
                banner = sock.recv(256).decode("latin-1", "replace").strip()
            except OSError:
                pass
    finally:
        sock.close()
    return {"port": port, "banner": "".join(c for c in banner if c.isprintable())[:160]}


@check("ports", "Open ports", stage=2, requires="resolved", active=True)
def run(ctx):
    s = Section()
    ip = next((i for i in ctx.ips if ":" not in i), ctx.ips[0])
    lists = data.lists()
    ports = lists["scan_ports"]
    with ThreadPoolExecutor(max_workers=32) as pool:
        results = [r for r in pool.map(lambda p: _probe(ip, p), ports) if r]
    risky = lists["risky_ports"]
    for r in results:
        meta = risky.get(str(r["port"]))
        r["service"] = meta[0] if meta else {22: "SSH", 53: "DNS", 80: "HTTP", 443: "HTTPS", 8080: "HTTP-alt",
                                             8443: "HTTPS-alt", 993: "IMAPS", 995: "POP3S", 143: "IMAP",
                                             110: "POP3", 3000: "dev server", 5000: "dev server",
                                             8000: "HTTP-alt", 8888: "HTTP-alt"}.get(r["port"], "")
        if meta and meta[2]:
            s.flag(f"ports.{r['port']}", f"{meta[0]} (port {r['port']}) is reachable from the internet", meta[1],
                   penalty=meta[2], evidence=r["banner"] or f"{ip}:{r['port']} open", fix=meta[3])
    s.data.update({"ip": ip, "scanned": ports, "open": sorted(results, key=lambda r: r["port"])})
    return s
