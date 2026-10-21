"""Check registry and the shared per-scan context.

A check is a function `fn(ctx) -> Section` registered with @check(...). Checks run in stages:
  stage 1 -- independent (HTTP fetch, TLS, DNS, WHOIS, lexical, blocklists)
  stage 2 -- needs stage-1 data (headers, redirects, OSINT, tech, takeover, active, sandbox)
  stage 3 -- post-processing that can use the sandbox's rendered DOM (content analysis)
"""
import threading
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from bs4 import BeautifulSoup

from .. import data
from ..utils import split_host, to_unicode_host


@dataclass
class Check:
    name: str
    title: str
    func: object
    stage: int = 1
    requires: str = ""  # "" | "resolved" | "http"
    active: bool = False
    browser: bool = False


REGISTRY = []


def check(name, title, *, stage=1, requires="", active=False, browser=False):
    def deco(fn):
        REGISTRY.append(Check(name, title, fn, stage, requires, active, browser))
        return fn
    return deco


class ScanContext:
    def __init__(self, url, options=None):
        self.url = url
        self.parts = urlsplit(url)
        self.scheme = self.parts.scheme
        self.host = (self.parts.hostname or "").lower()
        self.host_unicode = to_unicode_host(self.host)
        self.port = self.parts.port or (443 if self.scheme == "https" else 80)
        self.subdomain, self.domain_label, self.suffix, self.registered_domain = split_host(self.host)
        self.options = options or {}
        self.ips = []
        self.resolve_error = ""
        self.fetch = None          # net.FetchResult of the main request
        self.fetch_error = ""
        self.rendered_html = ""    # from the browser sandbox
        self.sections = {}         # name -> data dict (filled as checks finish)
        self._soup = None
        self._lock = threading.Lock()

    @property
    def trusted(self):
        return self.registered_domain in data.trusted_domains()

    @property
    def final_url(self):
        return self.fetch.final_url if self.fetch else self.url

    @property
    def final_registered_domain(self):
        return split_host((urlsplit(self.final_url).hostname or "").lower())[3]

    @property
    def html(self):
        if self.fetch and self.fetch.is_html:
            return self.fetch.text
        return ""

    @property
    def soup(self):
        with self._lock:
            if self._soup is None:
                self._soup = BeautifulSoup(self.html or "", "lxml")
            return self._soup


def load_all():
    """Import every check module so their @check decorators register."""
    from . import (lexical, http_check, tls, dns_checks, whois_age, blocklist, headers,  # noqa: F401
                   redirects, osint, techstack, takeover, content, active_ports, sandbox, file_check,
                   wellknown)
    return sorted(REGISTRY, key=lambda c: c.stage)
