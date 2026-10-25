"""Central redaction of private data in URLs taken from e-mail.

Links in real mail often carry personal secrets: password-reset tokens, invoice or order ids, the
recipient's own address. The scanner needs the full URL in memory while it analyses it, but nothing it
stores, exports, logs or displays may contain those parts. Everything scanner.mail persists goes
through a Redactor first.
"""
import re
from urllib.parse import parse_qsl, unquote, urlsplit, urlunsplit

MASK = "***"
_MIN_SECRET = 6       # shorter values ("en", "1", "true") are not worth hunting for in free text
_MIN_PREFIX = 4       # truncated evidence can end part-way through a secret
_SAFE_SEGMENT = re.compile(r"[A-Za-z0-9_\-=.~%+]+")


def _looks_like_token(segment):
    """A path segment that is probably an identifier rather than a word: long and mixes letters/digits."""
    seg = unquote(segment)
    if len(seg) < 16 or not _SAFE_SEGMENT.fullmatch(seg):
        return "@" in seg
    return any(c.isdigit() for c in seg) and any(c.isalpha() for c in seg)


def _is_secret_value(v):
    return len(v) >= _MIN_SECRET and (len(v) >= 16 or "@" in v or any(c.isdigit() for c in v))


def url(u):
    """The URL with every query value, fragment, userinfo and token-like path segment masked.
    Scheme, host and the shape of the path survive, which is all a report needs."""
    try:
        p = urlsplit(u)
        host = p.hostname or ""
        port = f":{p.port}" if p.port else ""
    except ValueError:
        return MASK
    netloc = (f"{MASK}@" if "@" in p.netloc else "") + (f"[{host}]" if ":" in host else host) + port
    path = "/".join(MASK if _looks_like_token(s) else s for s in p.path.split("/"))
    query = "&".join(f"{k}={MASK}" if v else k for k, v in parse_qsl(p.query, keep_blank_values=True))
    return urlunsplit((p.scheme, netloc, path, query, MASK if p.fragment else ""))


def secrets_of(u):
    """The private substrings of a URL, in raw and percent-decoded form."""
    out = set()
    try:
        p = urlsplit(u)
    except ValueError:
        return out
    for raw in re.split(r"[&;]", p.query):
        if "=" in raw:
            raw_v = raw.split("=", 1)[1]
            for v in (raw_v, unquote(raw_v), unquote(raw_v.replace("+", " "))):
                if _is_secret_value(v):
                    out.add(v)
    for seg in p.path.split("/"):
        if _looks_like_token(seg):
            out.update(x for x in (seg, unquote(seg)) if len(x) >= _MIN_SECRET)
    if len(p.fragment) >= _MIN_SECRET:
        out.add(p.fragment)
    if "@" in p.netloc:
        userinfo = p.netloc.rsplit("@", 1)[0]
        out.update(x for x in (userinfo, unquote(userinfo)) if len(x) >= 3)
    return out


class Redactor:
    """Collects every original URL of one message, then scrubs any data structure built from them."""

    def __init__(self):
        self._urls = {}
        self._secrets = set()

    def add(self, u):
        if u and u not in self._urls:
            self._urls[u] = url(u)
            self._secrets |= secrets_of(u)
        return self._urls.get(u, "")

    def text(self, s):
        if not s or not (self._urls or self._secrets):
            return s
        for orig in sorted(self._urls, key=len, reverse=True):
            if orig in s:
                s = s.replace(orig, self._urls[orig])
        for sec in sorted(self._secrets, key=len, reverse=True):
            if sec in s:
                s = s.replace(sec, MASK)
        return self._partial(s)

    def _partial(self, s):
        """Evidence strings are often truncated, which can cut a secret in half: mask a secret's
        prefix at the end of the string (before any ellipsis) and its suffix at the start."""
        for sec in self._secrets:
            tail = s.rstrip(".… ")
            head, pos = sec[:_MIN_PREFIX], max(0, len(tail) - len(sec) + 1)
            i = tail.find(head, pos)
            while i != -1:
                if sec.startswith(tail[i:]):
                    s = tail[:i] + MASK + s[len(tail):]
                    break
                i = tail.find(head, i + 1)
            end, cut = sec[-_MIN_PREFIX:], 0
            j = s.find(end, 0, len(sec) - 1)
            while j != -1 and j + _MIN_PREFIX < len(sec):
                if sec.endswith(s[:j + _MIN_PREFIX]):
                    cut = j + _MIN_PREFIX
                j = s.find(end, j + 1, len(sec) - 1)
            if cut:
                s = MASK + s[cut:]
        return s

    def value(self, obj):
        """Return a redacted deep copy of dicts / lists / strings."""
        if isinstance(obj, str):
            return self.text(obj)
        if isinstance(obj, dict):
            return {k: self.value(v) for k, v in obj.items()}
        if isinstance(obj, (list, tuple)):
            return [self.value(v) for v in obj]
        return obj
