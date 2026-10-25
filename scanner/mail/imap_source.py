"""Read-only access to a Gmail mailbox over IMAP (stdlib imaplib, Google App Password).

Guarantees:
  * messages are fetched with BODY.PEEK[] from a mailbox selected read-only (EXAMINE), so nothing is
    ever marked as read, moved or deleted;
  * labelling (the only write) uses a separate connection and only adds/removes URLscanner/* labels;
  * the password never appears in an exception, log line or stored record.

Gmail-specific IMAP extensions used: X-GM-MSGID (stable message id across folders), X-GM-RAW (Gmail
search syntax), X-GM-LABELS. Folders are found by their SPECIAL-USE flag (\\Junk, \\All), since their
names depend on the account's language.
"""
import datetime as dt
import imaplib
import re
import socket
import ssl
from dataclasses import dataclass

import config

LABEL_PREFIX = "URLscanner/"
_LIST_LINE = re.compile(rb'^\((?P<flags>[^)]*)\)\s+(?P<delim>"[^"]*"|NIL)\s+(?P<name>.+)$')
_ADDRESS = re.compile(r"^[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9.\-]{1,253}$")
_MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")


class ImapError(Exception):
    """A mailbox problem, with any credential scrubbed from the message."""


@dataclass
class MailMeta:
    uid: int
    msgid: str
    size: int
    received_at: float = None
    raw: bytes = None
    skipped: str = ""


def _quote(s):
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _imap_date(when):
    return f"{when.day:02d}-{_MONTHS[when.month - 1]}-{when.year}"


def _parse_fetch(resp):
    """Map imaplib FETCH response chunks to {uid: {field: value, 'body': bytes}}."""
    out = {}
    items = list(resp or [])
    for i, item in enumerate(items):
        head, body = (item[0], item[1]) if isinstance(item, tuple) else (item, None)
        if not isinstance(head, bytes):
            continue
        m = re.search(rb"UID (\d+)", head)
        if not m and body is not None and i + 1 < len(items) and isinstance(items[i + 1], bytes):
            # some servers send the UID after the message literal: (BODY[] {n} ... UID 5)
            m = re.search(rb"UID (\d+)", items[i + 1])
            head = head + b" " + items[i + 1]
        if not m:
            continue
        rec = out.setdefault(int(m.group(1)), {})
        for key, rx in (("msgid", rb"X-GM-MSGID (\d+)"), ("size", rb"RFC822\.SIZE (\d+)")):
            mm = re.search(rx, head)
            if mm:
                rec[key] = mm.group(1).decode()
        mm = re.search(rb'INTERNALDATE "([^"]+)"', head)
        if mm:
            t = imaplib.Internaldate2tuple(b'INTERNALDATE "' + mm.group(1) + b'"')
            if t:
                rec["received_at"] = dt.datetime(*t[:6]).timestamp()
        mm = re.search(rb"X-GM-LABELS \((.*?)\)(?: |$|\))", head)
        if mm:
            rec["labels"] = [a.decode("utf-8", "replace").strip('"').replace('\\"', '"')
                             for a in re.findall(rb'"(?:[^"\\]|\\.)*"|[^\s"]+', mm.group(1))]
        if body is not None and b"BODY[" in head:
            rec["body"] = body
    return out


class ImapSource:
    """One Gmail account. Use as a context manager; every method may raise ImapError."""

    def __init__(self, address=None, password=None, host=None, factory=None, timeout=30):
        self.address = (address if address is not None else config.GMAIL_ADDRESS).strip()
        self._password = password if password is not None else config.GMAIL_APP_PASSWORD
        self.host = host or config.GMAIL_IMAP_HOST
        self._factory = factory or imaplib.IMAP4_SSL
        self.timeout = timeout
        self._conns = {}
        self._folders = None
        self._seen_cache = {}
        if not self.address or not self._password:
            raise ImapError("GMAIL_ADDRESS and GMAIL_APP_PASSWORD must be set (in .env)")

    # ---- connection handling ------------------------------------------------------------
    def _scrub(self, text):
        text = str(text)
        for secret in {self._password, self._password.replace(" ", "")}:
            if secret:
                text = text.replace(secret, "***")
        return text

    def _conn(self, role="read"):
        """Separate connections per role: 'read' (EXAMINE only), 'aux' (sender look-ups in All Mail),
        'write' (labels) -- so selecting one mailbox never disturbs an iteration over another."""
        if role not in self._conns:
            try:
                c = self._factory(self.host, 993, ssl_context=ssl.create_default_context(), timeout=self.timeout)
                c.login(self.address, self._password)
            except (imaplib.IMAP4.error, OSError, socket.timeout, ssl.SSLError) as e:
                raise ImapError(f"IMAP login to {self.host} failed: {self._scrub(e)}") from None
            self._conns[role] = c
        return self._conns[role]

    def close(self):
        for c in self._conns.values():
            try:
                c.logout()
            except Exception:
                pass
        self._conns.clear()

    def __enter__(self):
        self._conn("read")
        return self

    def __exit__(self, *exc):
        self.close()

    def _call(self, role, fn, *args):
        try:
            typ, data = getattr(self._conn(role), fn)(*args)
        except (imaplib.IMAP4.error, OSError, socket.timeout, ssl.SSLError) as e:
            self._conns.pop(role, None)  # the connection is unusable; reconnect next time
            raise ImapError(f"IMAP {fn} failed: {self._scrub(e)}") from None
        if typ != "OK":
            raise ImapError(f"IMAP {fn} refused: {self._scrub(data)[:200]}")
        return data

    # ---- folders ------------------------------------------------------------------------
    def folders(self):
        """{'inbox': 'INBOX', 'spam': ..., 'all': ..., ...} from the SPECIAL-USE flags in LIST."""
        if self._folders is None:
            found = {"inbox": "INBOX"}
            for line in self._call("read", "list"):
                m = _LIST_LINE.match(line or b"")
                if not m:
                    continue
                flags = m.group("flags").decode("ascii", "replace").lower().split()
                name = m.group("name").decode("utf-8", "replace").strip()
                if name.startswith('"') and name.endswith('"'):
                    name = name[1:-1].replace('\\"', '"').replace("\\\\", "\\")
                for flag, key in (("\\junk", "spam"), ("\\all", "all"), ("\\sent", "sent"), ("\\trash", "trash")):
                    if flag in flags:
                        found[key] = name
            self._folders = found
        return self._folders

    def resolve_folder(self, name):
        key = (name or "inbox").lower()
        if key in ("inbox", "spam", "junk", "all", "sent", "trash"):
            folder = self.folders().get("spam" if key == "junk" else key)
            if not folder:
                raise ImapError(f"this account exposes no '{key}' folder over IMAP (check Gmail's IMAP settings)")
            return folder
        return name

    def _select(self, folder, role="read", readonly=True):
        self._call(role, "select", _quote(folder), readonly)
        validity = self._conn(role).response("UIDVALIDITY")[1]
        try:
            return int(validity[0]) if validity and validity[0] else None
        except (TypeError, ValueError):
            return None

    # ---- reading ------------------------------------------------------------------------
    def search(self, folder, since_days=None, unread_only=False, min_uid=None):
        """(uidvalidity, ascending UIDs) of matching messages; the mailbox is opened read-only."""
        validity = self._select(folder)
        criteria = []
        if since_days:
            criteria += ["SINCE", _imap_date(dt.date.today() - dt.timedelta(days=int(since_days)))]
        if unread_only:
            criteria.append("UNSEEN")
        if min_uid:
            criteria += ["UID", f"{int(min_uid)}:*"]
        data = self._call("read", "uid", "SEARCH", *(criteria or ["ALL"]))
        uids = sorted({int(x) for x in (data[0] or b"").split()})
        if min_uid:
            uids = [u for u in uids if u >= int(min_uid)]  # "N:*" always matches the newest message
        return validity, uids

    def fetch_meta(self, uids):
        out = {}
        for i in range(0, len(uids), 200):
            chunk = ",".join(str(u) for u in uids[i:i + 200])
            out.update(_parse_fetch(self._call("read", "uid", "FETCH", chunk,
                                               "(X-GM-MSGID RFC822.SIZE INTERNALDATE)")))
        return out

    def fetch_raw(self, uid):
        resp = self._call("read", "uid", "FETCH", str(uid), "(BODY.PEEK[])")
        rec = _parse_fetch(resp).get(int(uid))
        if rec is None:  # a single-message fetch whose response did not echo the UID
            bodies = [x[1] for x in resp or [] if isinstance(x, tuple) and b"BODY[" in (x[0] or b"")]
            return bodies[0] if len(bodies) == 1 else None
        return rec.get("body")

    def iter_messages(self, folder, uids, *, max_message_bytes, max_run_bytes, skip=None):
        """Yield MailMeta for each UID (in the order given) with .raw filled in, or .skipped set.
        skip(msgid) -> True leaves a message out (e.g. already scanned)."""
        meta = self.fetch_meta(uids)
        total = 0
        for uid in uids:
            m = meta.get(uid)
            if not m or "msgid" not in m:
                continue
            item = MailMeta(uid=uid, msgid=m["msgid"], size=int(m.get("size") or 0),
                            received_at=m.get("received_at"))
            if skip and skip(item.msgid):
                item.skipped = "already scanned"
            elif item.size > max_message_bytes:
                item.skipped = f"too large ({item.size // (1024 * 1024)} MB)"
            elif total + item.size > max_run_bytes:
                item.skipped = "download limit for this run reached"
            else:
                total += item.size
                item.raw = self.fetch_raw(uid)
                if item.raw is None:
                    item.skipped = "message disappeared"
            yield item

    def fetch_by_msgid(self, msgid):
        """Raw bytes of one message (searched in All Mail by its Gmail id), or None."""
        if not str(msgid).isdigit():
            return None
        self._select(self.resolve_folder("all"))
        data = self._call("read", "uid", "SEARCH", "X-GM-MSGID", str(msgid))
        uids = (data[0] or b"").split()
        return self.fetch_raw(int(uids[0])) if uids else None

    def uid_for_msgid(self, folder, msgid):
        """(uidvalidity, uid or None) of a message in `folder`, found by its Gmail message id."""
        validity = self._select(folder)
        if not str(msgid).isdigit():
            return validity, None
        uids = (self._call("read", "uid", "SEARCH", "X-GM-MSGID", str(msgid))[0] or b"").split()
        return validity, (int(uids[0]) if uids else None)

    def sender_seen_before(self, address, before=None):
        """Has this address sent mail before `before` (a date)? True / False, or None when unknown
        (All Mail hidden from IMAP, odd address, or any error) -- unknown must never count as "new"."""
        address = (address or "").strip().lower()
        if not _ADDRESS.match(address):
            return None
        key = (address, before)
        if key not in self._seen_cache:
            try:
                self._select(self.resolve_folder("all"), role="aux")
                criteria = ["X-GM-RAW", _quote(f"from:{address}")]
                if before:
                    criteria += ["BEFORE", _imap_date(before)]
                data = self._call("aux", "uid", "SEARCH", *criteria)
                self._seen_cache[key] = bool((data[0] or b"").split())
            except ImapError:
                self._seen_cache[key] = None
        return self._seen_cache[key]

    # ---- labelling (the only write) ------------------------------------------------------
    def reconcile_labels(self, folder, uid, uidvalidity, wanted):
        """Make URLscanner/* labels on one message exactly `wanted` ('' = none). Uses its own read-write
        connection (an EXAMINEd mailbox rejects STORE); never touches \\Seen or any other label."""
        if wanted and not wanted.startswith(LABEL_PREFIX):
            raise ValueError("only URLscanner/* labels may be written")
        validity = self._select(folder, role="write", readonly=False)
        if uidvalidity is not None and validity != uidvalidity:
            raise ImapError("mailbox changed since it was scanned (UIDVALIDITY differs); re-scan first")
        rec = _parse_fetch(self._call("write", "uid", "FETCH", str(uid), "(X-GM-LABELS)")).get(int(uid))
        if rec is None:
            raise ImapError("message no longer in this folder")
        current = {l for l in rec.get("labels", []) if l.startswith(LABEL_PREFIX)}
        stale = sorted(current - {wanted})
        if stale:
            self._call("write", "uid", "STORE", str(uid), "-X-GM-LABELS",
                       "(" + " ".join(_quote(l) for l in stale) + ")")
        if wanted and wanted not in current:
            try:
                self._call("write", "create", _quote(wanted))
            except ImapError:
                pass  # already exists
            self._call("write", "uid", "STORE", str(uid), "+X-GM-LABELS", f"({_quote(wanted)})")
        return {"added": wanted if wanted and wanted not in current else "", "removed": stale}
