"""Inbox-level operations shared by the CLI and the web UI: scan, label, deep-scan, watch."""
import contextlib
import datetime as dt
import logging
import os
import time

import config
from .. import storage
from . import limits, notify
from .imap_source import ImapError
from .pipeline import looks_like_token_link, persist, scan_message

log = logging.getLogger(__name__)
FLAGGED = ("Suspicious", "Dangerous")


class TokenLinkRefused(Exception):
    """Deep scan would open links that look like one-time tokens and the user did not confirm."""

    def __init__(self, links):
        super().__init__("links look like one-time tokens")
        self.links = links


def _seen_lookup(source, received_at):
    before = dt.date.fromtimestamp(received_at) if received_at else None
    return lambda addr: source.sender_seen_before(addr, before)


def apply_label(source, folder, uid, uidvalidity, msgid, result):
    """Reconcile the message's URLscanner/* label with its latest verdict; failures are recorded, not raised."""
    wanted = result.get("label", "") if not result.get("error") else ""
    try:
        source.reconcile_labels(folder, uid, uidvalidity, wanted)
        storage.set_email_label(msgid, wanted, "")
        return ""
    except (ImapError, ValueError) as e:
        storage.set_email_label(msgid, "", str(e))
        return str(e)


def process(source, folder, uidvalidity, item, *, label, network, cache, deep=False, deep_links=None):
    """Analyse, store and (optionally) label one fetched message."""
    r = scan_message(item.raw, trusted_source=True, network=network, deep=deep, deep_links=deep_links,
                     seen_before=_seen_lookup(source, item.received_at), link_cache=cache)
    persist(r, account=source.address, folder=folder, msgid=item.msgid, received_at=item.received_at)
    r["label_error"] = apply_label(source, folder, item.uid, uidvalidity, item.msgid, r) if label else ""
    return r


def scan_inbox(source, *, folder="inbox", days=7, unread=False, limit=200, rescan=False, label=True,
               network=None, on_result=None, on_skip=None):
    """Scan recent messages of one folder (newest first). Returns {'verdicts': {...}, 'skipped': n, ...}."""
    network = network or config.MAIL_NETWORK
    name = source.resolve_folder(folder)
    validity, uids = source.search(name, since_days=days, unread_only=unread)
    uids = sorted(uids, reverse=True)[:limit]
    summary = {"folder": name, "found": len(uids), "scanned": 0, "skipped": 0, "errors": 0, "verdicts": {},
               "label_errors": 0}
    cache = {}
    skip = None if rescan else storage.email_seen
    for item in source.iter_messages(name, uids, max_message_bytes=limits.MAX_MESSAGE_BYTES,
                                     max_run_bytes=config.MAIL_MAX_RUN_BYTES, skip=skip):
        if item.skipped:
            summary["skipped"] += 1
            if on_skip:
                on_skip(item)
            continue
        try:
            r = process(source, name, validity, item, label=label, network=network, cache=cache)
        except ImapError:
            raise
        except Exception as e:  # one bad message must not end the run
            log.warning("message %s failed: %s", item.msgid, type(e).__name__)
            summary["errors"] += 1
            continue
        summary["scanned"] += 1
        summary["verdicts"][r["verdict"]] = summary["verdicts"].get(r["verdict"], 0) + 1
        summary["label_errors"] += bool(r.get("label_error"))
        if on_result:
            on_result(r, item)
    return summary


def deep_scan(source, msgid, *, links=None, allow_token_links=False, label=True, network=None):
    """Re-analyse one stored message, this time opening its (untrusted) links. Only ever run on an explicit
    user request. Links that look like one-time tokens need allow_token_links=True."""
    row = storage.get_email(msgid)
    if not row:
        raise ImapError("unknown message id: scan it first")
    raw = source.fetch_by_msgid(msgid)
    if raw is None:
        raise ImapError("message not found in the mailbox any more")
    passive = scan_message(raw, trusted_source=True, network="none", budget=30)
    chosen = [l for l in passive["links"] if not l["trusted"] and (links is None or l["n"] in links)]
    risky = [l for l in chosen if l["token_like"] or looks_like_token_link(l["url"])]
    if risky and not allow_token_links:
        raise TokenLinkRefused(risky)
    folder = row.get("folder") or source.resolve_folder("inbox")
    validity, uid = source.uid_for_msgid(folder, msgid)
    r = scan_message(raw, trusted_source=True, network=network or config.MAIL_NETWORK, deep=True,
                     deep_links={l["n"] for l in chosen},
                     seen_before=_seen_lookup(source, row.get("received_at")))
    persist(r, account=source.address, folder=folder, msgid=msgid, received_at=row.get("received_at"))
    if label and uid is not None:
        r["label_error"] = apply_label(source, folder, uid, validity, msgid, r)
    return r


@contextlib.contextmanager
def single_instance(name="gmail-watch"):
    """An OS-level file lock: released automatically if the process dies, so no stale-lock clean-up."""
    os.makedirs(config.OUTPUT_DIR, exist_ok=True)
    path = os.path.join(config.OUTPUT_DIR, f".{name}.lock")
    f = open(path, "a+")
    try:
        try:
            if os.name == "nt":
                import msvcrt
                f.seek(0)
                msvcrt.locking(f.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(f.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            raise RuntimeError("another watcher is already running for this scanner") from None
        yield
    finally:
        f.close()


def watch_once(source, folder, *, label, network, on_result=None, first_days=1):
    """Process messages that arrived since the last run of `watch` (state is saved after each one)."""
    name = source.resolve_folder(folder)
    stored_validity, last_uid = storage.get_mail_state(source.address, name)
    validity, uids, baseline = None, [], None
    if stored_validity is not None:
        validity, uids = source.search(name, min_uid=(last_uid or 0) + 1)
    if stored_validity is None or validity != stored_validity:
        # First run, or Gmail renumbered the folder: look at recent mail only, then remember the newest
        # UID so older mail is never swept up later. Message ids prevent duplicates.
        if stored_validity is not None:
            log.warning("UIDVALIDITY changed for %s; re-scanning the last %s day(s)", name, first_days)
        validity, everything = source.search(name)
        baseline = everything[-1] if everything else 0
        _, uids = source.search(name, since_days=first_days)
    cache, done, completed, newest = {}, 0, True, 0
    for item in source.iter_messages(name, uids, max_message_bytes=limits.MAX_MESSAGE_BYTES,
                                     max_run_bytes=config.MAIL_MAX_RUN_BYTES, skip=storage.email_seen):
        if item.skipped.startswith("download limit"):
            completed = False
            break  # not processed: leave it (and everything after it) for the next round
        if not item.skipped:
            try:
                r = process(source, name, validity, item, label=label, network=network, cache=cache)
            except ImapError:
                raise
            except Exception as e:
                log.warning("message %s failed: %s", item.msgid, type(e).__name__)
            else:
                done += 1
                if r.get("verdict") == "Dangerous":
                    notify.toast("URLscanner: dangerous e-mail",
                                 f"{r.get('from_address') or r.get('from')}\n{r.get('subject')} "
                                 f"({r.get('risk_score')}/100)")
                if on_result:
                    on_result(r, item)
        # progress is saved only after the message is fully processed (or deliberately skipped)
        storage.set_mail_state(source.address, name, validity, item.uid)
        newest = max(newest, item.uid)
    if baseline is not None and completed:
        storage.set_mail_state(source.address, name, validity, max(baseline, newest))
    return done


def watch(make_source, folder="inbox", *, interval=300, label=True, network=None, on_result=None,
          on_error=None, stop=lambda: False, sleep=time.sleep):
    """Poll forever (until stop()). Reconnects with exponential backoff after connection failures."""
    network = network or config.MAIL_NETWORK
    backoff = 30
    with single_instance():
        while not stop():
            try:
                with make_source() as source:
                    watch_once(source, folder, label=label, network=network, on_result=on_result)
                backoff = 30
                wait = interval
            except ImapError as e:
                if on_error:
                    on_error(e)
                wait = backoff
                backoff = min(backoff * 2, 1800)
            slept = 0
            while slept < wait and not stop():
                sleep(min(5, wait - slept))
                slept += 5
