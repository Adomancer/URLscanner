"""Phases B and C of the Gmail scanner against a fake Gmail IMAP server (no network)."""
import imaplib
import re
import time
from email.message import EmailMessage

import pytest

import config
from scanner import storage
from scanner.mail import limits, notify, pipeline, runner
from scanner.mail.imap_source import ImapError, ImapSource

PASSWORD = "abcd efgh ijkl mnop"


def mail(sender, subject="Hi", text="hello", html=""):
    m = EmailMessage()
    m["From"] = sender
    m["To"] = "me@gmail.com"
    m["Subject"] = subject
    m.set_content(text)
    if html:
        m.add_alternative(html, subtype="html")
    return m.as_bytes()


PHISH = mail("BCA <bca.security@gmail.com>", "Akun anda akan diblokir",
             "Akun anda akan diblokir dalam waktu 24 jam. Kirimkan kode OTP anda.",
             '<a href="https://bca-verify.xyz/login">https://www.klikbca.com</a>')
CLEAN = mail("Friend <friend@example.org>", "Lunch", "See you at noon")


class FakeGmail:
    """In-memory mailbox shared by every connection the code under test opens."""

    def __init__(self):
        self.folders = {
            "INBOX": {"flags": r"\HasNoChildren", "validity": 7, "msgs": {}},
            "[Google Mail]/Spam": {"flags": r"\HasNoChildren \Junk", "validity": 9, "msgs": {}},
            "[Google Mail]/All Mail": {"flags": r"\HasNoChildren \All", "validity": 11, "msgs": {}},
        }
        self.log = []          # (connection id, command, args, readonly)
        self.next_msgid = 1000
        self.fail_fetch_uid = None
        self.labels_created = set()

    def add(self, raw, folder="INBOX", labels=(), uid=None):
        box = self.folders[folder]["msgs"]
        uid = uid or (max(box) + 1 if box else 1)
        self.next_msgid += 1
        msg = {"raw": raw, "msgid": str(self.next_msgid), "labels": set(labels), "seen": False,
               "date": time.time()}
        box[uid] = msg
        all_mail = self.folders.get("[Google Mail]/All Mail")
        if all_mail is not None:
            all_mail["msgs"][len(all_mail["msgs"]) + 1] = msg
        return uid, msg


class FakeIMAP:
    gmail = None
    counter = 0

    def __init__(self, host, port, ssl_context=None, timeout=None):
        FakeIMAP.counter += 1
        self.cid = FakeIMAP.counter
        self.box = None
        self.readonly = True

    def _log(self, cmd, *args):
        self.gmail.log.append((self.cid, cmd, args, self.readonly))

    def login(self, user, password):
        if password != PASSWORD:
            raise imaplib.IMAP4.error(f"[AUTHENTICATIONFAILED] Invalid credentials {password}")
        return "OK", [b"logged in"]

    def logout(self):
        return "BYE", []

    def list(self):
        return "OK", [f'({f["flags"]}) "/" "{name}"'.encode() for name, f in self.gmail.folders.items()]

    def select(self, mailbox, readonly=False):
        name = mailbox.strip('"')
        self.box, self.readonly = name, readonly
        self._log("SELECT", name)
        if name not in self.gmail.folders:
            return "NO", [b"no such mailbox"]
        return "OK", [str(len(self.gmail.folders[name]["msgs"])).encode()]

    def response(self, code):
        return code, [str(self.gmail.folders[self.box]["validity"]).encode()]

    def create(self, name):
        self._log("CREATE", name)
        if name in self.gmail.labels_created:
            return "NO", [b"[ALREADYEXISTS]"]
        self.gmail.labels_created.add(name)
        return "OK", []

    def _msgs(self):
        return self.gmail.folders[self.box]["msgs"]

    def uid(self, cmd, *args):
        self._log(cmd, *args)
        msgs = self._msgs()
        if cmd == "SEARCH":
            uids = sorted(msgs)
            a = list(args)
            while a:
                k = a.pop(0)
                if k == "UID":
                    lo = int(a.pop(0).split(":")[0])
                    uids = [u for u in uids if u >= lo] or ([max(msgs)] if msgs else [])
                elif k == "X-GM-MSGID":
                    want = a.pop(0)
                    uids = [u for u in uids if msgs[u]["msgid"] == want]
                elif k == "X-GM-RAW":
                    addr = a.pop(0).strip('"').split(":", 1)[1]
                    uids = [u for u in uids if addr.encode() in msgs[u]["raw"].lower()]
                elif k in ("SINCE", "BEFORE"):
                    a.pop(0)
                elif k == "UNSEEN":
                    uids = [u for u in uids if not msgs[u]["seen"]]
            return "OK", [" ".join(map(str, uids)).encode()]
        if cmd == "FETCH":
            uids = [int(x) for x in args[0].split(",")]
            spec = args[1]
            out = []
            for u in uids:
                m = msgs.get(u)
                if not m:
                    continue
                if "BODY.PEEK[]" in spec or "BODY[]" in spec:
                    if self.gmail.fail_fetch_uid == u:
                        raise OSError("connection reset")
                    if "PEEK" not in spec:
                        m["seen"] = True
                    out.append((f"1 (UID {u} BODY[] {{{len(m['raw'])}}}".encode(), m["raw"]))
                    out.append(b")")
                elif "X-GM-LABELS" in spec:
                    labels = " ".join(f'"{l}"' for l in sorted(m["labels"]))
                    out.append(f"1 (X-GM-LABELS ({labels}) UID {u})".encode())
                else:
                    out.append(f'1 (X-GM-MSGID {m["msgid"]} RFC822.SIZE {len(m["raw"])} UID {u} '
                               f'INTERNALDATE "25-Oct-2026 10:00:00 +0000")'.encode())
            return "OK", out
        if cmd == "STORE":
            if self.readonly:
                return "NO", [b"mailbox is read-only"]
            u, op, labels = int(args[0]), args[1], re.findall(r'"([^"]+)"', args[2])
            target = msgs[u]["labels"]
            (target.update if op.startswith("+") else target.difference_update)(labels)
            return "OK", []
        raise AssertionError(f"unexpected UID {cmd}")


@pytest.fixture
def gmail(monkeypatch, tmp_path):
    monkeypatch.setattr(config, "DB_PATH", str(tmp_path / "mail.db"))
    monkeypatch.setattr(config, "OUTPUT_DIR", str(tmp_path))
    monkeypatch.setattr(config, "MAIL_NETWORK", "none")
    FakeIMAP.gmail = FakeGmail()
    return FakeIMAP.gmail


def source(password=PASSWORD):
    return ImapSource("me@gmail.com", password, factory=FakeIMAP)


def cmds(g, name):
    return [entry for entry in g.log if entry[1] == name]


# --- phase B: read-only access ---------------------------------------------------------------

def test_scan_is_read_only_and_keeps_mail_unread(gmail):
    gmail.add(PHISH)
    gmail.add(CLEAN)
    with source() as src:
        summary = runner.scan_inbox(src, label=False)
    assert summary["scanned"] == 2
    assert all(readonly for _, _, _, readonly in cmds(gmail, "SELECT"))
    fetches = [a[1] for _, _, a, _ in cmds(gmail, "FETCH")]
    assert any("BODY.PEEK[]" in f for f in fetches) and not any("BODY[]" in f and "PEEK" not in f for f in fetches)
    assert not cmds(gmail, "STORE") and not cmds(gmail, "CREATE")
    assert all(not m["seen"] for m in gmail.folders["INBOX"]["msgs"].values())
    assert {e["verdict"] for e in storage.list_emails()} >= {"Dangerous"}


def test_large_message_skipped_by_size(gmail, monkeypatch):
    monkeypatch.setattr(limits, "MAX_MESSAGE_BYTES", 100)
    gmail.add(PHISH)
    skipped = []
    with source() as src:
        summary = runner.scan_inbox(src, label=False, on_skip=skipped.append)
    assert summary["scanned"] == 0 and "too large" in skipped[0].skipped
    assert not any("BODY" in a[1] for _, _, a, _ in cmds(gmail, "FETCH"))


def test_special_use_folders_found_by_flag(gmail):
    with source() as src:
        assert src.resolve_folder("spam") == "[Google Mail]/Spam"
        assert src.resolve_folder("all") == "[Google Mail]/All Mail"


def test_password_never_in_errors(gmail):
    with pytest.raises(ImapError) as e:
        with source(password="wrong-secret-pw"):
            pass
    assert "wrong-secret-pw" not in str(e.value) and "***" in str(e.value)


def test_rescan_skips_known_messages(gmail):
    gmail.add(PHISH)
    with source() as src:
        runner.scan_inbox(src, label=False)
        again = runner.scan_inbox(src, label=False)
    assert again["scanned"] == 0 and again["skipped"] == 1
    assert len(storage.list_emails()) == 1


def test_sender_lookup_unknown_when_all_mail_hidden(gmail):
    del gmail.folders["[Google Mail]/All Mail"]
    gmail.add(CLEAN)
    with source() as src:
        assert src.sender_seen_before("friend@example.org") is None
        assert src.sender_seen_before('evil" OR "x@y') is None


def test_sender_lookup(gmail):
    gmail.add(CLEAN)
    with source() as src:
        assert src.sender_seen_before("friend@example.org") is True
        assert src.sender_seen_before("stranger@example.org") is False


def test_fetch_parser_handles_uid_after_literal():
    from scanner.mail.imap_source import _parse_fetch
    resp = [(b"1 (BODY[] {5}", b"hello"), b" UID 42 X-GM-MSGID 777)"]
    rec = _parse_fetch(resp)[42]
    assert rec["body"] == b"hello" and rec["msgid"] == "777"


# --- phase C: labels -------------------------------------------------------------------------

def test_labels_use_separate_read_write_connection(gmail):
    uid, msg = gmail.add(PHISH)
    with source() as src:
        runner.scan_inbox(src, label=True)
    assert msg["labels"] == {"URLscanner/Dangerous"}
    stores = cmds(gmail, "STORE")
    assert stores and all(not readonly for _, _, _, readonly in stores)
    read_conn = cmds(gmail, "SEARCH")[0][0]
    assert all(cid != read_conn for cid, *_ in stores)
    assert not msg["seen"]
    assert storage.get_email(msg["msgid"])["label_applied"] == "URLscanner/Dangerous"


def test_labels_reconcile_both_ways(gmail):
    uid, msg = gmail.add(CLEAN, labels={"URLscanner/Suspicious", "Work"})
    with source() as src:
        validity, _ = src.search("INBOX")
        src.reconcile_labels("INBOX", uid, validity, "URLscanner/Dangerous")      # verdict went up
        assert msg["labels"] == {"URLscanner/Dangerous", "Work"}
        src.reconcile_labels("INBOX", uid, validity, "")                          # verdict went down
        assert msg["labels"] == {"Work"}
        with pytest.raises(ValueError):
            src.reconcile_labels("INBOX", uid, validity, "Inbox")                 # never other labels


def test_label_failure_is_recorded(gmail):
    uid, msg = gmail.add(PHISH)
    with source() as src:
        validity, _ = src.search("INBOX")
        r = pipeline.scan_message(PHISH, network="none")
        pipeline.persist(r, account="me@gmail.com", folder="INBOX", msgid=msg["msgid"])
        err = runner.apply_label(src, "INBOX", uid, validity + 1, msg["msgid"], r)
    assert "UIDVALIDITY" in err
    assert storage.get_email(msg["msgid"])["label_error"]


# --- phase C: watch --------------------------------------------------------------------------

def test_watch_saves_progress_and_resumes(gmail):
    gmail.add(CLEAN)
    gmail.add(PHISH)
    gmail.fail_fetch_uid = 2
    with source() as src:
        with pytest.raises(ImapError):
            runner.watch_once(src, "inbox", label=False, network="none")
    assert storage.get_mail_state("me@gmail.com", "INBOX") == (7, 1)   # only the finished message
    gmail.fail_fetch_uid = None
    gmail.add(CLEAN)
    with source() as src:
        assert runner.watch_once(src, "inbox", label=False, network="none") == 2
        assert runner.watch_once(src, "inbox", label=False, network="none") == 0
    assert storage.get_mail_state("me@gmail.com", "INBOX") == (7, 3)
    assert len(storage.list_emails()) == 3


def test_watch_first_run_never_sweeps_old_mail(gmail, monkeypatch):
    for _ in range(3):
        gmail.add(CLEAN)                                   # old mail, outside the first-run window
    real_search = ImapSource.search

    def search(self, folder, since_days=None, unread_only=False, min_uid=None):
        validity, uids = real_search(self, folder, since_days, unread_only, min_uid)
        return validity, ([] if since_days else uids)       # nothing arrived in the last day
    monkeypatch.setattr(ImapSource, "search", search)
    with source() as src:
        assert runner.watch_once(src, "inbox", label=False, network="none") == 0
        assert storage.get_mail_state("me@gmail.com", "INBOX") == (7, 3)
        gmail.add(PHISH)
        assert runner.watch_once(src, "inbox", label=False, network="none") == 1  # only the new one
    assert len(storage.list_emails()) == 1


def test_watch_uidvalidity_change_rescans_without_duplicates(gmail):
    gmail.add(CLEAN)
    with source() as src:
        runner.watch_once(src, "inbox", label=False, network="none")
    gmail.folders["INBOX"]["validity"] = 8
    gmail.add(PHISH)
    with source() as src:
        assert runner.watch_once(src, "inbox", label=False, network="none") == 1
    assert len(storage.list_emails()) == 2
    assert storage.get_mail_state("me@gmail.com", "INBOX")[0] == 8


def test_watch_toasts_dangerous_mail(gmail, monkeypatch):
    shown = []
    monkeypatch.setattr(notify, "toast", lambda title, body: shown.append((title, body)))
    gmail.add(PHISH)
    with source() as src:
        runner.watch_once(src, "inbox", label=False, network="none")
    assert shown and "Akun anda" in shown[0][1]


def test_watch_loop_backs_off_on_errors(gmail):
    attempts, waits = [], []

    def broken():
        attempts.append(1)
        raise ImapError("offline")

    runner.watch(broken, interval=300, network="none", stop=lambda: len(attempts) >= 3,
                 sleep=waits.append)
    assert len(attempts) == 3 and sum(waits) >= 30 + 60


def test_single_watcher(gmail):
    with runner.single_instance():
        with pytest.raises(RuntimeError):
            with runner.single_instance():
                pass


# --- phase C: deep scan ----------------------------------------------------------------------

def test_deep_scan_refuses_token_links_without_confirmation(gmail, monkeypatch):
    raw = mail("x <x@shop.xyz>", html='<a href="https://shop.xyz/reset-password?t=abc">reset</a>'
                                      '<a href="https://promo.xyz/sale">sale</a>')
    uid, msg = gmail.add(raw)
    opened = []
    real = pipeline.scan_url

    def fake(url, passive=False, network="dns", store=True):
        if not passive:
            opened.append(url)
            return {"id": "d", "url": url, "risk_score": 10, "verdict": "Clean", "reasons": [], "findings": []}
        return real(url, passive=True, network="none", store=False)

    monkeypatch.setattr(pipeline, "scan_url", fake)
    with source() as src:
        runner.scan_inbox(src, label=False)
        with pytest.raises(runner.TokenLinkRefused):
            runner.deep_scan(src, msg["msgid"], label=False)
        assert opened == []
        r = runner.deep_scan(src, msg["msgid"], links={2}, label=False)
        assert opened == ["https://promo.xyz/sale"]
        runner.deep_scan(src, msg["msgid"], allow_token_links=True, label=False)
    assert "https://shop.xyz/reset-password?t=abc" in opened
    assert storage.get_email(msg["msgid"])["deep_scanned"] == 1
    assert [l["mode"] for l in r["links"]] == ["passive", "deep"] or [l["mode"] for l in r["links"]] == ["deep", "passive"]


# --- notification ----------------------------------------------------------------------------

@pytest.mark.parametrize("subject", ["'; Start-Process calc; '", '<x>&\' "$(Get-Process)" `whoami`',
                                     "a‮evil\x07\r\n"])
def test_toast_text_travels_only_in_env(monkeypatch, subject):
    calls = []

    def fake_run(argv, **kw):
        calls.append((argv, kw))

        class P:
            returncode = 0
        return P()

    monkeypatch.setattr(notify.os, "name", "nt")
    assert notify.toast("URLscanner", f"x@y.z\n{subject}", runner=fake_run) is True
    argv, kw = calls[0]
    assert argv[-1] == notify.SCRIPT and kw["shell"] is False
    assert all(subject not in a for a in argv)
    body = kw["env"][notify.BODY_VAR]
    assert "‮" not in body and "\x07" not in body and "\r" not in body
    assert "[Security.SecurityElement]::Escape" in notify.SCRIPT
