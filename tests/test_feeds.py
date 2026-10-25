import importlib.util
import os

from scanner import net

_spec = importlib.util.spec_from_file_location(
    "update_feeds", os.path.join(os.path.dirname(__file__), "..", "tools", "update_feeds.py"))
update_feeds = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(update_feeds)


def test_entries_from_plain_and_csv():
    plain = "# comment\nhttps://a.example/x\nnot a url\nhttps://a.example/x\n"
    assert update_feeds._entries(plain) == ["https://a.example/x"]
    csv_text = ('# id,dateadded,url,url_status\n'
                '"1","2026-10-25","http://bad.example/m.exe","online"\n')
    assert update_feeds._entries(csv_text) == ["http://bad.example/m.exe"]


def test_key_feed_skipped_without_key_and_key_never_leaks(monkeypatch):
    feed = {"url": "https://feeds.example/{key}/x.csv", "file": "t.txt", "about": "t", "key_env": "T_KEY"}
    monkeypatch.delenv("T_KEY", raising=False)
    assert update_feeds.update("t", feed).startswith("skipped")
    monkeypatch.setenv("T_KEY", "SUPERSECRETKEY")

    def boom(url, **kw):
        raise net.ResolveError(f"cannot resolve {url}")

    monkeypatch.setattr(net, "safe_fetch", boom)
    msg = update_feeds.update("t", feed)
    assert msg.startswith("failed") and "SUPERSECRETKEY" not in msg
