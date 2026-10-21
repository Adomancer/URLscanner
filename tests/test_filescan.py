import hashlib
import io
import os
import zipfile

import pytest

from scanner import filescan, scoring
from scanner.models import Finding

# The standard EICAR test file is 68 bytes; assembled here so no source file holds it verbatim.
EICAR_BODY = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$" + filescan.EICAR


def ids(rep):
    return {f["id"] for f in filescan.flags(rep)}


def test_eicar_is_detected_and_hashed():
    rep = filescan.analyze(EICAR_BODY, url_name="eicar.txt")
    assert rep["eicar"] is True
    assert rep["sha256"] == hashlib.sha256(EICAR_BODY).hexdigest()
    assert "file.eicar" in ids(rep)


def test_pe_renamed_to_pdf_is_flagged():
    rep = filescan.analyze(b"MZ" + b"\x00" * 300, url_name="invoice.pdf")
    assert rep["type"] == "PE"
    assert rep["mismatch"][0] == "disguised"
    assert "file.disguised" in ids(rep)


def test_correctly_named_pe_is_not_disguised():
    rep = filescan.analyze(b"MZ" + b"\x00" * 300, url_name="setup.exe")
    assert rep["mismatch"] is None


def test_zip_double_extension_and_macro():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("invoice.pdf.exe", b"x")
        z.writestr("word/vbaProject.bin", b"y")
        z.writestr("[Content_Types].xml", b"<Types/>")
    rep = filescan.analyze(buf.getvalue(), url_name="docs.zip")
    assert rep["type"] == "ZIP"
    assert {"file.double_ext", "file.macros", "file.archive.executable"} <= ids(rep)


def test_pdf_with_javascript_is_flagged():
    body = (b"%PDF-1.7\n1 0 obj << /Type /Catalog /OpenAction 2 0 R >> endobj\n"
            b"2 0 obj << /S /JavaScript /JS (app.alert(1)) >> endobj")
    rep = filescan.analyze(body, url_name="report.pdf")
    assert rep["type"] == "PDF"
    assert "file.pdf.active" in ids(rep)


def test_plain_text_is_quiet():
    rep = filescan.analyze(b"User-agent: *\nDisallow: /admin\n", url_name="robots.txt")
    assert rep["type"] == "TEXT"
    assert filescan.flags(rep) == []


def test_entropy_bounds():
    assert filescan.entropy(os.urandom(8192)) > 7.5
    assert filescan.entropy(b"a" * 1000) == 0.0


@pytest.mark.skipif(not os.path.exists(r"C:\Windows\System32\notepad.exe"), reason="needs Windows")
def test_real_pe_parses():
    with open(r"C:\Windows\System32\notepad.exe", "rb") as f:
        body = f.read()
    pe = filescan.analyze(body, url_name="notepad.exe")["pe"]
    assert pe is not None
    assert ".text" in [s["name"] for s in pe["sections"]]
    assert any(d.endswith(".dll") for d in pe["dlls"])


def test_hash_list_match(tmp_path, monkeypatch):
    body = b"known bad sample bytes for the hash list test"
    (tmp_path / "feed.txt").write_text(f"# test feed\n{hashlib.sha256(body).hexdigest()}  sample\n")
    monkeypatch.setattr(filescan, "HASHLIST_DIR", str(tmp_path))
    rep = filescan.analyze(body, url_name="x.bin")
    assert rep["hash_hits"] == ["feed.txt"]
    assert "file.known_bad" in ids(rep)


def test_consensus_counts_local_engines():
    state = {
        "lexical": {"title": "URL structure", "status": "done"},
        "file": {"title": "File analysis", "status": "done"},
        "blocklist": {"title": "Offline threat feeds", "status": "done"},
        "tls": {"title": "TLS certificate", "status": "skipped"},
    }
    findings = [Finding("file.eicar", "x", "critical", weight=0.9, category="file")]
    sections = {"blocklist": {"feeds": ["urlhaus.txt", "phish.txt"], "feed_hits": ["phish.txt"]}}
    det = scoring.consensus(state, findings, sections)
    # engines: lexical, file, plus the two feed files; the blocklist check itself and skipped TLS are not counted
    assert det["total"] == 4
    assert det["flagged"] == 2  # file analysis and phish.txt


OLE_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
VBA_STREAM = "_VBA_PROJECT".encode("utf-16-le")


def test_ole_macros_and_autoexec():
    # b"\x10" stands in for an MS-OVBA flag byte splitting the name inside compressed source
    body = OLE_MAGIC + bytes(500) + VBA_STREAM + bytes(64) + b"Sub Auto\x10Open()"
    rep = filescan.analyze(body, url_name="invoice.doc")
    assert rep["ole"] == {"macros": True, "autoexec": ["AutoOpen"]}
    assert {"file.macros", "file.macros.autoexec"} <= ids(rep)


def test_ole_without_vba_is_quiet():
    body = OLE_MAGIC + bytes(500) + "WordDocument".encode("utf-16-le") + b"AutoOpen"  # just text, no VBA project
    rep = filescan.analyze(body, url_name="report.doc")
    assert rep["ole"]["macros"] is False
    assert not ids(rep) & {"file.macros", "file.macros.autoexec"}


def test_docm_autoexec_inside_vbaproject():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", "<Types/>")
        z.writestr("word/vbaProject.bin", OLE_MAGIC + VBA_STREAM + b"Sub Document_Open()")
    rep = filescan.analyze(buf.getvalue(), url_name="invoice.docm")
    assert rep["archive"]["autoexec"] == ["Document_Open"]
    assert {"file.macros", "file.macros.autoexec"} <= ids(rep)
