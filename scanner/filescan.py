"""Static analysis of a fetched file: an offline take on VirusTotal's file report.

Nothing is executed, unpacked to disk or sent anywhere. The input is the body the HTTP check already
downloaded (size-capped). analyze() gathers facts; flags() turns facts into weighted signals that feed
the same threat-risk model as every other check.
"""
import glob
import hashlib
import io
import math
import os
import re
import struct
import threading
import zipfile
from collections import Counter
from datetime import datetime, timezone
from importlib.util import find_spec

from . import data

HASHLIST_DIR = os.path.join(data.DATA_DIR, "hashlists")
YARA_DIR = os.path.join(data.DATA_DIR, "yara")

# Harmless antivirus test string. Assembled at runtime so no source file contains it verbatim.
EICAR = b"EICAR-STANDARD-" + b"ANTIVIRUS-TEST-FILE"

MAGIC = [
    (b"MZ", "PE"),
    (b"\x7fELF", "ELF"),
    (b"\xfe\xed\xfa\xce", "Mach-O"), (b"\xfe\xed\xfa\xcf", "Mach-O"),
    (b"\xce\xfa\xed\xfe", "Mach-O"), (b"\xcf\xfa\xed\xfe", "Mach-O"),
    (b"PK\x03\x04", "ZIP"),
    (b"%PDF-", "PDF"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "OLE"),
    (b"Rar!\x1a\x07", "RAR"),
    (b"7z\xbc\xaf\x27\x1c", "7Z"),
    (b"\x1f\x8b", "GZIP"),
    (b"L\x00\x00\x00\x01\x14\x02", "LNK"),
    (b"\xff\xd8\xff", "JPEG"),
    (b"\x89PNG\r\n\x1a\n", "PNG"),
    (b"GIF87a", "GIF"), (b"GIF89a", "GIF"),
]

# Which content types a given file extension should carry.
EXPECTED = {
    "exe": {"PE"}, "dll": {"PE"}, "sys": {"PE"}, "scr": {"PE"}, "ocx": {"PE"}, "cpl": {"PE"},
    "pdf": {"PDF"},
    "zip": {"ZIP"}, "jar": {"ZIP"}, "apk": {"ZIP"}, "docx": {"ZIP"}, "docm": {"ZIP"}, "xlsx": {"ZIP"},
    "xlsm": {"ZIP"}, "pptx": {"ZIP"}, "odt": {"ZIP"},
    "doc": {"OLE"}, "xls": {"OLE"}, "ppt": {"OLE"}, "msi": {"OLE"},
    "rar": {"RAR"}, "7z": {"7Z"}, "gz": {"GZIP"}, "tgz": {"GZIP"}, "lnk": {"LNK"}, "elf": {"ELF"},
    "jpg": {"JPEG"}, "jpeg": {"JPEG"}, "png": {"PNG"}, "gif": {"GIF"},
}
PE_EXT = {"exe", "dll", "sys", "scr", "ocx", "cpl"}
SCRIPT_EXT = {"js", "vbs", "vbe", "jse", "ps1", "hta", "wsf", "bat", "cmd"}
DANGEROUS_IN_ARCHIVE = {"exe", "scr", "com", "bat", "cmd", "ps1", "vbs", "vbe", "js", "jse", "wsf", "hta",
                        "lnk", "msi", "iso", "img", "dll", "jar", "pif", "cpl", "reg", "inf"}
DOUBLE_EXT = re.compile(r"\.(pdf|docx?|xlsx?|pptx?|jpe?g|png|gif|txt|zip|rtf)\."
                        r"(exe|scr|com|pif|bat|cmd|js|vbs|hta|lnk|ps1|jar|msi)$", re.I)

# Imports commonly seen in malware triage. Each group is a hint, not a verdict: installers use some too.
SUSPICIOUS_IMPORTS = {
    "injection": {"VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", "NtUnmapViewOfSection",
                  "QueueUserAPC", "SetThreadContext"},
    "download": {"URLDownloadToFileA", "URLDownloadToFileW", "InternetOpenUrlA", "InternetOpenUrlW"},
    "keylog": {"GetAsyncKeyState", "SetWindowsHookExA", "SetWindowsHookExW"},
    "evasion": {"IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess"},
}
PACKER_SECTIONS = {"UPX0", "UPX1", "UPX2", ".upx", ".aspack", ".themida", ".vmp0", ".vmp1", ".petite", ".mpress1"}
MACHINES = {0x14C: "x86", 0x8664: "x64", 0xAA64: "ARM64", 0x1C4: "ARM"}

SCRIPT_PATTERNS = [
    (re.compile(rb"-e(?:nc|ncodedcommand)\s+[A-Za-z0-9+/=]{40,}", re.I), "encoded PowerShell command"),
    (re.compile(rb"\bInvoke-Expression\b|\bIEX\s*\(", re.I), "Invoke-Expression"),
    (re.compile(rb"FromBase64String", re.I), "base64 decoding"),
    (re.compile(rb"DownloadString|DownloadFile|Invoke-WebRequest|Net\.WebClient", re.I), "network download"),
    (re.compile(rb"WScript\.Shell|Shell\.Application", re.I), "shell automation"),
    (re.compile(rb"-WindowStyle\s+Hidden", re.I), "hidden window"),
    (re.compile(rb"eval\s*\(\s*(?:unescape|atob)\s*\(", re.I), "eval of decoded data"),
]
PDF_PATTERNS = [
    (re.compile(rb"/JavaScript(?![A-Za-z])"), "JavaScript"),
    (re.compile(rb"/JS(?![A-Za-z])"), "JavaScript"),
    (re.compile(rb"/Launch(?![A-Za-z])"), "Launch action"),
    (re.compile(rb"/OpenAction(?![A-Za-z])"), "auto-run action"),
    (re.compile(rb"/EmbeddedFile(?![A-Za-z])"), "embedded file"),
    (re.compile(rb"/RichMedia(?![A-Za-z])"), "rich media"),
]

# VBA in OLE (.doc/.xls/.ppt, and vbaProject.bin inside .docm/.xlsm): stream names are UTF-16LE.
_OLE_VBA_MARKERS = ("_VBA_PROJECT".encode("utf-16-le"), "Macros".encode("utf-16-le") + b"\x00\x00")
AUTOEXEC = ("AutoOpen", "AutoExec", "AutoClose", "Document_Open", "Document_Close", "Workbook_Open",
            "Workbook_Activate")  # the loose match also catches Auto_Open / Auto_Close


def _loose(name):
    """Match a name even when MS-OVBA compression put a flag byte between two of its letters."""
    return re.compile(b".?".join(re.escape(bytes([c])) for c in name.encode()), re.S | re.I)


_AUTOEXEC_RX = [(n, _loose(n)) for n in AUTOEXEC]
VBA_MAX = 16 * 1024 * 1024

_lock = threading.Lock()
_hash_cache = {"sig": None, "map": {}}
_yara = {"sig": None, "rules": None, "error": ""}


# --- identification -----------------------------------------------------------------------

def ext_of(name):
    base = os.path.basename(name or "")
    return base.rsplit(".", 1)[-1].lower() if "." in base else ""


def sniff(body):
    for magic, kind in MAGIC:
        if body.startswith(magic):
            return kind
    head = body[:512].lstrip().lower()
    if head.startswith((b"<!doctype html", b"<html")):
        return "HTML"
    if body[:2] == b"#!" or head.startswith(b"<?php"):
        return "SCRIPT"
    sample = body[:1024]
    if not sample:
        return "EMPTY"
    printable = sum(1 for x in sample if x in (9, 10, 13) or 32 <= x < 127)
    return "TEXT" if printable / len(sample) > 0.95 else "BINARY"


def mismatch(ext, kind):
    """(kind, explanation) when the content contradicts the file name, else None."""
    if kind == "PE" and ext and ext not in PE_EXT:
        return ("disguised", f"Windows executable served as .{ext}")
    expected = EXPECTED.get(ext)
    if expected and kind not in expected:
        if kind == "HTML":
            return ("html", f"Link to a .{ext} file returned a web page")
        return ("type", f"Named .{ext} but the content is {kind.lower()}")
    return None


def entropy(data_bytes):
    sample = data_bytes[:2_000_000]
    if not sample:
        return 0.0
    counts = Counter(sample)
    n = len(sample)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


# --- PE (Windows executables and DLLs) ---------------------------------------------------------

def _rva_off(rva, sections):
    for s in sections:
        span = max(s["virtual_size"], s["raw_size"])
        if s["rva"] <= rva < s["rva"] + span:
            return rva - s["rva"] + s["raw_ptr"]
    return None


def _cstr(body, off, limit=256):
    if off is None or off >= len(body):
        return ""
    end = body.find(b"\x00", off, min(off + limit, len(body)))
    return body[off:end if end >= 0 else min(off + limit, len(body))].decode("latin-1")


def _imports(body, import_rva, sections, plus):
    """DLL name -> list of imported API names (ordinal-only imports are skipped)."""
    off = _rva_off(import_rva, sections)
    thunk = 8 if plus else 4
    fmt = "<Q" if plus else "<I"
    ordinal_flag = 1 << (63 if plus else 31)
    out = {}
    for _ in range(256):
        if off is None or off + 20 > len(body):
            break
        ilt, _, _, name_rva, iat = struct.unpack_from("<IIIII", body, off)
        if not (ilt or name_rva or iat):
            break
        dll = _cstr(body, _rva_off(name_rva, sections)).lower() or "?"
        apis = out.setdefault(dll, [])
        t_off = _rva_off(ilt or iat, sections)
        for i in range(4096):
            if t_off is None or t_off + thunk * (i + 1) > len(body):
                break
            val = struct.unpack_from(fmt, body, t_off + thunk * i)[0]
            if val == 0:
                break
            if val & ordinal_flag:
                continue
            hint = _rva_off(val & 0xFFFFFFFF, sections)
            if hint is not None:
                apis.append(_cstr(body, hint + 2))
        off += 20
    return out


def pe_info(body):
    """Parse the PE header, sections and imports. Returns None if the file is not a valid PE."""
    try:
        if len(body) < 0x40 or body[:2] != b"MZ":
            return None
        e_lfanew = struct.unpack_from("<I", body, 0x3C)[0]
        if body[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
            return None
        machine, nsec, ts, _, _, opt_size, chars = struct.unpack_from("<HHIIIHH", body, e_lfanew + 4)
        opt = e_lfanew + 24
        plus = struct.unpack_from("<H", body, opt)[0] == 0x20B
        ndd = struct.unpack_from("<I", body, opt + (108 if plus else 92))[0]
        dd0 = opt + (112 if plus else 96)
        dirs = [struct.unpack_from("<II", body, dd0 + 8 * i) for i in range(min(ndd, 16))]
        sec0 = opt + opt_size
        sections = []
        for i in range(min(nsec, 96)):
            base = sec0 + 40 * i
            vsize, rva, rawsize, rawptr = struct.unpack_from("<IIII", body, base + 8)
            sflags = struct.unpack_from("<I", body, base + 36)[0]
            sections.append({
                "name": body[base:base + 8].rstrip(b"\x00").decode("latin-1"),
                "virtual_size": vsize, "raw_size": rawsize, "rva": rva, "raw_ptr": rawptr,
                "entropy": round(entropy(body[rawptr:rawptr + rawsize]), 2),
                "executable": bool(sflags & 0x20000000),
                "writable": bool(sflags & 0x80000000),
            })
        imports = _imports(body, dirs[1][0], sections, plus) if len(dirs) > 1 and dirs[1][0] else {}
        api_set = {a for apis in imports.values() for a in apis}
        groups = {g: sorted(api_set & apis) for g, apis in SUSPICIOUS_IMPORTS.items() if api_set & apis}
        return {
            "machine": MACHINES.get(machine, hex(machine)),
            "is_dll": bool(chars & 0x2000),
            "compiled": datetime.fromtimestamp(ts, timezone.utc).date().isoformat() if 0 < ts < 4e9 else "",
            "signed": len(dirs) > 4 and dirs[4][1] > 0,
            "sections": sections,
            "groups": groups,
            "dlls": sorted(imports)[:60],
        }
    except (struct.error, IndexError, ValueError, OverflowError, OSError):
        return None


# --- OLE documents (legacy Office) -------------------------------------------------------------

def ole_info(body):
    """Does an OLE compound file carry VBA macros, and do they look auto-run? Best effort: the macro
    source is compressed, so an auto-run name split by a back-reference can be missed."""
    macros = any(m in body for m in _OLE_VBA_MARKERS)
    autoexec = sorted({n for n, rx in _AUTOEXEC_RX if rx.search(body)}) if macros else []
    return {"macros": macros, "autoexec": autoexec}


# --- archives (zip, Office documents, JAR, APK) ------------------------------------------------

def zip_info(body):
    try:
        zf = zipfile.ZipFile(io.BytesIO(body))
        infos = zf.infolist()[:5000]
    except Exception:  # not a usable archive
        return None
    names = [i.filename for i in infos]
    autoexec = []
    for i in infos:
        if i.filename.lower().endswith("vbaproject.bin") and i.file_size <= VBA_MAX:
            try:
                autoexec = ole_info(zf.read(i))["autoexec"]
            except Exception:  # damaged or encrypted entry
                pass
            break
    total = sum(i.file_size for i in infos)
    packed = sum(i.compress_size for i in infos) or 1
    return {
        "entries": len(infos),
        "names": names[:40],
        "uncompressed": total,
        "ratio": round(total / packed, 1),
        "macros": any(n.lower().endswith("vbaproject.bin") for n in names),
        "autoexec": autoexec,
        "office": "[Content_Types].xml" in names,
        "executables": sorted({n for n in names if ext_of(n) in DANGEROUS_IN_ARCHIVE})[:20],
        "double_extensions": sorted({n for n in names if DOUBLE_EXT.search(n)})[:20],
        "encrypted": any(i.flag_bits & 0x1 for i in infos),
    }


# --- PDF and scripts ---------------------------------------------------------------------------

def pdf_counts(body):
    out = {}
    for rx, label in PDF_PATTERNS:
        n = len(rx.findall(body))
        if n:
            out[label] = out.get(label, 0) + n
    return out


def script_hits(body):
    return [label for rx, label in SCRIPT_PATTERNS if rx.search(body)]


# --- hash lists and YARA (both user-supplied) --------------------------------------------------

def _load_hashes():
    files = sorted(glob.glob(os.path.join(HASHLIST_DIR, "*.txt")))
    sig = tuple((f, os.path.getmtime(f)) for f in files)
    with _lock:
        if sig != _hash_cache["sig"]:
            found = {}
            for f in files:
                label = os.path.basename(f)
                with open(f, encoding="utf-8", errors="replace") as fh:
                    for line in fh:
                        line = line.split("#", 1)[0].strip()
                        if not line:
                            continue
                        token = re.split(r"[\s,;]+", line)[0].lower()
                        if re.fullmatch(r"[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64}", token):
                            found.setdefault(token, label)
            _hash_cache.update(sig=sig, map=found)
        return dict(_hash_cache["map"])


def yara_matches(body):
    """Rule names matched by scanner/data/yara/*.yar (needs yara-python). Returns (matches, note)."""
    if find_spec("yara") is None:
        return None, "yara-python not installed (pip install yara-python)"
    rule_files = sorted(glob.glob(os.path.join(YARA_DIR, "*.yar")))
    if not rule_files:
        return None, "no rules in scanner/data/yara/"
    import yara
    sig = tuple((f, os.path.getmtime(f)) for f in rule_files)
    with _lock:
        if _yara["sig"] != sig:
            _yara.update(sig=sig, rules=None, error="")
            try:
                _yara["rules"] = yara.compile(filepaths={os.path.basename(f): f for f in rule_files})
            except Exception as e:
                _yara["error"] = f"rules failed to compile: {str(e)[:160]}"
        rules, err = _yara["rules"], _yara["error"]
    if rules is None:
        return None, err
    try:
        return sorted({m.rule for m in rules.match(data=body)}), ""
    except Exception as e:
        return None, f"YARA error: {str(e)[:160]}"


# --- public API ----------------------------------------------------------------------------------

def analyze(body, *, url_name="", content_type="", truncated=False):
    """Gather facts about a file. Returns a plain dict; see flags() for the weighted signals."""
    kind = sniff(body)
    ext = ext_of(url_name)
    rep = {
        "name": url_name, "ext": ext, "size": len(body), "type": kind, "content_type": content_type,
        "truncated": truncated, "entropy": round(entropy(body), 2), "mismatch": mismatch(ext, kind),
        "eicar": EICAR in body, "hash_hits": [], "yara": None, "yara_note": "",
    }
    if not truncated:
        rep["md5"] = hashlib.md5(body).hexdigest()
        rep["sha1"] = hashlib.sha1(body).hexdigest()
        rep["sha256"] = hashlib.sha256(body).hexdigest()
        known = _load_hashes()
        rep["hash_hits"] = sorted({known[h] for h in (rep["md5"], rep["sha1"], rep["sha256"]) if h in known})
    if kind == "PE":
        rep["pe"] = pe_info(body)
    if kind == "ZIP":
        rep["archive"] = zip_info(body)
    if kind == "OLE":
        rep["ole"] = ole_info(body)
    if kind == "PDF":
        counts = pdf_counts(body)
        rep["pdf"] = counts
        rep["pdf_summary"] = ", ".join(f"{k} ×{v}" for k, v in counts.items())
    if kind in ("SCRIPT", "TEXT") or ext in SCRIPT_EXT:
        rep["script"] = script_hits(body)
    if truncated:
        rep["yara_note"] = "file was over the analysis limit"
    else:
        rep["yara"], rep["yara_note"] = yara_matches(body)
    return rep


def flags(rep):
    """Weighted signals derived from analyze(). Weights are on the same 0..1 scale as other checks."""
    out = []

    def add(fid, title, severity, weight=0.0, penalty=0, evidence="", fix=""):
        out.append({"id": fid, "title": title, "severity": severity, "weight": weight,
                    "penalty": penalty, "evidence": str(evidence)[:300], "fix": fix})

    if rep.get("eicar"):
        add("file.eicar", "EICAR antivirus test file", "critical", 0.9,
            evidence="Standard harmless test string. Detection is the expected result for this file.")
    for feed in rep.get("hash_hits") or []:
        add("file.known_bad", f"File hash is listed in {feed}", "critical", 0.9, evidence=rep.get("sha256", ""))
    for rule in rep.get("yara") or []:
        add(f"file.yara.{rule}", f"YARA rule matched: {rule}", "high", 0.45)

    mm = rep.get("mismatch")
    if mm:
        kind, text = mm
        if kind == "disguised":
            add("file.disguised", "Executable disguised as another file type", "critical", 0.6, evidence=text,
                fix="Malware is often renamed to look like a document or image.")
        elif kind == "type":
            add("file.type_mismatch", "File content does not match its extension", "low", 0.08, evidence=text)
        else:
            add("file.html_instead", "Download link returned a web page", "info", evidence=text)

    pe = rep.get("pe")
    if pe:
        groups = pe["groups"]
        if "injection" in groups and len(groups["injection"]) >= 2:
            add("file.pe.injection", "Process-injection APIs imported", "high", 0.4,
                evidence=", ".join(groups["injection"]))
        elif "injection" in groups:
            add("file.pe.injection_one", "A process-injection API is imported", "medium", 0.12,
                evidence=", ".join(groups["injection"]))
        if "download" in groups:
            add("file.pe.download", "Network download APIs imported", "medium", 0.12,
                evidence=", ".join(groups["download"]))
        if "keylog" in groups:
            add("file.pe.keylog", "Keyboard-hook APIs imported", "medium", 0.12, evidence=", ".join(groups["keylog"]))
        if "evasion" in groups:
            add("file.pe.evasion", "Anti-debugging APIs imported", "low", 0.05, evidence=", ".join(groups["evasion"]))
        packers = [s["name"] for s in pe["sections"] if s["name"] in PACKER_SECTIONS]
        if packers:
            add("file.pe.packed", "Packer section names present", "medium", 0.12, evidence=", ".join(packers))
        rwx = [s["name"] for s in pe["sections"] if s["writable"] and s["executable"]]
        if rwx:
            add("file.pe.rwx", "Section is both writable and executable", "medium", 0.12, evidence=", ".join(rwx))
        dense = [s for s in pe["sections"] if s["executable"] and s["raw_size"] >= 4096 and s["entropy"] >= 7.2]
        if dense:
            add("file.pe.entropy", "Executable code looks packed or encrypted", "medium", 0.15,
                evidence=", ".join(f"{s['name']} (entropy {s['entropy']})" for s in dense))

    ole = rep.get("ole")
    if ole and ole["macros"]:
        add("file.macros", "Document contains macros", "medium", 0.25, evidence="VBA project in OLE document")
    autoexec = (ole or {}).get("autoexec") or (rep.get("archive") or {}).get("autoexec") or []
    if autoexec:
        add("file.macros.autoexec", "Macros run automatically when the document opens", "high", 0.35,
            evidence=", ".join(autoexec), fix="Auto-run macros are the classic malicious-document technique.")

    arch = rep.get("archive")
    if arch:
        if arch["macros"]:
            add("file.macros", "Document contains macros", "medium", 0.25, evidence="vbaProject.bin")
        if arch["double_extensions"]:
            add("file.double_ext", "Double file extension", "high", 0.35, evidence=", ".join(arch["double_extensions"]))
        if arch["executables"]:
            add("file.archive.executable", "Archive contains executables or scripts", "high", 0.3,
                evidence=", ".join(arch["executables"]))
        if arch["encrypted"]:
            add("file.archive.encrypted", "Archive has encrypted entries", "low", 0.1,
                evidence="contents cannot be inspected")
        if arch["ratio"] > 100 and arch["uncompressed"] > 100 * 1024 * 1024:
            add("file.archive.bomb", "Archive expands far beyond its size", "medium", 0.2,
                evidence=f"{arch['ratio']}× compression ratio")

    pdf = rep.get("pdf") or {}
    if "JavaScript" in pdf or "Launch action" in pdf:
        add("file.pdf.active", "PDF contains active content", "high", 0.3, evidence=rep.get("pdf_summary", ""))
    elif "embedded file" in pdf:
        add("file.pdf.embedded", "PDF embeds other files", "low", 0.08, evidence=rep.get("pdf_summary", ""))

    script = rep.get("script") or []
    if len(script) >= 2:
        add("file.script", "Script uses several risky techniques", "medium", 0.25, evidence=", ".join(script))
    elif script:
        add("file.script.one", f"Script uses {script[0]}", "low", 0.08)
    return out
