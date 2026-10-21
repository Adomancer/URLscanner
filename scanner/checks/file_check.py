"""File analysis for non-HTML responses: downloads, attachments, scripts, documents."""
import re
from urllib.parse import unquote, urlsplit

from .. import filescan
from ..models import Section
from . import check

_DISPOSITION = re.compile(r"filename\*?=(?:UTF-8'')?\"?([^\";]+)", re.I)


def _file_name(fetch):
    headers = {k.lower(): v for k, v in fetch.headers.items()}
    m = _DISPOSITION.search(headers.get("content-disposition", ""))
    if m:
        return unquote(m.group(1).strip())
    return unquote(urlsplit(fetch.final_url).path.rsplit("/", 1)[-1])


def _summary(rep):
    out = {k: rep.get(k) for k in ("name", "type", "content_type", "size", "entropy", "truncated",
                                    "md5", "sha1", "sha256", "yara_note", "pdf_summary")}
    out["hash_hits"] = rep.get("hash_hits") or []
    out["yara"] = rep.get("yara") or []
    out["script"] = rep.get("script") or []
    out["mismatch"] = rep["mismatch"][1] if rep.get("mismatch") else ""
    pe = rep.get("pe")
    if pe:
        out["pe"] = {
            "machine": pe["machine"], "is_dll": pe["is_dll"], "compiled": pe["compiled"], "signed": pe["signed"],
            "sections": [f"{s['name']} (entropy {s['entropy']})" for s in pe["sections"]],
            "suspicious": [f"{g}: {', '.join(apis)}" for g, apis in pe["groups"].items()],
            "dlls": pe["dlls"],
        }
    arch = rep.get("archive")
    if arch:
        out["archive"] = {k: arch[k] for k in ("entries", "names", "macros", "autoexec", "executables",
                                               "double_extensions", "encrypted", "ratio")}
    if rep.get("ole"):
        out["ole"] = rep["ole"]
    return out


@check("file", "File analysis", stage=2, requires="http")
def run(ctx):
    s = Section()
    f = ctx.fetch
    if f.is_html or not f.body:
        s.data["applicable"] = False
        return s
    rep = filescan.analyze(f.body, url_name=_file_name(f), content_type=f.content_type, truncated=f.truncated)
    found = filescan.flags(rep)
    for x in found:
        s.flag(x["id"], x["title"], x["severity"], weight=x["weight"], penalty=x["penalty"],
               evidence=x["evidence"], fix=x["fix"])
    s.data.update(_summary(rep))
    s.data["show"] = rep["type"] != "TEXT" or bool(found)
    return s
