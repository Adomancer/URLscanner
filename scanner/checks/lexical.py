"""URL-structure heuristics: homographs, typosquats, combosquats, and classic phishing tricks."""
import ipaddress
import re
import unicodedata
from functools import lru_cache
from urllib.parse import unquote

from .. import data
from ..models import Section
from ..utils import shannon_entropy, split_host
from . import check

# ASCII look-alikes used by typosquatters
_HOMOGLYPH_SUBS = [("rn", "m"), ("vv", "w"), ("cl", "d"), ("0", "o"), ("1", "l"), ("3", "e"),
                   ("5", "s"), ("4", "a"), ("7", "t"), ("8", "b"), ("9", "g"), ("!", "i")]
_COMMON_SCRIPTS = {"DIGIT", "HYPHEN-MINUS", "LOW", "FULL", "COMMON"}


def _script_of(ch):
    if ch.isascii() and not ch.isalpha():
        return "COMMON"
    try:
        return unicodedata.name(ch).split()[0]
    except ValueError:
        return "UNKNOWN"


def skeleton(text):
    """Map look-alike Unicode characters to ASCII (TR39-style skeleton, simplified)."""
    conf = data.confusables()
    out = []
    for ch in unicodedata.normalize("NFKC", text.lower()):
        if ch in conf:
            out.append(conf[ch])
            continue
        base = unicodedata.normalize("NFKD", ch)
        base = "".join(c for c in base if not unicodedata.combining(c))
        out.append(base)
    return "".join(out)


def ascii_homoglyph_normalize(label):
    for a, b in _HOMOGLYPH_SUBS:
        label = label.replace(a, b)
    return label


def _tokens(label):
    return [t for t in re.split(r"[-_.\d]+", label) if t]


_QWERTY = ["1234567890-", "qwertyuiop", "asdfghjkl", "zxcvbnm"]


@lru_cache(maxsize=None)
def _adjacent(ch):
    for r, row in enumerate(_QWERTY):
        c = row.find(ch)
        if c < 0:
            continue
        out = set()
        for dr in (-1, 0, 1):
            rr = r + dr
            if 0 <= rr < len(_QWERTY):
                for dc in (-1, 0, 1):
                    cc = c + dc
                    if (dr or dc) and 0 <= cc < len(_QWERTY[rr]):
                        out.add(_QWERTY[rr][cc])
        return out
    return set()


def typo_variants(kw):
    """Realistic typo variants of a keyword (dnstwist-style), excluding the keyword itself."""
    out = set()
    for i in range(len(kw)):
        out.add(kw[:i] + kw[i + 1:])                       # omission
        out.add(kw[:i] + kw[i] + kw[i:])                   # repetition
        if i < len(kw) - 1:
            out.add(kw[:i] + kw[i + 1] + kw[i] + kw[i + 2:])  # transposition
        if i:
            out.add(kw[:i] + "-" + kw[i:])                 # hyphenation
        for a in _adjacent(kw[i]):
            out.add(kw[:i] + a + kw[i + 1:])               # adjacent-key replacement
            out.add(kw[:i] + a + kw[i:])                   # adjacent-key insertion
        if kw[i] in "aeiou":
            out.update(kw[:i] + v + kw[i + 1:] for v in "aeiou")  # vowel swap
        for bit in range(7):                               # bitsquatting
            c = chr(ord(kw[i]) ^ (1 << bit))
            if c.isascii() and (c.isalnum() or c == "-") and c.lower() == c:
                out.add(kw[:i] + c + kw[i + 1:])
    out.discard(kw)
    return out


@lru_cache(maxsize=None)
def _typo_index():
    idx = {}
    for b in data.brands():
        for kw in b["keywords"]:
            if len(kw) >= 5:
                for v in typo_variants(kw):
                    idx.setdefault(v, (b, kw))
    return idx


def brand_matches(label, registered, subdomain=""):
    """Yield (kind, brand, keyword) for every brand impersonation pattern found in the host."""
    if registered in data.brand_domains():
        return
    norm = ascii_homoglyph_normalize(label)          # 0->o, 1->l, rn->m, ...
    tokens = set(_tokens(label)) | set(_tokens(norm))
    sub_tokens = set(_tokens(subdomain.replace(".", "-")))
    typo = _typo_index().get(label) or _typo_index().get(norm)
    for b in data.brands():
        for kw in b["keywords"]:
            if label == kw:
                yield "tld-swap", b, kw
            elif len(kw) >= 5 and norm == kw:
                yield "homoglyph", b, kw
            elif typo and typo[0] is b:
                yield "typosquat", b, kw
            elif kw in tokens:
                yield "combosquat", b, kw
            elif len(kw) >= 6 and (kw in label or kw in norm):
                yield "embedded", b, kw
            elif kw in sub_tokens or (len(kw) >= 6 and kw in subdomain):
                yield "subdomain", b, kw
            else:
                continue
            break


@check("lexical", "URL structure", passive=True)
def run(ctx):
    s = Section()
    url, host = ctx.url, ctx.host
    unicode_host = ctx.host_unicode
    label, registered, suffix, subdomain = ctx.domain_label, ctx.registered_domain, ctx.suffix, ctx.subdomain
    lists = data.lists()

    is_ip = False
    try:
        ipaddress.ip_address(host.strip("[]"))
        is_ip = True
    except ValueError:
        pass

    s.data.update({
        "length": len(url),
        "host": host,
        "host_unicode": unicode_host,
        "registered_domain": registered,
        "subdomain": subdomain,
        "suffix": suffix,
        "subdomain_depth": len(subdomain.split(".")) if subdomain else 0,
        "label_entropy": round(shannon_entropy(label), 2),
        "is_ip": is_ip,
        "is_idn": unicode_host != host,
        "trusted": ctx.trusted,
    })

    if is_ip:
        s.flag("lexical.ip_host", "URL uses a raw IP address instead of a domain", "high", weight=0.35,
               evidence=host, fix="Legitimate services almost always use a domain name.")
    if ctx.parts.username or "@" in ctx.parts.netloc:
        s.flag("lexical.userinfo", "URL hides its real host behind an '@' (userinfo trick)", "high", weight=0.4,
               evidence=ctx.parts.netloc, fix="Everything before '@' is ignored by the browser; the real host follows it.")
    if ctx.parts.port and ctx.parts.port not in (80, 443):
        s.flag("lexical.port", f"Non-standard port {ctx.parts.port}", "low", weight=0.1, evidence=ctx.parts.netloc)
    if len(url) > 150:
        s.flag("lexical.long", f"Very long URL ({len(url)} chars)", "low", weight=0.08)
    elif len(url) > 90:
        s.flag("lexical.long", f"Long URL ({len(url)} chars)", "info", weight=0.03)
    if s.data["subdomain_depth"] >= 4:
        s.flag("lexical.deep_subdomain", f"Deeply nested subdomain ({s.data['subdomain_depth']} levels)", "low",
               weight=0.1, evidence=subdomain)
    if not is_ip and label.count("-") >= 2:
        s.flag("lexical.hyphens", "Many hyphens in the domain name", "low", weight=0.07, evidence=label)
    if not is_ip and len(label) >= 12 and shannon_entropy(label) >= 3.7 and sum(c.isdigit() for c in label) >= 2:
        s.flag("lexical.dga", "Domain looks algorithmically generated (high entropy)", "medium", weight=0.18,
               evidence=f"{label} (entropy {shannon_entropy(label):.2f})")

    pct = len(re.findall(r"%[0-9a-fA-F]{2}", url))
    if pct >= 10 and pct * 3 > len(url) * 0.15:
        s.flag("lexical.encoded", "Heavy percent-encoding (obfuscated URL)", "low", weight=0.1, evidence=f"{pct} encoded bytes")
    if "//" in ctx.parts.path[1:]:
        s.flag("lexical.double_slash", "Double slash inside the path (redirect trick)", "low", weight=0.05,
               evidence=ctx.parts.path[:120])

    # --- IDN / homograph ---------------------------------------------------------------
    if unicode_host != host:
        per_label = [{_script_of(c) for c in lbl} - _COMMON_SCRIPTS for lbl in unicode_host.split(".")[:-1]]
        scripts = set().union(*per_label) if per_label else set()
        s.data["scripts"] = sorted(scripts)
        if any(len(sc) > 1 for sc in per_label):
            s.flag("lexical.mixed_script", "Domain mixes alphabets (IDN homograph attack)", "high", weight=0.45,
                   evidence=f"{unicode_host} uses {', '.join(sorted(scripts))}",
                   fix="Look-alike letters from other alphabets are used to imitate a real domain.")
        skel = skeleton(unicode_host)
        s.data["skeleton"] = skel
        skel_sub, skel_label, skel_suffix, skel_reg = split_host(skel)
        owned = data.brand_domains()
        target = owned.get(skel_reg)
        if not target:
            for kind, b, kw in brand_matches(skel_label, skel_reg, skel_sub):
                if kind in ("tld-swap", "homoglyph", "typosquat"):
                    target = b["brand"]
                    break
        if target and registered not in owned:
            s.flag("lexical.homograph", f"Homograph of {target}", "critical", weight=0.65,
                   evidence=f"{unicode_host} renders like {skel}",
                   fix="This domain is visually identical to a well-known brand but is not owned by it.")
        elif not scripts - {"LATIN"} and skel != unicode_host:
            s.flag("lexical.idn", "Internationalised (IDN) domain", "info", evidence=unicode_host)

    # --- brand impersonation ------------------------------------------------------------
    if not is_ip:
        weights = {"homoglyph": (0.55, "critical", "Look-alike spelling of {b}"),
                   "typosquat": (0.45, "high", "Typosquat of {b}"),
                   "combosquat": (0.4, "high", "Brand name '{k}' combined with other words"),
                   "embedded": (0.25, "medium", "Brand name '{k}' embedded in the domain"),
                   "subdomain": (0.45, "high", "Brand name '{k}' used in a subdomain of an unrelated site"),
                   "tld-swap": (0.3, "medium", "{b}'s name on a domain it does not own")}
        seen = set()
        matches = []
        for kind, b, kw in brand_matches(label, registered, subdomain):
            if b["brand"] in seen:
                continue
            seen.add(b["brand"])
            w, sev, title = weights[kind]
            if kind == "tld-swap" and len(suffix.rsplit(".", 1)[-1]) == 2:
                w, sev = 0.12, "low"  # could be a regional site of the brand (ccTLD)
            matches.append({"brand": b["brand"], "kind": kind, "keyword": kw})
            s.flag(f"lexical.brand.{kind}", title.format(b=b["brand"], k=kw), sev, weight=w,
                   evidence=f"{host} vs {', '.join(b['domains'][:3])}",
                   fix=f"Official {b['brand']} domains: {', '.join(b['domains'][:4])}.")
        s.data["brand_matches"] = matches
        if not matches and registered not in data.brand_domains():
            path_l = unquote(ctx.parts.path + "?" + ctx.parts.query).lower()
            for b in data.brands():
                hit = next((d for d in b["domains"][:3] if d in path_l), None)
                if hit:
                    s.flag("lexical.brand.path", f"{b['brand']} domain appears in the path of an unrelated site",
                           "medium", weight=0.2, evidence=hit)
                    break

    # --- reputation-style lists ---------------------------------------------------------
    tld = suffix.rsplit(".", 1)[-1] if suffix else ""
    if tld in lists["suspicious_tlds"]:
        s.flag("lexical.tld", f"TLD '.{tld}' is heavily abused for phishing/malware", "low", weight=0.08, evidence=tld)
    if registered in lists["shorteners"] or host in lists["shorteners"]:
        s.flag("lexical.shortener", "URL shortener hides the real destination", "low", weight=0.12,
               evidence=host, fix="See the redirect chain for where it really goes.")
    for fh in lists["free_hosting"]:
        if host == fh or host.endswith("." + fh):
            s.flag("lexical.free_hosting", f"Hosted on a free/abusable platform ({fh})", "low", weight=0.12,
                   evidence=host, fix="Anyone can publish here in minutes; phishing kits commonly do.")
            break

    text = unquote(f"{host}{ctx.parts.path}?{ctx.parts.query}").lower()
    kws = sorted({k for k in lists["phish_keywords"] if re.search(rf"(?<![a-z]){re.escape(k)}(?![a-z])", text)})
    s.data["keywords"] = kws
    if kws:
        s.flag("lexical.keywords", f"Phishing-bait keywords in URL ({len(kws)})", "low",
               weight=min(0.05 * len(kws), 0.2), evidence=", ".join(kws[:8]))
    return s
