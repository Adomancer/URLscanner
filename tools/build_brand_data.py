#!/usr/bin/env python3
"""Build scanner/data/favicon_hashes.json by fetching each brand's real favicon once.

Run occasionally to refresh the reference set:  python tools/build_brand_data.py
This is a build-time helper; it is never called during a scan.
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanner import data, net          # noqa: E402
from scanner.utils import favicon_hash  # noqa: E402

OUT = os.path.join(data.DATA_DIR, "favicon_hashes.json")


def main():
    result = {}
    for b in data.brands():
        hashes = set()
        for domain in b["domains"][:3]:
            for url in (f"https://{domain}/favicon.ico", f"https://www.{domain}/favicon.ico"):
                try:
                    r = net.safe_fetch(url, max_bytes=300_000, timeout=8, max_redirects=3)
                    if r.status == 200 and r.body and not r.is_html:
                        hashes.add(favicon_hash(r.body))
                except Exception as e:
                    print(f"  ! {url}: {str(e)[:70]}")
        if hashes:
            result[b["brand"]] = sorted(hashes)
            print(f"{b['brand']:24} {sorted(hashes)}")
    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2)
    print(f"\nWrote {len(result)} brands -> {OUT}")


if __name__ == "__main__":
    main()
