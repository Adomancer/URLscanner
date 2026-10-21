#!/usr/bin/env python3
"""Turn a Tranco (or similar) ranked CSV into scanner/data/top_domains.txt.

Download a list yourself (e.g. from https://tranco-list.eu/) and run:
    python tools/build_top_domains.py tranco.csv 10000

CSV format expected: "rank,domain" per line (Tranco's default). This is a build-time helper.
"""
import csv
import os
import sys

OUT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                   "scanner", "data", "top_domains.txt")


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    path = sys.argv[1]
    limit = int(sys.argv[2]) if len(sys.argv) > 2 else 10000
    domains = []
    with open(path, encoding="utf-8", errors="replace", newline="") as f:
        for parts in csv.reader(f):
            if not parts:
                continue
            domain = (parts[1] if len(parts) > 1 else parts[0]).strip().lower()
            if domain and "." in domain:
                domains.append(domain)
            if len(domains) >= limit:
                break
    with open(OUT, "w", encoding="utf-8") as f:
        f.write("# Generated from " + os.path.basename(path) + f" (top {len(domains)}).\n")
        f.write("\n".join(domains) + "\n")
    print(f"Wrote {len(domains)} domains -> {OUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
