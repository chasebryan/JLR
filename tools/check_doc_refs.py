#!/usr/bin/env python3
"""Fails if a document cites a test (or other function) by name that does not exist in the source.

Documents make claims and back them with test names. A renamed or deleted test must not leave a claim pointing at nothing.
Any backticked snake_case identifier of 25 or more characters in README.md or docs/*.md is treated as a reference.
"""
import glob
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
src = "".join(p.read_text() for p in ROOT.glob("crates/**/*.rs"))
fns = set(re.findall(r"fn\s+([a-z0-9_]+)\s*\(", src))
bad = []
count = 0
for doc in [ROOT / "README.md", *ROOT.glob("docs/*.md")]:
    for name in sorted(set(re.findall(r"`([a-z][a-z0-9_]{24,})`", doc.read_text()))):
        count += 1
        if name not in fns:
            bad.append((doc.relative_to(ROOT), name))
for d, n in bad:
    print(f"{d}: cites `{n}`, which is not a function in crates/", file=sys.stderr)
print(f"{count} references checked, {len(bad)} dangling")
sys.exit(1 if bad else 0)
