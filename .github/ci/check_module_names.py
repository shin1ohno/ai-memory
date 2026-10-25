#!/usr/bin/env python3
"""Fail when a deployed module name collides with the stdlib or an installed distribution.

  <venv>/bin/python check_module_names.py <MANIFEST|file.py>...

The units run with their install directory first on sys.path, so a MANIFEST entry
named like a stdlib module or a dependency's top-level package (jwt.py, httpx.py)
silently replaces it (IMPORT-14). Run once per venv the host uses; the distributions
checked are the ones importable by the interpreter running this script.
"""

import importlib.metadata
import os
import sys


def manifest_modules(path):
    if path.endswith(".py"):
        return {os.path.basename(path)[:-3]}
    mods = set()
    with open(path, encoding="utf-8") as f:
        for raw in f:
            line = raw.strip()
            if line and not line.startswith("#") and "/" not in line and line.endswith(".py"):
                mods.add(line[:-3])
    return mods


def top_level_names():
    names = {}
    for dist in importlib.metadata.distributions():
        dname = dist.metadata["Name"]
        tops = set()
        text = dist.read_text("top_level.txt")
        if text:
            tops.update(t.strip() for t in text.splitlines() if t.strip())
        for f in dist.files or ():
            first = f.parts[0]
            if first in ("..", "__pycache__") or first.endswith((".dist-info", ".egg-info", ".pth", ".data")):
                continue
            tops.add(first[:-3] if first.endswith(".py") else first.split(".")[0])
        for t in tops:
            names.setdefault(t, set()).add(dname)
    return names


def main():
    mods = {}
    for p in sys.argv[1:]:
        for m in manifest_modules(p):
            mods.setdefault(m, set()).add(p)
    tops = top_level_names()
    bad = 0
    for m in sorted(mods):
        hits = []
        if m in sys.stdlib_module_names:
            hits.append("stdlib")
        hits += sorted(f"distribution {d}" for d in tops.get(m, ()))
        if hits:
            print(f"FAIL  {m} ({', '.join(sorted(mods[m]))}) shadows {', '.join(hits)}")
            bad += 1
    print(f"{'FAIL' if bad else 'PASS'}  {len(mods)} module names vs {len(sys.stdlib_module_names)} stdlib"
          f" names and {len(tops)} top-level names in {sys.prefix}")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
