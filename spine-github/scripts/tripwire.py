#!/usr/bin/env python3
"""Refuse to publish agent-written text that looks like it carries a credential.

  tripwire.py [--patch change.patch] [TEXT_FILE ...]

Checks every line of each TEXT_FILE (the PR description, a comment, the replies) and every
line the patch adds. A line trips the wire when it holds `sk-ant-`, a run of 40 or more hex
digits, or a run of 40 or more base64 / base64url characters that mixes upper case, lower
case and digits (a file path is long too, but rarely mixes all three). Exit 1 on a hit, 0
otherwise; the hit is reported as file:line only, never the matched text.

This is a tripwire, not a defence: the same secret re-encoded another way passes. It exists
so the obvious leak — the agent pasting CLAUDE_CODE_OAUTH_TOKEN into its PR — stops at
publish and lands with a human. A 40-digit commit id trips it too; the cost of that false
positive is one human look.
"""

from __future__ import annotations

import argparse
import re
import sys

HEX = re.compile(r"[0-9A-Fa-f]{40,}")
B64 = re.compile(r"[A-Za-z0-9+/_-]{40,}")


def suspicious(line: str) -> bool:
    if "sk-ant-" in line or HEX.search(line):
        return True
    for m in B64.finditer(line):
        run = m.group(0)
        if re.search(r"[A-Z]", run) and re.search(r"[a-z]", run) and re.search(r"[0-9]", run):
            return True
    return False


def added_lines(patch: str):
    for n, line in enumerate(patch.splitlines(), 1):
        if line.startswith("+") and not line.startswith("+++"):
            yield n, line[1:]


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--patch")
    ap.add_argument("text", nargs="*")
    args = ap.parse_args(argv)
    hits: list[str] = []
    for path in args.text:
        with open(path, encoding="utf-8", errors="replace") as fh:
            for n, line in enumerate(fh, 1):
                if suspicious(line):
                    hits.append(f"{path}:{n}")
    if args.patch:
        with open(args.patch, encoding="utf-8", errors="replace") as fh:
            for n, line in added_lines(fh.read()):
                if suspicious(line):
                    hits.append(f"{args.patch}:{n}")
    for h in hits:
        print(f"::error::{h}: looks like a credential (long hex/base64 run or sk-ant-); not publishing")
    return 1 if hits else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
