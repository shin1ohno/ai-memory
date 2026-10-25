#!/usr/bin/env python3
"""Increment a round counter inside a pull request body's agent-envelope block.

The round caps are only real if something deterministic increments the counter, and the
agent job cannot: its token is read-only by design. This script is that something. It is
deliberately narrow — it rewrites exactly one line and touches nothing else, so it cannot
disagree with the block that `envelope-guard` regenerates from the source issue.

  bump_rounds.py --body-file pr.md --counter ci_fix_rounds --out pr.new.md

Exit codes
  0  incremented; the new body is on stdout (or at --out) and the new value on stderr
  3  no agent-envelope block, or the counter line is missing from it
  4  usage / IO error
  9  the cap is already reached — nothing written. This is the expected exit for the
     "hand it back to a human" path, so callers must distinguish it from a real error.
"""

from __future__ import annotations

import argparse
import re
import sys

BLOCK_RE = re.compile(
    r"(?P<open><!--\s*agent-envelope:v1\s*-->)(?P<inner>.*?)(?P<close><!--\s*/agent-envelope\s*-->)",
    re.S,
)
CAP_FOR = {
    "ci_fix_rounds": "max_ci_fix_rounds",
    "ai_review_rounds": "max_ai_review_rounds",
}
DEFAULT_CAP = {"ci_fix_rounds": 2, "ai_review_rounds": 1}


def read_int(inner: str, name: str) -> int | None:
    m = re.search(rf"^(?P<indent>[ \t]*){name}[ \t]*:[ \t]*(?P<value>\d+)[ \t]*$", inner, re.M)
    return int(m.group("value")) if m else None


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--body-file", required=True, help="current PR body, or - for stdin")
    ap.add_argument("--counter", default="ci_fix_rounds", choices=sorted(CAP_FOR))
    ap.add_argument("--out", help="write the new body here instead of stdout")
    ap.add_argument(
        "--cap",
        type=int,
        help="override the cap. Default: the block's max_* field, else the blueprint constant "
        "(ci_fix_rounds 2, ai_review_rounds 1). A task may lower a cap, never raise it.",
    )
    args = ap.parse_args(argv)

    try:
        body = sys.stdin.read() if args.body_file == "-" else open(args.body_file, encoding="utf-8").read()
    except OSError as exc:
        print(f"cannot read body: {exc}", file=sys.stderr)
        return 4

    m = BLOCK_RE.search(body)
    if not m:
        print("no agent-envelope block in the body", file=sys.stderr)
        return 3
    inner = m.group("inner")

    current = read_int(inner, args.counter)
    if current is None:
        print(f"the block has no {args.counter} line", file=sys.stderr)
        return 3

    blueprint_cap = DEFAULT_CAP[args.counter]
    declared = read_int(inner, CAP_FOR[args.counter])
    cap = args.cap if args.cap is not None else (declared if declared is not None else blueprint_cap)
    # A task may lower a cap, never raise it above the blueprint constant.
    cap = min(cap, blueprint_cap)

    if current >= cap:
        print(f"{args.counter}={current} already at cap {cap}; not incrementing", file=sys.stderr)
        return 9

    new_value = current + 1
    new_inner = re.sub(
        rf"^(?P<indent>[ \t]*){args.counter}[ \t]*:[ \t]*\d+[ \t]*$",
        lambda mm: f"{mm.group('indent')}{args.counter}: {new_value}",
        inner,
        count=1,
        flags=re.M,
    )
    new_body = body[: m.start()] + m.group("open") + new_inner + m.group("close") + body[m.end() :]

    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(new_body)
    else:
        sys.stdout.write(new_body)
    print(f"{args.counter}: {current} -> {new_value} (cap {cap})", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
