#!/usr/bin/env python3
"""Decide what happens after the AI review node, deterministically.

The reviewer agent only reads and comments. Whether its review earns an "address" round
is decided here, from two facts nobody can talk their way around:

  * how many inline review comments the agent actually emitted — counted from the
    agent output file (`$GH_AW_AGENT_OUTPUT`), not from the agent's own summary;
  * the `ai_review_rounds` counter in the PR body's agent-envelope block, which only
    `bump_rounds.py` increments and which caps at the blueprint constant (1).

  route_review.py --agent-output agent_output.json --pr-body-file pr.md --out pr.new.md

Prints exactly one decision line on stdout and exits accordingly:

  none                 exit 0   no inline comments; nothing to address
  address <engine> <n> exit 0   counter bumped to n in --out; dispatch agent-address-review-<engine>
  cap                  exit 9   round cap reached; hand the PR to a human
  error <reason>       exit 3   no envelope block / no usable engine / unreadable input
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
BUMP = os.path.join(HERE, "bump_rounds.py")
COMMENT_TYPE = "create_pull_request_review_comment"
ENGINES = {"claude", "codex"}


def count_inline_comments(agent_output: dict) -> int:
    items = agent_output.get("items") or []
    return sum(1 for item in items if isinstance(item, dict) and item.get("type") == COMMENT_TYPE)


def block_engine(body: str) -> str | None:
    m = re.search(
        r"<!--\s*agent-envelope:v1\s*-->.*?^\s*engine\s*:\s*([a-z]+)\s*$.*?<!--\s*/agent-envelope\s*-->",
        body,
        re.S | re.M,
    )
    return m.group(1) if m else None


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--agent-output", required=True)
    ap.add_argument("--pr-body-file", required=True)
    ap.add_argument("--out", required=True, help="where the bumped PR body is written")
    args = ap.parse_args(argv)

    try:
        with open(args.agent_output, encoding="utf-8") as fh:
            agent_output = json.load(fh)
        with open(args.pr_body_file, encoding="utf-8") as fh:
            body = fh.read()
    except (OSError, json.JSONDecodeError) as exc:
        print(f"error unreadable-input: {exc}")
        return 3

    comments = count_inline_comments(agent_output)
    print(f"inline review comments emitted: {comments}", file=sys.stderr)
    if comments == 0:
        print("none")
        return 0

    engine = block_engine(body)
    if engine not in ENGINES:
        print(f"error no-usable-engine: {engine!r}")
        return 3

    proc = subprocess.run(
        [sys.executable, BUMP, "--body-file", args.pr_body_file, "--counter", "ai_review_rounds", "--out", args.out],
        capture_output=True,
        text=True,
    )
    sys.stderr.write(proc.stderr)
    if proc.returncode == 9:
        print("cap")
        return 9
    if proc.returncode != 0:
        print(f"error bump-failed-{proc.returncode}")
        return 3

    with open(args.out, encoding="utf-8") as fh:
        m = re.search(r"^\s*ai_review_rounds\s*:\s*(\d+)\s*$", fh.read(), re.M)
    print(f"address {engine} {m.group(1) if m else '?'}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
