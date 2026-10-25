#!/usr/bin/env python3
"""Find the pull requests a newly merged PR declares it reworks, and judge the 7-day window.

rework_rate_7d counts merged agent PRs that carry a `rework` label. This script is the
deterministic half of applying that label. Per the pilot's definition, only two signals
count, both explicit:

  * a revert — the body GitHub's Revert button writes (`Reverts owner/repo#N`, which may sit
    below a `## Description` heading rather than on the first line), or the commit message
    `git revert` writes (`This reverts commit <sha>.`);
  * a declared rework — a human writing `Reworks #N` in the PR body.

A bare `#N` mention, and any reference to another repository, is deliberately not a signal:
a silent fix in an unrelated PR is not counted, so the resulting rate is a lower bound.

Two modes:

  detect_rework.py refs --repo owner/repo --body-file body.md [--commits-file msgs.txt]
      prints one reference per line: `pr <N> <kind>` or `sha <sha> <kind>`,
      kind = revert | rework; duplicates collapsed, PR references first

  detect_rework.py within --target-merged <ISO> --rework-merged <ISO> [--days 7]
      exit 0 if the rework merged after the target and within the window, else exit 1;
      prints the elapsed hours
"""

from __future__ import annotations

import argparse
import re
import sys
from datetime import datetime, timedelta

SHA_RE = re.compile(r"\bThis reverts commit ([0-9a-f]{7,40})\b", re.I)


def pr_refs(text: str, repo: str) -> list[tuple[int, str]]:
    """Return [(number, kind)] for same-repository revert / rework references."""
    owner_repo = re.escape(repo)
    # `Reverts owner/repo#N` or `Reverts #N`; `Reworks` likewise. A different owner/repo
    # is refused by requiring either nothing or exactly this repository before the `#`.
    pattern = re.compile(
        rf"\b(?P<verb>Reverts|Reworks)\s+(?:(?P<repo>[\w.-]+/[\w.-]+))?#(?P<num>\d+)\b",
        re.I,
    )
    found: list[tuple[int, str]] = []
    for m in pattern.finditer(text or ""):
        ref_repo = m.group("repo")
        if ref_repo and not re.fullmatch(owner_repo, ref_repo, re.I):
            continue
        kind = "revert" if m.group("verb").lower() == "reverts" else "rework"
        found.append((int(m.group("num")), kind))
    return found


def sha_refs(text: str) -> list[str]:
    return [m.group(1).lower() for m in SHA_RE.finditer(text or "")]


def cmd_refs(args: argparse.Namespace) -> int:
    try:
        body = open(args.body_file, encoding="utf-8").read()
        commits = open(args.commits_file, encoding="utf-8").read() if args.commits_file else ""
    except OSError as exc:
        print(f"cannot read input: {exc}", file=sys.stderr)
        return 4
    seen: set[tuple[str, str]] = set()
    lines: list[str] = []
    for number, kind in pr_refs(body, args.repo) + pr_refs(commits, args.repo):
        key = ("pr", str(number))
        if key not in seen:
            seen.add(key)
            lines.append(f"pr {number} {kind}")
    for sha in sha_refs(body) + sha_refs(commits):
        key = ("sha", sha)
        if key not in seen:
            seen.add(key)
            lines.append(f"sha {sha} revert")
    if lines:
        print("\n".join(lines))
    return 0


def parse_time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def cmd_within(args: argparse.Namespace) -> int:
    try:
        target = parse_time(args.target_merged)
        rework = parse_time(args.rework_merged)
    except ValueError as exc:
        print(f"unparseable timestamp: {exc}", file=sys.stderr)
        return 4
    elapsed = rework - target
    hours = elapsed.total_seconds() / 3600
    print(f"{hours:.1f}")
    if elapsed < timedelta(0):
        print("the rework merged before its target: not a rework of it", file=sys.stderr)
        return 1
    return 0 if elapsed <= timedelta(days=args.days) else 1


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("refs")
    r.add_argument("--repo", required=True)
    r.add_argument("--body-file", required=True)
    r.add_argument("--commits-file")
    w = sub.add_parser("within")
    w.add_argument("--target-merged", required=True)
    w.add_argument("--rework-merged", required=True)
    w.add_argument("--days", type=int, default=7)
    args = ap.parse_args(argv)
    return cmd_refs(args) if args.cmd == "refs" else cmd_within(args)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
