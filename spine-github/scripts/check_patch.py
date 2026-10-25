#!/usr/bin/env python3
"""Refuse an agent patch before it is committed anywhere.

The agent runs with no GitHub credentials; its output reaches the repository only through
the publish job, and this check is the publish job's gate. It is the equivalent of gh-aw's
`protected-files: blocked` plus `allowed-files`, applied to the change the patch actually
makes:

  * no file under a protected path — the default list in protected_paths.py (workflows,
    the agent's own instructions, attributes and submodules, package manifests, the
    pilot's scripts) and the repository's own `.github/agent-protected.txt`, read from the
    base commit. A deletion or a rename counts against both of its paths: the input is
    `git diff --no-renames --raw`, which lists a rename as its deletion and its addition;
  * no symlink (120000) and no submodule (160000) entry: either can point the tree at
    content no allowed_paths check can see;
  * no added path that collides, case-folded, with a path already in the base tree or with
    another added path;
  * when the envelope lists allowed_paths, every changed file matches one of them
    (same glob semantics as pr_guard.py: `*` stops at `/`, `**` crosses it);
  * at most MAX_FILES files.

An agent patch gets no exception to `.github/agent-protected.txt`. The one exception (D3)
belongs to the L4 import, which runs no agent: import_verify.py passes d3_allows() and
grades through grade() in this module.

  check_patch.py --raw-file diff.raw [--base-files base.txt]
                 [--agent-protected-file list.txt] [--protected-required true]
                 [--envelope envelope.json] [--max-files 100]
  check_patch.py --files-file changed.txt [--envelope envelope.json]     # names only

--raw-file is `git diff --cached --no-renames --raw --no-abbrev -z HEAD`; --base-files is
`git ls-tree -r -z --name-only --full-tree HEAD`. --protected-required true (the variable
AGENT_PROTECTED_REQUIRED) refuses every patch when no --agent-protected-file is given.

Exit 0 clean, 1 refused (reasons on stdout, one per line), 4 usage error.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import dataclass
from typing import Callable

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from protected_paths import PROTECTED, matches_any, matches_folded, parse_agent_protected  # noqa: E402

LINK_MODES = {"120000", "160000"}


@dataclass(frozen=True)
class Entry:
    old_mode: str
    new_mode: str
    old_oid: str
    new_oid: str
    status: str
    path: str


def parse_raw(data: bytes) -> list[Entry]:
    """Parse `git diff --raw -z --no-renames` output: ':<meta>\\0<path>\\0' per entry."""
    fields = data.split(b"\0")
    out: list[Entry] = []
    i = 0
    while i < len(fields):
        meta = fields[i].decode("utf-8", "surrogateescape")
        if not meta:
            i += 1
            continue
        parts = meta.lstrip(":").split()
        if not meta.startswith(":") or len(parts) != 5 or i + 1 >= len(fields):
            raise ValueError(f"not a --raw -z record: {meta[:80]!r}")
        if parts[4][:1] in ("R", "C"):
            raise ValueError("rename or copy record: the diff must be taken with --no-renames")
        path = fields[i + 1].decode("utf-8", "surrogateescape")
        out.append(Entry(parts[0], parts[1], parts[2], parts[3], parts[4], path))
        i += 2
    return out


def names_only(paths: list[str]) -> list[Entry]:
    """The legacy input: a list of names, graded without modes, OIDs or statuses."""
    return [Entry("?", "?", "", "", "M", p) for p in paths]


def d3_allows(
    entry: Entry,
    *,
    agent_protected: list[str],
    base_paths: set[str],
    source_pin: str,
    protected_pins: set[str],
    expected: dict[str, tuple[str, str]],
) -> bool:
    """The import exception to `.github/agent-protected.txt` (D3). All four must hold:

    the path is on the repository's list (the default PROTECTED never gets one), the base
    has no such path, `repo@sha` is in IMPORT_PROTECTED_PINS, and (mode, OID) equal the
    source entry. Only a plain addition qualifies: a deletion, a rename (a deletion plus an
    addition here) and a mode change are refused whatever the pins say.
    """
    folded_base = {p.casefold() for p in base_paths}
    return (
        entry.status == "A"
        and entry.old_mode == "000000"
        and matches_folded(entry.path, agent_protected)
        and entry.path.casefold() not in folded_base
        and source_pin in protected_pins
        and expected.get(entry.path) == (entry.new_mode, entry.new_oid)
    )


def grade(
    entries: list[Entry],
    *,
    allowed: list[str],
    agent_protected: list[str] | None,
    protected_required: bool = False,
    base_paths: set[str] | None = None,
    max_files: int = 100,
    exception: Callable[[Entry], bool] | None = None,
) -> list[str]:
    reasons: list[str] = []
    if agent_protected is None and protected_required:
        reasons.append(".github/agent-protected.txt is missing from the base and AGENT_PROTECTED_REQUIRED is true")
    extra = agent_protected or []
    if not entries:
        reasons.append("the patch changes no files")
    paths = sorted({e.path for e in entries})
    if len(paths) > max_files:
        reasons.append(f"the patch changes {len(paths)} files, more than the limit of {max_files}")

    base = base_paths or set()
    base_folded: dict[str, str] = {}
    for p in base:
        base_folded.setdefault(p.casefold(), p)
    added_folded: dict[str, str] = {}

    for e in entries:
        if e.new_mode in LINK_MODES:
            kind = "symlink" if e.new_mode == "120000" else "submodule"
            reasons.append(f"{kind} entry ({e.new_mode}): {e.path}")
        if matches_folded(e.path, PROTECTED):
            reasons.append(f"protected path: {e.path}")
        elif extra and matches_folded(e.path, extra):
            if exception is None or not exception(e):
                reasons.append(f"protected path (.github/agent-protected.txt): {e.path}")
        elif allowed and not matches_any(e.path, allowed):
            reasons.append(f"outside allowed_paths: {e.path}")
        if e.status == "A":
            key = e.path.casefold()
            other = base_folded.get(key)
            if other is not None and other != e.path:
                reasons.append(f"added path collides case-folded with {other}: {e.path}")
            twin = added_folded.setdefault(key, e.path)
            if twin != e.path:
                reasons.append(f"added paths collide case-folded: {twin} and {e.path}")
    return reasons


def read_list(path: str) -> list[str]:
    data = open(path, "rb").read()
    sep = b"\0" if b"\0" in data else b"\n"
    return [p.decode("utf-8", "surrogateescape").strip() for p in data.split(sep) if p.strip()]


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--raw-file", help="`git diff --cached --no-renames --raw --no-abbrev -z HEAD` output")
    src.add_argument("--files-file", help="newline-separated changed paths (names only)")
    ap.add_argument("--base-files", help="paths in the base tree, NUL- or newline-separated")
    ap.add_argument("--agent-protected-file", help="the base commit's .github/agent-protected.txt")
    ap.add_argument("--protected-required", default="", help="'true' refuses the patch when the list is absent")
    ap.add_argument("--envelope", help="envelope.json; its allowed_paths bound the patch")
    ap.add_argument("--max-files", type=int, default=100)
    args = ap.parse_args(argv)

    try:
        if args.raw_file:
            entries = parse_raw(open(args.raw_file, "rb").read())
        else:
            entries = names_only(read_list(args.files_file))
        base = set(read_list(args.base_files)) if args.base_files else set()
        agent_protected = None
        if args.agent_protected_file:
            agent_protected = parse_agent_protected(open(args.agent_protected_file, encoding="utf-8").read())
        allowed: list[str] = []
        if args.envelope:
            allowed = json.load(open(args.envelope, encoding="utf-8")).get("allowed_paths") or []
    except (OSError, ValueError) as exc:
        print(f"cannot read input: {exc}", file=sys.stderr)
        return 4

    reasons = grade(
        entries,
        allowed=allowed,
        agent_protected=agent_protected,
        protected_required=args.protected_required == "true",
        base_paths=base,
        max_files=args.max_files,
    )
    listed = "absent" if agent_protected is None else f"{len(agent_protected)} path(s)"
    print(
        f"changed files: {len({e.path for e in entries})}; allowed_paths: {allowed or '(repository default)'}; "
        f"agent-protected.txt: {listed}"
    )
    if reasons:
        print(f"REFUSED ({len(reasons)}):")
        for r in reasons:
            print(f"  - {r}")
        return 1
    print("OK: patch may be published")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
