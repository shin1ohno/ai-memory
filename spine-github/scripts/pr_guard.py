#!/usr/bin/env python3
"""Deterministic gate on an agent-authored pull request. Runs as a required check.

It answers four questions that nothing else in the chain can answer:

  1. Does the PR carry a parsable `agent-envelope` block? Without it the pilot has no
     metrics and no audit trail, so a missing block fails the check rather than
     degrading quietly.
  2. Do the PR labels agree with the block? Labels are what the metrics query on, so a
     PR labelled agent:claude whose block says codex would silently corrupt the
     comparison.
  3. Is every changed file inside allowed_paths? gh-aw's own `allowed-files` is a static
     per-workflow list and accepts no expression, so a PER-TASK path restriction cannot
     be pushed into the runner — it has to be enforced here, against the real changed-file
     list, at the merge gate.
  4. Does a T3 PR name its design note?
  5. Does an agent PR stay off the protected paths? The default list (protected_paths.py)
     and the base commit's `.github/agent-protected.txt`, checked against both names of a
     renamed file (`status` and `previous_filename` from `pulls/<n>/files`). An L4 import
     PR may add files on the repository's list, and only add them: its body carries the
     marker import_verify.py wrote, naming the PR's current head and a source in
     IMPORT_PROTECTED_PINS. This is defence in depth behind publish, not the boundary:
     the boundary is the code owner's approval.

Glob semantics deliberately mirror gh-aw's create-pull-request allowed-files:
`*` matches any characters except `/`, `**` matches any characters including `/`.

Usage (see .github/workflows/envelope-guard.yml):
  pr_guard.py --pr-body-file body.md --changed-files-file files.txt \
              --labels "agent:claude,risk:T2,blueprint:implement-v1" \
              [--files-json files.jsonl --head-sha SHA --agent-protected-file LIST \
               --protected-required true --import-pins "$IMPORT_PROTECTED_PINS"]

--files-json holds one {filename, status, previous_filename} object per line; when it is
given, the changed-file list for rule 3 also comes from it, both names of a rename included.

Exit 0 clean, 1 one or more violations, 4 usage error.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from protected_paths import (  # noqa: E402  (same directory)
    AGENT_PROTECTED_FILE,
    PROTECTED,
    matches_any,
    matches_folded,
    parse_agent_protected,
)

BLOCK_RE = re.compile(
    r"<!--\s*agent-envelope:v1\s*-->(?P<inner>.*?)<!--\s*/agent-envelope\s*-->",
    re.S,
)
KV_RE = re.compile(r"^\s*(?P<key>[a-z_][a-z0-9_]*)\s*:\s*(?P<value>.*?)\s*$")

IMPORT_MARKER_RE = re.compile(r"<!-- agent-import-verified (\{.*?\}) -->")
LIST_KEYS = {"allowed_paths"}
INT_KEYS = {"envelope_version", "ci_fix_rounds", "ai_review_rounds", "max_ci_fix_rounds"}


def parse_block(body: str) -> dict[str, object] | None:
    m = BLOCK_RE.search(body or "")
    if not m:
        return None
    out: dict[str, object] = {}
    for line in m.group("inner").split("\n"):
        line = line.strip()
        if not line or line.startswith("```") or line.startswith("#"):
            continue
        kv = KV_RE.match(line)
        if not kv:
            continue
        key, raw = kv.group("key"), kv.group("value")
        if key in LIST_KEYS:
            out[key] = [p.strip() for p in raw.split(",") if p.strip()]
        elif key in INT_KEYS:
            try:
                out[key] = int(raw)
            except ValueError:
                out[key] = raw
        else:
            out[key] = raw
    return out


def read_files_json(text: str) -> list[dict[str, str]]:
    out = []
    for line in text.splitlines():
        line = line.strip()
        if line:
            obj = json.loads(line)
            out.append(
                {
                    "filename": str(obj.get("filename") or ""),
                    "status": str(obj.get("status") or ""),
                    "previous_filename": str(obj.get("previous_filename") or ""),
                }
            )
    return out


def import_source(body: str, head_sha: str, files: list[dict[str, str]]) -> str | None:
    """The `repo@sha` of a verified import PR, or None.

    The marker counts only while it names the PR's current head (a later push voids it) and
    every file is an addition.
    """
    hits = IMPORT_MARKER_RE.findall(body or "")
    if len(hits) != 1 or not head_sha:
        return None
    try:
        marker = json.loads(hits[0])
    except json.JSONDecodeError:
        return None
    if marker.get("head") != head_sha or not files or any(f["status"] != "added" for f in files):
        return None
    source = marker.get("source")
    return source if isinstance(source, str) else None


def protected_violations(
    files: list[dict[str, str]],
    *,
    agent_protected: list[str] | None,
    protected_required: bool,
    source: str | None,
    import_pins: set[str],
) -> list[str]:
    out: list[str] = []
    if agent_protected is None and protected_required:
        out.append(".github/agent-protected.txt is missing from the base and AGENT_PROTECTED_REQUIRED is true")
    extra = agent_protected or []
    for f in files:
        for path in filter(None, (f["filename"], f["previous_filename"])):
            if matches_folded(path, PROTECTED):
                out.append(f"agent PR touches a protected path: {path} ({f['status'] or 'changed'})")
            elif extra and matches_folded(path, extra):
                if source is None or source not in import_pins or f["status"] != "added":
                    out.append(
                        f"agent PR touches a path on {AGENT_PROTECTED_FILE}: {path} ({f['status'] or 'changed'})"
                    )
    return out


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--pr-body-file", required=True, help="file containing the PR body, or -")
    ap.add_argument("--changed-files-file", required=True, help="newline-separated changed paths, or -")
    ap.add_argument("--labels", default="", help="comma-separated PR label names")
    ap.add_argument(
        "--require-block",
        default="true",
        choices=["true", "false"],
        help="false lets a human-authored PR without a block pass (default true)",
    )
    ap.add_argument("--files-json", help="pulls/<n>/files as JSON lines: filename, status, previous_filename")
    ap.add_argument("--head-sha", default="", help="the PR's current head commit")
    ap.add_argument("--agent-protected-file", help="the base commit's .github/agent-protected.txt (may be absent)")
    ap.add_argument("--protected-required", default="", help="'true' fails an agent PR when that list is absent")
    ap.add_argument("--import-pins", default="", help="IMPORT_PROTECTED_PINS, one repo@sha per line")
    args = ap.parse_args(argv)

    def read(path: str) -> str:
        if path == "-":
            return sys.stdin.read()
        with open(path, encoding="utf-8") as fh:
            return fh.read()

    try:
        body = read(args.pr_body_file)
        changed = [line.strip() for line in read(args.changed_files_file).split("\n") if line.strip()]
        files = read_files_json(read(args.files_json)) if args.files_json else None
        agent_protected = None
        if args.agent_protected_file and os.path.exists(args.agent_protected_file):
            agent_protected = parse_agent_protected(read(args.agent_protected_file))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"cannot read input: {exc}", file=sys.stderr)
        return 4

    labels = [label.strip() for label in args.labels.split(",") if label.strip()]
    violations: list[str] = []
    if files is not None:
        changed = sorted({p for f in files for p in (f["filename"], f["previous_filename"]) if p})
    else:
        files = [{"filename": p, "status": "", "previous_filename": ""} for p in changed]

    # 5. an agent PR stays off the protected paths, whatever its block says
    if any(label.startswith("agent:") for label in labels):
        source = import_source(body, args.head_sha, files)
        pins = {line.strip() for line in args.import_pins.splitlines() if line.strip()}
        if source:
            print(f"import PR: verified marker for {source} at head {args.head_sha}")
        violations += protected_violations(
            files,
            agent_protected=agent_protected,
            protected_required=args.protected_required == "true",
            source=source,
            import_pins=pins,
        )
    env = parse_block(body)

    if env is None:
        if args.require_block == "true":
            print("FAIL: no agent-envelope block in the pull request body")
            print("      the block is what metrics.sh reads; add it or set require-block=false")
            return 1
        print("skip: no agent-envelope block and require-block=false")
        return 0

    print(f"envelope block: {len(env)} field(s) parsed")
    for key in ("task_id", "engine", "risk_tier", "blueprint"):
        if not env.get(key):
            violations.append(f"envelope block is missing '{key}'")
    if env.get("envelope_version") != 1:
        violations.append(f"envelope_version must be 1, block says {env.get('envelope_version')!r}")

    # 2. labels must agree with the block
    for key, prefix in (("engine", "agent:"), ("risk_tier", "risk:"), ("blueprint", "blueprint:")):
        value = env.get(key)
        if not value:
            continue
        expected = f"{prefix}{value}"
        present = [label for label in labels if label.startswith(prefix)]
        if expected not in present:
            violations.append(
                f"label {expected!r} missing (block says {key}={value!r}, labels present: {present or 'none'})"
            )
        extra = [label for label in present if label != expected]
        if extra:
            violations.append(f"conflicting label(s) {extra} for {key}={value!r}")

    # 3. changed files must stay inside allowed_paths
    allowed = env.get("allowed_paths") or []
    if isinstance(allowed, str):
        allowed = [p.strip() for p in allowed.split(",") if p.strip()]
    if env.get("risk_tier") == "T3" and not allowed:
        violations.append("risk_tier T3 requires a non-empty allowed_paths in the block")
    if allowed:
        outside = [path for path in changed if not matches_any(path, allowed)]
        print(f"allowed_paths: {allowed}")
        print(f"changed files: {len(changed)} ({len(outside)} outside the allowlist)")
        for path in outside:
            violations.append(f"changed file outside allowed_paths: {path}")
    else:
        print("allowed_paths: (empty — repository default applies, no per-task restriction)")

    # 4. T3 needs its design note on the PR too, not only on the source issue
    if env.get("risk_tier") == "T3":
        source = str(env.get("source_url") or "")
        if not source.startswith("https://"):
            violations.append("risk_tier T3 requires an https source_url in the block")

    # Round counters must not exceed the cap the envelope declared.
    cap = env.get("max_ci_fix_rounds", 2)
    rounds = env.get("ci_fix_rounds", 0)
    if isinstance(cap, int) and isinstance(rounds, int) and rounds > cap:
        violations.append(f"ci_fix_rounds={rounds} exceeds max_ci_fix_rounds={cap}")

    if violations:
        print(f"\nFAIL: {len(violations)} violation(s)")
        for v in violations:
            print(f"  - {v}")
        return 1
    print("\nOK: envelope block, labels, paths and tier rules all agree")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
