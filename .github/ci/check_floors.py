#!/usr/bin/env python3
"""Fail when a suite ran fewer cases than its floor.

  check_floors.py <make-test.log>      floors come from $SUITE_FLOORS (set in ci.yml)

$SUITE_FLOORS is JSON: {"<suite as named on its === RUN line>": {"pass": N, "max_skip": S}}.
Each named suite must have run, printed its `---- pass=N fail=F [skip=S]` summary, and
reported fail == 0, pass >= N and skip <= S, with exactly one summary. A suite emptied to `print("---- pass=0")`, a
deleted suite and a suite turned into skips all fail here, because `make test` alone only
sees exit codes.
"""

import json
import os
import re
import sys

RUN = re.compile(r"^=== RUN (.+)$")
SUMMARY = re.compile(r"^---- pass=(\d+) fail=(\d+)(?: skip=(\d+))?\s*$")


def summaries(lines):
    found, current = {}, None
    for line in lines:
        m = RUN.match(line)
        if m:
            current = m.group(1).strip()
            continue
        m = SUMMARY.match(line)
        if m and current is not None:
            found.setdefault(current, []).append((int(m.group(1)), int(m.group(2)), int(m.group(3) or 0)))
    return found


def main():
    floors = json.loads(os.environ["SUITE_FLOORS"])
    with open(sys.argv[1], encoding="utf-8", errors="replace") as f:
        found = summaries(f.read().splitlines())
    bad = 0
    for suite, floor in floors.items():
        if suite not in found:
            print(f"FAIL  {suite}: no `---- pass=` summary after its === RUN line")
            bad += 1
            continue
        if len(found[suite]) != 1:
            print(f"FAIL  {suite}: {len(found[suite])} summaries after one === RUN line, expected 1")
            bad += 1
            continue
        passed, failed, skipped = found[suite][0]
        ok = failed == 0 and passed >= floor["pass"] and skipped <= floor.get("max_skip", 0)
        print(f"{'PASS' if ok else 'FAIL'}  {suite}: pass={passed} fail={failed} skip={skipped}"
              f" (floor pass>={floor['pass']}, skip<={floor.get('max_skip', 0)})")
        bad += not ok
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
