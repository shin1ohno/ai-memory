#!/usr/bin/env python3
"""Decide whether a failed Claude agent step is worth retrying later.

Runs right after the agent step of a claude-*.yml workflow, only when that step failed. It
reads the two files run_claude_sandboxed.sh leaves behind — claude's stdout (the
--output-format json result) and claude's stderr — and prints exactly one line:

  retryable <reason>   a subscription usage limit, a rate limit, or an overloaded API.
                       The failure handler labels the item agent:waiting-quota and
                       claude-requeue.yml starts the run again later.
  fatal <reason>       anything else. The failure handler hands the item to a human, as
                       it did before retries existed.

  classify_failure.py --result .agent-out/claude-result.json \
                      --stderr .agent-out/claude-stderr.log [--github-output "$GITHUB_OUTPUT"]

With --github-output it also appends `retry=true` or `retry=false` to that file.

Retryable means a case-insensitive match of one of RETRY_PATTERNS in the result JSON (its
`result` field and every other string in it) or in stderr. Numbers in the JSON are never
matched: a `duration_api_ms` of 529 is not an overloaded API.

Fatal wins over a pattern match in two cases, because a retry would fail the same way or
the limit text is not about this run:
  - subtype `error_max_turns`: the agent ran out of turns; another run would too.
  - `is_error` false: claude finished normally, so the step failed for some other reason
    (the sandbox timeout, a missing tool). The result text is the agent's own summary and
    may well mention rate limits in the code it was working on.
A missing or empty result file with nothing matching in stderr is fatal too.

UNVERIFIED: the subscription usage-limit wording has never been observed live in this
pilot. The patterns are a guess from wording Claude Code has printed in other contexts
("usage limit reached", "You've hit your limit", "out of extra usage"). Update them from
the first real occurrence — run_claude_sandboxed.sh prints the tail of claude's stderr to
the step log whenever the agent step fails. Anything unrecognised is classified fatal on
purpose: an unknown failure goes to a human rather than into an hourly retry loop.

Exit 0 whenever a verdict was printed; 4 on a usage error or an unwritable --github-output.
"""

from __future__ import annotations

import argparse
import json
import re
import sys

# Case-insensitive. The bare status codes are word-bounded so that "1429" or "5290" in a log
# line does not count; numbers inside the result JSON are not searched at all.
RETRY_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (label, re.compile(rx, re.IGNORECASE))
    for label, rx in [
        ("usage limit", r"usage limit"),
        ("limit reached", r"limit reached"),
        ("hit your limit", r"hit your limit"),
        ("out of extra usage", r"out of extra usage"),
        ("out of usage", r"out of usage"),
        ("rate_limit_error", r"rate_limit_error"),
        ("rate limit", r"rate limit"),
        ("429", r"\b429\b"),
        ("overloaded", r"overloaded"),
        ("529", r"\b529\b"),
    ]
]


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:  # argparse would exit 2; the contract says 4
        self.print_usage(sys.stderr)
        print(f"{self.prog}: error: {message}", file=sys.stderr)
        sys.exit(4)


def _read(path: str) -> str:
    """The file's text, or "" when it is missing or unreadable (both mean "no signal")."""
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return ""


def _strings(value) -> list[str]:
    """Every string value in a parsed JSON document; keys and numbers are left out."""
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [s for v in value.values() for s in _strings(v)]
    if isinstance(value, list):
        return [s for v in value for s in _strings(v)]
    return []


def _match(text: str) -> str | None:
    for label, rx in RETRY_PATTERNS:
        if rx.search(text):
            return label
    return None


def classify(result_text: str, stderr_text: str) -> tuple[bool, str]:
    """(retryable, reason) for one failed agent step."""
    haystack = ""
    if result_text.strip():
        try:
            data = json.loads(result_text)
        except json.JSONDecodeError:
            # Not JSON (claude died mid-write, or printed plain text): search it as it is.
            data = None
            haystack = result_text
        if isinstance(data, dict):
            if data.get("subtype") == "error_max_turns":
                return False, "the agent hit its turn limit (error_max_turns)"
            if data.get("is_error") is False:
                return False, "claude finished without an error (is_error false); the step failed for another reason"
        if data is not None:
            # The `result` field is one of these strings; the others cover an error object
            # that some claude version might put elsewhere in the document.
            haystack = "\n".join(_strings(data))
        label = _match(haystack)
        if label:
            return True, f"'{label}' in the result JSON"
    label = _match(stderr_text)
    if label:
        return True, f"'{label}' in claude's stderr"
    if not result_text.strip():
        return False, "no result JSON and no usage or rate limit in stderr"
    return False, "no usage or rate limit in the result JSON or stderr"


def main(argv: list[str]) -> int:
    ap = _Parser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--result", required=True, help="claude's --output-format json stdout")
    ap.add_argument("--stderr", required=True, help="claude's stderr")
    ap.add_argument("--github-output", help="append retry=true|false to this file")
    args = ap.parse_args(argv)

    retryable, reason = classify(_read(args.result), _read(args.stderr))
    # One line, whatever the reason contains.
    print(f"{'retryable' if retryable else 'fatal'} {' '.join(reason.split())}")
    if args.github_output:
        try:
            with open(args.github_output, "a", encoding="utf-8") as fh:
                fh.write(f"retry={'true' if retryable else 'false'}\n")
        except OSError as exc:
            print(f"cannot append to --github-output: {exc}", file=sys.stderr)
            return 4
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
