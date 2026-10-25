#!/usr/bin/env python3
"""Parse a human-authored task body into a canonical Task Envelope, validate it, and emit.

The same parser serves both spines, because both front doors produce heading-sectioned
markdown:

  * GitHub issue forms render each field as `### <label>` followed by the value.
  * A Linear issue description written from the template uses the same `### <label>`
    sections, so the Linear spine feeds this script the issue description verbatim.

Exit codes
  0  envelope is valid; requested artifact written to stdout
  2  envelope parsed but failed validation (errors on stderr, one per line)
  3  body could not be parsed at all (no recognisable sections)
  4  usage / IO error

Validation uses `jsonschema` when it is importable, and otherwise a built-in evaluator
covering the subset of JSON Schema the envelope actually uses. The schema file is the
single source of truth in both paths: no field list is duplicated in this script.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from typing import Any

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_SCHEMA = os.path.join(HERE, os.pardir, "schemas", "task-envelope.schema.json")

# Heading label (lower-cased, punctuation-stripped) -> envelope field.
# Keep both the terse and the verbose spellings so the GitHub issue form and the
# Linear template can use reader-friendly labels without forking the parser.
FIELD_ALIASES = {
    "title": "title",
    "summary": "title",
    "risk tier": "risk_tier",
    "risk": "risk_tier",
    "engine": "engine",
    "profile": "profile",
    "service": "profile",
    "goal": "goal",
    "goal and why": "goal",
    "non goals": "non_goals",
    "out of scope": "non_goals",
    "acceptance criteria": "acceptance_criteria",
    "allowed paths": "allowed_paths",
    "test command": "test_command",
    "source url": "source_url",
    "design note": "source_url",
    "design note url": "source_url",
    "context refs": "context_refs",
    "context": "context_refs",
    "rollback": "rollback",
    "max ci fix rounds": "max_ci_fix_rounds",
    "max ai credits": "max_ai_credits",
    "task id": "task_id",
    "import from": "import_from",
}

LIST_FIELDS = {"non_goals", "acceptance_criteria", "allowed_paths", "context_refs"}
INT_FIELDS = {"max_ci_fix_rounds", "max_ai_credits"}

# GitHub issue forms write this literal into an untouched optional field.
NO_RESPONSE = "_no response_"

SECTION_RE = re.compile(r"^\s{0,3}#{2,4}\s+(?P<label>.+?)\s*$")
BULLET_RE = re.compile(r"^\s*(?:[-*+]|\d+[.)])\s+(?P<item>.+?)\s*$")
CHECKBOX_RE = re.compile(r"^\s*\[(?P<mark>[ xX])\]\s*")
# CommonMark backslash escapes. Linear normalises a stored description and escapes
# characters it would otherwise render — `services/**` comes back as `services/\*\*` — so
# an unescaped value must be recovered before it is used as a glob or a command.
MD_ESCAPE_RE = re.compile(r"\\([!-/:-@\[-`{-~])")


def unescape_markdown(text: str) -> str:
    return MD_ESCAPE_RE.sub(r"\1", text)


def normalise_label(label: str) -> str:
    label = re.sub(r"[`*_:]+", " ", label)
    label = re.sub(r"\(.*?\)", " ", label)
    label = re.sub(r"[^A-Za-z0-9 ]+", " ", label)
    return re.sub(r"\s+", " ", label).strip().lower()


def split_sections(body: str) -> dict[str, str]:
    """Return {normalised heading: raw text} preserving first occurrence only."""
    sections: dict[str, str] = {}
    current: str | None = None
    buf: list[str] = []
    for raw_line in body.replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        m = SECTION_RE.match(raw_line)
        if m:
            if current is not None and current not in sections:
                sections[current] = "\n".join(buf).strip()
            current = normalise_label(m.group("label"))
            buf = []
            continue
        if current is not None:
            buf.append(raw_line)
    if current is not None and current not in sections:
        sections[current] = "\n".join(buf).strip()
    return sections


def parse_list(text: str) -> list[str]:
    items: list[str] = []
    for line in text.split("\n"):
        line = line.strip()
        if not line or line.lower() == NO_RESPONSE:
            continue
        m = BULLET_RE.match(line)
        item = m.group("item") if m else line
        item = CHECKBOX_RE.sub("", item).strip()
        item = unescape_markdown(item.strip("`").strip())
        if item:
            items.append(item)
    return items


def parse_scalar(text: str) -> str:
    # Dropdowns and single-line inputs may arrive fenced or back-ticked.
    text = text.strip()
    if text.lower() == NO_RESPONSE:
        return ""
    fence = re.match(r"^```[a-zA-Z0-9]*\n(?P<inner>.*?)\n?```$", text, re.S)
    if fence:
        text = fence.group("inner").strip()
    if text.count("`") >= 2 and "\n" not in text:
        text = text.strip("`").strip()
    return unescape_markdown(text)


IMPORT_KEY_RE = re.compile(r"^(?P<key>repo|ref)\s*:\s*(?P<value>\S+)$", re.I)


def parse_import(text: str) -> dict[str, Any] | None:
    """Read an `Import from` section: `repo: OWNER/NAME`, `ref: <sha>`, then `from -> to` lines.

    A line that is none of these is kept under `unparsed`, which the schema refuses, so a
    typo fails validation instead of silently dropping a file from the import.
    """
    text = text.strip()
    fence = re.match(r"^```[a-zA-Z0-9]*\n(?P<inner>.*?)\n?```$", text, re.S)
    if fence:
        text = fence.group("inner")
    spec: dict[str, Any] = {}
    mapping: list[dict[str, str]] = []
    unparsed: list[str] = []
    for line in text.split("\n"):
        line = line.strip()
        if not line or line.lower() == NO_RESPONSE:
            continue
        m = BULLET_RE.match(line)
        line = unescape_markdown(m.group("item") if m else line)
        kv = IMPORT_KEY_RE.match(line.replace("`", ""))
        if kv:
            spec[kv.group("key").lower()] = kv.group("value")
        elif "->" in line:
            src, dst = (part.strip().strip("`").strip() for part in line.split("->", 1))
            mapping.append({"from": src, "to": dst})
        else:
            unparsed.append(line)
    if not spec and not mapping and not unparsed:
        return None
    spec["map"] = mapping
    if unparsed:
        spec["unparsed"] = unparsed
    return spec


def parse_body(body: str, *, task_id: str | None) -> tuple[dict[str, Any], list[str]]:
    # Strip any canonical block this script appended on an earlier run. The validation
    # workflow re-parses on every `issues: edited` event, and the block sits after the
    # last heading — without this, the block would be absorbed into that heading's value
    # and grow on each edit.
    body = CANON_RE.sub("", body)
    sections = split_sections(body)
    if not sections:
        raise SystemExit(3)
    notes: list[str] = []
    env: dict[str, Any] = {"envelope_version": 1, "blueprint": "implement-v1"}
    for label, text in sections.items():
        field = FIELD_ALIASES.get(label)
        if field is None:
            notes.append(f"ignored unmapped section: {label}")
            continue
        if field == "import_from":
            value: Any = parse_import(text)
            if value is None:
                continue
        elif field in LIST_FIELDS:
            value = parse_list(text)
            if not value:
                continue
        else:
            scalar = parse_scalar(text)
            if scalar == "":
                continue
            if field in INT_FIELDS:
                digits = re.sub(r"[^0-9-]", "", scalar.split()[0])
                if digits in ("", "-"):
                    notes.append(f"{field}: not an integer, dropped: {scalar!r}")
                    continue
                value = int(digits)
            elif field == "risk_tier":
                value = scalar.split()[0].upper()
            elif field == "engine":
                value = scalar.split()[0].strip().lower()
            elif field == "source_url":
                m = re.search(r"https://\S+", scalar)
                value = m.group(0).rstrip(").,>") if m else scalar
            else:
                value = scalar
        env[field] = value
    if task_id:
        env["task_id"] = task_id
    return env, notes


# --------------------------------------------------------------------------- #
# Minimal JSON Schema evaluator (used when the jsonschema package is absent).
# Supports exactly the keywords the envelope schema uses.
# --------------------------------------------------------------------------- #

TYPES = {
    "object": dict,
    "array": list,
    "string": str,
    "integer": int,
    "number": (int, float),
    "boolean": bool,
}


def _type_ok(value: Any, expected: str) -> bool:
    if expected == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if expected == "boolean":
        return isinstance(value, bool)
    py = TYPES.get(expected)
    return isinstance(value, py) if py else True


def validate_subset(instance: Any, schema: dict[str, Any], path: str = "") -> list[str]:
    errors: list[str] = []
    where = path or "(root)"

    if "const" in schema and instance != schema["const"]:
        errors.append(f"{where}: must be {schema['const']!r}, got {instance!r}")
    if "enum" in schema and instance not in schema["enum"]:
        errors.append(f"{where}: must be one of {schema['enum']}, got {instance!r}")
    if "type" in schema:
        expected = schema["type"]
        options = expected if isinstance(expected, list) else [expected]
        if not any(_type_ok(instance, t) for t in options):
            errors.append(f"{where}: must be {expected}, got {type(instance).__name__}")
            return errors

    if isinstance(instance, str):
        if "minLength" in schema and len(instance) < schema["minLength"]:
            errors.append(f"{where}: shorter than {schema['minLength']} characters")
        if "maxLength" in schema and len(instance) > schema["maxLength"]:
            errors.append(f"{where}: longer than {schema['maxLength']} characters")
        if "pattern" in schema and not re.search(schema["pattern"], instance):
            errors.append(f"{where}: does not match {schema['pattern']}")

    if isinstance(instance, int) and not isinstance(instance, bool):
        if "minimum" in schema and instance < schema["minimum"]:
            errors.append(f"{where}: below minimum {schema['minimum']}")
        if "maximum" in schema and instance > schema["maximum"]:
            errors.append(f"{where}: above maximum {schema['maximum']}")

    if isinstance(instance, list):
        if "minItems" in schema and len(instance) < schema["minItems"]:
            errors.append(f"{where}: needs at least {schema['minItems']} item(s)")
        if "items" in schema:
            for i, item in enumerate(instance):
                errors += validate_subset(item, schema["items"], f"{where}[{i}]")

    if isinstance(instance, dict):
        for key in schema.get("required", []):
            if key not in instance:
                errors.append(f"{where}: missing required field '{key}'")
        props = schema.get("properties", {})
        if schema.get("additionalProperties") is False:
            for key in instance:
                if key not in props:
                    errors.append(f"{where}: unknown field '{key}'")
        for key, subschema in props.items():
            if key in instance:
                child = f"{where}.{key}" if path else key
                errors += validate_subset(instance[key], subschema, child)

    for sub in schema.get("allOf", []):
        errors += validate_subset(instance, sub, path)

    if "if" in schema:
        if not validate_subset(instance, schema["if"], path):
            if "then" in schema:
                errors += validate_subset(instance, schema["then"], path)
        elif "else" in schema:
            errors += validate_subset(instance, schema["else"], path)

    return errors


def validate(env: dict[str, Any], schema: dict[str, Any]) -> list[str]:
    try:
        import jsonschema  # type: ignore
    except ImportError:
        errors = validate_subset(env, schema)
    else:
        validator = jsonschema.Draft202012Validator(schema)
        errors = [
            f"{'.'.join(str(p) for p in e.absolute_path) or '(root)'}: {e.message}"
            for e in sorted(validator.iter_errors(env), key=lambda e: list(e.absolute_path))
        ]
    if "import_from" in env:
        # The path grammar is more than a pattern can say; import_verify.py owns it, so the
        # issue is marked invalid here rather than refused later by the import job.
        sys.path.insert(0, HERE)
        from import_verify import grammar_errors

        errors += grammar_errors(env["import_from"])
    return errors


# --------------------------------------------------------------------------- #
# Emitters
# --------------------------------------------------------------------------- #

PR_BLOCK_FIELDS = [
    "envelope_version",
    "task_id",
    "blueprint",
    "engine",
    "risk_tier",
    "profile",
    "source_url",
    "allowed_paths",
    "test_command",
    "max_ci_fix_rounds",
]


PR_BLOCK_OPEN = "<!-- agent-envelope:v1 -->"
PR_BLOCK_CLOSE = "<!-- /agent-envelope -->"
PR_BLOCK_RE = re.compile(
    re.escape(PR_BLOCK_OPEN) + r"(?P<inner>.*?)" + re.escape(PR_BLOCK_CLOSE) + r"\n?",
    re.S,
)

# A Linear-mirrored task gets its own marked section, outside the envelope block so no
# block parser (pr_guard, bump_rounds, metrics) sees an extra line. The closing magic word
# lets Linear's GitHub integration link the PR to the Linear issue and move that issue on
# merge. GitHub reads `GH-<n>` as its own issue reference and would close issue #<n> on
# merge, so a Linear team keyed `GH` is never linked this way.
LINEAR_OPEN = "<!-- agent-linear -->"
LINEAR_CLOSE = "<!-- /agent-linear -->"
_LINEAR_ID = r"[A-Z][A-Z0-9]{0,9}-[1-9][0-9]{0,8}"
LINEAR_ID_RE = re.compile(rf"^(?!GH-){_LINEAR_ID}$")
# Only the section linear_section() writes is removed: its exact three lines, directly above
# the envelope block where pr_body_with_block puts it. A description that mentions the
# marker, or quotes the whole section in a code fence, keeps its text and its `Fixes #<issue>`.
LINEAR_RE = re.compile(
    rf"^{re.escape(LINEAR_OPEN)}\r?\nFixes {_LINEAR_ID}\r?\n{re.escape(LINEAR_CLOSE)}[ \t]*"
    rf"(?:\r?\n[ \t]*)*(?={re.escape(PR_BLOCK_OPEN)})",
    re.M,
)
# linear-intake creates each mirror issue with GITHUB_TOKEN and writes this marker on a line of
# its own (the first, until someone edits the body). REST and gh's --json name that author
# differently.
MIRROR_MARKER_RE = re.compile(r"^[ \t]*<!-- linear-mirror:(?P<id>\S+) -->[ \t]*\r?$", re.M)
MIRROR_AUTHORS = {"github-actions[bot]", "app/github-actions"}


def linear_id_for_issue(issue: dict[str, Any]) -> tuple[str | None, str]:
    """Return (Linear ID, "") for a mirror issue, or (None, why not; "" if not a mirror).

    The ID is read from the marker line of an issue the Actions bot created; editing that body
    takes write access. A `linear:<ID>` label is not used: triage rights are enough to swap
    one, and anyone can paste the marker into an issue of their own. A pull request is never a
    mirror, even one the bot opened, because its description is agent-written.
    """
    ids = {m.group("id") for m in MIRROR_MARKER_RE.finditer(issue.get("body") or "")}
    if not ids:
        return None, ""
    if "pull_request" in issue:
        return None, "the source is a pull request, not a mirror issue"
    author = ((issue.get("user") or issue.get("author") or {}).get("login") or "")
    if author not in MIRROR_AUTHORS:
        return None, "the issue carries a linear-mirror marker but was not created by linear-intake"
    if len(ids) != 1:
        return None, "the issue carries more than one linear-mirror marker"
    ident = ids.pop()
    if not LINEAR_ID_RE.match(ident):
        return None, "the linear-mirror marker holds no linkable Linear identifier (GH-<n> is also a GitHub issue reference)"
    return ident, ""


def existing_counters(body: str) -> tuple[int, int]:
    """Read ci_fix_rounds / ai_review_rounds out of a PR body's existing block.

    The CI-fix and review-address nodes increment these in place. Anything that rewrites
    the block (the sync job on every `synchronize` event) must carry them forward, or the
    round caps become unenforceable and first_ci_pass_rate reads as 100%.
    """
    m = PR_BLOCK_RE.search(body or "")
    if not m:
        return 0, 0

    def read(name: str) -> int:
        hit = re.search(rf"^\s*{name}\s*:\s*(\d+)\s*$", m.group("inner"), re.M)
        return int(hit.group(1)) if hit else 0

    return read("ci_fix_rounds"), read("ai_review_rounds")


def pr_body_with_block(
    body: str,
    env: dict[str, Any],
    *,
    ci_fix_rounds: int | None = None,
    ai_review_rounds: int | None = None,
    linear_id: str | None = None,
) -> str:
    """Return the PR body with the agent-envelope block replaced or appended.

    With `linear_id`, the Linear section is replaced or added just above the block; without
    it, any existing Linear section is removed, so the body always matches the source issue.
    """
    keep_ci, keep_ai = existing_counters(body)
    block = pr_block(
        env,
        ci_fix_rounds=keep_ci if ci_fix_rounds is None else ci_fix_rounds,
        ai_review_rounds=keep_ai if ai_review_rounds is None else ai_review_rounds,
    )
    # The Linear section first: it is recognised by the block that follows it.
    stripped = PR_BLOCK_RE.sub("", LINEAR_RE.sub("", body or "")).rstrip()
    if linear_id:
        return f"{stripped}\n\n{linear_section(linear_id)}\n\n{block}\n"
    return f"{stripped}\n\n{block}\n"


def linear_section(linear_id: str) -> str:
    if not LINEAR_ID_RE.match(linear_id):
        raise ValueError(f"not a Linear issue identifier: {linear_id!r}")
    return f"{LINEAR_OPEN}\nFixes {linear_id}\n{LINEAR_CLOSE}"


def pr_block(env: dict[str, Any], *, ci_fix_rounds: int = 0, ai_review_rounds: int = 0) -> str:
    """Render the PR-body block. Field names here are a contract: metrics.sh parses them."""
    lines = ["<!-- agent-envelope:v1 -->", "```yaml"]
    for key in PR_BLOCK_FIELDS:
        if key not in env:
            continue
        value = env[key]
        if isinstance(value, list):
            value = ",".join(str(v) for v in value)
        lines.append(f"{key}: {value}")
    lines.append(f"ci_fix_rounds: {ci_fix_rounds}")
    lines.append(f"ai_review_rounds: {ai_review_rounds}")
    lines.append("```")
    lines.append("<!-- /agent-envelope -->")
    return "\n".join(lines)


def labels_for(env: dict[str, Any]) -> list[str]:
    return [
        f"agent:{env['engine']}",
        f"risk:{env['risk_tier']}",
        f"blueprint:{env['blueprint']}",
    ]


CANON_OPEN = "<!-- task-envelope:v1 -->"
CANON_CLOSE = "<!-- /task-envelope -->"
CANON_RE = re.compile(
    re.escape(CANON_OPEN) + r".*?" + re.escape(CANON_CLOSE) + r"\n?",
    re.S,
)


def issue_body_with_canonical(body: str, env: dict[str, Any]) -> str:
    """Return the issue body with the canonical envelope block replaced or appended.

    The block is what every later node reads, so the human-facing sections above it can
    be reworded without changing what the agent receives. Re-running on an already
    annotated body replaces the block rather than stacking a second one.
    """
    block = "\n".join(
        [
            CANON_OPEN,
            "<details><summary>Canonical task envelope (generated — do not edit by hand)</summary>",
            "",
            "```json",
            json.dumps(env, indent=2, sort_keys=True),
            "```",
            "",
            "</details>",
            CANON_CLOSE,
        ]
    )
    stripped = CANON_RE.sub("", body).rstrip()
    return f"{stripped}\n\n{block}\n"


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--body-file", help="path to the issue body markdown, or - for stdin")
    src.add_argument("--envelope-file", help="skip parsing; validate an existing envelope JSON")
    ap.add_argument("--task-id", help="override task_id (gh-<number> or LINEAR-KEY)")
    ap.add_argument("--schema", default=DEFAULT_SCHEMA)
    ap.add_argument(
        "--emit",
        default="json",
        choices=["json", "pr-block", "labels", "issue-body", "pr-body", "none"],
        help="what to print on success",
    )
    ap.add_argument("--out", help="also write the canonical envelope JSON to this path")
    ap.add_argument(
        "--existing-file",
        help="current PR body, for --emit pr-body: the block is replaced in place and the "
        "ci_fix_rounds / ai_review_rounds counters are carried forward",
    )
    link = ap.add_mutually_exclusive_group()
    link.add_argument(
        "--linear-id",
        help="for --emit pr-body: the Linear issue this task mirrors (e.g. ENG-123); adds a "
        "`Fixes <ID>` section for Linear's GitHub integration. Omitted: any such section is removed",
    )
    link.add_argument(
        "--issue-json",
        help="for --emit pr-body: the source issue as the REST API returns it; the Linear ID is "
        "taken from it only if linear-intake created it (see linear_id_for_issue)",
    )
    ap.add_argument("--quiet", action="store_true", help="suppress parse notes on stderr")
    args = ap.parse_args(argv)
    linear_id = args.linear_id
    if linear_id is not None and not LINEAR_ID_RE.match(linear_id):
        print(f"--linear-id is not a linkable Linear issue identifier: {linear_id!r}", file=sys.stderr)
        return 4
    if args.issue_json:
        try:
            with open(args.issue_json, encoding="utf-8") as fh:
                issue = json.load(fh)
        except (OSError, json.JSONDecodeError) as exc:
            print(f"cannot read issue JSON: {exc}", file=sys.stderr)
            return 4
        linear_id, why_not = linear_id_for_issue(issue)
        if why_not:
            print(f"not linking the PR to Linear: {why_not}", file=sys.stderr)

    try:
        with open(args.schema, encoding="utf-8") as fh:
            schema = json.load(fh)
    except OSError as exc:
        print(f"cannot read schema: {exc}", file=sys.stderr)
        return 4

    notes: list[str] = []
    if args.envelope_file:
        try:
            with open(args.envelope_file, encoding="utf-8") as fh:
                env = json.load(fh)
        except (OSError, json.JSONDecodeError) as exc:
            print(f"cannot read envelope: {exc}", file=sys.stderr)
            return 3
    else:
        try:
            if args.body_file == "-":
                body = sys.stdin.read()
            else:
                with open(args.body_file, encoding="utf-8") as fh:
                    body = fh.read()
        except OSError as exc:
            print(f"cannot read body: {exc}", file=sys.stderr)
            return 4
        try:
            env, notes = parse_body(body, task_id=args.task_id)
        except SystemExit:
            print("no recognisable '### heading' sections in body", file=sys.stderr)
            return 3

    if not args.quiet:
        for note in notes:
            print(f"note: {note}", file=sys.stderr)

    errors = validate(env, schema)
    if errors:
        print(f"envelope invalid ({len(errors)} error(s)):", file=sys.stderr)
        for err in errors:
            print(f"  - {err}", file=sys.stderr)
        return 2

    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            json.dump(env, fh, indent=2, sort_keys=True)
            fh.write("\n")

    if args.emit == "json":
        print(json.dumps(env, indent=2, sort_keys=True))
    elif args.emit == "pr-block":
        print(pr_block(env))
    elif args.emit == "labels":
        print("\n".join(labels_for(env)))
    elif args.emit == "pr-body":
        existing = ""
        if args.existing_file:
            try:
                with open(args.existing_file, encoding="utf-8") as fh:
                    existing = fh.read()
            except OSError as exc:
                print(f"cannot read existing PR body: {exc}", file=sys.stderr)
                return 4
        print(pr_body_with_block(existing, env, linear_id=linear_id), end="")
    elif args.emit == "issue-body":
        if args.envelope_file:
            print("--emit issue-body requires --body-file", file=sys.stderr)
            return 4
        print(issue_body_with_canonical(body, env), end="")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
