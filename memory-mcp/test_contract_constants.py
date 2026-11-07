#!/usr/bin/env python3
"""The file-memory mirror hook and the server's policy gate share three
constants that today are kept in sync only by a comment (identity.py:209-212,
"the two sides must change together"). If either side changes alone, the hook
keeps sending notes the server refuses, or `--check` misreads the denial text,
or a tool gains dataset scoping on one side without the other.

This suite reads both source files as text (the hook is Ruby; it is never
imported) and asserts the pairs still agree:

  - hook MAX_CHARS                              <-> identity.RESTRICTED_INGEST_MAX_CHARS
  - the "policy_denied:" prefix hook's           <-> identity.POLICY_DENIED_MESSAGE
    expect_denied matches
  - the tools the hook calls with a `dataset`   <-> identity.DATASET_SCOPED_TOOLS
    argument (ingest, forget)

Dependency-free: identity.py imports only the standard library, and the hook
is read as plain text, so this runs on a bare python3 (CI) with no venv.

Usage: python3 test_contract_constants.py
"""

from __future__ import annotations

import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)

IDENTITY_REL = "memory-mcp/identity.py"
HOOK_REL = "hooks/mirror-file-memory.rb"
HOOK_PATH = os.path.join(REPO_ROOT, "hooks", "mirror-file-memory.rb")

import identity  # noqa: E402  (stdlib-only; safe to import directly)

with open(HOOK_PATH, encoding="utf-8") as fh:
    HOOK_SRC = fh.read()

PASS = 0
FAIL = 0


def check(name, condition, detail=""):
    global PASS, FAIL
    if condition:
        PASS += 1
        print(f"ok   {name}")
    else:
        FAIL += 1
        print(f"FAIL {name} :: {detail}")


# --------------------------------------------------------------------------- #
# Extract what the hook actually says, from its source text.
# --------------------------------------------------------------------------- #
def hook_max_chars() -> int:
    m = re.search(r"^MAX_CHARS\s*=\s*([\d_]+)", HOOK_SRC, re.MULTILINE)
    if not m:
        raise SystemExit(f"{HOOK_REL}: no `MAX_CHARS = <number>` found")
    return int(m.group(1).replace("_", ""))


def hook_denied_prefix() -> str:
    m = re.search(r'e\.text\.start_with\?\("([^"]+)"\)', HOOK_SRC)
    if not m:
        raise SystemExit(f"{HOOK_REL}: expect_denied's `e.text.start_with?(\"...\")` not found")
    return m.group(1)


def hook_dataset_scoped_tools() -> set:
    """Tool names the hook calls (`client.call("<tool>", { ... })`) whose
    argument hash includes a `"dataset"` key — the hook's own notion of which
    tools are dataset-scoped."""
    tools = set()
    for m in re.finditer(r'client\.call\(\s*"(\w+)"\s*,\s*\{([\s\S]*?)\}\s*\)', HOOK_SRC):
        tool, body = m.group(1), m.group(2)
        if '"dataset"' in body:
            tools.add(tool)
    if not tools:
        raise SystemExit(f"{HOOK_REL}: no `client.call(\"...\", {{ ... \"dataset\" ... }})` found")
    return tools


# --------------------------------------------------------------------------- #
# 1. MAX_CHARS <-> RESTRICTED_INGEST_MAX_CHARS
# --------------------------------------------------------------------------- #
def test_max_chars():
    hook_val = hook_max_chars()
    server_val = identity.RESTRICTED_INGEST_MAX_CHARS
    check(
        "hook MAX_CHARS equals identity.RESTRICTED_INGEST_MAX_CHARS",
        hook_val == server_val,
        f"{HOOK_REL}: MAX_CHARS = {hook_val} != {IDENTITY_REL}: "
        f"RESTRICTED_INGEST_MAX_CHARS = {server_val}",
    )


# --------------------------------------------------------------------------- #
# 2. the "policy_denied:" prefix <-> POLICY_DENIED_MESSAGE
# --------------------------------------------------------------------------- #
def test_denied_prefix():
    prefix = hook_denied_prefix()
    check(
        "identity.POLICY_DENIED_MESSAGE starts with the exact prefix "
        "the hook's expect_denied matches",
        identity.POLICY_DENIED_MESSAGE.startswith(prefix),
        f"{HOOK_REL}: expect_denied matches e.text.start_with?({prefix!r}) but "
        f"{IDENTITY_REL}: POLICY_DENIED_MESSAGE = {identity.POLICY_DENIED_MESSAGE!r} "
        "does not start with it",
    )


# --------------------------------------------------------------------------- #
# 3. hook's dataset-scoped calls <-> DATASET_SCOPED_TOOLS
# --------------------------------------------------------------------------- #
def test_dataset_scoped_tools():
    hook_tools = hook_dataset_scoped_tools()
    missing = sorted(hook_tools - identity.DATASET_SCOPED_TOOLS)
    check(
        "every tool the hook calls with a `dataset` argument is in "
        "identity.DATASET_SCOPED_TOOLS",
        not missing,
        f"{HOOK_REL} calls {sorted(hook_tools)} with a dataset argument, but "
        f"{IDENTITY_REL}: DATASET_SCOPED_TOOLS = {sorted(identity.DATASET_SCOPED_TOOLS)} "
        f"is missing {missing}",
    )


test_max_chars()
test_denied_prefix()
test_dataset_scoped_tools()

print(f"---- pass={PASS} fail={FAIL}")
sys.exit(1 if FAIL else 0)
