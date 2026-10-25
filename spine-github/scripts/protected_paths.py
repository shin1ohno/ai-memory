#!/usr/bin/env python3
"""The paths no agent patch may touch, and the glob semantics every gate shares.

Three gates read these lists: check_patch.py (publish, before anything is committed),
import_verify.py (the L4 import, which runs no agent at all) and pr_guard.py (the merge gate).
Keeping them in one module is what makes "the same path is protected everywhere" true.

  * PROTECTED is the default list, the same in every repository. Nothing opens an exception
    to it, not even an import.
  * `.github/agent-protected.txt`, read from the base commit, adds a repository's own
    paths. An import may add a file there only under the four D3 conditions
    (check_patch.d3_allows); an agent patch never may.
  * IMPORT_TO_FORBIDDEN is stricter again for the destination of an import.

Glob semantics mirror gh-aw's create-pull-request allowed-files: `*` matches any
characters except `/`, `**` matches any characters including `/`. Protected matching also
compares case-folded, because a checkout on a case-insensitive file system turns
`.GitHub/workflows/x.yml` into `.github/workflows/x.yml`.
"""

from __future__ import annotations

import re
import subprocess

PROTECTED = [
    ".github/**",
    "AGENTS.md",
    "**/AGENTS.md",
    "CLAUDE.md",
    "**/CLAUDE.md",
    ".claude/**",
    "spine-github/**",
    "spine-linear/**",
    # attributes and submodules decide how content is checked out (filters, eol, gitlinks),
    # so a patch that adds one changes files no allowed_paths check can see
    ".gitattributes",
    "**/.gitattributes",
    ".gitmodules",
    # the import and agent work areas: nothing a patch writes may land there
    ".agent-import/**",
    ".agent-out/**",
    # package manifests and lock files: a dependency change is a human decision
    "package.json", "**/package.json", "package-lock.json", "**/package-lock.json",
    "pnpm-lock.yaml", "**/pnpm-lock.yaml", "yarn.lock", "**/yarn.lock",
    "go.mod", "**/go.mod", "go.sum", "**/go.sum",
    "Cargo.toml", "**/Cargo.toml", "Cargo.lock", "**/Cargo.lock",
    "pyproject.toml", "**/pyproject.toml", "requirements*.txt", "**/requirements*.txt",
    "Gemfile", "**/Gemfile", "Gemfile.lock", "**/Gemfile.lock",
]

# An import never writes these, whatever the pins say: the Makefile is the CI definition
# (`make test` is the required check), so importing one would let a source repository
# rewrite what the target's CI runs.
IMPORT_TO_FORBIDDEN = PROTECTED + ["Makefile", "**/Makefile"]

AGENT_PROTECTED_FILE = ".github/agent-protected.txt"


def glob_to_regex(pattern: str) -> re.Pattern[str]:
    """Translate a glob to a regex with gh-aw's allowed-files semantics."""
    out: list[str] = ["^"]
    i = 0
    while i < len(pattern):
        ch = pattern[i]
        if ch == "*":
            if pattern[i : i + 2] == "**":
                out.append(".*")
                i += 2
                continue
            out.append("[^/]*")
        elif ch == "?":
            out.append("[^/]")
        else:
            out.append(re.escape(ch))
        i += 1
    out.append("$")
    return re.compile("".join(out))


def matches_any(path: str, patterns: list[str]) -> bool:
    return any(glob_to_regex(p).match(path) for p in patterns)


def matches_folded(path: str, patterns: list[str]) -> bool:
    """matches_any, and the same again with both sides case-folded."""
    if matches_any(path, patterns):
        return True
    folded = path.casefold()
    return any(glob_to_regex(p.casefold()).match(folded) for p in patterns)


def parse_agent_protected(text: str) -> list[str]:
    """One path or glob per line; blank lines and `#` comments are ignored."""
    out: list[str] = []
    for line in text.splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            out.append(line)
    return out


def read_agent_protected(repo_dir: str, rev: str = "HEAD") -> list[str] | None:
    """The list at <rev>:.github/agent-protected.txt, or None when the file is absent.

    Read from a commit, never from the working tree: the tree may already carry the patch
    being graded, and a patch that edits the list must be graded by the list before it.
    """
    proc = subprocess.run(
        ["git", "-C", repo_dir, "show", f"{rev}:{AGENT_PROTECTED_FILE}"],
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        return None
    return parse_agent_protected(proc.stdout)
