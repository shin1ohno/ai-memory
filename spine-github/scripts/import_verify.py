#!/usr/bin/env python3
"""Build and verify an L4 import commit. No agent takes part (decision R5-Q1, D1).

An import task names files of another repository at one commit and where they go:

  import_from: {repo: OWNER/NAME, ref: <40-hex commit>, map: [{from, to}, ...]}

A trusted job turns that into one commit with git plumbing. The blobs are the source's own
objects, entered into the index by (mode, OID), so nothing is checked out, no filter or
attribute runs, and nothing an agent wrote is involved. Every step can only refuse:

  grammar   repo, ref and every path component match fixed patterns; `to` paths are unique
            case-folded and never land on a protected destination (IMPORT_TO_FORBIDDEN)
  allowed   repo is a line of IMPORT_ALLOWED_REPOS; "repo@sha" is a line of IMPORT_PINS
  ancestry  the SHA is a commit and an ancestor of the source's default branch. A fork's
            commit or an unmerged PR head is fetchable through the parent's URL too, so
            "the object exists" proves nothing
  expand    `git ls-tree -r` at the SHA; a directory mapping (trailing slash) takes every
            file under it, a file mapping exactly one entry. Every entry must be a regular
            blob (100644 or 100755); 120000 and 160000 are refused
  index     `git update-index --add --cacheinfo mode,oid,to` per file, then
            `git diff --cached --no-renames --raw HEAD` must be exactly the set of additions
            expanded above, and check_patch.grade() must pass it. A path on the base's
            `.github/agent-protected.txt` passes only under D3 (check_patch.d3_allows)
  commit    after `git commit`, `git ls-tree -r HEAD -- <to...>` must equal the source's
            (mode, OID) for every file, and the commit's own diff against its parent must be
            those additions and nothing else

  import_verify.py validate --envelope envelope.json
  import_verify.py build --envelope envelope.json --issue N --body-out body.md
                         [--manifest-out m.json] [--source-url URL] [--lookup-prs]
  import_verify.py check-commit --manifest m.json [--commit HEAD]

`build` runs in the target checkout with the import branch checked out at the base and a
clean index; it leaves the commit on that branch and writes the PR body (one table row per
file) to --body-out. Environment: IMPORT_ALLOWED_REPOS, IMPORT_PINS, IMPORT_PROTECTED_PINS
(newline-separated), AGENT_PROTECTED_REQUIRED ("true" refuses when the base has no list),
GH_TOKEN for --lookup-prs.

Exit 0 built / valid, 1 refused (reasons on stdout), 4 usage error.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from typing import Any

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import check_patch  # noqa: E402  (same directory)
from protected_paths import IMPORT_TO_FORBIDDEN, matches_folded, read_agent_protected  # noqa: E402

REPO_RE = re.compile(r"^[A-Za-z0-9-]+/[A-Za-z0-9._-]+$")
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
COMPONENT_RE = re.compile(r"^[A-Za-z0-9._-]+$")
FORBIDDEN_COMPONENTS = {".", "..", ".git"}
BLOB_MODES = {"100644", "100755"}
MARKER = "agent-import-verified"


class Refused(Exception):
    pass


def path_errors(path: str, what: str) -> list[str]:
    """A path is components joined by `/`, optionally ending in `/` for a directory."""
    if not path:
        return [f"{what}: empty path"]
    if path.startswith("/"):
        return [f"{what}: {path!r} starts with a slash"]
    body = path[:-1] if path.endswith("/") else path
    errors: list[str] = []
    for comp in body.split("/"):
        if not COMPONENT_RE.match(comp):
            errors.append(f"{what}: {path!r} has a component outside [A-Za-z0-9._-]+")
            break
        if comp.casefold() in FORBIDDEN_COMPONENTS:
            errors.append(f"{what}: {path!r} has a {comp!r} component")
            break
    return errors


def forbidden_destination(to: str) -> bool:
    if to.endswith("/"):
        # Any file under this directory would be forbidden: `.github/`, `.agent-out/` and the
        # like. Files that are forbidden by name only (a nested Makefile) are caught after
        # expansion.
        return matches_folded(to + "x", IMPORT_TO_FORBIDDEN)
    return matches_folded(to, IMPORT_TO_FORBIDDEN)


def grammar_errors(spec: Any) -> list[str]:
    """Static checks on the import_from object, before any git call."""
    if not isinstance(spec, dict):
        return ["import_from: must be an object"]
    errors: list[str] = []
    repo, ref, mapping = spec.get("repo"), spec.get("ref"), spec.get("map")
    if not isinstance(repo, str) or not REPO_RE.match(repo):
        errors.append(f"import_from.repo: {repo!r} is not OWNER/NAME")
    if not isinstance(ref, str) or not SHA_RE.match(ref):
        errors.append(f"import_from.ref: {ref!r} is not a 40-hex commit SHA (no tag, no branch)")
    if not isinstance(mapping, list) or not mapping:
        errors.append("import_from.map: needs at least one `from -> to` line")
        return errors
    seen: dict[str, str] = {}
    for i, item in enumerate(mapping):
        src = item.get("from") if isinstance(item, dict) else None
        dst = item.get("to") if isinstance(item, dict) else None
        if not isinstance(src, str) or not isinstance(dst, str):
            errors.append(f"import_from.map[{i}]: needs `from` and `to`")
            continue
        errs = path_errors(src, f"import_from.map[{i}].from") + path_errors(dst, f"import_from.map[{i}].to")
        errors += errs
        if errs:
            continue
        if src.endswith("/") != dst.endswith("/"):
            errors.append(f"import_from.map[{i}]: a directory (trailing slash) maps only to a directory")
        if forbidden_destination(dst):
            errors.append(f"import_from.map[{i}].to: {dst!r} is a protected destination")
        key = dst.casefold()
        if key in seen:
            errors.append(f"import_from.map[{i}].to: {dst!r} repeats {seen[key]!r} (compared case-folded)")
        seen.setdefault(key, dst)
    return errors


def env_lines(name: str) -> set[str]:
    return {line.strip() for line in os.environ.get(name, "").splitlines() if line.strip()}


def git(args: list[str], *, check: bool = True, env: dict[str, str] | None = None) -> bytes:
    proc = subprocess.run(["git", *args], capture_output=True, env=env)
    if check and proc.returncode != 0:
        raise Refused(f"git {' '.join(args[:3])} … failed: {proc.stderr.decode(errors='replace').strip()[:300]}")
    return proc.stdout


def literal_env() -> dict[str, str]:
    return {**os.environ, "GIT_LITERAL_PATHSPECS": "1"}


def ls_tree(rev: str, paths: list[str]) -> list[tuple[str, str, str, str]]:
    """(mode, type, oid, path) for every entry under <paths> at <rev>, recursively."""
    out = git(["ls-tree", "-r", "-z", "--full-tree", rev, "--", *paths], env=literal_env())
    rows = []
    for rec in out.split(b"\0"):
        if not rec:
            continue
        meta, _, path = rec.decode("utf-8", "surrogateescape").partition("\t")
        mode, typ, oid = meta.split()
        rows.append((mode, typ, oid, path))
    return rows


def expand(sha: str, mapping: list[dict[str, str]]) -> list[dict[str, str]]:
    """One {to, from, mode, oid} per file, in map order then source path order."""
    files: list[dict[str, str]] = []
    for item in mapping:
        src, dst = item["from"], item["to"]
        rows = ls_tree(sha, [src])
        if src.endswith("/"):
            rows = [r for r in rows if r[3].startswith(src)]
            if not rows:
                raise Refused(f"{src} is not a directory with files at {sha}")
        else:
            rows = [r for r in rows if r[3] == src]
            if len(rows) != 1:
                raise Refused(f"{src} is not a single file at {sha}")
        for mode, typ, oid, path in rows:
            if mode not in BLOB_MODES or typ != "blob":
                raise Refused(f"{path} is a {mode} {typ} entry; only regular files (100644, 100755) are imported")
            to = dst + path[len(src):] if src.endswith("/") else dst
            files.append({"to": to, "from": path, "mode": mode, "oid": oid})
    seen: dict[str, str] = {}
    for f in files:
        errs = path_errors(f["to"], "expanded to")
        if errs:
            raise Refused(errs[0])
        if matches_folded(f["to"], IMPORT_TO_FORBIDDEN):
            raise Refused(f"{f['to']} is a protected destination")
        key = f["to"].casefold()
        if key in seen:
            raise Refused(f"two files land on {f['to']} (compared case-folded with {seen[key]})")
        seen[key] = f["to"]
    return files


def check_commit(manifest: dict[str, Any], commit: str) -> list[str]:
    """Compare a commit, not the index, with the source entries it is meant to carry."""
    expected = {f["to"]: (f["mode"], f["oid"]) for f in manifest["files"]}
    reasons: list[str] = []
    got = {path: (mode, oid) for mode, _typ, oid, path in ls_tree(commit, sorted(expected))}
    for to, want in sorted(expected.items()):
        if got.get(to) != want:
            reasons.append(f"{to}: commit has {got.get(to)}, source has {want}")
    parent = git(["rev-parse", f"{commit}^"]).decode().strip()
    if parent != manifest["base"]:
        reasons.append(f"the commit's parent is {parent}, not the base {manifest['base']}")
    entries = check_patch.parse_raw(git(["diff", "--no-renames", "--raw", "--no-abbrev", "-z", parent, commit]))
    changed = {(e.status, e.path) for e in entries}
    if changed != {("A", to) for to in expected}:
        extra = sorted(changed - {("A", to) for to in expected})
        reasons.append(f"the commit changes more or other than the import: {extra[:5]}")
    return reasons


def last_change(sha: str, path: str) -> str:
    return git(["log", "-1", "--format=%H", sha, "--", path], env=literal_env()).decode().strip()


def pr_for(repo: str, commit: str, cache: dict[str, str]) -> str:
    if commit not in cache:
        proc = subprocess.run(
            ["gh", "api", f"repos/{repo}/commits/{commit}/pulls", "--jq", ".[0].number // empty"],
            capture_output=True,
            text=True,
        )
        num = proc.stdout.strip() if proc.returncode == 0 else ""
        cache[commit] = f"{repo}#{num}" if num.isdigit() else "?"
    return cache[commit]


def build(args: argparse.Namespace) -> int:
    env = json.load(open(args.envelope, encoding="utf-8"))
    spec = env.get("import_from")
    errors = grammar_errors(spec)
    if errors:
        raise Refused("; ".join(errors))
    repo, sha, mapping = spec["repo"], spec["ref"], spec["map"]
    pin = f"{repo}@{sha}"
    if repo not in env_lines("IMPORT_ALLOWED_REPOS"):
        raise Refused(f"{repo} is not a line of IMPORT_ALLOWED_REPOS")
    if pin not in env_lines("IMPORT_PINS"):
        raise Refused(f"{pin} is not a line of IMPORT_PINS")

    base = git(["rev-parse", "HEAD"]).decode().strip()
    if subprocess.run(["git", "diff", "--cached", "--quiet", "HEAD"]).returncode != 0:
        raise Refused("the index differs from HEAD before the import starts")
    agent_protected = read_agent_protected(".")
    required = os.environ.get("AGENT_PROTECTED_REQUIRED", "") == "true"
    if agent_protected is None and required:
        raise Refused(".github/agent-protected.txt is missing from the base and AGENT_PROTECTED_REQUIRED is true")

    url = args.source_url or f"https://github.com/{repo}"
    head = git(["ls-remote", "--symref", url, "HEAD"]).decode()
    m = re.search(r"^ref: refs/heads/(\S+)\tHEAD$", head, re.M)
    if not m:
        raise Refused(f"cannot tell the default branch of {repo}")
    default = m.group(1)
    git(["fetch", "--no-tags", "-q", url, f"+refs/heads/{default}:refs/import/src"])
    if git(["cat-file", "-t", sha], check=False).decode().strip() != "commit":
        raise Refused(f"{sha} is not a commit of {repo}")
    if subprocess.run(["git", "merge-base", "--is-ancestor", sha, "refs/import/src"]).returncode != 0:
        raise Refused(f"{sha} is not an ancestor of {repo}'s {default}")

    files = expand(sha, mapping)
    for f in files:
        git(["update-index", "--add", "--cacheinfo", f"{f['mode']},{f['oid']},{f['to']}"])

    entries = check_patch.parse_raw(git(["diff", "--cached", "--no-renames", "--raw", "--no-abbrev", "-z", "HEAD"]))
    want = {("A", f["to"], f["mode"], f["oid"]) for f in files}
    got = {(e.status, e.path, e.new_mode, e.new_oid) for e in entries}
    if got != want:
        raise Refused(
            f"the index is not exactly the import: extra {sorted(got - want)[:5]}, missing {sorted(want - got)[:5]}"
        )
    base_paths = {
        p.decode("utf-8", "surrogateescape")
        for p in git(["ls-tree", "-r", "-z", "--name-only", "--full-tree", "HEAD"]).split(b"\0")
        if p
    }
    expected = {f["to"]: (f["mode"], f["oid"]) for f in files}
    protected_pins = env_lines("IMPORT_PROTECTED_PINS")

    def exception(entry: check_patch.Entry) -> bool:
        return check_patch.d3_allows(
            entry,
            agent_protected=agent_protected or [],
            base_paths=base_paths,
            source_pin=pin,
            protected_pins=protected_pins,
            expected=expected,
        )

    reasons = check_patch.grade(
        entries,
        allowed=env.get("allowed_paths") or [],
        agent_protected=agent_protected,
        protected_required=required,
        base_paths=base_paths,
        exception=exception,
    )
    if reasons:
        raise Refused("; ".join(reasons))

    title = str(env.get("title", "import"))
    issue = args.issue
    git(["commit", "-q", "-m", f"import({repo}@{sha[:12]}): {title}", "-m", f"Implements #{issue}."])
    commit = git(["rev-parse", "HEAD"]).decode().strip()
    manifest = {"source": pin, "base": base, "commit": commit, "files": files}
    reasons = check_commit(manifest, commit)
    if reasons:
        raise Refused("; ".join(reasons))
    if args.manifest_out:
        with open(args.manifest_out, "w", encoding="utf-8") as fh:
            json.dump(manifest, fh, indent=2)
            fh.write("\n")

    cache: dict[str, str] = {}
    rows = []
    for f in files:
        changed = last_change(sha, f["from"])
        pr = pr_for(repo, changed, cache) if args.lookup_prs else "-"
        rows.append(f"| `{f['to']}` | {f['mode']} | `{f['oid']}` | `{f['from']}` | `{changed[:12]}` | {pr} |")
    marker = json.dumps({"source": pin, "head": commit, "files": len(files)}, sort_keys=True)
    body = "\n".join(
        [
            f"Import of {len(files)} file(s) from `{pin}`, built by import_verify.py without an agent.",
            "Every row was checked twice: in the index before the commit, and in the commit after it.",
            "",
            "| to | mode | OID | from | last changed in | PR |",
            "|---|---|---|---|---|---|",
            *rows,
            "",
            f"<!-- {MARKER} {marker} -->",
            "",
        ]
    )
    with open(args.body_out, "w", encoding="utf-8") as fh:
        fh.write(body)
    print(f"import: {len(files)} file(s) from {pin} committed as {commit}")
    return 0


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    v = sub.add_parser("validate")
    v.add_argument("--envelope", required=True)
    b = sub.add_parser("build")
    b.add_argument("--envelope", required=True)
    b.add_argument("--issue", required=True, type=int)
    b.add_argument("--body-out", required=True)
    b.add_argument("--manifest-out")
    b.add_argument("--source-url", help="fetch from here instead of https://github.com/<repo> (tests)")
    b.add_argument("--lookup-prs", action="store_true", help="name the PR of each last-changing commit (gh)")
    c = sub.add_parser("check-commit")
    c.add_argument("--manifest", required=True)
    c.add_argument("--commit", default="HEAD")
    args = ap.parse_args(argv)

    try:
        if args.cmd == "validate":
            env = json.load(open(args.envelope, encoding="utf-8"))
            if "import_from" not in env:
                print("not an import task")
                return 0
            errors = grammar_errors(env["import_from"])
            for e in errors:
                print(f"  - {e}")
            if errors:
                print(f"REFUSED ({len(errors)})")
                return 1
            print("OK: import_from is well formed")
            return 0
        if args.cmd == "check-commit":
            manifest = json.load(open(args.manifest, encoding="utf-8"))
            reasons = check_commit(manifest, args.commit)
            for r in reasons:
                print(f"  - {r}")
            if reasons:
                print(f"REFUSED ({len(reasons)})")
                return 1
            print(f"OK: {len(manifest['files'])} file(s) match the source")
            return 0
        return build(args)
    except Refused as exc:
        print(f"REFUSED: {exc}")
        return 1
    except (OSError, json.JSONDecodeError, KeyError) as exc:
        print(f"cannot read input: {exc}", file=sys.stderr)
        return 4


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
