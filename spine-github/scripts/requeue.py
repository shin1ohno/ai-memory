#!/usr/bin/env python3
"""Start again the Claude runs that stopped on a usage or rate limit.

claude-requeue.yml runs this every hour. When a Claude node's agent step fails and
classify_failure.py calls the failure retryable, the node's failure handler labels the
issue or pull request `agent:waiting-quota` and posts a comment carrying a hidden marker:

  <!-- claude-requeue {"workflow":"claude-implement.yml","issue":"12"} -->
  <!-- claude-requeue {"workflow":"claude-fix-ci.yml","inputs":{"pr":"7","round":"1","run_id":"99"}} -->
  <!-- claude-requeue {"workflow":"claude-address-review.yml","inputs":{"pr":"7","round":"1"}} -->
  <!-- claude-requeue {"workflow":"claude-review.yml","inputs":{"pr":"7"}} -->

For every open item with that label, this script reads the item's comments and counts the
markers written by github-actions[bot]; each failed attempt posts one, so the count is the
number of attempts so far. The latest marker says what to start:

  issue, claude-implement.yml   remove agent:waiting-quota, then remove and re-add
                                agent:claude with TRIGGER_TOKEN. A label change made with
                                GITHUB_TOKEN raises no event, so only the App's token (or
                                the PAT) can start claude-implement.yml again.
  pull request, one of the      remove agent:waiting-quota, then `gh workflow run` it on the
  three PR workflows            default branch with the marker's inputs (GITHUB_TOKEN may
                                start workflow_dispatch runs).

A marker is trusted as data, never as a command: the author must be exactly
github-actions[bot], the workflow must be on the allowlist for the item's kind, the input
keys must be exactly the ones that workflow takes, every value must be all digits, and `pr`
(or `issue`) must be the item's own number. Anything else — no marker, an invalid one,
max-hours passed since the first marker, or max-attempts reached — takes agent:waiting-quota
off, puts needs-human on, and says why in a comment.

  requeue.py --repo OWNER/NAME [--max-attempts 48] [--max-hours 48]

Environment: GH_TOKEN (the workflow's token), TRIGGER_TOKEN (the factory App's issues:write
token, or GH_AW_CI_TRIGGER_TOKEN where no App is configured; may be empty, in which case
implement items are left waiting and an error is printed).
Prints one line per item. Exit 1 if any gh call failed (or returned JSON that could not be
read), 4 on a usage error, else 0. A restart whose gh call fails puts agent:waiting-quota
back, so the item is tried again next hour instead of leaving the queue unnoticed.
"""

from __future__ import annotations

import argparse
import contextlib
import datetime
import json
import os
import re
import subprocess
import sys

WAITING = "agent:waiting-quota"
BOT = "github-actions[bot]"
MARKER_RE = re.compile(r"<!-- claude-requeue (.*?) -->", re.S)
DIGITS = re.compile(r"^[0-9]+$")
REPO_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")

# Workflow -> the exact input keys its marker must carry. Issues only ever go to implement.
PR_WORKFLOWS: dict[str, tuple[str, ...]] = {
    "claude-fix-ci.yml": ("pr", "round", "run_id"),
    "claude-review.yml": ("pr",),
    "claude-address-review.yml": ("pr", "round"),
}
ISSUE_WORKFLOW = "claude-implement.yml"


class GhError(Exception):
    pass


def gh(args: list[str], token: str | None = None, ok_404: bool = False) -> str:
    """Run gh with list args (never a shell). token overrides GH_TOKEN for this call only."""
    env = dict(os.environ)
    if token is not None:
        env["GH_TOKEN"] = token
    proc = subprocess.run(["gh", *args], env=env, capture_output=True, text=True)
    if proc.returncode != 0:
        if ok_404 and "HTTP 404" in proc.stderr:
            return ""
        raise GhError(f"gh {' '.join(args[:4])} … exited {proc.returncode}: {proc.stderr.strip()[:300]}")
    return proc.stdout


def json_values(text: str) -> list:
    """`gh api --paginate` prints one JSON array per page, back to back: flatten them."""
    dec, i, out = json.JSONDecoder(), 0, []
    while True:
        while i < len(text) and text[i].isspace():
            i += 1
        if i >= len(text):
            return out
        value, i = dec.raw_decode(text, i)
        out.extend(value if isinstance(value, list) else [value])


class Repo:
    def __init__(self, name: str, trigger_token: str):
        self.name = name
        self.trigger_token = trigger_token
        self._default_branch: str | None = None

    def default_branch(self) -> str:
        if self._default_branch is None:
            branch = gh(["api", f"repos/{self.name}", "--jq", ".default_branch"]).strip()
            if not branch:
                raise GhError("could not read the default branch")
            self._default_branch = branch
        return self._default_branch

    def remove_label(self, n: int, label: str, token: str | None = None) -> None:
        # 404: the label is already gone, which is the state this call wants.
        gh(["api", "-X", "DELETE", f"repos/{self.name}/issues/{n}/labels/{label}", "--silent"],
           token=token, ok_404=True)

    def add_label(self, n: int, label: str, token: str | None = None) -> None:
        gh(["api", "-X", "POST", f"repos/{self.name}/issues/{n}/labels", "-f", f"labels[]={label}", "--silent"],
           token=token)

    def comment(self, n: int, body: str) -> None:
        gh(["api", "-X", "POST", f"repos/{self.name}/issues/{n}/comments", "-f", f"body={body}", "--silent"])


def _marker_comments(comments: list) -> list[tuple[str, str]]:
    """(payload, created_at) of every github-actions[bot] comment that carries a marker,
    oldest first. created_at is "" when the comment has none."""
    found = []
    for c in comments:
        if not isinstance(c, dict) or (c.get("user") or {}).get("login") != BOT:
            continue
        hits = MARKER_RE.findall(str(c.get("body") or ""))
        if hits:
            found.append((hits[-1], str(c.get("created_at") or "")))
    return found


def markers(comments: list) -> list[str]:
    """The marker payload of every github-actions[bot] comment that carries one, oldest first."""
    return [payload for payload, _ in _marker_comments(comments)]


def hours_since_first_marker(comments: list, now: datetime.datetime) -> float | None:
    """Hours since the first marker was posted, i.e. since the item first stopped on a limit.
    None when that comment has no readable timestamp."""
    found = _marker_comments(comments)
    if not found:
        return None
    try:
        first = datetime.datetime.fromisoformat(found[0][1].replace("Z", "+00:00"))
    except ValueError:
        return None
    if first.tzinfo is None:
        return None
    return (now - first).total_seconds() / 3600


def validate(payload: str, number: int, is_pr: bool) -> tuple[str, list[tuple[str, str]]] | str:
    """(workflow, [(input, value), ...]) for a usable marker, or the reason it is refused.

    Reasons are fixed strings: they go into a public comment, and the marker's own values
    are not echoed back.
    """
    try:
        data = json.loads(payload)
    except json.JSONDecodeError:
        return "the latest marker is not valid JSON"
    if not isinstance(data, dict):
        return "the latest marker is not a JSON object"
    wf = data.get("workflow")
    if not is_pr:
        if wf != ISSUE_WORKFLOW or set(data) != {"workflow", "issue"}:
            return f"an issue marker must name {ISSUE_WORKFLOW} and an issue number, nothing else"
        issue = data.get("issue")
        if not isinstance(issue, str) or not DIGITS.match(issue) or issue != str(number):
            return "the marker's issue number is not this issue"
        return wf, [("issue", issue)]
    if wf not in PR_WORKFLOWS:
        return "the marker names a workflow outside the pull-request allowlist"
    inputs = data.get("inputs")
    if set(data) != {"workflow", "inputs"} or not isinstance(inputs, dict):
        return "a pull-request marker must carry exactly a workflow and its inputs"
    keys = PR_WORKFLOWS[wf]
    if set(inputs) != set(keys):
        return f"{wf} takes exactly the inputs {', '.join(keys)}"
    for k in keys:
        v = inputs[k]
        if not isinstance(v, str) or not DIGITS.match(v):
            return f"the marker's input '{k}' is not a number"
    if inputs["pr"] != str(number):
        return "the marker's pr input is not this pull request"
    return wf, [(k, inputs[k]) for k in keys]


@contextlib.contextmanager
def _restore_waiting_on_failure(repo: Repo, n: int):
    """If the restart fails, put agent:waiting-quota back so the next hour tries again
    instead of the item silently leaving the queue. Best effort; the original error wins."""
    try:
        yield
    except GhError:
        try:
            repo.add_label(n, WAITING)
        except GhError as again:
            print(f"::error::#{n}: could not restore {WAITING} either: {again}")
        raise


def give_up(repo: Repo, n: int, why: str) -> None:
    repo.remove_label(n, WAITING)
    repo.add_label(n, "needs-human")
    repo.comment(n, f"claude-requeue stopped retrying: {why}. This is a human task now.\n\n"
                    "<!-- claude-requeue-stopped -->\n")


def handle(repo: Repo, item: dict, max_attempts: int, max_hours: float = 48.0,
           now: datetime.datetime | None = None) -> str:
    """Act on one waiting item; return the line to print. Raises GhError on a failed call."""
    n = int(item["number"])
    is_pr = "pull_request" in item
    kind = "pr" if is_pr else "issue"
    comments = json_values(gh(["api", f"repos/{repo.name}/issues/{n}/comments?per_page=100", "--paginate"]))
    found = markers(comments)
    attempts = len(found)
    if attempts == 0:
        give_up(repo, n, f"no claude-requeue marker from {BOT} on this {'pull request' if is_pr else 'issue'}")
        return f"#{n} {kind}: needs-human (no marker)"
    # Time is the real bound: GitHub starts hourly schedules hours late and skips many, so
    # 48 attempts alone stretched to about ten days in the sandbox.
    hours = hours_since_first_marker(comments, now or datetime.datetime.now(datetime.timezone.utc))
    if hours is not None and hours >= max_hours:
        give_up(repo, n, f"gave up {hours:.0f} hours after the first failure ({attempts} attempts); "
                         "Claude kept hitting a usage or rate limit")
        return f"#{n} {kind}: needs-human (gave up after {hours:.0f} hours)"
    if attempts >= max_attempts:
        give_up(repo, n, f"gave up after {attempts} attempts; Claude kept hitting a usage or rate limit")
        return f"#{n} {kind}: needs-human (gave up after {attempts} attempts)"
    verdict = validate(found[-1], n, is_pr)
    if isinstance(verdict, str):
        give_up(repo, n, f"refused the marker: {verdict}")
        return f"#{n} {kind}: needs-human (refused: {verdict})"
    wf, inputs = verdict
    so_far = f"{attempts} failed attempt(s) so far, limit {max_attempts}"
    if not is_pr:
        if not repo.trigger_token:
            print(f"::error::#{n}: TRIGGER_TOKEN (the App token or GH_AW_CI_TRIGGER_TOKEN) is empty; "
                  f"cannot re-label agent:claude, leaving {WAITING} in place")
            return f"#{n} issue: left waiting (no trigger token)"
        # The waiting label comes off first: if the new run fails fast on the limit again,
        # its report job puts the label back, and nothing here may take it off after that.
        repo.remove_label(n, WAITING)
        with _restore_waiting_on_failure(repo, n):
            repo.remove_label(n, "agent:claude", token=repo.trigger_token)
            repo.add_label(n, "agent:claude", token=repo.trigger_token)
        return f"#{n} issue: re-labelled agent:claude to restart {wf} ({so_far})"
    ref = repo.default_branch()
    repo.remove_label(n, WAITING)
    fields = [a for k, v in inputs for a in ("-f", f"{k}={v}")]
    with _restore_waiting_on_failure(repo, n):
        gh(["workflow", "run", wf, "--repo", repo.name, "--ref", ref, *fields])
    shown = " ".join(f"{k}={v}" for k, v in inputs)
    return f"#{n} pr: dispatched {wf} {shown} ({so_far})"


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        self.print_usage(sys.stderr)
        print(f"{self.prog}: error: {message}", file=sys.stderr)
        sys.exit(4)


def main(argv: list[str]) -> int:
    ap = _Parser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--repo", required=True)
    ap.add_argument("--max-attempts", type=int, default=48)
    ap.add_argument("--max-hours", type=float, default=48.0,
                    help="give up this many hours after the first failure (default 48)")
    args = ap.parse_args(argv)
    if not REPO_RE.match(args.repo):
        ap.error(f"--repo must be OWNER/NAME, got {args.repo!r}")
    if args.max_attempts < 1:
        ap.error("--max-attempts must be at least 1")
    if not args.max_hours > 0:
        ap.error("--max-hours must be positive")
    if not os.environ.get("GH_TOKEN"):
        ap.error("GH_TOKEN is not set")

    repo = Repo(args.repo, os.environ.get("TRIGGER_TOKEN", ""))
    try:
        items = json_values(gh(["api", f"repos/{args.repo}/issues?labels={WAITING}&state=open&per_page=100",
                                "--paginate"]))
    except (GhError, json.JSONDecodeError) as exc:
        print(f"::error::could not list the waiting items: {exc}")
        return 1
    print(f"{len(items)} open item(s) labelled {WAITING}")
    failed = False
    for item in items:
        try:
            print(handle(repo, item, args.max_attempts, args.max_hours))
        except (GhError, json.JSONDecodeError, KeyError, ValueError, TypeError) as exc:
            failed = True
            print(f"::error::#{item.get('number', '?') if isinstance(item, dict) else '?'}: {exc}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
