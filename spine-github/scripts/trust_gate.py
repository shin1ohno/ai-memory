#!/usr/bin/env python3
"""Decide who may start an agent run, and whose tasks an agent may work on.

  trust_gate.py admit --repo OWNER/NAME --event EVENT.json [--github-output FILE]
  trust_gate.py author --issue-json ISSUE.json

`admit` is claude-implement's first step. It reads the `issues: labeled` event and applies
four rules; every one must hold:

  (1) who applied the label
      User  write, maintain or admin on the repository (as before).
      Bot   exactly the factory App: type Bot, `str(id) == AGENT_APP_BOT_ID` and login
            `AGENT_APP_SLUG + "[bot]"`, so a renamed App or any other App that holds
            issues:write is refused. And the label must come from one of two places:
            requeue  github-actions[bot] parked this issue with a valid claude-requeue
                     marker, and before that marker a User with write access had applied
                     agent:claude (the run being restarted was a human's);
            intake   LINEAR_INTAKE_ENABLED is "true" and the issue is a linear-intake mirror.
      Anything else is refused.
  (2) who wrote the task: the issue author's numeric id is in TRUSTED_ISSUE_AUTHOR_IDS, and
      an issue github-actions[bot] wrote must be a linear-intake mirror. The App's own id
      never belongs in that list: the App does not create issues.
  (3) the body that runs is the body that was approved. A human start posts
      `<!-- agent-approved {"issue":N,"sha256":H} -->` as github-actions[bot], H being the
      sha256 of the body as envelope-validate canonicalises it. A bot start requires the
      latest such marker to carry the hash of the body now.
  (4) no open pull request from this repository already works on the issue (a branch
      `agent/gh-N-…` or a `Fixes #N` body). Fork pull requests do not count: anyone can open
      one, and counting it would let a stranger block a run.

On refusal it writes `refused=<reason>` to --github-output and exits 1, so the report job
can tell the requester instead of the issue going quiet. The reasons are fixed strings; no
user-controlled text is echoed into the issue. The sender and the author are logged as
`sender type=… id=… login=…` on every run.

`author` applies rule (2) to one issue JSON (as REST returns it), for pr_context.sh and
envelope-guard's sync. Exit 0 trusted, 1 not.

Environment: GH_TOKEN (admit only), TRUSTED_ISSUE_AUTHOR_IDS (comma-separated numeric ids),
AGENT_APP_BOT_ID, AGENT_APP_SLUG, LINEAR_INTAKE_ENABLED. Exit 4 on a usage error.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import requeue  # noqa: E402  (same directory; markers and their validation)
from envelope_from_issue import linear_id_for_issue  # noqa: E402

ACTIONS_BOT_ID = 41898282
ACTIONS_BOT_LOGIN = "github-actions[bot]"
WRITE_ROLES = {"admin", "maintain", "write"}
APPROVED_RE = re.compile(r"<!-- agent-approved (\{.*?\}) -->", re.S)
DIGITS = re.compile(r"^[0-9]+$")


class Refused(Exception):
    pass


def gh(args: list[str]) -> str:
    proc = subprocess.run(["gh", *args], capture_output=True, text=True)
    if proc.returncode != 0:
        raise requeue.GhError(f"gh {' '.join(args[:3])} … exited {proc.returncode}: {proc.stderr.strip()[:300]}")
    return proc.stdout


def who(person: dict | None) -> str:
    p = person or {}
    return f"type={p.get('type', '?')} id={p.get('id', '?')} login={p.get('login', '?')}"


def trusted_author_ids() -> set[str]:
    raw = os.environ.get("TRUSTED_ISSUE_AUTHOR_IDS", "")
    return {part.strip() for part in raw.split(",") if part.strip()}


def is_actions_bot(person: dict | None) -> bool:
    p = person or {}
    return str(p.get("id")) == str(ACTIONS_BOT_ID) and p.get("login") == ACTIONS_BOT_LOGIN


def is_mirror(issue: dict) -> bool:
    """A linear-intake mirror: github-actions[bot] wrote it with the marker on a line of its
    own (envelope_from_issue.linear_id_for_issue). The linear:<ID> label is not consulted:
    triage rights are enough to add one."""
    return is_actions_bot(issue.get("user")) and linear_id_for_issue(issue)[0] is not None


def check_author(issue: dict) -> None:
    """Rule (2). Raises Refused."""
    ids = trusted_author_ids()
    if not ids:
        raise Refused("TRUSTED_ISSUE_AUTHOR_IDS is not set, so no issue author is trusted")
    if not all(DIGITS.match(i) for i in ids):
        raise Refused("TRUSTED_ISSUE_AUTHOR_IDS must be numeric account ids, comma-separated")
    user = issue.get("user") or {}
    if str(user.get("id")) not in ids:
        raise Refused("the issue was not written by a trusted author")
    if str(user.get("id")) == str(ACTIONS_BOT_ID) and not is_mirror(issue):
        raise Refused("an issue written by github-actions[bot] is trusted only as a linear-intake mirror")


def body_hash(body: str, number: int) -> str:
    """sha256 of the body as envelope-validate writes it back (--emit issue-body), so the
    canonical rewrite that follows a human's edit does not count as a change."""
    proc = subprocess.run(
        [sys.executable, os.path.join(HERE, "envelope_from_issue.py"), "--body-file", "-",
         "--task-id", f"gh-{number}", "--emit", "issue-body", "--quiet"],
        input=body, capture_output=True, text=True)
    if proc.returncode != 0:
        raise Refused("the issue body is not a valid task envelope")
    return hashlib.sha256(proc.stdout.encode("utf-8")).hexdigest()


def permission(repo: str, login: str) -> str:
    try:
        return gh(["api", f"repos/{repo}/collaborators/{login}/permission", "--jq", ".permission"]).strip()
    except requeue.GhError:
        return "none"


def by_actions_bot(comments: list) -> list[dict]:
    return [c for c in comments if isinstance(c, dict) and is_actions_bot(c.get("user"))]


def latest_approval(comments: list, number: int) -> str | None:
    """The sha256 in the latest agent-approved marker github-actions[bot] wrote, or None."""
    found = None
    for c in by_actions_bot(comments):
        for payload in APPROVED_RE.findall(str(c.get("body") or "")):
            try:
                data = json.loads(payload)
            except json.JSONDecodeError:
                continue
            if isinstance(data, dict) and data.get("issue") == number and isinstance(data.get("sha256"), str):
                found = data["sha256"]
    return found


def requeue_origin(repo: str, number: int, comments: list) -> None:
    """Rule (1) for a bot: the label re-applies a human's run that claude-requeue parked."""
    parked = [c for c in by_actions_bot(comments) if requeue.MARKER_RE.search(str(c.get("body") or ""))]
    if not parked:
        raise Refused("the App applied the label, but no claude-requeue marker parked this issue")
    last = parked[-1]
    verdict = requeue.validate(requeue.MARKER_RE.findall(str(last.get("body") or ""))[-1], number, is_pr=False)
    if isinstance(verdict, str):
        raise Refused("the App applied the label, but the latest claude-requeue marker is invalid")
    since = str(last.get("created_at") or "")
    events = requeue.json_values(gh(["api", f"repos/{repo}/issues/{number}/events?per_page=100", "--paginate"]))
    starts = [e for e in events
              if isinstance(e, dict) and e.get("event") == "labeled"
              and (e.get("label") or {}).get("name") == "agent:claude"
              and (e.get("actor") or {}).get("type") == "User"
              and str(e.get("created_at") or "") < since]
    if not starts:
        raise Refused("the App applied the label, but no person had started a run before it was parked")
    starter = starts[-1]["actor"]
    if permission(repo, str(starter.get("login"))) not in WRITE_ROLES:
        raise Refused("the run the App restarts was started by someone without write access")


def admit(repo: str, event: dict) -> str:
    """Apply rules (1)-(4); return a line to print. Raises Refused."""
    sender = event.get("sender") or {}
    issue = event.get("issue") or {}
    number = int(issue.get("number"))
    print(f"sender {who(sender)}")
    print(f"author {who(issue.get('user'))}")

    comments: list | None = None

    def get_comments() -> list:
        nonlocal comments
        if comments is None:
            comments = requeue.json_values(
                gh(["api", f"repos/{repo}/issues/{number}/comments?per_page=100", "--paginate"]))
        return comments

    # (1) who applied the label
    if sender.get("type") == "User":
        perm = permission(repo, str(sender.get("login")))
        if perm not in WRITE_ROLES:
            raise Refused("the label was applied by an account without write access")
        human = True
    elif sender.get("type") == "Bot":
        bot_id = os.environ.get("AGENT_APP_BOT_ID", "")
        slug = os.environ.get("AGENT_APP_SLUG", "")
        if not (DIGITS.match(bot_id) and str(sender.get("id")) == bot_id):
            raise Refused("the label was applied by a bot that is not the factory App")
        if not slug or sender.get("login") != f"{slug}[bot]":
            raise Refused("the label was applied by a bot whose login is not the factory App's")
        if os.environ.get("LINEAR_INTAKE_ENABLED") == "true" and is_mirror(issue):
            pass
        else:
            requeue_origin(repo, number, get_comments())
        human = False
    else:
        raise Refused("the label was applied by an account that is neither a person nor the factory App")

    # (2) who wrote the task
    check_author(issue)

    # (3) the body that runs is the body that was approved
    digest = body_hash(str(issue.get("body") or ""), number)
    if not human and latest_approval(get_comments(), number) != digest:
        raise Refused("the issue body changed after the run was approved")

    # (4) one open agent pull request per issue, counting this repository's only
    pulls = requeue.json_values(gh(["api", f"repos/{repo}/pulls?state=open&per_page=100", "--paginate"]))
    closing = re.compile(rf"(?i)\b(fixes|closes|resolves) #{number}\b")
    for pr in pulls:
        if not isinstance(pr, dict) or ((pr.get("head") or {}).get("repo") or {}).get("full_name") != repo:
            continue
        if str((pr.get("head") or {}).get("ref") or "").startswith(f"agent/gh-{number}-") \
                or closing.search(str(pr.get("body") or "")):
            raise Refused(f"the issue already has an open agent pull request (#{pr.get('number')})")

    # Recorded last, so only an admitted run leaves an approval behind.
    if human:
        marker = json.dumps({"issue": number, "sha256": digest}, separators=(",", ":"))
        gh(["api", "-X", "POST", f"repos/{repo}/issues/{number}/comments", "--silent", "-f",
            f"body=Run approved for the issue body with sha256 `{digest}`. A restart runs only "
            f"while the body is unchanged.\n\n<!-- agent-approved {marker} -->\n"])

    return f"admitted: {'a person' if human else 'the factory App'} started the run on #{number}"


def write_output(path: str | None, key: str, value: str) -> None:
    if path:
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(f"{key}={value}\n")


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        self.print_usage(sys.stderr)
        print(f"{self.prog}: error: {message}", file=sys.stderr)
        sys.exit(4)


def main(argv: list[str]) -> int:
    ap = _Parser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("admit")
    a.add_argument("--repo", required=True)
    a.add_argument("--event", required=True)
    a.add_argument("--github-output")
    b = sub.add_parser("author")
    b.add_argument("--issue-json", required=True)
    args = ap.parse_args(argv)

    if args.cmd == "author":
        try:
            with open(args.issue_json, encoding="utf-8") as fh:
                issue = json.load(fh)
            print(f"author {who(issue.get('user'))}")
            check_author(issue)
        except (OSError, json.JSONDecodeError, AttributeError) as exc:
            print(f"::error::cannot read the issue JSON: {exc}")
            return 1
        except Refused as why:
            print(f"::error::{why}")
            return 1
        print("author trusted")
        return 0

    if not requeue.REPO_RE.match(args.repo):
        ap.error(f"--repo must be OWNER/NAME, got {args.repo!r}")
    try:
        with open(args.event, encoding="utf-8") as fh:
            event = json.load(fh)
        print(admit(args.repo, event))
        return 0
    except Refused as why:
        reason = str(why)
    except (OSError, json.JSONDecodeError, requeue.GhError, KeyError, TypeError, ValueError) as exc:
        print(f"::error::{exc}")
        reason = "the admission check could not complete"
    print(f"::error::refused: {reason}")
    write_output(args.github_output, "refused", reason)
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
