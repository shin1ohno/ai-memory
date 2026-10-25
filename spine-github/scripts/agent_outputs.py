#!/usr/bin/env python3
"""Validate what a sandboxed Claude node wrote, and turn it into a GitHub API payload.

The agent runs with no GitHub access, so it cannot post anything. It writes JSON under
.agent-out/, and the publish job posts it only after this script accepts it. Two shapes:

  review   .agent-out/review.json, written by the AI review node:
             {"summary": "...",
              "comments": [{"path": "calc/stats.py", "line": 12, "body": "..."}]}
           Output: the body for POST /repos/{o}/{r}/pulls/{n}/reviews. The event is always
           COMMENT — there is no field the agent can set to approve or request changes. Every
           comment must anchor to a file the PR changes; at most 20 comments.
           With --diff, a comment whose line is not on the new side of a diff hunk is moved
           into the review body instead: GitHub rejects the whole review (422) when a single
           inline comment points outside the diff. Moved comments do not count as inline
           comments for routing — the address node works on review threads, and they have none.
           Also written: the agent-output file route_review.py reads
           ({"items": [{"type": "create_pull_request_review_comment"}, ...]}).

  replies  .agent-out/replies.json, written by the address-review node:
             [{"comment_id": 123, "reply": "...", "resolve": true}]
           Output: the replies to post, restricted to comment ids that open the unresolved
           threads the node was given (threads.json), with each thread's node id attached
           when the agent asked to resolve it.

  agent_outputs.py review  --in review.json  --changed-files files.txt --diff pr.diff --out payload.json --route-out ao.json
  agent_outputs.py replies --in replies.json --threads threads.json   --out replies-payload.json

Exit 0 accepted, 1 rejected (reasons printed), 4 unreadable input.
"""

from __future__ import annotations

import argparse
import json
import re
import sys

MAX_REVIEW_COMMENTS = 20
MAX_BODY = 4000


def _load(path: str):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


HUNK_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")


def commentable_lines(diff_text: str) -> dict[str, set[int]]:
    """Map each file to the new-side line numbers a review comment may anchor to."""
    lines: dict[str, set[int]] = {}
    # File headers only occur between `diff --git` and the file's first hunk, so an added
    # line whose content starts with "++ " is never mistaken for one.
    path, new_line, in_header = None, 0, False
    for raw in diff_text.splitlines():
        if raw.startswith("diff --git "):
            path, new_line, in_header = None, 0, True
        elif in_header and raw.startswith("+++ "):
            target = raw[4:].strip()
            path = target[2:] if target.startswith("b/") else None  # /dev/null: file deleted
            if path is not None:
                lines.setdefault(path, set())
        elif m := HUNK_RE.match(raw):
            in_header = False
            new_line = int(m.group(1))
        elif path is not None and new_line and raw[:1] in (" ", "+"):
            lines[path].add(new_line)
            new_line += 1
    return lines


def cmd_review(args: argparse.Namespace) -> int:
    try:
        data = _load(args.infile)
        changed = {l.strip() for l in open(args.changed_files, encoding="utf-8") if l.strip()}
        anchors = commentable_lines(open(args.diff, encoding="utf-8").read()) if args.diff else None
    except (OSError, json.JSONDecodeError) as exc:
        print(f"unreadable input: {exc}")
        return 4
    problems: list[str] = []
    if not isinstance(data, dict):
        print("review.json must be an object")
        return 1
    summary = str(data.get("summary") or "").strip()
    comments = data.get("comments") or []
    if not isinstance(comments, list):
        problems.append("comments must be a list")
        comments = []
    if len(comments) > MAX_REVIEW_COMMENTS:
        problems.append(f"{len(comments)} comments, more than {MAX_REVIEW_COMMENTS}")
    api_comments = []
    moved: list[str] = []
    for i, c in enumerate(comments):
        if not isinstance(c, dict):
            problems.append(f"comment {i}: not an object")
            continue
        path, line, body = c.get("path"), c.get("line"), str(c.get("body") or "").strip()
        if path not in changed:
            problems.append(f"comment {i}: {path!r} is not a file this PR changes")
        if not isinstance(line, int) or isinstance(line, bool) or line < 1:
            problems.append(f"comment {i}: line must be a positive integer")
        if not body:
            problems.append(f"comment {i}: empty body")
        if anchors is not None and path in changed and isinstance(line, int) and line not in anchors.get(path, set()):
            moved.append(f"- `{path}:{line}` — {body[:MAX_BODY]}")
            continue
        api_comments.append({"path": path, "line": line, "side": "RIGHT", "body": body[:MAX_BODY]})
    if not summary:
        summary = f"AI review: {len(api_comments)} comment(s)."
    if problems:
        print(f"REJECTED ({len(problems)}):")
        for p in problems:
            print(f"  - {p}")
        return 1
    body = summary[:MAX_BODY]
    if moved:
        body += "\n\n**Comments on lines outside the diff**\n\n" + "\n".join(moved)
    payload = {"event": "COMMENT", "body": body, "comments": api_comments}
    json.dump(payload, open(args.out, "w", encoding="utf-8"), ensure_ascii=False)
    if args.route_out:
        items = [{"type": "create_pull_request_review_comment"} for _ in api_comments]
        items.append({"type": "submit_pull_request_review", "event": "COMMENT"})
        json.dump({"items": items}, open(args.route_out, "w", encoding="utf-8"))
    print(f"OK: review with {len(api_comments)} inline comment(s), {len(moved)} moved to the body, event COMMENT")
    return 0


def cmd_replies(args: argparse.Namespace) -> int:
    try:
        data = _load(args.infile)
        threads = _load(args.threads)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"unreadable input: {exc}")
        return 4
    # threads.json: [{"thread_id": "PRRT_...", "comment_id": 123, ...}] — the first comment of
    # each unresolved thread, as exported before the agent ran.
    by_comment = {t["comment_id"]: t["thread_id"] for t in threads if "comment_id" in t}
    problems: list[str] = []
    out = []
    if not isinstance(data, list):
        print("replies.json must be a list")
        return 1
    for i, r in enumerate(data):
        if not isinstance(r, dict):
            problems.append(f"reply {i}: not an object")
            continue
        cid, text = r.get("comment_id"), str(r.get("reply") or "").strip()
        if cid not in by_comment:
            problems.append(f"reply {i}: comment {cid!r} does not open an unresolved thread")
            continue
        if not text:
            problems.append(f"reply {i}: empty reply")
            continue
        out.append({"comment_id": cid, "body": text[:MAX_BODY],
                    "resolve_thread": by_comment[cid] if r.get("resolve") is True else None})
    if problems:
        print(f"REJECTED ({len(problems)}):")
        for p in problems:
            print(f"  - {p}")
        return 1
    json.dump(out, open(args.out, "w", encoding="utf-8"), ensure_ascii=False)
    print(f"OK: {len(out)} reply(ies), {sum(1 for o in out if o['resolve_thread'])} to resolve")
    return 0


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("review")
    r.add_argument("--in", dest="infile", required=True)
    r.add_argument("--changed-files", required=True)
    r.add_argument("--diff", help="the PR diff; comments must anchor inside its hunks")
    r.add_argument("--out", required=True)
    r.add_argument("--route-out")
    p = sub.add_parser("replies")
    p.add_argument("--in", dest="infile", required=True)
    p.add_argument("--threads", required=True)
    p.add_argument("--out", required=True)
    args = ap.parse_args(argv)
    return cmd_review(args) if args.cmd == "review" else cmd_replies(args)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
