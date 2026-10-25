#!/usr/bin/env bash
# Gather everything a sandboxed Claude node needs about one agent pull request, before the
# agent starts. Inside awf the agent has no GitHub access, so whatever it must read — the
# task, the PR body, the diff, the changed files — is put on disk here.
#
#   pr_context.sh <pr-number> <out-dir> <pilot-dir>
#
#   <pilot-dir>  a checkout of the DEFAULT branch, whose scripts are trusted; never the PR's.
#
# Writes into <out-dir>: pr.json, pr-body.md, pr.diff, changed-files.txt, envelope.json
# Prints to stdout (for $GITHUB_OUTPUT): head_sha=…, head_ref=…, engine=…, issue=…
# Refuses (exit 1) a PR that is not an open, same-repository agent PR, or one whose source
# issue was not written by an author in TRUSTED_ISSUE_AUTHOR_IDS (trust_gate.py author). With
# REQUIRE_CLAUDE_BRANCH=1 (the nodes that push to the PR) it also refuses any head branch
# claude-implement.yml did not create: a human's branch is never written to by an agent.
set -euo pipefail
PR="${1:?pr number}"; OUT="${2:?out dir}"; PILOT="${3:?pilot dir}"
: "${GH_TOKEN:?GH_TOKEN}"; : "${REPO:?REPO}"
case "$PR" in ''|*[!0-9]*) echo "refusing non-numeric PR" >&2; exit 1 ;; esac
mkdir -p "$OUT"

gh api "repos/$REPO/pulls/$PR" > "$OUT/pr.json"
state="$(jq -r '.state' "$OUT/pr.json")"
head_ref="$(jq -r '.head.ref' "$OUT/pr.json")"
head_sha="$(jq -r '.head.sha' "$OUT/pr.json")"
head_repo="$(jq -r '.head.repo.full_name' "$OUT/pr.json")"
labels="$(jq -r '[.labels[].name] | join(",")' "$OUT/pr.json")"
[ "$state" = "open" ] || { echo "PR #$PR is $state" >&2; exit 1; }
[ "$head_repo" = "$REPO" ] || { echo "PR #$PR comes from a fork" >&2; exit 1; }
if [ "${REQUIRE_CLAUDE_BRANCH:-0}" = 1 ]; then
  printf '%s' "$head_ref" | grep -Eq '^agent/gh-[0-9]+-[0-9]+$' || {
    echo "PR #$PR head '$head_ref' is not a branch claude-implement created" >&2; exit 1; }
fi
printf '%s' "$head_sha" | grep -Eq '^[0-9a-f]{40}$' || { echo "bad head sha" >&2; exit 1; }
printf '%s' "$labels" | tr ',' '\n' | grep -q '^agent:' || { echo "PR #$PR is not an agent PR" >&2; exit 1; }

jq -r '.body // ""' "$OUT/pr.json" > "$OUT/pr-body.md"
gh pr diff "$PR" --repo "$REPO" > "$OUT/pr.diff"
gh api "repos/$REPO/pulls/$PR/files" --paginate --jq '.[].filename' > "$OUT/changed-files.txt"

# `|| true`: with pipefail a missing block would otherwise exit here with no message.
engine="$(grep -oE '^[[:space:]]*engine[[:space:]]*:[[:space:]]*[a-z]+' "$OUT/pr-body.md" | head -1 | cut -d: -f2 | tr -d ' ' || true)"
case "$engine" in claude|codex) ;; *) echo "PR #$PR has no agent-envelope block with a usable engine (envelope-guard's sync job writes it)" >&2; exit 1 ;; esac

issue="$(grep -oiE '(fixes|closes|resolves) #[0-9]+' "$OUT/pr-body.md" | head -1 | grep -oE '[0-9]+' || true)"
if [ -z "$issue" ] && printf '%s' "$head_ref" | grep -Eq '^agent/gh-[0-9]+-[0-9]+$'; then
  issue="$(printf '%s' "$head_ref" | cut -d- -f2)"
fi
[ -n "$issue" ] || { echo "PR #$PR names no source issue: refusing to work blind" >&2; exit 1; }
gh api "repos/$REPO/issues/$issue" > "$OUT/issue.json"
# The task is only as trustworthy as whoever wrote it: on a public repository anyone can
# open an issue, and a PR that says `Fixes #<their issue>` would otherwise hand that issue's
# envelope to the agent.
python3 "$PILOT/spine-github/scripts/trust_gate.py" author --issue-json "$OUT/issue.json" >&2 || {
  echo "PR #$PR works on issue #$issue, whose author is not trusted" >&2; exit 1; }
jq -r '.body // ""' "$OUT/issue.json" > "$OUT/issue-body.md"
python3 "$PILOT/spine-github/scripts/envelope_from_issue.py" \
  --body-file "$OUT/issue-body.md" --task-id "gh-$issue" --out "$OUT/envelope.json" --emit none --quiet
rm -f "$OUT/issue-body.md" "$OUT/issue.json"

printf 'head_sha=%s\nhead_ref=%s\nengine=%s\nissue=%s\n' "$head_sha" "$head_ref" "$engine" "$issue"
