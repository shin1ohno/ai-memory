#!/usr/bin/env bash
# Export the unresolved AI-review threads of one pull request as JSON.
#
#   review_threads.sh <pr-number> <out.json>
#
# Output: [{"thread_id", "comment_id", "path", "line", "body"}]
# where comment_id is the REST id of the thread's first comment (the id a reply is posted
# against) and thread_id the GraphQL node id (the id a thread is resolved by).
#
# Only threads the AI reviewer opened are exported: the address node answers the AI review,
# and a human reviewer's thread is theirs to close. The reviewer posts as github-actions;
# GraphQL reports a bot's login without the "[bot]" suffix REST uses, so both are accepted.
#
# The address node calls this twice: before the agent runs (what it reads) and again in the
# publish job (what its replies are checked against), so nothing the agent job wrote decides
# which comments receive a reply.
#
# Only the comment that opens a thread is exported, never the replies under it. The repository
# is public: anyone can reply in a thread, and threads.json is what the agent reads, so a reply
# would hand a stranger a line into the agent's prompt.
set -euo pipefail
PR="${1:?pr number}"; OUT="${2:?out file}"
: "${GH_TOKEN:?GH_TOKEN}"; : "${REPO:?REPO}"
case "$PR" in ''|*[!0-9]*) echo "refusing non-numeric PR" >&2; exit 1 ;; esac
owner="${REPO%%/*}"; name="${REPO##*/}"

gh api graphql -F owner="$owner" -F name="$name" -F pr="$PR" -f query='
  query($owner:String!,$name:String!,$pr:Int!){repository(owner:$owner,name:$name){
    pullRequest(number:$pr){reviewThreads(first:100){nodes{
      id isResolved path line
      comments(first:30){nodes{databaseId body author{login}}}}}}}}' \
| jq '[.data.repository.pullRequest.reviewThreads.nodes[]
        | select(.isResolved | not)
        | select((.comments.nodes[0].author.login // "") | IN("github-actions", "github-actions[bot]"))
        | {thread_id: .id,
           comment_id: .comments.nodes[0].databaseId,
           path, line,
           body: .comments.nodes[0].body}]' > "$OUT"
printf 'unresolved AI-review threads: %s\n' "$(jq 'length' "$OUT")" >&2
