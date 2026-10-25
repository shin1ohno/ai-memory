#!/usr/bin/env bash
# [D] Grade an agent patch before it touches the working tree.
#
# usage: grade_patch.sh <patch> <envelope.json> <out-list>
#
# Run it from a copy of spine-github taken before any patch is applied (the publish job
# copies the default branch's spine-github aside first). The patch is applied to a
# throwaway index built from HEAD, so the change comes from the patch itself, not from the
# list the agent job reported. Then check_patch.py — the copy next to this script — grades
# it against the envelope, the protected lists and the base tree.
#
# <out-list> receives `git diff --cached --no-renames --raw --no-abbrev -z HEAD` of that
# throwaway index: modes, OIDs, statuses and paths. The caller takes the same diff after
# its real `git apply --index` and compares the two byte for byte, so what it commits is
# exactly what was graded here.
#
# Environment:
#   PROTECTED_BASE_DIR        the checkout whose HEAD is the base the agent PR targets
#                             (default: the current directory). `.github/agent-protected.txt`
#                             is read from that commit, never from a tree the patch reached.
#   AGENT_PROTECTED_REQUIRED  "true" refuses every patch when the base has no such list.
set -euo pipefail

if [ "$#" -ne 3 ]; then
  echo "usage: grade_patch.sh <patch> <envelope.json> <out-list>" >&2
  exit 2
fi
patch="$1"
envelope="$2"
out="$3"
here="$(cd "$(dirname "$0")" && pwd)"
base_dir="${PROTECTED_BASE_DIR:-.}"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

ap=()
if git -C "$base_dir" show HEAD:.github/agent-protected.txt > "$tmp/agent-protected.txt" 2>/dev/null; then
  ap=(--agent-protected-file "$tmp/agent-protected.txt")
fi
git ls-tree -r -z --name-only --full-tree HEAD > "$tmp/base-files"

export GIT_INDEX_FILE="$tmp/index"
git read-tree HEAD
git apply --cached "$patch"

# --no-renames lists a rename as its deletion and its addition, so a protected file moved
# elsewhere is graded under its old path too. --raw carries the modes, so a symlink
# (120000) or a submodule (160000) is refused by check_patch.py.
git diff --cached --no-renames --raw --no-abbrev -z HEAD > "$out"
python3 "$here/check_patch.py" --raw-file "$out" --base-files "$tmp/base-files" \
  "${ap[@]}" --protected-required "${AGENT_PROTECTED_REQUIRED:-}" --envelope "$envelope"
