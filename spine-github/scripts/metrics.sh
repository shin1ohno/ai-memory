#!/usr/bin/env bash
# Per-engine pilot metrics for agentic implementation PRs.
#
#   bash spine-github/scripts/metrics.sh <OWNER/REPO> [--since 2026-09-01] [--cost-file costs.json]
#
# Emits the six metrics from README section 7, once per engine:
#   pr_count, merge_rate, first_ci_pass_rate, median_hours_to_merge,
#   rework_rate_7d, cost_per_merged_pr
#
# Every metric is derived from data that already exists on the PR:
#   * labels          agent:<engine>, risk:T1|T2|T3, blueprint:<id>
#   * the PR body's `agent-envelope` block, whose field names are a contract
#     (ci_fix_rounds is what makes first_ci_pass_rate computable after the fact)
#
# cost_per_merged_pr needs a cost source, which GitHub does not carry. Supply one
# with --cost-file: a JSON object of {"<engine>": {"credits": <number>, "usd": <number>}}
# or {"runs": [{"engine": "...", "credits": n, "usd": n}, ...]}. Without it the column
# reports "no-cost-source" rather than guessing.
#
# Requires: gh (authenticated), jq. Read-only: no mutation of any PR.
set -uo pipefail

REPO="${1:-}"
shift || true
SINCE=""
COST_FILE=""
LIMIT=500
ENGINES="claude codex"
FIXTURE_DIR=""

while [ $# -gt 0 ]; do
  case "$1" in
    --since) SINCE="${2:-}"; shift 2 ;;
    --cost-file) COST_FILE="${2:-}"; shift 2 ;;
    --limit) LIMIT="${2:-500}"; shift 2 ;;
    --engines) ENGINES="${2:-}"; shift 2 ;;
    # Offline mode: read <engine>.json from DIR instead of calling gh. Exists so the
    # aggregation can be tested against known inputs — a live run against a repo with
    # zero agent PRs exercises none of the parsing.
    --fixture-dir) FIXTURE_DIR="${2:-}"; shift 2 ;;
    *) printf 'unknown argument: %s\n' "$1" >&2; exit 64 ;;
  esac
done

if [ -z "$REPO" ]; then
  printf 'usage: metrics.sh <OWNER/REPO> [--since YYYY-MM-DD] [--cost-file FILE] [--limit N]\n' >&2
  exit 64
fi
command -v jq >/dev/null 2>&1 || { printf 'missing required tool: jq\n' >&2; exit 69; }
if [ -z "$FIXTURE_DIR" ]; then
  command -v gh >/dev/null 2>&1 || { printf 'missing required tool: gh\n' >&2; exit 69; }
fi

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

fetch_engine() {
  # fetch_engine <engine> -> writes $TMP/<engine>.json (array of PR objects)
  local engine="$1" query
  if [ -n "$FIXTURE_DIR" ]; then
    if [ -f "$FIXTURE_DIR/$engine.json" ]; then
      cp "$FIXTURE_DIR/$engine.json" "$TMP/$engine.json"
      return 0
    fi
    printf 'no fixture for engine %s in %s\n' "$engine" "$FIXTURE_DIR" >"$TMP/$engine.err"
    return 1
  fi
  query="label:agent:$engine"
  [ -n "$SINCE" ] && query="$query created:>=$SINCE"
  gh pr list \
    --repo "$REPO" \
    --state all \
    --limit "$LIMIT" \
    --search "$query" \
    --json number,state,title,body,labels,createdAt,mergedAt,closedAt,url \
    >"$TMP/$engine.json" 2>"$TMP/$engine.err"
}

# jq program: turn raw PR JSON into one flat record per PR, with the envelope fields
# pulled out of the body block.
read -r -d '' FLATTEN <<'JQ'
def envelope_field($name):
  (.body // "")
  | split("\n")
  | map(select(test("^\\s*" + $name + "\\s*:")))
  | if length == 0 then null
    else .[0] | sub("^\\s*" + $name + "\\s*:\\s*"; "") | sub("\\s+$"; "")
    end;
map({
  number: .number,
  url: .url,
  state: .state,
  title: .title,
  merged: (.mergedAt != null),
  createdAt: .createdAt,
  mergedAt: .mergedAt,
  labels: [.labels[].name],
  risk: ([.labels[].name | select(startswith("risk:"))] | (.[0] // "risk:unknown") | sub("^risk:"; "")),
  has_rework_label: ([.labels[].name | select(. == "rework" or startswith("rework:"))] | length > 0),
  task_id: envelope_field("task_id"),
  engine_field: envelope_field("engine"),
  ci_fix_rounds: (envelope_field("ci_fix_rounds") | if . == null then null else (tonumber? // null) end),
  ai_review_rounds: (envelope_field("ai_review_rounds") | if . == null then null else (tonumber? // null) end),
  hours_to_merge: (
    if .mergedAt == null then null
    else ((.mergedAt | fromdateiso8601) - (.createdAt | fromdateiso8601)) / 3600
    end
  )
})
JQ

# jq program: reduce flat records to the six metrics.
read -r -d '' SUMMARISE <<'JQ'
def median:
  (map(select(. != null)) | sort) as $s
  | if ($s | length) == 0 then null
    elif ($s | length) % 2 == 1 then $s[($s | length) / 2 | floor]
    else (($s[($s | length) / 2 - 1] + $s[($s | length) / 2]) / 2)
    end;
def pct($n; $d): if $d == 0 then null else (100 * $n / $d) end;
. as $prs
| ($prs | length) as $count
| ($prs | map(select(.merged)) | length) as $merged
| ($prs | map(select(.merged and .ci_fix_rounds == 0)) | length) as $first_pass
| ($prs | map(select(.merged and .ci_fix_rounds != null)) | length) as $merged_with_counter
| ($prs | map(select(.merged and .has_rework_label)) | length) as $reworked
| {
    pr_count: $count,
    merged: $merged,
    merge_rate_pct: pct($merged; $count),
    first_ci_pass_rate_pct: pct($first_pass; $merged_with_counter),
    first_ci_pass_denominator: $merged_with_counter,
    median_hours_to_merge: ($prs | map(.hours_to_merge) | median),
    rework_rate_7d_pct: pct($reworked; $merged),
    by_risk: ($prs | group_by(.risk) | map({ (.[0].risk): length }) | add // {}),
    envelope_block_missing: ($prs | map(select(.task_id == null)) | length)
  }
JQ

printf '# agentic pilot metrics\n'
printf 'repo: %s\n' "$REPO"
[ -n "$SINCE" ] && printf 'since: %s\n' "$SINCE"
printf 'generated_by: spine-github/scripts/metrics.sh\n\n'

ALL="$TMP/all.json"
printf '{}' >"$ALL"

for engine in $ENGINES; do
  if ! fetch_engine "$engine"; then
    printf '## %s\nerror: gh pr list failed\n' "$engine"
    sed 's/^/  /' "$TMP/$engine.err" 2>/dev/null
    printf '\n'
    continue
  fi
  jq "$FLATTEN" "$TMP/$engine.json" >"$TMP/$engine.flat.json"
  jq "$SUMMARISE" "$TMP/$engine.flat.json" >"$TMP/$engine.sum.json"

  cost_json='{"cost_per_merged_pr":"no-cost-source"}'
  if [ -n "$COST_FILE" ] && [ -f "$COST_FILE" ]; then
    cost_json="$(
      jq --arg e "$engine" --slurpfile s "$TMP/$engine.sum.json" '
        ( $s[0].merged ) as $merged
        | ( if has("runs")
            then ([.runs[] | select(.engine == $e)] | { credits: (map(.credits // 0) | add), usd: (map(.usd // 0) | add) })
            else (.[$e] // {}) end ) as $c
        | { cost_source: "file",
            credits_total: ($c.credits // null),
            usd_total: ($c.usd // null),
            cost_per_merged_pr: (
              if $merged == 0 or ($c.credits // null) == null then null
              else (($c.credits) / $merged) end),
            usd_per_merged_pr: (
              if $merged == 0 or ($c.usd // null) == null then null
              else (($c.usd) / $merged) end) }
      ' "$COST_FILE"
    )" || cost_json='{"cost_per_merged_pr":"cost-file-parse-error"}'
  fi

  printf '## %s\n' "$engine"
  jq -s '.[0] * .[1]' "$TMP/$engine.sum.json" <(printf '%s' "$cost_json")
  printf '\n'
  jq -s --arg e "$engine" '.[0] + { ($e): (.[1] * .[2]) }' \
    "$ALL" "$TMP/$engine.sum.json" <(printf '%s' "$cost_json") >"$TMP/all.next" \
    && mv "$TMP/all.next" "$ALL"
done

printf '## combined\n'
jq '.' "$ALL"
