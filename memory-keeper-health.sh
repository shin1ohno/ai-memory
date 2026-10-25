#!/bin/bash
# memory-keeper-health.sh — write memory-keeper reconcile-loop health as
# node_exporter textfile metrics so Prometheus (already scraping this LXC on
# :9100) can alert on a stalled reconcile/consolidate loop.
#
# Reuses the es-cluster-health.sh textfile pattern (mktemp -> mv -> chmod; no
# separate exporter binary, no new Prometheus scrape job). Runs on the
# es-memory LXC via memory-keeper-health.timer (every ~60s) and talks to the
# REMOTE ES cluster (192.168.1.77) — ES_VERIFY_CERTS=false so curl uses -k.
#
# Two health signals:
#   memory_keeper_raw_backlog        — memory-fact docs still reconcile_status=raw
#                                      (the keeper's outstanding reconcile queue)
#   memory_keeper_stats_age_seconds  — seconds since the latest memory-stats
#                                      self-report doc; a growing age = a stalled
#                                      keeper loop (mini's reconcile/consolidate
#                                      cron stopped writing stats)
# Both use -1 as the "ES unreachable / never" sentinel (matches es-cluster-health).
set -uo pipefail

ENV_FILE="${ENV_FILE:-/opt/es-memory/memory-v2.env}"
TEXTFILE_DIR="${TEXTFILE_DIR:-/var/lib/node_exporter/textfile}"
OUT="${TEXTFILE_DIR}/memory-keeper-health.prom"
FACT_INDEX="${FACT_INDEX:-memory-fact}"
STATS_INDEX="${STATS_INDEX:-memory-stats}"

# Load ES creds the metacharacter-safe way (matches es-cluster-health.sh):
# ES_PASSWORD may contain shell metacharacters that `source` would mangle.
if [[ -f "${ENV_FILE}" ]]; then
  while IFS='=' read -r __k __v; do
    [[ "${__k}" =~ ^[[:space:]]*# ]] && continue
    [[ -z "${__k// }" ]] && continue
    eval "${__k}=\$__v"
  done < "${ENV_FILE}"
fi

ES_URL="${ES_URL:-https://192.168.1.77:9200}"
ES_USER="${ES_USER:-elastic}"

raw_backlog="-1"
stats_age="-1"
now=$(date +%s)

if [[ -n "${ES_PASSWORD:-}" ]]; then
  # Reconcile backlog: memory-fact docs still awaiting reconcile.
  cnt=$(curl -sS -k --max-time 10 -u "${ES_USER}:${ES_PASSWORD}" \
    -H 'Content-Type: application/json' \
    "${ES_URL}/${FACT_INDEX}/_count" \
    -d '{"query":{"term":{"reconcile_status":"raw"}}}' 2>/dev/null || true)
  parsed=$(grep -oE '"count":[0-9]+' <<<"${cnt}" | head -1 | grep -oE '[0-9]+$')
  [[ -n "${parsed}" ]] && raw_backlog="${parsed}"

  # Latest memory-stats self-report age. docvalue_fields with epoch_millis
  # gives bash an integer to subtract without ISO-8601 parsing — but ES returns
  # it as a QUOTED string ("fields":{"written_at":["1787988186553"]}), not a
  # bare number, so the extraction below must tolerate the quote. Without the
  # optional `"` this grep never matches and stats_age is pinned to its -1
  # never-written sentinel forever, which reads as "keeper idle" rather than
  # "metric dead" — see the 2026-08-29 reconcile outage that it failed to show.
  stats=$(curl -sS -k --max-time 10 -u "${ES_USER}:${ES_PASSWORD}" \
    -H 'Content-Type: application/json' \
    "${ES_URL}/${STATS_INDEX}/_search" \
    -d '{"size":1,"_source":false,"sort":[{"written_at":"desc"}],"docvalue_fields":[{"field":"written_at","format":"epoch_millis"}]}' 2>/dev/null || true)
  ts=$(grep -oE '"written_at":\["?[0-9]+' <<<"${stats}" | grep -oE '[0-9]+' | head -1)
  [[ -n "${ts}" ]] && stats_age=$(( now - ts / 1000 ))
fi

mkdir -p "${TEXTFILE_DIR}"
tmp=$(mktemp "${OUT}.XXXXXX")
trap 'rm -f "${tmp}"' EXIT
{
  echo "# HELP memory_keeper_raw_backlog memory-fact docs awaiting reconcile (reconcile_status=raw); -1 = ES unreachable"
  echo "# TYPE memory_keeper_raw_backlog gauge"
  echo "memory_keeper_raw_backlog ${raw_backlog}"
  echo "# HELP memory_keeper_stats_age_seconds Seconds since the latest memory-stats self-report (-1 = unknown/never)"
  echo "# TYPE memory_keeper_stats_age_seconds gauge"
  echo "memory_keeper_stats_age_seconds ${stats_age}"
  echo "# HELP memory_keeper_health_scrape_timestamp_seconds Unix time of last keeper health probe"
  echo "# TYPE memory_keeper_health_scrape_timestamp_seconds gauge"
  echo "memory_keeper_health_scrape_timestamp_seconds ${now}"
} > "${tmp}"
mv "${tmp}" "${OUT}"
trap - EXIT
chmod 0644 "${OUT}"
