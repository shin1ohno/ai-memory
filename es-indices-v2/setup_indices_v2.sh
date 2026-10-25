#!/bin/bash
# Idempotently create the memory-v2 ES indices + the memory-all alias.
# Usage: ES_URL=https://192.168.1.77:9200 ES_USER=elastic ES_PASSWORD=... \
#        setup_indices_v2.sh [indices_dir]
#
# Preflight: waits until analysis-kuromoji is present on ALL nodes (the
# ja_en_hybrid analyzer's kuromoji_tokenizer is a hard dependency — creating the
# indices before the plugin is loaded fleet-wide fails with
# unknown_tokenizer). Then PUTs the 4 indices (treating
# resource_already_exists_exception as success) and adds the memory-all alias
# over the 3 content indices (NOT memory-stats). Then the two session-search
# indices (memory-session, memory-session-message), which are never in
# memory-all. Safe to re-run.

set -euo pipefail

ES_URL="${ES_URL:?ES_URL required (e.g. https://192.168.1.77:9200)}"
ES_USER="${ES_USER:-elastic}"
ES_PASSWORD="${ES_PASSWORD:?ES_PASSWORD required}"
DIR="${1:-$(dirname "$0")}"
ES_NODES="${ES_NODES:-3}"          # expected node count carrying kuromoji
KUROMOJI_TRIES="${KUROMOJI_TRIES:-30}"
KUROMOJI_SLEEP="${KUROMOJI_SLEEP:-5}"

FACT_INDEX="${FACT_INDEX:-memory-fact}"
KNOWLEDGE_INDEX="${KNOWLEDGE_INDEX:-memory-knowledge}"
EPISODE_INDEX="${EPISODE_INDEX:-memory-episode}"
STATS_INDEX="${STATS_INDEX:-memory-stats}"
ALL_ALIAS="${ALL_ALIAS:-memory-all}"
# Session search (design spec §7.1). Deliberately NOT in memory-all.
SESSION_INDEX="${SESSION_INDEX:-memory-session}"
SESSION_MESSAGE_INDEX="${SESSION_MESSAGE_INDEX:-memory-session-message}"

es_curl() {
  curl -sk -u "${ES_USER}:${ES_PASSWORD}" "$@"
}

wait_for_kuromoji() {
  local got tries="${KUROMOJI_TRIES}"
  for _ in $(seq 1 "${tries}"); do
    # _cat/plugins lists one row per (node, plugin); count kuromoji rows.
    got=$(es_curl "${ES_URL}/_cat/plugins?h=component" 2>/dev/null \
      | grep -c '^analysis-kuromoji$' || true)
    got="${got:-0}"
    if [ "${got}" -ge "${ES_NODES}" ]; then
      echo "analysis-kuromoji present on ${got} node(s) — ok"
      return 0
    fi
    echo "waiting for analysis-kuromoji on all ${ES_NODES} node(s) (have ${got})..."
    sleep "${KUROMOJI_SLEEP}"
  done
  echo "ERROR: analysis-kuromoji not present on all ${ES_NODES} node(s) after preflight" >&2
  return 1
}

create_index() {
  local name="$1" body_file="$2" code
  code=$(es_curl -o /tmp/es-setup-v2-resp.json -w '%{http_code}' \
    -X PUT "${ES_URL}/${name}" \
    -H 'Content-Type: application/json' \
    --data-binary "@${body_file}")
  case "${code}" in
    200|201)
      echo "created index ${name}"
      ;;
    400)
      if grep -q 'resource_already_exists_exception' /tmp/es-setup-v2-resp.json; then
        echo "index ${name} already exists — ok"
      else
        echo "ERROR creating ${name}: $(cat /tmp/es-setup-v2-resp.json)" >&2
        return 1
      fi
      ;;
    *)
      echo "ERROR creating ${name} (HTTP ${code}): $(cat /tmp/es-setup-v2-resp.json)" >&2
      return 1
      ;;
  esac
}

create_alias() {
  local code
  code=$(es_curl -o /tmp/es-setup-v2-alias.json -w '%{http_code}' \
    -X POST "${ES_URL}/_aliases" \
    -H 'Content-Type: application/json' \
    --data-binary @- <<EOF
{"actions": [
  {"add": {"index": "${FACT_INDEX}",      "alias": "${ALL_ALIAS}"}},
  {"add": {"index": "${KNOWLEDGE_INDEX}", "alias": "${ALL_ALIAS}"}},
  {"add": {"index": "${EPISODE_INDEX}",   "alias": "${ALL_ALIAS}"}}
]}
EOF
  )
  case "${code}" in
    200|201)
      echo "alias ${ALL_ALIAS} → ${FACT_INDEX},${KNOWLEDGE_INDEX},${EPISODE_INDEX} — ok"
      ;;
    *)
      echo "ERROR creating alias ${ALL_ALIAS} (HTTP ${code}): $(cat /tmp/es-setup-v2-alias.json)" >&2
      return 1
      ;;
  esac
}

wait_for_kuromoji

create_index "${FACT_INDEX}"      "${DIR}/memory-fact.json"
create_index "${KNOWLEDGE_INDEX}" "${DIR}/memory-knowledge.json"
create_index "${EPISODE_INDEX}"   "${DIR}/memory-episode.json"
create_index "${STATS_INDEX}"     "${DIR}/memory-stats.json"

create_alias

# The session indices are optional here: the memory-mcp server also creates them
# at startup (sessions_app.ensure_session_indices), and a deploy whose file list
# does not yet carry their JSON must not fail the whole bootstrap.
for pair in "${SESSION_INDEX}:memory-session.json" "${SESSION_MESSAGE_INDEX}:memory-session-message.json"; do
  name="${pair%%:*}"; file="${DIR}/${pair#*:}"
  if [ -f "${file}" ]; then
    create_index "${name}" "${file}"
  else
    echo "WARN: ${file} not deployed — skipping ${name} (the server creates it at startup)" >&2
  fi
done

echo "memory-v2 ES index setup complete."
