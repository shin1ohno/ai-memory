#!/usr/bin/env bash
# Guardrail for the memory-v2 distribution units (ADR 0010), ported from setup's
# bin/check-memory-v2-manifest with the unit directories at the repository root.
# Run it through `make check-distribution`, which supplies MEMORY_MCP_PYTHON.
# Differences from setup's copy: __pycache__ directories (left by `make test`)
# are not counted as undeployed files, and the session_redact.py client-copy
# check stays in setup, where the client copy lives.
#
# For each unit (memory-mcp, memory-keeper):
#   1. MANIFEST lists every runtime file in the directory (every *.py that is
#      not a test_*.py, every prompts/*.md) — a new module that is committed
#      but not listed is exactly the #895 merge_rules.py failure (keeper
#      ModuleNotFoundError on every tick for 4 days).
#   2. every MANIFEST entry exists.
#   3. ARTIFACT INSTALL: copy ONLY the MANIFEST files into an empty directory —
#      the same file set the host receives — and import every module from
#      there with `python3 -I` (no user site, no PYTHONPATH, cwd inserted
#      explicitly). memory-keeper is stdlib-only, so this runs with the system
#      python3; memory-mcp needs its requirements-v2.txt wheels, which the
#      caller provides via MEMORY_MCP_PYTHON — when it is unset the mcp import
#      step is SKIPPED and reported as such.
#   4. the keeper's own unit tests run against the INSTALLED copy.
#
# With neither MANIFEST present (before the first import) there is nothing to
# check; it says so and exits 0. With one present, both are required.
set -euo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BASE="$REPO"
if [[ ! -f "$BASE/memory-mcp/MANIFEST" && ! -f "$BASE/memory-keeper/MANIFEST" ]]; then
  echo "check-distribution: no distribution units yet (memory-mcp/MANIFEST, memory-keeper/MANIFEST)"
  exit 0
fi
for unit in memory-mcp memory-keeper; do
  [[ -f "$BASE/$unit/MANIFEST" ]] || { echo "FAIL  $unit/MANIFEST is missing while the other unit exists"; exit 1; }
done
fail=0
T=$(mktemp -d "${TMPDIR:-/tmp}/memory-v2-artifact.XXXXXX"); trap 'rm -rf "$T"' EXIT

# Normalize the same way the cookbook's compile-time loader does
# (`.map(&:strip)` in cookbooks/lxc-es-memory/default.rb) — otherwise a
# MANIFEST line the cookbook accepts (" scoring.py ", trailing CR) can
# mismatch the checker's own file-exists / shape checks (review D5).
manifest_entries() { grep -vE '^\s*(#|$)' "$BASE/$1/MANIFEST" | sed 's/\r$//; s/^[[:space:]]*//; s/[[:space:]]*$//'; }

for unit in memory-mcp memory-keeper; do
  echo "== $unit"
  dir="$BASE/$unit"
  # 1. EVERY file in the unit directory is either a listed runtime file, a
  #    test (test_*.py, CI-only), or the MANIFEST itself. Any other file —
  #    data, templates, nested modules, symlinks — FAILS: the cookbook does
  #    not deploy it and this unit's shape does not allow it (review F3).
  while IFS= read -r f; do
    case "$f" in MANIFEST|test_*.py) continue ;; esac
    grep -qxF "$f" "$dir/MANIFEST" || { echo "FAIL  $unit: $f exists but is not in MANIFEST (would not be deployed)"; fail=1; }
  done < <(cd "$dir" && find . -mindepth 1 -name __pycache__ -prune -o \( -type f -o -type l \) -print | sed 's#^\./##' | sort)
  # 2. every listed file exists AND has a shape the cookbook can deploy: a
  #    top-level *.py for both units, plus prompts/*.md ONLY for memory-keeper
  #    — its recipe creates keeper_dir/prompts before the MANIFEST loop;
  #    memory-mcp's loop has no such directory resource, so a prompts/*.md
  #    entry there would pass this check and then fail on the LXC with
  #    `cp: No such file or directory` (review D1). A deeper path than either
  #    shape would pass a copy-based check and fail the same way (review F2).
  #    A symlink entry is also rejected here: `-f` follows the link and `cp`
  #    copies the link's target content, so a symlink can smuggle in a file
  #    outside the unit's own directory (review D3).
  while IFS= read -r f; do
    [[ -f "$dir/$f" ]] || { echo "FAIL  $unit: MANIFEST lists $f but it does not exist"; fail=1; }
    [[ -L "$dir/$f" ]] && { echo "FAIL  $unit: MANIFEST entry $f is a symlink — not a plain file the cookbook can deploy"; fail=1; }
    shape_ok=0
    [[ "$f" =~ ^[A-Za-z0-9_]+\.py$ ]] && shape_ok=1
    [[ "$unit" == memory-keeper && "$f" =~ ^prompts/[A-Za-z0-9_-]+\.md$ ]] && shape_ok=1
    [[ $shape_ok -eq 1 ]] \
      || { echo "FAIL  $unit: MANIFEST entry $f is not a shape this unit's cookbook recipe creates a directory for (top-level .py; prompts/*.md only for memory-keeper)"; fail=1; }
  done < <(manifest_entries "$unit")
  # 3. artifact install into an empty dir
  inst="$T/$unit"; mkdir -p "$inst"
  while IFS= read -r f; do
    mkdir -p "$inst/$(dirname "$f")"; cp "$dir/$f" "$inst/$f"
  done < <(manifest_entries "$unit")
  mods=$(manifest_entries "$unit" | grep -E '^[^/]+\.py$' | sed 's/\.py$//' | tr '\n' ' ')
  # server.py runs `asyncio.run(be.ensure_indices())` at IMPORT time (ES
  # bootstrap coupled to module load), so a hermetic import would try to reach
  # ES. It is byte-compiled AND its third-party import lines (mcp / starlette /
  # httpx / uvicorn) are executed against the real wheels — the mcp 2.x
  # `mcp.server.fastmcp` removal that crash-looped the unit in 2026-08 is
  # exactly an import-line failure (review F7). The four leaf modules import
  # for real. Decoupling the bootstrap into the lifespan is the next step.
  compile_only=""
  if [[ "$unit" == memory-mcp ]]; then compile_only="server"; mods=$(tr ' ' '\n' <<<"$mods" | grep -vx server | tr '\n' ' '); fi
  py=python3
  if [[ "$unit" == memory-mcp ]]; then
    if [[ -n "${MEMORY_MCP_PYTHON:-}" ]]; then py="$(cd "$(dirname "$MEMORY_MCP_PYTHON")" && pwd)/$(basename "$MEMORY_MCP_PYTHON")"; else
      echo "SKIP  $unit: import check needs requirements-v2.txt wheels — set MEMORY_MCP_PYTHON"; py=""; fi
  fi
  # Import-time REQUIRED env (os.environ["..."] at module top level). The systemd
  # units get these from the generated env file; the artifact check supplies
  # placeholders — it proves the file set is complete and importable, it does
  # not talk to ES or Voyage.
  export VOYAGE_API_KEY="${VOYAGE_API_KEY:-artifact-check-placeholder}"
  export ES_URL="${ES_URL:-http://127.0.0.1:9}"          # port 9 = discard; nothing connects at import
  export ES_PASSWORD="${ES_PASSWORD:-artifact-check-placeholder}"
  if [[ -n "$py" ]]; then
    # -I isolates (no user site, no env) and drops cwd from sys.path; the units
    # run as `python3 /opt/.../<module>.py`, which puts the install dir first on
    # sys.path — insert cwd explicitly to match that and nothing else.
    if (cd "$inst" && "$py" -I -c "import importlib,os,sys; sys.path.insert(0, os.getcwd()); [importlib.import_module(m) for m in sys.argv[1:]]" $mods 2>"$T/$unit.err") \
       && { [[ -z "$compile_only" ]] || (cd "$inst" && "$py" -I -m py_compile "$compile_only.py" 2>>"$T/$unit.err"); } \
       && { [[ -z "$compile_only" ]] || (cd "$inst" && grep -hE '^(from|import) (mcp|starlette|httpx|uvicorn)\b' "$compile_only.py" | "$py" -I - 2>>"$T/$unit.err"); }; then
      echo "PASS  $unit: installed artifact imports cleanly ($mods)${compile_only:+; $compile_only.py byte-compiles + its mcp/starlette import lines resolve against the wheels (import-time ES bootstrap keeps the module itself un-importable here, ADR 0010)}"
    else
      echo "FAIL  $unit: import from the installed artifact failed:"; sed 's/^/      /' "$T/$unit.err"; fail=1
    fi
  fi
  # 4. unit tests against the installed copy
  if [[ "$unit" == memory-keeper ]]; then
    if (cd "$inst" && cp "$dir"/test_*.py . && python3 -I test_merge_rules.py >"$T/keeper-tests.log" 2>&1); then
      echo "PASS  $unit: test_merge_rules.py against the installed copy"
    else
      echo "FAIL  $unit: keeper tests against the installed copy:"; tail -20 "$T/keeper-tests.log" | sed 's/^/      /'; fail=1
    fi
  fi
done
[[ $fail -eq 0 ]] && echo "OK: memory-v2 distribution units are complete and importable." || { echo "FAIL: see above"; exit 1; }
