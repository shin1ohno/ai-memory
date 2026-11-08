# TODO

Follow-up work for the files that moved here from shin1ohno/setup (ADR 0013).
A path marked "(setup)" lives in that repository.

## Auth-proxy resource isolation needs a re-audit (Low, review needed)

- **Failure class**: `auth-proxy/proxy.py` passes `options={"verify_aud": False}`
  on the raw JWT signature-decode path, so the decode itself does not check the
  audience. A token issued for another resource could be replayed here unless a
  later check rejects it.
- **Current state**: the proxy now adds an audience and subject matrix at
  authorization time. `client_credentials` grants require
  `aud ∩ MEMORY_AUDIENCES` and `client_id ∈ ALLOWED_CLIENT_IDS` (otherwise 403
  `forbidden_audience`). `authorization_code` tokens from claude.ai carry
  `aud=[]`, so the audience is not required on that path. The original
  "audience enforcement infeasible" conclusion predates this matrix, so whether
  the gap is already closed needs a fresh audit against the current code.
- **Why it matters**: this is a defense-in-depth gap, not a multi-tenant
  isolation failure. Only the owner passes the consent allow-list, so exploiting
  it needs a token leak and a second principal to isolate from.
- **Options if a gap remains after the re-audit** (each needs design):
  1. RFC 8707: have claude.ai send `resource=https://mcp.ohno.be/<svc>`, have
     Hydra and the consent app populate `aud` from
     `grant_access_token_audience`, then enforce the audience in the proxy.
     Correct, but the largest change.
  2. Scope-based isolation: mint and enforce a per-resource scope claim. First
     confirm which `scope` a real claude.ai token carries.
  3. Keep it as a documented known limitation.
- **First step**: re-run the log-first probe against the proxy to confirm the
  claim shapes (`aud` and `scope` on a real claude.ai token and on the monitoring
  `client_credentials` prober), then decide whether the matrix suffices or
  option 1 or 2 is still wanted.

Moved from shin1ohno/setup@056169f.

## Nothing catches a keeper file that is imported but never deployed (Medium)

- **Failure class**: `systemd/memory-keeper-reconcile.service` crashed on every
  tick from 2026-08-26 19:26 to 2026-08-29 16:00 with `ModuleNotFoundError: No
  module named 'merge_rules'`. `memory-keeper/merge_rules.py` and its import in
  `memory-keeper/reconcile.py` and `memory-keeper/consolidate.py` were added
  without the matching entry in the deploy map then held in
  `cookbooks/lxc-es-memory/default.rb` (setup).
- **Why it matters**: `memory-keeper-health.sh` reports
  `memory_keeper_raw_backlog` and `memory_keeper_stats_age_seconds`, and neither
  moved when the unit died. Backlog stayed 0 because nothing was arriving, so a
  permanently failing oneshot with an empty queue looked identical to a healthy
  idle one.
- **First step**: confirm whether `.github/ci/check-distribution.sh` fails when a
  module imported by a keeper file is absent from `memory-keeper/MANIFEST`, and
  add that check if it does not. The unit's exit status is tracked separately as
  the `memory_keeper_reconcile_last_exit_code` metric.

Moved from shin1ohno/setup@056169f.

## memory-mirror follow-ups after the first rollout (Medium)

- **Failure class**: the machine client `memory-mirror` (CLIENT_POLICY:
  ingest,forget@file-memory) shipped with accepted gaps.
  - `_supersede_prior_doc` in `memory-mcp/es_backend.py` supersedes any
    `file-memory` doc with the same doc_key, whoever wrote it. That was needed
    once so the first sweep could take over the 105 docs migrated by hand on
    2026-09-26, but a leaked credential can overwrite other hosts' docs.
  - `PROXY_SHARED_SECRET` is unset on CT 119, so a local process there can forge
    `X-Verified-*` and bypass the policy. Once it is set, read tools also need
    it, because the gate parses identity on every tools/call.
  - CT 119 has no persistent journald, so `POLICY` and `AUDIT deny` lines are
    lost on restart.
  - memory-work runs the same server code. `memory-mcp/server.py` falls back to
    an ungated FastMCP when `memory-mcp/policy_mcp.py` is absent and
    CLIENT_POLICY is unset. Whether that deployment should adopt a CLIENT_POLICY
    of its own is undecided.
  - neo has been offline since before the rollout. It needs the interactive
    darwin apply, `--check` and a first manual `--sweep` when it returns.
- **Why it matters**: each gap weakens the per-client policy that the mirror
  credential is supposed to be confined by.
- **First step**: after the first sweep on every personal host, add a
  `provenance.agent` condition to `_supersede_prior_doc` for client_credentials
  callers (or split into per-host clients bound to a doc_key prefix), then set
  `PROXY_SHARED_SECRET` in `systemd/memory-mcp-v2.service` and
  `systemd/memory-v2-proxy.service`.

Moved from shin1ohno/setup@056169f.
