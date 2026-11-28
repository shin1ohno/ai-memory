# C-MAINT-1: Session maintenance run

Plan section 2.7. Python reference: `612b1cb`. Round-trip coverage: **partial**.

## Contract

`sessions_maint.py run` is the only accepted invocation (anything else exits 64). A held flock exits 0
without touching ES. Retention: sessions not updated for SESSION_RETENTION_DAYS (365) become purge markers;
markers older than SESSION_MARKER_DAYS (30) are removed. A run records a `memory-stats` document with
`run_kind=session-maint`, `expired_deleted`, `errors`, `loop_lag_ms`, `host`, `written_at`; any counted
error exits 1.

## Python reference

- `memory-mcp/sessions_maint.py:30-40,65`
- `memory-mcp/sessions_maint.py:178-230`
- `memory-mcp/sessions_maint.py:403-475`
- `systemd/memory-session-maint.service:17,20`

## Test

case `session_maint`.

## Notes

Boundaries are tested 30 s either side, not ±1 s: the suite cannot fix the CLI's clock.
