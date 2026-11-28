# C-MCP-10: Session lifetime

Plan section 2.1. Python reference: `612b1cb`. Round-trip coverage: **partial**.

## Contract

An unknown session id is 404. A session expires when it has had no request in flight and no open
standalone GET for `MCP_SESSION_IDLE_TIMEOUT` seconds (default 1800); an open GET keeps it alive and
closing it starts the clock; a tools/call slower than the timeout completes and the session survives; every
request resets the clock. DELETE ends the session (then 404). At most 10,000 sessions; one more is 503.

## Python reference

- `memory-mcp/server.py:82-84 (MCP_SESSION_IDLE_TIMEOUT)`
- `.venv mcp 1.30.0 streamable_http_manager.py:43-45,99-118,300-320 (defaults 1800 s and 10,000; 503)`

## Test

case `session_lifetime` with the timeout shortened to 2 s: unknown id, (a)-(d), DELETE.

## Notes

Not exercised: the 10,000-session cap and its 503 (opening 10,000 sessions per run is too slow for the suite). The cap is not configurable through the environment in server.py, so a short test needs an env knob first.
