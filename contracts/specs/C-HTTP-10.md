# C-HTTP-10: No query strings in logs

Plan section 2.2. Python reference: `612b1cb`. Round-trip coverage: **covered**.

## Contract

Neither the proxy nor the server writes request query strings to stdout or stderr. The proxy logs method
and path; uvicorn runs with `--no-access-log`.

## Python reference

- `auth-proxy/proxy.py:373,624 (path only, access_log=None)`
- `systemd/memory-mcp-v2.service:44-48`

## Test

case `no_query_logging` (sentinel in the query, positive control on the path).
