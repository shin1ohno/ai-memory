# C-ES-5: Least-privilege start

Plan section 2.4. Python reference: `612b1cb`. Round-trip coverage: **covered**.

## Contract

`PUT /<index>` or `POST /_aliases` answering 403 counts as success when the index (HEAD 200) or alias
(GET /_alias) already exists. When it does not, startup retries 10 times 3 s apart and the process exits
non-zero. Missing session indices never stop the MCP server: tools/call works, session routes are 503,
`GET /status` is 200 `ready:false`.

## Python reference

- `memory-mcp/es_backend.py:417-495`
- `memory-mcp/server.py:359-369`
- `memory-mcp/sessions_app.py:205-240,1550-1572`

## Test

case `least_privilege` (about 36 s).
