# C-SES-2: Session gate

Plan section 2.2. Python reference: `612b1cb`. Round-trip coverage: **covered**.

## Contract

PROXY_SHARED_SECRET unset: every request 403 `gate_unconfigured`. Secret missing or wrong: 401
`unauthenticated`. A raw path containing `%2f`, `%5c`, `%2e` (any case) or a `.`/`..` segment: 403
`forbidden`. Until both session indices exist with the expected `_meta.schema`, every route except
`GET /status` answers 503 `index_unavailable`; `GET /status` answers 200 with `ready:false` and an `error`.

## Python reference

- `memory-mcp/sessions_app.py:1519-1540`
- `memory-mcp/sessions_app.py:1550-1572`
- `memory-mcp/sessions_app.py:1464-1477 (status)`
- `memory-mcp/identity.py:570-573`

## Test

case `gate`.

## Notes

The `error` text of a not-ready status is the implementation's diagnostic; only its presence is compared.
