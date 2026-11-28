# C-HTTP-2: Health

Plan section 2.2. Python reference: `612b1cb`. Round-trip coverage: **covered**.

## Contract

`GET /health` answers 200 `{"status":"ok"}` with the CORS headers, without authentication.

## Python reference

- `auth-proxy/proxy.py:379-381`

## Test

case `health`.
