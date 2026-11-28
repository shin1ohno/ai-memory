# C-HTTP-1: CORS preflight

Plan section 2.2. Python reference: `612b1cb`. Round-trip coverage: **covered**.

## Contract

`OPTIONS` on any path answers 204 without authentication, never reaches the upstream, and carries exactly
`Access-Control-Allow-Origin: *`, `Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS`,
`Access-Control-Allow-Headers: Content-Type, Authorization, Accept`,
`Access-Control-Expose-Headers: WWW-Authenticate`, `Access-Control-Max-Age: 86400`.

## Python reference

- `auth-proxy/proxy.py:305-311 (CORS_HEADERS)`
- `auth-proxy/proxy.py:375-377`

## Test

case `options`.
