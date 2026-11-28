# C-HTTP-4: 401 and 403 bodies

Plan section 2.2. Python reference: `612b1cb`. Round-trip coverage: **covered**.

## Contract

No `Bearer ` authorization: 401, JSON-RPC body `{"jsonrpc":"2.0","id":null,"error":{"code":-32001,
"message":"unauthorized"}}`, `WWW-Authenticate: Bearer resource_metadata="<RESOURCE_ID>/.well-known/
oauth-protected-resource"`. A token that fails verification: 401, message `invalid_token`,
`WWW-Authenticate: Bearer error="invalid_token", resource_metadata="..."`. With MEMORY_AUDIENCES set, a
client_credentials token without an allowed audience or client id: 403 code -32003 `forbidden_audience`; an
authorization_code token whose sub is not in ALLOWED_SUBS: 403 -32003 `forbidden_subject`. Refused
requests are not forwarded.

## Python reference

- `auth-proxy/proxy.py:353-369`
- `auth-proxy/proxy.py:401-467`

## Test

case `auth_errors`.
