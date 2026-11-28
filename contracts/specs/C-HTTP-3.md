# C-HTTP-3: OAuth protected-resource metadata

Plan section 2.2. Python reference: `612b1cb`. Round-trip coverage: **covered**.

## Contract

`GET /.well-known/oauth-protected-resource` answers 200 without authentication with
`{"resource": OIDC_ISSUER + PATH_PREFIX, "authorization_servers": [OIDC_ISSUER],
"scopes_supported": ["mcp:read","mcp:write","mcp:admin"], "bearer_methods_supported": ["header"]}`,
`Cache-Control: public, max-age=3600` and CORS. Every other path under `/.well-known/` answers 404
`{"error":"not_found"}` and is not forwarded, including dot segments that would resolve elsewhere.

## Python reference

- `auth-proxy/proxy.py:323-328 (RESOURCE_ID, WWW_AUTH)`
- `auth-proxy/proxy.py:383-399`

## Test

case `well_known`.

## Notes

Changed by #32 (612b1cb): the plan's text says other `.well-known` paths are passed through to the upstream. Since #32 they are 404 and never forwarded (forwarding was an authentication bypass). This spec follows 612b1cb.
