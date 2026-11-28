# C-OPS-2: Environment variables

Plan section 2.6. Python reference: `612b1cb`. Round-trip coverage: **partial**.

## Contract

Required: ES_URL, ES_PASSWORD, VOYAGE_API_KEY (the server does not start without them). Defaults: index
names memory-fact/-knowledge/-episode/-stats, alias memory-all, session indices memory-session and
memory-session-message, ES_USER elastic, EMBEDDING_PROVIDER voyage, EMBEDDING_DIMENSIONS 1024,
MCP_SESSION_IDLE_TIMEOUT 1800. Inert when unset: PROXY_SHARED_SECRET (no secret check), CLIENT_POLICY
(gate off), MEMORY_AUDIENCES in the proxy (no enforcement). The proxy reads OIDC_ISSUER, OIDC_JWKS_URL,
UPSTREAM_URL, PORT, PATH_PREFIX, ALLOWED_SUBS, ALLOWED_CLIENT_IDS, PROXY_SHARED_SECRET.

## Python reference

- `memory-mcp/es_backend.py:36-47`
- `memory-mcp/voyage.py:27-35`
- `memory-mcp/identity.py:54,194,477`
- `memory-mcp/sessions_app.py:68-71`
- `auth-proxy/proxy.py:63-90`

## Test

case `env_contract`.

## Notes

Every variable is set by name in run.py; the suite does not yet enumerate each default one by one.
