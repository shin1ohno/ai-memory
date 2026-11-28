# C-SES-7: SESSION_SCOPE_POLICY

Plan section 2.2. Python reference: `612b1cb`. Round-trip coverage: **covered**.

## Contract

JSON `{"rules":[{"match":{grant?,client_id?,sub?},"host":str|null,"scopes":[...]}]}`, parsed strictly:
anything unexpected (12 kinds in the suite) makes the policy deny-all with a `SESSIONS scope-policy
deny-all reason=...` line. The first rule whose match fits decides; a later rule is never consulted. The
rule's host is the caller's host: a write to another host's body or session is 403 `host_mismatch`, a
host-less identity cannot ingest (403 `host_mismatch`) but may purge any host. Reads are not host-scoped.

## Python reference

- `memory-mcp/identity.py:462-567`
- `memory-mcp/sessions_app.py:635-650,1006-1009`

## Test

case `scope_policy`.
