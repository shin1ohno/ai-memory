# C-MCP-8: Provenance and the destructive-op matrix

Plan section 2.1. Python reference: `612b1cb`. Round-trip coverage: **covered**.

## Contract

Provenance is built only from `X-Verified-Grant`, `X-Verified-Sub`, `X-Verified-Client-Id`; tool arguments
cannot set it. `agent` is client_id for client_credentials and sub otherwise. Facts written by an
authorization_code caller are `user-stated`, by a machine caller `tool-output`; knowledge is
`tool-output`, episodes `reflection`. forget/revise: a `user-stated` target only by authorization_code;
authorization_code anything else; client_credentials only targets whose `provenance.agent` is its own
client_id; anything else denied. With PROXY_SHARED_SECRET set, a request without the matching
`X-Proxy-Secret` gets no identity.

## Python reference

- `memory-mcp/identity.py:90-139 (secret check, parse_identity, build_provenance)`
- `memory-mcp/identity.py:142-158 (authorize_supersede)`
- `memory-mcp/server.py:186-244 (source classes)`

## Test

case `provenance_matrix`: stamping with forged arguments, and 3 target classes x 3 callers.
