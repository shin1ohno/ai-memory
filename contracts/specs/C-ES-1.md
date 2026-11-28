# C-ES-1: Index definitions

Plan section 2.4. Python reference: `612b1cb`. Round-trip coverage: **covered**.

## Contract

At startup the server PUTs six indices whose bodies equal `es-indices-v2/*.json` (the session indices'
replica count comes from SESSION_INDEX_REPLICAS), adds `memory-all` over memory-fact, memory-knowledge and
memory-episode only, and checks the session indices' `_meta.schema` (`session/1`,
`session-message/1`). ES 9.4.2.

## Python reference

- `memory-mcp/es_backend.py:315-405 (_ANALYSIS, _common_props, _INDEX_DEFS)`
- `memory-mcp/es_backend.py:444-495`
- `memory-mcp/sessions_app.py:144-224`
- `es-indices-v2/*.json`

## Test

case `index_definitions`.
