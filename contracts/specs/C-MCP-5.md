# C-MCP-5: remember routing

Plan section 2.1. Python reference: `612b1cb`. Round-trip coverage: **covered**.

## Contract

`type` is `fact`, `knowledge`, `episode` or `auto`. `auto` routes to `episode` when the content has a date
or a first-person/session marker and to `knowledge` otherwise, never to `fact`. The response carries
`action`, `id`, `routed_type`, `reason`, and for facts `reconcile_status`; a fact that already exists
(content_hash) is a `noop` with the existing id, and new tags on it are unioned in and reported as
`tags_added`. Knowledge is an upsert keyed by `content_hash(content)`; omitting tags keeps the superseded
version's tags. An unknown type answers `action: "noop"` with `reason: "unknown type '...'"`.

## Python reference

- `memory-mcp/server.py:125-137 (auto routing)`
- `memory-mcp/server.py:178-247 (remember)`
- `memory-mcp/es_backend.py:632-698 (remember_fact, dedup and tag union)`

## Test

case `remember_routing`: 4 types x (new, tagged, duplicate) + a dated auto + an unknown type.
