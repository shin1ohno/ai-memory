# C-ES-4: Documents the keeper reads and writes

Plan section 2.4. Python reference: `612b1cb`. Round-trip coverage: **covered**.

## Contract

A fact written by the server carries what memory-keeper's merge rules read (`content`, `embedding`,
`memory_type`, `tags`, `entities`, `provenance` with agent/session_id/source_class/written_at, `use_count`,
`content_hash`, `reconcile_status`), and a document the keeper writes is readable and revisable by the
server.

## Python reference

- `memory-keeper/merge_rules.py:44-120`
- `memory-keeper/es_client.py:99-136`

## Test

case `keeper_shapes`.
