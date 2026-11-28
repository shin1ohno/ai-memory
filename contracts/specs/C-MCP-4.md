# C-MCP-4: Tool responses

Plan section 2.1. Python reference: `612b1cb`. Round-trip coverage: **covered**.

## Contract

For a fixed store the eight tools return the shapes recorded in `contracts/golden/C-MCP-4/`. In
particular: recall hits carry `id`, `doc_id`, `chunk_index`, `dataset`, `doc_key`, `content`, `type`
(renamed from the stored `memory_type`), `score`, `tags`, `provenance`, `superseded:false`; at most one hit
per document; `degraded: "bm25-only"` appears only when the embedding leg failed. get returns the
`_source` minus `embedding`, plus `id`, `chain` and, for a document id, the joined `content` and
`chunk_count`. browse returns `items`, `total`, `truncated`, `total_is_lower_bound`. memory_stats returns
`counts`, `raw_backlog`, `keeper`, `ingest_jobs`. revise returns `new_id`; forget `superseded_count`.

## Python reference

- `memory-mcp/server.py:143-175 (recall rename-only pass-through, degraded)`
- `memory-mcp/es_backend.py:513-625 (recall)`
- `memory-mcp/es_backend.py:1057-1078 (get)`
- `memory-mcp/es_backend.py:1139-1182 (browse)`
- `memory-mcp/es_backend.py:1185-1223 (stats)`

## Test

case `tool_responses` (an 18-step scenario over all tools, plus a degraded recall); goldens `contracts/golden/C-MCP-4/`.
