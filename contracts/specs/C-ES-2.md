# C-ES-2: REST semantics

Plan section 2.4. Python reference: `612b1cb`. Round-trip coverage: **covered**.

## Contract

Per tool the method, path, query and body sent to ES are those in `contracts/golden/C-ES-2/`: writes with
`refresh=wait_for`, bulk with `refresh=true`, the tag union with `retry_on_conflict=3`, update_by_query with
`conflicts=proceed` (and `refresh=true` for supersede), recall's BM25 then kNN search, the fire-and-forget
use_count bump on the top three hits.

## Python reference

- `memory-mcp/es_backend.py:264-304`
- `memory-mcp/es_backend.py:513-625,632-698,799-1251`

## Test

case `rest_semantics` over the C-MCP-4 scenario.
