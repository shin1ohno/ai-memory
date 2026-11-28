# C-MCP-1: Tool definitions

Plan section 2.1. Python reference: `612b1cb`. Round-trip coverage: **covered**.

## Contract

The server registers exactly eight tools: `recall`, `remember`, `ingest`, `revise`, `forget`, `get`,
`browse`, `memory_stats`. Their names, argument names, types, defaults, descriptions and annotations
(`readOnlyHint` on recall/get/browse/memory_stats, `idempotentHint` on ingest, `destructiveHint` on
revise/forget) and recall's `_meta["anthropic/alwaysLoad"] = true` are frozen as the `tools/list`
result in `contracts/mcp-tools.json`. A new implementation returns that JSON as is; `tools/list` is not
filtered by caller (visibility is not authorization).

## Python reference

- `memory-mcp/server.py:92-108 (alwaysLoad meta)`
- `memory-mcp/server.py:143-343 (the eight tools)`
- `memory-mcp/policy_mcp.py:10-11 (tools/list is not filtered)`

## Test

case `tools_list`; compares the live `tools/list` result with `contracts/mcp-tools.json`.
