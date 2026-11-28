# C-MCP-6: Error text prefixes

Plan section 2.1. Python reference: `612b1cb`. Round-trip coverage: **covered**.

## Contract

A CLIENT_POLICY refusal is a tool result with `isError: true` whose text is exactly
`policy_denied: this client is not permitted to make this call` (the reason stays server-side). A failure
inside a tool body is `isError: true` with text `Error executing tool <name>: <message>`. An unknown tool
is `isError: true`, `Unknown tool: <name>`. The messages after the prefix for QueryError and not-found
cases are recorded in the golden and are part of the contract.

## Python reference

- `memory-mcp/identity.py:205-207 (POLICY_DENIED_MESSAGE)`
- `memory-mcp/policy_mcp.py:51-58 (gate raises before the tool)`
- `memory-mcp/es_backend.py:191-217 (QueryError texts)`
- `hooks/mirror-file-memory.rb:860 (hook matches the prefix)`

## Test

case `error_prefixes`.
