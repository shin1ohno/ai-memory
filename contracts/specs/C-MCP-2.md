# C-MCP-2: Stateful Streamable HTTP

Plan section 2.1. Python reference: `612b1cb`. Round-trip coverage: **covered**.

## Contract

`POST /memory/mcp` speaks MCP Streamable HTTP in stateful mode. `initialize` answers 200 with an
`Mcp-Session-Id` header; the client then sends `notifications/initialized` (202) and every later request
carries the id. A request without the id on a stateful server is refused (400). Three protocol versions are
accepted and echoed in `result.protocolVersion`: 2024-11-05 (setup's mcp-probe), 2025-06-18 (the mirror
hook) and 2025-11-25.

## Python reference

- `memory-mcp/server.py:9-11 (why stateful)`
- `memory-mcp/server.py:82-84 (PolicyFastMCP, idle timeout)`
- `memory-mcp/server.py:385 (mount at /memory, route /mcp)`
- `hooks/mirror-file-memory.rb:413,433-434 (protocol 2025-06-18, requires mcp-session-id)`
- `setup:cookbooks/mcp-probe/files/probe.py:331 (protocol 2024-11-05)`

## Test

case `initialize_versions`; golden `contracts/golden/C-MCP-2/`.

## Notes

Pending M5/M6: if the claude.ai connector is observed asking for a session-less version, a session-less path is added here before the freeze (plan 4.1).
