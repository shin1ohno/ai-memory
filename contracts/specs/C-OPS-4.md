# C-OPS-4: External probe path

Plan section 2.6. Python reference: `612b1cb`. Round-trip coverage: **outside run.py (accepted 2026-11-28)**.

## Contract

setup's mcp-probe (initialize with 2024-11-05, tools/list, a recall) succeeds against the deployed URL in
every phase.

## Python reference

- `setup:cookbooks/mcp-probe/files/probe.py:62,281-288,331`

## Test

Outside run.py, by owner decision on 2026-11-28. Alternative verification: at each cutover phase, run
setup's mcp-probe (`setup:cookbooks/mcp-probe/files/probe.py`) against the deployed URL — initialize with
`2024-11-05`, `tools/list`, one `recall` — and require success. The deployed URL, its TLS and its
issuer exist only in production. The protocol steps the probe takes are covered locally by C-MCP-2
(version negotiation), C-MCP-1 (`tools/list`) and C-MCP-4 (recall).
