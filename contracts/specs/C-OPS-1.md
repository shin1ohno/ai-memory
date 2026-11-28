# C-OPS-1: Units, ports and names

Plan section 2.6. Python reference: `612b1cb`. Round-trip coverage: **partial**.

## Contract

Units `memory-mcp-v2` (uvicorn on 127.0.0.1:8010) and `memory-v2-proxy` (PORT 8767, UPSTREAM_URL
`http://127.0.0.1:8010/memory`), `memory-session-maint` (`sessions_maint.py run`), APM service name
`ai-memory-auth-proxy`, metric files `memory_mcp.prom`, `memory_proxy.prom`, `memory_proxy_jwks.prom`,
paths under /opt/es-memory.

## Python reference

- `systemd/memory-mcp-v2.service:10,48`
- `systemd/memory-v2-proxy.service:10-17,47`
- `systemd/memory-session-maint.service:20`
- `auth-proxy/proxy.py:49`
- `memory-mcp/timing.py:28-31`
- `setup:docs/adr/0013-ai-memory-own-repo.md:223-234`

## Test

case `units_static` reads the repository's units. The host half (`systemctl cat`, `ss -ltn` on CT 119) runs at cutover.
