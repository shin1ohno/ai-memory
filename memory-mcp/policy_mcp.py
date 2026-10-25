"""FastMCP subclass that puts CLIENT_POLICY in front of every tools/call.

FastMCP registers `self.call_tool` as the low-level CallToolRequest handler
inside `__init__` (`_setup_handlers`), so overriding `call_tool` here
intercepts every tool invocation — including tools added later — without
touching the tool functions themselves. A refusal raised here is turned into a
`CallToolResult(isError=True)` by the low-level handler; the tool body never
runs.

`tools/list` is deliberately NOT filtered: visibility is not authorization, and
the gate is the only place a call can be refused.

Kept out of server.py because server.py bootstraps the ES indices at import
time; this module imports without side effects, so test_client_policy.py can
exercise the gate against the real mcp package.
"""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP

import identity

# ToolError surfaces a clean tool-level error to the client. Fallback to a plain
# Exception subclass if the import path differs on the installed wheel.
try:
    from mcp.server.fastmcp.exceptions import ToolError
except Exception:  # pragma: no cover
    class ToolError(Exception):
        pass


def request_headers(ctx):
    """Inbound HTTP headers from the MCP request context.

    Documented path on the streamable-http FastMCP:
    ctx.request_context.request.headers (a case-insensitive Starlette Headers).
    Outside a request `request_context` raises ValueError; with no HTTP request
    behind it `request` is None. Both yield {} — no identity headers, which the
    policy treats as a missing grant and denies.
    """
    try:
        return ctx.request_context.request.headers
    except (AttributeError, ValueError, LookupError):
        return {}


class PolicyFastMCP(FastMCP):
    """FastMCP whose every tools/call passes identity.authorize_tool first."""

    async def call_tool(self, name, arguments):
        ident = identity.parse_identity(request_headers(self.get_context()))
        ok, reason = identity.authorize_tool(ident, name, arguments)
        if not ok:
            dataset = arguments.get("dataset") if isinstance(arguments, dict) else None
            identity.audit_policy_deny(name, ident.get("client_id"), dataset)
            raise ToolError(reason)
        return await super().call_tool(name, arguments)

    def check_client_policy(self) -> None:
        """Validate CLIENT_POLICY's tool names against the tools registered so
        far and log the effective policy. Call once, after every @tool."""
        identity.check_client_policy(t.name for t in self._tool_manager.list_tools())
