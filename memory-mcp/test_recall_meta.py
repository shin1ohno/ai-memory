#!/usr/bin/env python3
"""The recall tool is advertised with `_meta: {"anthropic/alwaysLoad": true}`.

Claude Code defers MCP tool schemas behind a ToolSearch step; this flag makes
recall available from the first turn. Every recall session in the SH1-230 sample
went through ToolSearch first, so a regression here puts that step back without
any error. The assertion is on the tools/list wire form (the `_meta` alias), not
on a Python attribute, and the other tools must NOT carry the flag.

Needs the server venv (imports server.py, which stubs only ES startup).

Usage: python3 test_recall_meta.py
"""

from __future__ import annotations

import asyncio
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
for k, v in (("ES_URL", "http://127.0.0.1:9200"), ("ES_PASSWORD", "stub"),
             ("ES_USER", "memory_mcp"), ("VOYAGE_API_KEY", "stub")):
    os.environ.setdefault(k, v)

import es_backend as be  # noqa: E402


async def _no_bootstrap():
    return None


be.ensure_indices = _no_bootstrap  # server.py would otherwise contact ES at import
import server  # noqa: E402

PASS = 0
FAIL = 0


def check(name: str, condition: bool, detail: str = "") -> None:
    global PASS, FAIL
    if condition:
        PASS += 1
        print(f"ok   {name}")
    else:
        FAIL += 1
        print(f"FAIL {name}" + (f" — {detail}" if detail else ""))


def test_recall_is_always_loaded_on_the_wire():
    tools = asyncio.run(server.mcp.list_tools())
    wire = {t.name: t.model_dump(by_alias=True, exclude_none=True) for t in tools}
    check("recall's tools/list entry carries _meta alwaysLoad true",
          wire["recall"].get("_meta") == {"anthropic/alwaysLoad": True},
          f"got {wire['recall'].get('_meta')!r}")
    others = [n for n, t in wire.items() if n != "recall" and "anthropic/alwaysLoad" in (t.get("_meta") or {})]
    check("no other tool is preloaded", not others, f"got {others!r}")


if __name__ == "__main__":
    test_recall_is_always_loaded_on_the_wire()
    print(f"\n---- pass={PASS} fail={FAIL}")
    sys.exit(1 if FAIL else 0)
