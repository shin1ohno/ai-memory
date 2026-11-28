#!/usr/bin/env python3
"""auth-proxy in front of the real memory-mcp app, hermetic.

    python -B test_proxy_server_upstream.py

memory-mcp's server:app runs under uvicorn with the CT 119 unit's defaults
(proxy headers on, only 127.0.0.1 trusted) and Elasticsearch stubbed; the proxy
runs in-process with the token verifier stubbed. Nothing leaves the host.

Covers two things the unit tests in test_proxy.py cannot:
- Every Location the proxy hands back for the one redirect memory-mcp emits
  (Starlette's redirect_slashes on /mcp/) names the upstream's own host and port,
  whatever Host, X-Forwarded-*, Forwarded, path or request-target form the client
  sends. If a layer that reads X-Forwarded-Host is ever added, this fails.
- The legitimate request shapes (claude.ai connector, mirror hook, monitoring
  prober, sessions API), sent with the header set nginx adds, get the statuses
  and bodies they need.
"""

from __future__ import annotations

import asyncio
import json
import os
import socket
import sys
import threading
import time
import unittest
from pathlib import Path
from urllib.parse import urlsplit

HERE = Path(__file__).resolve().parent
MCP_DIR = HERE.parent / "memory-mcp"
SECRET = "proxy-secret-for-tests"
os.environ.update({
    "ES_URL": "http://127.0.0.1:9",
    "ES_PASSWORD": "test-placeholder",
    "VOYAGE_API_KEY": "test-placeholder",
    "PROXY_SHARED_SECRET": SECRET,
    # The values of systemd/memory-mcp-v2.service and memory-v2-proxy.service.
    "CLIENT_POLICY": ("memory-keeper=;monitoring-prober=;memory-mirror=ingest,forget@file-memory;"
                      "session-search-pro-dev=;session-search-mini=;session-search-neo="),
    "SESSION_SCOPE_POLICY": json.dumps({"rules": [{
        "match": {"grant": "client_credentials", "client_id": "session-search-pro-dev"},
        "host": "pro-dev", "scopes": ["sessions:ingest", "sessions:read", "sessions:purge"]}]}),
    "MEMORY_AUDIENCES": "https://mcp.ohno.be/memory,memory",
    "ALLOWED_SUBS": "operator@example.com",
    "ALLOWED_CLIENT_IDS": ("memory-keeper,monitoring-prober,memory-mirror,"
                           "session-search-pro-dev,session-search-mini,session-search-neo"),
    "OIDC_ISSUER": "https://mcp.ohno.be",
    "PATH_PREFIX": "/memory",
    "MEMORY_MCP_METRICS_FILE": "",
    "MEMORY_PROXY_METRICS_FILE": "",
    "OTEL_TRACES_EXPORTER": "none",
    "OTEL_SDK_DISABLED": "true",
})
# The unit sets no FORWARDED_ALLOW_IPS, so uvicorn trusts 127.0.0.1 only.
os.environ.pop("FORWARDED_ALLOW_IPS", None)

sys.path.insert(0, str(HERE))
import proxy  # noqa: E402

sys.path.insert(0, str(MCP_DIR))
import es_backend as be  # noqa: E402

from aiohttp import ClientSession, ClientTimeout, web  # noqa: E402
from aiohttp.test_utils import TestServer  # noqa: E402

ISS = "https://mcp.ohno.be"
CLAIMS = {
    # claude.ai connector: authorization_code, a dynamic client id, aud=[].
    "t-human": {"sub": "operator@example.com", "client_id": "1fa21cc7-0000-4000-8000-000000000000",
                "aud": [], "iss": ISS},
    "t-prober": {"sub": "monitoring-prober", "client_id": "monitoring-prober", "aud": ["memory"], "iss": ISS},
    "t-mirror": {"sub": "memory-mirror", "client_id": "memory-mirror", "aud": ["memory"], "iss": ISS},
    "t-ccs": {"sub": "session-search-pro-dev", "client_id": "session-search-pro-dev",
              "aud": ["memory"], "iss": ISS},
}

# What nginx adds in home-monitor scripts/mcp-proxy.conf.tftpl, location /memory/
# on the 443 server: Host $host, X-Real-IP $remote_addr, X-Forwarded-For
# $proxy_add_x_forwarded_for, X-Forwarded-Proto $scheme, Connection ''.
NGINX = {"Host": "mcp.ohno.be", "X-Real-IP": "203.0.113.7",
         "X-Forwarded-For": "203.0.113.7", "X-Forwarded-Proto": "https"}
MCP_ACCEPT = {"Accept": "application/json, text/event-stream", "Content-Type": "application/json"}
PROTOCOL = "2025-06-18"
SESSION_KEY = "sk_" + "a" * 32


def init_body(name):
    return {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
        "protocolVersion": PROTOCOL, "capabilities": {}, "clientInfo": {"name": name, "version": "0"}}}


class Upstream:
    """server:app under uvicorn in its own thread and event loop. FastMCP's
    session manager runs once per process, so one instance serves the module."""

    def __init__(self):
        import uvicorn

        async def no_bootstrap():
            return None

        async def ingest_document(document, dataset, doc_key=None, provenance=None,
                                  tags=None, background=True):
            return {"doc_id": "d1", "chunk_count": 1, "dataset": dataset,
                    "agent": (provenance or {}).get("agent")}

        be.ensure_indices = no_bootstrap
        be.ingest_document = ingest_document
        import server  # noqa: PLC0415 — needs the stubs and env above
        sessions = server.sessions_app
        sessions.start_background = lambda: None
        sessions._STATE.update(ready=True, error=None)

        def search(_be, body, caller):
            return {"hits": [], "query": body.get("query"), "caller": caller.get("client_id")}

        def preview(_be, session_key, q, caller):
            return {"session_key": session_key, "q": q, "caller": caller.get("client_id")}

        sessions.sessions_search.search = search
        sessions.sessions_search.preview = preview

        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        self.server = uvicorn.Server(uvicorn.Config(
            server.app, log_level="warning", access_log=False, lifespan="on"))
        self.thread = threading.Thread(
            target=lambda: asyncio.run(self.server.serve(sockets=[self.sock])), daemon=True)

    def start(self):
        self.thread.start()
        deadline = time.monotonic() + 20
        while not self.server.started:
            if time.monotonic() > deadline or not self.thread.is_alive():
                raise RuntimeError("memory-mcp did not start")
            time.sleep(0.05)

    def stop(self):
        self.server.should_exit = True
        self.thread.join(10)


UPSTREAM: Upstream | None = None


def setUpModule():
    global UPSTREAM
    UPSTREAM = Upstream()
    UPSTREAM.start()

    async def verify(token):
        c = CLAIMS.get(token)
        return dict(c) if c else None

    proxy.verifier.verify = verify
    proxy.UPSTREAM_URL = f"http://127.0.0.1:{UPSTREAM.port}/memory"


def tearDownModule():
    if UPSTREAM is not None:
        UPSTREAM.stop()


async def with_proxy(scenario):
    app = web.Application(middlewares=[proxy.request_metrics])
    app.on_startup.append(proxy.on_startup)
    app.on_cleanup.append(proxy.on_cleanup)
    app.router.add_route("*", "/{path_info:.*}", proxy.handle)
    srv = TestServer(app, host="127.0.0.1")
    await srv.start_server()
    try:
        return await scenario(srv.port)
    finally:
        await srv.close()


async def raw(port, method, target, headers):
    """(status, headers) for a request whose target and headers are sent byte for
    byte (no client-side normalisation of dot segments or the Host header)."""
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    lines = [f"{method} {target} HTTP/1.1"]
    if not any(k.lower() == "host" for k in headers):
        lines.append(f"Host: 127.0.0.1:{port}")
    lines += [f"{k}: {v}" for k, v in headers.items()] + ["Connection: close", "Content-Length: 0"]
    writer.write(("\r\n".join(lines) + "\r\n\r\n").encode())
    await writer.drain()
    data = await asyncio.wait_for(reader.read(), 30)
    writer.close()
    head = data.split(b"\r\n\r\n", 1)[0].decode("latin1").split("\r\n")
    hdrs = {}
    for line in head[1:]:
        k, _, v = line.partition(":")
        hdrs[k.strip().lower()] = v.strip()
    return int(head[0].split()[1]), hdrs


def normalise(body: bytes, session_id: str | None) -> str:
    text = body.decode("utf-8", "replace")
    return text.replace(session_id, "<session-id>") if session_id else text


async def legitimate_transcript(port: int) -> list[dict]:
    """The request shapes of the four legitimate clients, as nginx forwards
    them. Returns one entry per request: status, content type, Location and the
    body with the random session id replaced."""
    base = f"http://127.0.0.1:{port}"
    out = []

    async def send(s, label, method, path, token, *, json_body=None, headers=None, sid=None, stream=False):
        h = {**NGINX, "Authorization": f"Bearer {token}", **(headers or {})}
        if sid:
            h["Mcp-Session-Id"] = sid
            h["MCP-Protocol-Version"] = PROTOCOL
        async with s.request(method, base + path, json=json_body, headers=h, allow_redirects=False,
                             timeout=ClientTimeout(total=30)) as r:
            body = b"" if stream else await r.read()
            out.append({"step": label, "status": r.status,
                        "content_type": r.headers.get("Content-Type", ""),
                        "location": r.headers.get("Location"),
                        "body": normalise(body, sid or r.headers.get("Mcp-Session-Id"))})
            return r.headers.get("Mcp-Session-Id")

    async with ClientSession() as s:
        # claude.ai connector: /mcp without a slash, a session, a GET stream, DELETE.
        sid = await send(s, "connector initialize", "POST", "/mcp", "t-human",
                         json_body=init_body("claude-ai"), headers=MCP_ACCEPT)
        out[-1]["has_session_id"] = bool(sid)
        await send(s, "connector notifications/initialized", "POST", "/mcp", "t-human",
                   json_body={"jsonrpc": "2.0", "method": "notifications/initialized"},
                   headers=MCP_ACCEPT, sid=sid)
        await send(s, "connector tools/list", "POST", "/mcp", "t-human",
                   json_body={"jsonrpc": "2.0", "id": 2, "method": "tools/list"}, headers=MCP_ACCEPT, sid=sid)
        await send(s, "connector GET stream", "GET", "/mcp", "t-human",
                   headers={"Accept": "text/event-stream"}, sid=sid, stream=True)
        await send(s, "connector DELETE", "DELETE", "/mcp", "t-human", sid=sid)

        # hooks/mirror-file-memory.rb: initialize, initialized, tools/call ingest.
        sid = await send(s, "mirror initialize", "POST", "/mcp", "t-mirror",
                         json_body=init_body("memory-mirror"), headers=MCP_ACCEPT)
        out[-1]["has_session_id"] = bool(sid)
        await send(s, "mirror notifications/initialized", "POST", "/mcp", "t-mirror",
                   json_body={"jsonrpc": "2.0", "method": "notifications/initialized"},
                   headers=MCP_ACCEPT, sid=sid)
        await send(s, "mirror tools/call ingest", "POST", "/mcp", "t-mirror",
                   json_body={"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {
                       "name": "ingest", "arguments": {"document": "fixture", "dataset": "file-memory",
                                                       "doc_key": "fixture-key"}}},
                   headers=MCP_ACCEPT, sid=sid)

        # setup cookbooks/mcp-probe/files/probe.py after setup #1276: exactly
        # /memory/mcp, session id carried, DELETE at the end.
        sid = await send(s, "prober initialize", "POST", "/mcp", "t-prober",
                         json_body=init_body("mcp-probe"), headers=MCP_ACCEPT)
        out[-1]["has_session_id"] = bool(sid)
        await send(s, "prober notifications/initialized", "POST", "/mcp", "t-prober",
                   json_body={"jsonrpc": "2.0", "method": "notifications/initialized"},
                   headers=MCP_ACCEPT, sid=sid)
        await send(s, "prober tools/list", "POST", "/mcp", "t-prober",
                   json_body={"jsonrpc": "2.0", "id": 2, "method": "tools/list"}, headers=MCP_ACCEPT, sid=sid)
        await send(s, "prober DELETE", "DELETE", "/mcp", "t-prober", sid=sid)

        # session-search ccs/api.py: endpoint + /status, /search, /preview.
        await send(s, "sessions GET /status", "GET", "/sessions/v1/status", "t-ccs")
        await send(s, "sessions POST /search", "POST", "/sessions/v1/search", "t-ccs",
                   json_body={"query": "fixture"})
        await send(s, "sessions GET /preview", "GET", "/sessions/v1/preview?session_key=" + SESSION_KEY + "&q=x", "t-ccs")
        # The purge route reads Elasticsearch, which is unreachable here, so it
        # stops at the backend; the proxy's part (auth, identity, path) is the same.
        await send(s, "sessions DELETE /session", "DELETE", "/sessions/v1/session?session_key=" + SESSION_KEY, "t-ccs")

        # The unauthenticated discovery document and health check.
        async with s.get(base + "/.well-known/oauth-protected-resource", headers=NGINX) as r:
            out.append({"step": "GET /.well-known/oauth-protected-resource", "status": r.status,
                        "content_type": r.headers.get("Content-Type", ""), "location": None,
                        "body": (await r.read()).decode()})
        async with s.get(base + "/health", headers=NGINX) as r:
            out.append({"step": "GET /health", "status": r.status,
                        "content_type": r.headers.get("Content-Type", ""), "location": None,
                        "body": (await r.read()).decode()})
    return out


# Request variants aimed at the redirect memory-mcp emits for /mcp/. Each
# either gets a 307 whose Location is the upstream's own origin, or no redirect.
LOCATION_VARIANTS = [
    ("plain /mcp/", "/mcp/", {}, True),
    ("Host", "/mcp/", {"Host": "canary.example"}, True),
    ("X-Forwarded-Host", "/mcp/", {"X-Forwarded-Host": "canary.example"}, True),
    ("Forwarded", "/mcp/", {"Forwarded": "for=198.51.100.9;host=canary.example;proto=https"}, True),
    ("X-Forwarded-Proto http://evil", "/mcp/", {"X-Forwarded-Proto": "http://canary.example"}, True),
    ("X-Forwarded-Proto ws", "/mcp/", {"X-Forwarded-Proto": "ws"}, True),
    ("nginx header set", "/mcp/", dict(NGINX), True),
    ("query //host", "/mcp/?next=//canary.example/x", {}, True),
    ("dot segment", "/x/../mcp/", {}, True),
    ("absolute-form", "http://canary.example/mcp/", {}, True),
    ("path //host", "//canary.example/mcp/", {}, False),
    ("path %2F", "/%2Fcanary.example/mcp/", {}, False),
    ("path backslash", "/\\canary.example/mcp/", {}, False),
]


class ServerUpstreamTest(unittest.TestCase):
    def test_redirect_location_is_always_the_upstream_origin(self):
        async def scenario(port):
            out = []
            for label, target, extra, _ in LOCATION_VARIANTS:
                status, hdrs = await raw(port, "POST", target, {"Authorization": "Bearer t-prober", **extra})
                out.append((label, status, hdrs.get("location")))
            return out

        upstream_origin = f"127.0.0.1:{UPSTREAM.port}"
        results = asyncio.run(with_proxy(scenario))
        for (label, status, location), (_, _, _, redirects) in zip(results, LOCATION_VARIANTS):
            with self.subTest(variant=label):
                if redirects:
                    self.assertEqual(status, 307, f"{label}: the client did not get the redirect")
                    self.assertIsNotNone(location, label)
                if location is not None:
                    parts = urlsplit(location)
                    self.assertEqual(parts.netloc, upstream_origin, f"{label}: {location}")
                    self.assertIn(parts.scheme, ("http", "https"), f"{label}: {location}")
                    self.assertEqual(parts.path, "/memory/mcp", f"{label}: {location}")

    def test_legitimate_flows_through_nginx_headers(self):
        steps = {e["step"]: e for e in asyncio.run(with_proxy(legitimate_transcript))}
        expected = {
            "connector initialize": 200, "connector notifications/initialized": 202,
            "connector tools/list": 200, "connector GET stream": 200, "connector DELETE": 200,
            "mirror initialize": 200, "mirror notifications/initialized": 202,
            "mirror tools/call ingest": 200,
            "prober initialize": 200, "prober notifications/initialized": 202,
            "prober tools/list": 200, "prober DELETE": 200,
            "sessions GET /status": 200, "sessions POST /search": 200, "sessions GET /preview": 200,
            "sessions DELETE /session": 503,
            "GET /.well-known/oauth-protected-resource": 200, "GET /health": 200,
        }
        self.assertEqual({k: steps[k]["status"] for k in expected}, expected)
        for client in ("connector", "mirror", "prober"):
            self.assertTrue(steps[f"{client} initialize"]["has_session_id"], client)
        self.assertIn('"tools"', steps["connector tools/list"]["body"])
        self.assertIn('"tools"', steps["prober tools/list"]["body"])
        self.assertIn("text/event-stream", steps["connector GET stream"]["content_type"])
        self.assertIn("memory-mirror", steps["mirror tools/call ingest"]["body"])
        self.assertNotIn('"isError":true', steps["mirror tools/call ingest"]["body"].replace(" ", ""))
        self.assertIn('"caller": "session-search-pro-dev"'.replace(" ", ""),
                      steps["sessions POST /search"]["body"].replace(" ", ""))
        self.assertIn('"caller_host":"pro-dev"', steps["sessions GET /status"]["body"].replace(" ", ""))
        for e in steps.values():
            self.assertIsNone(e["location"], e["step"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
