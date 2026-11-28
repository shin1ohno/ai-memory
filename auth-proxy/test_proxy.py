#!/usr/bin/env python3
"""auth-proxy body limits, proxy secret and log hygiene, hermetic.

Needs the es-memory venv (aiohttp, PyJWT, opentelemetry from requirements.txt):

    python -B test_proxy.py

The token verifier is stubbed and the upstream is an in-process aiohttp app,
so nothing leaves the process. Covers (design spec §7.2 "Body limits", §8 rows
20 / 22): 1 MiB + 1 byte on /mcp is 413 and never reaches upstream; 8 MiB on
/sessions/v1/ingest passes through intact; 8 MiB + 1 there is 413; a chunked
body without Content-Length over either limit is 413; a dot-segment path does
not get the larger limit; an unauthenticated oversized body is 401 (no body
read before authentication); X-Proxy-Secret is injected and an inbound one is
dropped; no response body reaches the log.

Redirects, discovery and forwarding headers: an upstream 3xx (to another origin
or to itself) is returned to the client as is, never followed, so the shared
secret and X-Verified-* never travel to a Location; /.well-known/* other than
oauth-protected-resource is answered 404 by the proxy (no upstream call, so a
dot segment cannot reach an upstream path unauthenticated); X-Forwarded-Host and
Forwarded are dropped and X-Forwarded-Proto / X-Forwarded-For are the proxy's own.
"""

from __future__ import annotations

import asyncio
import logging
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
os.environ["MEMORY_AUDIENCES"] = "memory"
os.environ["ALLOWED_CLIENT_IDS"] = "session-search-pro-dev"
os.environ["ALLOWED_SUBS"] = "operator@example.com"
os.environ["PROXY_SHARED_SECRET"] = "proxy-secret-for-tests"
os.environ.setdefault("OTEL_TRACES_EXPORTER", "none")

from aiohttp import ClientSession, web  # noqa: E402
from aiohttp.test_utils import TestClient, TestServer  # noqa: E402

os.environ.setdefault("MEMORY_PROXY_METRICS_FILE", "")
import proxy  # noqa: E402

MIB = 1024 * 1024
MARKER = "TRANSCRIPT-TEXT-MARKER"
CLAIMS = {"sub": "session-search-pro-dev", "client_id": "session-search-pro-dev", "aud": ["memory"]}
AUTH = {"Authorization": "Bearer stub"}


class Capture(logging.Handler):
    def __init__(self):
        super().__init__()
        self.lines: list[str] = []

    def emit(self, record):
        self.lines.append(record.getMessage())


class ProxyTest(unittest.TestCase):
    def setUp(self):
        self.seen: list = []
        self.cap = Capture()
        proxy.logger.addHandler(self.cap)
        async def verify(token):
            return dict(CLAIMS) if token == "stub" else None
        proxy.verifier.verify = verify

    def tearDown(self):
        proxy.logger.removeHandler(self.cap)

    def call(self, method, path, **kw):
        async def go():
            async def upstream(request):
                body = await request.read()
                self.seen.append((request.path, len(body), dict(request.headers)))
                return web.json_response({"echo": MARKER, "len": len(body)})

            up = web.Application(client_max_size=64 * MIB)
            up.router.add_route("*", "/{tail:.*}", upstream)
            up_srv = TestServer(up)
            await up_srv.start_server()
            proxy.UPSTREAM_URL = str(up_srv.make_url("")).rstrip("/")
            # A fresh Application per call wired exactly like proxy.app (an
            # aiohttp Application is bound to the first event loop it runs on).
            app = web.Application()
            app.on_startup.append(proxy.on_startup)
            app.on_cleanup.append(proxy.on_cleanup)
            app.router.add_route("*", "/{path_info:.*}", proxy.handle)
            client = TestClient(TestServer(app))
            await client.start_server()
            try:
                resp = await client.request(method, path, **kw)
                return resp.status, await resp.read()
            finally:
                await client.close()
                await up_srv.close()

        return asyncio.run(go())

    def test_default_limit_on_mcp(self):
        status, _ = self.call("POST", "/mcp", data=b"x" * (MIB + 1), headers=AUTH)
        self.assertEqual(status, 413)
        self.assertEqual(self.seen, [])
        status, _ = self.call("POST", "/mcp", data=b"x" * MIB, headers=AUTH)
        self.assertEqual(status, 200)
        self.assertEqual(self.seen[-1][1], MIB)

    def test_request_content_encoding_refused(self):
        # A Content-Encoding request used to stall (aiohttp decompresses on read
        # while Content-Length counts compressed bytes). It is refused up front.
        import gzip as _gzip
        gz = _gzip.compress(b'{"a":1}')
        status, body = self.call("POST", "/sessions/v1/ingest", data=gz,
                                 headers=dict(AUTH, **{"Content-Encoding": "gzip"}))
        self.assertEqual(status, 415, body[:200])
        self.assertEqual(self.seen, [])

    def test_gzip_body_without_header_passes_through_unchanged(self):
        import gzip as _gzip
        gz = _gzip.compress(b'{"a":1}' * 1000)
        status, body = self.call("POST", "/sessions/v1/ingest", data=gz, headers=AUTH)
        self.assertEqual(status, 200, body[:200])
        self.assertEqual(self.seen[-1][:2], ("/sessions/v1/ingest", len(gz)))

    def test_sessions_limit(self):
        status, body = self.call("POST", "/sessions/v1/ingest", data=b"y" * (8 * MIB), headers=AUTH)
        self.assertEqual(status, 200, body[:200])
        self.assertEqual(self.seen[-1][:2], ("/sessions/v1/ingest", 8 * MIB))
        status, _ = self.call("POST", "/sessions/v1/ingest", data=b"y" * (8 * MIB + 1), headers=AUTH)
        self.assertEqual(status, 413)
        self.assertEqual(len(self.seen), 1)

    def test_chunked_over_limit(self):
        async def gen(total):
            sent = 0
            while sent < total:
                n = min(256 * 1024, total - sent)
                sent += n
                yield b"z" * n

        status, _ = self.call("POST", "/sessions/v1/ingest", data=gen(9 * MIB), headers=AUTH)
        self.assertEqual(status, 413)
        status, _ = self.call("POST", "/mcp", data=gen(2 * MIB), headers=AUTH)
        self.assertEqual(status, 413)
        self.assertEqual(self.seen, [])
        # A chunked body under the limit is forwarded whole.
        status, _ = self.call("POST", "/sessions/v1/ingest", data=gen(3 * MIB), headers=AUTH)
        self.assertEqual(status, 200)
        self.assertEqual(self.seen[-1][1], 3 * MIB)

    def test_dot_segment_does_not_widen_limit(self):
        for path in ("/sessions/v1/../mcp", "/sessions/v1/%2e%2e/mcp"):
            class R:
                raw_path = path
            self.assertEqual(proxy.body_limit(R), proxy.BODY_LIMIT_DEFAULT, path)

    def test_unauthenticated_large_body_is_401(self):
        status, _ = self.call("POST", "/sessions/v1/ingest", data=b"q" * (8 * MIB))
        self.assertEqual(status, 401)
        self.assertEqual(self.seen, [])

    def test_proxy_secret_injected_and_inbound_dropped(self):
        status, _ = self.call("POST", "/sessions/v1/status", data=b"{}",
                              headers={**AUTH, "X-Proxy-Secret": "forged", "X-Verified-Sub": "forged"})
        self.assertEqual(status, 200)
        headers = {k.lower(): v for k, v in self.seen[-1][2].items()}
        self.assertEqual(headers["x-proxy-secret"], "proxy-secret-for-tests")
        self.assertEqual(headers["x-verified-sub"], "session-search-pro-dev")

    def test_no_response_body_in_logs(self):
        status, body = self.call("GET", "/sessions/v1/status", headers=AUTH)
        self.assertEqual(status, 200)
        self.assertIn(MARKER.encode(), body)
        self.assertTrue(self.cap.lines)  # the proxy did log the request
        self.assertFalse([line for line in self.cap.lines if MARKER in line], self.cap.lines)

    def test_query_string_not_logged(self):
        self.call("GET", "/sessions/v1/preview?session_key=sk_x&q=secretsearchterm", headers=AUTH)
        self.assertFalse([line for line in self.cap.lines if "secretsearchterm" in line])



REDIRECTS = (301, 302, 303, 307, 308)


async def raw_get(port: int, target: str, headers: dict | None = None) -> int:
    """Status of a GET whose request target is sent byte for byte: an aiohttp or
    yarl client would resolve the dot segments before they reach the proxy."""
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    lines = [f"GET {target} HTTP/1.1", f"Host: 127.0.0.1:{port}", "Connection: close"]
    lines += [f"{k}: {v}" for k, v in (headers or {}).items()]
    writer.write(("\r\n".join(lines) + "\r\n\r\n").encode())
    await writer.drain()
    status_line = await reader.readline()
    await reader.read()
    writer.close()
    return int(status_line.split()[1])


class UpstreamBoundaryTest(unittest.TestCase):
    """An upstream that answers with whatever `self.reply` builds, a canary on
    another origin that records every request it receives, and the proxy wired
    like proxy.app (metrics middleware included)."""

    def setUp(self):
        self.upstream_hits: list = []
        self.canary_hits: list = []
        self.reply = lambda request, canary: web.json_response({"ok": True})
        async def verify(token):
            return dict(CLAIMS) if token == "stub" else None
        proxy.verifier.verify = verify

    def run_against(self, scenario):
        """scenario(client, canary_url, upstream_url, proxy_port) runs inside the
        event loop with everything started."""
        async def go():
            async def canary(request):
                self.canary_hits.append((request.method, request.path, dict(request.headers)))
                return web.json_response({"canary": True})

            can = web.Application()
            can.router.add_route("*", "/{tail:.*}", canary)
            # 127.0.0.2 is a different origin from the upstream's 127.0.0.1.
            can_srv = TestServer(can, host="127.0.0.2")
            await can_srv.start_server()
            canary_url = str(can_srv.make_url("")).rstrip("/")

            async def upstream(request):
                await request.read()
                self.upstream_hits.append((request.method, request.path_qs, dict(request.headers)))
                return self.reply(request, canary_url)

            up = web.Application()
            up.router.add_route("*", "/{tail:.*}", upstream)
            up_srv = TestServer(up)
            await up_srv.start_server()
            upstream_url = str(up_srv.make_url("")).rstrip("/")
            proxy.UPSTREAM_URL = upstream_url
            app = web.Application(middlewares=[proxy.request_metrics])
            app.on_startup.append(proxy.on_startup)
            app.on_cleanup.append(proxy.on_cleanup)
            app.router.add_route("*", "/{path_info:.*}", proxy.handle)
            client = TestClient(TestServer(app))
            await client.start_server()
            try:
                return await scenario(client, canary_url, upstream_url, client.server.port)
            finally:
                await client.close()
                await up_srv.close()
                await can_srv.close()

        return asyncio.run(go())

    def redirect_to(self, status, location):
        return lambda request, canary: web.Response(
            status=status, headers={"Location": location(canary)})

    # ── F1: redirects are returned, never followed ──

    def test_off_origin_redirect_returned_not_followed(self):
        for status in REDIRECTS:
            for method in ("GET", "POST"):
                with self.subTest(status=status, method=method):
                    self.canary_hits.clear()
                    self.upstream_hits.clear()
                    self.reply = self.redirect_to(status, lambda c: c + "/stolen")

                    async def scenario(client, canary_url, _up, _port):
                        resp = await client.request(method, "/mcp", headers=AUTH, allow_redirects=False,
                                                    data=b'{"jsonrpc":"2.0"}' if method == "POST" else None)
                        await resp.read()
                        return resp.status, resp.headers.get("Location"), canary_url

                    got, location, canary_url = self.run_against(scenario)
                    self.assertEqual((got, location), (status, canary_url + "/stolen"))
                    self.assertEqual(len(self.upstream_hits), 1)
                    self.assertEqual(self.canary_hits, [], "the proxy followed the redirect")

    def test_canary_never_receives_secret_or_identity(self):
        leaked = []
        for status in REDIRECTS:
            self.reply = self.redirect_to(status, lambda c: c + "/stolen")

            async def scenario(client, *_):
                resp = await client.post("/mcp", data=b"{}", headers=AUTH, allow_redirects=False)
                await resp.read()

            self.run_against(scenario)
            for _method, _path, headers in self.canary_hits:
                names = {k.lower() for k in headers}
                leaked += [(status, n) for n in names
                           if n == "x-proxy-secret" or n.startswith("x-verified-")]
        self.assertEqual(leaked, [])

    def test_same_origin_redirect_not_followed(self):
        # Starlette's redirect_slashes: /mcp/ -> /mcp on the upstream itself.
        self.reply = lambda request, canary: (
            web.Response(status=307, headers={"Location": str(request.url.with_path("/mcp"))})
            if request.path == "/mcp/" else web.json_response({"ok": True}))

        async def scenario(client, _c, upstream_url, _port):
            resp = await client.post("/mcp/", data=b"{}", headers=AUTH, allow_redirects=False)
            await resp.read()
            return resp.status, resp.headers.get("Location"), upstream_url

        status, location, upstream_url = self.run_against(scenario)
        self.assertEqual(status, 307)
        self.assertEqual(location, upstream_url + "/mcp")
        self.assertEqual([path for _m, path, _h in self.upstream_hits], ["/mcp/"])

    def test_redirect_recorded_as_its_own_status(self):
        self.reply = self.redirect_to(307, lambda c: c + "/stolen")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "proxy.prom"
            with patch.dict(os.environ, {"ALLOWED_CLIENT_IDS": "", "CLIENT_POLICY": ""}):
                metric = proxy.Metrics("proxy", str(path))

            async def scenario(client, *_):
                resp = await client.post("/mcp", data=b"{}", headers=AUTH, allow_redirects=False)
                await resp.read()

            with patch.object(proxy, "proxy_metrics", metric):
                self.run_against(scenario)
            metric.flush()
            output = path.read_text()
        statuses = [line for line in output.splitlines() if line.startswith("memory_proxy_requests_total")]
        self.assertTrue(any('status="307"' in line for line in statuses), statuses)
        self.assertFalse(any('status="502"' in line or 'status="200"' in line for line in statuses), statuses)

    def test_event_stream_redirect_keeps_status(self):
        self.reply = lambda request, canary: web.Response(
            status=307, headers={"Location": canary + "/stolen", "Content-Type": "text/event-stream"})

        async def scenario(client, canary_url, *_):
            resp = await client.get("/mcp", headers={**AUTH, "Accept": "text/event-stream"},
                                    allow_redirects=False)
            await resp.read()
            return resp.status, resp.headers.get("Location"), canary_url

        status, location, canary_url = self.run_against(scenario)
        self.assertEqual((status, location), (307, canary_url + "/stolen"))
        self.assertEqual(self.canary_hits, [])

    # ── F3: /.well-known/ is answered by the proxy alone ──

    def test_unknown_well_known_is_404_without_upstream_call(self):
        self.reply = self.redirect_to(307, lambda c: c + "/stolen")

        async def scenario(client, *_):
            out = []
            for path in ("/.well-known/x", "/.well-known/openid-configuration",
                         "/.well-known/oauth-protected-resource/", "/.well-known/x/"):
                resp = await client.get(path, allow_redirects=False)
                await resp.read()
                out.append((path, resp.status, resp.headers.get("Location")))
            return out

        results = self.run_against(scenario)
        self.assertEqual(self.upstream_hits, [], "an unauthenticated request reached upstream")
        self.assertEqual(self.canary_hits, [])
        for path, status, location in results:
            self.assertEqual((status, location), (404, None), path)

    def test_well_known_dot_segments_never_reach_upstream(self):
        targets = ("/.well-known/../mcp/", "/.well-known/%2e%2e/mcp", "/.well-known/../../x",
                   "/.well-known/oauth-protected-resource/../../mcp")

        async def scenario(_client, _c, _u, port):
            return [(t, await raw_get(port, t)) for t in targets]

        results = self.run_against(scenario)
        self.assertEqual([path for _m, path, _h in self.upstream_hits], [],
                         "an unauthenticated request reached upstream")
        for target, status in results:
            self.assertEqual(status, 404, target)

    def test_protected_resource_metadata_still_served(self):
        async def scenario(client, *_):
            resp = await client.get("/.well-known/oauth-protected-resource")
            return resp.status, await resp.json(), resp.headers.get("Access-Control-Allow-Origin")

        status, body, cors = self.run_against(scenario)
        self.assertEqual(status, 200)
        self.assertEqual(body["resource"], proxy.RESOURCE_ID)
        self.assertEqual(body["authorization_servers"], [proxy.OIDC_ISSUER])
        self.assertEqual(cors, "*")
        self.assertEqual(self.upstream_hits, [])

    # ── F5: forwarding headers are the proxy's own ──

    def forwarded_headers(self, inbound: dict) -> dict:
        async def scenario(client, *_):
            resp = await client.post("/mcp", data=b"{}", headers={**AUTH, **inbound})
            await resp.read()
            return resp.status

        self.assertEqual(self.run_against(scenario), 200)
        headers = self.upstream_hits[-1][2]
        return {k.lower(): v for k, v in headers.items()
                if k.lower().startswith("x-forwarded-") or k.lower() == "forwarded"}

    def test_direct_client_forwarding_headers_replaced(self):
        got = self.forwarded_headers({
            "X-Forwarded-Host": "canary.example",
            "Forwarded": "for=198.51.100.9;host=canary.example;proto=https",
            "X-Forwarded-Proto": "ws",
            "X-Forwarded-For": "198.51.100.9",
        })
        self.assertEqual(got, {"x-forwarded-proto": "http", "x-forwarded-for": "127.0.0.1"})

    def test_forwarded_proto_only_accepts_https(self):
        for inbound, expected in (("https", "https"), ("HTTPS ", "https"), ("http", "http"),
                                  ("http://canary.example", "http"), ("wss", "http"),
                                  ("https, http", "http"), (None, "http")):
            with self.subTest(inbound=inbound):
                got = self.forwarded_headers({} if inbound is None else {"X-Forwarded-Proto": inbound})
                self.assertEqual(got["x-forwarded-proto"], expected)

    def test_nginx_shaped_request_keeps_https(self):
        # home-monitor mcp-proxy.conf.tftpl, location /memory/: Host $host,
        # X-Real-IP $remote_addr, X-Forwarded-For $proxy_add_x_forwarded_for,
        # X-Forwarded-Proto $scheme (always https on the 443 server).
        got = self.forwarded_headers({
            "Host": "mcp.ohno.be",
            "X-Real-IP": "203.0.113.7",
            "X-Forwarded-For": "198.51.100.9, 203.0.113.7",
            "X-Forwarded-Proto": "https",
        })
        self.assertEqual(got, {"x-forwarded-proto": "https", "x-forwarded-for": "127.0.0.1"})


if __name__ == "__main__":
    unittest.main(verbosity=2)
