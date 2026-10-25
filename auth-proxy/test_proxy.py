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
"""

from __future__ import annotations

import asyncio
import logging
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
os.environ["MEMORY_AUDIENCES"] = "memory"
os.environ["ALLOWED_CLIENT_IDS"] = "session-search-pro-dev"
os.environ["ALLOWED_SUBS"] = "operator@example.com"
os.environ["PROXY_SHARED_SECRET"] = "proxy-secret-for-tests"
os.environ.setdefault("OTEL_TRACES_EXPORTER", "none")

from aiohttp import web  # noqa: E402
from aiohttp.test_utils import TestClient, TestServer  # noqa: E402

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
        proxy.verifier.verify = lambda token: dict(CLAIMS) if token == "stub" else None

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


if __name__ == "__main__":
    unittest.main(verbosity=2)
