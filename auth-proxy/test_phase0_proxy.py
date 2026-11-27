#!/usr/bin/env python3
"""Exercise JWKS I/O and the actual proxy entry point using local fixtures."""
import asyncio
import json
import os
from pathlib import Path
import socket
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from aiohttp import ClientSession, web
from aiohttp.test_utils import TestClient, TestServer
from cryptography.hazmat.primitives.asymmetric import rsa
import jwt

sys.path.insert(0, str(Path(__file__).resolve().parent))
os.environ['MEMORY_PROXY_METRICS_FILE'] = ''
import proxy

KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
NEXT = rsa.generate_private_key(public_exponent=65537, key_size=2048)
ISSUER = 'https://issuer.example.test'


def jwk(key, kid='key'):
    return dict(json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key())), kid=kid)


def token(key=KEY, kid='key', **claims):
    body = dict(iss=ISSUER, sub='fixture', exp=int(time.time()) + 600)
    body.update(claims)
    return jwt.encode(body, key, algorithm='RS256', headers={'kid': kid})


class JWKS(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.calls = 0
        self.redirects = 0
        self.document = {'keys': [jwk(KEY)]}
        self.status = 200
        self.release = asyncio.Event()
        self.release.set()
        self.entered = asyncio.Event()
        self.directory = tempfile.TemporaryDirectory()
        self.path = Path(self.directory.name) / 'jwks.prom'
        self.env = patch.dict(os.environ, {'MEMORY_PROXY_JWKS_METRICS_FILE': str(self.path)})
        self.env.start()

        async def keys(request):
            self.calls += 1
            self.entered.set()
            await self.release.wait()
            if self.status == 302:
                raise web.HTTPFound('/redirect-target')
            return web.json_response(self.document, status=self.status)

        async def target(request):
            self.redirects += 1
            return web.json_response(self.document)

        app = web.Application()
        app.router.add_get('/keys', keys)
        app.router.add_get('/redirect-target', target)
        self.server = TestServer(app)
        await self.server.start_server()
        self.verifier = proxy.TokenVerifier(str(self.server.make_url('/keys')), ISSUER)

    async def asyncTearDown(self):
        self.release.set()
        await self.verifier.close()
        await self.server.close()
        self.env.stop()
        self.directory.cleanup()

    async def test_fifty_cold_requests_share_one_fetch(self):
        result = await asyncio.gather(*(self.verifier.verify(token()) for _ in range(50)))
        self.assertTrue(all(r['sub'] == 'fixture' for r in result))
        self.assertEqual(self.calls, 1)
        metric = self.path.read_text()
        self.assertIn('memory_proxy_jwks_fetch_seconds_count{outcome="success"} 1', metric)
        self.assertIn('memory_proxy_jwks_fetch_seconds_bucket{outcome="success",le="+Inf"} 1', metric)

    async def test_failure_is_cached_for_thirty_seconds(self):
        self.status = 503
        results = await asyncio.gather(*(self.verifier.verify(token()) for _ in range(50)))
        self.assertEqual(results, [None] * 50)
        self.assertEqual(self.calls, 1)
        self.assertGreater(self.verifier._retry_after - time.monotonic(), 29)
        self.assertLessEqual(self.verifier._retry_after - time.monotonic(), 30)
        self.assertIsNone(await self.verifier.verify(token()))
        self.assertEqual(self.calls, 1)
        self.verifier._retry_after = 0
        self.status = 200
        self.assertIsNotNone(await self.verifier.verify(token()))
        self.assertEqual(self.calls, 2)
        self.assertIn('memory_proxy_jwks_fetch_failures_total 1', self.path.read_text())

    async def test_expired_keys_survive_failed_refresh(self):
        self.assertIsNotNone(await self.verifier.verify(token()))
        old = self.verifier._keys
        self.verifier._fetched_at -= 301
        self.status = 503
        self.assertIsNotNone(await self.verifier.verify(token()))
        await self.verifier._fetch_task
        self.assertIs(self.verifier._keys, old)
        self.assertEqual(self.calls, 2)
        self.assertIsNotNone(await self.verifier.verify(token()))
        self.assertEqual(self.calls, 2)

    async def test_keys_replace_atomically_and_removed_key_is_rejected(self):
        await self.verifier.verify(token())
        old = self.verifier._keys
        self.document = {'keys': [jwk(NEXT, 'next'), {'kty': 'RSA', 'n': 'broken'}]}
        self.release.clear()
        self.entered.clear()
        pending = asyncio.create_task(self.verifier._ensure_keys(force=True))
        await asyncio.wait_for(self.entered.wait(), 1)
        self.assertIs(self.verifier._keys, old)
        self.release.set()
        with self.assertLogs('auth-proxy', level='INFO') as logs:
            await pending
        self.assertIn('JWKS entries skipped: 1', '\n'.join(logs.output))
        self.assertEqual(list(self.verifier._keys), ['next'])
        self.assertIsNotNone(await self.verifier.verify(token(NEXT, 'next')))
        self.assertIsNone(await self.verifier.verify(token()))

    async def test_mixed_rsa_and_non_rsa_keys_accept_usable_entries(self):
        self.document = {'keys': [{'kty': 'EC'}, jwk(KEY), None, {'kid': []}]}
        self.assertIsNotNone(await self.verifier.verify(token()))
        self.assertEqual(list(self.verifier._keys), ['key'])

    async def test_empty_authoritative_set_rejects_all_tokens(self):
        await self.verifier.verify(token())
        self.document = {'keys': []}
        await self.verifier._ensure_keys(force=True)
        self.assertEqual(self.verifier._keys, {})
        self.assertIsNone(await self.verifier.verify(token()))
        self.assertEqual(self.calls, 2)
        self.assertGreater(self.verifier._retry_after - time.monotonic(), 29)
        self.assertLessEqual(self.verifier._retry_after - time.monotonic(), 30)

    async def test_empty_set_retries_at_thirty_seconds_independent_of_ttl(self):
        signed = token()
        for ttl in (1, 300, 900):
            with self.subTest(cache_ttl=ttl):
                await self.verifier.close()
                self.verifier = proxy.TokenVerifier(str(self.server.make_url('/keys')), ISSUER, cache_ttl=ttl)
                self.calls = 0
                self.document = {'keys': []}
                now = [1000.0]
                # Replace only the verifier's clock; asyncio and aiohttp keep
                # their real clocks and the fetch still uses a real endpoint.
                clock = SimpleNamespace(monotonic=lambda: now[0])
                with patch.object(proxy, 'time', clock):
                    self.assertIsNone(await self.verifier.verify(signed))
                    self.assertEqual(self.calls, 1)
                    self.document = {'keys': [jwk(KEY)]}
                    for elapsed in (0, 1, 10, 20, 29.999):
                        now[0] = 1000.0 + elapsed
                        for _ in range(3):
                            self.assertIsNone(await self.verifier.verify(signed))
                        self.assertEqual(self.calls, 1)
                    now[0] = 1030.0
                    self.assertIsNotNone(await self.verifier.verify(signed))
                    self.assertEqual(self.calls, 2)

    async def test_invalid_document_and_network_failure_preserve_keys(self):
        await self.verifier.verify(token())
        old = self.verifier._keys
        for document in [[], {}, {'keys': None}]:
            self.document = document
            self.verifier._retry_after = 0
            await self.verifier._ensure_keys(force=True)
            self.assertIs(self.verifier._keys, old)
            self.assertIsNotNone(await self.verifier.verify(token()))
        await self.server.close()
        self.verifier._retry_after = 0
        await self.verifier._ensure_keys(force=True)
        self.assertIs(self.verifier._keys, old)
        self.assertIsNotNone(await self.verifier.verify(token()))

    async def test_real_timeout_enters_negative_cache(self):
        self.release.clear()
        started = time.monotonic()
        # Exercise the real configured timeout. The outer bound kills a 300s
        # mutation promptly; aiohttp may round the 10s deadline up by <1s.
        self.assertIsNone(await asyncio.wait_for(self.verifier.verify(token()), 12))
        elapsed = time.monotonic() - started
        self.assertGreaterEqual(elapsed, 9)
        self.assertLess(elapsed, 12)
        self.assertEqual(self.calls, 1)
        self.assertIsNone(await self.verifier.verify(token()))
        self.assertEqual(self.calls, 1)
        self.assertGreater(self.verifier._retry_after - time.monotonic(), 29)

    async def test_metric_failures_do_not_break_verification(self):
        with patch.object(self.verifier, '_record_fetch', side_effect=RuntimeError('fixture')):
            self.assertIsNotNone(await self.verifier.verify(token()))
        for failure in [OSError('fixture'), RuntimeError('fixture')]:
            with patch.object(proxy.os, 'replace', side_effect=failure), \
                 patch.object(proxy.os, 'unlink', side_effect=failure):
                await self.verifier._ensure_keys(force=True)
                self.assertIsNotNone(await self.verifier.verify(token()))

    async def test_metric_disk_io_does_not_block_other_authenticated_requests(self):
        import threading
        entered, release = threading.Event(), threading.Event()
        gaps = []
        def blocked(*args):
            entered.set()
            release.wait(2)
        async def heartbeat():
            previous = time.perf_counter()
            while True:
                await asyncio.sleep(.005)
                now = time.perf_counter()
                gaps.append(now - previous)
                previous = now
        ticker = asyncio.create_task(heartbeat())
        await asyncio.sleep(0)
        with patch.object(self.verifier, '_record_fetch', side_effect=blocked):
            pending = asyncio.create_task(self.verifier.verify(token()))
            try:
                for _ in range(100):
                    if entered.is_set():
                        break
                    await asyncio.sleep(.005)
                self.assertTrue(entered.is_set())
                await asyncio.sleep(.02)
                self.assertTrue(gaps)
                print(f'blocked metric I/O max heartbeat gap={max(gaps):.6f}s')
                self.assertLess(max(gaps), .1)
                self.assertFalse(pending.done(), 'metric writer must still be blocked')
                self.assertIsNotNone(await asyncio.wait_for(self.verifier.verify(token()), .1))
            finally:
                release.set()
                await pending
                ticker.cancel()
                await asyncio.gather(ticker, return_exceptions=True)

    async def test_refused_connection_enters_negative_cache(self):
        await self.server.close()
        self.assertIsNone(await self.verifier.verify(token()))
        self.assertEqual(self.verifier._fetch_counts['failure'], 1)
        self.assertIsNone(await self.verifier.verify(token()))
        self.assertEqual(self.verifier._fetch_counts['failure'], 1)

    async def test_redirect_is_not_followed(self):
        self.status = 302
        self.assertIsNone(await self.verifier.verify(token()))
        self.assertEqual(self.redirects, 0)
        self.assertEqual(self.calls, 1)

    async def test_signature_rotation_has_one_shared_forced_refresh(self):
        await self.verifier.verify(token())
        self.document = {'keys': [jwk(NEXT)]}
        result = await asyncio.gather(*(self.verifier.verify(token(NEXT)) for _ in range(50)))
        self.assertTrue(all(result))
        self.assertEqual(self.calls, 2)

    async def test_successful_rotation_does_not_cache_a_failure(self):
        await self.verifier.verify(token())
        self.document = {'keys': [jwk(NEXT)]}
        self.assertIsNotNone(await self.verifier.verify(token(NEXT)))
        self.document = {'keys': [jwk(KEY)]}
        self.assertIsNotNone(await self.verifier.verify(token()))
        self.assertEqual(self.calls, 3)

    async def test_bad_signatures_do_not_trigger_unbounded_fetches(self):
        await self.verifier.verify(token())
        self.assertIsNone(await self.verifier.verify(token(NEXT)))
        self.assertIsNone(await self.verifier.verify(token(NEXT)))
        self.assertEqual(self.calls, 2)

    async def test_repeated_bad_tokens_do_not_extend_forced_refresh_window(self):
        now = [1000.0]
        with patch.object(proxy, 'time', SimpleNamespace(monotonic=lambda: now[0])):
            self.assertIsNotNone(await self.verifier.verify(token()))
            bad = token(NEXT)
            self.assertIsNone(await self.verifier.verify(bad))
            self.assertEqual(self.calls, 2)
            for elapsed in (5, 10, 20, 29.999):
                now[0] = 1000.0 + elapsed
                self.assertIsNone(await self.verifier.verify(bad))
                self.assertEqual(self.calls, 2)
                self.assertEqual(self.verifier._force_after, 1030.0)
            self.document = {'keys': [jwk(NEXT)]}
            now[0] = 1030.0
            self.assertIsNotNone(await self.verifier.verify(bad))
            self.assertEqual(self.calls, 3)

    async def test_cancelled_creator_leaves_shared_fetch_running(self):
        self.release.clear()
        creator = asyncio.create_task(self.verifier.verify(token()))
        await asyncio.wait_for(self.entered.wait(), 1)
        waiter = asyncio.create_task(self.verifier.verify(token()))
        await asyncio.sleep(0)
        creator.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await creator
        self.assertFalse(self.verifier._fetch_task.done())
        self.assertFalse(waiter.done())
        self.release.set()
        self.assertIsNotNone(await waiter)
        self.assertEqual(self.calls, 1)

    async def test_cancelled_waiter_does_not_cancel_other_waiters(self):
        self.release.clear()
        first = asyncio.create_task(self.verifier.verify(token()))
        await asyncio.wait_for(self.entered.wait(), 1)
        second = asyncio.create_task(self.verifier.verify(token()))
        await asyncio.sleep(0)
        second.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await second
        self.assertFalse(first.done())
        self.release.set()
        self.assertIsNotNone(await first)
        self.assertEqual(self.calls, 1)

    async def test_shutdown_drains_fetch(self):
        self.release.clear()
        pending = asyncio.create_task(self.verifier.verify(token()))
        await asyncio.wait_for(self.entered.wait(), 1)
        await self.verifier.close()
        with self.assertRaises(asyncio.CancelledError):
            await pending
        self.assertTrue(self.verifier._fetch_task.done())

    async def test_claim_checks_and_kid_fallback_are_preserved(self):
        self.assertIsNotNone(await self.verifier.verify(token(kid='unknown', aud='other')))
        for claims in [dict(iss='https://wrong.example'), dict(exp=1), dict(nbf=int(time.time())+600)]:
            self.assertIsNone(await self.verifier.verify(token(**claims)))
        unsigned = jwt.encode({'iss': ISSUER}, '', algorithm='none')
        self.assertIsNone(await self.verifier.verify(unsigned))

    async def test_hanging_refresh_keeps_authenticated_p95_under_100ms(self):
        await self.verifier.verify(token())
        async def upstream(request):
            return web.json_response({'authenticated': True})
        up = web.Application()
        up.router.add_route('*', '/{tail:.*}', upstream)
        async with TestServer(up) as server:
            app = web.Application()
            app.on_startup.append(proxy.on_startup)
            app.on_cleanup.append(proxy.on_cleanup)
            app.router.add_route('*', '/{tail:.*}', proxy.handle)
            with patch.object(proxy, 'verifier', self.verifier), \
                 patch.object(proxy, 'MEMORY_AUDIENCES', set()), \
                 patch.object(proxy, 'UPSTREAM_URL', str(server.make_url('')).rstrip('/')):
                async with TestClient(TestServer(app)) as client:
                    for expired in [False, True]:
                        self.release.clear()
                        self.entered.clear()
                        if expired:
                            self.verifier._fetched_at -= 301
                            started = time.perf_counter()
                            await asyncio.wait_for(self.verifier._ensure_keys(), .1)
                            elapsed = time.perf_counter() - started
                            print(f'TTL-expired refresh scheduling returned in {elapsed:.6f}s')
                            self.assertLess(elapsed, .1)
                            pending = self.verifier._fetch_task
                        else:
                            pending = asyncio.create_task(self.verifier._ensure_keys(force=True))
                        await asyncio.wait_for(self.entered.wait(), 1)
                        self.assertFalse(self.verifier._fetch_task.done())
                        latencies = []
                        signed = token()
                        for _ in range(20):
                            started = time.perf_counter()
                            response = await asyncio.wait_for(client.get('/mcp', headers={
                                'Authorization': 'Bearer ' + signed}), .5)
                            self.assertEqual(response.status, 200)
                            self.assertEqual(await response.json(), {'authenticated': True})
                            latencies.append(time.perf_counter() - started)
                        p95 = sorted(latencies)[18]
                        print(f'authenticated JWKS hanging expired={expired} p95={p95:.6f}s')
                        self.assertLess(p95, .1)
                        self.release.set()
                        await pending


class EntryPoint(unittest.IsolatedAsyncioTestCase):
    async def test_run_app_does_not_log_query_string(self):
        with socket.socket() as s:
            s.bind(('127.0.0.1', 0))
            port = s.getsockname()[1]
        env = {'PATH': os.defpath, 'PORT': str(port), 'MEMORY_PROXY_JWKS_METRICS_FILE': '', 'MEMORY_PROXY_METRICS_FILE': ''}
        process = await asyncio.create_subprocess_exec(
            sys.executable, '-u', str(Path(proxy.__file__)), env=env,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        marker = 'QUERY_SENTINEL_MUST_NOT_APPEAR'
        try:
            async with ClientSession() as session:
                for _ in range(100):
                    if process.returncode is not None:
                        self.fail('proxy exited before listening')
                    try:
                        async with session.get(f'http://127.0.0.1:{port}/health?q={marker}') as response:
                            self.assertEqual(response.status, 200)
                        break
                    except OSError:
                        await asyncio.sleep(0.05)
                else:
                    self.fail('proxy did not listen')
                for path, status in [('/mcp', 401), ('/.well-known/oauth-protected-resource', 200)]:
                    async with session.get(f'http://127.0.0.1:{port}{path}?q={marker}') as response:
                        self.assertEqual(response.status, status)
        finally:
            process.terminate()
            stdout, stderr = await asyncio.wait_for(process.communicate(), 15)
        self.assertIn(b'/health', stderr)
        self.assertNotIn(marker.encode(), stdout + stderr)
        self.assertNotIn(b'aiohttp.access', stdout + stderr)


if __name__ == '__main__':
    unittest.main()
