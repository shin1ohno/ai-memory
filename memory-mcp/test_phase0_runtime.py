#!/usr/bin/env python3
"""Startup and recall concurrency without a live backend or credentials."""
import asyncio
from contextlib import asynccontextmanager
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import AsyncMock, patch

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
os.environ['ES_URL'] = 'http://127.0.0.1:9'
os.environ['ES_PASSWORD'] = 'test-placeholder'
os.environ['VOYAGE_API_KEY'] = 'test-placeholder'

import es_backend as be


class Startup(unittest.TestCase):
    def test_import_never_opens_a_socket(self):
        code = '''
import socket, sys
sys.path.insert(0, sys.argv[1])
def forbidden(*args, **kwargs):
    raise AssertionError("network used during import")
socket.socket.connect = forbidden
socket.socket.connect_ex = forbidden
socket.create_connection = forbidden
socket.getaddrinfo = forbidden
import server
assert [route.path for route in server.app.routes] == ["/memory/sessions/v1", "/memory"]
'''
        result = subprocess.run([sys.executable, '-I', '-c', code, str(HERE)],
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_lifespan_bootstraps_before_sessions_and_requests(self):
        import server
        events = []

        async def ensure():
            events.append('indices')

        @asynccontextmanager
        async def run():
            events.append('manager')
            yield
            events.append('closed')

        async def exercise():
            with patch.object(be, 'ensure_indices', ensure), \
                 patch.object(server.sessions_app, 'start_background', lambda: events.append('sessions')), \
                 patch.object(server.mcp.session_manager, 'run', run):
                async with server.lifespan(server.app):
                    events.append('serving')
        asyncio.run(exercise())
        self.assertEqual(events, ['indices', 'sessions', 'manager', 'serving', 'closed'])

    def test_bootstrap_failure_prevents_serving(self):
        import server

        async def exercise():
            with patch.object(be, 'ensure_indices', AsyncMock(side_effect=RuntimeError('unavailable'))), \
                 patch.object(server.sessions_app, 'start_background') as start:
                with self.assertRaisesRegex(RuntimeError, 'unavailable'):
                    async with server.lifespan(server.app):
                        self.fail('served before indices were ready')
                start.assert_not_called()
        asyncio.run(exercise())


class Recall(unittest.IsolatedAsyncioTestCase):
    async def test_embedding_and_bm25_overlap_then_knn_uses_vector(self):
        embedded = asyncio.Event()
        searched = asyncio.Event()
        calls = []

        async def embed(query):
            self.assertEqual(query, 'example')
            embedded.set()
            await asyncio.wait_for(searched.wait(), 1)
            return [0.1, 0.2]

        async def search(method, path, body):
            calls.append((method, path, body))
            if 'query' in body:
                searched.set()
                await asyncio.wait_for(embedded.wait(), 1)
            else:
                self.assertEqual(body['knn']['query_vector'], [0.1, 0.2])
            return {'hits': {'hits': []}}

        with patch.object(be.voyage, 'embed_query', embed), patch.object(be, '_es_json', search):
            self.assertEqual(await be.recall('example', include_auto=False), {'hits': []})
        self.assertEqual(len(calls), 2)
        self.assertEqual(calls[0][2]['query']['bool']['filter'], calls[1][2]['knn']['filter'])
        self.assertTrue(all(c[0:2] == ('POST', '/memory-all/_search') for c in calls))

    async def test_unavailable_embedding_preserves_bm25_degradation(self):
        with patch.object(be.voyage, 'embed_query', AsyncMock(side_effect=be.voyage.VoyageUnavailable('down'))), \
             patch.object(be, '_es_json', AsyncMock(return_value={'hits': {'hits': []}})) as search:
            self.assertEqual(await be.recall('example'), {'hits': [], 'degraded': 'bm25-only'})
            self.assertEqual(search.await_count, 1)

    async def test_search_failure_cancels_and_drains_embedding(self):
        started = asyncio.Event()
        closed = asyncio.Event()

        async def embed(query):
            started.set()
            try:
                await asyncio.Event().wait()
            finally:
                closed.set()

        async def search(*args):
            await started.wait()
            raise RuntimeError('ES unavailable')

        with patch.object(be.voyage, 'embed_query', embed), patch.object(be, '_es_json', search):
            with self.assertRaisesRegex(RuntimeError, 'ES unavailable'):
                await be.recall('example')
        self.assertTrue(closed.is_set())

    async def test_caller_cancellation_drains_both_legs(self):
        started = [asyncio.Event(), asyncio.Event()]
        closed = [asyncio.Event(), asyncio.Event()]

        async def wait(i):
            started[i].set()
            try:
                await asyncio.Event().wait()
            finally:
                closed[i].set()

        with patch.object(be.voyage, 'embed_query', lambda *_: wait(0)), \
             patch.object(be, '_es_json', lambda *_: wait(1)):
            task = asyncio.create_task(be.recall('example'))
            await asyncio.wait_for(asyncio.gather(*(e.wait() for e in started)), 1)
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
        self.assertTrue(all(e.is_set() for e in closed))


if __name__ == '__main__':
    unittest.main()
