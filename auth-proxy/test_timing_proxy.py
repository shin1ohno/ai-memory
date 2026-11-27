#!/usr/bin/env python3
"""The aiohttp adapter records verified IDs and initialize versions only."""
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import AsyncMock, patch

os.environ['MEMORY_PROXY_METRICS_FILE'] = ''
sys.path.insert(0, str(Path(__file__).resolve().parent))
import proxy
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer


class ProxyMetrics(unittest.IsolatedAsyncioTestCase):
    async def test_forwarding_and_metadata_without_content_in_textfile(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'proxy.prom'
            with patch.dict(os.environ, {'ALLOWED_CLIENT_IDS': '', 'CLIENT_POLICY': ''}):
                metric = proxy.Metrics('proxy', str(path))
            seen = []
            async def upstream(request):
                seen.append((request.path_qs, await request.read(), dict(request.headers)))
                return web.json_response({'jsonrpc':'2.0', 'id':1, 'result':{}})
            up = web.Application()
            up.router.add_route('*','/{tail:.*}',upstream)
            server = TestServer(up)
            await server.start_server()
            app = web.Application(middlewares=[proxy.request_metrics])
            app.on_startup.append(proxy.on_startup)
            app.on_cleanup.append(proxy.on_cleanup)
            app.router.add_route('*','/{tail:.*}',proxy.handle)
            claims = {'sub':'human@example.test', 'client_id':'dynamic-client', 'aud':[]}
            body = json.dumps({'method':'initialize','params':{'protocolVersion':'2025-11-25'},
                               'content':'BODY_PRIVATE'}).encode()
            try:
                with patch.object(proxy, 'proxy_metrics', metric), \
                     patch.object(proxy, 'UPSTREAM_URL', str(server.make_url('')).rstrip('/')), \
                     patch.object(proxy, 'MEMORY_AUDIENCES', {'memory'}), \
                     patch.object(proxy, 'ALLOWED_CLIENT_IDS', set()), \
                     patch.object(proxy, 'ALLOWED_SUBS', {'human@example.test'}), \
                     patch.object(proxy.verifier, 'verify', AsyncMock(return_value=claims)):
                    async with TestClient(TestServer(app)) as client:
                        response = await client.post('/mcp?q=QUERY_PRIVATE', data=body,
                                                     headers={'Authorization':'Bearer fixture'})
                        self.assertEqual(response.status, 200)
                        self.assertEqual((await response.json())['result'], {})
                        deep = b'[' * 60000
                        response = await client.post('/mcp', data=deep,
                                                     headers={'Authorization':'Bearer fixture'})
                        self.assertEqual(response.status, 200)
                        await response.read()
            finally:
                await server.close()
            self.assertEqual(seen[0][0], '/mcp?q=QUERY_PRIVATE')
            self.assertEqual(seen[0][1], body)
            self.assertEqual(seen[0][2]['X-Verified-Client-Id'], 'dynamic-client')
            self.assertEqual(seen[1][1], b'[' * 60000)
            output = path.read_text()
            self.assertIn('requests_total{client_id="dynamic-client",protocol_version="2025-11-25",status="200"} 1', output)
            self.assertNotIn('PRIVATE', output)
            self.assertNotIn('Bearer', output)


if __name__ == '__main__':
    unittest.main()
