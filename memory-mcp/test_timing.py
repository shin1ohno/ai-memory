#!/usr/bin/env python3
"""Check telemetry at its ASGI, task and textfile boundaries."""
import ast
import asyncio
import json
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
os.environ['MEMORY_MCP_METRICS_FILE'] = ''
import timing


class Textfile(unittest.TestCase):
    def test_imports_are_standard_library_only(self):
        tree = ast.parse(Path(timing.__file__).read_text())
        imports = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imports.extend(n.name.split('.')[0] for n in node.names)
            elif isinstance(node, ast.ImportFrom):
                imports.append(node.module.split('.')[0])
        self.assertTrue(imports)
        self.assertTrue(set(imports) <= sys.stdlib_module_names)

    def test_histogram_and_atomic_publication(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'metric.prom'
            metric = timing.Metrics('mcp', str(path))
            metric.observe('phase_seconds', .04, phase='embed', tool='recall')
            metric.observe('phase_seconds', .2, phase='embed', tool='recall')
            metric.flush()
            published = path.read_text()
            self.assertIn('phase_seconds_bucket{phase="embed",tool="recall",le="0.05"} 1', published)
            self.assertIn('phase_seconds_bucket{phase="embed",tool="recall",le="+Inf"} 2', published)
            self.assertIn('phase_seconds_count{phase="embed",tool="recall"} 2', published)
            self.assertEqual(path.stat().st_mode & 0o777, 0o644)
            with patch.object(timing.os, 'replace', side_effect=OSError('failure')):
                metric.count('requests_total')
                metric.flush()
            self.assertEqual(path.read_text(), published)
            self.assertEqual(list(Path(directory).iterdir()), [path])

    def test_publication_and_cleanup_failures_are_contained(self):
        with tempfile.TemporaryDirectory() as directory:
            metric = timing.Metrics('mcp', str(Path(directory)/'metric.prom'))
            with patch.object(timing.os, 'replace', side_effect=RuntimeError('fixture')), \
                 patch.object(timing.os, 'unlink', side_effect=RuntimeError('fixture')), \
                 self.assertLogs('memory-timing', level='WARNING') as logs:
                metric.flush()
            self.assertIn('Metric cleanup failed: RuntimeError', '\n'.join(logs.output))

    def test_labels_cannot_expand_with_untrusted_values(self):
        with patch.dict(os.environ, {'ALLOWED_CLIENT_IDS': 'allowed', 'CLIENT_POLICY': ''}):
            metric = timing.Metrics('proxy', '')
        self.assertEqual(metric.client('allowed'), 'allowed')
        for value in ['SECRET', 'x'*10000, '', 'allowed\n']:
            self.assertEqual(metric.client(value), 'other')
        for value in ['SECRET', [], {}, None]:
            self.assertEqual(metric.version(value), 'other')


class VerifiedClients(unittest.TestCase):
    def test_dynamic_clients_need_authorization_and_have_a_hard_cap(self):
        metric = timing.Metrics('proxy', '')
        self.assertEqual(metric.client('new-client'), 'other')
        self.assertEqual(metric.client('new-client', verified=True), 'new-client')
        for i in range(127):
            self.assertEqual(metric.client(f'client-{i}', verified=True), f'client-{i}')
        self.assertEqual(metric.client('overflow', verified=True), 'other')
        self.assertEqual(metric.client('new-client', verified=True), 'new-client')
        for value in ['with spaces', 'a\nsecret', [], None]:
            self.assertEqual(metric.client(value, verified=True), 'other')


class Runtime(unittest.IsolatedAsyncioTestCase):
    async def test_asgi_preserves_messages_and_counts_initialize_metadata(self):
        with patch.dict(os.environ, {'CLIENT_POLICY': 'client=recall', 'ALLOWED_CLIENT_IDS': ''}):
            metric = timing.Metrics('mcp', '')
        body = json.dumps({'method': 'initialize', 'params': {'protocolVersion': '2025-11-25'},
                           'secret': 'BODY_SECRET'}).encode()
        incoming = [{'type': 'http.request', 'body': body[:10], 'more_body': True},
                    {'type': 'http.request', 'body': body[10:], 'more_body': False}]
        seen, sent = [], []
        async def receive():
            return incoming.pop(0)
        async def send(message):
            sent.append(message)
        async def app(scope, receive, send):
            seen.append(await receive())
            seen.append(await receive())
            await send({'type': 'http.response.start', 'status': 200, 'headers': []})
            await send({'type': 'http.response.body', 'body': b'reply'})
        scope = dict(type='http', path='/memory/mcp', method='POST', query_string=b'QUERY_SECRET',
                     headers=[(b'x-verified-client-id', b'client')])
        await timing.RequestMetrics(app, metric)(scope, receive, send)
        self.assertEqual(b''.join(m['body'] for m in seen), body)
        self.assertTrue(seen[0]['more_body'])
        self.assertEqual(sent[-1]['body'], b'reply')
        output = metric.render()
        self.assertIn('requests_total{client_id="client",protocol_version="2025-11-25",status="200"} 1', output)
        self.assertNotIn('SECRET', output)

    async def test_bad_or_oversize_initialize_metadata_never_changes_response(self):
        for payload in [b'[' * 60000, b'not json', json.dumps({'method': 'initialize', 'params': {'protocolVersion': []}}).encode(), b'x'*70000]:
            metric = timing.Metrics('mcp', '')
            async def receive():
                return {'type': 'http.request', 'body': payload}
            async def send(message):
                self.assertEqual(message['status'], 400)
            async def app(scope, receive, send):
                self.assertEqual((await receive())['body'], payload)
                await send({'type': 'http.response.start', 'status': 400})
            await timing.RequestMetrics(app, metric)(dict(type='http', path='/memory/mcp', method='POST'), receive, send)
            self.assertIn('protocol_version="other",status="400"} 1', metric.render())

    async def test_unconfigured_header_is_never_a_verified_client_label(self):
        with patch.dict(os.environ, {'CLIENT_POLICY': '', 'ALLOWED_CLIENT_IDS': ''}):
            metric = timing.Metrics('mcp', '')
        async def receive():
            return {'type': 'http.request', 'body': b''}
        async def send(message):
            pass
        async def app(scope, receive, send):
            await send({'type': 'http.response.start', 'status': 200})
        scope = dict(type='http', headers=[(b'x-verified-client-id', b'dynamic-client')])
        await timing.RequestMetrics(app, metric)(scope, receive, send)
        self.assertIn('client_id="other"', metric.render())
        self.assertNotIn('dynamic-client', metric.render())

    async def test_monitor_logs_failures_and_recovers(self):
        metric = timing.Metrics('mcp', '')
        from unittest.mock import Mock
        sessions = Mock(side_effect=[RuntimeError('sampling'), 3, 3, 3, 3])
        flushed = asyncio.Event()
        loop = asyncio.get_running_loop()
        attempts = []
        def flush():
            attempts.append(1)
            if len(attempts) == 1:
                raise RuntimeError('publication')
            loop.call_soon_threadsafe(flushed.set)
        with patch.object(metric, 'flush', side_effect=flush), \
             self.assertLogs('memory-timing', level='WARNING') as logs:
            task = asyncio.create_task(metric.monitor(sessions))
            try:
                await asyncio.wait_for(flushed.wait(), 1)
                self.assertFalse(task.done())
                self.assertEqual(metric.gauges['sessions'], 3)
            finally:
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)
        self.assertIn('Metric sampling failed: RuntimeError', '\n'.join(logs.output))
        self.assertIn('Metric publication failed: RuntimeError', '\n'.join(logs.output))

    async def test_tool_total_and_failed_phase_keep_context_per_task(self):
        metric = timing.Metrics('mcp', '')
        @metric.tool('recall')
        async def failed():
            with metric.phase('embed'):
                await asyncio.sleep(0)
                raise ValueError('failure')
        @metric.tool('get')
        async def succeeded():
            await asyncio.sleep(0)
            return {'unchanged': True}
        values = await asyncio.gather(failed(), succeeded(), return_exceptions=True)
        self.assertIsInstance(values[0], ValueError)
        self.assertEqual(values[1], {'unchanged': True})
        output = metric.render()
        for phase, tool in [('embed','recall'),('total','recall'),('total','get')]:
            self.assertIn(f'phase_seconds_count{{phase="{phase}",tool="{tool}"}} 1', output)
        self.assertEqual(timing.CURRENT_TOOL.get(), 'other')

    async def test_monitor_publishes_observed_lag_and_session_count(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'mcp.prom'
            metric = timing.Metrics('mcp', str(path))
            task = asyncio.create_task(metric.monitor(lambda: 3))
            await asyncio.sleep(.08)
            time.sleep(.06)
            await asyncio.sleep(.04)
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
            self.assertTrue(path.exists())
            output = path.read_text()
            self.assertIn('memory_mcp_sessions 3', output)
            sample = metric.histograms[('event_loop_lag_seconds', ())]
            self.assertGreater(sample[0], .02)


if __name__ == '__main__':
    unittest.main()
