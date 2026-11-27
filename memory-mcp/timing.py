"""Bounded, stdlib-only Prometheus textfiles; request contents never become labels."""
from __future__ import annotations

import asyncio
from contextlib import contextmanager
from contextvars import ContextVar
from functools import wraps
import json
import logging
import math
import os
import re
import tempfile
import threading
import time

BUCKETS = (0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, math.inf)
TOOLS = frozenset({'recall', 'remember', 'ingest', 'revise', 'forget', 'get', 'browse', 'memory_stats'})
VERSIONS = frozenset({'2024-11-05', '2025-03-26', '2025-06-18', '2025-11-25'})
CURRENT_TOOL = ContextVar('memory_metric_tool', default='other')
logger = logging.getLogger('memory-timing')


class Metrics:
    def __init__(self, component, path=None):
        if component not in ('mcp', 'proxy'):
            raise ValueError('unknown component')
        self.prefix = 'memory_' + component
        self.path = path if path is not None else os.environ.get(
            f'MEMORY_{component.upper()}_METRICS_FILE',
            f'/var/lib/node_exporter/textfile/{self.prefix}.prom')
        self.histograms = {}
        self.counters = {}
        self.gauges = {}
        self.lock = threading.Lock()
        # Client labels come from configuration, never arbitrary inbound IDs.
        configured = os.environ.get('ALLOWED_CLIENT_IDS', '').split(',')
        configured += [rule.split('=', 1)[0] for rule in os.environ.get('CLIENT_POLICY', '').split(';')]
        self.verified_clients = set()
        self.clients = frozenset(s.strip() for s in configured if s.strip())

    def client(self, value, verified=False):
        if not isinstance(value, str):
            return 'other'
        if value in self.clients:
            return value
        # Dynamic OAuth registrations need distinct counts too, but only the
        # proxy may admit them, after both JWT verification and authorization.
        if not verified or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.:/@-]{0,127}', value):
            return 'other'
        with self.lock:
            if value in self.verified_clients:
                return value
            if len(self.verified_clients) < 128:
                self.verified_clients.add(value)
                return value
        return 'other'

    def version(self, value):
        return value if isinstance(value, str) and value in VERSIONS else 'other'

    def observe(self, name, seconds, **labels):
        key = (name, tuple(sorted(labels.items())))
        with self.lock:
            values = self.histograms.setdefault(key, [0.0, 0, [0] * len(BUCKETS)])
            values[0] += max(0.0, seconds)
            values[1] += 1
            for i, bound in enumerate(BUCKETS):
                values[2][i] += seconds <= bound

    def count(self, name, **labels):
        key = (name, tuple(sorted(labels.items())))
        with self.lock:
            self.counters[key] = self.counters.get(key, 0) + 1

    def gauge(self, name, value):
        with self.lock:
            self.gauges[name] = value

    @contextmanager
    def phase(self, name):
        started = time.perf_counter()
        try:
            yield
        finally:
            self.observe('phase_seconds', time.perf_counter() - started,
                         tool=CURRENT_TOOL.get(), phase=name)

    async def measure(self, phase, awaitable):
        with self.phase(phase):
            return await awaitable

    def tool(self, name):
        def decorate(function):
            @wraps(function)
            async def measured(*args, **kwargs):
                token = CURRENT_TOOL.set(name if name in TOOLS else 'other')
                try:
                    with self.phase('total'):
                        return await function(*args, **kwargs)
                finally:
                    CURRENT_TOOL.reset(token)
            return measured
        return decorate

    def render(self):
        def labels(values):
            if not values:
                return ''
            return '{' + ','.join(f'{k}={json.dumps(str(v), ensure_ascii=True)}' for k, v in values) + '}'

        lines = []
        types = set()
        with self.lock:
            for (name, tags), (total, count, buckets) in sorted(self.histograms.items()):
                full = self.prefix + '_' + name
                if full not in types:
                    lines.append(f'# TYPE {full} histogram')
                    types.add(full)
                for bound, value in zip(BUCKETS, buckets):
                    le = '+Inf' if math.isinf(bound) else str(bound)
                    lines.append(f'{full}_bucket{labels(tags + (("le", le),))} {value}')
                lines.extend([f'{full}_sum{labels(tags)} {total}', f'{full}_count{labels(tags)} {count}'])
            for (name, tags), count in sorted(self.counters.items()):
                full = self.prefix + '_' + name
                if full not in types:
                    lines.append(f'# TYPE {full} counter')
                    types.add(full)
                lines.append(f'{full}{labels(tags)} {count}')
            for name, value in sorted(self.gauges.items()):
                full = self.prefix + '_' + name
                lines.extend([f'# TYPE {full} gauge', f'{full} {value}'])
        return '\n'.join(lines) + '\n'

    def flush(self):
        if not self.path:
            return
        temporary = None
        try:
            with tempfile.NamedTemporaryFile(mode='w', dir=os.path.dirname(self.path) or '.',
                                             prefix='.memory-', delete=False) as output:
                temporary = output.name
                output.write(self.render())
                os.fchmod(output.fileno(), 0o644)
            os.replace(temporary, self.path)
        except Exception as exc:
            logger.warning('Metric write failed: %s', type(exc).__name__)
        finally:
            if temporary:
                try:
                    os.unlink(temporary)
                except FileNotFoundError:
                    pass
                except Exception as exc:
                    logger.warning('Metric cleanup failed: %s', type(exc).__name__)

    async def monitor(self, sessions=None):
        loop = asyncio.get_running_loop()
        next_flush = loop.time()
        while True:
            started = loop.time()
            await asyncio.sleep(0.1)
            try:
                self.observe('event_loop_lag_seconds', max(0, loop.time() - started - 0.1))
                if sessions is not None:
                    self.gauge('sessions', sessions())
            except Exception as exc:
                logger.warning('Metric sampling failed: %s', type(exc).__name__)
            if loop.time() >= next_flush:
                # Slow storage must not contribute to the loop delay being measured.
                try:
                    await asyncio.to_thread(self.flush)
                except Exception as exc:
                    logger.warning('Metric publication failed: %s', type(exc).__name__)
                else:
                    next_flush = loop.time() + 5


mcp_metrics = Metrics('mcp')


class RequestMetrics:
    """ASGI tee: preserve every message; inspect bounded initialize metadata only."""
    def __init__(self, app, metrics=mcp_metrics):
        self.app = app
        self.metrics = metrics

    async def __call__(self, scope, receive, send):
        if scope['type'] != 'http':
            return await self.app(scope, receive, send)
        headers = {k.lower(): v.decode('latin1') for k, v in scope.get('headers', [])}
        version = headers.get(b'mcp-protocol-version', '')
        client = self.metrics.client(headers.get(b'x-verified-client-id', ''))
        inspect = scope.get('path', '').rstrip('/') == '/memory/mcp' and scope.get('method') == 'POST'
        body = bytearray()
        status = 500
        started = time.perf_counter()

        async def receiving():
            nonlocal version, inspect
            message = await receive()
            if inspect and message['type'] == 'http.request':
                chunk = message.get('body', b'')
                if len(body) + len(chunk) > 65536:
                    body.clear()
                    inspect = False
                else:
                    body.extend(chunk)
                    if not message.get('more_body'):
                        try:
                            value = json.loads(body)
                            if isinstance(value, dict) and value.get('method') == 'initialize':
                                params = value.get('params', {})
                                if isinstance(params, dict):
                                    version = params.get('protocolVersion', version)
                        except (ValueError, UnicodeError, RecursionError):
                            pass
                        body.clear()
                        inspect = False
            return message

        async def sending(message):
            nonlocal status
            if message['type'] == 'http.response.start':
                status = message['status']
            await send(message)

        try:
            await self.app(scope, receiving, sending)
        finally:
            # Request rate is rate(requests_total[...]); SSE remains one request.
            tags = dict(client_id=client, protocol_version=self.metrics.version(version), status=str(status))
            self.metrics.count('requests_total', **tags)
            self.metrics.observe('request_seconds', time.perf_counter() - started, **tags)
