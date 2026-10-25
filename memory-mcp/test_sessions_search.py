#!/usr/bin/env python3
"""sessions_search unit tests (design spec §6.7, §7.2 /search and /preview,
§8 rows 10 and 17). Stubbed ES, stubbed embedding provider, nothing leaves
the process.

    python3 test_sessions_search.py            # stdlib only; the wiring case skips
    /tmp/memory-mcp-venv/bin/python test_sessions_search.py   # + sessions_app wiring

The query bodies are asserted verbatim: a keystroke path that grows a
highlight, loses collapse or forgets the default filters fails here instead of
showing up as a latency regression at one-year scale.
"""

from __future__ import annotations

import asyncio
import contextlib
import copy
import importlib.util
import io
import json
import math
import os
import sys
import types
import unittest
from datetime import datetime, timedelta, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import sessions_search as ss  # noqa: E402

MSG = "/memory-session-message/_search"
SES = "/memory-session/_search"
MGET_PREFIX = "/memory-session/_mget"
NOW = datetime.now(timezone.utc)
SECRETISH_QUERY = "zebra-quokka-unique-query-token"


def es_err():
    """The class sessions_search raises for ES failures: sessions_app's when it
    is loaded (the wiring case loads it), the module's fallback otherwise."""
    return type(ss._es_unavailable(""))


def not_found_err():
    return type(ss._not_found())


def iso(days_ago: float) -> str:
    return (NOW - timedelta(days=days_ago)).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


class Resp:
    def __init__(self, status, payload):
        self.status_code = status
        self._payload = payload

    def json(self):
        if isinstance(self._payload, Exception):
            raise self._payload
        return self._payload


class FakeES:
    """Records every (method, path, body) and answers from `routes`, a dict of
    path -> callable(body) -> (status, payload)."""

    def __init__(self, routes=None):
        self.calls: list = []
        self.routes = routes or {}

    async def request(self, method, path, json=None, **kw):  # noqa: A002
        self.calls.append((method, path, copy.deepcopy(json)))
        base = path.split("?")[0]
        if base not in self.routes:
            raise AssertionError(f"unexpected ES call {method} {path}")
        out = self.routes[base](json)
        if isinstance(out, Exception):
            raise out
        status, payload = out
        return Resp(status, payload)

    def bodies(self, base):
        return [b for (_, p, b) in self.calls if p.split("?")[0] == base]


def es_module(fake):
    m = types.ModuleType("fake_es_backend")
    m._es = fake
    return m


def run(coro):
    return asyncio.run(coro)


def sess(sk, days_ago=1.0, **kw):
    d = {"session_key": sk, "session_id": "00000000-0000-0000-0000-%012d" % (abs(hash(sk)) % 10**12),
         "host": "pro-dev", "title": f"title {sk}", "cwd": "/home/dev/proj",
         "resume_cwd": "/home/dev/proj", "updated_at": iso(days_ago), "jsonl_exists": True,
         "archived": True, "archive_complete": True, "interactive": True,
         "archive_chunks": [{"generation": 0, "offset": 0, "end_offset": 10, "sha256": "0" * 64}]}
    d.update(kw)
    return d


def msg_hits(rows):
    """rows = [(session_key, score)] in rank order."""
    return {"hits": {"hits": [{"_id": f"m{i}", "_score": s, "_source": {"session_key": k}}
                              for i, (k, s) in enumerate(rows)]}}


def standard_routes(lex_rows, sessions, knn_rows=None, counts=None):
    """A FakeES route table: lexical hits, knn hits (when the body has knn),
    hit-count aggregation and _mget over `sessions` (key -> source or None)."""
    def msg_search(body):
        if "knn" in body:
            return 200, msg_hits(knn_rows or [])
        if "aggs" in body:
            keys = body["query"]["bool"]["filter"][1]["terms"]["session_key"]
            return 200, {"aggregations": {"per_session": {"buckets": [
                {"key": k, "doc_count": (counts or {}).get(k, 1)} for k in keys]}}}
        return 200, msg_hits(lex_rows)

    def mget(body):
        docs = []
        for k in body["ids"]:
            src = sessions.get(k)
            docs.append({"_id": k, "found": src is not None, **({"_source": src} if src else {})})
        return 200, {"docs": docs}

    return {MSG: msg_search, MGET_PREFIX: mget}


def lexical_req(**kw):
    body = {"q": "hello world", "mode": "lexical"}
    body.update(kw)
    return ss.parse_request(body)


DEFAULT_FILTERS = [{"term": {"interactive": True}}, {"term": {"is_sidechain": False}}]


class Bodies(unittest.TestCase):
    def test_lexical_body_exact(self):
        self.assertEqual(ss.lexical_body(lexical_req()), {
            "size": 50,
            "_source": ["session_key"],
            "track_total_hits": False,
            "query": {"bool": {
                "must": [{"multi_match": {"query": "hello world", "fields": ["text^2"],
                                          "operator": "and"}}],
                "filter": DEFAULT_FILTERS}},
            "collapse": {"field": "session_key"},
        })

    def test_keystroke_bodies_never_highlight(self):
        req = lexical_req(deep=True, hosts=["pro-dev"], cwd_prefix="/a", since="2026-01-01T00:00:00Z")
        for body in (ss.lexical_body(req), ss.knn_body(req, [0.1] * 4),
                     ss.hit_count_body(req, ["sk_a"]), ss.recent_body(req)):
            self.assertNotIn("highlight", body)
            self.assertIs(body["track_total_hits"], False)
        self.assertNotIn("highlight", json.dumps(ss.lexical_body(req)))

    def test_deep_adds_tool_text_half_boost(self):
        mm = ss.lexical_body(lexical_req(deep=True))["query"]["bool"]["must"][0]["multi_match"]
        self.assertEqual(mm["fields"], ["text^2", "tool_text^0.5"])
        mm = ss.lexical_body(lexical_req(deep=False))["query"]["bool"]["must"][0]["multi_match"]
        self.assertEqual(mm["fields"], ["text^2"])

    def test_flags_widen_default_filters(self):
        self.assertEqual(ss.message_filters(lexical_req(include_headless=True)),
                         [{"term": {"is_sidechain": False}}])
        self.assertEqual(ss.message_filters(lexical_req(include_sidechain=True)),
                         [{"term": {"interactive": True}}])
        self.assertEqual(ss.message_filters(lexical_req(include_headless=True,
                                                        include_sidechain=True)), [])

    def test_optional_filters(self):
        f = ss.message_filters(lexical_req(hosts=["mini", "pro-dev", "mini"], cwd_prefix="/a/b/",
                                           since="2026-09-01T00:00:00Z"))
        self.assertEqual(f, [
            {"terms": {"host": ["mini", "pro-dev"]}},
            {"bool": {"should": [{"term": {"cwd": "/a/b"}}, {"prefix": {"cwd": "/a/b/"}}],
                      "minimum_should_match": 1}},
            {"term": {"interactive": True}},
            {"term": {"is_sidechain": False}},
            {"range": {"ts": {"gte": "2026-09-01T00:00:00Z"}}},
        ])
        self.assertEqual(ss.message_filters(lexical_req(cwd_prefix="/"))[0], {"prefix": {"cwd": "/"}})

    def test_knn_body(self):
        req = lexical_req(mode="hybrid", hosts=["air"])
        b = ss.knn_body(req, [0.5, 0.25])
        self.assertEqual(b["knn"], {"field": "embedding", "query_vector": [0.5, 0.25], "k": 100,
                                    "num_candidates": 1000,
                                    "filter": {"bool": {"filter": ss.message_filters(req)}}})
        self.assertEqual((b["size"], b["_source"]), (100, ["session_key"]))

    def test_recent_body_excludes_purged(self):
        b = ss.recent_body(ss.parse_request({"q": "", "limit": 20}))
        self.assertEqual(b["size"], 20)
        self.assertEqual(b["query"]["bool"]["filter"][0],
                         {"bool": {"must_not": [{"exists": {"field": "purged_at"}}]}})
        self.assertIn({"term": {"interactive": True}}, b["query"]["bool"]["filter"])
        self.assertEqual(b["sort"], [{"updated_at": {"order": "desc", "missing": "_last"}}])
        b = ss.recent_body(ss.parse_request({"q": "", "include_headless": True}))
        self.assertNotIn({"term": {"interactive": True}}, b["query"]["bool"]["filter"])


class Validation(unittest.TestCase):
    def test_rejects(self):
        bad = [
            "not a dict", {"mode": "fuzzy"}, {"limit": 0}, {"limit": 51}, {"limit": True},
            {"limit": "5"}, {"deep": "yes"}, {"include_headless": 1}, {"hosts": "pro-dev"},
            {"hosts": ["Pro_Dev"]}, {"hosts": ["h"] * 17}, {"cwd_prefix": ""},
            {"cwd_prefix": 3}, {"since": "7d"}, {"since": "now-7d"}, {"q": 5},
            {"q": "x" * 1001},
        ]
        for body in bad:
            with self.subTest(body=body), self.assertRaises(ValueError):
                ss.parse_request(body)

    def test_defaults(self):
        self.assertEqual(ss.parse_request({}), {
            "q": "", "mode": "lexical", "deep": False, "hosts": None, "cwd_prefix": None,
            "include_headless": False, "include_sidechain": False, "since": None, "limit": 50})


class Recency(unittest.TestCase):
    def test_nudge_math(self):
        now = datetime(2026, 10, 6, tzinfo=timezone.utc)
        self.assertAlmostEqual(ss.recency_nudge("2026-10-06T00:00:00Z", now), 0.05)
        self.assertAlmostEqual(ss.recency_nudge("2026-09-06T00:00:00Z", now), 0.025)
        self.assertAlmostEqual(ss.recency_nudge("2026-08-07T00:00:00Z", now), 0.0125)
        self.assertAlmostEqual(ss.recency_nudge("2026-10-01T00:00:00Z", now),
                               0.05 * math.pow(2, -5 / 30))
        self.assertAlmostEqual(ss.recency_nudge("2026-12-01T00:00:00Z", now), 0.05)  # future
        self.assertEqual(ss.recency_nudge(None, now), 0.0)
        self.assertEqual(ss.recency_nudge("garbage", now), 0.0)


class _EmbedStub:
    def __init__(self, vec=None, delay=0.0, exc=None):
        self.vec = vec or [0.1, 0.2, 0.3]
        self.delay, self.exc, self.calls = delay, exc, []

    async def __call__(self, q):
        self.calls.append(q)
        if self.delay:
            await asyncio.sleep(self.delay)
        if self.exc:
            raise self.exc
        return self.vec


class SearchBase(unittest.TestCase):
    def setUp(self):
        ss._CACHE.clear()
        self._timeout = ss.EMBED_TIMEOUT_S
        self.stderr = io.StringIO()
        self._redir = contextlib.redirect_stderr(self.stderr)
        self._redir.__enter__()

    def tearDown(self):
        self._redir.__exit__(None, None, None)
        ss.EMBED_QUERY = None
        ss.EMBED_TIMEOUT_S = self._timeout
        ss._CACHE.clear()

    def assertNothingLogged(self, *needles):
        log = self.stderr.getvalue()
        for n in needles:
            self.assertNotIn(n, log)


class LexicalSearch(SearchBase):
    def test_lexical_flow_ranking_and_counts(self):
        sessions = {"sk_a": sess("sk_a", days_ago=60), "sk_b": sess("sk_b", days_ago=0),
                    "sk_c": None, "sk_d": sess("sk_d", purged_at="2026-10-01T00:00:00Z")}
        fake = FakeES(standard_routes([("sk_a", 9.0), ("sk_b", 9.0), ("sk_c", 8.0), ("sk_d", 7.0)],
                                      sessions, counts={"sk_a": 4, "sk_b": 2}))
        out = run(ss.search(es_module(fake), {"q": SECRETISH_QUERY}, {"host": "pro-dev"}))
        # one keystroke query, then mget + hit count; nothing else
        self.assertEqual(sorted(p.split("?")[0] for _, p, _ in fake.calls),
                         sorted([MSG, MSG, MGET_PREFIX]))
        lex = [b for b in fake.bodies(MSG) if "collapse" in b]
        self.assertEqual(len(lex), 1)
        self.assertEqual(lex[0]["collapse"], {"field": "session_key"})
        mget_path = [p for _, p, _ in fake.calls if p.startswith(MGET_PREFIX)][0]
        self.assertIn("_source=", mget_path)
        self.assertNotIn("archive_chunks", mget_path)
        self.assertEqual(fake.bodies(MGET_PREFIX)[0], {"ids": ["sk_a", "sk_b", "sk_c", "sk_d"]})
        # purged (sk_d) and vanished (sk_c) sessions are dropped
        keys = [s["session_key"] for s in out["sessions"]]
        self.assertEqual(keys, ["sk_b", "sk_a"])  # equal BM25: recency nudge breaks the tie
        b, a = out["sessions"]
        self.assertAlmostEqual(b["score"], 9.0 * (1 + 0.05), places=4)
        self.assertAlmostEqual(a["score"], 9.0 * (1 + 0.0125), places=4)
        self.assertEqual((a["hit_count"], b["hit_count"]), (4, 2))
        self.assertEqual(set(a), set(ss.SEARCH_FIELDS) | {"score", "hit_count"})
        self.assertNotIn("archive_chunks", a)
        self.assertNotIn("degraded", out)
        self.assertIsInstance(out["took_ms"], int)
        self.assertNothingLogged(SECRETISH_QUERY)

    def test_limit_truncates_after_ranking(self):
        rows = [(f"sk_{i}", 10.0 - i) for i in range(5)]
        fake = FakeES(standard_routes(rows, {k: sess(k) for k, _ in rows}))
        out = run(ss.search(es_module(fake), {"q": "x y", "limit": 2}, {}))
        self.assertEqual([s["session_key"] for s in out["sessions"]], ["sk_0", "sk_1"])
        self.assertEqual(fake.bodies(MSG)[0]["size"], 50)

    def test_hit_count_body_matches_lexical_filters(self):
        fake = FakeES(standard_routes([("sk_a", 1.0)], {"sk_a": sess("sk_a")}))
        run(ss.search(es_module(fake), {"q": "x", "deep": True, "include_sidechain": True}, {}))
        agg = [b for b in fake.bodies(MSG) if "aggs" in b][0]
        self.assertEqual(agg["size"], 0)
        self.assertEqual(agg["query"]["bool"]["filter"][0]["multi_match"]["fields"],
                         ["text^2", "tool_text^0.5"])
        self.assertEqual(agg["query"]["bool"]["filter"][1], {"terms": {"session_key": ["sk_a"]}})
        self.assertEqual(agg["query"]["bool"]["filter"][2:], [{"term": {"interactive": True}}])

    def test_no_hits_skips_followups(self):
        fake = FakeES(standard_routes([], {}))
        out = run(ss.search(es_module(fake), {"q": "nothing matches"}, {}))
        self.assertEqual(out["sessions"], [])
        self.assertEqual(len(fake.calls), 1)

    def test_empty_query_returns_recent_sessions(self):
        rows = [sess("sk_new", days_ago=0), sess("sk_old", days_ago=30),
                sess("sk_gone", purged_at="2026-10-01T00:00:00Z")]
        fake = FakeES({SES: lambda body: (200, {"hits": {"hits": [
            {"_id": r["session_key"], "_source": r} for r in rows]}})})
        out = run(ss.search(es_module(fake), {"q": "", "mode": "hybrid"}, {}))
        self.assertEqual([p for _, p, _ in fake.calls], [SES])  # no message query, no embedding
        self.assertEqual([s["session_key"] for s in out["sessions"]], ["sk_new", "sk_old"])
        self.assertAlmostEqual(out["sessions"][1]["score"], 0.025, places=4)
        self.assertEqual(out["sessions"][0]["hit_count"], 0)
        self.assertNotIn("degraded", out)
        body = fake.bodies(SES)[0]
        self.assertEqual(body["size"], 50)
        self.assertNotIn("highlight", body)

    def test_es_errors_raise_es_unavailable(self):
        for route in (lambda b: (503, {}), lambda b: (200, ValueError("x")),
                      lambda b: (200, ["not", "a", "dict"]), lambda b: OSError("down")):
            fake = FakeES({MSG: route})
            with self.subTest(route=route), self.assertRaises(es_err()):
                run(ss.search(es_module(fake), {"q": SECRETISH_QUERY}, {}))
        self.assertNothingLogged(SECRETISH_QUERY)


class HybridSearch(SearchBase):
    def test_hybrid_fuses_with_rrf_k60(self):
        ss.EMBED_QUERY = _EmbedStub(vec=[1.0, 0.0])
        sessions = {k: sess(k, days_ago=10000) for k in ("sk_a", "sk_b", "sk_c")}
        fake = FakeES(standard_routes([("sk_a", 5.0), ("sk_b", 4.0)], sessions,
                                      knn_rows=[("sk_c", 0.9), ("sk_c", 0.8), ("sk_b", 0.7)]))
        out = run(ss.search(es_module(fake), {"q": "semantic thing", "mode": "hybrid"}, {}))
        knn = [b for b in fake.bodies(MSG) if "knn" in b]
        self.assertEqual(len(knn), 1)
        self.assertEqual(knn[0]["knn"]["query_vector"], [1.0, 0.0])
        self.assertEqual(knn[0]["knn"]["filter"]["bool"]["filter"], DEFAULT_FILTERS)
        got = {s["session_key"]: s["score"] for s in out["sessions"]}
        # best message rank per session: lex a=0 b=1; knn c=0 b=1
        self.assertAlmostEqual(got["sk_b"], 2 / 62, places=5)
        self.assertAlmostEqual(got["sk_a"], 1 / 61, places=5)
        self.assertAlmostEqual(got["sk_c"], 1 / 61, places=5)
        self.assertEqual(out["sessions"][0]["session_key"], "sk_b")
        self.assertNotIn("degraded", out)
        self.assertEqual(ss.EMBED_QUERY.calls, ["semantic thing"])

    def test_hybrid_relevance_beats_recency(self):
        # sk_old is ranked first by both legs (RRF 2/61); sk_new only second by
        # one leg (RRF 1/62) but updated today. An additive 0.05 nudge would put
        # sk_new on top; the multiplicative nudge must not.
        ss.EMBED_QUERY = _EmbedStub(vec=[1.0, 0.0])
        sessions = {"sk_old": sess("sk_old", days_ago=365), "sk_new": sess("sk_new", days_ago=0)}
        fake = FakeES(standard_routes([("sk_old", 5.0), ("sk_new", 4.0)], sessions,
                                      knn_rows=[("sk_old", 0.9)]))
        out = run(ss.search(es_module(fake), {"q": "semantic thing", "mode": "hybrid"}, {}))
        self.assertEqual([s["session_key"] for s in out["sessions"]], ["sk_old", "sk_new"])

    def test_embedding_timeout_degrades_and_fills_cache(self):
        ss.EMBED_TIMEOUT_S = 0.05
        ss.EMBED_QUERY = _EmbedStub(delay=0.3)
        fake = FakeES(standard_routes([("sk_a", 3.0)], {"sk_a": sess("sk_a")}))

        async def scenario():
            first = await ss.search(es_module(fake), {"q": SECRETISH_QUERY, "mode": "hybrid"}, {})
            await asyncio.sleep(0.4)  # the shielded call finishes in the background
            second = await ss.search(es_module(fake), {"q": SECRETISH_QUERY, "mode": "hybrid"}, {})
            return first, second

        first, second = run(scenario())
        self.assertEqual(first["degraded"], "bm25-only")
        self.assertEqual([s["session_key"] for s in first["sessions"]], ["sk_a"])
        self.assertAlmostEqual(first["sessions"][0]["score"], 3.0 * (1 + 0.05 * 2 ** (-1 / 30)), places=3)
        self.assertNotIn("degraded", second)
        self.assertEqual(len(ss.EMBED_QUERY.calls), 1)  # second request was a cache hit
        self.assertEqual(len([b for b in fake.bodies(MSG) if "knn" in b]), 1)
        self.assertNothingLogged(SECRETISH_QUERY)

    def test_provider_failure_degrades(self):
        ss.EMBED_QUERY = _EmbedStub(exc=RuntimeError("provider 503 " + SECRETISH_QUERY))
        fake = FakeES(standard_routes([("sk_a", 3.0)], {"sk_a": sess("sk_a")}))
        out = run(ss.search(es_module(fake), {"q": SECRETISH_QUERY, "mode": "hybrid"}, {}))
        self.assertEqual(out["degraded"], "bm25-only")
        self.assertFalse([b for b in fake.bodies(MSG) if "knn" in b])
        self.assertNothingLogged(SECRETISH_QUERY)

    def test_provider_not_configured_degrades(self):
        def boom():
            raise KeyError("VOYAGE_API_KEY")
        orig = ss._embed_fn
        ss._embed_fn = boom
        try:
            fake = FakeES(standard_routes([("sk_a", 3.0)], {"sk_a": sess("sk_a")}))
            out = run(ss.search(es_module(fake), {"q": "x", "mode": "hybrid"}, {}))
        finally:
            ss._embed_fn = orig
        self.assertEqual(out["degraded"], "bm25-only")

    def test_lexical_mode_never_embeds(self):
        ss.EMBED_QUERY = _EmbedStub()
        fake = FakeES(standard_routes([("sk_a", 3.0)], {"sk_a": sess("sk_a")}))
        run(ss.search(es_module(fake), {"q": "x"}, {}))
        self.assertEqual(ss.EMBED_QUERY.calls, [])


class Cache(unittest.TestCase):
    def test_lru_eviction_at_256(self):
        c = ss.EmbeddingCache()
        self.assertEqual(c.size, 256)
        for i in range(256):
            c.put(f"q{i}", [i])
        c.get("q0")  # refresh q0
        c.put("q256", [256])
        self.assertEqual(len(c), 256)
        self.assertIsNone(c.get("q1"))
        self.assertEqual(c.get("q0"), [0])

    def test_inflight_cap(self):
        ss._CACHE.clear()
        stub = ss.EMBED_QUERY = _EmbedStub(delay=0.2)
        ss.EMBED_TIMEOUT_S = 0.01

        async def scenario():
            res = [await ss.embed_query_bounded(f"q{i}") for i in range(ss.EMBED_INFLIGHT_MAX + 1)]
            await asyncio.sleep(0.3)
            return res

        try:
            res = run(scenario())
        finally:
            ss.EMBED_QUERY = None
            ss.EMBED_TIMEOUT_S = 1.5
        self.assertEqual(res[:-1], [(None, "embedding_timeout")] * ss.EMBED_INFLIGHT_MAX)
        self.assertEqual(res[-1], (None, "embedding_busy"))
        self.assertEqual(len(stub.calls), ss.EMBED_INFLIGHT_MAX)
        self.assertEqual(len(ss._CACHE), ss.EMBED_INFLIGHT_MAX)  # all finished in the background
        ss._CACHE.clear()


class Preview(SearchBase):
    def _fake(self, src, hits=None, status=200):
        def get(_):
            if status != 200:
                return status, {"found": False}
            return 200, {"found": src is not None, **({"_source": src} if src else {})}
        return FakeES({"/memory-session/_doc/sk_a": get,
                       MSG: lambda body: (200, {"hits": {"hits": hits or []}})})

    def test_preview_with_query_highlights_one_session(self):
        hits = [{"_source": {"ts": "2026-10-01T00:00:01Z", "role": "user"},
                 "highlight": {"text": ["a <em>hello</em> b", "second"]}},
                {"_source": {"ts": "2026-10-01T00:00:02Z", "role": "assistant"},
                 "highlight": {"tool_text": ["tool <em>hello</em>"]}},
                {"_source": {"ts": "2026-10-01T00:00:03Z", "role": "user"}}]
        fake = self._fake(sess("sk_a", project_dir="-home-dev-proj", jsonl_path="/x.jsonl"), hits)
        out = run(ss.preview(es_module(fake), "sk_a", " " + SECRETISH_QUERY + " ", {}))
        body = fake.bodies(MSG)[0]
        self.assertEqual(body, {
            "size": 6, "_source": ["ts", "role"], "track_total_hits": False,
            "query": {"bool": {"must": [{"multi_match": {"query": SECRETISH_QUERY,
                                                         "fields": ["text", "tool_text"],
                                                         "operator": "and"}}],
                               "filter": [{"term": {"session_key": "sk_a"}}]}},
            "highlight": {"fields": {"text": {}, "tool_text": {}}, "fragment_size": 160,
                          "number_of_fragments": 1}})
        self.assertEqual(out["snippets"], [
            {"ts": "2026-10-01T00:00:01Z", "role": "user", "fragment": "a <em>hello</em> b"},
            {"ts": "2026-10-01T00:00:02Z", "role": "assistant", "fragment": "tool <em>hello</em>"}])
        s = out["session"]
        self.assertEqual((s["session_key"], s["project_dir"], s["jsonl_path"]),
                         ("sk_a", "-home-dev-proj", "/x.jsonl"))
        self.assertNotIn("archive_chunks", s)
        self.assertNothingLogged(SECRETISH_QUERY, "hello")

    def test_preview_empty_query_returns_last_four_text_messages(self):
        hits = [{"_source": {"ts": f"2026-10-01T00:00:0{i}Z", "role": "user", "text": f"t{i}" * 300}}
                for i in (4, 3, 2, 1)]  # ES answers newest first
        fake = self._fake(sess("sk_a"), hits)
        out = run(ss.preview(es_module(fake), "sk_a", "", {}))
        body = fake.bodies(MSG)[0]
        self.assertEqual(body["size"], 4)
        self.assertEqual(body["sort"], [{"ts": {"order": "desc"}}])
        self.assertIn({"exists": {"field": "text"}}, body["query"]["bool"]["filter"])
        self.assertNotIn("highlight", body)
        self.assertEqual([x["ts"][-3:] for x in out["snippets"]], ["01Z", "02Z", "03Z", "04Z"])
        self.assertEqual(len(out["snippets"][0]["fragment"]), 400)

    def test_preview_missing_or_purged_is_404(self):
        for fake in (self._fake(None, status=404), self._fake(None),
                     self._fake(sess("sk_a", purged_at="2026-10-01T00:00:00Z"))):
            with self.subTest(), self.assertRaises(not_found_err()) as cm:
                run(ss.preview(es_module(fake), "sk_a", "x", {}))
            self.assertEqual(cm.exception.status, 404)
            self.assertFalse(fake.bodies(MSG))

    def test_preview_es_error_is_unavailable(self):
        with self.assertRaises(es_err()):
            run(ss.preview(es_module(self._fake(None, status=500)), "sk_a", "x", {}))


HAVE_APP_DEPS = all(importlib.util.find_spec(m) for m in ("starlette", "httpx", "zstandard"))


@unittest.skipUnless(HAVE_APP_DEPS, "needs the memory-mcp venv (starlette, httpx, zstandard)")
class AppWiring(unittest.TestCase):
    """POST /search and GET /preview through sessions_app's real gate, with the
    host-shaped request a ccs client sends (picker.search_body shape)."""

    @classmethod
    def setUpClass(cls):
        secret = "proxy-secret-for-tests"
        os.environ["PROXY_SHARED_SECRET"] = secret
        os.environ["SESSION_SCOPE_POLICY"] = json.dumps({"rules": [
            {"match": {"grant": "client_credentials", "client_id": "session-search-pro-dev"},
             "host": "pro-dev", "scopes": ["sessions:ingest", "sessions:read"]}]})
        cls.fake = FakeES({**standard_routes([("sk_a", 2.0)], {"sk_a": sess("sk_a")}),
                           "/memory-session/_doc/sk_a": lambda _: (200, {"found": True,
                                                                         "_source": sess("sk_a")})})
        be = types.ModuleType("es_backend")
        be._es = cls.fake
        with open(os.path.join(HERE, "..", "es-indices-v2", "memory-knowledge.json")) as fh:
            be._ANALYSIS = json.load(fh)["settings"]["analysis"]
        sys.modules["es_backend"] = be
        import sessions_app  # noqa: PLC0415
        from starlette.applications import Starlette  # noqa: PLC0415
        from starlette.routing import Mount  # noqa: PLC0415
        from starlette.testclient import TestClient  # noqa: PLC0415
        cls.sa = sessions_app
        sessions_app._STATE["ready"] = True
        cls.client = TestClient(Starlette(routes=[Mount("/memory/sessions/v1", app=sessions_app.app)]))
        cls.headers = {"x-verified-grant": "client_credentials",
                       "x-verified-client-id": "session-search-pro-dev",
                       "x-verified-sub": "session-search-pro-dev", "x-proxy-secret": secret}

    def test_module_is_wired(self):
        self.assertIs(self.sa.sessions_search, ss)

    def test_search_route(self):
        body = {"q": "hello", "mode": "lexical", "deep": False, "include_headless": False,
                "include_sidechain": False, "limit": 50, "hosts": ["pro-dev"]}
        r = self.client.post("/memory/sessions/v1/search", json=body, headers=self.headers)
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual([s["session_key"] for s in r.json()["sessions"]], ["sk_a"])

    def test_bad_request_is_400(self):
        r = self.client.post("/memory/sessions/v1/search", json={"limit": 999}, headers=self.headers)
        self.assertEqual(r.status_code, 400)

    def test_preview_route_and_404(self):
        r = self.client.get("/memory/sessions/v1/preview", params={"session_key": "sk_a", "q": "x"},
                            headers=self.headers)
        # sk_a is not a valid opaque key shape: the app's own validation answers first
        self.assertEqual((r.status_code, r.json()["error"]), (400, "invalid_session_key"))
        key = "sk_" + "a" * 32
        self.fake.routes[f"/memory-session/_doc/{key}"] = lambda _: (404, {"found": False})
        r = self.client.get("/memory/sessions/v1/preview", params={"session_key": key, "q": ""},
                            headers=self.headers)
        self.assertEqual((r.status_code, r.json()["error"]), (404, "not_found"))
        self.fake.routes[f"/memory-session/_doc/{key}"] = lambda _: (
            200, {"found": True, "_source": sess(key)})
        r = self.client.get("/memory/sessions/v1/preview", params={"session_key": key, "q": "x"},
                            headers=self.headers)
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(r.json()["session"]["session_key"], key)

    def test_es_down_is_503(self):
        orig = self.fake.routes[MSG]
        self.fake.routes[MSG] = lambda b: (503, {})
        try:
            r = self.client.post("/memory/sessions/v1/search", json={"q": "x"}, headers=self.headers)
        finally:
            self.fake.routes[MSG] = orig
        self.assertEqual((r.status_code, r.json()["error"]), (503, "es_unavailable"))


if __name__ == "__main__":
    unittest.main(verbosity=1)
