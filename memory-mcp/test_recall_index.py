#!/usr/bin/env python3
"""Index-like records (long file-memory notes) are demoted in recall.

An agent-maintained project note mirrored into file-memory is chunked into many
pieces and matches a wide range of queries. Each time it is returned in the top
3 its use_count rises and last_used_at refreshes, which raises its next score, so
it climbs on its own hits (SH1-244: 21.6% of the hit slots and 26.1% of the
rank-1 positions in the SH1-230 sample were 18 such documents). recall now:

1. scores an index-like record (dataset file-memory, 5+ live chunks) as
   rrf * freshness(written_at) * 0.85: no use_boost, no last_used_at recency;
2. never bumps it;
3. returns one hit per document;
4. takes index_records = demote (default) | include | exclude;
5. takes bump_use=False so an evaluation replay changes no record.

The index-like rule uses stored fields only; the live chunk count is one
aggregation query, sent only when a candidate could be index-like.

Dependency-free like test_tag_preservation: httpx is stubbed, nothing talks to ES.

Usage: python3 test_recall_index.py
"""

from __future__ import annotations

import asyncio
import os
import sys
import types

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

_httpx = types.ModuleType("httpx")


class _FakeClient:
    def __init__(self, *a, **kw):
        pass


class _FakeResponse:
    def __init__(self, status_code=200, text="", payload=None):
        self.status_code = status_code
        self.text = text
        self._payload = payload or {}

    @property
    def is_error(self):
        return self.status_code >= 400

    def json(self):
        return self._payload

    def raise_for_status(self):
        if self.is_error:
            raise _httpx.HTTPStatusError(f"{self.status_code}")


_httpx.AsyncClient = _FakeClient
_httpx.Response = _FakeResponse
_httpx.Timeout = lambda *a, **kw: None
_httpx.HTTPStatusError = type("HTTPStatusError", (Exception,), {})
sys.modules["httpx"] = _httpx

os.environ.setdefault("ES_URL", "http://127.0.0.1:9200")
os.environ.setdefault("ES_PASSWORD", "stub")
os.environ.setdefault("ES_USER", "memory_mcp")

_voyage = types.ModuleType("voyage")


async def _embed_documents(texts):
    return [[0.0] for _ in texts]


async def _embed_query(text):
    return [0.0]


_voyage.embed_documents = _embed_documents
_voyage.embed_query = _embed_query
_voyage.VoyageUnavailable = type("VoyageUnavailable", (Exception,), {})
sys.modules["voyage"] = _voyage

_identity = types.ModuleType("identity")
_identity.AuthzError = type("AuthzError", (Exception,), {})
_identity.audit_supersede = lambda *a, **kw: None
_identity.authorize_supersede = lambda *a, **kw: True
_identity.audit_policy_deny = lambda *a, **kw: None
_identity.POLICY_DENIED_MESSAGE = "policy_denied: stub"
sys.modules["identity"] = _identity

import es_backend as be  # noqa: E402  (after the stubs)

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


def run(coro):
    return asyncio.run(coro)


import scoring  # noqa: E402  (the real one: this suite is about scoring)
from datetime import datetime, timedelta, timezone  # noqa: E402

NOW = datetime.now(timezone.utc)


def iso(days_ago: float) -> str:
    return (NOW - timedelta(days=days_ago)).strftime("%Y-%m-%dT%H:%M:%SZ")


class _Es:
    """Answers recall's searches from a fixed list; records every request body."""

    def __init__(self, fail_aggs=False):
        self.docs: list[dict] = []
        self.bodies: list[dict] = []
        self.fail_aggs = fail_aggs

    def add(self, _id, **source):
        self.docs.append({"_id": _id, "_source": source})

    async def json(self, method, path, body=None, **kw):
        body = body or {}
        self.bodies.append(body)
        if "aggs" in body:
            if self.fail_aggs:
                raise RuntimeError("aggregation failed")
            want = set(body["query"]["bool"]["filter"][0]["terms"]["parent_id"])
            counts: dict = {}
            for d in self.docs:
                p = d["_source"].get("parent_id")
                if p in want and not d["_source"].get("superseded_by"):
                    counts[p] = counts.get(p, 0) + 1
            return {"hits": {"hits": []}, "aggregations": {"by_parent": {
                "buckets": [{"key": k, "doc_count": v} for k, v in counts.items()]}}}
        return {"hits": {"hits": list(self.docs)}}

    def agg_queries(self):
        return [b for b in self.bodies if "aggs" in b]


def recall(es, **kw):
    bumped: list[list[str]] = []

    async def fake_bump(ids):
        bumped.append(list(ids))

    saved = (be._es_json, be._spawn, be.bump_use_counts)
    be._es_json = es.json
    be._spawn = _pending.append  # recall's background bump; _recall awaits it
    be.bump_use_counts = fake_bump
    try:
        res = asyncio.run(_recall(**kw))
    finally:
        be._es_json, be._spawn, be.bump_use_counts = saved
    return res, bumped


_pending: list = []


async def _recall(**kw):
    res = await be.recall("q", top_k=kw.pop("top_k", 10), **kw)
    while _pending:
        await _pending.pop()
    return res


def hub_and_fact(hub_chunks=6, dataset="file-memory"):
    """A hub document (hub-0 ranks first) and one fact, same ES order in both legs."""
    es = _Es()
    hub = {"content": "hub", "memory_type": "knowledge", "dataset": dataset,
           "parent_id": "hub-doc", "use_count": 100, "last_used_at": iso(0),
           "provenance": {"written_at": iso(400)}}
    es.add("hub-0", **dict(hub, chunk_index=0))
    es.add("fact-1", content="fact", memory_type="fact", use_count=0,
           provenance={"written_at": iso(1)})
    for i in range(1, hub_chunks):
        es.add(f"hub-{i}", **dict(hub, chunk_index=i))
    return es


def ids(res):
    return [h["id"] for h in res["hits"]]


def test_composite_index_like_value():
    now = NOW
    src = {"use_count": 100, "last_used_at": iso(0), "provenance": {"written_at": iso(400)}}
    got = scoring.composite(0.03, src, now, "knowledge", index_like=True)
    want = 0.03 * scoring.freshness(iso(400), now, 180.0) * 0.85
    check("index_like composite = rrf * freshness(written_at) * 0.85",
          abs(got - want) < 1e-12, f"got {got!r} want {want!r}")
    plain = scoring.composite(0.03, src, now, "knowledge")
    check("without index_like the use_count boost and last_used_at still apply",
          plain > got * 1.4, f"plain {plain!r} demoted {got!r}")


def test_default_demotes_hub_below_equal_fact():
    res, _ = recall(hub_and_fact())
    check("default: the fact outranks the demoted hub", ids(res)[0] == "fact-1", f"got {ids(res)!r}")
    hub = next(h for h in res["hits"] if h["doc_id"] == "hub-doc")
    check("the hub hit says index_like: true", hub["index_like"] is True, f"got {hub!r}")
    check("the fact hit says index_like: false",
          res["hits"][0]["index_like"] is False, f"got {res['hits'][0]!r}")


def test_index_records_modes():
    res, _ = recall(hub_and_fact(), index_records="include")
    check("include: the hub keeps its boosted first place", ids(res)[0] == "hub-0", f"got {ids(res)!r}")
    check("include: the hub is still flagged", res["hits"][0]["index_like"] is True)
    res, _ = recall(hub_and_fact(), index_records="exclude")
    check("exclude: no hub hit", all(h["doc_id"] != "hub-doc" for h in res["hits"]), f"got {ids(res)!r}")
    check("exclude: other records remain", ids(res) == ["fact-1"], f"got {ids(res)!r}")
    try:
        recall(hub_and_fact(), index_records="bogus")
        check("an unknown index_records raises QueryError", False, "no exception")
    except be.QueryError:
        check("an unknown index_records raises QueryError", True)


def test_bump_skips_index_like_and_honours_the_flag():
    _, bumped = recall(hub_and_fact())
    flat = [i for b in bumped for i in b]
    check("demote: index-like ids are not bumped", not any(i.startswith("hub-") for i in flat), f"got {flat!r}")
    check("demote: the other top hits still are", "fact-1" in flat, f"got {flat!r}")
    _, bumped = recall(hub_and_fact(), index_records="include")
    flat = [i for b in bumped for i in b]
    check("include: the hub is bumped as before", "hub-0" in flat, f"got {flat!r}")
    _, bumped = recall(hub_and_fact(), bump_use=False)
    check("bump_use=False: nothing is bumped", bumped == [], f"got {bumped!r}")


def test_one_hit_per_document():
    es = _Es()
    for i in range(3):
        es.add(f"c{i}", content=f"c{i}", memory_type="knowledge", dataset="notes",
               parent_id="p1", chunk_index=i, provenance={"written_at": iso(1)})
    es.add("other", content="o", memory_type="fact", provenance={"written_at": iso(1)})
    res, _ = recall(es)
    docs = [h["doc_id"] for h in res["hits"]]
    check("chunks of one parent_id collapse to one hit", docs.count("p1") == 1 and len(docs) == 2, f"got {docs!r}")
    check("the kept chunk is the best-ranked one", res["hits"][0]["id"] == "c0", f"got {ids(res)!r}")


def test_rule_thresholds_and_no_extra_query():
    res, _ = recall(hub_and_fact(hub_chunks=4))
    check("file-memory with 4 live chunks is not index-like",
          not any(h["index_like"] for h in res["hits"]) and ids(res)[0] == "hub-0", f"got {res['hits']!r}")
    es = hub_and_fact(dataset="notes")
    res, _ = recall(es)
    check("a 6-chunk document outside file-memory is not index-like",
          not any(h["index_like"] for h in res["hits"]))
    check("no file-memory candidate sends no count query", es.agg_queries() == [])
    es = hub_and_fact()
    recall(es)
    check("a file-memory candidate sends exactly one count query", len(es.agg_queries()) == 1, f"got {len(es.agg_queries())}")
    es = hub_and_fact()
    for d in es.docs:
        if d["_id"] in ("hub-4", "hub-5"):
            d["_source"]["superseded_by"] = "x"
    res, _ = recall(es)
    check("superseded chunks do not count toward the 5", not any(h["index_like"] for h in res["hits"]))


def test_count_failure_is_reported_not_hidden():
    es = hub_and_fact()
    es.fail_aggs = True
    res, _ = recall(es)
    check("a failed count query reports degraded", res.get("degraded") == "index-check-skipped", f"got {res.get('degraded')!r}")
    check("and still returns hits", len(res["hits"]) == 2, f"got {ids(res)!r}")


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
    print(f"\n---- pass={PASS} fail={FAIL}")
    sys.exit(1 if FAIL else 0)
