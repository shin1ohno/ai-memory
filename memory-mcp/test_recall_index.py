#!/usr/bin/env python3
"""recall returns one hit per document and demotes nothing.

An agent-maintained project note mirrored into file-memory is chunked into many
pieces and matches a wide range of queries; without a collapse it fills several
of the top slots with itself (SH1-244: 206 slots in the SH1-262 sample repeated
a document). SH1-262 also judged a demotion of such "index-like" records (x0.85,
no use / recency boost): it made the top better in 18 of 43 changed queries and
worse in 12, while the collapse alone made no top-1 worse. Owner decision
2026-11-15 (SH1-272): ship the collapse only. recall now:

1. returns one hit per `doc_id` (the document's best chunk), collapsing BEFORE
   top_k is applied, so top_k counts documents;
2. keeps chunks migrated from cognee (parent_id "cognee", source_class
   "migration"; their doc_id is their own chunk id) as separate hits, while the
   chunks of a migrated document with a real parent_id collapse into one;
3. scores and bumps every record alike: no demotion multiplier, no use_count /
   last_used_at change for long file-memory notes, no count query, no
   `index_like` field, no `index_records` argument;
4. takes bump_use=False so an evaluation replay changes no record.

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


def docs(res):
    return [h["doc_id"] for h in res["hits"]]


def test_composite_has_no_demotion():
    src = {"use_count": 100, "last_used_at": iso(0), "provenance": {"written_at": iso(400)}}
    got = scoring.composite(0.03, src, NOW, "knowledge")
    want = (0.03 * scoring.freshness(iso(0), NOW, 180.0) * scoring.use_boost(100))
    check("composite = rrf * freshness(last_used_at) * use_boost, nothing else",
          abs(got - want) < 1e-12, f"got {got!r} want {want!r}")
    try:
        scoring.composite(0.03, src, NOW, "knowledge", index_like=True)
        check("composite has no index_like switch", False, "index_like accepted")
    except TypeError:
        check("composite has no index_like switch", True)


def test_default_does_not_demote_a_long_file_memory_note():
    es = hub_and_fact()
    res, bumped = recall(es)
    check("the hub (file-memory, 6 chunks, heavily used) keeps its first place",
          ids(res)[0] == "hub-0", f"got {ids(res)!r}")
    hub, fact = res["hits"][0], res["hits"][1]
    rrf = scoring.rrf_fuse([es.docs, es.docs], k=be.RRF_K)
    want = scoring.composite(rrf["hub-0"], es.docs[0]["_source"], NOW, "knowledge")
    check("the hub's score is the undemoted composite (no x0.85)",
          abs(hub["score"] - want) < 1e-9 * max(1.0, want), f"got {hub['score']!r} want {want!r}")
    check("the hub outscores the equally ranked fact by its use/recency boost",
          hub["score"] > fact["score"], f"got {hub['score']!r} vs {fact['score']!r}")
    check("no hit carries an index_like field", all("index_like" not in h for h in res["hits"]),
          f"got {res['hits']!r}")
    flat = [i for b in bumped for i in b]
    check("the hub is bumped like any top hit", "hub-0" in flat and "fact-1" in flat, f"got {flat!r}")


def test_no_count_query_and_no_index_records_argument():
    es = hub_and_fact()
    recall(es)
    check("recall sends only the two searches (no chunk-count aggregation)",
          es.agg_queries() == [] and len(es.bodies) == 2, f"got {len(es.bodies)} bodies, {len(es.agg_queries())} aggs")
    try:
        recall(hub_and_fact(), index_records="demote")
        check("recall has no index_records argument", False, "accepted")
    except TypeError:
        check("recall has no index_records argument", True)


def test_bump_use_flag():
    _, bumped = recall(hub_and_fact(), bump_use=False)
    check("bump_use=False: nothing is bumped", bumped == [], f"got {bumped!r}")


def test_one_hit_per_document():
    es = _Es()
    for i in range(3):
        es.add(f"c{i}", content=f"c{i}", memory_type="knowledge", dataset="notes",
               parent_id="p1", chunk_index=i, provenance={"written_at": iso(1)})
    es.add("other", content="o", memory_type="fact", provenance={"written_at": iso(1)})
    res, _ = recall(es)
    check("chunks of one parent_id collapse to one hit", docs(res).count("p1") == 1 and len(docs(res)) == 2,
          f"got {docs(res)!r}")
    check("the kept chunk is the best-ranked one", res["hits"][0]["id"] == "c0", f"got {ids(res)!r}")


def test_long_file_memory_note_collapses():
    res, _ = recall(hub_and_fact())
    check("the 6 chunks of a file-memory note are one hit", docs(res) == ["hub-doc", "fact-1"], f"got {docs(res)!r}")


def test_migrated_document_with_a_real_parent_collapses():
    es = _Es()
    for i in range(5):
        es.add(f"m{i}", content=f"m{i}", memory_type="knowledge", dataset="main_dataset",
               parent_id="50912c716c6245b62597f69a070fe120", chunk_index=i,
               provenance={"source_class": "migration", "written_at": iso(30)})
    res, _ = recall(es)
    check("5 chunks of one migrated document with a real parent are one hit",
          docs(res) == ["50912c716c6245b62597f69a070fe120"] and ids(res) == ["m0"], f"got {docs(res)!r} {ids(res)!r}")


def test_cognee_bucket_chunks_stay_separate():
    es = _Es()
    for i in range(4):
        es.add(f"g{i}", content=f"g{i}", memory_type="knowledge", dataset="main_dataset",
               parent_id=be.MIGRATION_BUCKET_PARENT, chunk_index=i,
               provenance={"source_class": "migration", "written_at": iso(30)})
    res, _ = recall(es)
    check("cognee-bucket chunks are one hit per chunk", ids(res) == ["g0", "g1", "g2", "g3"], f"got {ids(res)!r}")
    check("each carries its own chunk id as doc_id", docs(res) == ids(res), f"got {docs(res)!r}")
    es = _Es()
    for i in range(3):
        es.add(f"n{i}", content=f"n{i}", memory_type="knowledge", dataset="x",
               parent_id=be.MIGRATION_BUCKET_PARENT, provenance={"written_at": iso(30)})
    res, _ = recall(es)
    check("a parent_id of 'cognee' without source_class migration is an ordinary parent: one hit",
          docs(res) == [be.MIGRATION_BUCKET_PARENT], f"got {docs(res)!r}")


def test_facts_without_a_parent_never_merge():
    es = _Es()
    for i in range(3):
        es.add(f"f{i}", content=f"f{i}", memory_type="fact", provenance={"written_at": iso(1)})
    res, _ = recall(es)
    check("parentless records are one hit each", ids(res) == ["f0", "f1", "f2"], f"got {ids(res)!r}")


def test_top_k_counts_documents():
    es = _Es()
    for i in range(6):
        es.add(f"a{i}", content="a", memory_type="knowledge", dataset="notes", parent_id="A",
               chunk_index=i, provenance={"written_at": iso(1)})
    for j in range(3):
        es.add(f"b{j}", content="b", memory_type="fact", provenance={"written_at": iso(1)})
    res, _ = recall(es, top_k=3)
    check("collapse happens before top_k: 3 documents, not 1 document + 2 repeats",
          docs(res) == ["A", "b0", "b1"], f"got {docs(res)!r}")
    res, _ = recall(es, top_k=10)
    check("fewer documents than top_k: fewer hits come back, none padded",
          docs(res) == ["A", "b0", "b1", "b2"], f"got {docs(res)!r}")


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
    print(f"\n---- pass={PASS} fail={FAIL}")
    sys.exit(1 if FAIL else 0)
