#!/usr/bin/env python3
"""Regression tests for the ids a recall hit and `get` hand back.

`remember` returns a document id: a knowledge document's synthetic parent_id, or
the ES _id of a fact / episode. A recall hit used to carry only the matched
CHUNK's _id, so a caller could not tell which `remember` a hit came from or hand
the id to get / revise / forget. And `get(parent_id)` returned chunk 0 alone, so a
document longer than one chunk read as its first ~1200 characters.

1. every hit carries `doc_id` (parent_id, else the _id) beside the unchanged
   chunk `id`.
2. facts and migrated documents, which have no parent_id, fall back to `_id`.
3. the id ingest_document returned equals the doc_id recall reports for the
   chunks it wrote (the round trip a caller actually relies on).
4. get(doc_id) returns the whole document; get(chunk_id) still returns the chunk.

Dependency-free like test_tag_preservation: httpx is stubbed, nothing talks to ES.

Usage: python3 test_recall_ids.py
"""

from __future__ import annotations

import asyncio
import os
import re
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


class _Es:
    """A just-enough ES: keeps the chunks ingest_document wrote and answers the
    searches recall / get issue, by the shape of the query."""

    def __init__(self):
        self.docs: list[dict] = []   # {"_id", "_source"}

    def add(self, source: dict, _id: str | None = None) -> str:
        _id = _id or f"es{len(self.docs)}"
        self.docs.append({"_id": _id, "_source": source})
        return _id

    async def json(self, method, path, body=None, **kw):
        q = (body or {}).get("query", {})
        if "knn" in (body or {}) or "match" in str(q.get("bool", {}).get("must", "")):
            return {"hits": {"hits": [dict(d, _index="memory-knowledge")
                                      for d in self.docs]}}
        if "ids" in q:
            want = set(q["ids"]["values"])
            return {"hits": {"hits": [d for d in self.docs if d["_id"] in want]}}
        if "term" in q and "parent_id" in q["term"]:
            pid = q["term"]["parent_id"]
            rows = sorted((d for d in self.docs if d["_source"].get("parent_id") == pid),
                          key=lambda d: d["_source"].get("chunk_index", 0))
            return {"hits": {"hits": rows[: (body or {}).get("size", 10)]}}
        return {"hits": {"hits": []}}


def _patched(es, fn):
    saved = (be._es_json, be._spawn, be._bulk_index)

    async def bulk(index, docs):
        for d in docs:
            es.add(d)

    be._es_json, be._spawn, be._bulk_index = es.json, (lambda c: c.close()), bulk
    try:
        return fn()
    finally:
        be._es_json, be._spawn, be._bulk_index = saved


def test_hit_carries_doc_id_and_keeps_chunk_id():
    es = _Es()
    cid = es.add({"content": "c", "memory_type": "knowledge", "parent_id": "p1",
                  "chunk_index": 2, "dataset": "notes", "doc_key": "k1"}, "chunk-abc")
    hit = _patched(es, lambda: run(be.recall("c", top_k=5)))["hits"][0]
    check("knowledge hit: doc_id is the parent_id", hit.get("doc_id") == "p1", f"got {hit!r}")
    check("knowledge hit: id stays the chunk _id", hit.get("id") == cid, f"got {hit!r}")
    check("knowledge hit: chunk_index, dataset, doc_key present",
          (hit.get("chunk_index"), hit.get("dataset"), hit.get("doc_key")) == (2, "notes", "k1"),
          f"got {hit!r}")


def test_doc_id_falls_back_to_id_without_parent():
    es = _Es()
    es.add({"content": "f", "memory_type": "fact"}, "fact-1")
    es.add({"content": "m", "memory_type": "knowledge"}, "9f" * 16)  # migrated: no parent_id
    hits = _patched(es, lambda: run(be.recall("f", top_k=5)))["hits"]
    got = {h["id"]: h.get("doc_id") for h in hits}
    check("fact hit: doc_id == _id", got.get("fact-1") == "fact-1", f"got {got!r}")
    check("migrated knowledge hit without parent_id: doc_id == _id",
          got.get("9f" * 16) == "9f" * 16, f"got {got!r}")
    check("fact hit: chunk_index / dataset / doc_key are None",
          all(hits[0].get(k) is None for k in ("chunk_index", "dataset", "doc_key")),
          f"got {hits[0]!r}")


def test_remember_id_round_trips_to_recall_doc_id():
    es = _Es()
    text = ("Paragraph about doc ids. " * 120).strip()
    res = _patched(es, lambda: run(be.ingest_document(
        text, "notes", "key-1", {"agent": "a"}, background=False)))
    hits = _patched(es, lambda: run(be.recall("doc ids", top_k=10)))["hits"]
    check("ingest wrote more than one chunk", res["chunk_count"] > 1, f"got {res!r}")
    check("every recall hit's doc_id equals the id ingest returned",
          hits and all(h["doc_id"] == res["doc_id"] for h in hits),
          f"want {res['doc_id']!r} got {[h['doc_id'] for h in hits]!r}")


def _norm(t: str) -> str:
    return re.sub(r"\s+", " ", t).strip()


def test_get_by_doc_id_returns_whole_document():
    es = _Es()
    words = " ".join(f"sentence{i} ends here." for i in range(400))
    text = words
    run_res = _patched(es, lambda: run(be.ingest_document(
        text, "notes", "key-2", {"agent": "a"}, background=False)))
    doc_id = run_res["doc_id"]
    n = run_res["chunk_count"]
    whole = _patched(es, lambda: run(be.get_with_chain(doc_id)))
    check("get(doc_id): content is the whole document",
          _norm(whole.get("content", "")) == _norm(text),
          f"got {len(whole.get('content', ''))} chars of {len(text)}")
    check("get(doc_id): chunk_count reported", whole.get("chunk_count") == n and n >= 3,
          f"got {whole.get('chunk_count')!r}, chunks {n}")
    chunk = next(d for d in es.docs if d["_source"]["chunk_index"] == 1)
    one = _patched(es, lambda: run(be.get_with_chain(chunk["_id"])))
    check("get(chunk_id): returns that chunk only",
          one.get("content") == chunk["_source"]["content"] and "chunk_count" not in one,
          f"got {one.get('content', '')[:40]!r}")


def test_join_chunks_drops_overlap():
    text = " ".join(f"word{i}" for i in range(1000))
    chunks = be.chunk_text(text)
    check("join_chunks inverts chunk_text up to whitespace",
          _norm(be.join_chunks(chunks)) == _norm(text) and len(chunks) > 2)


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
    print(f"\n---- pass={PASS} fail={FAIL}")
    sys.exit(1 if FAIL else 0)
