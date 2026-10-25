#!/usr/bin/env python3
"""Regression tests for two silent write-path defects in es_backend.

1. `tags` were dropped on the knowledge path. `remember_fact` and
   `append_episode` stamped them; `ingest_document` had no tags parameter at all
   and `_ingest_chunks` hardcoded `"tags": []`, so every knowledge write landed
   untagged and no tag filter — including `tags:["todo"]`, which the TODO
   pipeline routes on — matched anything.

2. The id a knowledge write RETURNED could not be used. `ingest_document` and
   `revise` mint a synthetic `parent_id` and hand it back as `doc_id` / `new_id`,
   but `_get_by_id_any` only ran an `ids` query, which matches ES `_id`s. Every
   follow-up get / revise / forget on that id answered "id not found".

Both are invisible to a smoke test: the write still succeeds and returns an id.
So the assertions here are on the DOCUMENT that reaches ES and on which query
shape the id lookup falls back to.

Dependency-free on purpose: `httpx` is stubbed before import, so this runs on a
bare python3 (CI) as well as inside the app venv. Nothing here talks to ES.

Usage: python3 test_tags_and_ids.py
"""

from __future__ import annotations

import asyncio
import os
import sys
import types

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

# --------------------------------------------------------------------------- #
# Stub the third-party surface es_backend touches at import time.
# --------------------------------------------------------------------------- #
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

_scoring = types.ModuleType("scoring")
_scoring.composite = lambda *a, **kw: 1.0
sys.modules["scoring"] = _scoring

_voyage = types.ModuleType("voyage")


async def _embed(texts):
    return [[0.0] for _ in texts]


_voyage.embed_documents = _embed
sys.modules["voyage"] = _voyage

_identity = types.ModuleType("identity")
_identity.AuthzError = type("AuthzError", (Exception,), {})
_identity.audit_supersede = lambda *a, **kw: None
_identity.authorize_supersede = lambda *a, **kw: True
_identity.audit_policy_deny = lambda *a, **kw: None
_identity.POLICY_DENIED_MESSAGE = "policy_denied: stub"
sys.modules["identity"] = _identity

import es_backend as be  # noqa: E402  (import after the stubs are installed)

PASS = 0
FAIL = 0


def check(name, condition, detail=""):
    global PASS, FAIL
    if condition:
        PASS += 1
        print(f"ok   {name}")
    else:
        FAIL += 1
        print(f"FAIL {name} :: {detail}")


def run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


async def _quiet_es_json(method, path, body=None):
    """Swallow the supersede-prior-doc call _ingest_chunks makes."""
    return {"updated": 0, "hits": {"hits": []}}


# --------------------------------------------------------------------------- #
# 1. tags reach every knowledge chunk
# --------------------------------------------------------------------------- #
def test_tags_on_chunks():
    captured = []

    async def fake_bulk(index, docs):
        captured.extend(docs)
        return len(docs)

    orig, orig_json = be._bulk_index, be._es_json
    be._bulk_index, be._es_json = fake_bulk, _quiet_es_json
    try:
        run(be._ingest_chunks(["a", "b"], "notes", "k1", "parent1", {},
                              tags=["todo", "retro"]))
    finally:
        be._bulk_index, be._es_json = orig, orig_json

    check("tags stamped on every chunk",
          len(captured) == 2 and all(d["tags"] == ["todo", "retro"] for d in captured),
          f"got {[d.get('tags') for d in captured]}")
    check("chunk carries its parent_id",
          all(d["parent_id"] == "parent1" for d in captured))


def test_tags_default_empty():
    captured = []

    async def fake_bulk(index, docs):
        captured.extend(docs)
        return len(docs)

    orig, orig_json = be._bulk_index, be._es_json
    be._bulk_index, be._es_json = fake_bulk, _quiet_es_json
    try:
        run(be._ingest_chunks(["a"], "notes", "k1", "parent1", {}))
    finally:
        be._bulk_index, be._es_json = orig, orig_json

    check("tags default to [] when not given", captured and captured[0]["tags"] == [])


def test_ingest_document_forwards_tags():
    seen = {}

    async def fake_chunks(chunks, dataset, doc_key, new_doc_id, provenance,
                          derived_from=None, tags=None):
        seen["tags"] = tags
        return len(chunks)

    orig = be._ingest_chunks
    be._ingest_chunks = fake_chunks
    try:
        res = run(be.ingest_document("short doc", "notes", "k9", {}, tags=["todo"]))
    finally:
        be._ingest_chunks = orig

    check("ingest_document forwards tags", seen.get("tags") == ["todo"],
          f"got {seen.get('tags')!r}")
    check("ingest_document returns a doc_id", bool(res.get("doc_id")))


def test_revise_carries_tags_forward():
    seen = {}

    async def fake_chunks(chunks, dataset, doc_key, new_doc_id, provenance,
                          derived_from=None, tags=None):
        seen["tags"] = tags
        seen["derived_from"] = derived_from
        return len(chunks)

    async def fake_meta(_id):
        return {
            "index": be.KNOWLEDGE_INDEX,
            "source_class": "tool-output",
            "agent": "someone",
            "source": {"dataset": "notes", "doc_key": "k1",
                       "parent_id": "oldparent", "tags": ["todo"]},
        }

    async def fake_supersede_parent(parent_id, sb, now):
        return 1

    o1, o2, o3 = be._ingest_chunks, be._get_target_meta, be._supersede_parent
    be._ingest_chunks, be._get_target_meta, be._supersede_parent = (
        fake_chunks, fake_meta, fake_supersede_parent)
    try:
        run(be.revise("chunk-id", "new content", {}, "client_credentials", "someone"))
    finally:
        be._ingest_chunks, be._get_target_meta, be._supersede_parent = o1, o2, o3

    check("revise carries the old doc's tags forward", seen.get("tags") == ["todo"],
          f"got {seen.get('tags')!r}")
    check("revise records derived_from", seen.get("derived_from") == ["chunk-id"])


# --------------------------------------------------------------------------- #
# 2. a returned parent id resolves
# --------------------------------------------------------------------------- #
def test_id_lookup_prefers_es_id():
    calls = []

    async def fake_es_json(method, path, body=None):
        calls.append((path, body))
        return {"hits": {"hits": [{"_id": "chunk1", "_index": be.KNOWLEDGE_INDEX,
                                   "_source": {}}]}}

    orig = be._es_json
    be._es_json = fake_es_json
    try:
        hit = run(be._get_by_id_any("chunk1"))
    finally:
        be._es_json = orig

    check("an ES _id hit short-circuits", hit and hit["_id"] == "chunk1")
    check("no parent_id fallback query when the ids query hits", len(calls) == 1,
          f"{len(calls)} queries issued")


def test_id_lookup_falls_back_to_parent_id():
    calls = []

    async def fake_es_json(method, path, body=None):
        calls.append((path, body))
        if len(calls) == 1:  # the ids query misses
            return {"hits": {"hits": []}}
        return {"hits": {"hits": [{"_id": "chunk0", "_index": be.KNOWLEDGE_INDEX,
                                   "_source": {"parent_id": "parent9"}}]}}

    orig = be._es_json
    be._es_json = fake_es_json
    try:
        hit = run(be._get_by_id_any("parent9"))
    finally:
        be._es_json = orig

    check("a parent id resolves to a chunk", hit and hit["_id"] == "chunk0",
          f"got {hit!r}")
    check("the fallback queries parent_id", len(calls) == 2
          and calls[1][1]["query"] == {"term": {"parent_id": "parent9"}},
          f"got {calls[1][1] if len(calls) > 1 else None!r}")
    check("the fallback takes the first chunk",
          len(calls) == 2 and calls[1][1]["sort"] == [{"chunk_index": "asc"}])


def test_target_meta_resolves_a_parent_id():
    """The revise / supersede path must resolve a parent id too.

    #885 put the fallback in `_get_by_id_any` only, and this suite asserted that
    function directly — so it passed while `revise(<returned id>)` still failed,
    because `_get_target_meta` ran its own ids-only query. Assert the lookup the
    WRITE PATH actually uses, not just the helper the fix touched.
    """
    calls = []

    async def fake_es_json(method, path, body=None):
        calls.append((path, body))
        if len(calls) == 1:  # ids query misses
            return {"hits": {"hits": []}}
        return {"hits": {"hits": [{
            "_id": "chunk0", "_index": be.KNOWLEDGE_INDEX,
            "_source": {"parent_id": "parent9", "tags": ["todo"],
                        "provenance": {"source_class": "tool-output",
                                       "agent": "someone"}},
        }]}}

    orig = be._es_json
    be._es_json = fake_es_json
    try:
        meta = run(be._get_target_meta("parent9"))
    finally:
        be._es_json = orig

    check("_get_target_meta resolves a parent id", meta is not None,
          "revise/supersede would answer 'id not found'")
    check("_get_target_meta reports the resolved index",
          meta and meta["index"] == be.KNOWLEDGE_INDEX)
    check("_get_target_meta carries provenance through",
          meta and meta["source_class"] == "tool-output" and meta["agent"] == "someone")
    check("_get_target_meta shares the one lookup path", len(calls) == 2,
          f"{len(calls)} queries — expected the ids query plus the parent_id fallback")


def test_id_lookup_returns_none_when_absent():
    async def fake_es_json(method, path, body=None):
        return {"hits": {"hits": []}}

    orig = be._es_json
    be._es_json = fake_es_json
    try:
        hit = run(be._get_by_id_any("nope"))
    finally:
        be._es_json = orig

    check("an unknown id still resolves to None", hit is None)


for fn in (test_tags_on_chunks, test_tags_default_empty,
           test_ingest_document_forwards_tags, test_revise_carries_tags_forward,
           test_id_lookup_prefers_es_id, test_id_lookup_falls_back_to_parent_id,
           test_target_meta_resolves_a_parent_id,
           test_id_lookup_returns_none_when_absent):
    # A test that raises is a FAIL, not an abort: against the pre-fix backend the
    # tags cases raise TypeError, and swallowing the rest of the run there would
    # have hidden whether the id cases carry their own weight.
    try:
        fn()
    except Exception as exc:  # noqa: BLE001 — a raising test is a failing test
        FAIL += 1
        print(f"FAIL {fn.__name__} :: raised {type(exc).__name__}: {exc}")

print(f"---- pass={PASS} fail={FAIL}")
sys.exit(1 if FAIL else 0)
