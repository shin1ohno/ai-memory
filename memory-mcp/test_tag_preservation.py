#!/usr/bin/env python3
"""Regression tests for the ways a tag stopped being a usable routing key.

`tags` is how the TODO pipeline enumerates work (`browse(filters={"tags":
"todo"})`, docs/todo-management.md). Every defect below let the write or the read
succeed and return something plausible, so none of them surfaced until a caller
tried to enumerate and got a wrong answer:

1. remember_fact's content_hash dedup discarded the caller's tags. Storing "X"
   untagged and later remembering "X" with tags:["todo"] returned a noop and left
   the todo unenumerable — permanently, since every retry dedups the same way.
2. Re-ingesting a knowledge document without tags replaced the tagged version
   with an untagged one. server.remember(type='knowledge') derives doc_key from
   content_hash(content), so re-saving identical text is exactly this upsert.
3. recall accepted a tag filter but omitted `tags` from its hits, so a caller
   filtering by tag could not see the tags it matched on.
4. browse returned a bare page with no total, so a store with 200 matches was
   indistinguishable from one with exactly `limit` — an enumeration lost its tail
   silently. There is no cursor, so the total is the only truncation signal.
5. _filter_clause passed any key straight through as a term clause, so a typo or
   a wrong-cased field matched nothing and read as "no data".

Several assertions are on the QUERY BODY rather than the return value. That is
deliberate: a fix to a helper can pass its own unit test while the caller still
never asks ES for the field (#885 fixed the tags helper and the write path stayed
broken because the projection had not changed). Where the body is what carries
the fix, the body is what gets asserted.

Not covered: server.py's tool layer, which cannot be imported here — it runs
asyncio.run(ensure_indices()) at import and needs the mcp package. Its recall
projection is a rename-only pass-through of the backend dict precisely so there
is no second place to drift; the backend assertions below are therefore the whole
contract.

Dependency-free on purpose: httpx and friends are stubbed before import, so this
runs on a bare python3 in CI as well as inside the app venv. Nothing here talks
to ES.

Usage: python3 test_tag_preservation.py
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

# scoring is pure but recall needs both entry points, not just composite.
_scoring = types.ModuleType("scoring")
_scoring.composite = lambda base, src, now, mt: float(base)
_scoring.rrf_fuse = lambda legs, k=60: {
    h["_id"]: 1.0 for leg in legs for h in leg
}
sys.modules["scoring"] = _scoring

# voyage needs embed_query and the sentinel exception for the recall path, on top
# of embed_documents for the write path.
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

import es_backend as be  # noqa: E402  (import after the stubs are installed)

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
    return asyncio.new_event_loop().run_until_complete(coro)


class _EsRecorder:
    """Stands in for _es_json: records every call, replies from a script."""

    def __init__(self, replies=None):
        self.calls: list[tuple[str, str, dict | None]] = []
        self._replies = list(replies or [])

    async def __call__(self, method, path, body=None):
        self.calls.append((method, path, body))
        if self._replies:
            return self._replies.pop(0)
        return {"updated": 0, "hits": {"hits": [], "total": {"value": 0, "relation": "eq"}}}

    def paths(self):
        return [c[1] for c in self.calls]


# --------------------------------------------------------------------------- #
# 1. remember_fact: a dedup hit applies the caller's NEW tags
# --------------------------------------------------------------------------- #
def _dedup_hit(tags, doc_id="fact-1", status="reconciled"):
    return {"hits": {"hits": [{
        "_id": doc_id,
        "_source": {"tags": list(tags), "reconcile_status": status},
    }]}}


def test_dedup_unions_new_tags():
    es = _EsRecorder([_dedup_hit([])])
    orig = be._es_json
    be._es_json = es
    try:
        res = run(be.remember_fact("X", ["todo"], {"agent": "a"}))
    finally:
        be._es_json = orig

    check("dedup hit still reports noop", res["action"] == "noop", f"got {res!r}")
    check("dedup hit reports which tags it added", res.get("tags_added") == ["todo"],
          f"got {res.get('tags_added')!r}")
    updates = [c for c in es.calls if "_update/" in c[1]]
    check("dedup hit issues exactly one tag update", len(updates) == 1,
          f"got {es.paths()!r}")
    if updates:
        method, path, body = updates[0]
        check("the update targets the deduped doc", "fact-1" in path, path)
        check("the update retries on version conflict", "retry_on_conflict" in path,
              path)
        check("the update passes only the missing tags",
              body["script"]["params"]["tags"] == ["todo"], f"got {body!r}")
        check("the update is a union, not an overwrite",
              "contains" in body["script"]["source"], f"got {body!r}")


def test_dedup_skips_the_write_when_tags_already_present():
    es = _EsRecorder([_dedup_hit(["todo", "work"])])
    orig = be._es_json
    be._es_json = es
    try:
        res = run(be.remember_fact("X", ["todo"], {"agent": "a"}))
    finally:
        be._es_json = orig

    check("no tag update when the tag is already there",
          not [c for c in es.calls if "_update/" in c[1]], f"got {es.paths()!r}")
    check("no tags_added key when nothing was added", "tags_added" not in res,
          f"got {res!r}")


def test_dedup_lookup_asks_for_tags():
    # The body assertion: without `tags` in _source the union would compare
    # against [] and re-add tags the doc already has on every call.
    es = _EsRecorder([_dedup_hit(["todo"])])
    orig = be._es_json
    be._es_json = es
    try:
        run(be.remember_fact("X", ["todo"], {"agent": "a"}))
    finally:
        be._es_json = orig

    body = es.calls[0][2]
    check("the dedup lookup projects tags", "tags" in (body or {}).get("_source", []),
          f"got {body!r}")
    check("the dedup lookup does not fetch the embedding",
          "embedding" not in (body or {}).get("_source", []), f"got {body!r}")


def test_untagged_caller_leaves_a_deduped_doc_alone():
    es = _EsRecorder([_dedup_hit(["todo"])])
    orig = be._es_json
    be._es_json = es
    try:
        run(be.remember_fact("X", None, {"agent": "a"}))
    finally:
        be._es_json = orig

    check("a tagless remember never rewrites tags",
          not [c for c in es.calls if "_update/" in c[1]], f"got {es.paths()!r}")


# --------------------------------------------------------------------------- #
# 2. knowledge re-ingest: omitted tags inherit, [] clears
# --------------------------------------------------------------------------- #
def _ingest_capture(tags_arg, prior_tags):
    captured: list[dict] = []

    async def fake_bulk(index, docs):
        captured.extend(docs)
        return len(docs)

    prior = {"hits": {"hits": [{"_id": "old-chunk",
                                "_source": {"tags": list(prior_tags)}}]}}
    es = _EsRecorder([prior, {"updated": 1}])
    orig_bulk, orig_json = be._bulk_index, be._es_json
    be._bulk_index, be._es_json = fake_bulk, es
    try:
        run(be._ingest_chunks(["a"], "notes", "k1", "parent2", {}, tags=tags_arg))
    finally:
        be._bulk_index, be._es_json = orig_bulk, orig_json
    return captured, es


def test_reingest_inherits_prior_tags_when_omitted():
    captured, es = _ingest_capture(None, ["todo", "work"])
    check("an omitted tags argument inherits the superseded version's tags",
          captured and captured[0]["tags"] == ["todo", "work"],
          f"got {captured[0]['tags'] if captured else None!r}")
    body = es.calls[0][2]
    check("the inheritance lookup filters on dataset and doc_key",
          any("doc_key" in str(m) for m in body["query"]["bool"]["must"]), f"got {body!r}")
    check("the inheritance lookup excludes superseded chunks",
          "superseded_by" in str(body["query"]["bool"]["must_not"]), f"got {body!r}")


def test_explicit_empty_tags_clears():
    captured, es = _ingest_capture([], ["todo"])
    check("tags=[] clears rather than inherits",
          captured and captured[0]["tags"] == [],
          f"got {captured[0]['tags'] if captured else None!r}")
    check("tags=[] skips the inheritance lookup entirely",
          not [c for c in es.calls if c[0] == "POST" and "_search" in c[1]],
          f"got {es.paths()!r}")


def test_explicit_tags_win_over_prior():
    captured, _ = _ingest_capture(["fresh"], ["todo"])
    check("an explicit tag list is used verbatim",
          captured and captured[0]["tags"] == ["fresh"],
          f"got {captured[0]['tags'] if captured else None!r}")


# --------------------------------------------------------------------------- #
# 3. recall returns tags
# --------------------------------------------------------------------------- #
def test_recall_hits_carry_tags():
    hit = {"_id": "f1", "_source": {"content": "c", "memory_type": "fact",
                                    "tags": ["todo"], "provenance": {"agent": "a"}}}
    es = _EsRecorder([{"hits": {"hits": [hit]}}, {"hits": {"hits": [hit]}}])
    orig_json, orig_spawn = be._es_json, be._spawn
    be._es_json = es
    be._spawn = lambda coro: coro.close()
    try:
        res = run(be.recall("c", top_k=5))
    finally:
        be._es_json, be._spawn = orig_json, orig_spawn

    hits = res.get("hits", [])
    check("recall returns a hit", len(hits) == 1, f"got {res!r}")
    if hits:
        check("recall hits carry tags", hits[0].get("tags") == ["todo"],
              f"got {hits[0]!r}")
        check("recall still carries memory_type for the server's rename",
              "memory_type" in hits[0], f"got {hits[0]!r}")


def test_recall_tags_default_to_a_list():
    hit = {"_id": "f1", "_source": {"content": "c", "memory_type": "fact"}}
    es = _EsRecorder([{"hits": {"hits": [hit]}}, {"hits": {"hits": [hit]}}])
    orig_json, orig_spawn = be._es_json, be._spawn
    be._es_json = es
    be._spawn = lambda coro: coro.close()
    try:
        res = run(be.recall("c", top_k=5))
    finally:
        be._es_json, be._spawn = orig_json, orig_spawn

    check("a tagless doc recalls as [] rather than None",
          res["hits"][0].get("tags") == [], f"got {res['hits'][0]!r}")


# --------------------------------------------------------------------------- #
# 4. browse reports the total, so truncation is visible
# --------------------------------------------------------------------------- #
def _browse(total_value, n_items, relation="eq", **kw):
    items = [{"_id": f"d{i}", "_source": {"content": "c", "tags": ["todo"],
                                          "embedding": [0.0]}}
             for i in range(n_items)]
    es = _EsRecorder([{"hits": {"hits": items,
                                "total": {"value": total_value, "relation": relation}}}])
    orig = be._es_json
    be._es_json = es
    try:
        return run(be.browse(**kw)), es
    finally:
        be._es_json = orig


def test_browse_reports_total_and_truncation():
    res, _ = _browse(34, 10, limit=10, filters={"tags": "todo"})
    check("browse reports the matching total", res["total"] == 34, f"got {res!r}")
    check("browse flags a truncated page", res["truncated"] is True, f"got {res!r}")
    check("browse still returns the page", len(res["items"]) == 10, f"got {res!r}")
    check("browse drops the embedding from items",
          "embedding" not in res["items"][0], f"got {res['items'][0].keys()!r}")
    check("browse keeps tags on items", res["items"][0]["tags"] == ["todo"],
          f"got {res['items'][0]!r}")


def test_browse_complete_page_is_not_truncated():
    res, _ = _browse(7, 7, limit=50)
    check("a complete page is not flagged truncated", res["truncated"] is False,
          f"got {res!r}")
    check("an exact total is not a lower bound",
          res["total_is_lower_bound"] is False, f"got {res!r}")


def test_browse_marks_a_lower_bound_total():
    res, _ = _browse(10000, 50, relation="gte", limit=50)
    check("ES's total ceiling surfaces as a lower bound",
          res["total_is_lower_bound"] is True, f"got {res!r}")


def test_browse_rejects_an_out_of_range_limit():
    for bad in (0, -1, be.BROWSE_MAX_LIMIT + 1):
        try:
            run(be.browse(limit=bad))
            check(f"browse rejects limit={bad}", False, "no QueryError raised")
        except be.QueryError:
            check(f"browse rejects limit={bad}", True)


# --------------------------------------------------------------------------- #
# 5. _filter_clause: allowlisted keys, and a real error for the rest
# --------------------------------------------------------------------------- #
def test_filter_shapes():
    check("a scalar filter is an exact term",
          be._filter_clause({"tags": "todo"}) == [{"term": {"tags": "todo"}}])
    check("a list filter is OR (terms), not AND",
          be._filter_clause({"tags": ["todo", "work"]})
          == [{"terms": {"tags": ["todo", "work"]}}])
    check("no filters means no clauses", be._filter_clause(None) == []
          and be._filter_clause({}) == [])


def test_filter_rejects_unknown_and_unfilterable_keys():
    for key in ("tag", "Tags", "nope", "content", "embedding"):
        try:
            be._filter_clause({key: "x"})
            check(f"_filter_clause rejects {key!r}", False, "no QueryError raised")
        except be.QueryError as exc:
            # The message has to name what IS allowed, or the caller is stuck.
            check(f"_filter_clause rejects {key!r}", "tags" in str(exc), str(exc))


def test_filter_rejects_date_fields_with_the_reason():
    try:
        be._filter_clause({"provenance.written_at": "2026-08-17"})
        check("_filter_clause rejects a date field", False, "no QueryError raised")
    except be.QueryError as exc:
        check("_filter_clause rejects a date field", "range" in str(exc).lower(),
              str(exc))


def test_filter_allowlist_covers_every_mapped_keyword_field():
    term_ok, dates = be._filterable_fields()
    expected = {"tags", "entities", "memory_type", "dataset", "doc_key", "parent_id",
                "chunk_index", "reconcile_status", "promoted_to", "content_hash",
                "derived_from", "superseded_by", "use_count",
                "provenance.agent", "provenance.session_id", "provenance.source_class"}
    check("the allowlist is derived from the mappings, not hand-listed",
          expected <= term_ok, f"missing {sorted(expected - term_ok)!r}")
    check("date fields are classified separately",
          {"provenance.written_at", "superseded_at", "last_used_at",
           "expires_at"} <= dates, f"got {sorted(dates)!r}")
    check("the vector and the analyzed text are not filterable",
          "embedding" not in term_ok and "content" not in term_ok)


# --------------------------------------------------------------------------- #
TESTS = [
    test_dedup_unions_new_tags,
    test_dedup_skips_the_write_when_tags_already_present,
    test_dedup_lookup_asks_for_tags,
    test_untagged_caller_leaves_a_deduped_doc_alone,
    test_reingest_inherits_prior_tags_when_omitted,
    test_explicit_empty_tags_clears,
    test_explicit_tags_win_over_prior,
    test_recall_hits_carry_tags,
    test_recall_tags_default_to_a_list,
    test_browse_reports_total_and_truncation,
    test_browse_complete_page_is_not_truncated,
    test_browse_marks_a_lower_bound_total,
    test_browse_rejects_an_out_of_range_limit,
    test_filter_shapes,
    test_filter_rejects_unknown_and_unfilterable_keys,
    test_filter_rejects_date_fields_with_the_reason,
    test_filter_allowlist_covers_every_mapped_keyword_field,
]

for t in TESTS:
    try:
        t()
    except Exception as exc:  # a raising test is a failure, not an abort
        FAIL += 1
        print(f"FAIL {t.__name__} — raised {type(exc).__name__}: {exc}")

print(f"---- pass={PASS} fail={FAIL}")
sys.exit(1 if FAIL else 0)
