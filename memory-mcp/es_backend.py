"""Async ElasticSearch backend for memory-mcp v2 (contract §4).

3 content indices (memory-fact / memory-knowledge / memory-episode) + a
memory-all alias + memory-stats. strict ES basic tier: dense_vector + kNN + BM25,
client-side RRF, multiplicative composite score. No LLM (write intelligence lives
in the mini memory-keeper). Embeddings via Voyage AI (voyage.py).

`chunk_text` + `content_hash` are ported VERBATIM from the legacy es-memory-mcp
backend (pure, no I/O). Everything else is reimplemented async on
httpx.AsyncClient.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import sys
import time
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import uuid4

import httpx

import scoring
import voyage
from identity import (POLICY_DENIED_MESSAGE, AuthzError, audit_policy_deny,
                      audit_supersede, authorize_supersede)

# --------------------------------------------------------------------------- #
# Config (contract §2a). Index names come from the unit's Environment= lines.
# --------------------------------------------------------------------------- #
ES_URL = os.environ["ES_URL"].rstrip("/")
ES_USER = os.environ.get("ES_USER", "elastic")
ES_PASSWORD = os.environ["ES_PASSWORD"]
ES_VERIFY = os.environ.get("ES_VERIFY_CERTS", "false").lower() == "true"

EMBEDDING_DIMS = int(os.environ.get("EMBEDDING_DIMENSIONS", "1024"))

FACT_INDEX = os.environ.get("FACT_INDEX", "memory-fact")
KNOWLEDGE_INDEX = os.environ.get("KNOWLEDGE_INDEX", "memory-knowledge")
EPISODE_INDEX = os.environ.get("EPISODE_INDEX", "memory-episode")
STATS_INDEX = os.environ.get("STATS_INDEX", "memory-stats")
ALL_ALIAS = os.environ.get("ALL_ALIAS", "memory-all")

RRF_K = 60
EPISODE_TTL_DAYS = 90
INGEST_JOB_THRESHOLD = 40  # >40 chunks → background job
# browse has no cursor, so a caller wanting a full enumeration raises `limit`.
# Cap it below ES's index.max_result_window (10000) so an over-large ask fails
# with a reason instead of a raw 500 from ES.
BROWSE_MAX_LIMIT = 1000
_FORGET_SENTINEL = "forget"  # non-null superseded_by marker for logical delete
_SUPERSEDE_SCRIPT = (
    "ctx._source.superseded_by = params.sb; ctx._source.superseded_at = params.at;"
)
# Additive tags union on a doc that already exists. This is the one in-place
# content-ish mutation the store permits (the keeper's rule is supersede-only,
# with superseded_by/at, reconcile_status, use_count and last_used_at as the
# in-place exceptions). A union earns its place there because it is monotone,
# idempotent and commutative: it can never remove a routing key, replaying it is
# free, and two writers racing cannot lose one of their tags. Rationale:
# docs/adr/0007-memory-tags-are-a-routing-key.md.
_TAG_UNION_SCRIPT = (
    "if (ctx._source.tags == null) { ctx._source.tags = new ArrayList(); } "
    "for (t in params.tags) { if (!ctx._source.tags.contains(t)) "
    "{ ctx._source.tags.add(t); } }"
)

# Re-export for callers (server routes type=knowledge through content_hash doc_key).
__all__ = [
    "chunk_text", "content_hash", "ensure_indices", "recall", "remember_fact",
    "ingest_document", "append_episode", "revise", "supersede",
    "get_with_chain", "browse", "stats", "bump_use_counts",
    "FACT_INDEX", "KNOWLEDGE_INDEX", "EPISODE_INDEX", "STATS_INDEX", "ALL_ALIAS",
    "AuthzError", "QueryError", "BROWSE_MAX_LIMIT",
]

# Module-level async client — bound to uvicorn's event loop on first use.
# ensure_indices() (called at import via asyncio.run) uses a SEPARATE ephemeral
# client so this pool is never created inside a throwaway loop.
_es = httpx.AsyncClient(
    base_url=ES_URL,
    auth=(ES_USER, ES_PASSWORD),
    verify=ES_VERIFY,
    timeout=httpx.Timeout(connect=5.0, read=30.0, write=30.0, pool=5.0),
)

# In-process ingest job registry (surfaced by stats()).
_JOBS: dict[str, dict] = {}
# Strong refs to fire-and-forget tasks so they are not GC'd mid-flight.
_BG_TASKS: set[asyncio.Task] = set()


def _spawn(coro) -> asyncio.Task:
    task = asyncio.create_task(coro)
    _BG_TASKS.add(task)
    task.add_done_callback(_BG_TASKS.discard)
    return task


# --------------------------------------------------------------------------- #
# Ported VERBATIM from legacy es_backend (pure, no I/O)
# --------------------------------------------------------------------------- #
def chunk_text(text: str, size: int = 1200, overlap: int = 150) -> list[str]:
    """Character-window chunking with overlap. Splits on paragraph boundaries
    when possible to keep chunks coherent."""
    text = text.strip()
    if len(text) <= size:
        return [text] if text else []
    chunks: list[str] = []
    start = 0
    while start < len(text):
        end = min(start + size, len(text))
        # prefer to break at a paragraph/sentence boundary near the window end
        if end < len(text):
            window = text[start:end]
            for sep in ("\n\n", "\n", ". ", " "):
                idx = window.rfind(sep)
                if idx > size * 0.5:
                    end = start + idx + len(sep)
                    break
        chunks.append(text[start:end].strip())
        if end >= len(text):
            break  # reached the tail; stop before overlap re-emits tiny dupes
        start = max(end - overlap, start + 1)
    return [c for c in chunks if c]


def content_hash(text: str) -> str:
    return hashlib.md5(text.encode("utf-8")).hexdigest()


# --------------------------------------------------------------------------- #
# Time + query helpers
# --------------------------------------------------------------------------- #
def _now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


class QueryError(ValueError):
    """A filter key or limit a query cannot honour.

    Raised instead of running the query anyway. The old behaviour passed every
    key straight through as a term clause, so a typo, a wrong case, or a field
    that does not exist matched nothing and came back as an empty result — a
    caller could not tell "no such key" from "no such data". That is the same
    silent-ignore class as the tags argument that used to be dropped on the
    knowledge write path (#885): the request succeeded, the answer was wrong.
    """


def _filterable_fields() -> tuple[frozenset[str], frozenset[str]]:
    """(term-filterable, date-only) field names, derived from the mappings.

    Derived rather than restated so a field added to _common_props/_INDEX_DEFS
    becomes filterable without a second edit here — a hand-maintained copy is
    how the two-site recall projection drifted. Nested objects are flattened to
    their dotted paths (provenance.agent, …), which is what ES filters on.
    """
    term_ok: set[str] = set()
    dates: set[str] = set()
    for index in (FACT_INDEX, KNOWLEDGE_INDEX, EPISODE_INDEX):
        for name, spec in _INDEX_DEFS[index]["mappings"]["properties"].items():
            if "properties" in spec:
                for sub, sub_spec in spec["properties"].items():
                    path = f"{name}.{sub}"
                    (dates if sub_spec.get("type") == "date" else term_ok).add(path)
                continue
            kind = spec.get("type")
            if kind == "date":
                dates.add(name)
            elif kind in ("keyword", "integer"):
                term_ok.add(name)
    return frozenset(term_ok), frozenset(dates)


def _filter_clause(filters: dict[str, Any] | None) -> list[dict]:
    """term/terms clauses for an allowlisted set of keys.

    A list value is OR (terms), a scalar is exact (term) — there is no AND-over-
    tags shape. `content` (analyzed text) and `embedding` (vector) are rejected
    rather than allowed to produce nonsense matches, and date fields are rejected
    with the reason, since only term/terms are expressible here.
    """
    if not filters:
        return []
    term_ok, dates = _filterable_fields()
    out: list[dict] = []
    for k, v in filters.items():
        if k in dates:
            raise QueryError(
                f"filter key {k!r} is a date field and only term/terms filters are "
                f"supported here, so a range cannot be expressed. "
                f"Filterable keys: {', '.join(sorted(term_ok))}")
        if k not in term_ok:
            raise QueryError(
                f"unknown filter key {k!r}. Filterable keys: "
                f"{', '.join(sorted(term_ok))}")
        if isinstance(v, list):
            out.append({"terms": {k: v}})
        else:
            out.append({"term": {k: v}})
    return out


def _not_superseded() -> dict:
    return {"bool": {"must_not": {"exists": {"field": "superseded_by"}}}}


def _index_for(memory_type: str | None) -> str:
    return {
        "fact": FACT_INDEX,
        "knowledge": KNOWLEDGE_INDEX,
        "episode": EPISODE_INDEX,
    }.get(memory_type, ALL_ALIAS)


def _raise_for_status(resp: httpx.Response, method: str, path: str) -> None:
    """`raise_for_status()`, but log ES's own reason first.

    httpx's error message carries only the status and the URL, so an
    authorization failure reaches the MCP caller as a bare
    `403 Forbidden for url .../_update_by_query` with no way to tell WHICH
    principal ES rejected or WHICH action it wanted. ES puts both in the
    response body (`action [indices:data/write/update/byquery] is unauthorized
    for user [...]`) and that body was being discarded.

    This is the auth-boundary rule applied server-side: a reject at an
    authn/authz boundary logs its variant unconditionally, never behind a
    debug flag. The body is truncated and carries no credential — ES echoes the
    denied action, the principal and the index, not the password.

    Observed 2026-08-17: `revise`/`forget` on memory-knowledge returned 403
    through the server while the SAME endpoint, as the SAME configured
    ES_USER, returned 200 from curl (privileges verified with
    `_has_privileges`, live role checked, no index write-block, credential not
    stale). With the body dropped there was nothing left to diagnose from.
    """
    if resp.is_error:
        detail = resp.text[:800].replace("\n", " ")
        print(
            f"ES-ERROR status={resp.status_code} {method} {path} "
            f"es_user={ES_USER} body={detail}",
            file=sys.stderr,
            flush=True,
        )
    resp.raise_for_status()


async def _es_json(method: str, path: str, body: dict | None = None) -> dict:
    resp = await _es.request(method, path, json=body)
    _raise_for_status(resp, method, path)
    return resp.json()


async def _union_tags(index: str, doc_id: str, tags: list) -> None:
    """Add `tags` to an existing doc, touching nothing else.

    retry_on_conflict is load-bearing: bump_use_counts runs _update_by_query over
    the same docs after every recall, so a version conflict here is routine
    rather than exceptional — and losing the retry would drop the tag silently,
    which is the failure this whole change exists to remove.
    """
    if not tags:
        return
    await _es_json(
        "POST", f"/{index}/_update/{doc_id}?refresh=wait_for&retry_on_conflict=3",
        {"script": {"lang": "painless", "source": _TAG_UNION_SCRIPT,
                    "params": {"tags": list(tags)}}},
    )


async def _bulk_index(index: str, docs: list[dict]) -> int:
    if not docs:
        return 0
    lines: list[str] = []
    for d in docs:
        meta: dict[str, Any] = {"index": {"_index": index}}
        if "_id" in d:
            meta["index"]["_id"] = d.pop("_id")
        lines.append(json.dumps(meta))
        lines.append(json.dumps(d))
    payload = "\n".join(lines) + "\n"
    resp = await _es.post(
        "/_bulk?refresh=true",
        content=payload,
        headers={"Content-Type": "application/x-ndjson"},
    )
    _raise_for_status(resp, "POST", "/_bulk")
    result = resp.json()
    if result.get("errors"):
        errored = [i for i in result["items"] if i.get("index", {}).get("error")]
        raise RuntimeError(f"bulk index had {len(errored)} errors: {errored[:3]}")
    return len(docs)


# --------------------------------------------------------------------------- #
# Index definitions (contract §1). Built in-process so the server is
# self-bootstrapping; mirrors files/es-indices-v2/*.json — keep in sync.
# --------------------------------------------------------------------------- #
_ANALYSIS = {
    "analyzer": {
        "ja_en_hybrid": {
            "type": "custom",
            "tokenizer": "kuromoji_tokenizer",
            "filter": [
                "kuromoji_baseform",
                "kuromoji_part_of_speech",
                "cjk_width",
                "lowercase",
                "kuromoji_stemmer",
            ],
        }
    }
}


def _common_props() -> dict:
    return {
        "content": {"type": "text", "analyzer": "ja_en_hybrid"},
        "embedding": {
            "type": "dense_vector",
            "dims": EMBEDDING_DIMS,
            "similarity": "cosine",
            "index": True,
            "index_options": {"type": "int8_hnsw"},
        },
        "memory_type": {"type": "keyword"},
        "tags": {"type": "keyword"},
        "entities": {"type": "keyword"},
        "provenance": {
            "properties": {
                "agent": {"type": "keyword"},
                "session_id": {"type": "keyword"},
                "source_class": {"type": "keyword"},
                "written_at": {"type": "date"},
            }
        },
        "superseded_by": {"type": "keyword"},
        "superseded_at": {"type": "date"},
        "use_count": {"type": "integer"},
        "last_used_at": {"type": "date"},
        "content_hash": {"type": "keyword"},
        "derived_from": {"type": "keyword"},
    }


def _content_index_def(extra_props: dict) -> dict:
    props = _common_props()
    props.update(extra_props)
    return {
        "settings": {
            "number_of_shards": 1,
            "number_of_replicas": 1,
            "analysis": _ANALYSIS,
        },
        "mappings": {"properties": props},
    }


_INDEX_DEFS: dict[str, dict] = {
    FACT_INDEX: _content_index_def({"reconcile_status": {"type": "keyword"}}),
    KNOWLEDGE_INDEX: _content_index_def({
        "dataset": {"type": "keyword"},
        "doc_key": {"type": "keyword"},
        "parent_id": {"type": "keyword"},
        "chunk_index": {"type": "integer"},
    }),
    EPISODE_INDEX: _content_index_def({
        "expires_at": {"type": "date"},
        "promoted_to": {"type": "keyword"},
    }),
    STATS_INDEX: {
        "settings": {"number_of_shards": 1, "number_of_replicas": 1},
        "mappings": {"properties": {
            "written_at": {"type": "date"},
            "host": {"type": "keyword"},
            "raw_backlog": {"type": "integer"},
            "reconciled_total": {"type": "integer"},
            "superseded_total": {"type": "integer"},
            "promoted_total": {"type": "integer"},
            "expired_deleted": {"type": "integer"},
            "guard_violations": {"type": "integer"},
            "errors": {"type": "integer"},
            "loop_lag_ms": {"type": "float"},
            "reconciled_this_run": {"type": "integer"},
            "run_kind": {"type": "keyword"},
        }},
    },
}


def _make_client() -> httpx.AsyncClient:
    return httpx.AsyncClient(
        base_url=ES_URL,
        auth=(ES_USER, ES_PASSWORD),
        verify=ES_VERIFY,
        timeout=httpx.Timeout(connect=5.0, read=30.0, write=30.0, pool=5.0),
    )


async def _index_exists(client: httpx.AsyncClient, name: str) -> bool:
    """HEAD /<index>. Needs only view_index_metadata, so it stays available to a
    credential that has no create_index / manage."""
    try:
        resp = await client.request("HEAD", f"/{name}")
    except Exception:  # noqa: BLE001 — treated as "cannot confirm"
        return False
    return resp.status_code == 200


async def _alias_covers(client: httpx.AsyncClient, members: list[str]) -> bool:
    """True when every member index already carries ALL_ALIAS. GET /_alias/<name>
    answers with only the indices that carry it, so key presence is the test.
    view_index_metadata is enough for this too."""
    try:
        resp = await client.request("GET", f"/_alias/{ALL_ALIAS}")
    except Exception:  # noqa: BLE001
        return False
    if resp.status_code != 200:
        return False
    try:
        mapped = resp.json()
    except ValueError:
        return False
    return all(idx in mapped for idx in members)


async def ensure_indices(retries: int = 10, delay: float = 3.0) -> None:
    """Make sure the 4 indices and the memory-all alias exist, and tolerate not
    being allowed to create them. Retries because ES may be cold at boot. Uses an
    ephemeral client so the module-level `_es` pool is not created inside the
    throwaway loop used by the import-time asyncio.run() call.

    LEAST-PRIVILEGE CREDENTIALS. This server is deployable with an ES user that
    holds only read / write / view_index_metadata on the memory-* indices -- no
    manage, no create_index -- so that possessing its password cannot delete an
    index or wipe the cluster. Such a user gets 403 on `PUT /<index>` and on
    `POST /_aliases`, and ES answers the authorization check BEFORE it would have
    answered resource_already_exists_exception, so the 400 branch never fires.
    Left unhandled, that 403 propagates through the retry loop and the server
    fails to start against a perfectly healthy, already-provisioned cluster.
    Treat 403 as success when the object is verifiably already there (the
    operator or the deploy-time bootstrap created it as a privileged user), and
    keep failing when it genuinely is not."""
    last_err: Exception | None = None
    async with _make_client() as client:
        for _ in range(retries):
            try:
                for name, body in _INDEX_DEFS.items():
                    resp = await client.request("PUT", f"/{name}", json=body)
                    if resp.status_code in (200, 201):
                        continue
                    if resp.status_code == 400 and \
                            "resource_already_exists_exception" in resp.text:
                        continue
                    if resp.status_code == 403 and await _index_exists(client, name):
                        continue
                    resp.raise_for_status()
                await _ensure_alias(client)
                return
            except Exception as exc:  # noqa: BLE001 — startup retry loop
                last_err = exc
                await asyncio.sleep(delay)
    if last_err:
        raise last_err


async def _ensure_alias(client: httpx.AsyncClient) -> None:
    members = [FACT_INDEX, KNOWLEDGE_INDEX, EPISODE_INDEX]
    actions = {"actions": [
        {"add": {"index": idx, "alias": ALL_ALIAS}} for idx in members
    ]}
    resp = await client.request("POST", "/_aliases", json=actions)
    # Same 403-when-already-correct case as ensure_indices; see its docstring.
    if resp.status_code == 403 and await _alias_covers(client, members):
        return
    resp.raise_for_status()


# --------------------------------------------------------------------------- #
# recall (contract §4)
# --------------------------------------------------------------------------- #
async def recall(query: str, memory_type: str | None = None, top_k: int = 10,
                 filters: dict | None = None, include_auto: bool = True) -> dict:
    """Hybrid BM25 + kNN retrieval with client-side RRF and multiplicative
    composite scoring. Excludes superseded docs. Returns an envelope
    {"hits": [...], "degraded"?}. Hits use the `memory_type` key (server remaps
    to `type` for the tool schema)."""
    fetch = max(50, 5 * top_k)
    index = _index_for(memory_type)

    flt = _filter_clause(filters)
    flt.append(_not_superseded())
    if not include_auto:
        flt.append({"bool": {"must_not": {"term": {"provenance.source_class": "auto-capture"}}}})

    degraded: str | None = None
    qvec: list[float] | None = None
    try:
        qvec = await voyage.embed_query(query)
    except voyage.VoyageUnavailable:
        degraded = "bm25-only"

    # BM25 leg
    bm25_body = {
        "size": fetch,
        "query": {"bool": {"must": {"match": {"content": query}}, "filter": flt}},
    }
    bm25_hits = (await _es_json("POST", f"/{index}/_search", bm25_body))["hits"]["hits"]
    legs = [bm25_hits]

    # kNN leg (skip when Voyage is down)
    if qvec is not None:
        knn_body = {
            "size": fetch,
            "knn": {
                "field": "embedding",
                "query_vector": qvec,
                "k": fetch,
                "num_candidates": 10 * fetch,
                "filter": flt,
            },
        }
        knn_hits = (await _es_json("POST", f"/{index}/_search", knn_body))["hits"]["hits"]
        legs.append(knn_hits)

    rrf = scoring.rrf_fuse(legs, k=RRF_K)
    sources: dict[str, dict] = {}
    for leg in legs:
        for h in leg:
            sources.setdefault(h["_id"], h.get("_source", {}))

    now = datetime.now(timezone.utc)
    scored: list[tuple[str, float, dict]] = []
    for _id, base in rrf.items():
        src = sources.get(_id, {})
        mt = src.get("memory_type") or memory_type
        scored.append((_id, scoring.composite(base, src, now, mt), src))
    scored.sort(key=lambda t: t[1], reverse=True)
    top = scored[:top_k]

    top3 = [t[0] for t in top[:3]]
    if top3:
        _spawn(bump_use_counts(top3))

    # `tags` belongs in the projection: recall ACCEPTS a tag filter, so a caller
    # enumerating by tag could filter on one and then not see which tags came
    # back. browse and get both return it (they project the whole _source), so
    # recall was the only read tool that dropped it.
    hits = [{
        "id": _id,
        "content": src.get("content", ""),
        "memory_type": src.get("memory_type"),
        "score": comp,
        "tags": src.get("tags") or [],
        "provenance": src.get("provenance", {}),
        "superseded": False,
    } for _id, comp, src in top]

    result: dict = {"hits": hits}
    if degraded:
        result["degraded"] = degraded
    return result


# --------------------------------------------------------------------------- #
# remember_fact (contract §4)
# --------------------------------------------------------------------------- #
async def remember_fact(content: str, tags: list | None, provenance: dict) -> dict:
    """content_hash exact-match dedup on memory-fact (non-superseded) → noop
    (applying any NEW tags to the doc that already exists); else embed → index
    reconcile_status=raw with ?refresh=wait_for.

    The dedup branch used to discard `tags` entirely, which made a tag lost for
    good: `remember("X", tags=["todo"])` against an already-stored untagged "X"
    returned a cheerful noop and left the todo unenumerable by
    browse(filters={"tags": "todo"}) — the exact rot docs/todo-management.md
    warns about. Tags are a routing key, so the dedup hit unions them in.
    """
    h = content_hash(content)
    body = {
        "size": 1,
        # Only the two fields this branch reads. Without the projection ES ships
        # the whole _source, i.e. a 1024-float embedding, on every dedup hit.
        "_source": ["reconcile_status", "tags"],
        "query": {"bool": {
            "must": [{"term": {"content_hash": h}}],
            "must_not": [{"exists": {"field": "superseded_by"}}],
        }},
    }
    existing = (await _es_json("POST", f"/{FACT_INDEX}/_search", body))["hits"]["hits"]
    if existing:
        top = existing[0]
        src = top.get("_source", {})
        have = src.get("tags") or []
        # Preserve caller order, drop duplicates, keep only what is genuinely new.
        missing = list(dict.fromkeys(t for t in (tags or []) if t not in have))
        out = {
            "action": "noop",
            "id": top["_id"],
            "routed_type": "fact",
            "reconcile_status": src.get("reconcile_status", "raw"),
        }
        if missing:
            await _union_tags(FACT_INDEX, top["_id"], missing)
            out["tags_added"] = missing
        return out

    vec = (await voyage.embed_documents([content]))[0]
    prov = dict(provenance or {})
    prov.setdefault("written_at", _now_iso())
    doc = {
        "content": content,
        "embedding": vec,
        "memory_type": "fact",
        "tags": tags or [],
        "entities": [],
        "provenance": prov,
        "use_count": 0,
        "content_hash": h,
        "reconcile_status": "raw",
    }
    # ?refresh=wait_for is mandatory (design v3 §6 Phase A): a burst of writes
    # racing the refresh interval would otherwise dedup-miss and duplicate facts.
    resp = await _es.request("POST", f"/{FACT_INDEX}/_doc?refresh=wait_for", json=doc)
    _raise_for_status(resp, "POST", f"/{FACT_INDEX}/_doc")
    return {
        "action": "added",
        "id": resp.json()["_id"],
        "routed_type": "fact",
        "reconcile_status": "raw",
    }


# --------------------------------------------------------------------------- #
# ingest_document (contract §4) — document-level upsert
# --------------------------------------------------------------------------- #
async def ingest_document(document: str, dataset: str, doc_key: str | None = None,
                          provenance: dict | None = None,
                          tags: list | None = None,
                          background: bool = True) -> dict:
    """Chunk → embed → index NEW chunks (parent_id = new synthetic doc id) →
    supersede the prior version's chunks (new-first, no empty window). >40 chunks
    runs in a background job; a job_id is returned and surfaced in stats().

    tags=None inherits the superseded version's tags; tags=[] clears them.

    background=False always ingests inline, so the caller gets {doc_id,
    chunk_count} or the exception. server.ingest uses it for callers restricted
    by CLIENT_POLICY: they cannot call memory_stats, the only place a failed
    job is visible (see identity.RESTRICTED_INGEST_MAX_CHARS).
    """
    doc_key = doc_key or content_hash(document)
    chunks = chunk_text(document)
    if not chunks:
        return {"doc_id": None, "chunk_count": 0}

    new_doc_id = uuid4().hex
    if background and len(chunks) > INGEST_JOB_THRESHOLD:
        job_id = uuid4().hex
        _JOBS[job_id] = {
            "job_id": job_id,
            "dataset": dataset,
            "doc_key": doc_key,
            "doc_id": new_doc_id,
            "status": "running",
            "chunk_count": len(chunks),
            "started_at": _now_iso(),
        }
        _spawn(_ingest_job(job_id, chunks, dataset, doc_key, new_doc_id, provenance,
                           tags=tags))
        return {"job_id": job_id}

    count = await _ingest_chunks(chunks, dataset, doc_key, new_doc_id, provenance,
                                 tags=tags)
    return {"doc_id": new_doc_id, "chunk_count": count}


async def _prior_doc_tags(dataset: str, doc_key: str) -> list:
    """Tags on the live version of (dataset, doc_key); [] when there is none."""
    body = {
        "size": 1,
        "_source": ["tags"],
        "sort": [{"chunk_index": {"order": "asc"}}],
        "query": {"bool": {
            "must": [{"term": {"dataset": dataset}}, {"term": {"doc_key": doc_key}}],
            "must_not": [{"exists": {"field": "superseded_by"}}],
        }},
    }
    hits = (await _es_json("POST", f"/{KNOWLEDGE_INDEX}/_search", body))["hits"]["hits"]
    return (hits[0].get("_source", {}).get("tags") or []) if hits else []


async def _ingest_chunks(chunks: list[str], dataset: str, doc_key: str,
                         new_doc_id: str, provenance: dict | None,
                         derived_from: list | None = None,
                         tags: list | None = None) -> int:
    # tags=None means "not specified" and INHERITS the version being superseded;
    # tags=[] is an explicit clear. Without that distinction an upsert of an
    # unchanged document — server.remember(type='knowledge') routes through
    # doc_key=content_hash(content), so re-remembering the same text lands here —
    # replaced a tagged document with an untagged one and the routing key was
    # gone. `revise` already carries the prior tags forward; this makes the
    # re-ingest path agree with it.
    if tags is None:
        tags = await _prior_doc_tags(dataset, doc_key)
    vecs = await voyage.embed_documents(chunks)
    prov = dict(provenance or {})
    prov.setdefault("written_at", _now_iso())
    docs = []
    for i, (chunk, vec) in enumerate(zip(chunks, vecs)):
        doc = {
            "content": chunk,
            "embedding": vec,
            "memory_type": "knowledge",
            "tags": tags or [],
            "entities": [],
            "provenance": prov,
            "use_count": 0,
            "content_hash": content_hash(chunk),
            "dataset": dataset,
            "doc_key": doc_key,
            "parent_id": new_doc_id,
            "chunk_index": i,
        }
        if derived_from:
            doc["derived_from"] = derived_from
        docs.append(doc)
    await _bulk_index(KNOWLEDGE_INDEX, docs)
    # Supersede the prior version's chunks AFTER the new ones land (new-first).
    now = _now_iso()
    await _supersede_prior_doc(dataset, doc_key, new_doc_id, now)
    return len(docs)


async def _supersede_prior_doc(dataset: str, doc_key: str, new_doc_id: str, now: str) -> int:
    body = {
        "query": {"bool": {
            "must": [{"term": {"dataset": dataset}}, {"term": {"doc_key": doc_key}}],
            "must_not": [
                {"exists": {"field": "superseded_by"}},
                {"term": {"parent_id": new_doc_id}},
            ],
        }},
        "script": {
            "lang": "painless",
            "source": _SUPERSEDE_SCRIPT,
            "params": {"sb": new_doc_id, "at": now},
        },
    }
    res = await _es_json(
        "POST", f"/{KNOWLEDGE_INDEX}/_update_by_query?refresh=true&conflicts=proceed", body)
    return res.get("updated", 0)


async def _ingest_job(job_id: str, chunks, dataset, doc_key, new_doc_id, provenance,
                      tags: list | None = None) -> None:
    try:
        count = await _ingest_chunks(chunks, dataset, doc_key, new_doc_id, provenance,
                                     tags=tags)
        _JOBS[job_id].update(status="done", chunk_count=count, finished_at=_now_iso())
    except Exception as exc:  # noqa: BLE001 — background job; record failure
        _JOBS[job_id].update(status="error", error=str(exc), finished_at=_now_iso())


# --------------------------------------------------------------------------- #
# append_episode (contract §4)
# --------------------------------------------------------------------------- #
async def append_episode(content: str, tags: list | None, provenance: dict) -> dict:
    vec = (await voyage.embed_documents([content]))[0]
    now = datetime.now(timezone.utc)
    prov = dict(provenance or {})
    prov.setdefault("written_at", _iso(now))
    doc = {
        "content": content,
        "embedding": vec,
        "memory_type": "episode",
        "tags": tags or [],
        "entities": [],
        "provenance": prov,
        "use_count": 0,
        "content_hash": content_hash(content),
        "expires_at": _iso(now + timedelta(days=EPISODE_TTL_DAYS)),
    }
    resp = await _es.request("POST", f"/{EPISODE_INDEX}/_doc?refresh=wait_for", json=doc)
    _raise_for_status(resp, "POST", f"/{EPISODE_INDEX}/_doc")
    return {"action": "added", "id": resp.json()["_id"], "routed_type": "episode"}


# --------------------------------------------------------------------------- #
# Target resolution + supersede/revise (contract §3 authz, §4)
# --------------------------------------------------------------------------- #
async def _get_target_meta(doc_id: str) -> dict | None:
    """Resolve an id → {index, source_class, agent, source}.

    Delegates to `_get_by_id_any` so there is exactly ONE id-resolution path.
    This function used to run its own ids-only query, which meant #885's
    parent-id fallback reached `get` but not `revise` / `supersede` — those go
    through here, so a caller passing the id `remember` had just returned still
    got "id not found". Two lookups for one concept is how that happened; keep
    it at one.
    """
    h = await _get_by_id_any(doc_id)
    if h is None:
        return None
    src = h.get("_source", {})
    prov = src.get("provenance") or {}
    return {
        "index": h["_index"],
        "source_class": prov.get("source_class"),
        "agent": prov.get("agent"),
        "source": src,
    }


async def _get_by_id_any(doc_id: str) -> dict | None:
    res = await _es_json("POST", f"/{ALL_ALIAS}/_search",
                         {"size": 1, "query": {"ids": {"values": [doc_id]}}})
    hits = res["hits"]["hits"]
    if hits:
        return hits[0]

    # Fall back to a knowledge PARENT id. `ingest_document` and `revise` return
    # the synthetic `parent_id` they minted (`doc_id` / `new_id`), which is NOT
    # an ES _id — so an ids query misses it and every follow-up get / revise /
    # forget answered "id not found" for the very id the write had just handed
    # back. Resolving it here makes the returned id usable, which is what the
    # tool contract implies; callers should not have to run a recall to
    # re-discover a chunk id first.
    res = await _es_json(
        "POST", f"/{KNOWLEDGE_INDEX}/_search",
        {"size": 1,
         "sort": [{"chunk_index": "asc"}],
         "query": {"term": {"parent_id": doc_id}}})
    hits = res["hits"]["hits"]
    return hits[0] if hits else None


async def _supersede_parent(parent_id: str, sb_value: str, now: str) -> int:
    body = {
        "query": {"bool": {
            "must": [{"term": {"parent_id": parent_id}}],
            "must_not": [{"exists": {"field": "superseded_by"}}],
        }},
        "script": {
            "lang": "painless",
            "source": _SUPERSEDE_SCRIPT,
            "params": {"sb": sb_value, "at": now},
        },
    }
    res = await _es_json(
        "POST", f"/{KNOWLEDGE_INDEX}/_update_by_query?refresh=true&conflicts=proceed", body)
    return res.get("updated", 0)


async def _mark_superseded(index: str, doc_id: str, sb_value: str, now: str) -> None:
    await _es_json("POST", f"/{index}/_update/{doc_id}?refresh=true",
                   {"doc": {"superseded_by": sb_value, "superseded_at": now}})


def _in_allowed_datasets(dataset, allowed_datasets) -> bool:
    # isinstance first: a keyword field can hold an array, and a list is not
    # hashable for the frozenset membership test.
    return isinstance(dataset, str) and dataset in allowed_datasets


async def supersede(id: str | None = None, dataset: str | None = None,
                    doc_key: str | None = None, grant: str = "authorization_code",
                    agent: str = "", allowed_datasets=None) -> dict:
    """Logical delete (contract §4 forget). Authz per §3. knowledge supports
    dataset/doc_key scope; a knowledge chunk id supersedes its whole parent doc.

    allowed_datasets (identity.allowed_datasets): None = unrestricted; otherwise
    the target must be a knowledge document in one of those datasets. The
    CLIENT_POLICY gate already checks a `dataset` argument; the id path is
    checked here because only the resolved document says which dataset it is in.
    """
    now = _now_iso()

    if id:
        meta = await _get_target_meta(id)
        if meta is None:
            return {"superseded_count": 0}
        if allowed_datasets is not None:
            target_dataset = meta["source"].get("dataset")
            if not (meta["index"] == KNOWLEDGE_INDEX
                    and _in_allowed_datasets(target_dataset, allowed_datasets)):
                audit_policy_deny("forget", agent, target_dataset)
                raise AuthzError(POLICY_DENIED_MESSAGE)
        if not authorize_supersede(grant, agent, meta["source_class"], meta["agent"]):
            raise AuthzError(
                f"grant={grant} agent={agent} not permitted to forget id={id}")
        index = meta["index"]
        if index == KNOWLEDGE_INDEX:
            parent_id = meta["source"].get("parent_id")
            if parent_id:
                count = await _supersede_parent(parent_id, _FORGET_SENTINEL, now)
            else:
                await _mark_superseded(index, id, _FORGET_SENTINEL, now)
                count = 1
        else:
            await _mark_superseded(index, id, _FORGET_SENTINEL, now)
            count = 1
        audit_supersede(id, agent, grant)
        return {"superseded_count": count}

    if dataset and doc_key:
        if allowed_datasets is not None and not _in_allowed_datasets(dataset, allowed_datasets):
            audit_policy_deny("forget", agent, dataset)
            raise AuthzError(POLICY_DENIED_MESSAGE)
        must = [{"term": {"dataset": dataset}}, {"term": {"doc_key": doc_key}}]
        # client_credentials may only forget its own provenance.agent docs.
        if grant == "client_credentials":
            must.append({"term": {"provenance.agent": agent}})
        body = {
            "query": {"bool": {
                "must": must,
                "must_not": [{"exists": {"field": "superseded_by"}}],
            }},
            "script": {
                "lang": "painless",
                "source": _SUPERSEDE_SCRIPT,
                "params": {"sb": _FORGET_SENTINEL, "at": now},
            },
        }
        res = await _es_json(
            "POST", f"/{KNOWLEDGE_INDEX}/_update_by_query?refresh=true&conflicts=proceed", body)
        audit_supersede(f"dataset={dataset},doc_key={doc_key}", agent, grant)
        return {"superseded_count": res.get("updated", 0)}

    return {"superseded_count": 0}


async def revise(id: str, content: str, provenance: dict, grant: str, agent: str) -> dict:
    """Supersede old + write new (derived_from=[old]). A knowledge chunk id
    resolves to its parent doc — the whole doc is re-chunked/re-embedded."""
    meta = await _get_target_meta(id)
    if meta is None:
        raise ValueError(f"id {id} not found")
    if not authorize_supersede(grant, agent, meta["source_class"], meta["agent"]):
        raise AuthzError(
            f"grant={grant} agent={agent} not permitted to revise id={id}")

    index = meta["index"]
    src = meta["source"]
    now = _now_iso()
    prov = dict(provenance or {})
    prov.setdefault("written_at", now)

    if index == KNOWLEDGE_INDEX:
        dataset = src.get("dataset", "notes")
        doc_key = src.get("doc_key") or content_hash(content)
        new_doc_id = uuid4().hex
        chunks = chunk_text(content)
        await _ingest_chunks(chunks, dataset, doc_key, new_doc_id, prov,
                             derived_from=[id], tags=src.get("tags") or [])
        old_parent = src.get("parent_id")
        if old_parent:
            await _supersede_parent(old_parent, new_doc_id, now)
        else:
            await _mark_superseded(index, id, new_doc_id, now)
        audit_supersede(id, agent, grant)
        return {"new_id": new_doc_id}

    # fact / episode: supersede single + write new
    vec = (await voyage.embed_documents([content]))[0]
    memory_type = src.get("memory_type", "fact")
    new_doc = {
        "content": content,
        "embedding": vec,
        "memory_type": memory_type,
        "tags": src.get("tags", []),
        "entities": src.get("entities", []),
        "provenance": prov,
        "use_count": 0,
        "content_hash": content_hash(content),
        "derived_from": [id],
    }
    if memory_type == "fact":
        new_doc["reconcile_status"] = "raw"
    if memory_type == "episode" and src.get("expires_at"):
        new_doc["expires_at"] = src["expires_at"]
    resp = await _es.request("POST", f"/{index}/_doc?refresh=wait_for", json=new_doc)
    _raise_for_status(resp, "POST", f"/{index}/_doc")
    new_id = resp.json()["_id"]
    await _mark_superseded(index, id, new_id, now)
    audit_supersede(id, agent, grant)
    return {"new_id": new_id}


# --------------------------------------------------------------------------- #
# get_with_chain / browse / stats / bump_use_counts (contract §4)
# --------------------------------------------------------------------------- #
async def get_with_chain(id: str, include_chain: bool = False) -> dict:
    """Full _source (minus the raw vector) + optional supersede chain. NO
    use_count side effect (contract §4)."""
    hit = await _get_by_id_any(id)
    if hit is None:
        raise ValueError(f"id {id} not found")
    src = {k: v for k, v in hit.get("_source", {}).items() if k != "embedding"}
    out: dict = {"id": id, **src}
    out["chain"] = await _resolve_chain(id, hit["_source"]) if include_chain else []
    return out


async def _resolve_chain(id: str, source: dict) -> list[dict]:
    """Follow the superseded_by forward chain, dropping raw vectors."""
    chain: list[dict] = []
    seen = {id}
    cur = source
    for _ in range(50):  # hard cap against a cyclic chain
        sb = cur.get("superseded_by")
        if not sb or sb == _FORGET_SENTINEL or sb in seen:
            break
        nxt = await _get_by_id_any(sb)
        if nxt is None:
            break
        seen.add(sb)
        entry = {k: v for k, v in nxt.get("_source", {}).items() if k != "embedding"}
        entry["id"] = sb
        chain.append(entry)
        cur = nxt["_source"]
    return chain


async def browse(memory_type: str | None = None, filters: dict | None = None,
                 sort: str = "provenance.written_at:desc", limit: int = 50) -> dict:
    """Page of non-superseded memories, WITH the matching total.

    Returns {"items": [...], "total": N, "truncated": bool,
    "total_is_lower_bound": bool}. The total is the reason this returns an
    envelope rather than a bare list: there is no cursor and no offset here, so
    without it a caller cannot tell a store holding exactly `limit` matches from
    one holding a thousand — an enumeration silently loses its tail and reports
    the page as the whole set. ES already carries the count in the same response
    this function parses, so it costs no extra round trip.

    `total_is_lower_bound` is ES's track_total_hits ceiling (10000 by default):
    past it the count comes back as a lower bound, not an exact figure.
    """
    if not isinstance(limit, int) or limit < 1 or limit > BROWSE_MAX_LIMIT:
        raise QueryError(f"limit must be an int in 1..{BROWSE_MAX_LIMIT}, got {limit!r}")
    index = _index_for(memory_type)
    flt = _filter_clause(filters)
    flt.append(_not_superseded())
    field, _, direction = sort.partition(":")
    direction = direction or "desc"
    # The tool default is "written_at:desc"; the stored field is nested.
    if field == "written_at":
        field = "provenance.written_at"
    body = {
        "size": limit,
        "query": {"bool": {"filter": flt}},
        "sort": [{field: {"order": direction}}],
    }
    res = await _es_json("POST", f"/{index}/_search", body)
    items = []
    for h in res["hits"]["hits"]:
        s = {k: v for k, v in h.get("_source", {}).items() if k != "embedding"}
        s["id"] = h["_id"]
        items.append(s)
    total_obj = res.get("hits", {}).get("total") or {}
    total = total_obj.get("value", len(items))
    return {
        "items": items,
        "total": total,
        "truncated": total > len(items),
        "total_is_lower_bound": total_obj.get("relation", "eq") != "eq",
    }


async def stats() -> dict:
    counts: dict[str, int] = {}
    for label, idx in (("fact", FACT_INDEX), ("knowledge", KNOWLEDGE_INDEX),
                       ("episode", EPISODE_INDEX)):
        try:
            counts[label] = (await _es_json("GET", f"/{idx}/_count")).get("count", 0)
        except Exception:  # noqa: BLE001 — a missing index reports 0, not fatal
            counts[label] = 0

    raw_backlog = 0
    try:
        rb = await _es_json("POST", f"/{FACT_INDEX}/_count", {"query": {"bool": {
            "must": [{"term": {"reconcile_status": "raw"}}],
            "must_not": [{"exists": {"field": "superseded_by"}}],
        }}})
        raw_backlog = rb.get("count", 0)
    except Exception:  # noqa: BLE001
        raw_backlog = 0

    keeper: dict[str, dict] = {}
    for run_kind in ("reconcile", "consolidate"):
        try:
            r = await _es_json("POST", f"/{STATS_INDEX}/_search", {
                "size": 1,
                "query": {"term": {"run_kind": run_kind}},
                "sort": [{"written_at": {"order": "desc"}}],
            })
            hits = r["hits"]["hits"]
            if hits:
                keeper[run_kind] = hits[0]["_source"]
        except Exception:  # noqa: BLE001
            pass

    return {
        "counts": counts,
        "raw_backlog": raw_backlog,
        "keeper": keeper,
        "ingest_jobs": list(_JOBS.values()),
    }


async def bump_use_counts(ids) -> None:
    """Fire-and-forget increment of use_count + last_used_at for the given ids
    (top-3 recall hits only). Errors are swallowed — this must not affect the
    read path."""
    ids = list(ids)
    if not ids:
        return
    now = _now_iso()
    body = {
        "query": {"ids": {"values": ids}},
        "script": {
            "lang": "painless",
            "source": (
                "if (ctx._source.use_count == null) { ctx._source.use_count = 1 } "
                "else { ctx._source.use_count += 1 } "
                "ctx._source.last_used_at = params.now;"
            ),
            "params": {"now": now},
        },
    }
    try:
        resp = await _es.request(
            "POST", f"/{ALL_ALIAS}/_update_by_query?conflicts=proceed", json=body)
        _raise_for_status(resp, "POST", f"/{ALL_ALIAS}/_update_by_query")
    except Exception:  # noqa: BLE001 — fire-and-forget
        pass
