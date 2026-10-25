"""Session search and preview (design spec §6.7 query design, §7.2 /search and
/preview, §8 rows 10 and 17, §9 latency targets).

Called by sessions_app.py after its gate has authorized the caller:

    search(es, body, caller)            -> dict   (POST /search)
    preview(es, session_key, q, caller) -> dict   (GET /preview)

`es` is the es_backend module; only its `_es` client is used
(`await es._es.request(method, path, json=...)`). `caller` is the gate's dict
{sub, client_id, grant, agent, host, scope}. Reads cover every host in the
boundary (§7.2), so `caller` does not narrow the query.

Keystroke path (§3.3, §8 row 17): no highlight, `track_total_hits: false`,
`collapse` on session_key, size 50, `_source` limited to session_key, then one
`_mget` on the session index. Highlight exists only in preview, which is scoped
to one session.

Hybrid (§6.7): the lexical leg plus a kNN leg on message docs, fused per
session with scoring.rrf_fuse(k=60) over each session's best message rank. The
query embedding has a 1.5 s budget and an in-process LRU of 256 entries; on
timeout or provider failure the answer carries `degraded: "bm25-only"`
(§8 row 10). A timed-out embedding keeps running in the background and fills
the cache, so the next keystroke of the same query is a hit.

Never logged: the query string and any snippet. Errors log a class name only.
"""

from __future__ import annotations

import asyncio
import collections
import math
import os
import re
import sys
import time
from datetime import datetime, timezone

import scoring

SESSION_INDEX = os.environ.get("SESSION_INDEX", "memory-session")
MESSAGE_INDEX = os.environ.get("SESSION_MESSAGE_INDEX", "memory-session-message")

LIMIT_MAX = 50
Q_MAX_CHARS = 1000
HOSTS_MAX = 16
CWD_MAX_CHARS = 4096
TEXT_BOOST = 2.0
TOOL_TEXT_BOOST = 0.5
RRF_K = 60
KNN_K = 100
KNN_NUM_CANDIDATES = 1000
EMBED_TIMEOUT_S = 1.5
EMBED_CACHE_SIZE = 256
EMBED_INFLIGHT_MAX = 8
RECENCY_WEIGHT = 0.05
RECENCY_HALF_LIFE_DAYS = 30.0
PREVIEW_SIZE = 6
PREVIEW_FRAGMENT_SIZE = 160
PREVIEW_RECENT = 4
PREVIEW_RECENT_CHARS = 400
DEGRADED_BM25 = "bm25-only"

HOST_RE = re.compile(r"^[a-z0-9-]{1,63}$")
SINCE_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}(T\d{2}:\d{2}(:\d{2}(\.\d{1,9})?)?(Z|[+-]\d{2}:?\d{2})?)?$")

# Fields returned for each session in /search (§7.2) — and the _mget _source.
SEARCH_FIELDS = ["session_key", "session_id", "host", "title", "cwd", "resume_cwd",
                 "updated_at", "jsonl_exists", "archived", "archive_complete", "interactive"]
# /preview returns more of the session doc: ccs resume reads session_id, host,
# project_dir, jsonl_path, resume_cwd, archived, archive_complete from it.
# archive_chunks (internal sha256 bookkeeping) is never returned.
PREVIEW_FIELDS = SEARCH_FIELDS + [
    "project_dir", "jsonl_path", "resume_cwd_verified", "cwd_candidates", "title_source",
    "git_branch", "entrypoint", "cc_version", "started_at", "message_count",
    "text_message_count", "has_subagents", "jsonl_checked_at", "archive_generation",
    "archive_bytes", "restored_from", "redact_version", "parser_version"]
_MGET_SOURCE = SEARCH_FIELDS + ["purged_at"]


# --------------------------------------------------------------------------- #
# Errors: resolved from sessions_app at call time (it imports this module at
# load time, so a top-level import would be circular). The fallbacks keep this
# module importable and testable on its own.
# --------------------------------------------------------------------------- #
class _LocalESUnavailable(Exception):
    pass


class _LocalHTTPError(Exception):
    def __init__(self, status: int, code: str, **extra):
        super().__init__(code)
        self.status, self.code, self.extra = status, code, extra


def _app():
    return sys.modules.get("sessions_app")


def _es_unavailable(msg: str) -> Exception:
    cls = getattr(_app(), "ESUnavailable", None) or _LocalESUnavailable
    return cls(msg)


def _not_found() -> Exception:
    cls = getattr(_app(), "HTTPError", None) or _LocalHTTPError
    return cls(404, "not_found")


def _log(msg: str) -> None:
    print(f"sessions_search: {msg}", file=sys.stderr, flush=True)


async def _call(es, method: str, path: str, body: dict) -> dict:
    """One ES round trip. Transport errors and non-2xx answers become
    sessions_app.ESUnavailable (503 at the gate), never a partial result."""
    try:
        resp = await es._es.request(method, path, json=body)
    except Exception as exc:  # noqa: BLE001
        raise _es_unavailable(f"{path.split('?')[0]}: {exc.__class__.__name__}") from None
    if resp.status_code >= 300:
        raise _es_unavailable(f"{path.split('?')[0]}: HTTP {resp.status_code}")
    try:
        data = resp.json()
    except ValueError:
        raise _es_unavailable(f"{path.split('?')[0]}: unparseable response") from None
    if not isinstance(data, dict):
        raise _es_unavailable(f"{path.split('?')[0]}: malformed response")
    return data


# --------------------------------------------------------------------------- #
# Request validation (ValueError -> 400 bad_request at sessions_app)
# --------------------------------------------------------------------------- #
def _bool(body: dict, name: str, default: bool) -> bool:
    v = body.get(name, default)
    if v is None:
        return default
    if not isinstance(v, bool):
        raise ValueError(f"{name} must be a boolean")
    return v


def _query_string(v) -> str:
    if v is None:
        return ""
    if not isinstance(v, str):
        raise ValueError("q must be a string")
    if len(v) > Q_MAX_CHARS:
        raise ValueError(f"q is longer than {Q_MAX_CHARS} characters")
    return v.strip()


def parse_request(body) -> dict:
    if not isinstance(body, dict):
        raise ValueError("body must be a JSON object")
    mode = body.get("mode") or "lexical"
    if mode not in ("lexical", "hybrid"):
        raise ValueError("mode must be lexical or hybrid")
    limit = body.get("limit", LIMIT_MAX)
    if limit is None:
        limit = LIMIT_MAX
    if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= LIMIT_MAX:
        raise ValueError(f"limit must be an integer in 1..{LIMIT_MAX}")
    hosts = body.get("hosts")
    if hosts is not None:
        if (not isinstance(hosts, list) or len(hosts) > HOSTS_MAX
                or not all(isinstance(h, str) and HOST_RE.match(h) for h in hosts)):
            raise ValueError("hosts must be a list of host labels")
        hosts = sorted(set(hosts)) or None
    cwd_prefix = body.get("cwd_prefix")
    if cwd_prefix is not None:
        if not isinstance(cwd_prefix, str) or not cwd_prefix or len(cwd_prefix) > CWD_MAX_CHARS:
            raise ValueError("cwd_prefix must be a non-empty path")
        cwd_prefix = cwd_prefix.rstrip("/") or "/"
    since = body.get("since")
    if since is not None:
        if not isinstance(since, str) or not SINCE_RE.match(since):
            raise ValueError("since must be an ISO 8601 timestamp")
    return {
        "q": _query_string(body.get("q")),
        "mode": mode,
        "deep": _bool(body, "deep", False),
        "hosts": hosts,
        "cwd_prefix": cwd_prefix,
        "include_headless": _bool(body, "include_headless", False),
        "include_sidechain": _bool(body, "include_sidechain", False),
        "since": since,
        "limit": limit,
    }


# --------------------------------------------------------------------------- #
# Query bodies (pure; the unit tests assert them verbatim)
# --------------------------------------------------------------------------- #
def _cwd_clause(prefix: str) -> dict:
    """cwd equal to the prefix, or under it — never a sibling that only shares
    the leading characters (/a/b must not match /a/bc)."""
    if prefix == "/":
        return {"prefix": {"cwd": "/"}}
    return {"bool": {"should": [{"term": {"cwd": prefix}},
                                {"prefix": {"cwd": prefix + "/"}}],
                     "minimum_should_match": 1}}


def message_filters(req: dict) -> list:
    """Filters on message docs; host, cwd and interactive are copied onto each
    message (§7.1.2), so they run without a join."""
    f = []
    if req["hosts"]:
        f.append({"terms": {"host": req["hosts"]}})
    if req["cwd_prefix"]:
        f.append(_cwd_clause(req["cwd_prefix"]))
    if not req["include_headless"]:
        f.append({"term": {"interactive": True}})
    if not req["include_sidechain"]:
        f.append({"term": {"is_sidechain": False}})
    if req["since"]:
        f.append({"range": {"ts": {"gte": req["since"]}}})
    return f


def session_filters(req: dict) -> list:
    """Filters on session docs (the empty-query path)."""
    f = [{"bool": {"must_not": [{"exists": {"field": "purged_at"}}]}}]
    if req["hosts"]:
        f.append({"terms": {"host": req["hosts"]}})
    if req["cwd_prefix"]:
        f.append(_cwd_clause(req["cwd_prefix"]))
    if not req["include_headless"]:
        f.append({"term": {"interactive": True}})
    if req["since"]:
        f.append({"range": {"updated_at": {"gte": req["since"]}}})
    return f


def _fields(deep: bool) -> list:
    return [f"text^{TEXT_BOOST:g}"] + ([f"tool_text^{TOOL_TEXT_BOOST:g}"] if deep else [])


def _match(q: str, deep: bool) -> dict:
    return {"multi_match": {"query": q, "fields": _fields(deep), "operator": "and"}}


def lexical_body(req: dict) -> dict:
    return {
        "size": LIMIT_MAX,
        "_source": ["session_key"],
        "track_total_hits": False,
        "query": {"bool": {"must": [_match(req["q"], req["deep"])],
                           "filter": message_filters(req)}},
        "collapse": {"field": "session_key"},
    }


def knn_body(req: dict, vector: list) -> dict:
    return {
        "size": KNN_K,
        "_source": ["session_key"],
        "track_total_hits": False,
        "knn": {"field": "embedding", "query_vector": vector, "k": KNN_K,
                "num_candidates": KNN_NUM_CANDIDATES,
                "filter": {"bool": {"filter": message_filters(req)}}},
    }


def hit_count_body(req: dict, keys: list) -> dict:
    """Matching messages per session for the returned keys. The match runs in
    filter context (no scoring), restricted to <= 150 sessions."""
    return {
        "size": 0,
        "track_total_hits": False,
        "query": {"bool": {"filter": [_match(req["q"], req["deep"]),
                                      {"terms": {"session_key": keys}}]
                           + message_filters(req)}},
        "aggs": {"per_session": {"terms": {"field": "session_key", "size": len(keys)}}},
    }


def recent_body(req: dict) -> dict:
    return {
        "size": req["limit"],
        "_source": SEARCH_FIELDS,
        "track_total_hits": False,
        "query": {"bool": {"filter": session_filters(req)}},
        "sort": [{"updated_at": {"order": "desc", "missing": "_last"}}],
    }


def mget_body(keys: list) -> dict:
    return {"ids": keys}


def preview_match_body(session_key: str, q: str) -> dict:
    return {
        "size": PREVIEW_SIZE,
        "_source": ["ts", "role"],
        "track_total_hits": False,
        "query": {"bool": {"must": [{"multi_match": {"query": q, "fields": ["text", "tool_text"],
                                                     "operator": "and"}}],
                           "filter": [{"term": {"session_key": session_key}}]}},
        "highlight": {"fields": {"text": {}, "tool_text": {}},
                      "fragment_size": PREVIEW_FRAGMENT_SIZE, "number_of_fragments": 1},
    }


def preview_recent_body(session_key: str) -> dict:
    return {
        "size": PREVIEW_RECENT,
        "_source": ["ts", "role", "text"],
        "track_total_hits": False,
        "query": {"bool": {"filter": [{"term": {"session_key": session_key}},
                                      {"exists": {"field": "text"}}]}},
        "sort": [{"ts": {"order": "desc"}}],
    }


# --------------------------------------------------------------------------- #
# Ranking
# --------------------------------------------------------------------------- #
def recency_nudge(updated_at, now: datetime) -> float:
    """0.05 x 2^(-age_days/30) (§6.7). A missing or unparseable timestamp gets
    no nudge; a timestamp in the future counts as age 0."""
    ts = scoring._parse_iso(updated_at)
    if ts is None:
        return 0.0
    age_days = max(0.0, (now - ts).total_seconds() / 86400.0)
    return RECENCY_WEIGHT * math.pow(2.0, -age_days / RECENCY_HALF_LIFE_DAYS)


def session_ranks(hits: list) -> list:
    """Session keys in the order of each session's best (first) message hit."""
    seen, out = set(), []
    for h in hits:
        sk = (h.get("_source") or {}).get("session_key")
        if isinstance(sk, str) and sk not in seen:
            seen.add(sk)
            out.append(sk)
    return out


# --------------------------------------------------------------------------- #
# Query embedding: 1.5 s budget, 256-entry LRU, background completion
# --------------------------------------------------------------------------- #
class EmbeddingCache:
    def __init__(self, size: int = EMBED_CACHE_SIZE):
        self.size = size
        self._d: collections.OrderedDict = collections.OrderedDict()
        self.inflight: dict = {}

    def get(self, key):
        v = self._d.get(key)
        if v is not None:
            self._d.move_to_end(key)
        return v

    def put(self, key, vec) -> None:
        self._d[key] = vec
        self._d.move_to_end(key)
        while len(self._d) > self.size:
            self._d.popitem(last=False)

    def __len__(self):
        return len(self._d)

    def clear(self) -> None:
        self._d.clear()
        self.inflight.clear()


_CACHE = EmbeddingCache()
_STATS = {"embed_timeouts": 0, "embed_failures": 0, "cache_hits": 0, "cache_misses": 0}


def _embed_fn():
    """voyage.embed_query, imported lazily (voyage reads VOYAGE_API_KEY at
    import). Tests replace this attribute."""
    import voyage  # noqa: PLC0415
    return voyage.embed_query


EMBED_QUERY = None  # tests may set an async callable here


async def embed_query_bounded(q: str, timeout: float | None = None):
    """(vector, None) or (None, reason). Never raises."""
    timeout = EMBED_TIMEOUT_S if timeout is None else timeout
    key = q
    hit = _CACHE.get(key)
    if hit is not None:
        _STATS["cache_hits"] += 1
        return hit, None
    _STATS["cache_misses"] += 1
    task = _CACHE.inflight.get(key)
    if task is None:
        if len(_CACHE.inflight) >= EMBED_INFLIGHT_MAX:
            return None, "embedding_busy"
        try:
            fn = EMBED_QUERY or _embed_fn()
        except Exception as exc:  # noqa: BLE001 — provider not configured
            _STATS["embed_failures"] += 1
            _log(f"embedding unavailable: {exc.__class__.__name__}")
            return None, "embedding_unavailable"
        task = asyncio.ensure_future(fn(q))
        _CACHE.inflight[key] = task

        def _done(t, key=key):
            _CACHE.inflight.pop(key, None)
            if t.cancelled():
                return
            exc = t.exception()
            if exc is None and t.result():
                _CACHE.put(key, t.result())

        task.add_done_callback(_done)
    try:
        vec = await asyncio.wait_for(asyncio.shield(task), timeout)
    except asyncio.TimeoutError:
        _STATS["embed_timeouts"] += 1
        _log("embedding timeout")
        return None, "embedding_timeout"
    except Exception as exc:  # noqa: BLE001
        _STATS["embed_failures"] += 1
        _log(f"embedding failed: {exc.__class__.__name__}")
        return None, "embedding_failed"
    if not vec:
        return None, "embedding_failed"
    return vec, None


# --------------------------------------------------------------------------- #
# Handlers
# --------------------------------------------------------------------------- #
def _public(src: dict, fields: list) -> dict:
    return {f: src.get(f) for f in fields}


async def _mget_sessions(es, keys: list) -> dict:
    if not keys:
        return {}
    data = await _call(es, "POST", f"/{SESSION_INDEX}/_mget?_source="
                       + ",".join(_MGET_SOURCE), mget_body(keys))
    out = {}
    for d in data.get("docs") or []:
        src = d.get("_source") if isinstance(d, dict) and d.get("found") else None
        if isinstance(src, dict) and src.get("purged_at") is None:
            out[d.get("_id")] = src
    return out


async def _hit_counts(es, req: dict, keys: list) -> dict:
    if not keys:
        return {}
    data = await _call(es, "POST", f"/{MESSAGE_INDEX}/_search", hit_count_body(req, keys))
    buckets = ((data.get("aggregations") or {}).get("per_session") or {}).get("buckets") or []
    return {b.get("key"): int(b.get("doc_count") or 0) for b in buckets if isinstance(b, dict)}


async def _recent(es, req: dict, now: datetime) -> list:
    data = await _call(es, "POST", f"/{SESSION_INDEX}/_search", recent_body(req))
    out = []
    for h in (data.get("hits") or {}).get("hits") or []:
        src = h.get("_source") if isinstance(h, dict) else None
        if not isinstance(src, dict) or src.get("purged_at") is not None:
            continue
        row = _public(src, SEARCH_FIELDS)
        row["session_key"] = row["session_key"] or h.get("_id")
        row["score"] = round(recency_nudge(src.get("updated_at"), now), 6)
        row["hit_count"] = 0
        out.append(row)
    return out


async def search(es, body, caller) -> dict:
    t0 = time.monotonic()
    req = parse_request(body)
    now = datetime.now(timezone.utc)
    degraded = None
    if not req["q"]:
        sessions = await _recent(es, req, now)
    else:
        embed_task = None
        if req["mode"] == "hybrid":
            embed_task = asyncio.ensure_future(embed_query_bounded(req["q"]))
        try:
            lex = await _call(es, "POST", f"/{MESSAGE_INDEX}/_search", lexical_body(req))
        except BaseException:
            if embed_task is not None:
                embed_task.cancel()
            raise
        lex_hits = (lex.get("hits") or {}).get("hits") or []
        lex_keys = session_ranks(lex_hits)
        bm25 = {}
        for h in lex_hits:
            sk = (h.get("_source") or {}).get("session_key")
            if sk in lex_keys and sk not in bm25:
                bm25[sk] = float(h.get("_score") or 0.0)
        if embed_task is not None:
            vec, why = await embed_task
            knn_keys = []
            if vec is not None:
                knn = await _call(es, "POST", f"/{MESSAGE_INDEX}/_search", knn_body(req, vec))
                knn_keys = session_ranks((knn.get("hits") or {}).get("hits") or [])
            else:
                degraded = DEGRADED_BM25
            if degraded is None:
                base = scoring.rrf_fuse([lex_keys, knn_keys], k=RRF_K)
                candidates = list(base)
            else:
                base, candidates = bm25, lex_keys
        else:
            base, candidates = bm25, lex_keys
        meta, counts = await asyncio.gather(_mget_sessions(es, candidates),
                                            _hit_counts(es, req, candidates))
        sessions = []
        for sk in candidates:
            src = meta.get(sk)
            if src is None:  # purged or vanished between the two reads
                continue
            row = _public(src, SEARCH_FIELDS)
            row["session_key"] = sk
            # Multiplicative, so recency only reorders sessions of similar
            # relevance: an RRF score is at most ~2/61, smaller than an additive
            # 0.05 nudge, which would let recency outrank relevance in hybrid.
            row["score"] = round(base.get(sk, 0.0) * (1.0 + recency_nudge(src.get("updated_at"), now)), 6)
            row["hit_count"] = counts.get(sk, 0)
            sessions.append(row)
        sessions.sort(key=lambda r: (-r["score"], r["session_key"]))
        sessions = sessions[:req["limit"]]
    out = {"sessions": sessions, "took_ms": int((time.monotonic() - t0) * 1000)}
    if degraded:
        out["degraded"] = degraded
    return out


async def preview(es, session_key: str, q: str, caller) -> dict:
    q = _query_string(q)
    try:
        resp = await es._es.request("GET", f"/{SESSION_INDEX}/_doc/{session_key}")
    except Exception as exc:  # noqa: BLE001
        raise _es_unavailable(f"preview get: {exc.__class__.__name__}") from None
    if resp.status_code == 404:
        raise _not_found()
    if resp.status_code != 200:
        raise _es_unavailable(f"preview get: HTTP {resp.status_code}")
    try:
        doc = resp.json()
    except ValueError:
        raise _es_unavailable("preview get: unparseable response") from None
    src = doc.get("_source") if isinstance(doc, dict) and doc.get("found") else None
    if not isinstance(src, dict) or src.get("purged_at") is not None:
        raise _not_found()
    session = _public(src, PREVIEW_FIELDS)
    session["session_key"] = session_key
    snippets = []
    if q:
        data = await _call(es, "POST", f"/{MESSAGE_INDEX}/_search",
                           preview_match_body(session_key, q))
        for h in (data.get("hits") or {}).get("hits") or []:
            hl = h.get("highlight") or {}
            frags = hl.get("text") or hl.get("tool_text") or []
            if not frags:
                continue
            s = h.get("_source") or {}
            snippets.append({"ts": s.get("ts"), "role": s.get("role"), "fragment": frags[0]})
    else:
        data = await _call(es, "POST", f"/{MESSAGE_INDEX}/_search",
                           preview_recent_body(session_key))
        for h in reversed((data.get("hits") or {}).get("hits") or []):
            s = h.get("_source") or {}
            text = s.get("text")
            if not isinstance(text, str):
                continue
            snippets.append({"ts": s.get("ts"), "role": s.get("role"),
                             "fragment": text[:PREVIEW_RECENT_CHARS]})
    return {"session": session, "snippets": snippets}
