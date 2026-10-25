"""Session search server API (design spec §6.5 C6, §7.2 routes, §7.6 gate).

Mounted by server.py as `Mount("/memory/sessions/v1", sessions_app.app)` AHEAD
of `Mount("/memory", mcp)`, so /memory/mcp is not shadowed.

Gate (decision I). One ASGI wrapper sits in front of every route and runs, in
order:

  1. the proxy shared secret must be configured on this server (otherwise any
     local process could forge the identity headers) and present on the request
     (identity.require_proxy_secret) — 403 / 401;
  2. identity.parse_identity — the X-Verified-* headers the proxy injected;
  3. the fixed ROUTES table: an unlisted (method, path) is 403, whatever its
     shape (`..`, `%2F`, trailing slash and HEAD are all unlisted);
  4. identity.authorize_session_scope against SESSION_SCOPE_POLICY, which also
     yields the caller's host. Unset or malformed policy = deny-all.

The host of a write is NEVER taken from the request body: it comes from step 4,
and a write whose target session belongs to another host is 403 host_mismatch.

Ingest pipeline (§6.5): bounded body read → bounded gzip → C2 re-scan in
detect-only mode with the client's declared ruleset (422 names line indexes and
kinds, never values) → C1 parse → archive chunk (main only) → `_bulk` WITHOUT
refresh → session doc → embedding queued in the background.

`es` handed to sessions_search.search / preview is the es_backend module itself
(its `_es_json`, `_es` client and index constants). `caller` is the dict
{sub, client_id, grant, agent, host, scope}.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import importlib
import importlib.util
import inspect
import io
import json
import os
import re
import sys
import tarfile
import time
import weakref
import zlib

from starlette.requests import Request
from starlette.responses import JSONResponse, Response

import es_backend as be  # attributes are read at call time only (tests stub the module)
import identity
import session_redact
import sessions_archive
import sessions_parse

# sessions_search.py belongs to a separate stream. Missing module = the two
# routes answer 501; a module that exists but fails to import is a real bug and
# propagates.
if importlib.util.find_spec("sessions_search") is not None:
    sessions_search = importlib.import_module("sessions_search")
else:
    sessions_search = None

SCHEMA_SESSION = "session/1"
SCHEMA_MESSAGE = "session-message/1"
SESSION_INDEX = os.environ.get("SESSION_INDEX", "memory-session")
MESSAGE_INDEX = os.environ.get("SESSION_MESSAGE_INDEX", "memory-session-message")
# 1 on personal (3-node cluster), 0 on work (single node) — §7.1.
SESSION_INDEX_REPLICAS = int(os.environ.get("SESSION_INDEX_REPLICAS", "1"))

WIRE_MAX = 8 * 1024 * 1024          # bytes on the wire (§7.2)
DECOMPRESSED_MAX = 5 * 1024 * 1024  # bytes after gunzip (§6.5 step 2)
EMBED_TEXT_CAP = 16 * 1024
EMBED_BATCH = 128

SESSION_ID_RE = sessions_archive.SESSION_ID_RE
SESSION_KEY_RE = sessions_archive.SESSION_KEY_RE
HOST_RE = sessions_archive.HOST_RE
TOOL_RESULT_NAME_RE = sessions_archive.TOOL_RESULT_NAME_RE
PROJECT_DIR_RE = re.compile(r"^[A-Za-z0-9-]{1,255}$")
AGENT_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,128}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")

SCOPE_INGEST = "sessions:ingest"
SCOPE_READ = "sessions:read"
SCOPE_PURGE = "sessions:purge"

# The fixed route -> scope table. Anything not here is 403.
ROUTES = {
    ("POST", "/ingest"): SCOPE_INGEST,
    ("POST", "/blob"): SCOPE_INGEST,
    ("POST", "/state"): SCOPE_INGEST,
    ("POST", "/search"): SCOPE_READ,
    ("GET", "/preview"): SCOPE_READ,
    ("GET", "/archive"): SCOPE_READ,
    ("GET", "/archive/tool-results"): SCOPE_READ,
    ("DELETE", "/session"): SCOPE_PURGE,
    ("DELETE", "/purged"): SCOPE_PURGE,
    ("GET", "/status"): SCOPE_READ,
}

# Readiness: the session indices must exist with the expected _meta.schema.
# Until then every route except /status answers 503, and the MCP server under
# /memory keeps serving (a missing grant on the work ES must not take recall
# down with it).
_STATE = {"ready": False, "error": "starting", "started": False}
# In-process counters surfaced by /status (§8 row 4).
_COUNTERS = {"unknown_types": {}, "rejected_lines": 0, "ingested_segments": 0}
_BG_TASKS: set = set()


def _log(msg: str) -> None:
    print(f"SESSIONS {msg}", file=sys.stderr, flush=True)


def _now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _err(status: int, code: str, **extra) -> JSONResponse:
    return JSONResponse({"error": code, **extra}, status_code=status)


class HTTPError(Exception):
    def __init__(self, status: int, code: str, **extra):
        super().__init__(code)
        self.status = status
        self.code = code
        self.extra = extra


def make_session_key(host: str, project_dir: str, session_id: str) -> str:
    """Opaque, server-issued (§6.5): sk_ + base32(sha256(host\\0dir\\0sid)[:20])."""
    raw = hashlib.sha256(f"{host}\0{project_dir}\0{session_id}".encode("utf-8")).digest()[:20]
    return "sk_" + base64.b32encode(raw).decode("ascii").lower()


# --------------------------------------------------------------------------- #
# Index definitions (§7.1). Mirrors files/es-indices-v2/memory-session*.json;
# test_sessions_app.py asserts they stay identical.
# --------------------------------------------------------------------------- #
def index_definitions(analysis=None, replicas: int | None = None) -> dict:
    analysis = be._ANALYSIS if analysis is None else analysis
    kw = {"type": "keyword"}
    session = {
        "settings": {"number_of_shards": 1, "codec": "best_compression", "analysis": analysis},
        "mappings": {
            "dynamic": "strict",
            "_meta": {"schema": SCHEMA_SESSION},
            "properties": {
                "session_key": kw, "session_id": kw, "host": kw, "project_dir": kw,
                "jsonl_path": {"type": "keyword", "index": False},
                "cwd": kw, "cwd_candidates": kw, "resume_cwd": kw,
                "resume_cwd_verified": {"type": "boolean"},
                "title": {"type": "text", "analyzer": "ja_en_hybrid",
                          "fields": {"raw": {"type": "keyword", "ignore_above": 256}}},
                "title_source": kw, "git_branch": kw, "entrypoint": kw,
                "interactive": {"type": "boolean"}, "cc_version": kw,
                "started_at": {"type": "date"}, "updated_at": {"type": "date"},
                "message_count": {"type": "integer"}, "text_message_count": {"type": "integer"},
                "has_subagents": {"type": "boolean"}, "jsonl_exists": {"type": "boolean"},
                "jsonl_checked_at": {"type": "date"}, "archived": {"type": "boolean"},
                "archive_complete": {"type": "boolean"},
                "archive_generation": {"type": "integer"}, "archive_bytes": {"type": "long"},
                "archive_chunks": {"type": "object", "enabled": False},
                "restored_from": kw, "redact_version": kw, "parser_version": kw,
                # purge tombstone (the only fields a purged session keeps)
                "purged_at": {"type": "date"}, "purged_by": kw,
            },
        },
    }
    message = {
        "settings": {"number_of_shards": 1, "codec": "best_compression",
                     "refresh_interval": "1s", "analysis": analysis},
        "mappings": {
            "dynamic": "strict",
            "_meta": {"schema": SCHEMA_MESSAGE},
            "_source": {"excludes": ["embedding"]},
            "properties": {
                "session_key": kw, "session_id": kw, "host": kw, "cwd": kw,
                "interactive": {"type": "boolean"}, "uuid": kw, "parent_uuid": kw,
                "message_id": kw, "role": kw, "ts": {"type": "date"},
                "is_sidechain": {"type": "boolean"}, "agent_id": kw,
                "text": {"type": "text", "analyzer": "ja_en_hybrid"},
                "tool_text": {"type": "text", "analyzer": "ja_en_hybrid"},
                "tool_names": kw,
                "embedding": {"type": "dense_vector", "dims": 1024, "similarity": "cosine",
                              "index_options": {"type": "int8_hnsw"}},
                "embedding_status": kw, "line_offset": {"type": "long"}, "redact_version": kw,
            },
        },
    }
    if replicas is not None:
        session["settings"]["number_of_replicas"] = replicas
        message["settings"]["number_of_replicas"] = replicas
    return {SESSION_INDEX: (session, SCHEMA_SESSION), MESSAGE_INDEX: (message, SCHEMA_MESSAGE)}


class SchemaMismatch(Exception):
    pass


async def ensure_session_indices() -> None:
    """Create both indices when missing (403-tolerant like es_backend.
    ensure_indices) and check `_meta.schema` (§8 row 11). Raises on failure."""
    async with be._make_client() as client:
        for name, (body, schema) in index_definitions(replicas=SESSION_INDEX_REPLICAS).items():
            resp = await client.request("PUT", f"/{name}", json=body)
            ok = resp.status_code in (200, 201) or (
                resp.status_code == 400 and "resource_already_exists_exception" in resp.text) or (
                resp.status_code == 403 and await be._index_exists(client, name))
            if not ok:
                raise RuntimeError(f"create {name}: HTTP {resp.status_code}")
            m = await client.request("GET", f"/{name}/_mapping")
            if m.status_code != 200:
                raise RuntimeError(f"mapping {name}: HTTP {m.status_code}")
            got = None
            for v in (m.json() or {}).values():
                got = ((v.get("mappings") or {}).get("_meta") or {}).get("schema")
                break
            if got != schema:
                raise SchemaMismatch(f"{name}: _meta.schema={got!r}, expected {schema!r}")


async def _startup_loop(delay: float = 30.0) -> None:
    attempt = 0
    while True:
        attempt += 1
        try:
            await ensure_session_indices()
            _STATE.update(ready=True, error="")
            _log("indices ready")
            return
        except Exception as exc:  # noqa: BLE001 — retried forever, logged every time
            _STATE.update(ready=False, error=f"{exc.__class__.__name__}: {exc}"[:300])
            _log(f"indices not ready attempt={attempt} error={_STATE['error']}")
        await asyncio.sleep(min(delay * attempt, 300.0))


def start_background() -> None:
    """Called from server.py's lifespan. Never blocks startup."""
    if _STATE["started"]:
        return
    _STATE["started"] = True
    for line in identity.session_scope_policy_lines():
        print(line, file=sys.stderr, flush=True)
    if not identity.proxy_secret_configured():
        _log("gate refuses every request: PROXY_SHARED_SECRET is not set")
    _spawn(_startup_loop())


def _spawn(coro):
    task = asyncio.get_running_loop().create_task(coro)
    _BG_TASKS.add(task)
    task.add_done_callback(_BG_TASKS.discard)
    return task


# --------------------------------------------------------------------------- #
# ES helpers (status-aware; es_backend._es_json raises on every 4xx)
# --------------------------------------------------------------------------- #
class ESUnavailable(Exception):
    pass


async def _es(method: str, path: str, **kw):
    try:
        return await be._es.request(method, path, **kw)
    except Exception as exc:  # noqa: BLE001 — transport errors become 503
        raise ESUnavailable(exc.__class__.__name__) from exc


async def _get_session(session_key: str):
    """(source, seq_no, primary_term) or None."""
    r = await _es("GET", f"/{SESSION_INDEX}/_doc/{session_key}")
    if r.status_code == 404:
        return None
    if r.status_code != 200:
        raise ESUnavailable(f"get session: {r.status_code}")
    # Fail closed: an unparseable or malformed answer is "unknown", never
    # "not purged" (every caller turns ESUnavailable into 503).
    try:
        data = r.json()
    except ValueError:
        raise ESUnavailable("get session: unparseable response") from None
    if not isinstance(data, dict):
        raise ESUnavailable("get session: malformed response")
    if not data.get("found"):
        return None
    src, seq, term = data.get("_source"), data.get("_seq_no"), data.get("_primary_term")
    if not isinstance(src, dict) or not isinstance(seq, int) or not isinstance(term, int):
        raise ESUnavailable("get session: malformed response")
    return src, seq, term


class _Conflict(Exception):
    """A conditional session-doc write lost: the doc changed (or appeared)
    since the writer read it."""


async def _put_session(session_key: str, doc: dict, seq=None, term=None) -> None:
    """Never unconditional: with (seq, term) it is `if_seq_no/if_primary_term`,
    without them it is `_create` (fails if the doc exists). Either way a purge
    that flipped the doc in between makes this raise _Conflict."""
    if seq is not None and term is not None:
        path = f"/{SESSION_INDEX}/_doc/{session_key}?if_seq_no={seq}&if_primary_term={term}"
    else:
        path = f"/{SESSION_INDEX}/_create/{session_key}"
    r = await _es("PUT", path, json=doc)
    if r.status_code == 409:
        raise _Conflict()
    if r.status_code >= 400:
        raise ESUnavailable(f"put session: {r.status_code}")


async def _update_session(session_key: str, partial: dict, upsert: dict | None = None) -> int:
    body = {"doc": partial}
    if upsert is not None:
        body["upsert"] = upsert
    r = await _es("POST", f"/{SESSION_INDEX}/_update/{session_key}?retry_on_conflict=3", json=body)
    if r.status_code >= 400 and r.status_code != 404:
        raise ESUnavailable(f"update session: {r.status_code}")
    return r.status_code


async def _bulk_index(index: str, docs: list[dict]) -> int:
    """`_bulk` WITHOUT refresh (§6.5 step 5): the 1 s refresh interval is fast
    enough for a picker. es_backend._bulk_index forces refresh=true, so it is
    not reused here. Docs keep their `_id` key; it becomes the action id."""
    if not docs:
        return 0
    lines = []
    for d in docs:
        lines.append(json.dumps({"index": {"_index": index, "_id": d["_id"]}}))
        lines.append(json.dumps({k: v for k, v in d.items() if not k.startswith("_")}))
    r = await _es("POST", "/_bulk", content="\n".join(lines) + "\n",
                  headers={"Content-Type": "application/x-ndjson"})
    if r.status_code >= 400:
        raise ESUnavailable(f"bulk: {r.status_code}")
    res = r.json()
    if res.get("errors"):
        bad = [i for i in res.get("items", []) if (i.get("index") or {}).get("error")]
        types = sorted({(i["index"]["error"] or {}).get("type", "?") for i in bad})
        _log(f"bulk errors index={index} count={len(bad)} types={','.join(types)}")
        raise ESUnavailable("bulk had errors")
    # Remember each doc's _seq_no/_primary_term: the embedding update is
    # conditional on them, so it can never re-create or overwrite a doc that a
    # purge or a newer ingest replaced in the meantime.
    for d, item in zip(docs, res.get("items", [])):
        meta = item.get("index") or {}
        d["_seq_no"] = meta.get("_seq_no")
        d["_primary_term"] = meta.get("_primary_term")
    return len(docs)


async def _bulk_embed_updates(updates: list) -> dict:
    """Conditional partial updates [(doc_id, seq_no, primary_term, vector)].
    `_update` on a missing doc fails (no upsert) and a changed doc fails the
    seq_no check; both are dropped, never retried here. Returns counts."""
    lines = []
    for doc_id, seq, term, vec in updates:
        lines.append(json.dumps({"update": {"_index": MESSAGE_INDEX, "_id": doc_id,
                                            "if_seq_no": seq, "if_primary_term": term}}))
        lines.append(json.dumps({"doc": {"embedding": vec, "embedding_status": "done"}}))
    r = await _es("POST", "/_bulk", content="\n".join(lines) + "\n",
                  headers={"Content-Type": "application/x-ndjson"})
    if r.status_code >= 400:
        raise ESUnavailable(f"bulk update: {r.status_code}")
    out = {"updated": 0, "dropped": 0, "failed": 0}
    for item in r.json().get("items", []):
        meta = item.get("update") or {}
        err = meta.get("error")
        if not err:
            out["updated"] += 1
        elif meta.get("status") in (404, 409):
            out["dropped"] += 1
        else:
            out["failed"] += 1
    return out


# --------------------------------------------------------------------------- #
# Purge (security review: a purge must not be undone by work in flight)
# --------------------------------------------------------------------------- #
# Three layers, so that no check-then-write window survives:
#
# 1. The session doc IS the tombstone. DELETE /session first flips it, with a
#    seq-guarded write, to a purged form ({session_key, host, purged_at,
#    purged_by} only — nothing transcript-derived survives; C8 deletes the
#    marker 30 days after purged_at; mapped fields
#    only); only then are messages and objects deleted. The doc stays purged
#    until the operator clears it (DELETE /purged); ingest answers 409 purged.
# 2. Every writer read the session doc's _seq_no/_primary_term before writing,
#    and its own session-doc write is conditional on them (or `_create` for a
#    new session). A purge that flipped the doc in between makes that write
#    fail; the writer then re-reads, sees "purged", and DISCARDS what it wrote
#    (its message docs by id, its archive object). The embedding update is a
#    seq-guarded `_update` without upsert, so it cannot re-create a doc either.
# 3. Object storage cannot be conditional on ES, so every archive / blob PUT is
#    write-then-verify: the session doc is re-read after the PUT and the object
#    is deleted again when the session is purged. Purge deletes the whole
#    prefix; a straggler from a writer that died between PUT and verify is
#    removed by C8's daily re-sweep of purged sessions (bound: one day).
#
# Within one process a per-session asyncio lock also serializes ingest, blob,
# state and purge for the same key, so layers 2 and 3 only ever fire across
# processes or restarts.
_PURGED: set = set()
_LOCKS: "weakref.WeakValueDictionary" = weakref.WeakValueDictionary()


def _session_lock(session_key: str) -> asyncio.Lock:
    key = (id(asyncio.get_running_loop()), session_key)
    lock = _LOCKS.get(key)
    if lock is None:
        lock = asyncio.Lock()
        _LOCKS[key] = lock
    return lock


def _is_purged_doc(src) -> bool:
    return isinstance(src, dict) and src.get("purged_at") is not None


async def _purged_now(session_key: str, expect_exists: bool = True) -> bool:
    """Authoritative re-read (no cache): used after every object PUT and after
    a lost conditional write. Raises ESUnavailable when the state cannot be
    established — including a session doc that is missing although the writer
    read it earlier (expect_exists) — so callers fail closed."""
    got = await _get_session(session_key)
    if got is None:
        if expect_exists:
            raise ESUnavailable("session doc vanished during a write")
        return False
    if _is_purged_doc(got[0]):
        _PURGED.add(session_key)
        return True
    return False


def _refuse_purged_doc(session_key: str, src) -> None:
    if session_key in _PURGED or _is_purged_doc(src):
        if _is_purged_doc(src):
            _PURGED.add(session_key)
        raise HTTPError(409, "purged")


async def _delete_object_quietly(backend, session_key: str, name: str) -> None:
    try:
        await backend.delete(name)
    except sessions_archive.ArchiveError:
        _log(f"straggler object left for C8 session={session_key}")


async def _put_object_verified(backend, session_key: str, name: str, data: bytes,
                               expect_exists: bool = True) -> None:
    """Write-then-verify (layer 3). Purged -> delete the object, 409. The
    purge state cannot be read -> delete the object too, 503 (fail closed)."""
    try:
        await backend.put(name, data)
    except sessions_archive.ArchiveError:
        raise HTTPError(503, "archive_unavailable") from None
    try:
        purged = await _purged_now(session_key, expect_exists)
    except ESUnavailable:
        await _delete_object_quietly(backend, session_key, name)
        raise HTTPError(503, "es_unavailable") from None
    if purged:
        await _delete_object_quietly(backend, session_key, name)
        raise HTTPError(409, "purged")


async def _discard_quietly(discard, session_key: str) -> None:
    try:
        await discard()
    except (ESUnavailable, sessions_archive.ArchiveError):
        _log(f"discard incomplete, left for C8 session={session_key}")


async def _guarded_put_session(session_key: str, doc: dict, seq, term, discard) -> None:
    """Layer 2: the writer's conditional session write. Lost to a purge ->
    discard this writer's own writes, 409. Lost to anything else -> 503 busy
    (the writes are idempotent and the client retries). The write or the
    follow-up read failing -> discard as well and 503: an unknown state is
    treated like a purge, never as success."""
    try:
        await _put_session(session_key, doc, seq, term)
        return
    except _Conflict:
        pass
    except ESUnavailable:
        await _discard_quietly(discard, session_key)
        raise HTTPError(503, "es_unavailable") from None
    try:
        purged = await _purged_now(session_key, expect_exists=seq is not None)
    except ESUnavailable:
        await _discard_quietly(discard, session_key)
        raise HTTPError(503, "es_unavailable") from None
    if purged:
        await _discard_quietly(discard, session_key)
        raise HTTPError(409, "purged")
    raise HTTPError(503, "busy")


async def _delete_message_ids(ids: list) -> None:
    if not ids:
        return
    lines = [json.dumps({"delete": {"_index": MESSAGE_INDEX, "_id": i}}) for i in ids]
    r = await _es("POST", "/_bulk", content="\n".join(lines) + "\n",
                  headers={"Content-Type": "application/x-ndjson"})
    if r.status_code >= 400:
        raise ESUnavailable(f"bulk delete: {r.status_code}")


def _purged_form(src: dict, purged_by: str) -> dict:
    """The tombstone keeps nothing derived from the transcript: no title,
    cwd, paths, branch or chunk list — only what is needed to refuse writes,
    check the host, and let C8 expire the marker after 30 days."""
    return {"session_key": src["session_key"], "host": src["host"],
            "purged_at": _now_iso(), "purged_by": purged_by}


async def _flip_purged(session_key: str, purged_by: str = "") -> dict:
    """Layer 1: seq-guarded flip of the session doc to its purged form.
    Retries a lost race against a writer (which then sees the new seq and
    fails its own conditional write). Returns the purged doc."""
    for _ in range(10):
        got = await _get_session(session_key)
        if got is None:
            raise HTTPError(404, "not_found")
        src, seq, term = got
        if _is_purged_doc(src):
            _PURGED.add(session_key)
            return src
        purged = _purged_form(src, purged_by)
        try:
            await _put_session(session_key, purged, seq, term)
        except _Conflict:
            continue
        _PURGED.add(session_key)
        return purged
    raise HTTPError(503, "busy")


async def _delete_messages(session_key: str, agent_id: str | None = None,
                           main_only: bool = False) -> int:
    """Delete a session's message docs: all of them, one subagent's
    (agent_id), or only the main file's (main_only: is_sidechain false)."""
    filters = [{"term": {"session_key": session_key}}]
    if agent_id is not None:
        filters.append({"term": {"agent_id": agent_id}})
    elif main_only:
        filters.append({"term": {"is_sidechain": False}})
    r = await _es("POST", f"/{MESSAGE_INDEX}/_delete_by_query?conflicts=proceed",
                  json={"query": {"bool": {"filter": filters}}})
    if r.status_code >= 400:
        raise ESUnavailable(f"delete_by_query: {r.status_code}")
    return int(r.json().get("deleted", 0))


async def _count(index: str, query: dict | None = None) -> int | None:
    r = await _es("POST", f"/{index}/_count", json={"query": query or {"match_all": {}}})
    if r.status_code != 200:
        return None
    return int(r.json().get("count", 0))


# --------------------------------------------------------------------------- #
# Body handling (bounded)
# --------------------------------------------------------------------------- #
async def _read_body(request: Request) -> bytes:
    cl = request.headers.get("content-length")
    if cl is not None:
        try:
            if int(cl) > WIRE_MAX:
                raise HTTPError(413, "too_large")
        except ValueError:
            raise HTTPError(400, "bad_content_length") from None
    buf = bytearray()
    async for chunk in request.stream():
        buf += chunk
        if len(buf) > WIRE_MAX:
            raise HTTPError(413, "too_large")
    return bytes(buf)


def _gunzip_bounded(data: bytes, limit: int = DECOMPRESSED_MAX) -> bytes:
    d = zlib.decompressobj(16 + zlib.MAX_WBITS)
    try:
        out = d.decompress(data, limit + 1)
    except zlib.error:
        raise HTTPError(400, "bad_gzip") from None
    if len(out) > limit or d.unconsumed_tail:
        raise HTTPError(413, "too_large")
    if not d.eof:
        raise HTTPError(400, "bad_gzip")
    return out


async def _json_body(request: Request) -> dict:
    raw = await _read_body(request)
    if raw[:2] == b"\x1f\x8b":
        raw = _gunzip_bounded(raw)
    elif len(raw) > DECOMPRESSED_MAX:
        raise HTTPError(413, "too_large")
    try:
        body = json.loads(raw)
    except (ValueError, RecursionError):  # RecursionError: a hostile nesting depth
        raise HTTPError(400, "bad_json") from None
    if not isinstance(body, dict):
        raise HTTPError(400, "bad_json")
    return body


def _int(v, name, minimum=0):
    if not isinstance(v, int) or isinstance(v, bool) or v < minimum:
        raise HTTPError(400, "invalid_request", field=name)
    return v


def _str(v, name, regex=None, maxlen=4096):
    if not isinstance(v, str) or not v or len(v) > maxlen or (regex and not regex.fullmatch(v)):
        raise HTTPError(400, "invalid_request", field=name)
    return v


def _session_key_param(v) -> str:
    if not isinstance(v, str) or not SESSION_KEY_RE.fullmatch(v):
        raise HTTPError(400, "invalid_session_key")
    return v


def _require_host(caller) -> str:
    if not caller.get("host"):
        raise HTTPError(403, "host_mismatch")
    return caller["host"]


async def _owned_session(session_key: str, caller, *, allow_hostless=False):
    got = await _get_session(session_key)
    if got is None:
        raise HTTPError(404, "not_found")
    src = got[0]
    if caller.get("host") is None and allow_hostless:
        return got
    if src.get("host") != _require_host(caller):
        raise HTTPError(403, "host_mismatch")
    return got


# --------------------------------------------------------------------------- #
# Strict line handling + CPU budget (security review of the first revision)
# --------------------------------------------------------------------------- #
# Invariant: the bytes written to the archive and the record handed to the
# parser are both derived from EXACTLY the object the detector scanned. A raw
# line is never archived. Each line is loaded strictly (no duplicate keys, no
# NaN/Infinity, no lone surrogates, bounded depth, an object at top level) and
# re-serialised canonically; whatever cannot round-trip is rejected per line
# with 422 so the client tombstones it instead of stalling the file.
SEGMENT_BUDGET_S = float(os.environ.get("SESSION_SEGMENT_BUDGET_S", "2.0"))
SEGMENT_CONCURRENCY = 2
MAX_RECORD_DEPTH = 64
# Per-segment totals, so per-value caps cannot be defeated by volume. Over any
# of them the whole segment is refused (413; the client halves it) — never
# partially accepted. Total characters are bounded by DECOMPRESSED_MAX.
SEGMENT_MAX_LINES = 50_000
SEGMENT_MAX_STRINGS = 200_000
BLOB_MAX_CHARS = DECOMPRESSED_MAX
ARCHIVE_DOWNLOAD_MAX = 512 * 1024 * 1024
TOOL_RESULTS_MAX_BYTES = 256 * 1024 * 1024
TOOL_RESULTS_MAX_FILES = 1000
_SURROGATE_RE = re.compile("[\ud800-\udfff]")
_PRINTABLE_PATH_RE = re.compile("[^\x00-\x1f\x7f\ud800-\udfff]{1,4096}")


class _OverBudget(Exception):
    def __init__(self, code="too_expensive"):
        super().__init__(code)
        self.code = code


class _BadLine(ValueError):
    def __init__(self, kind):
        super().__init__(kind)
        self.kind = kind


def _no_duplicate_keys(pairs):
    out = {}
    for k, v in pairs:
        if k in out:
            raise _BadLine("duplicate-key")
        out[k] = v
    return out


def _reject_constant(name):
    raise _BadLine("non-finite-number")


def strict_load(line: str):
    """Parse one JSONL line strictly. Returns (record, number of strings —
    keys and values) or raises _BadLine."""
    try:
        rec = json.loads(line, object_pairs_hook=_no_duplicate_keys,
                         parse_constant=_reject_constant)
    except _BadLine:
        raise
    except (ValueError, RecursionError):
        raise _BadLine("invalid-json") from None
    if not isinstance(rec, dict):
        raise _BadLine("not-an-object")
    stack = [(rec, 1)]
    strings = 0
    while stack:
        v, depth = stack.pop()
        if depth > MAX_RECORD_DEPTH:
            raise _BadLine("too-deep")
        if isinstance(v, dict):
            for k, cv in v.items():
                strings += 1
                if _SURROGATE_RE.search(k):
                    raise _BadLine("surrogate")
                stack.append((cv, depth + 1))
        elif isinstance(v, list):
            stack.extend((cv, depth + 1) for cv in v)
        elif isinstance(v, str):
            strings += 1
            if _SURROGATE_RE.search(v):
                raise _BadLine("surrogate")
    return rec, strings


def canonical_line(rec) -> str:
    """Compact JSON, UTF-8, control characters escaped (json.dumps always
    escapes them), and U+2028/U+2029 escaped too so no reader that splits on
    Unicode line boundaries sees a different line structure."""
    try:
        out = json.dumps(rec, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
    except (ValueError, RecursionError):
        raise _BadLine("invalid-json") from None
    return out.replace("\u2028", "\\u2028").replace("\u2029", "\\u2029")


def _scan_segment(lines: list, version: str, deadline: float | None = None) -> dict:
    """CPU-bound part of the ingest: strict load, C2 detect, canonicalise.
    Runs in a worker thread. Checks the deadline between lines; every single
    regex call inside is bounded by session_redact's caps."""
    bad, kinds, canonical = [], set(), []
    secret = False
    if len(lines) > SEGMENT_MAX_LINES:
        raise _OverBudget("too_many_lines")
    strings = 0

    def check_deadline():
        if deadline is not None and time.monotonic() > deadline:
            raise _OverBudget()

    # Pass 1: strict load of every line and the segment totals, BEFORE any
    # regex runs (json.loads and the walk are linear C/Python work).
    loaded = []
    for i, line in enumerate(lines):
        check_deadline()
        try:
            rec, n = strict_load(line)
        except _BadLine as exc:
            loaded.append(exc)
            continue
        strings += n
        if strings > SEGMENT_MAX_STRINGS:
            raise _OverBudget("too_many_values")
        loaded.append(rec)
    # Pass 2: detect + canonicalise.
    for i, rec in enumerate(loaded):
        check_deadline()
        try:
            if isinstance(rec, _BadLine):
                raise rec
            hit = session_redact.detect_record(rec, version, _check=check_deadline)
            if hit:
                bad.append(i)
                kinds.update(hit)
                secret = True
                continue
            canonical.append(canonical_line(rec))
        except _BadLine as exc:
            bad.append(i)
            kinds.add(exc.kind)
    return {"bad_lines": bad, "kinds": sorted(kinds), "canonical": canonical,
            "error": "unmasked_secret" if secret else "invalid_line"}


SEGMENT_MAX_WAITERS = 4
SEGMENT_WAIT_S = 10.0
SEGMENT_PER_CALLER = 1


class _Slots:
    """Bounded admission for the CPU-bound worker jobs: `size` running at
    once, at most `max_waiters` queued (more = 503 busy, never an unbounded
    queue), a bounded wait, and at most `per_caller` running-or-waiting jobs
    per identity, so one client cannot hold every slot."""

    def __init__(self, size, max_waiters, per_caller, wait_s):
        self.size, self.max_waiters, self.per_caller, self.wait_s = size, max_waiters, per_caller, wait_s
        self.active = 0
        self.waiters = 0
        self.by_caller: dict = {}
        self.cond = asyncio.Condition()

    def hold(self, caller_key):
        return _SlotHold(self, caller_key)


class _SlotHold:
    def __init__(self, slots, caller_key):
        self.s, self.k = slots, caller_key

    async def __aenter__(self):
        s = self.s
        if s.by_caller.get(self.k, 0) >= s.per_caller:
            raise HTTPError(503, "busy", reason="caller_concurrency")
        s.by_caller[self.k] = s.by_caller.get(self.k, 0) + 1
        try:
            async with s.cond:
                if s.active >= s.size:
                    if s.waiters >= s.max_waiters:
                        raise HTTPError(503, "busy", reason="queue_full")
                    s.waiters += 1
                    try:
                        await asyncio.wait_for(s.cond.wait_for(lambda: s.active < s.size), s.wait_s)
                    except asyncio.TimeoutError:
                        raise HTTPError(503, "busy", reason="wait_timeout") from None
                    finally:
                        s.waiters -= 1
                s.active += 1
        except BaseException:
            self._release_caller()
            raise
        return self

    async def __aexit__(self, *exc):
        s = self.s
        async with s.cond:
            s.active -= 1
            s.cond.notify()
        self._release_caller()
        return False

    def _release_caller(self):
        n = self.s.by_caller.get(self.k, 1) - 1
        if n <= 0:
            self.s.by_caller.pop(self.k, None)
        else:
            self.s.by_caller[self.k] = n


_SLOTS: dict = {}


def _caller_key(caller) -> str:
    c = caller or {}
    return f"{c.get('grant', '')}|{c.get('client_id', '')}|{c.get('sub', '')}"


def _segment_slot(caller):
    loop = asyncio.get_running_loop()
    slots = _SLOTS.get(loop)
    if slots is None:
        slots = _SLOTS[loop] = _Slots(SEGMENT_CONCURRENCY, SEGMENT_MAX_WAITERS,
                                      SEGMENT_PER_CALLER, SEGMENT_WAIT_S)
    return slots.hold(_caller_key(caller))


async def _run_bounded(fn, *args, **kw):
    """Run fn in a worker thread with a wall-clock budget. Functions that take
    a `deadline` keyword get it and stop themselves; for the rest the wait is
    abandoned (their work is linear and capped). Over budget = 413, which the
    client answers by halving the segment."""
    budget = SEGMENT_BUDGET_S
    if fn is _scan_segment:
        kw["deadline"] = time.monotonic() + budget
    try:
        return await asyncio.wait_for(asyncio.to_thread(fn, *args, **kw), timeout=budget + 1.0)
    except _OverBudget as exc:
        _log(f"segment refused fn={fn.__name__} reason={exc.code} budget_s={budget}")
        raise HTTPError(413, exc.code) from None
    except asyncio.TimeoutError:
        _log(f"segment over budget fn={fn.__name__} budget_s={budget}")
        raise HTTPError(413, "too_expensive") from None


def _segment_chunks(chunks):
    """The main file's archive chunks (no blobs, no subagent cursors)."""
    return [c for c in chunks or [] if "name" not in c and "agent_id" not in c]


def _stream_chunks(chunks, agent_id):
    """Cursor entries of one stream: the main file (agent_id None) or one
    subagent. Subagent entries are cursor bookkeeping only, never archived."""
    if agent_id is None:
        return _segment_chunks(chunks)
    return [c for c in chunks or [] if "name" not in c and c.get("agent_id") == agent_id]


def _blob_entries(chunks):
    return [c for c in chunks or [] if "name" in c]


# --------------------------------------------------------------------------- #
# Embedding queue (§6.5 "Embedding")
# --------------------------------------------------------------------------- #
_EMBED_LOCK = None
# Bounded: at most EMBED_QUEUE_MAX_DOCS docs queued or in flight. Beyond that a
# batch is not queued at all; its docs simply stay embedding_status=pending,
# which C8 retries (§6.5, §8 row 10).
EMBED_QUEUE_MAX_DOCS = 5000
_EMBED_STATE = {"queued": 0, "dropped": 0}


async def _embed_docs(docs: list[dict]) -> None:
    """Embed text docs in batches of 128 and attach the vector with a
    conditional `_update` (see _bulk_embed_updates). Docs of a purged session
    are skipped before and after the provider call. A failed batch keeps
    embedding_status=pending for C8 to retry."""
    global _EMBED_LOCK
    if _EMBED_LOCK is None:
        _EMBED_LOCK = asyncio.Lock()
    async with _EMBED_LOCK:
        try:
            import voyage  # noqa: PLC0415 — lazy: reads VOYAGE_API_KEY at import
        except Exception as exc:  # noqa: BLE001
            _log(f"embedding unavailable: {exc.__class__.__name__}")
            return
        for i in range(0, len(docs), EMBED_BATCH):
            batch = [d for d in docs[i:i + EMBED_BATCH]
                     if d["session_key"] not in _PURGED and d.get("_seq_no") is not None]
            if not batch:
                continue
            texts = [sessions_parse._cap_bytes(d["text"], EMBED_TEXT_CAP) for d in batch]
            try:
                vecs = await voyage.embed_documents(texts)
                updates = [(d["_id"], d["_seq_no"], d["_primary_term"], v)
                           for d, v in zip(batch, vecs) if d["session_key"] not in _PURGED]
                if updates:
                    res = await _bulk_embed_updates(updates)
                    if res["dropped"] or res["failed"]:
                        _log(f"embedding updates dropped={res['dropped']} failed={res['failed']}")
            except Exception as exc:  # noqa: BLE001 — stays pending
                _log(f"embedding batch failed size={len(batch)} error={exc.__class__.__name__}")


async def _embed_and_release(docs: list[dict]) -> None:
    try:
        await _embed_docs(docs)
    finally:
        _EMBED_STATE["queued"] -= len(docs)


def _schedule_embedding(docs: list[dict]) -> None:
    """Indirection so the tests can capture the queued docs."""
    if not docs:
        return
    if _EMBED_STATE["queued"] + len(docs) > EMBED_QUEUE_MAX_DOCS:
        _EMBED_STATE["dropped"] += len(docs)
        _log(f"embedding queue full: {len(docs)} docs left pending")
        return
    _EMBED_STATE["queued"] += len(docs)
    _spawn(_embed_and_release(docs))


EMBED_SCHEDULER = _schedule_embedding


def _archive_backend():
    """The configured archive backend (None = archive disabled). Read lazily
    so a bad configuration shows on the request, not at import."""
    if "backend" not in _ARCHIVE:
        try:
            _ARCHIVE["backend"] = sessions_archive.backend_from_env()
        except ValueError as exc:
            _log(f"archive misconfigured: {exc}")
            _ARCHIVE["backend"] = _MISCONFIGURED
    b = _ARCHIVE["backend"]
    if b is _MISCONFIGURED:
        raise HTTPError(503, "archive_unavailable")
    return b


_ARCHIVE: dict = {}
_MISCONFIGURED = object()


# --------------------------------------------------------------------------- #
# Routes
# --------------------------------------------------------------------------- #
async def ingest(request: Request, caller: dict):
    body = await _json_body(request)
    client = body.get("client") if isinstance(body.get("client"), dict) else None
    f = body.get("file") if isinstance(body.get("file"), dict) else None
    seg = body.get("segment") if isinstance(body.get("segment"), dict) else None
    if client is None or f is None or seg is None:
        raise HTTPError(400, "invalid_request", field="client/file/segment")
    host = _require_host(caller)
    # Step 1: the body's host must be the authenticated one.
    if client.get("host") != host:
        raise HTTPError(403, "host_mismatch")
    version = client.get("redact_version")
    if version not in session_redact.SUPPORTED_VERSIONS:
        raise HTTPError(400, "unsupported_redact_version")
    session_id = _str(f.get("session_id"), "file.session_id", SESSION_ID_RE)
    project_dir = _str(f.get("project_dir"), "file.project_dir", PROJECT_DIR_RE)
    jsonl_path = _str(f.get("jsonl_path"), "file.jsonl_path")
    kind = f.get("kind")
    if kind not in ("main", "subagent"):
        raise HTTPError(400, "invalid_request", field="file.kind")
    agent_id = None
    if kind == "subagent":
        # Client contract (S3): a subagent file carries the PARENT's session id
        # in both session_id and parent_session_id, plus its own agent_id. Its
        # messages go into the parent's session (is_sidechain, agent_id); it is
        # never archived, and its cursor is tracked separately per agent_id.
        agent_id = _str(f.get("agent_id"), "file.agent_id", AGENT_ID_RE)
        parent_sid = _str(f.get("parent_session_id"), "file.parent_session_id", SESSION_ID_RE)
        if parent_sid != session_id:
            raise HTTPError(400, "invalid_request", field="file.parent_session_id")
    generation = _int(seg.get("generation"), "segment.generation")
    offset = _int(seg.get("offset"), "segment.offset")
    end_offset = _int(seg.get("end_offset"), "segment.end_offset", offset + 1)
    seg_sha = _str(seg.get("sha256"), "segment.sha256", SHA256_RE)
    lines = seg.get("lines")
    if not isinstance(lines, list) or not lines or not all(isinstance(x, str) for x in lines):
        raise HTTPError(400, "invalid_request", field="segment.lines")

    session_key = make_session_key(host, project_dir, session_id)
    # The whole write phase runs under the session's lock, so a concurrent
    # DELETE /session in this process either waits for it (and then deletes what
    # it wrote) or has already flipped the session doc, which refuses it here.
    # Across processes the conditional session write below decides.
    async with _session_lock(session_key):
        if session_key in _PURGED:
            raise HTTPError(409, "purged")
        # Step 3: strict load + re-scan, off the event loop, under a deadline.
        async with _segment_slot(caller):
            scan = await _run_bounded(_scan_segment, lines, version)
        if scan["bad_lines"]:
            _COUNTERS["rejected_lines"] += len(scan["bad_lines"])
            _log(f"reject {scan['error']} host={host} kinds={','.join(scan['kinds'])}"
                 f" lines={','.join(map(str, scan['bad_lines'][:50]))}")
            raise HTTPError(422, scan["error"], lines=scan["bad_lines"], kinds=scan["kinds"])
        if session_redact.detect_text(jsonl_path, version) or not _PRINTABLE_PATH_RE.fullmatch(jsonl_path):
            raise HTTPError(400, "invalid_request", field="file.jsonl_path")
        # segment.sha256 = sha256 of the masked lines, each followed by "\n" (client
        # contract): transport integrity of what the client sent.
        sent = "".join(line + "\n" for line in lines).encode("utf-8", "surrogatepass")
        if hashlib.sha256(sent).hexdigest() != seg_sha:
            raise HTTPError(422, "sha256_mismatch")
        # What is archived and parsed is the canonical serialisation of exactly the
        # records the detector scanned (see _scan_segment), never the raw lines.
        canonical = scan["canonical"]
        payload = "".join(line + "\n" for line in canonical).encode("utf-8")
        if len(payload) > sessions_archive.MAX_CHUNK_OUTPUT:
            raise HTTPError(413, "too_large")
        sha = hashlib.sha256(payload).hexdigest()

        got = await _get_session(session_key)
        existing, seq, term = got if got else (None, None, None)
        if existing and existing.get("host") != host:
            raise HTTPError(403, "host_mismatch")
        _refuse_purged_doc(session_key, existing)
        chunks = list((existing or {}).get("archive_chunks") or [])
        stream = _stream_chunks(chunks, agent_id)
        if agent_id is None:
            cur_gen = (existing or {}).get("archive_generation")
            cur_gen = -1 if cur_gen is None else cur_gen
        else:
            cur_gen = max((c["generation"] for c in stream), default=-1)
        seg_chunks = [c for c in stream if c.get("generation") == cur_gen]
        next_expected = max((c["end_offset"] for c in seg_chunks), default=0)
        new_generation = False
        if generation < cur_gen:
            raise HTTPError(409, "stale_generation", expected_offset=0, generation=cur_gen)
        if generation > cur_gen:
            if offset != 0:
                raise HTTPError(409, "offset_mismatch", expected_offset=0)
            new_generation = True
            seg_chunks = []
        elif offset != next_expected:
            if any(c["offset"] == offset for c in seg_chunks):
                # A retry of a segment already accepted: the same objects and ids
                # are rewritten, and anything after it is superseded.
                seg_chunks = [c for c in seg_chunks if c["offset"] < offset]
            else:
                raise HTTPError(409, "offset_mismatch", expected_offset=next_expected)

        async with _segment_slot(caller):
            parsed = await _run_bounded(
                sessions_parse.parse_lines, session_key, kind, canonical, offset, host=host,
                session_id=session_id, agent_id=agent_id,
                known_entrypoint=(existing or {}).get("entrypoint"), redact_version=version)
        for k, n in parsed["counters"]["unknown_types"].items():
            _COUNTERS["unknown_types"][k] = _COUNTERS["unknown_types"].get(k, 0) + n

        # Step 6 (main only): the archive chunk.
        archive_state = "skipped"
        archived_chunk = False
        backend = name = None

        async def discard():
            # This writer lost to a purge (or cannot tell): undo exactly what it
            # wrote. The purge already deleted everything that existed when it ran.
            await _delete_message_ids([d["_id"] for d in parsed["docs"]])
            if archived_chunk:
                await _delete_object_quietly(backend, session_key, name)

        if kind == "main":
            backend = _archive_backend()
            if backend is None and not sessions_archive.archive_disabled():
                # No backend configured and no explicit opt-out: refuse instead of
                # accepting the segment unarchived. The client keeps its cursor and
                # retries, so nothing is lost while the operator finishes setup; a
                # silently skipped segment would never be archived later.
                raise HTTPError(503, "archive_unavailable")
            if backend is not None:
                name = sessions_archive.object_name(host, session_key, generation=generation, offset=offset)
                await _put_object_verified(backend, session_key, name, sessions_archive.compress(payload),
                                           expect_exists=existing is not None)
                archive_state = "written"
                archived_chunk = True

        try:
            if new_generation and existing is not None:
                # A rewritten or truncated JSONL starts over (§8 row 5) — only this
                # stream's docs: the main file's, or one subagent's.
                await _delete_messages(session_key, agent_id=agent_id, main_only=agent_id is None)
            # Step 5: bulk index, no refresh.
            await _bulk_index(MESSAGE_INDEX, parsed["docs"])
        except ESUnavailable:
            # Fail closed: if the session is purged meanwhile, or its state cannot
            # be read, remove what this writer may already have written. A plain
            # ES hiccup on a live session leaves idempotent writes for the retry.
            try:
                purged = await _purged_now(session_key, expect_exists=existing is not None)
            except ESUnavailable:
                purged = True
            if purged:
                await _discard_quietly(discard, session_key)
            raise

        delta = parsed["delta"]
        entry = {
            "generation": generation, "offset": offset, "end_offset": end_offset,
            "sha256": sha, "bytes": len(payload), "archived": archived_chunk,
            "messages": delta["message_count"], "text_messages": delta["text_message_count"],
            "tombstones": delta["tombstones"],
        }
        if agent_id is not None:
            entry["agent_id"] = agent_id
        seg_chunks.append(entry)
        seg_chunks.sort(key=lambda c: c["offset"])
        others = [c for c in chunks if c not in stream]  # blobs and the other streams

        if agent_id is not None:
            doc = dict(existing or {
                "session_key": session_key, "session_id": session_id, "host": host,
                "project_dir": project_dir, "archived": False, "archive_complete": False})
            doc["has_subagents"] = True
            doc["archive_chunks"] = others + seg_chunks
            if delta.get("updated_at") and delta["updated_at"] > (doc.get("updated_at") or ""):
                doc["updated_at"] = delta["updated_at"]
            doc.setdefault("updated_at", _now_iso())
        else:
            if new_generation:
                others = [c for c in others if "agent_id" in c or "name" in c]
            doc = sessions_parse.merge_session(None if new_generation else existing, delta,
                                               project_dir=project_dir)
            all_archived = all(c.get("archived") for c in seg_chunks)
            doc.update({
                "session_key": session_key, "session_id": session_id, "host": host,
                "project_dir": project_dir, "jsonl_path": jsonl_path,
                "jsonl_exists": True, "jsonl_checked_at": _now_iso(),
                "message_count": sum(c["messages"] for c in seg_chunks),
                "text_message_count": sum(c["text_messages"] for c in seg_chunks),
                "has_subagents": bool((existing or {}).get("has_subagents")),
                "archived": all_archived,
                "archive_complete": all_archived and not any(c["tombstones"] for c in seg_chunks),
                "archive_generation": generation,
                "archive_bytes": sum(c["bytes"] for c in seg_chunks if c.get("archived")),
                "archive_chunks": seg_chunks + others,
                "redact_version": version,
            })
            if not doc.get("updated_at"):
                doc["updated_at"] = _now_iso()
            if existing and existing.get("restored_from"):
                doc["restored_from"] = existing["restored_from"]
        await _guarded_put_session(session_key, doc, seq, term, discard)

        _COUNTERS["ingested_segments"] += 1
        # Step 7: embeddings in the background.
        EMBED_SCHEDULER([d for d in parsed["docs"] if d.get("text")])
        return JSONResponse({"session_key": session_key, "indexed": len(parsed["docs"]),
                             "next_offset": end_offset, "archive": archive_state})

async def blob(request: Request, caller: dict):
    body = await _json_body(request)
    session_key = _session_key_param(body.get("session_key"))
    name = body.get("name")
    if not isinstance(name, str) or not TOOL_RESULT_NAME_RE.fullmatch(name):
        raise HTTPError(400, "invalid_name")
    sha = _str(body.get("sha256"), "sha256", SHA256_RE)
    content = body.get("content")
    if not isinstance(content, str):
        raise HTTPError(400, "invalid_request", field="content")
    src, seq, term = await _owned_session(session_key, caller)
    version = src.get("redact_version") or session_redact.RULESET_VERSION
    if _SURROGATE_RE.search(content):
        # Not encodable as UTF-8: what would be stored is not what was scanned.
        raise HTTPError(422, "invalid_line", lines=[], kinds=["surrogate"])
    existing_blobs = _blob_entries(src.get("archive_chunks"))
    if len(existing_blobs) >= TOOL_RESULTS_MAX_FILES and all(e["name"] != name for e in existing_blobs):
        raise HTTPError(413, "too_many_tool_results")
    async with _segment_slot(caller):
        kinds = await _run_bounded(session_redact.detect_text, content, version, BLOB_MAX_CHARS)
    if kinds:
        _log(f"reject unmasked_secret blob host={src.get('host')} kinds={','.join(kinds)}")
        raise HTTPError(422, "unmasked_secret", lines=[], kinds=kinds)
    # The scanned str is exactly what is stored (strict UTF-8, surrogates refused).
    data = content.encode("utf-8")
    if hashlib.sha256(data).hexdigest() != sha:
        raise HTTPError(400, "sha256_mismatch")
    backend = _archive_backend()
    if backend is None:
        return JSONResponse({"stored": False, "reason": "archive_disabled"})
    # Write phase under the session lock, re-reading the session doc: a purge
    # that ran while the content was being scanned leaves the marker (409).
    async with _session_lock(session_key):
        src, seq, term = await _owned_session(session_key, caller)
        _refuse_purged_doc(session_key, src)
        obj = sessions_archive.object_name(src["host"], session_key, tool_result=name)
        await _put_object_verified(backend, session_key, obj, sessions_archive.compress(data))
        chunks = [c for c in src.get("archive_chunks") or [] if c.get("name") != name]
        chunks.append({"name": name, "sha256": sha, "bytes": len(data)})
        src = dict(src)
        src["archive_chunks"] = chunks

        async def discard():
            try:
                await backend.delete(obj)
            except sessions_archive.ArchiveError:
                _log(f"purged-session straggler left for C8 session={session_key}")

        await _guarded_put_session(session_key, src, seq, term, discard)
    return JSONResponse({"stored": True})


async def state(request: Request, caller: dict):
    body = await _json_body(request)
    session_key = _session_key_param(body.get("session_key"))
    exists = body.get("jsonl_exists")
    if not isinstance(exists, bool):
        raise HTTPError(400, "invalid_request", field="jsonl_exists")
    async with _session_lock(session_key):
        src, seq, term = await _owned_session(session_key, caller)
        _refuse_purged_doc(session_key, src)
        r = await _es("POST", f"/{SESSION_INDEX}/_update/{session_key}"
                      f"?if_seq_no={seq}&if_primary_term={term}",
                      json={"doc": {"jsonl_exists": exists, "jsonl_checked_at": _now_iso()}})
        if r.status_code == 409:
            if await _purged_now(session_key):
                raise HTTPError(409, "purged")
            raise HTTPError(503, "busy")
        if r.status_code >= 400:
            raise ESUnavailable(f"state update: {r.status_code}")
    return JSONResponse({"ok": True})


async def _call_search(fn, *args):
    if fn is None:
        raise HTTPError(501, "not_implemented")
    try:
        res = fn(*args)
        if inspect.isawaitable(res):
            res = await res
    except ValueError as exc:
        raise HTTPError(400, "bad_request", detail=str(exc)[:200]) from None
    return JSONResponse(res)


async def search(request: Request, caller: dict):
    if sessions_search is None:
        raise HTTPError(501, "not_implemented")
    body = await _json_body(request)
    return await _call_search(sessions_search.search, be, body, caller)


async def preview(request: Request, caller: dict):
    if sessions_search is None:
        raise HTTPError(501, "not_implemented")
    session_key = _session_key_param(request.query_params.get("session_key"))
    q = request.query_params.get("q", "")
    return await _call_search(sessions_search.preview, be, session_key, q, caller)


async def _mark_incomplete(src: dict, seq, term) -> None:
    """archive_complete=false, conditional on the doc version the download read:
    a purged (or otherwise rewritten) doc is never touched."""
    r = await _es("POST", f"/{SESSION_INDEX}/_update/{src['session_key']}"
                  f"?if_seq_no={seq}&if_primary_term={term}",
                  json={"doc": {"archive_complete": False}})
    if r.status_code >= 400 and r.status_code not in (404, 409):
        raise ESUnavailable(f"mark incomplete: {r.status_code}")


async def _download_segments(src: dict, seq=None, term=None) -> bytes:
    """Concatenate the highest generation's chunks in offset order, checking
    contiguity and each chunk's sha256 against ES (§6.5, §8 rows 12 / 19)."""
    if not src.get("archived"):
        raise HTTPError(404, "not_archived")
    if not src.get("archive_complete"):
        raise HTTPError(409, "archive_incomplete")
    segs = _segment_chunks(src.get("archive_chunks"))
    if not segs:
        raise HTTPError(404, "not_archived")
    gen = max(c["generation"] for c in segs)
    segs = sorted((c for c in segs if c["generation"] == gen), key=lambda c: c["offset"])
    expected = 0
    for c in segs:
        if c["offset"] != expected or not c.get("archived"):
            await _mark_incomplete(src, seq, term)
            raise HTTPError(409, "archive_incomplete")
        expected = c["end_offset"]
    backend = _archive_backend()
    if backend is None:
        raise HTTPError(503, "archive_unavailable")
    out = bytearray()
    for c in segs:
        name = sessions_archive.object_name(src["host"], src["session_key"],
                                            generation=gen, offset=c["offset"])
        try:
            data = sessions_archive.decompress(await backend.get(name))
        except sessions_archive.ArchiveNotFound:
            await _mark_incomplete(src, seq, term)
            raise HTTPError(409, "archive_incomplete") from None
        except sessions_archive.ArchiveUnavailable:
            raise HTTPError(503, "archive_unavailable") from None
        except sessions_archive.ArchiveError:
            raise HTTPError(409, "archive_tampered") from None
        if hashlib.sha256(data).hexdigest() != c["sha256"]:
            _log(f"archive_tampered session={src['session_key']} offset={c['offset']}")
            raise HTTPError(409, "archive_tampered")
        out += data
        if len(out) > ARCHIVE_DOWNLOAD_MAX:
            raise HTTPError(413, "too_large")
    return bytes(out)


async def archive(request: Request, caller: dict):
    session_key = _session_key_param(request.query_params.get("session_key"))
    got = await _get_session(session_key)
    if got is None or _is_purged_doc(got[0]):
        raise HTTPError(404, "not_found")
    data = await _download_segments(*got)
    return Response(data, media_type="application/x-ndjson",
                    headers={"X-Archive-Sha256": hashlib.sha256(data).hexdigest()})


async def archive_tool_results(request: Request, caller: dict):
    session_key = _session_key_param(request.query_params.get("session_key"))
    got = await _get_session(session_key)
    if got is None or _is_purged_doc(got[0]):
        raise HTTPError(404, "not_found")
    src = got[0]
    entries = _blob_entries(src.get("archive_chunks"))
    backend = _archive_backend() if entries else None
    if len(entries) > TOOL_RESULTS_MAX_FILES:
        raise HTTPError(413, "too_large")
    total = 0
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        for e in sorted(entries, key=lambda x: x["name"]):
            if not TOOL_RESULT_NAME_RE.fullmatch(e["name"]):
                raise HTTPError(409, "archive_tampered")
            obj = sessions_archive.object_name(src["host"], session_key, tool_result=e["name"])
            try:
                data = sessions_archive.decompress(await backend.get(obj))
            except sessions_archive.ArchiveNotFound:
                raise HTTPError(409, "archive_incomplete") from None
            except sessions_archive.ArchiveUnavailable:
                raise HTTPError(503, "archive_unavailable") from None
            except sessions_archive.ArchiveError:
                raise HTTPError(409, "archive_tampered") from None
            if hashlib.sha256(data).hexdigest() != e["sha256"]:
                raise HTTPError(409, "archive_tampered")
            total += len(data)
            if total > TOOL_RESULTS_MAX_BYTES:
                raise HTTPError(413, "too_large")
            info = tarfile.TarInfo(e["name"])
            info.size = len(data)
            info.mode = 0o600
            tar.addfile(info, io.BytesIO(data))
    return Response(buf.getvalue(), media_type="application/x-tar")


async def delete_session(request: Request, caller: dict):
    session_key = _session_key_param(request.query_params.get("session_key"))
    # A host-less identity (the personal operator) may purge any host's
    # session; a host-bound one only its own (§7.2 writes rule).
    async with _session_lock(session_key):
        src, _, _ = await _owned_session(session_key, caller, allow_hostless=True)
        backend = _archive_backend()
        # Flip FIRST (seq-guarded): from here on every writer's conditional
        # write fails and it discards its batch. A failed purge (503) can be
        # retried; the doc stays purged meanwhile and the deletions re-run.
        await _flip_purged(session_key, identity._audit_token(caller.get("agent")))
        deleted_objects = 0
        if backend is not None:
            prefix = sessions_archive.object_name(src["host"], session_key)
            try:
                for name in await backend.list(prefix):
                    if name.startswith(prefix):
                        await backend.delete(name)
                        deleted_objects += 1
            except sessions_archive.ArchiveError:
                raise HTTPError(503, "archive_unavailable") from None
        deleted_docs = await _delete_messages(session_key)
    _log(f"purge session={session_key} host={src.get('host')} by={caller.get('agent')}"
         f" docs={deleted_docs} objects={deleted_objects}")
    return JSONResponse({"deleted_docs": deleted_docs, "deleted_objects": deleted_objects})


async def clear_purged(request: Request, caller: dict):
    """Operator action: lift the purge marker so the key may be ingested again
    (e.g. a deliberate re-backfill). Same host rule as DELETE /session."""
    session_key = _session_key_param(request.query_params.get("session_key"))
    async with _session_lock(session_key):
        got = await _get_session(session_key)
        if got is None or not _is_purged_doc(got[0]):
            _PURGED.discard(session_key)
            raise HTTPError(404, "not_purged")
        src, seq, term = got
        if caller.get("host") is not None and src.get("host") != caller["host"]:
            raise HTTPError(403, "host_mismatch")
        d = await _es("DELETE", f"/{SESSION_INDEX}/_doc/{session_key}"
                      f"?if_seq_no={seq}&if_primary_term={term}")
        if d.status_code == 409:
            raise HTTPError(503, "busy")
        if d.status_code not in (200, 404):
            raise ESUnavailable(f"purged doc delete: {d.status_code}")
        _PURGED.discard(session_key)
    _log(f"purge marker cleared session={session_key} by={caller.get('agent')}")
    return JSONResponse({"cleared": True})


async def status(request: Request, caller: dict):
    out = {"schema": {"session": SCHEMA_SESSION, "message": SCHEMA_MESSAGE},
           "redact_version": session_redact.RULESET_VERSION,
           "parser_version": sessions_parse.PARSER_VERSION,
           "ready": _STATE["ready"], "docs": None, "sessions": None,
           "pending_embeddings": None, "last_retention_run": None,
           "caller_host": caller.get("host"),
           "unknown_types": dict(_COUNTERS["unknown_types"]),
           "rejected_lines": _COUNTERS["rejected_lines"],
           "embedding_queue": dict(_EMBED_STATE),
           "search": sessions_search is not None}
    if not _STATE["ready"]:
        out["error"] = _STATE["error"]
        return JSONResponse(out)
    try:
        out["docs"] = await _count(MESSAGE_INDEX)
        out["sessions"] = await _count(
            SESSION_INDEX, {"bool": {"must_not": [{"exists": {"field": "purged_at"}}]}})
        out["purged_markers"] = await _count(SESSION_INDEX, {"exists": {"field": "purged_at"}})
        out["pending_embeddings"] = await _count(
            MESSAGE_INDEX, {"term": {"embedding_status": "pending"}})
    except ESUnavailable:
        pass
    return JSONResponse(out)


HANDLERS = {
    ("POST", "/ingest"): ingest,
    ("POST", "/blob"): blob,
    ("POST", "/state"): state,
    ("POST", "/search"): search,
    ("GET", "/preview"): preview,
    ("GET", "/archive"): archive,
    ("GET", "/archive/tool-results"): archive_tool_results,
    ("DELETE", "/session"): delete_session,
    ("DELETE", "/purged"): clear_purged,
    ("GET", "/status"): status,
}
assert set(HANDLERS) == set(ROUTES)  # noqa: S101 — import-time invariant


# --------------------------------------------------------------------------- #
# Gate + dispatch (pure ASGI)
# --------------------------------------------------------------------------- #
def _route_path(scope) -> str:
    """Path relative to the mount point. Starlette versions differ in whether a
    Mount passes the full path (with root_path set) or the remainder."""
    path = scope.get("path", "")
    root = scope.get("root_path", "")
    if root and path.startswith(root):
        path = path[len(root):]
    return path


def gate(scope, headers) -> tuple:
    """(caller | None, error JSONResponse | None). Pure apart from audit lines;
    exposed for tests."""
    if not identity.proxy_secret_configured():
        return None, _err(403, "gate_unconfigured")
    try:
        identity.require_proxy_secret(headers)
        ident = identity.parse_identity(headers)
    except identity.ProxyAuthError:
        return None, _err(401, "unauthenticated")
    key = (scope.get("method", ""), _route_path(scope))
    raw = scope.get("raw_path") or b""
    if isinstance(raw, bytes):
        low = raw.split(b"?", 1)[0].lower()
        # An encoded separator or a dot segment never names a route: refuse it
        # instead of letting the decoded path resolve to one (§8 row 23).
        if b"%2f" in low or b"%5c" in low or b"%2e" in low or any(
                seg in (b".", b"..") for seg in low.split(b"/")):
            return None, _err(403, "forbidden")
    scope_name = ROUTES.get(key)
    if scope_name is None:
        return None, _err(403, "forbidden")
    ok, host = identity.authorize_session_scope(ident, scope_name)
    if not ok:
        print(f"AUDIT sessions_deny route={identity._audit_token(key[1])}"
              f" client={identity._audit_token(ident.get('client_id'))}"
              f" grant={identity._audit_token(ident.get('grant'))}", file=sys.stderr, flush=True)
        return None, _err(403, "forbidden")
    return {**ident, "host": host, "scope": scope_name}, None


async def app(scope, receive, send):
    if scope["type"] == "lifespan":
        # Mounted: the parent runs the lifespan; answer a direct one politely.
        while True:
            msg = await receive()
            if msg["type"] == "lifespan.startup":
                await send({"type": "lifespan.startup.complete"})
            elif msg["type"] == "lifespan.shutdown":
                await send({"type": "lifespan.shutdown.complete"})
                return
    if scope["type"] != "http":
        return
    request = Request(scope, receive)
    caller, denied = gate(scope, request.headers)
    if denied is not None:
        await denied(scope, receive, send)
        return
    key = (scope["method"], _route_path(scope))
    if not _STATE["ready"] and key != ("GET", "/status"):
        response = _err(503, "index_unavailable")
    else:
        try:
            response = await HANDLERS[key](request, caller)
        except HTTPError as exc:
            response = _err(exc.status, exc.code, **exc.extra)
        except sessions_archive.InvalidName:
            response = _err(400, "invalid_name")
        except ESUnavailable as exc:
            _log(f"es unavailable route={key[1]} error={exc}")
            response = _err(503, "es_unavailable")
    await response(scope, receive, send)
