#!/usr/bin/env python3
"""Session search C8: retention and maintenance (design spec §6.9, §8 rows 8 / 10 / 15).

One entry point, run daily by memory-session-maint.timer:

    python3 sessions_maint.py run

Under an exclusive lock file (a second run exits at once) it:

  (a) expires every session whose `updated_at` is older than 365 days: the
      session doc is first flipped to its purged form (seq-guarded, so a writer
      in flight loses its conditional write and discards its batch, exactly as
      for DELETE /session), then its archive prefix and message docs are
      deleted, then the marker itself;
  (a') sweeps every purge marker: its message docs (`delete_by_query` on
      `session_key`) and its archive prefix are deleted again — the documented
      one-day bound for objects a writer left between PUT and verify — and a
      marker older than 30 days is removed;
  (b) retries `embedding_status=pending` message docs in batches of 128 through
      sessions_app._embed_docs, the same conditional embed path ingest uses;
  (c) re-masks the archive and ES in place for sessions whose `redact_version`
      is older than session_redact.RULESET_VERSION. The HMAC key is read from
      SESSION_REDACT_KEY_FILE; without it the step is skipped and counted as an
      error (there is nothing to do while every session is on the current
      ruleset, so r1 needs no key);
  (d) records the run in the memory-stats index (run_kind=session-maint,
      written_at = the run time), which is where /status reads
      `last_retention_run` from.

Nothing transcript-derived is logged: only counts, session keys and kinds.
Reuses sessions_app's helpers by import (ES client, purge form, conditional
writes, embed path, archive backend); it changes none of them.

Env (besides what es_backend / voyage / sessions_archive read):
    SESSION_MAINT_LOCK          default /run/lock/memory-session-maint.lock
    SESSION_RETENTION_DAYS      default 365
    SESSION_MARKER_DAYS         default 30
    SESSION_MAINT_EMBED_BATCHES default 50   (x 128 docs per run)
    SESSION_REDACT_KEY_FILE     unset = re-mask unavailable
    STATS_INDEX                 default memory-stats
    KEEPER_HOST                 default es-memory (the stats doc's host)
"""

from __future__ import annotations

import asyncio
import fcntl
import hashlib
import json
import os
import sys
import time
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import es_backend as be  # noqa: E402
import session_redact  # noqa: E402
import sessions_app as sa  # noqa: E402
import sessions_archive  # noqa: E402

DAY = 86400
RUN_KIND = "session-maint"
SEARCH_PAGE = 200
MAX_PAGES = 500


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, str(default)))
    except ValueError:
        return default


def _log(msg: str) -> None:
    print(f"SESSION-MAINT {msg}", file=sys.stderr, flush=True)


def _iso(ts: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts))


def _parse_ts(value) -> float | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc).timestamp()
    except ValueError:
        return None


def _version_num(v) -> int:
    """'r3' -> 3. Missing or unparseable = 0 (older than any ruleset)."""
    if isinstance(v, str) and v.startswith("r") and v[1:].isdigit():
        return int(v[1:])
    return 0


class _Run:
    def __init__(self):
        self.counts = {
            "expired_sessions": 0, "expired_messages": 0, "expired_objects": 0,
            "markers_swept": 0, "markers_removed": 0, "straggler_objects": 0,
            "straggler_messages": 0, "embed_attempted": 0, "remasked_sessions": 0,
            "remasked_messages": 0, "remasked_objects": 0, "remask_skipped": 0,
        }
        self.errors = 0

    def err(self, what: str) -> None:
        self.errors += 1
        _log(f"error {what}")


# --------------------------------------------------------------------------- #
# ES helpers
# --------------------------------------------------------------------------- #
async def _search(index: str, query: dict, size: int, source) -> list:
    """Hits with _id, _source, _seq_no, _primary_term. A missing index is []."""
    r = await sa._es("POST", f"/{index}/_search", json={
        "query": query, "size": size, "_source": source,
        "seq_no_primary_term": True, "track_total_hits": False})
    if r.status_code == 404:
        return []
    if r.status_code != 200:
        raise sa.ESUnavailable(f"search {index}: {r.status_code}")
    return list(((r.json() or {}).get("hits") or {}).get("hits") or [])


async def _pages(index: str, query: dict, source, size: int = SEARCH_PAGE):
    """Yield hits until the query is exhausted. Each yielded id is excluded from
    the next page, so a doc the caller could not change is not seen twice, and
    a doc it deleted or updated (not yet refreshed) is not either."""
    seen: list = []
    for _ in range(MAX_PAGES):
        q = {"bool": {"filter": [query], "must_not": [{"ids": {"values": list(seen)}}]}} if seen else query
        hits = await _search(index, q, size, source)
        if not hits:
            return
        for h in hits:
            seen.append(h["_id"])
            yield h
    _log(f"page cap reached index={index}")


async def _delete_doc_if(index: str, doc_id: str, seq, term) -> bool:
    r = await sa._es("DELETE", f"/{index}/_doc/{doc_id}?if_seq_no={seq}&if_primary_term={term}")
    if r.status_code in (200, 404):
        return True
    if r.status_code == 409:
        return False
    raise sa.ESUnavailable(f"delete doc: {r.status_code}")


def _backend(run: _Run):
    """(backend, ok). backend None + ok True = archive disabled; ok False = the
    archive is configured but unusable (objects cannot be handled this run)."""
    try:
        return sa._archive_backend(), True
    except sa.HTTPError:
        run.err("archive misconfigured")
        return None, False


async def _delete_prefix(backend, host: str, session_key: str) -> int:
    prefix = sessions_archive.object_name(host, session_key)
    n = 0
    for name in await backend.list(prefix):
        if name.startswith(prefix):
            await backend.delete(name)
            n += 1
    return n


# --------------------------------------------------------------------------- #
# (a) retention
# --------------------------------------------------------------------------- #
async def expire_sessions(run: _Run, now: float, backend, archive_ok: bool) -> None:
    cutoff_ts = now - _env_int("SESSION_RETENTION_DAYS", 365) * DAY
    query = {"bool": {"filter": [{"range": {"updated_at": {"lt": _iso(cutoff_ts)}}}],
                      "must_not": [{"exists": {"field": "purged_at"}}]}}
    async for h in _pages(sa.SESSION_INDEX, query, ["session_key"]):
        key = h["_id"]
        try:
            await _expire_one(run, key, cutoff_ts, backend, archive_ok)
        except (sa.ESUnavailable, sessions_archive.ArchiveError, sessions_archive.InvalidName) as exc:
            run.err(f"expire session={key} {exc.__class__.__name__}")


async def _expire_one(run: _Run, key: str, cutoff_ts: float, backend, archive_ok: bool) -> None:
    got = await sa._get_session(key)
    if got is None:
        return
    src, seq, term = got
    updated = _parse_ts(src.get("updated_at"))
    if sa._is_purged_doc(src) or updated is None or updated >= cutoff_ts:
        return  # re-checked on the authoritative copy: touched since the search
    try:
        await sa._put_session(key, sa._purged_form(src, "retention"), seq, term)
    except sa._Conflict:
        return  # a writer got there first; the session is no longer idle
    run.counts["expired_sessions"] += 1
    if backend is not None:
        run.counts["expired_objects"] += await _delete_prefix(backend, src["host"], key)
    run.counts["expired_messages"] += await sa._delete_messages(key)
    if not archive_ok:
        return  # keep the marker: the daily sweep finishes the objects later
    got = await sa._get_session(key)
    if got is not None and sa._is_purged_doc(got[0]):
        await _delete_doc_if(sa.SESSION_INDEX, key, got[1], got[2])


# --------------------------------------------------------------------------- #
# (a') purge-marker sweep
# --------------------------------------------------------------------------- #
async def sweep_markers(run: _Run, now: float, backend, archive_ok: bool) -> None:
    marker_cutoff = now - _env_int("SESSION_MARKER_DAYS", 30) * DAY
    async for h in _pages(sa.SESSION_INDEX, {"exists": {"field": "purged_at"}},
                          ["session_key", "host", "purged_at"]):
        key = h["_id"]
        src = h.get("_source") or {}
        try:
            run.counts["markers_swept"] += 1
            run.counts["straggler_messages"] += await sa._delete_messages(key)
            if backend is not None and sessions_archive.HOST_RE.fullmatch(str(src.get("host", ""))):
                run.counts["straggler_objects"] += await _delete_prefix(backend, src["host"], key)
            purged = _parse_ts(src.get("purged_at"))
            if archive_ok and purged is not None and purged < marker_cutoff:
                if await _delete_doc_if(sa.SESSION_INDEX, key, h.get("_seq_no"), h.get("_primary_term")):
                    sa._PURGED.discard(key)
                    run.counts["markers_removed"] += 1
        except (sa.ESUnavailable, sessions_archive.ArchiveError, sessions_archive.InvalidName) as exc:
            run.err(f"sweep marker={key} {exc.__class__.__name__}")


# --------------------------------------------------------------------------- #
# (b) pending embeddings
# --------------------------------------------------------------------------- #
async def retry_embeddings(run: _Run) -> None:
    max_batches = _env_int("SESSION_MAINT_EMBED_BATCHES", 50)
    batch: list = []
    batches = 0
    async for h in _pages(sa.MESSAGE_INDEX, {"term": {"embedding_status": "pending"}},
                          ["session_key", "text"], size=sa.EMBED_BATCH):
        src = h.get("_source") or {}
        if not src.get("text") or h.get("_seq_no") is None:
            continue
        batch.append({"_id": h["_id"], "_seq_no": h["_seq_no"], "_primary_term": h.get("_primary_term"),
                      "session_key": src.get("session_key", ""), "text": src["text"]})
        if len(batch) == sa.EMBED_BATCH:
            await _embed(run, batch)
            batch = []
            batches += 1
            if batches >= max_batches:
                return
    if batch:
        await _embed(run, batch)


async def _embed(run: _Run, docs: list) -> None:
    run.counts["embed_attempted"] += len(docs)
    # _embed_docs never raises for a provider failure: the batch stays pending.
    await sa._embed_docs(docs)


# --------------------------------------------------------------------------- #
# (c) re-mask after a ruleset upgrade
# --------------------------------------------------------------------------- #
async def remask(run: _Run, backend, archive_ok: bool) -> None:
    current = session_redact.RULESET_VERSION
    cur_n = _version_num(current)
    query = {"bool": {"must_not": [{"term": {"redact_version": current}},
                                   {"exists": {"field": "purged_at"}}]}}
    key_bytes = None
    async for h in _pages(sa.SESSION_INDEX, query, ["session_key", "redact_version"]):
        if _version_num((h.get("_source") or {}).get("redact_version")) >= cur_n:
            continue  # declared by a newer client: nothing to raise it to
        if key_bytes is None:
            path = os.environ.get("SESSION_REDACT_KEY_FILE", "")
            try:
                key_bytes = session_redact.load_key(path) if path else None
            except session_redact.KeyMissing:
                key_bytes = None
            if key_bytes is None:
                run.counts["remask_skipped"] += 1
                run.err("remask needed but SESSION_REDACT_KEY_FILE is unusable")
                return
        if not archive_ok:
            run.counts["remask_skipped"] += 1
            continue
        try:
            if await _remask_one(run, h["_id"], key_bytes, current, backend):
                run.counts["remasked_sessions"] += 1
        except (sa.ESUnavailable, sessions_archive.ArchiveError, sessions_archive.InvalidName,
                ValueError) as exc:
            run.err(f"remask session={h['_id']} {exc.__class__.__name__}")


def _remask_lines(data: bytes, key: bytes, version: str) -> bytes:
    out = []
    for line in data.decode("utf-8").split("\n"):
        if not line:
            continue
        masked, _ = session_redact.redact_record(json.loads(line), key, version)
        out.append(sa.canonical_line(masked) + "\n")
    return "".join(out).encode("utf-8")


async def _remask_messages(run: _Run, session_key: str, key: bytes, version: str) -> bool:
    query = {"bool": {"filter": [{"term": {"session_key": session_key}}],
                      "must_not": [{"term": {"redact_version": version}}]}}
    async for h in _pages(sa.MESSAGE_INDEX, query, ["text", "tool_text"], size=500):
        src = h.get("_source") or {}
        partial = {"redact_version": version}
        for field in ("text", "tool_text"):
            value = src.get(field)
            if isinstance(value, str) and value:
                masked, _ = session_redact.redact_text(value, key, version)
                if masked != value:
                    partial[field] = masked
                    if field == "text":
                        partial["embedding_status"] = "pending"  # the vector described the old text
        lines = [json.dumps({"update": {"_index": sa.MESSAGE_INDEX, "_id": h["_id"],
                                        "if_seq_no": h.get("_seq_no"),
                                        "if_primary_term": h.get("_primary_term")}}),
                 json.dumps({"doc": partial})]
        r = await sa._es("POST", "/_bulk", content="\n".join(lines) + "\n",
                         headers={"Content-Type": "application/x-ndjson"})
        if r.status_code >= 400:
            raise sa.ESUnavailable(f"remask bulk: {r.status_code}")
        item = ((r.json().get("items") or [{}])[0]).get("update") or {}
        if item.get("error"):
            return False  # changed under us: the whole session waits for the next run
        run.counts["remasked_messages"] += 1
    return True


async def _remask_one(run: _Run, session_key: str, key: bytes, version: str, backend) -> bool:
    """Messages first, archive second, session doc last: the session doc's
    redact_version is the completion mark, so an interrupted run is redone."""
    if not await _remask_messages(run, session_key, key, version):
        return False
    got = await sa._get_session(session_key)
    if got is None or sa._is_purged_doc(got[0]):
        return False
    src, seq, term = got
    chunks = [dict(c) for c in (src.get("archive_chunks") or [])]
    originals: list = []  # (object name, original compressed bytes) for rollback
    if backend is not None:
        for c in chunks:
            if "name" in c:
                name = sessions_archive.object_name(src["host"], session_key, tool_result=c["name"])
            elif c.get("archived") and "agent_id" not in c:
                name = sessions_archive.object_name(src["host"], session_key,
                                                    generation=c["generation"], offset=c["offset"])
            else:
                continue
            raw = await backend.get(name)
            data = sessions_archive.decompress(raw)
            if hashlib.sha256(data).hexdigest() != c.get("sha256"):
                _log(f"remask skipped archive_tampered session={session_key}")
                await _rollback(backend, originals)
                return False
            if "name" in c:
                new, _ = session_redact.redact_text(data.decode("utf-8"), key, version)
                new = new.encode("utf-8")
            else:
                new = _remask_lines(data, key, version)
            if new == data:
                continue
            await backend.put(name, sessions_archive.compress(new))
            originals.append((name, raw))
            c["sha256"] = hashlib.sha256(new).hexdigest()
            c["bytes"] = len(new)
            run.counts["remasked_objects"] += 1
    doc = dict(src)
    doc["archive_chunks"] = chunks
    if any("name" not in c and "agent_id" not in c for c in chunks) and "archive_bytes" in doc:
        doc["archive_bytes"] = sum(c.get("bytes", 0) for c in chunks
                                   if "name" not in c and "agent_id" not in c and c.get("archived"))
    if isinstance(doc.get("title"), str):
        doc["title"], _ = session_redact.redact_text(doc["title"], key, version)
    doc["redact_version"] = version
    try:
        await sa._put_session(session_key, doc, seq, term)
    except sa._Conflict:
        # The doc changed since we read it: restore the objects it still
        # describes (their sha256 values are the old ones) and retry next run.
        await _rollback(backend, originals)
        return False
    return True


async def _rollback(backend, originals: list) -> None:
    for name, raw in originals:
        await backend.put(name, raw)


# --------------------------------------------------------------------------- #
# (d) run record
# --------------------------------------------------------------------------- #
async def record_run(run: _Run, now: float, started: float) -> None:
    index = os.environ.get("STATS_INDEX", "memory-stats")
    doc = {"written_at": _iso(now), "host": os.environ.get("KEEPER_HOST", "es-memory"),
           "run_kind": RUN_KIND, "expired_deleted": run.counts["expired_sessions"],
           "errors": run.errors, "loop_lag_ms": (time.monotonic() - started) * 1000.0}
    r = await sa._es("POST", f"/{index}/_doc", json=doc)
    if r.status_code >= 400:
        raise sa.ESUnavailable(f"stats write: {r.status_code}")


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #
class Locked(Exception):
    pass


def _acquire(path: str):
    fh = open(path, "a")  # noqa: SIM115 — held for the whole run
    try:
        fcntl.flock(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        fh.close()
        raise Locked(path) from None
    return fh


async def run_once(now: float | None = None) -> dict:
    now = time.time() if now is None else now
    started = time.monotonic()
    run = _Run()
    backend, archive_ok = _backend(run)
    for name, step in (("retention", expire_sessions), ("markers", sweep_markers)):
        try:
            await step(run, now, backend, archive_ok)
        except (sa.ESUnavailable, sessions_archive.ArchiveError) as exc:
            run.err(f"{name} {exc.__class__.__name__}")
    try:
        await retry_embeddings(run)
    except sa.ESUnavailable as exc:
        run.err(f"embeddings {exc.__class__.__name__}")
    try:
        await remask(run, backend, archive_ok)
    except (sa.ESUnavailable, sessions_archive.ArchiveError) as exc:
        run.err(f"remask {exc.__class__.__name__}")
    try:
        await record_run(run, now, started)
    except sa.ESUnavailable as exc:
        run.err(f"record {exc.__class__.__name__}")
    return {"status": "ok" if run.errors == 0 else "errors", "errors": run.errors, **run.counts}


def run(now: float | None = None, lock_path: str | None = None) -> dict:
    lock_path = lock_path or os.environ.get("SESSION_MAINT_LOCK", "/run/lock/memory-session-maint.lock")
    try:
        fh = _acquire(lock_path)
    except Locked:
        _log("another run holds the lock; exiting")
        return {"status": "locked"}
    try:
        return asyncio.run(run_once(now))
    finally:
        fh.close()


def main(argv: list) -> int:
    if argv[1:] != ["run"]:
        print("usage: sessions_maint.py run", file=sys.stderr)
        return 64
    summary = run()
    _log(json.dumps(summary, sort_keys=True))
    return 1 if summary.get("status") == "errors" else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
