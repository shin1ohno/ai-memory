#!/usr/bin/env python3
"""sessions_maint (C8) over an in-memory ES and archive, hermetic.

Needs the memory-mcp venv (sessions_app imports starlette; the archive uses
zstandard):

    /tmp/memory-mcp-venv/bin/python test_sessions_maint.py

Covers: the 365-day retention boundary (364 d kept, 366 d deleted with its
message docs and archive objects), the purge-marker sweep (stragglers removed,
markers older than 30 days dropped), pending-embedding retry on success and on
provider failure, re-mask with a fake newer ruleset (archive objects, chunk
sha256, message text, title; and the r1 no-op), a missing HMAC key, the run
record /status reads, and the lock that keeps two runs apart.
"""

from __future__ import annotations

import asyncio
import copy
import fcntl
import hashlib
import json
import os
import sys
import tempfile
import time
import types
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

for k in ("SESSION_ARCHIVE_BACKEND", "SESSION_ARCHIVE_BUCKET", "SESSION_REDACT_KEY_FILE"):
    os.environ.pop(k, None)


# --------------------------------------------------------------------------- #
# Fake ES: the REST subset sessions_app + sessions_maint use, with a small
# query evaluator (bool/filter/must_not, term, range lt, exists, ids, match_all)
# --------------------------------------------------------------------------- #
class Resp:
    def __init__(self, status, payload=None):
        self.status_code = status
        self._payload = {} if payload is None else payload

    def json(self):
        return self._payload


def matches(q, doc_id, src) -> bool:
    if not q or "match_all" in q:
        return True
    if "bool" in q:
        b = q["bool"]
        return (all(matches(c, doc_id, src) for c in b.get("filter", []) + b.get("must", []))
                and not any(matches(c, doc_id, src) for c in b.get("must_not", [])))
    if "term" in q:
        (f, v), = q["term"].items()
        return src.get(f) == v
    if "exists" in q:
        return src.get(q["exists"]["field"]) is not None
    if "ids" in q:
        return doc_id in q["ids"]["values"]
    if "range" in q:
        (f, cond), = q["range"].items()
        val = src.get(f)
        return val is not None and val < cond["lt"]
    raise AssertionError(f"query not supported by the fake: {q}")


class FakeES:
    def __init__(self):
        self.indices: dict = {}
        self.seq = 0
        self.auto = 0

    def idx(self, name):
        return self.indices.setdefault(name, {})

    def put(self, index, doc_id, src):
        self.seq += 1
        self.idx(index)[doc_id] = (copy.deepcopy(src), self.seq)

    def src(self, index, doc_id):
        got = self.idx(index).get(doc_id)
        return None if got is None else got[0]

    async def request(self, method, path, json=None, content=None, headers=None):  # noqa: A002
        base, _, query = path.partition("?")
        params = dict(p.split("=", 1) for p in query.split("&") if "=" in p)
        parts = base.strip("/").split("/")
        if method == "POST" and parts == ["_bulk"]:
            return self._bulk(content)
        index = parts[0]
        docs = self.idx(index)
        if len(parts) == 2 and parts[1] == "_search":
            hits = []
            for did, (s, seq) in list(docs.items()):
                if matches(json["query"], did, s):
                    src = {k: v for k, v in s.items() if k in json["_source"]}
                    hits.append({"_id": did, "_source": copy.deepcopy(src), "_seq_no": seq,
                                 "_primary_term": 1})
            return Resp(200, {"hits": {"hits": hits[:json["size"]]}})
        if len(parts) == 2 and parts[1] == "_delete_by_query":
            gone = [d for d, (s, _) in docs.items() if matches(json["query"], d, s)]
            for d in gone:
                del docs[d]
            return Resp(200, {"deleted": len(gone)})
        if len(parts) == 2 and parts[1] == "_doc" and method == "POST":
            self.auto += 1
            self.put(index, f"auto{self.auto}", json)
            return Resp(201, {})
        if len(parts) == 3 and parts[1] == "_doc":
            did = parts[2]
            if method == "GET":
                if did not in docs:
                    return Resp(404, {"found": False})
                s, seq = docs[did]
                return Resp(200, {"found": True, "_source": copy.deepcopy(s), "_seq_no": seq,
                                  "_primary_term": 1})
            if "if_seq_no" in params and (did not in docs or docs[did][1] != int(params["if_seq_no"])):
                return Resp(409, {})
            if method == "PUT":
                self.put(index, did, json)
                return Resp(200, {})
            if method == "DELETE":
                return Resp(200 if docs.pop(did, None) is not None else 404, {})
        if len(parts) == 3 and parts[1] == "_create" and method == "PUT":
            if parts[2] in docs:
                return Resp(409, {})
            self.put(index, parts[2], json)
            return Resp(201, {})
        raise AssertionError(f"unexpected ES call {method} {path}")

    def _bulk(self, content):
        lines = content.strip().split("\n")
        items, errors = [], False
        i = 0
        while i < len(lines):
            action = json.loads(lines[i])
            if "delete" in action:
                m = action["delete"]
                self.idx(m["_index"]).pop(m["_id"], None)
                items.append({"delete": {"status": 200}})
                i += 1
                continue
            body = json.loads(lines[i + 1])
            i += 2
            if "update" in action:
                m = action["update"]
                docs = self.idx(m["_index"])
                if m["_id"] not in docs:
                    items.append({"update": {"status": 404, "error": {"type": "document_missing"}}})
                    errors = True
                    continue
                cur, seq = docs[m["_id"]]
                if m.get("if_seq_no") is not None and m["if_seq_no"] != seq:
                    items.append({"update": {"status": 409, "error": {"type": "version_conflict"}}})
                    errors = True
                    continue
                self.put(m["_index"], m["_id"], {**cur, **body["doc"]})
                items.append({"update": {"status": 200}})
                continue
            m = action["index"]
            self.put(m["_index"], m["_id"], body)
            items.append({"index": {"status": 201, "_seq_no": self.seq, "_primary_term": 1}})
        return Resp(200, {"errors": errors, "items": items})


FAKE = FakeES()
_be = types.ModuleType("es_backend")
_be._es = FAKE
_be._make_client = lambda: FAKE
sys.modules["es_backend"] = _be


class FakeVoyage(types.ModuleType):
    fail = False
    calls = 0

    async def embed_documents(self, texts):
        FakeVoyage.calls += 1
        if FakeVoyage.fail:
            raise RuntimeError("provider down")
        return [[0.1] * 4 for _ in texts]


sys.modules["voyage"] = FakeVoyage("voyage")

import session_redact  # noqa: E402
import sessions_app as sa  # noqa: E402
import sessions_archive as arc  # noqa: E402
import sessions_maint as sm  # noqa: E402

NOW = time.time()
SI, MI = sa.SESSION_INDEX, sa.MESSAGE_INDEX


def iso_days_ago(days: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(NOW - days * 86400))


def sid(n: int) -> str:
    return f"{n:08x}-0000-0000-0000-000000000000"


def make_session(n: int, *, updated_days: float, host="pro-dev", version="r1", lines=None,
                 messages=2, blob=None):
    """A session doc with one archived main chunk, `messages` message docs and
    an optional tool-results blob. Returns its session_key."""
    key = sa.make_session_key(host, "-home-dev-proj", sid(n))
    lines = lines or [{"type": "user", "message": {"content": f"hello {n}"}}]
    payload = "".join(sa.canonical_line(r) + "\n" for r in lines).encode()
    chunk = {"generation": 0, "offset": 0, "end_offset": len(payload),
             "sha256": hashlib.sha256(payload).hexdigest(), "bytes": len(payload),
             "archived": True, "messages": messages, "text_messages": messages, "tombstones": 0}
    BACKEND.objects[arc.object_name(host, key, generation=0, offset=0)] = arc.compress(payload)
    chunks = [chunk]
    if blob is not None:
        data = blob.encode()
        BACKEND.objects[arc.object_name(host, key, tool_result="t1.txt")] = arc.compress(data)
        chunks.append({"name": "t1.txt", "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)})
    FAKE.put(SI, key, {"session_key": key, "session_id": sid(n), "host": host,
                       "project_dir": "-home-dev-proj", "updated_at": iso_days_ago(updated_days),
                       "title": f"title {n}", "archived": True, "archive_complete": True,
                       "archive_generation": 0, "archive_bytes": len(payload),
                       "archive_chunks": chunks, "redact_version": version})
    for m in range(messages):
        FAKE.put(MI, f"{key}:{m}", {"session_key": key, "host": host, "text": f"text {n}.{m}",
                                    "embedding_status": "done", "redact_version": version})
    return key


def objects_of(host, key):
    prefix = arc.object_name(host, key)
    return [n for n in BACKEND.objects if n.startswith(prefix)]


BACKEND = arc.MemoryBackend()


class Base(unittest.TestCase):
    def setUp(self):
        FAKE.indices.clear()
        BACKEND.objects.clear()
        sa._ARCHIVE.clear()
        sa._ARCHIVE["backend"] = BACKEND
        sa._PURGED.clear()
        FakeVoyage.fail = False
        FakeVoyage.calls = 0
        self.tmp = tempfile.mkdtemp()
        self.lock = os.path.join(self.tmp, "maint.lock")
        os.environ.pop("SESSION_REDACT_KEY_FILE", None)

    def run_maint(self):
        return sm.run(now=NOW, lock_path=self.lock)


class Retention(Base):
    def test_boundary(self):
        keep = make_session(1, updated_days=364)
        drop = make_session(2, updated_days=366, blob="side file")
        self.assertEqual(len(objects_of("pro-dev", drop)), 2)
        out = self.run_maint()
        self.assertEqual(out["status"], "ok", out)
        self.assertEqual(out["expired_sessions"], 1)
        # 366 d: session doc, messages and every archive object gone; no marker left.
        self.assertIsNone(FAKE.src(SI, drop))
        self.assertFalse([d for d, (s, _) in FAKE.idx(MI).items() if s["session_key"] == drop])
        self.assertEqual(objects_of("pro-dev", drop), [])
        # 364 d: untouched.
        self.assertIsNotNone(FAKE.src(SI, keep))
        self.assertEqual(len([d for d, (s, _) in FAKE.idx(MI).items() if s["session_key"] == keep]), 2)
        self.assertEqual(len(objects_of("pro-dev", keep)), 1)

    def test_archive_unavailable_keeps_marker(self):
        drop = make_session(3, updated_days=400)
        sa._ARCHIVE["backend"] = sa._MISCONFIGURED
        out = self.run_maint()
        self.assertEqual(out["status"], "errors")
        src = FAKE.src(SI, drop)
        # Flipped (no writer can revive it), messages gone, marker kept for the sweep.
        self.assertIsNotNone(src)
        self.assertIsNotNone(src.get("purged_at"))
        self.assertNotIn("title", src)
        self.assertFalse([d for d, (s, _) in FAKE.idx(MI).items() if s["session_key"] == drop])

    def test_marker_sweep(self):
        old = make_session(4, updated_days=10)
        new = make_session(5, updated_days=10)
        for key, days in ((old, 31), (new, 5)):
            src = FAKE.src(SI, key)
            FAKE.put(SI, key, {"session_key": key, "host": src["host"],
                               "purged_at": iso_days_ago(days), "purged_by": "op"})
        out = self.run_maint()
        self.assertEqual(out["status"], "ok", out)
        self.assertEqual(out["markers_removed"], 1)
        self.assertIsNone(FAKE.src(SI, old))
        self.assertIsNotNone(FAKE.src(SI, new))
        # Stragglers of both are swept daily.
        for key in (old, new):
            self.assertEqual(objects_of("pro-dev", key), [])
            self.assertFalse([d for d, (s, _) in FAKE.idx(MI).items() if s["session_key"] == key])


class Embeddings(Base):
    def _pending(self, n):
        key = make_session(6, updated_days=1, messages=n)
        for m in range(n):
            s = FAKE.src(MI, f"{key}:{m}")
            s["embedding_status"] = "pending"
            FAKE.put(MI, f"{key}:{m}", s)
        return key

    def test_success(self):
        self._pending(130)  # two provider batches (128 + 2)
        out = self.run_maint()
        self.assertEqual(out["embed_attempted"], 130)
        self.assertEqual(FakeVoyage.calls, 2)
        statuses = {s["embedding_status"] for s, _ in FAKE.idx(MI).values()}
        self.assertEqual(statuses, {"done"})

    def test_failure_stays_pending(self):
        self._pending(3)
        FakeVoyage.fail = True
        out = self.run_maint()
        self.assertEqual(out["embed_attempted"], 3)
        statuses = [s["embedding_status"] for s, _ in FAKE.idx(MI).values()]
        self.assertEqual(statuses, ["pending"] * 3)


SECRET2 = "FAKESECRETV2"


class FakeR2:
    """A ruleset newer than r1 that additionally masks SECRET2."""

    def __enter__(self):
        self.saved = (session_redact.RULESET_VERSION, session_redact.redact_text,
                      session_redact.redact_record)

        def text(t, key, version="r2"):
            assert version == "r2" and key
            n = t.count(SECRET2)
            return t.replace(SECRET2, "[REDACTED:fake]"), ({"fake": n} if n else {})

        def record(r, key, version="r2"):
            out = json.loads(json.dumps(r).replace(SECRET2, "[REDACTED:fake]"))
            return out, {}

        session_redact.RULESET_VERSION = "r2"
        session_redact.redact_text = text
        session_redact.redact_record = record
        return self

    def __exit__(self, *a):
        (session_redact.RULESET_VERSION, session_redact.redact_text,
         session_redact.redact_record) = self.saved


class Remask(Base):
    def _key_file(self):
        p = os.path.join(self.tmp, "hmac.key")
        with open(p, "w") as fh:
            fh.write("hmac-key-for-tests\n")
        os.environ["SESSION_REDACT_KEY_FILE"] = p

    def _session(self):
        key = make_session(7, updated_days=1, lines=[{"type": "user", "message": {"content": SECRET2}}],
                           blob=f"tool output {SECRET2}")
        s = FAKE.src(MI, f"{key}:0")
        s["text"] = f"see {SECRET2}"
        FAKE.put(MI, f"{key}:0", s)
        src = FAKE.src(SI, key)
        src["title"] = f"title {SECRET2}"
        FAKE.put(SI, key, src)
        return key

    def test_r1_is_noop(self):
        key = self._session()
        before = (copy.deepcopy(FAKE.src(SI, key)), dict(BACKEND.objects))
        out = self.run_maint()
        self.assertEqual(out["remasked_sessions"], 0)
        self.assertEqual(out["status"], "ok", out)  # no key needed while nothing is old
        self.assertEqual(FAKE.src(SI, key), before[0])
        self.assertEqual(BACKEND.objects, before[1])

    def test_newer_ruleset_remasks_in_place(self):
        key = self._session()
        self._key_file()
        with FakeR2():
            out = self.run_maint()
            self.assertEqual(out["status"], "ok", out)
            self.assertEqual(out["remasked_sessions"], 1)
            self.assertEqual(out["remasked_objects"], 2)
            src = FAKE.src(SI, key)
            self.assertEqual(src["redact_version"], "r2")
            self.assertNotIn(SECRET2, src["title"])
            # The download path's own checks (contiguity + per-chunk sha256) pass.
            got = asyncio.run(sa._get_session(key))
            data = asyncio.run(sa._download_segments(*got))
            self.assertNotIn(SECRET2.encode(), data)
            self.assertIn(b"[REDACTED:fake]", data)
            blob = arc.decompress(BACKEND.objects[arc.object_name("pro-dev", key, tool_result="t1.txt")])
            self.assertNotIn(SECRET2.encode(), blob)
            entry = [c for c in src["archive_chunks"] if c.get("name") == "t1.txt"][0]
            self.assertEqual(entry["sha256"], hashlib.sha256(blob).hexdigest())
            m0 = FAKE.src(MI, f"{key}:0")
            self.assertNotIn(SECRET2, m0["text"])
            self.assertEqual(m0["redact_version"], "r2")
            self.assertEqual(m0["embedding_status"], "pending")  # re-embedded next run
            self.assertEqual(FAKE.src(MI, f"{key}:1")["embedding_status"], "done")
            # A second run finds nothing to do.
            again = self.run_maint()
            self.assertEqual(again["remasked_sessions"], 0)

    def test_missing_key_skips(self):
        key = self._session()
        with FakeR2():
            out = self.run_maint()
        self.assertEqual(out["status"], "errors")
        self.assertEqual(out["remask_skipped"], 1)
        self.assertEqual(FAKE.src(SI, key)["redact_version"], "r1")

    def test_tampered_chunk_is_left_alone(self):
        key = self._session()
        self._key_file()
        name = arc.object_name("pro-dev", key, generation=0, offset=0)
        BACKEND.objects[name] = arc.compress(b'{"forged":1}\n')
        with FakeR2():
            out = self.run_maint()
        self.assertEqual(out["remasked_sessions"], 0)
        self.assertEqual(FAKE.src(SI, key)["redact_version"], "r1")
        self.assertEqual(arc.decompress(BACKEND.objects[name]), b'{"forged":1}\n')


class RunRecordAndLock(Base):
    def test_run_record(self):
        out = self.run_maint()
        self.assertEqual(out["status"], "ok", out)
        stats = [s for s, _ in FAKE.idx(os.environ.get("STATS_INDEX", "memory-stats")).values()]
        self.assertEqual(len(stats), 1)
        self.assertEqual(stats[0]["run_kind"], "session-maint")
        self.assertEqual(stats[0]["written_at"], time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(NOW)))
        self.assertEqual(stats[0]["errors"], 0)

    def test_lock_prevents_concurrent_runs(self):
        drop = make_session(8, updated_days=400)
        with open(self.lock, "a") as held:
            fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
            out = self.run_maint()
            self.assertEqual(out, {"status": "locked"})
            self.assertIsNotNone(FAKE.src(SI, drop))  # nothing ran
        out = self.run_maint()  # released: the next run proceeds
        self.assertEqual(out["expired_sessions"], 1)

    def test_cli_usage(self):
        self.assertEqual(sm.main(["sessions_maint.py"]), 64)


if __name__ == "__main__":
    unittest.main(verbosity=2)
