#!/usr/bin/env python3
"""sessions_app end-to-end over Starlette's TestClient, hermetic.

ES is an in-memory fake installed as the `es_backend` module before import, and
the archive is sessions_archive.MemoryBackend, so nothing leaves the process.
Needs the memory-mcp venv (starlette, httpx, zstandard):

    /tmp/memory-mcp-venv/bin/python test_sessions_app.py

Covers the gate (proxy secret, unknown routes, memory-mirror, scopes, host
mismatch), body limits (9 MiB, gzip bomb), the 422 re-scan, offsets and
generations, session_key opacity and object-name validation, archive download
with tampered / missing chunks, blobs, purge, status, the 501 search fallback,
and that the in-process index definitions equal the committed JSON.
"""

from __future__ import annotations

import asyncio
import gzip
import hashlib
import io
import json
import os
import re
import sys
import tarfile
import types
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

SECRET = "proxy-secret-for-tests"
POLICY = {"rules": [
    {"match": {"grant": "client_credentials", "client_id": "session-search-pro-dev"},
     "host": "pro-dev", "scopes": ["sessions:ingest", "sessions:read"]},
    {"match": {"grant": "authorization_code", "client_id": "tailnet:nXXXX"},
     "host": "air", "scopes": ["sessions:ingest", "sessions:read", "sessions:purge"]},
    {"match": {"grant": "authorization_code", "sub": "operator@example.com"},
     "host": None, "scopes": ["sessions:read", "sessions:purge"]},
]}
os.environ["PROXY_SHARED_SECRET"] = SECRET
os.environ["SESSION_SCOPE_POLICY"] = json.dumps(POLICY)
for k in ("SESSION_ARCHIVE_BACKEND", "SESSION_ARCHIVE_BUCKET"):
    os.environ.pop(k, None)


# --------------------------------------------------------------------------- #
# Fake ES (the subset of the REST API sessions_app uses)
# --------------------------------------------------------------------------- #
class FakeResp:
    def __init__(self, status, payload=None):
        self.status_code = status
        self._payload = payload if payload is not None else {}
        self.text = json.dumps(self._payload)

    def json(self):
        return self._payload


class FakeES:
    def __init__(self):
        self.indices: dict[str, dict] = {}
        self.seq = 0
        self.calls: list = []
        self.created: dict = {}
        self.fail: dict = {}

    def _idx(self, name):
        return self.indices.setdefault(name, {})

    async def request(self, method, path, json=None, content=None, headers=None):  # noqa: A002
        self.calls.append((method, path))
        base, _, query = path.partition("?")
        # failure injection: {(method, base path): "5xx" | "garbage"}
        mode = self.fail.get((method, base))
        if mode == "5xx":
            return FakeResp(503, {"error": "injected"})
        if mode == "garbage":
            r = FakeResp(200, {})
            r.json = lambda: (_ for _ in ()).throw(ValueError("not json"))
            return r
        parts = base.strip("/").split("/")
        if method == "POST" and parts == ["_bulk"]:
            lines = content.strip().split("\n")
            items = []
            errors = False
            actions = []
            it = iter(lines)
            for meta in it:
                action = __import__("json").loads(meta)
                if "delete" in action:
                    actions.append((action, None))
                else:
                    actions.append((action, __import__("json").loads(next(it))))
            for action, body in actions:
                if "delete" in action:
                    m = action["delete"]
                    found = self._idx(m["_index"]).pop(m["_id"], None) is not None
                    items.append({"delete": {"_id": m["_id"], "status": 200 if found else 404}})
                    continue
                if "update" in action:
                    m = action["update"]
                    docs = self._idx(m["_index"])
                    if m["_id"] not in docs:
                        items.append({"update": {"_id": m["_id"], "status": 404,
                                                 "error": {"type": "document_missing_exception"}}})
                        errors = True
                        continue
                    cur, seq = docs[m["_id"]]
                    if m.get("if_seq_no") is not None and m["if_seq_no"] != seq:
                        items.append({"update": {"_id": m["_id"], "status": 409,
                                                 "error": {"type": "version_conflict_engine_exception"}}})
                        errors = True
                        continue
                    self.seq += 1
                    docs[m["_id"]] = ({**cur, **body["doc"]}, self.seq)
                    items.append({"update": {"_id": m["_id"], "status": 200, "_seq_no": self.seq,
                                             "_primary_term": 1}})
                    continue
                m = action["index"]
                self.seq += 1
                self._idx(m["_index"])[m["_id"]] = (body, self.seq)
                items.append({"index": {"_id": m["_id"], "status": 201, "_seq_no": self.seq,
                                        "_primary_term": 1}})
            self.calls[-1] = (method, path, query)
            return FakeResp(200, {"errors": errors, "items": items})
        index = parts[0]
        if len(parts) == 3 and parts[1] == "_doc":
            docs = self._idx(index)
            did = parts[2]
            if method == "GET":
                if did not in docs:
                    return FakeResp(404, {"found": False})
                src, seq = docs[did]
                return FakeResp(200, {"found": True, "_source": __import__("copy").deepcopy(src),
                                      "_seq_no": seq, "_primary_term": 1})
            if method == "PUT":
                if "if_seq_no" in query:
                    want = int(re.search(r"if_seq_no=(\d+)", query).group(1))
                    if did not in docs or docs[did][1] != want:
                        return FakeResp(409, {})
                self.seq += 1
                docs[did] = (__import__("copy").deepcopy(json), self.seq)
                return FakeResp(200, {})
            if method == "DELETE":
                if did in docs:
                    del docs[did]
                    return FakeResp(200, {})
                return FakeResp(404, {})
        if len(parts) == 3 and parts[1] == "_create" and method == "PUT":
            docs = self._idx(index)
            if parts[2] in docs:
                return FakeResp(409, {})
            self.seq += 1
            docs[parts[2]] = (__import__("copy").deepcopy(json), self.seq)
            return FakeResp(201, {})
        if len(parts) == 3 and parts[1] == "_update" and method == "POST":
            docs = self._idx(index)
            did = parts[2]
            if "if_seq_no" in query:
                want = int(re.search(r"if_seq_no=(\d+)", query).group(1))
                if did not in docs or docs[did][1] != want:
                    return FakeResp(409, {})
            self.seq += 1
            if did in docs:
                src = dict(docs[did][0])
                src.update(json["doc"])
                docs[did] = (src, self.seq)
                return FakeResp(200, {})
            if "upsert" in json:
                docs[did] = (dict(json["upsert"]), self.seq)
                return FakeResp(201, {})
            return FakeResp(404, {})
        if len(parts) == 2 and parts[1] == "_delete_by_query":
            terms = [list(t["term"].items())[0] for t in json["query"]["bool"]["filter"]]
            docs = self._idx(index)
            gone = [k for k, (s, _) in docs.items() if all(s.get(f) == v for f, v in terms)]
            for k in gone:
                del docs[k]
            return FakeResp(200, {"deleted": len(gone)})
        if len(parts) == 2 and parts[1] == "_count":
            docs = self._idx(index)
            q = json["query"]
            if "term" in q:
                (f, v), = q["term"].items()
                n = sum(1 for s, _ in docs.values() if s.get(f) == v)
            elif "exists" in q:
                n = sum(1 for s, _ in docs.values() if s.get(q["exists"]["field"]) is not None)
            elif "bool" in q:
                f = q["bool"]["must_not"][0]["exists"]["field"]
                n = sum(1 for s, _ in docs.values() if s.get(f) is None)
            else:
                n = len(docs)
            return FakeResp(200, {"count": n})
        if len(parts) == 1 and method == "PUT":
            if index in self.created:
                return FakeResp(400, {"error": {"type": "resource_already_exists_exception"}})
            self.created[index] = json
            return FakeResp(200, {})
        if len(parts) == 2 and parts[1] == "_mapping":
            body = self.created.get(index)
            if body is None:
                return FakeResp(404, {})
            return FakeResp(200, {index: {"mappings": body["mappings"]}})
        if len(parts) == 1 and method == "HEAD":
            return FakeResp(200 if index in self.created else 404)
        raise AssertionError(f"unexpected ES call {method} {path}")

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False


FAKE = FakeES()
_be = types.ModuleType("es_backend")
_be._es = FAKE
_be._make_client = lambda: FAKE


async def _index_exists(client, name):
    return name in FAKE.created


_be._index_exists = _index_exists
with open(os.path.join(HERE, "..", "es-indices-v2", "memory-knowledge.json")) as _fh:
    _be._ANALYSIS = json.load(_fh)["settings"]["analysis"]
sys.modules["es_backend"] = _be

from starlette.applications import Starlette  # noqa: E402
from starlette.routing import Mount  # noqa: E402
from starlette.testclient import TestClient  # noqa: E402

import identity  # noqa: E402
import session_redact  # noqa: E402
import sessions_app as sa  # noqa: E402
import sessions_archive as arc  # noqa: E402
import sessions_parse  # noqa: E402

PREFIX = "/memory/sessions/v1"
APP = Starlette(routes=[Mount(PREFIX, app=sa.app)])
KEY = b"hmac-key-for-tests"

PRO_DEV = {"x-verified-grant": "client_credentials", "x-verified-client-id": "session-search-pro-dev",
           "x-verified-sub": "session-search-pro-dev", "x-proxy-secret": SECRET}
AIR = {"x-verified-grant": "authorization_code", "x-verified-client-id": "tailnet:nXXXX",
       "x-verified-sub": "human", "x-proxy-secret": SECRET}
OPERATOR = {"x-verified-grant": "authorization_code", "x-verified-client-id": "claude-ai",
            "x-verified-sub": "operator@example.com", "x-proxy-secret": SECRET}
MIRROR = {"x-verified-grant": "client_credentials", "x-verified-client-id": "memory-mirror",
          "x-verified-sub": "memory-mirror", "x-proxy-secret": SECRET}

SID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
PDIR = "-home-dev-proj"
ALL_ROUTES = [(m, p) for (m, p) in sa.ROUTES]


def line(uuid, text, ts="2026-10-01T10:00:00Z", **kw):
    r = {"type": "user", "uuid": uuid, "sessionId": SID, "cwd": "/home/dev/proj",
         "entrypoint": "cli", "timestamp": ts, "message": {"role": "user", "content": text}}
    r.update(kw)
    return json.dumps(r, ensure_ascii=False, separators=(",", ":"))


def segment_body(lines, offset, end_offset=None, generation=0, host="pro-dev", sid=SID,
                 kind="main", pdir=PDIR, version="r1", **file_extra):
    payload = "".join(x + "\n" for x in lines).encode()
    return {
        "client": {"host": host, "client_version": "test", "redact_version": version},
        "file": {"session_id": sid, "project_dir": pdir, "jsonl_path": f"/x/{sid}.jsonl",
                 "kind": kind, **file_extra},
        "segment": {"generation": generation, "offset": offset,
                    "end_offset": end_offset if end_offset is not None else offset + len(payload),
                    "sha256": hashlib.sha256(payload).hexdigest(), "lines": lines},
    }


def gz(obj):
    return gzip.compress(json.dumps(obj).encode())


class Base(unittest.TestCase):
    def setUp(self):
        FAKE.indices.clear()
        FAKE.calls.clear()
        FAKE.fail.clear()
        self.store = arc.MemoryBackend()
        sa._ARCHIVE.clear()
        sa._ARCHIVE["backend"] = self.store
        sa._STATE["ready"] = True
        sa._PURGED.clear()
        sa._EMBED_STATE.update(queued=0, dropped=0)
        self.embedded = []
        sa.EMBED_SCHEDULER = self.embedded.extend
        self.c = TestClient(APP)

    def ingest(self, body, headers=PRO_DEV, raw=None):
        return self.c.post(PREFIX + "/ingest", content=raw if raw is not None else gz(body),
                           headers={**headers, "content-type": "application/json"})

    def session(self, sk):
        return FAKE.indices["memory-session"][sk][0]


class Gate(Base):
    def test_missing_or_wrong_proxy_secret_is_401(self):
        for h in ({k: v for k, v in PRO_DEV.items() if k != "x-proxy-secret"},
                  {**PRO_DEV, "x-proxy-secret": "wrong"}):
            r = self.c.get(PREFIX + "/status", headers=h)
            self.assertEqual(r.status_code, 401, r.text)

    def test_unconfigured_secret_refuses_everything(self):
        saved = identity._PROXY_SHARED_SECRET
        identity._PROXY_SHARED_SECRET = ""
        try:
            r = self.c.get(PREFIX + "/status", headers=PRO_DEV)
            self.assertEqual((r.status_code, r.json()["error"]), (403, "gate_unconfigured"))
        finally:
            identity._PROXY_SHARED_SECRET = saved

    def test_unknown_routes_are_403(self):
        for method, path in (("GET", "/nope"), ("GET", "/status/"), ("HEAD", "/status"),
                             ("POST", "/status"), ("GET", "/ingest"), ("PUT", "/session"),
                             ("GET", "/archive%2Ftool-results"), ("GET", "")):
            with self.subTest(method=method, path=path):
                r = self.c.request(method, PREFIX + path, headers=AIR)
                self.assertEqual(r.status_code, 403, (path, r.text))

    def test_dot_segments_and_encoded_separators_in_raw_path_are_403(self):
        # httpx resolves dot segments client-side, so drive the gate directly
        # with the raw_path a hostile client (or proxy) could send.
        headers = {k: v for k, v in AIR.items()}
        for raw in (b"/memory/sessions/v1/x/../status", b"/memory/sessions/v1/./status",
                    b"/memory/sessions/v1/archive%2Ftool-results", b"/memory/sessions/v1/%2e%2e/status",
                    b"/memory/sessions/v1/status%5c"):
            with self.subTest(raw=raw):
                scope = {"method": "GET", "path": "/memory/sessions/v1/status",
                         "root_path": "/memory/sessions/v1", "raw_path": raw}
                caller, denied = sa.gate(scope, headers)
                self.assertIsNone(caller)
                self.assertEqual(denied.status_code, 403)
        scope = {"method": "GET", "path": "/memory/sessions/v1/status",
                 "root_path": "/memory/sessions/v1", "raw_path": b"/memory/sessions/v1/status"}
        caller, denied = sa.gate(scope, headers)
        self.assertIsNone(denied)
        self.assertEqual((caller["host"], caller["scope"]), ("air", "sessions:read"))

    def test_memory_mirror_is_403_everywhere(self):
        for method, path in ALL_ROUTES:
            with self.subTest(route=path):
                r = self.c.request(method, PREFIX + path, headers=MIRROR)
                self.assertEqual(r.status_code, 403, r.text)

    def test_no_identity_is_403(self):
        r = self.c.get(PREFIX + "/status", headers={"x-proxy-secret": SECRET})
        self.assertEqual(r.status_code, 403)

    def test_scope_is_enforced_per_route(self):
        # pro-dev has no purge scope; the operator has no ingest scope
        r = self.c.delete(PREFIX + "/session", params={"session_key": "sk_" + "a" * 32},
                          headers=PRO_DEV)
        self.assertEqual(r.status_code, 403)
        r = self.ingest(segment_body([line("u1", "hi")], 0), headers=OPERATOR)
        self.assertEqual(r.status_code, 403)

    def test_policy_unset_denies_all(self):
        saved = identity._SESSION_SCOPE_POLICY
        identity._SESSION_SCOPE_POLICY = None
        try:
            for h in (PRO_DEV, AIR, OPERATOR):
                self.assertEqual(self.c.get(PREFIX + "/status", headers=h).status_code, 403)
        finally:
            identity._SESSION_SCOPE_POLICY = saved

    def test_status_reports_caller_host(self):
        r = self.c.get(PREFIX + "/status", headers=PRO_DEV)
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(r.json()["caller_host"], "pro-dev")
        self.assertEqual(r.json()["redact_version"], "r1")
        self.assertIsNone(self.c.get(PREFIX + "/status", headers=OPERATOR).json()["caller_host"])

    def test_not_ready_is_503_except_status(self):
        sa._STATE["ready"] = False
        r = self.ingest(segment_body([line("u1", "hi")], 0))
        self.assertEqual((r.status_code, r.json()["error"]), (503, "index_unavailable"))
        self.assertEqual(self.c.get(PREFIX + "/status", headers=PRO_DEV).status_code, 200)

    def test_search_and_preview_501_without_module(self):
        if sa.sessions_search is not None:
            self.skipTest("sessions_search is installed")
        r = self.c.post(PREFIX + "/search", json={"q": "x"}, headers=PRO_DEV)
        self.assertEqual((r.status_code, r.json()["error"]), (501, "not_implemented"))
        r = self.c.get(PREFIX + "/preview", params={"session_key": "sk_" + "a" * 32, "q": "x"},
                       headers=PRO_DEV)
        self.assertEqual(r.status_code, 501)
        self.assertEqual(self.c.post(PREFIX + "/search", json={}, headers=MIRROR).status_code, 403)


class Limits(Base):
    def test_9_mib_body_is_413(self):
        r = self.ingest(None, raw=b"x" * (9 * 1024 * 1024))
        self.assertEqual((r.status_code, r.json()["error"]), (413, "too_large"))

    def test_9_mib_body_without_content_length_is_413(self):
        def gen():
            for _ in range(9):
                yield b"x" * (1024 * 1024)
        r = self.c.post(PREFIX + "/ingest", content=gen(), headers=PRO_DEV)
        self.assertEqual(r.status_code, 413)

    def test_gzip_bomb_is_413(self):
        bomb = gzip.compress(b"\0" * (6 * 1024 * 1024), compresslevel=9)
        self.assertLess(len(bomb), 16 * 1024)
        r = self.ingest(None, raw=bomb)
        self.assertEqual((r.status_code, r.json()["error"]), (413, "too_large"))

    def test_truncated_gzip_is_400(self):
        r = self.ingest(None, raw=gz({"a": 1})[:-6])
        self.assertEqual(r.status_code, 400)


class Ingest(Base):
    def test_happy_path(self):
        lines = [line("u1", "find the worktree bug"),
                 json.dumps({"type": "ai-title", "aiTitle": "Worktree bug"})]
        r = self.ingest(segment_body(lines, 0))
        self.assertEqual(r.status_code, 200, r.text)
        out = r.json()
        sk = out["session_key"]
        self.assertEqual(out["archive"], "written")
        self.assertEqual(out["indexed"], 1)
        self.assertRegex(sk, r"^sk_[a-z2-7]{32}$")
        self.assertEqual(sk, sa.make_session_key("pro-dev", PDIR, SID))
        self.assertNotIn(SID.replace("-", ""), sk)
        s = self.session(sk)
        self.assertEqual((s["host"], s["title"], s["resume_cwd"]), ("pro-dev", "Worktree bug",
                                                                    "/home/dev/proj"))
        self.assertTrue(s["resume_cwd_verified"] and s["archived"] and s["archive_complete"])
        self.assertEqual(s["message_count"], 1)
        # no refresh on the bulk call
        bulk = [c for c in FAKE.calls if c[1].startswith("/_bulk")]
        self.assertTrue(bulk and all("refresh" not in c[1] for c in bulk))
        self.assertEqual([d["uuid"] for d in self.embedded], ["u1"])
        mapping = sa.index_definitions()["memory-session"][0]["mappings"]["properties"]
        self.assertLessEqual(set(s), set(mapping), set(s) - set(mapping))
        mmap = sa.index_definitions()["memory-session-message"][0]["mappings"]["properties"]
        for src, _ in FAKE.indices["memory-session-message"].values():
            self.assertLessEqual(set(src), set(mmap), set(src) - set(mmap))

    def test_body_host_must_match_identity(self):
        r = self.ingest(segment_body([line("u1", "x")], 0, host="mini"))
        self.assertEqual((r.status_code, r.json()["error"]), (403, "host_mismatch"))
        r = self.ingest(segment_body([line("u1", "x")], 0, host="air"))
        self.assertEqual(r.status_code, 403)

    def test_write_to_another_hosts_session_is_403(self):
        r = self.ingest(segment_body([line("u1", "x")], 0, host="air"), headers=AIR)
        sk = r.json()["session_key"]
        r = self.c.post(PREFIX + "/state", json={"session_key": sk, "jsonl_exists": False},
                        headers=PRO_DEV)
        self.assertEqual((r.status_code, r.json()["error"]), (403, "host_mismatch"))
        r = self.c.post(PREFIX + "/blob", content=gz({"session_key": sk, "name": "a.txt",
                                                      "sha256": "0" * 64, "content": "x"}),
                        headers=PRO_DEV)
        self.assertEqual(r.status_code, 403)
        r = self.c.post(PREFIX + "/state", json={"session_key": sk, "jsonl_exists": False},
                        headers=AIR)
        self.assertEqual(r.status_code, 200)
        self.assertFalse(self.session(sk)["jsonl_exists"])

    def test_unmasked_secret_is_422_with_line_indexes(self):
        tok = "ghp_" + "A" * 36
        lines = [line("u1", "fine"), line("u2", f"oops {tok}"), line("u3", "fine"),
                 line("u4", "DB_PASSWORD=hunter2hunter2")]
        r = self.ingest(segment_body(lines, 0))
        self.assertEqual(r.status_code, 422, r.text)
        self.assertEqual(r.json(), {"error": "unmasked_secret", "lines": [1, 3],
                                    "kinds": ["config-secret", "github-token"]})
        self.assertNotIn(tok, r.text)
        self.assertFalse(FAKE.indices.get("memory-session"))

    def test_masked_input_passes_rescan(self):
        rec = json.loads(line("u2", "token ghp_" + "A" * 36 + " and Authorization: Bearer "
                              + "z" * 30))
        masked, counts = session_redact.redact_record(rec, KEY)
        r = self.ingest(segment_body([json.dumps(masked)], 0))
        self.assertEqual(r.status_code, 200, r.text)

    def test_tombstone_marks_archive_incomplete(self):
        tomb = json.dumps({"type": "session-search-tombstone", "reason": "unmasked_secret",
                           "kinds": ["jwt"], "line_offset": 10})
        r = self.ingest(segment_body([line("u1", "x"), tomb], 0))
        self.assertEqual(r.status_code, 200, r.text)
        s = self.session(r.json()["session_key"])
        self.assertFalse(s["archive_complete"])
        r = self.c.get(PREFIX + "/archive", params={"session_key": s["session_key"]}, headers=AIR)
        self.assertEqual((r.status_code, r.json()["error"]), (409, "archive_incomplete"))

    def test_validation(self):
        bad = [
            segment_body([line("u1", "x")], 0, sid="../../etc/passwd"),
            segment_body([line("u1", "x")], 0, pdir="../x"),
            segment_body([line("u1", "x")], 0, pdir="a/b"),
            segment_body([line("u1", "x")], 0, kind="other"),
            segment_body([line("u1", "x")], 0, version="r9"),
            segment_body([], 0),
        ]
        for b in bad:
            with self.subTest(b=b["file"]):
                self.assertEqual(self.ingest(b).status_code, 400)
        b = segment_body([line("u1", "x")], 0)
        b["segment"]["sha256"] = "0" * 64
        r = self.ingest(b)
        self.assertEqual((r.status_code, r.json()["error"]), (422, "sha256_mismatch"))

    def test_offsets_and_retries(self):
        b1 = segment_body([line("u1", "one")], 0)
        r1 = self.ingest(b1)
        end1 = r1.json()["next_offset"]
        r = self.ingest(segment_body([line("u2", "two")], end1 + 50))
        self.assertEqual((r.status_code, r.json()["expected_offset"]), (409, end1))
        r = self.ingest(segment_body([line("u2", "two")], 7))
        self.assertEqual(r.status_code, 409)
        self.assertEqual(self.ingest(b1).status_code, 200)  # retry of an accepted segment
        r2 = self.ingest(segment_body([line("u2", "two")], end1))
        self.assertEqual(r2.status_code, 200, r2.text)
        s = self.session(r1.json()["session_key"])
        self.assertEqual([c["offset"] for c in s["archive_chunks"]], [0, end1])
        self.assertEqual(s["message_count"], 2)

    def test_generation_bump_starts_over(self):
        r = self.ingest(segment_body([line("u1", "one"), line("u2", "two")], 0))
        sk = r.json()["session_key"]
        self.assertEqual(len(FAKE.indices["memory-session-message"]), 2)
        r = self.ingest(segment_body([line("u9", "new")], 40, generation=1))
        self.assertEqual((r.status_code, r.json()["expected_offset"]), (409, 0))
        r = self.ingest(segment_body([line("u9", "new")], 0, generation=1))
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual([s["uuid"] for s, _ in FAKE.indices["memory-session-message"].values()],
                         ["u9"])
        s = self.session(sk)
        self.assertEqual((s["archive_generation"], s["message_count"]), (1, 1))
        r = self.ingest(segment_body([line("u1", "old")], 0, generation=0))
        self.assertEqual((r.status_code, r.json()["error"]), (409, "stale_generation"))
        dl = self.c.get(PREFIX + "/archive", params={"session_key": sk}, headers=PRO_DEV)
        self.assertEqual(dl.text, line("u9", "new") + "\n")

    def sub(self, uuid, text, offset, agent="a1b2", generation=0):
        return segment_body([line(uuid, text, isSidechain=True)], offset, kind="subagent",
                            parent_session_id=SID, agent_id=agent, generation=generation)

    def msgs(self):
        return {s["uuid"]: s for s, _ in FAKE.indices["memory-session-message"].values()}

    def test_subagent_goes_into_the_parent_session_unarchived(self):
        main = self.ingest(segment_body([line("u1", "parent")], 0)).json()
        objects_before = dict(self.store.objects)
        r = self.ingest(self.sub("s1", "child", 0))
        self.assertEqual(r.status_code, 200, r.text)
        out = r.json()
        self.assertEqual(out["session_key"], main["session_key"])
        self.assertEqual(out["archive"], "skipped")
        self.assertEqual(self.store.objects, objects_before)
        s = self.session(main["session_key"])
        self.assertTrue(s["has_subagents"])
        self.assertTrue(s["archived"] and s["archive_complete"])
        self.assertEqual(s["message_count"], 1)
        child = self.msgs()["s1"]
        self.assertTrue(child["is_sidechain"])
        self.assertEqual((child["agent_id"], child["session_key"]), ("a1b2", main["session_key"]))
        # the main archive is untouched by the subagent stream
        dl = self.c.get(PREFIX + "/archive", params={"session_key": main["session_key"]},
                        headers=PRO_DEV)
        self.assertEqual(dl.text, line("u1", "parent") + "\n")

    def test_subagent_cursor_is_per_agent(self):
        sk = self.ingest(segment_body([line("u1", "parent")], 0)).json()["session_key"]
        r1 = self.ingest(self.sub("s1", "child", 0)).json()
        r = self.ingest(self.sub("s2", "next", r1["next_offset"] + 5))
        self.assertEqual((r.status_code, r.json()["expected_offset"]), (409, r1["next_offset"]))
        self.assertEqual(self.ingest(self.sub("t1", "other agent", 0, agent="zz9")).status_code, 200)
        # main continues from its own offset, unaffected by subagent offsets
        main_next = [c for c in self.session(sk)["archive_chunks"] if "agent_id" not in c][0]["end_offset"]
        self.assertEqual(self.ingest(segment_body([line("u2", "more")], main_next)).status_code, 200)

    def test_generation_bumps_are_per_stream(self):
        sk = self.ingest(segment_body([line("u1", "parent")], 0)).json()["session_key"]
        self.ingest(self.sub("s1", "child", 0))
        self.ingest(self.sub("t1", "other", 0, agent="zz9"))
        self.assertEqual(self.ingest(self.sub("s9", "rewritten", 0, generation=1)).status_code, 200)
        self.assertEqual(set(self.msgs()), {"u1", "s9", "t1"})
        self.assertEqual(self.ingest(segment_body([line("u9", "new main")], 0, generation=1)).status_code, 200)
        self.assertEqual(set(self.msgs()), {"u9", "s9", "t1"})
        self.assertEqual(self.session(sk)["archive_generation"], 1)

    def test_subagent_before_main(self):
        r = self.ingest(self.sub("s1", "child", 0))
        self.assertEqual(r.status_code, 200, r.text)
        sk = r.json()["session_key"]
        self.assertFalse(self.session(sk)["archived"])
        r = self.ingest(segment_body([line("u1", "parent")], 0))
        self.assertEqual(r.status_code, 200, r.text)
        s = self.session(sk)
        self.assertTrue(s["has_subagents"] and s["archived"] and s["archive_complete"])
        self.assertEqual(s["cwd"], "/home/dev/proj")

    def test_subagent_must_name_the_parent(self):
        b = self.sub("s1", "child", 0)
        b["file"]["parent_session_id"] = "bbbbbbbb-bbbb-cccc-dddd-eeeeeeeeeeee"
        self.assertEqual(self.ingest(b).status_code, 400)
        b = self.sub("s1", "child", 0)
        del b["file"]["agent_id"]
        self.assertEqual(self.ingest(b).status_code, 400)

    def test_unknown_body_keys_are_ignored(self):
        b = segment_body([line("u1", "x")], 0)
        b["client"]["future_field"] = 1
        b["file"]["mtime"] = 123
        b["segment"]["compression"] = "none"
        b["extra"] = {"anything": True}
        self.assertEqual(self.ingest(b).status_code, 200)

    def test_tombstone_is_archived_and_skipped_by_the_parser(self):
        for reason in ("unmasked_secret", "too_large"):
            with self.subTest(reason=reason):
                FAKE.indices.clear()
                self.store.objects.clear()
                tomb = json.dumps({"type": "session-search-tombstone", "reason": reason,
                                   "kinds": ["jwt"], "line_offset": 4}, separators=(",", ":"))
                r = self.ingest(segment_body([line("u1", "x"), tomb], 0))
                self.assertEqual(r.status_code, 200, r.text)
                self.assertEqual(set(self.msgs()), {"u1"})
                sk = r.json()["session_key"]
                self.assertFalse(self.session(sk)["archive_complete"])
                stored = arc.decompress(next(iter(self.store.objects.values()))).decode()
                self.assertEqual(stored.splitlines()[1], tomb)

    def test_archive_explicitly_disabled_is_skipped(self):
        sa._ARCHIVE["backend"] = None
        os.environ["SESSION_ARCHIVE_BACKEND"] = "none"
        try:
            r = self.ingest(segment_body([line("u1", "x")], 0))
        finally:
            os.environ.pop("SESSION_ARCHIVE_BACKEND", None)
        self.assertEqual(r.json()["archive"], "skipped")
        s = self.session(r.json()["session_key"])
        self.assertFalse(s["archived"])

    def test_archive_unconfigured_is_503_and_indexes_nothing(self):
        # Unset backend is "not ready yet", not "disabled": a main segment
        # accepted now would never be archived later, so it is refused and the
        # client keeps its cursor.
        sa._ARCHIVE["backend"] = None
        os.environ.pop("SESSION_ARCHIVE_BACKEND", None)
        r = self.ingest(segment_body([line("u1", "x")], 0))
        self.assertEqual(r.status_code, 503)
        self.assertEqual(r.json()["error"], "archive_unavailable")
        self.assertEqual(len(FAKE.indices.get(sa.MESSAGE_INDEX, {})), 0)

    def test_archive_outage_is_503_and_holds_the_cursor(self):
        class Down(arc.MemoryBackend):
            async def put(self, name, data):
                raise arc.ArchiveUnavailable("down")
        sa._ARCHIVE["backend"] = Down()
        r = self.ingest(segment_body([line("u1", "x")], 0))
        self.assertEqual((r.status_code, r.json()["error"]), (503, "archive_unavailable"))
        self.assertFalse(FAKE.indices.get("memory-session"))
        self.assertFalse(FAKE.indices.get("memory-session-message"))


class Hostile(Base):
    """Parser-differential, ReDoS and event-loop findings from the security
    review: what is archived and indexed is exactly what the detector saw."""

    def test_invalid_lines_are_422_per_line(self):
        cases = {
            "duplicate-key": '{"type":"user","uuid":"d","message":{"content":"a"},"message":{"content":"b"}}',
            "surrogate": '{"type":"user","uuid":"s","message":{"content":"\\ud800x"}}',
            "non-finite-number": '{"type":"user","uuid":"n","x":NaN}',
            "invalid-json": "not json",
            "not-an-object": "[1,2]",
            "too-deep": '{"a":' * 70 + "1" + "}" * 70,
        }
        for kind, bad in cases.items():
            with self.subTest(kind=kind):
                r = self.ingest(segment_body([line("u1", "ok"), bad], 0))
                self.assertEqual(r.status_code, 422, r.text)
                self.assertEqual(r.json(), {"error": "invalid_line", "lines": [1], "kinds": [kind]})

    def test_secret_and_invalid_lines_are_reported_together(self):
        r = self.ingest(segment_body([line("u1", "ghp_" + "A" * 36), "nope", line("u3", "ok")], 0))
        self.assertEqual(r.status_code, 422)
        self.assertEqual(r.json(), {"error": "unmasked_secret", "lines": [0, 1],
                                    "kinds": ["github-token", "invalid-json"]})

    def test_secret_in_a_dict_key_is_rejected(self):
        bad = json.dumps({"type": "user", "uuid": "k", "toolUseResult": {"ghp_" + "A" * 36: 1}})
        r = self.ingest(segment_body([bad], 0))
        self.assertEqual((r.status_code, r.json()["kinds"]), (422, ["github-token"]))

    def test_archive_holds_the_canonical_form_of_what_was_scanned(self):
        rec = {"type": "user", "uuid": "c1", "cwd": "/home/dev/proj",
               "message": {"role": "user", "content": "line\u2028sep and \u0000 nul\r\nend"}}
        spaced = json.dumps(rec, ensure_ascii=False)  # ", " / ": " separators, raw U+2028
        self.assertIn("\u2028", spaced)
        r = self.ingest(segment_body([spaced], 0))
        self.assertEqual(r.status_code, 200, r.text)
        sk = r.json()["session_key"]
        dl = self.c.get(PREFIX + "/archive", params={"session_key": sk}, headers=AIR).content
        self.assertEqual(dl.decode(), sa.canonical_line(rec) + "\n")
        self.assertNotIn("\u2028".encode(), dl)
        self.assertNotIn(b"\r", dl)
        self.assertNotIn(b"\0", dl)
        self.assertEqual(dl.count(b"\n"), 1)
        self.assertEqual(json.loads(dl), rec)
        chunk = self.session(sk)["archive_chunks"][0]
        self.assertEqual(chunk["sha256"], hashlib.sha256(dl).hexdigest())
        doc = next(iter(FAKE.indices["memory-session-message"].values()))[0]
        self.assertEqual(doc["text"], rec["message"]["content"].strip())

    def test_jsonl_path_is_scanned_and_printable(self):
        for p in ("/x/ghp_" + "A" * 36 + ".jsonl", "/x/a\nb.jsonl", "/x/\x00.jsonl"):
            with self.subTest(p=p):
                b = segment_body([line("u1", "x")], 0)
                b["file"]["jsonl_path"] = p
                self.assertEqual(self.ingest(b).status_code, 400)

    def test_deeply_nested_request_body_is_400(self):
        r = self.ingest(None, raw=gzip.compress(b"[" * 200_000 + b"]" * 200_000))
        self.assertEqual((r.status_code, r.json()["error"]), (400, "bad_json"))

    def test_surrogate_blob_is_422(self):
        sk = self.ingest(segment_body([line("u1", "x")], 0)).json()["session_key"]
        raw = ('{"session_key":"%s","name":"a.txt","sha256":"%s","content":"\\ud800"}'
               % (sk, "0" * 64)).encode()
        r = self.c.post(PREFIX + "/blob", content=gzip.compress(raw), headers=PRO_DEV)
        self.assertEqual((r.status_code, r.json()["kinds"]), (422, ["surrogate"]))

    def test_hostile_segment_is_bounded_and_does_not_block_the_loop(self):
        """A segment that costs well over the budget is cut off with 413, and a
        cheap request issued while it runs completes promptly."""
        import time as _t

        import httpx
        hostile = 'token=eyJ-a://xx_sk-"secret": "' * 6000  # ~190 KB of worst-case text
        lines = [json.dumps({"type": "user", "uuid": f"h{i}", "message": {"content": hostile}})
                 for i in range(18)]
        body = gz(segment_body(lines, 0))

        async def run():
            transport = httpx.ASGITransport(app=APP)
            async with httpx.AsyncClient(transport=transport, base_url="http://t") as client:
                t0 = _t.monotonic()
                slow = asyncio.ensure_future(client.post(
                    PREFIX + "/ingest", content=body, headers=PRO_DEV))
                await asyncio.sleep(0.3)
                t1 = _t.monotonic()
                st = await client.get(PREFIX + "/status", headers=PRO_DEV)
                status_latency = _t.monotonic() - t1
                done_before = slow.done()
                res = await slow
                return res, st, status_latency, done_before, _t.monotonic() - t0

        # A low budget keeps the test independent of runner speed: the segment
        # costs ~1.5-4 s of CPU (measured on CI and pro-dev), far above 0.6 s.
        saved = sa.SEGMENT_BUDGET_S
        sa.SEGMENT_BUDGET_S = 0.6
        try:
            res, st, status_latency, done_before, total = asyncio.run(run())
        finally:
            sa.SEGMENT_BUDGET_S = saved
        self.assertEqual(st.status_code, 200)
        self.assertFalse(done_before, "the hostile segment should still be running")
        self.assertLess(status_latency, 0.5)
        self.assertEqual((res.status_code, res.json()["error"]), (413, "too_expensive"))
        self.assertLess(total, 0.6 + 2.0)

    def test_value_past_the_cap_is_rejected_not_truncated(self):
        cap = sa.session_redact.MAX_VALUE_CHARS
        tok = "ghp_" + "A" * 36
        for value in ("x" * cap + " " + tok,            # token after the cap boundary
                      "x" * (cap - 10) + " " + tok):     # token straddling it
            with self.subTest(at=len(value)):
                bad = json.dumps({"type": "user", "uuid": "o", "message": {"content": value}})
                r = self.ingest(segment_body([bad], 0))
                self.assertEqual(r.status_code, 422, r.text)
                self.assertEqual(r.json()["lines"], [0])
                self.assertEqual(r.json()["kinds"], ["oversize"])
        self.assertFalse(FAKE.indices.get("memory-session-message"))
        self.assertEqual(self.store.objects, {})

    def test_segment_totals(self):
        r = self.ingest(segment_body(["{}"] * (sa.SEGMENT_MAX_LINES + 1), 0))
        self.assertEqual((r.status_code, r.json()["error"]), (413, "too_many_lines"))
        per_line = 25_000
        lines = [json.dumps({"type": "user", "uuid": f"v{i}", "x": ["a"] * per_line})
                 for i in range(sa.SEGMENT_MAX_STRINGS // per_line + 1)]
        r = self.ingest(segment_body(lines, 0))
        self.assertEqual((r.status_code, r.json()["error"]), (413, "too_many_values"))
        self.assertFalse(FAKE.indices.get("memory-session-message"))
        # positive control: just under the cap is accepted inside the default budget
        under = [json.dumps({"type": "user", "uuid": f"w{i}", "x": ["a"] * per_line})
                 for i in range(sa.SEGMENT_MAX_STRINGS // per_line - 1)]
        r = self.ingest(segment_body(under, 0))
        self.assertEqual(r.status_code, 200, r.text)
        deep = '{"a":' * (sa.MAX_RECORD_DEPTH + 1) + "1" + "}" * (sa.MAX_RECORD_DEPTH + 1)
        ok_depth = '{"a":' * (sa.MAX_RECORD_DEPTH - 1) + "1" + "}" * (sa.MAX_RECORD_DEPTH - 1)
        r = self.ingest(segment_body([ok_depth, deep], 0))
        self.assertEqual((r.status_code, r.json()["lines"], r.json()["kinds"]),
                         (422, [1], ["too-deep"]))


class Archive(Base):
    def two_segments(self):
        l1, l2 = [line("u1", "one")], [line("u2", "two")]
        r1 = self.ingest(segment_body(l1, 0)).json()
        self.ingest(segment_body(l2, r1["next_offset"]))
        return r1["session_key"], l1 + l2

    def test_download_roundtrip(self):
        sk, lines = self.two_segments()
        r = self.c.get(PREFIX + "/archive", params={"session_key": sk}, headers=AIR)
        self.assertEqual(r.status_code, 200, r.text)
        body = "".join(x + "\n" for x in lines)
        self.assertEqual(r.text, body)
        self.assertEqual(r.headers["x-archive-sha256"], hashlib.sha256(body.encode()).hexdigest())
        self.assertTrue(r.headers["content-type"].startswith("application/x-ndjson"))
        names = sorted(self.store.objects)
        self.assertTrue(all(n.startswith(f"sessions/pro-dev/{sk}/g0/") for n in names), names)
        self.assertTrue(names[0].endswith("/000000000000.jsonl.zst"))

    def test_tampered_chunk_is_409(self):
        sk, _ = self.two_segments()
        name = sorted(self.store.objects)[1]
        self.store.objects[name] = arc.compress(b'{"type":"user","forged":true}\n')
        r = self.c.get(PREFIX + "/archive", params={"session_key": sk}, headers=AIR)
        self.assertEqual((r.status_code, r.json()["error"]), (409, "archive_tampered"))
        self.store.objects[name] = b"not zstd"
        r = self.c.get(PREFIX + "/archive", params={"session_key": sk}, headers=AIR)
        self.assertEqual((r.status_code, r.json()["error"]), (409, "archive_tampered"))

    def test_gap_is_409_incomplete(self):
        sk, _ = self.two_segments()
        src, seq = FAKE.indices["memory-session"][sk]
        src["archive_chunks"] = [c for c in src["archive_chunks"] if c["offset"] != 0]
        r = self.c.get(PREFIX + "/archive", params={"session_key": sk}, headers=AIR)
        self.assertEqual((r.status_code, r.json()["error"]), (409, "archive_incomplete"))
        self.assertFalse(self.session(sk)["archive_complete"])

    def test_missing_object_is_409_incomplete(self):
        sk, _ = self.two_segments()
        del self.store.objects[sorted(self.store.objects)[0]]
        r = self.c.get(PREFIX + "/archive", params={"session_key": sk}, headers=AIR)
        self.assertEqual((r.status_code, r.json()["error"]), (409, "archive_incomplete"))

    def test_bad_session_keys(self):
        for v in ("../../x", "sk_..%2F..", "sk_" + "A" * 32, "sk_" + "a" * 31, "", "sk_a/b"):
            with self.subTest(v=v):
                r = self.c.get(PREFIX + "/archive", params={"session_key": v}, headers=AIR)
                self.assertEqual(r.status_code, 400, r.text)
        r = self.c.get(PREFIX + "/archive", params={"session_key": "sk_" + "a" * 32}, headers=AIR)
        self.assertEqual(r.status_code, 404)

    def test_blob_and_tool_results_tar(self):
        sk, _ = self.two_segments()
        content = "masked tool output"
        ok = {"session_key": sk, "name": "toolu_01.txt",
              "sha256": hashlib.sha256(content.encode()).hexdigest(), "content": content}
        for bad in ({**ok, "name": "../x"}, {**ok, "name": "a/b"}, {**ok, "name": ".hidden"},
                    {**ok, "name": "x%2Fy"}, {**ok, "sha256": "0" * 64}):
            with self.subTest(bad=bad["name"]):
                r = self.c.post(PREFIX + "/blob", content=gz(bad), headers=PRO_DEV)
                self.assertEqual(r.status_code, 400, r.text)
        secret = {**ok, "content": "ghp_" + "A" * 36}
        secret["sha256"] = hashlib.sha256(secret["content"].encode()).hexdigest()
        r = self.c.post(PREFIX + "/blob", content=gz(secret), headers=PRO_DEV)
        self.assertEqual(r.status_code, 422)
        r = self.c.post(PREFIX + "/blob", content=gz(ok), headers=PRO_DEV)
        self.assertEqual(r.json(), {"stored": True})
        self.assertIn(f"sessions/pro-dev/{sk}/tool-results/toolu_01.txt.zst", self.store.objects)
        r = self.c.get(PREFIX + "/archive/tool-results", params={"session_key": sk}, headers=AIR)
        self.assertEqual(r.status_code, 200)
        with tarfile.open(fileobj=io.BytesIO(r.content)) as tar:
            self.assertEqual(tar.getnames(), ["toolu_01.txt"])
            self.assertEqual(tar.extractfile("toolu_01.txt").read().decode(), content)
        # still downloadable after the blob was recorded
        self.assertEqual(self.c.get(PREFIX + "/archive", params={"session_key": sk},
                                    headers=AIR).status_code, 200)
        self.store.objects[f"sessions/pro-dev/{sk}/tool-results/toolu_01.txt.zst"] = arc.compress(b"x")
        r = self.c.get(PREFIX + "/archive/tool-results", params={"session_key": sk}, headers=AIR)
        self.assertEqual((r.status_code, r.json()["error"]), (409, "archive_tampered"))


class Purge(Base):
    def test_delete(self):
        r = self.ingest(segment_body([line("u1", "x")], 0, host="air"), headers=AIR)
        sk = r.json()["session_key"]
        r = self.c.delete(PREFIX + "/session", params={"session_key": sk}, headers=AIR)
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(r.json(), {"deleted_docs": 1, "deleted_objects": 1})
        self.assertEqual(self.store.objects, {})
        self.assertTrue(sa._is_purged_doc(self.session(sk)))

    def test_hostless_operator_may_purge_any_host(self):
        sk = self.ingest(segment_body([line("u1", "x")], 0)).json()["session_key"]
        r = self.c.delete(PREFIX + "/session", params={"session_key": sk}, headers=OPERATOR)
        self.assertEqual(r.status_code, 200, r.text)

    def test_hostbound_cannot_purge_other_host(self):
        sk = self.ingest(segment_body([line("u1", "x")], 0)).json()["session_key"]
        r = self.c.delete(PREFIX + "/session", params={"session_key": sk}, headers=AIR)
        self.assertEqual((r.status_code, r.json()["error"]), (403, "host_mismatch"))


class Names(unittest.TestCase):
    SK = "sk_" + "a" * 32

    def test_builder_always_under_sessions(self):
        good = [arc.object_name("pro-dev", self.SK, generation=3, offset=42),
                arc.object_name("air", self.SK, tool_result="toolu_9.txt"),
                arc.object_name("air", self.SK)]
        self.assertEqual(good[0], f"sessions/pro-dev/{self.SK}/g3/000000000042.jsonl.zst")
        self.assertEqual(good[1], f"sessions/air/{self.SK}/tool-results/toolu_9.txt.zst")
        self.assertEqual(good[2], f"sessions/air/{self.SK}/")
        for n in good:
            self.assertTrue(n.startswith("sessions/"))
            self.assertNotIn("..", n.split("/"))

    def test_builder_rejects(self):
        bad = [dict(host="..", session_key=self.SK), dict(host="a/b", session_key=self.SK),
               dict(host="UP", session_key=self.SK), dict(host="h", session_key="../x"),
               dict(host="h", session_key=self.SK, tool_result=".."),
               dict(host="h", session_key=self.SK, tool_result="a%2Fb"),
               dict(host="h", session_key=self.SK, tool_result="../x"),
               dict(host="h", session_key=self.SK, generation=-1, offset=0),
               dict(host="h", session_key=self.SK, generation=0, offset=10 ** 12),
               dict(host="h", session_key=self.SK, generation=True, offset=0)]
        for kw in bad:
            with self.subTest(kw=kw):
                with self.assertRaises(arc.InvalidName):
                    arc.object_name(**kw)

    def test_bounded_decompress(self):
        blob = arc.compress(b"\0" * (6 * 1024 * 1024))
        with self.assertRaises(arc.ArchiveError):
            arc.decompress(blob)
        self.assertEqual(arc.decompress(arc.compress(b"abc")), b"abc")

    def test_backend_from_env(self):
        self.assertIsNone(arc.backend_from_env({}))
        self.assertIsInstance(arc.backend_from_env({"SESSION_ARCHIVE_BACKEND": "gcs",
                                                    "SESSION_ARCHIVE_BUCKET": "b"}), arc.GCSBackend)
        s3 = arc.backend_from_env({"SESSION_ARCHIVE_BACKEND": "s3", "SESSION_ARCHIVE_BUCKET": "b",
                                   "SESSION_ARCHIVE_AWS_ACCESS_KEY_ID": "AKIDEXAMPLE",
                                   "SESSION_ARCHIVE_AWS_SECRET_ACCESS_KEY": "fake",
                                   "SESSION_ARCHIVE_AWS_REGION": "ap-northeast-1"})
        self.assertEqual(s3.host, "b.s3.ap-northeast-1.amazonaws.com")
        for env in ({"SESSION_ARCHIVE_BACKEND": "gcs"}, {"SESSION_ARCHIVE_BACKEND": "ftp",
                                                        "SESSION_ARCHIVE_BUCKET": "b"},
                    {"SESSION_ARCHIVE_BACKEND": "s3", "SESSION_ARCHIVE_BUCKET": "b"}):
            with self.assertRaises(ValueError):
                arc.backend_from_env(env)


class Indices(unittest.TestCase):
    def test_in_process_definitions_equal_committed_json(self):
        for name, (body, schema) in sa.index_definitions().items():
            with open(os.path.join(HERE, "..", "es-indices-v2", f"{name}.json")) as fh:
                committed = json.load(fh)
            self.assertEqual(body, committed, name)
            self.assertEqual(committed["mappings"]["_meta"]["schema"], schema)
            self.assertEqual(committed["mappings"]["dynamic"], "strict")

    def test_setup_script_lists_both(self):
        with open(os.path.join(HERE, "..", "es-indices-v2", "setup_indices_v2.sh")) as fh:
            src = fh.read()
        self.assertIn("memory-session.json", src)
        self.assertIn("memory-session-message.json", src)
        self.assertNotIn('"${SESSION_INDEX}",   "alias"', src)

    def test_ensure_creates_checks_schema_and_tolerates_existing(self):
        FAKE.created.clear()
        asyncio.run(sa.ensure_session_indices())
        self.assertEqual(set(FAKE.created), {"memory-session", "memory-session-message"})
        self.assertEqual(FAKE.created["memory-session"]["settings"]["number_of_replicas"],
                         sa.SESSION_INDEX_REPLICAS)
        asyncio.run(sa.ensure_session_indices())  # already exists: fine
        FAKE.created["memory-session"]["mappings"]["_meta"]["schema"] = "session/0"
        with self.assertRaises(sa.SchemaMismatch):
            asyncio.run(sa.ensure_session_indices())
        FAKE.created.clear()


class _StubVoyage:
    """Installs a fake `voyage` module; counts provider calls."""

    def __init__(self):
        self.calls = 0

    def __enter__(self):
        mod = types.ModuleType("voyage")

        async def embed_documents(texts, batch=128):
            self.calls += 1
            return [[0.5] * 4 for _ in texts]

        mod.embed_documents = embed_documents
        sys.modules["voyage"] = mod
        return self

    def __exit__(self, *a):
        sys.modules.pop("voyage", None)


class Embedding(Base):
    def msg(self, uuid):
        for s, _ in FAKE.indices["memory-session-message"].values():
            if s["uuid"] == uuid:
                return s
        return None

    def test_conditional_update_attaches_vector(self):
        self.ingest(segment_body([line("u1", "embed me"), line("u2", "and me")], 0))
        self.assertEqual(len(self.embedded), 2)
        self.assertTrue(all(d["_seq_no"] is not None for d in self.embedded))
        with _StubVoyage():
            asyncio.run(sa._embed_docs(self.embedded))
        for u in ("u1", "u2"):
            self.assertEqual((self.msg(u)["embedding_status"], self.msg(u)["embedding"]),
                             ("done", [0.5] * 4))
        # bookkeeping keys never reach ES
        self.assertFalse([k for k in self.msg("u1") if k.startswith("_")])

    def test_deleted_doc_is_not_recreated(self):
        self.ingest(segment_body([line("u1", "x")], 0))
        FAKE.indices["memory-session-message"].clear()  # deleted by anyone, any way
        with _StubVoyage():
            asyncio.run(sa._embed_docs(self.embedded))
        self.assertEqual(FAKE.indices["memory-session-message"], {})

    def test_changed_doc_is_not_overwritten(self):
        b = segment_body([line("u1", "x")], 0)
        self.ingest(b)
        stale = list(self.embedded)
        self.ingest(b)  # a retry re-indexes the doc: new seq_no
        with _StubVoyage():
            asyncio.run(sa._embed_docs(stale))
        self.assertEqual(self.msg("u1")["embedding_status"], "pending")
        self.assertNotIn("embedding", self.msg("u1"))

    def test_purge_while_an_embed_batch_is_pending(self):
        sk = self.ingest(segment_body([line("u1", "x")], 0, host="air"), headers=AIR).json()["session_key"]
        pending = list(self.embedded)
        r = self.c.delete(PREFIX + "/session", params={"session_key": sk}, headers=AIR)
        self.assertEqual(r.status_code, 200)
        with _StubVoyage() as v:
            asyncio.run(sa._embed_docs(pending))
        self.assertEqual(v.calls, 0, "a purged session is not even sent to the provider")
        self.assertEqual(FAKE.indices["memory-session-message"], {})

    def test_embedding_queue_is_bounded(self):
        spawned = []
        saved_spawn, saved_max = sa._spawn, sa.EMBED_QUEUE_MAX_DOCS
        sa._spawn = lambda coro: (spawned.append(coro), coro.close())
        sa.EMBED_QUEUE_MAX_DOCS = 10
        try:
            docs = [{"_id": str(i), "text": "t", "session_key": "sk"} for i in range(6)]
            sa._schedule_embedding(docs)
            sa._schedule_embedding(docs)  # 12 > 10: not queued, stays pending
            self.assertEqual(len(spawned), 1)
            self.assertEqual(sa._EMBED_STATE, {"queued": 6, "dropped": 6})
            r = self.c.get(PREFIX + "/status", headers=PRO_DEV)
            self.assertEqual(r.json()["embedding_queue"], {"queued": 6, "dropped": 6})
        finally:
            sa._spawn, sa.EMBED_QUEUE_MAX_DOCS = saved_spawn, saved_max

    def test_queue_slot_is_released_after_the_batch(self):
        async def run():
            with _StubVoyage():
                sa._schedule_embedding([{"_id": "x", "text": "t", "session_key": "sk",
                                         "_seq_no": None}])
                self.assertEqual(sa._EMBED_STATE["queued"], 1)
                await asyncio.gather(*list(sa._BG_TASKS))
        asyncio.run(run())
        self.assertEqual(sa._EMBED_STATE["queued"], 0)


class PurgeRace(Base):
    def test_purge_between_parse_and_bulk(self):
        import httpx
        r1 = self.ingest(segment_body([line("u1", "first")], 0)).json()
        sk = r1["session_key"]
        reached, release = None, None
        real_bulk = sa._bulk_index

        async def slow_bulk(index, docs):
            if index == sa.MESSAGE_INDEX and any(d["uuid"] == "u2" for d in docs):
                reached.set()
                await release.wait()
            return await real_bulk(index, docs)

        async def run():
            nonlocal reached, release
            reached, release = asyncio.Event(), asyncio.Event()
            transport = httpx.ASGITransport(app=APP)
            async with httpx.AsyncClient(transport=transport, base_url="http://t") as client:
                ing = asyncio.ensure_future(client.post(
                    PREFIX + "/ingest", content=gz(segment_body([line("u2", "second")],
                                                                r1["next_offset"])),
                    headers=PRO_DEV))
                await asyncio.wait_for(reached.wait(), 5)  # parsed, bulk not yet written
                dele = asyncio.ensure_future(client.delete(
                    PREFIX + "/session", params={"session_key": sk}, headers=OPERATOR))
                await asyncio.sleep(0.2)
                blocked = not dele.done()
                release.set()
                return await ing, await dele, blocked

        sa._bulk_index = slow_bulk
        try:
            ing, dele, blocked = asyncio.run(run())
        finally:
            sa._bulk_index = real_bulk
        self.assertTrue(blocked, "the purge waits for the in-flight write phase")
        self.assertEqual(ing.status_code, 200, ing.text)
        self.assertEqual(dele.status_code, 200, dele.text)
        # nothing the in-flight ingest wrote survived the purge
        self.assertEqual(FAKE.indices["memory-session-message"], {})
        self.assertTrue(sa._is_purged_doc(self.session(sk)))
        self.assertEqual(self.store.objects, {})
        self.assertEqual(set(self.session(sk)), {"session_key", "host", "purged_at", "purged_by"})

    def purged_session(self):
        r = self.ingest(segment_body([line("u1", "x")], 0))
        sk = r.json()["session_key"]
        self.assertEqual(self.c.delete(PREFIX + "/session", params={"session_key": sk},
                                       headers=OPERATOR).status_code, 200)
        return sk

    def test_every_write_path_refuses_a_purged_key(self):
        sk = self.purged_session()
        r = self.ingest(segment_body([line("u1", "x")], 0))
        self.assertEqual((r.status_code, r.json()["error"]), (409, "purged"))
        r = self.c.post(PREFIX + "/state", json={"session_key": sk, "jsonl_exists": False},
                        headers=PRO_DEV)
        self.assertEqual((r.status_code, r.json()["error"]), (409, "purged"))
        content = "x"
        r = self.c.post(PREFIX + "/blob", content=gz({
            "session_key": sk, "name": "a.txt", "content": content,
            "sha256": hashlib.sha256(content.encode()).hexdigest()}), headers=PRO_DEV)
        self.assertEqual((r.status_code, r.json()["error"]), (409, "purged"))
        self.assertEqual(self.store.objects, {})

    def test_marker_survives_a_restart(self):
        sk = self.purged_session()
        sa._PURGED.clear()  # a new process: only the ES marker remains
        r = self.ingest(segment_body([line("u1", "x")], 0))
        self.assertEqual((r.status_code, r.json()["error"]), (409, "purged"))
        self.assertIn(sk, sa._PURGED)

    def test_operator_clears_the_marker(self):
        sk = self.purged_session()
        r = self.c.delete(PREFIX + "/purged", params={"session_key": sk}, headers=PRO_DEV)
        self.assertEqual(r.status_code, 403)  # pro-dev has no purge scope
        r = self.c.delete(PREFIX + "/purged", params={"session_key": sk}, headers=OPERATOR)
        self.assertEqual(r.json(), {"cleared": True})
        self.assertEqual(self.ingest(segment_body([line("u1", "x")], 0)).status_code, 200)
        r = self.c.delete(PREFIX + "/purged", params={"session_key": sk}, headers=OPERATOR)
        self.assertEqual(r.status_code, 404)

    def test_hostbound_operator_cannot_clear_another_hosts_marker(self):
        sk = self.purged_session()
        r = self.c.delete(PREFIX + "/purged", params={"session_key": sk}, headers=AIR)
        self.assertEqual((r.status_code, r.json()["error"]), (403, "host_mismatch"))


class CrossProcessInterleavings(Base):
    """The per-session lock only serializes one process. These drive another
    process's purge (sa._flip_purged + deletions, no lock) into the exact gaps
    of a writer, and assert the ES / storage guards alone keep the purge final."""

    def other_process_purge(self, sk, delete_objects=True):
        async def purge():
            await sa._flip_purged(sk)
            await sa._delete_messages(sk)
            if delete_objects:
                for name in await self.store.list(arc.object_name("pro-dev", sk)):
                    await self.store.delete(name)
        return purge()

    def test_purge_between_seq_read_and_write(self):
        r1 = self.ingest(segment_body([line("u1", "first")], 0)).json()
        sk = r1["session_key"]
        real = sa._bulk_index

        async def bulk_after_purge(index, docs):
            if index == sa.MESSAGE_INDEX and any(d["uuid"] == "u2" for d in docs):
                await self.other_process_purge(sk)  # flip + delete_by_query BEFORE our bulk
            return await real(index, docs)

        sa._bulk_index = bulk_after_purge
        try:
            r = self.ingest(segment_body([line("u2", "second")], r1["next_offset"]))
        finally:
            sa._bulk_index = real
        self.assertEqual((r.status_code, r.json()["error"]), (409, "purged"))
        # u2 was written after the purge's delete_by_query; only the writer's own
        # discard can have removed it
        self.assertEqual(FAKE.indices["memory-session-message"], {})
        self.assertTrue(sa._is_purged_doc(self.session(sk)))
        self.assertEqual(self.store.objects, {})
        self.assertFalse([d for d in self.embedded if d["uuid"] == "u2"], "nothing of a discarded batch is embedded")

    def test_purge_between_put_and_verify_ingest(self):
        r1 = self.ingest(segment_body([line("u1", "first")], 0)).json()
        sk = r1["session_key"]
        store, test = self.store, self
        real_put = store.put
        written, mark = [], []

        async def put_then_purge(name, data):
            await real_put(name, data)
            written.append(name)
            # the other purge listed the prefix BEFORE this object existed
            await test.other_process_purge(sk, delete_objects=False)
            mark.append(len(FAKE.calls))

        store.put = put_then_purge
        try:
            r = self.ingest(segment_body([line("u2", "second")], r1["next_offset"]))
        finally:
            store.put = real_put
        self.assertEqual((r.status_code, r.json()["error"]), (409, "purged"))
        self.assertEqual(len(written), 1)
        self.assertNotIn(written[0], self.store.objects, "verify deleted the straggler")
        self.assertFalse(any(s["uuid"] == "u2" for s, _ in
                             FAKE.indices.get("memory-session-message", {}).values()))
        # refused AT verify: after the PUT nothing but the verify read reached ES
        # (no bulk, no conditional session write)
        after = FAKE.calls[mark[0]:]
        self.assertEqual([c[:2] for c in after], [("GET", f"/memory-session/_doc/{sk}")])

    def test_purge_between_put_and_verify_blob(self):
        sk = self.ingest(segment_body([line("u1", "x")], 0)).json()["session_key"]
        real_put = self.store.put
        test = self

        mark = []

        async def put_then_purge(name, data):
            await real_put(name, data)
            await test.other_process_purge(sk, delete_objects=False)
            mark.append(len(FAKE.calls))

        self.store.put = put_then_purge
        content = "tool output"
        try:
            r = self.c.post(PREFIX + "/blob", content=gz({
                "session_key": sk, "name": "t.txt", "content": content,
                "sha256": hashlib.sha256(content.encode()).hexdigest()}), headers=PRO_DEV)
        finally:
            self.store.put = real_put
        self.assertEqual((r.status_code, r.json()["error"]), (409, "purged"))
        self.assertNotIn(f"sessions/pro-dev/{sk}/tool-results/t.txt.zst", self.store.objects)
        self.assertEqual([c[:2] for c in FAKE.calls[mark[0]:]],
                         [("GET", f"/memory-session/_doc/{sk}")],
                         "refused at verify, before the conditional session write")

    def test_purge_between_read_and_state_update(self):
        sk = self.ingest(segment_body([line("u1", "x")], 0)).json()["session_key"]
        real = sa._owned_session

        async def owned_then_purge(session_key, caller, **kw):
            got = await real(session_key, caller, **kw)
            await self.other_process_purge(sk)
            return got

        sa._owned_session = owned_then_purge
        try:
            r = self.c.post(PREFIX + "/state", json={"session_key": sk, "jsonl_exists": False},
                            headers=PRO_DEV)
        finally:
            sa._owned_session = real
        self.assertEqual((r.status_code, r.json()["error"]), (409, "purged"))
        doc = self.session(sk)
        self.assertTrue(sa._is_purged_doc(doc))
        self.assertNotIn("jsonl_checked_at", doc)

    def test_two_creators_of_a_new_session(self):
        real = sa._bulk_index
        sk = sa.make_session_key("pro-dev", PDIR, SID)

        async def bulk_while_other_creates(index, docs):
            if index == sa.MESSAGE_INDEX:
                FAKE.seq += 1
                FAKE._idx("memory-session")[sk] = ({"session_key": sk, "host": "pro-dev"}, FAKE.seq)
            return await real(index, docs)

        sa._bulk_index = bulk_while_other_creates
        try:
            r = self.ingest(segment_body([line("u1", "x")], 0))
        finally:
            sa._bulk_index = real
        self.assertEqual((r.status_code, r.json()["error"]), (503, "busy"))
        self.assertEqual(self.session(sk), {"session_key": sk, "host": "pro-dev"},
                         "the other creator's doc is never overwritten unconditionally")

    def test_session_doc_writes_are_never_unconditional(self):
        with open(os.path.join(HERE, "sessions_app.py")) as fh:
            src = fh.read()
        body = src[src.index("async def _put_session"):src.index("async def _update_session")]
        self.assertIn("if_seq_no", body)
        self.assertIn("/_create/", body)
        self.assertNotIn('f"/{SESSION_INDEX}/_doc/{session_key}"\n', body)


class FailClosed(Base):
    """An unreadable purge state aborts the write with 503 and leaves nothing
    behind; it is never read as "not purged"."""

    def first(self):
        r = self.ingest(segment_body([line("u1", "first")], 0)).json()
        return r["session_key"], r["next_offset"]

    def msgs(self):
        return {s["uuid"] for s, _ in FAKE.indices.get("memory-session-message", {}).values()}

    def test_purge_read_failure_at_ingest_start(self):
        sk, nxt = self.first()
        objects = dict(self.store.objects)
        for mode in ("5xx", "garbage"):
            with self.subTest(mode=mode):
                FAKE.fail[("GET", f"/memory-session/_doc/{sk}")] = mode
                r = self.ingest(segment_body([line("u2", "second")], nxt))
                self.assertEqual((r.status_code, r.json()["error"]), (503, "es_unavailable"))
                self.assertEqual(self.msgs(), {"u1"})
                self.assertEqual(self.store.objects, objects)
        FAKE.fail.clear()
        self.assertEqual(self.ingest(segment_body([line("u2", "second")], nxt)).status_code, 200)

    def test_verify_read_failure_deletes_the_object(self):
        sk, nxt = self.first()
        real_put = self.store.put
        written = []

        async def put_then_break(name, data):
            await real_put(name, data)
            written.append(name)
            FAKE.fail[("GET", f"/memory-session/_doc/{sk}")] = "5xx"

        self.store.put = put_then_break
        try:
            r = self.ingest(segment_body([line("u2", "second")], nxt))
        finally:
            self.store.put = real_put
        self.assertEqual((r.status_code, r.json()["error"]), (503, "es_unavailable"))
        self.assertNotIn(written[0], self.store.objects)
        self.assertEqual(self.msgs(), {"u1"})

    def test_session_doc_missing_where_expected(self):
        sk, nxt = self.first()
        real_put = self.store.put
        written = []

        async def put_then_vanish(name, data):
            await real_put(name, data)
            written.append(name)
            FAKE.indices["memory-session"].pop(sk)

        self.store.put = put_then_vanish
        try:
            r = self.ingest(segment_body([line("u2", "second")], nxt))
        finally:
            self.store.put = real_put
        self.assertEqual(r.status_code, 503)
        self.assertNotIn(written[0], self.store.objects)
        self.assertEqual(self.msgs(), {"u1"})

    def test_session_write_failure_discards(self):
        sk, nxt = self.first()
        FAKE.fail[("PUT", f"/memory-session/_doc/{sk}")] = "5xx"
        r = self.ingest(segment_body([line("u2", "second")], nxt))
        self.assertEqual((r.status_code, r.json()["error"]), (503, "es_unavailable"))
        self.assertEqual(self.msgs(), {"u1"})
        self.assertEqual(len(self.store.objects), 1, "the u2 chunk was deleted again")

    def test_conflict_with_unreadable_state_discards(self):
        sk, nxt = self.first()
        real = sa._bulk_index

        async def bulk_then_bump(index, docs):
            res = await real(index, docs)
            if index == sa.MESSAGE_INDEX:
                src, _ = FAKE.indices["memory-session"][sk]
                FAKE.seq += 1
                FAKE.indices["memory-session"][sk] = (dict(src), FAKE.seq)  # someone wrote
                FAKE.fail[("GET", f"/memory-session/_doc/{sk}")] = "5xx"   # and ES is down
            return res

        sa._bulk_index = bulk_then_bump
        try:
            r = self.ingest(segment_body([line("u2", "second")], nxt))
        finally:
            sa._bulk_index = real
        self.assertEqual(r.status_code, 503)
        self.assertEqual(self.msgs(), {"u1"})

    def test_blob_verify_failure_deletes_the_object(self):
        sk, _ = self.first()
        real_put = self.store.put

        async def put_then_break(name, data):
            await real_put(name, data)
            FAKE.fail[("GET", f"/memory-session/_doc/{sk}")] = "5xx"

        self.store.put = put_then_break
        content = "out"
        try:
            r = self.c.post(PREFIX + "/blob", content=gz({
                "session_key": sk, "name": "b.txt", "content": content,
                "sha256": hashlib.sha256(content.encode()).hexdigest()}), headers=PRO_DEV)
        finally:
            self.store.put = real_put
        self.assertEqual(r.status_code, 503)
        self.assertNotIn(f"sessions/pro-dev/{sk}/tool-results/b.txt.zst", self.store.objects)

    def test_bulk_failure_racing_a_purge_discards(self):
        sk, nxt = self.first()
        real = sa._bulk_index
        test = self

        async def purge_then_fail(index, docs):
            if index == sa.MESSAGE_INDEX:
                await sa._flip_purged(sk)
                await sa._delete_messages(sk)
                raise sa.ESUnavailable("bulk: 503")
            return await real(index, docs)

        sa._bulk_index = purge_then_fail
        try:
            r = self.ingest(segment_body([line("u2", "second")], nxt))
        finally:
            sa._bulk_index = real
        self.assertEqual(r.status_code, 503)
        u2_chunk = arc.object_name("pro-dev", sk, generation=0, offset=nxt)
        test.assertNotIn(u2_chunk, self.store.objects)

    def test_bulk_failure_on_a_live_session_is_retryable(self):
        sk, nxt = self.first()
        real = sa._bulk_index
        calls = []

        async def fail_once(index, docs):
            if index == sa.MESSAGE_INDEX and not calls:
                calls.append(1)
                raise sa.ESUnavailable("bulk: 503")
            return await real(index, docs)

        sa._bulk_index = fail_once
        try:
            b = segment_body([line("u2", "second")], nxt)
            self.assertEqual(self.ingest(b).status_code, 503)
            self.assertEqual(self.ingest(b).status_code, 200)
        finally:
            sa._bulk_index = real
        self.assertEqual(self.msgs(), {"u1", "u2"})
        r = self.c.get(PREFIX + "/archive", params={"session_key": sk}, headers=AIR)
        self.assertEqual(r.status_code, 200)

    def test_incomplete_mark_never_touches_a_purged_marker(self):
        sk, _ = self.first()
        src, seq = FAKE.indices["memory-session"][sk]
        asyncio.run(sa._flip_purged(sk, "operator@example.com"))
        asyncio.run(sa._mark_incomplete(src, seq, 1))  # stale version: dropped
        self.assertEqual(set(self.session(sk)), {"session_key", "host", "purged_at", "purged_by"})

    def test_purge_read_failure_aborts_the_purge(self):
        sk, _ = self.first()
        FAKE.fail[("GET", f"/memory-session/_doc/{sk}")] = "garbage"
        r = self.c.delete(PREFIX + "/session", params={"session_key": sk}, headers=OPERATOR)
        self.assertEqual(r.status_code, 503)
        FAKE.fail.clear()
        self.assertFalse(sa._is_purged_doc(self.session(sk)))
        self.assertEqual(self.msgs(), {"u1"})


class PurgedMarker(Base):
    def test_marker_keeps_nothing_transcript_derived(self):
        lines = [line("u1", "secret project plans"),
                 json.dumps({"type": "ai-title", "aiTitle": "Plans for the merger"})]
        sk = self.ingest(segment_body(lines, 0)).json()["session_key"]
        content = "tool output"
        self.c.post(PREFIX + "/blob", content=gz({
            "session_key": sk, "name": "t.txt", "content": content,
            "sha256": hashlib.sha256(content.encode()).hexdigest()}), headers=PRO_DEV)
        before = self.session(sk)
        self.assertEqual(before["title"], "Plans for the merger")
        with _StubVoyage():
            asyncio.run(sa._embed_docs(self.embedded))
        self.assertTrue(any("embedding" in s for s, _ in FAKE.indices["memory-session-message"].values()))
        r = self.c.delete(PREFIX + "/session", params={"session_key": sk}, headers=OPERATOR)
        self.assertEqual(r.status_code, 200)
        doc = self.session(sk)
        self.assertEqual(set(doc), {"session_key", "host", "purged_at", "purged_by"})
        self.assertEqual(doc["purged_by"], "operator@example.com")
        dumped = json.dumps(doc)
        for leaked in ("Plans", "secret", "/home/dev", PDIR, SID, "t.txt"):
            self.assertNotIn(leaked, dumped)
        # message docs, and their vectors with them, are gone; so are objects
        self.assertEqual(FAKE.indices["memory-session-message"], {})
        self.assertEqual(self.store.objects, {})
        mapping = sa.index_definitions()["memory-session"][0]["mappings"]["properties"]
        self.assertEqual((mapping["purged_at"]["type"], mapping["purged_by"]["type"]), ("date", "keyword"))

    def test_status_and_downloads_never_expose_a_purged_session(self):
        sk = self.ingest(segment_body([line("u1", "x")], 0)).json()["session_key"]
        self.ingest(segment_body([line("u1", "y")], 0, sid="bbbbbbbb-bbbb-cccc-dddd-eeeeeeeeeeee"))
        self.c.delete(PREFIX + "/session", params={"session_key": sk}, headers=OPERATOR)
        st = self.c.get(PREFIX + "/status", headers=PRO_DEV).json()
        self.assertEqual((st["sessions"], st["purged_markers"]), (1, 1))
        self.assertNotIn("title", json.dumps(st))
        for path in ("/archive", "/archive/tool-results"):
            r = self.c.get(PREFIX + path, params={"session_key": sk}, headers=AIR)
            self.assertEqual(r.status_code, 404, path)


class Bounds(unittest.TestCase):
    def test_queue_full_is_503(self):
        async def run():
            s = sa._Slots(size=1, max_waiters=1, per_caller=5, wait_s=5)
            a = s.hold("a")
            await a.__aenter__()
            waiter = asyncio.ensure_future(s.hold("b").__aenter__())
            await asyncio.sleep(0.05)
            self.assertEqual(s.waiters, 1)
            with self.assertRaises(sa.HTTPError) as ctx:
                await s.hold("c").__aenter__()
            self.assertEqual((ctx.exception.status, ctx.exception.extra["reason"]), (503, "queue_full"))
            await a.__aexit__(None, None, None)
            b = await asyncio.wait_for(waiter, 1)
            self.assertEqual(s.active, 1)
            await b.__aexit__(None, None, None)
            self.assertEqual((s.active, s.waiters, s.by_caller), (0, 0, {}))
        asyncio.run(run())

    def test_wait_is_bounded(self):
        async def run():
            s = sa._Slots(size=1, max_waiters=4, per_caller=5, wait_s=0.1)
            a = s.hold("a")
            await a.__aenter__()
            with self.assertRaises(sa.HTTPError) as ctx:
                await s.hold("b").__aenter__()
            self.assertEqual(ctx.exception.extra["reason"], "wait_timeout")
            self.assertEqual((s.waiters, set(s.by_caller)), (0, {"a"}))
            await a.__aexit__(None, None, None)
        asyncio.run(run())

    def test_per_caller_limit(self):
        async def run():
            s = sa._Slots(size=2, max_waiters=4, per_caller=1, wait_s=5)
            x = s.hold("x")
            await x.__aenter__()
            with self.assertRaises(sa.HTTPError) as ctx:
                await s.hold("x").__aenter__()
            self.assertEqual(ctx.exception.extra["reason"], "caller_concurrency")
            y = s.hold("y")
            await y.__aenter__()  # another caller still gets the second slot
            await x.__aexit__(None, None, None)
            await y.__aexit__(None, None, None)
            self.assertEqual(s.by_caller, {})
        asyncio.run(run())

    def test_production_limits(self):
        self.assertEqual((sa.SEGMENT_CONCURRENCY, sa.SEGMENT_PER_CALLER), (2, 1))
        self.assertLessEqual(sa.SEGMENT_MAX_WAITERS, 8)
        self.assertLessEqual(sa.SEGMENT_WAIT_S, 30)

    def test_one_caller_cannot_hold_both_slots_over_http(self):
        import httpx
        gate_open = None
        real = sa._scan_segment

        def slow_scan(lines, version, deadline=None):
            import time as _t
            _t.sleep(0.4)
            return real(lines, version, None)

        async def run():
            transport = httpx.ASGITransport(app=APP)
            async with httpx.AsyncClient(transport=transport, base_url="http://t") as client:
                b1 = gz(segment_body([line("u1", "x")], 0))
                b2 = gz(segment_body([line("u1", "x")], 0, sid="bbbbbbbb-bbbb-cccc-dddd-eeeeeeeeeeee"))
                first = asyncio.ensure_future(client.post(PREFIX + "/ingest", content=b1, headers=PRO_DEV))
                await asyncio.sleep(0.1)
                second = await client.post(PREFIX + "/ingest", content=b2, headers=PRO_DEV)
                other = await client.post(PREFIX + "/ingest", content=gz(segment_body(
                    [line("u1", "x")], 0, host="air")), headers=AIR)
                return await first, second, other

        FAKE.indices.clear()
        sa._ARCHIVE["backend"] = arc.MemoryBackend()
        sa._STATE["ready"] = True
        sa.EMBED_SCHEDULER = lambda docs: None
        saved = sa._run_bounded

        async def bounded(fn, *args, **kw):
            if fn is sa._scan_segment:
                return await asyncio.to_thread(slow_scan, *args)
            return await saved(fn, *args, **kw)

        sa._run_bounded = bounded
        try:
            first, second, other = asyncio.run(run())
        finally:
            sa._run_bounded = saved
        self.assertEqual(first.status_code, 200, first.text)
        self.assertEqual((second.status_code, second.json()["reason"]), (503, "caller_concurrency"))
        self.assertEqual(other.status_code, 200, other.text)


class ServerWiring(unittest.TestCase):
    def test_sessions_mount_precedes_memory_mount(self):
        with open(os.path.join(HERE, "server.py")) as fh:
            src = fh.read()
        a = src.index('Mount("/memory/sessions/v1", app=sessions_app.app)')
        b = src.index('Mount("/memory", app=mcp.streamable_http_app())')
        self.assertLess(a, b)
        self.assertIn("sessions_app.start_background()", src)

    def test_parse_and_redact_versions_exposed(self):
        self.assertEqual(sessions_parse.PARSER_VERSION, "p1")
        self.assertEqual(session_redact.RULESET_VERSION, "r1")


if __name__ == "__main__":
    unittest.main(verbosity=1)
