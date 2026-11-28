"""In-process fake backends for the round-trip suite (standard library only).

Every fake records the requests it receives, so a case can compare what an
implementation SENT (contract C-ES-2, C-EMB-1, C-HTTP-7) as well as what it
answered. Behaviour switches (`mode`) let one case make a backend fail, stall
or redirect without restarting anything.

FakeES is a small evaluator for exactly the query shapes memory-mcp issues
(bool/match/term/terms/exists/ids/knn, sort, size, _source, the three painless
scripts). It is not a general Elasticsearch: an unknown shape answers 400 so a
new query is noticed rather than silently matched.
"""

from __future__ import annotations

import base64
import hashlib
import json
import math
import re
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit


class Recorded:
    def __init__(self, method, raw_path, headers, body):
        self.method = method
        self.raw_path = raw_path
        parts = urlsplit(raw_path)
        self.path = parts.path
        self.query = {k: v[-1] for k, v in parse_qs(parts.query, keep_blank_values=True).items()}
        self.headers = headers  # list of (name, value) as received
        self.body = body
        self.at = time.monotonic()

    def header(self, name):
        for k, v in self.headers:
            if k.lower() == name.lower():
                return v
        return None

    def json(self):
        try:
            return json.loads(self.body) if self.body else None
        except ValueError:
            return None


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_args):  # keep the suite's stdout to case lines
        pass

    def _dispatch(self):
        length = self.headers.get("Content-Length")
        if self.headers.get("Transfer-Encoding", "").lower() == "chunked":
            body = bytearray()
            while True:
                size = int(self.rfile.readline().strip() or b"0", 16)
                if size == 0:
                    self.rfile.readline()
                    break
                body += self.rfile.read(size)
                self.rfile.readline()
            body = bytes(body)
        else:
            body = self.rfile.read(int(length)) if length else b""
        rec = Recorded(self.command, self.path, list(self.headers.items()), body)
        fake = self.server.fake
        with fake.lock:
            fake.requests.append(rec)
        try:
            fake.handle(self, rec)
        except (BrokenPipeError, ConnectionResetError):
            fake.note_disconnect(rec)

    do_GET = do_POST = do_PUT = do_DELETE = do_HEAD = do_OPTIONS = do_PATCH = _dispatch

    def reply(self, status, obj=None, *, body=None, ctype="application/json", headers=None):
        if body is None:
            body = b"" if obj is None else json.dumps(obj).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)


class Fake:
    name = "fake"

    def __init__(self):
        self.lock = threading.RLock()
        self.requests: list[Recorded] = []
        self.mode: dict = {}
        self.disconnects: list[Recorded] = []
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self.httpd.daemon_threads = True
        self.httpd.fake = self
        self.port = self.httpd.server_address[1]
        self.url = f"http://127.0.0.1:{self.port}"
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    def note_disconnect(self, rec):
        with self.lock:
            self.disconnects.append(rec)

    def clear(self):
        with self.lock:
            self.requests.clear()
            self.disconnects.clear()

    def taken(self, pred=lambda r: True):
        with self.lock:
            return [r for r in self.requests if pred(r)]

    def wait_for(self, pred, timeout=5.0):
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            got = self.taken(pred)
            if got:
                return got
            time.sleep(0.02)
        return []

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()

    def handle(self, h, rec):  # pragma: no cover - overridden
        h.reply(404, {"error": "no handler"})


# --------------------------------------------------------------------------- #
# Elasticsearch
# --------------------------------------------------------------------------- #
def _get_path(src, dotted):
    cur = src
    for part in dotted.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur


def _set_path(src, dotted, value):
    parts = dotted.split(".")
    cur = src
    for part in parts[:-1]:
        cur = cur.setdefault(part, {})
    cur[parts[-1]] = value


class QueryShapeError(ValueError):
    pass


def _tokens(text):
    return [t for t in re.split(r"\W+", str(text).lower()) if t]


class FakeES(Fake):
    """mode keys: deny_create (PUT index / _aliases answer 403),
    missing (set of index names HEAD/PUT treat as absent and uncreatable),
    delay ((path substring, seconds) to stall matching requests), down (503)."""

    name = "es"
    CONTENT_ALIAS_MEMBERS = None  # set from the first POST /_aliases

    def __init__(self):
        super().__init__()
        self.indices: dict[str, dict] = {}   # name -> {"def": body, "docs": {id: src}, "seq": {id: (seq, term)}}
        self.aliases: dict[str, list[str]] = {}
        self.counter = 0
        self.seq_no = 0

    # -- helpers ---------------------------------------------------------- #
    def reset_data(self):
        with self.lock:
            for idx in self.indices.values():
                idx["docs"].clear()
                idx["seq"].clear()
            self.counter = 0

    def seed(self, index, doc_id, src):
        with self.lock:
            self.indices.setdefault(index, {"def": None, "docs": {}, "seq": {}})
            self.indices[index]["docs"][doc_id] = json.loads(json.dumps(src))
            self._bump_seq(index, doc_id)

    def _bump_seq(self, index, doc_id):
        self.seq_no += 1
        self.indices[index]["seq"][doc_id] = (self.seq_no, 1)

    def _new_id(self):
        self.counter += 1
        return f"es{self.counter:05d}"

    def _resolve(self, name):
        if name in self.aliases:
            return [n for n in self.aliases[name] if n in self.indices]
        return [name] if name in self.indices else []

    # -- query evaluation ------------------------------------------------- #
    def _match(self, q, src, _id):
        """(matches, score)."""
        if not isinstance(q, dict) or len(q) != 1:
            raise QueryShapeError(f"query clause {q!r}")
        (kind, arg), = q.items()
        if kind == "match_all":
            return True, 1.0
        if kind == "bool":
            score = 0.0
            for key in ("must", "filter"):
                clauses = arg.get(key, [])
                for c in clauses if isinstance(clauses, list) else [clauses]:
                    ok, s = self._match(c, src, _id)
                    if not ok:
                        return False, 0.0
                    if key == "must":
                        score += s
            nots = arg.get("must_not", [])
            for c in nots if isinstance(nots, list) else [nots]:
                if self._match(c, src, _id)[0]:
                    return False, 0.0
            shoulds = arg.get("should", [])
            if shoulds:
                hit = [self._match(c, src, _id) for c in shoulds]
                if not any(ok for ok, _ in hit) and not arg.get("must") and not arg.get("filter"):
                    return False, 0.0
                msm = arg.get("minimum_should_match")
                if msm is not None and sum(1 for ok, _ in hit if ok) < int(msm):
                    return False, 0.0
                score += sum(s for ok, s in hit if ok)
            unknown = set(arg) - {"must", "filter", "must_not", "should", "minimum_should_match"}
            if unknown:
                raise QueryShapeError(f"bool keys {sorted(unknown)}")
            return True, score or 1.0
        if kind == "match":
            (field, value), = arg.items()
            if isinstance(value, dict):
                value = value.get("query", "")
            text = str(_get_path(src, field) or "").lower()
            hits = sum(text.count(t) for t in _tokens(value))
            return hits > 0, float(hits)
        if kind == "term":
            (field, value), = arg.items()
            if isinstance(value, dict):
                value = value.get("value")
            have = _get_path(src, field)
            ok = value in have if isinstance(have, list) else have == value
            return ok, 1.0
        if kind == "terms":
            (field, values), = arg.items()
            have = _get_path(src, field)
            have = have if isinstance(have, list) else [have]
            return any(v in have for v in values), 1.0
        if kind == "multi_match":
            # best_fields: a field matches when it holds the query's tokens (all of
            # them with operator "and"); the score is the best field's boosted hits.
            tokens = _tokens(arg["query"])
            best, ok_any = 0.0, False
            for spec in arg.get("fields", []):
                field, _, boost = spec.partition("^")
                have = _tokens(_get_path(src, field) or "")
                present = [t for t in tokens if t in have]
                ok = bool(tokens) and (len(present) == len(tokens) if arg.get("operator") == "and" else bool(present))
                if ok:
                    ok_any = True
                    best = max(best, float(boost or 1) * sum(have.count(t) for t in tokens))
            return ok_any, best
        if kind == "prefix":
            (field, value), = arg.items()
            if isinstance(value, dict):
                value = value.get("value")
            have = _get_path(src, field)
            return isinstance(have, str) and have.startswith(value), 1.0
        if kind == "exists":
            v = _get_path(src, arg["field"])
            return v is not None and v != [], 1.0
        if kind == "ids":
            return _id in arg["values"], 1.0
        if kind == "range":
            (field, cond), = arg.items()
            v = _get_path(src, field)
            if v is None:
                return False, 0.0
            for op, bound in cond.items():
                if op == "lt" and not v < bound or op == "lte" and not v <= bound \
                        or op == "gt" and not v > bound or op == "gte" and not v >= bound:
                    return False, 0.0
            return True, 1.0
        raise QueryShapeError(f"query kind {kind!r}")

    def _search(self, names, body):
        body = body or {}
        rows = []
        order = 0
        for name in names:
            for _id, src in self.indices[name]["docs"].items():
                rows.append((name, _id, src, order))
                order += 1
        size = body.get("size", 10)
        if "knn" in body:
            knn = body["knn"]
            qv = knn["query_vector"]
            out = []
            for name, _id, src, o in rows:
                flt = knn.get("filter") or []
                if all(self._match(c, src, _id)[0] for c in (flt if isinstance(flt, list) else [flt])):
                    vec = src.get(knn["field"])
                    if vec:
                        out.append((name, _id, src, o, _cosine(qv, vec)))
            out.sort(key=lambda r: (-r[4], r[3]))
            out = out[:knn.get("k", size)]
        else:
            q = body.get("query", {"match_all": {}})
            out = []
            for name, _id, src, o in rows:
                ok, score = self._match(q, src, _id)
                if ok:
                    out.append((name, _id, src, o, score))
            sort = body.get("sort")
            if sort:
                for spec in reversed(sort):
                    (field, how), = spec.items() if isinstance(spec, dict) else ((spec, "asc"),)
                    direction = how.get("order", "asc") if isinstance(how, dict) else how
                    out.sort(key=lambda r: (_get_path(r[2], field) is None, _get_path(r[2], field) or 0),
                             reverse=(direction == "desc"))
            else:
                out.sort(key=lambda r: (-r[4], r[3]))
        unknown = set(body) - {"size", "_source", "query", "knn", "sort", "seq_no_primary_term", "from",
                               "track_total_hits", "collapse", "aggs", "highlight"}
        if unknown:
            raise QueryShapeError(f"search keys {sorted(unknown)}")
        if body.get("collapse"):
            field, seen, kept = body["collapse"]["field"], set(), []
            for row in out:
                v = _get_path(row[2], field)
                if v not in seen:
                    seen.add(v)
                    kept.append(row)
            out = kept
        total = len(out)
        hits = []
        hl = body.get("highlight")
        tokens = _tokens(_query_text(body.get("query"))) if hl else []
        for name, _id, src, _o, score in out[:size]:
            hit = {"_index": name, "_id": _id, "_score": score,
                   "_source": _project(src, body.get("_source"))}
            if body.get("seq_no_primary_term"):
                hit["_seq_no"], hit["_primary_term"] = self.indices[name]["seq"].get(_id, (0, 1))
            if hl:
                frags = {}
                for field in hl.get("fields", {}):
                    text = _get_path(src, field)
                    if isinstance(text, str) and any(t in _tokens(text) for t in tokens):
                        marked = re.sub(r"\w+", lambda m: f"<em>{m.group(0)}</em>"
                                        if m.group(0).lower() in tokens else m.group(0), text)
                        frags[field] = [marked[:hl.get("fragment_size", 100) * 2]]
                if frags:
                    hit["highlight"] = frags
            hits.append(hit)
        res = {"took": 1, "timed_out": False,
               "hits": {"total": {"value": total, "relation": "eq"}, "max_score": None, "hits": hits}}
        if body.get("aggs"):
            res["aggregations"] = {}
            for agg_name, spec in body["aggs"].items():
                if set(spec) != {"terms"}:
                    raise QueryShapeError(f"aggregation {sorted(spec)}")
                counts: dict = {}
                for row in out:
                    v = _get_path(row[2], spec["terms"]["field"])
                    counts[v] = counts.get(v, 0) + 1
                buckets = sorted(({"key": k, "doc_count": n} for k, n in counts.items()),
                                 key=lambda b: (-b["doc_count"], str(b["key"])))
                res["aggregations"][agg_name] = {"buckets": buckets[:spec["terms"].get("size", 10)]}
        return res

    def _apply_script(self, src, script):
        source = script.get("source", "")
        params = script.get("params", {})
        if "superseded_by = params.sb" in source:
            src["superseded_by"] = params["sb"]
            src["superseded_at"] = params["at"]
        elif "tags.contains" in source:
            tags = src.get("tags") or []
            for t in params["tags"]:
                if t not in tags:
                    tags.append(t)
            src["tags"] = tags
        elif "use_count" in source and "last_used_at" in source:
            src["use_count"] = (src.get("use_count") or 0) + 1
            src["last_used_at"] = params["now"]
        else:
            raise QueryShapeError(f"script {source[:60]!r}")

    # -- dispatch --------------------------------------------------------- #
    def hold(self, pred):
        """Stop the next request matching pred(rec) until release() (C-SES-9's
        competing writer). arrived is set while it is held."""
        with self.lock:
            self._hold = {"pred": pred, "arrived": threading.Event(), "go": threading.Event()}
            return self._hold

    def release(self):
        with self.lock:
            h, self._hold = getattr(self, "_hold", None), None
        if h:
            h["go"].set()

    def handle(self, h, rec):
        with self.lock:
            gate = getattr(self, "_hold", None)
            hit = gate is not None and not gate["arrived"].is_set() and gate["pred"](rec)
            if hit:
                gate["arrived"].set()
        if hit:
            gate["go"].wait(30)
        delay = self.mode.get("delay")
        if delay and delay[0] in rec.path:
            time.sleep(delay[1])
        if self.mode.get("down"):
            h.reply(503, {"error": "fake es down"})
            return
        try:
            with self.lock:
                status, obj = self._route(rec)
        except QueryShapeError as exc:
            status, obj = 400, {"error": {"type": "fake_es_unsupported", "reason": str(exc)}}
        h.reply(status, obj)

    def _route(self, rec):
        m, path, body = rec.method, rec.path, rec.json()
        parts = [p for p in path.split("/") if p]
        missing = self.mode.get("missing", set())
        if m == "POST" and parts == ["_bulk"]:
            return self._bulk(rec.body)
        if m == "POST" and parts == ["_aliases"]:
            if self.mode.get("deny_create"):
                return 403, {"error": {"type": "security_exception"}}
            for act in body["actions"]:
                add = act["add"]
                members = self.aliases.setdefault(add["alias"], [])
                if add["index"] not in members:
                    members.append(add["index"])
            return 200, {"acknowledged": True}
        if m == "GET" and len(parts) == 2 and parts[0] == "_alias":
            out = {i: {"aliases": {parts[1]: {}}} for i in self.aliases.get(parts[1], []) if i in self.indices}
            return (200, out) if out else (404, {"error": "alias missing", "status": 404})
        if len(parts) == 1:
            name = parts[0]
            if m == "HEAD":
                return (200, None) if name in self.indices and name not in missing else (404, None)
            if m == "PUT":
                if self.mode.get("deny_create") or name in missing:
                    return 403, {"error": {"type": "security_exception",
                                           "reason": "action [indices:admin/create] is unauthorized"}}
                if name in self.indices and self.indices[name]["def"] is not None:
                    return 400, {"error": {"type": "resource_already_exists_exception"}}
                existing = self.indices.get(name, {"docs": {}, "seq": {}})
                self.indices[name] = {"def": body, "docs": existing["docs"], "seq": existing["seq"]}
                return 200, {"acknowledged": True, "index": name}
        if len(parts) >= 2:
            names = self._resolve(parts[0])
            op = parts[1]
            if op == "_mapping" and m == "GET":
                if not names:
                    return 404, {"error": "no such index"}
                return 200, {n: {"mappings": (self.indices[n]["def"] or {}).get("mappings", {})} for n in names}
            if op == "_mget" and m in ("POST", "GET"):
                fields = rec.query.get("_source")
                spec = fields.split(",") if fields else None
                docs = []
                for _id in body["ids"]:
                    src = next((self.indices[n]["docs"][_id] for n in names if _id in self.indices[n]["docs"]), None)
                    docs.append({"_index": parts[0], "_id": _id, "found": src is not None,
                                 **({"_source": _project(src, spec)} if src is not None else {})})
                return 200, {"docs": docs}
            if op == "_search":
                if not names:
                    return 404, {"error": {"type": "index_not_found_exception"}}
                return 200, self._search(names, body)
            if op == "_count":
                if not names:
                    return 404, {"error": {"type": "index_not_found_exception"}}
                res = self._search(names, {**(body or {}), "size": 0})
                return 200, {"count": res["hits"]["total"]["value"]}
            if op == "_update_by_query":
                q = (body or {}).get("query", {"match_all": {}})
                updated = 0
                for n in names:
                    for _id, src in self.indices[n]["docs"].items():
                        if self._match(q, src, _id)[0]:
                            self._apply_script(src, body["script"])
                            self._bump_seq(n, _id)
                            updated += 1
                return 200, {"updated": updated, "total": updated, "failures": []}
            if op == "_doc":
                if not names and m != "POST" and m != "PUT":
                    return 404, {"found": False}
                name = names[0] if names else parts[0]
                self.indices.setdefault(name, {"def": None, "docs": {}, "seq": {}})
                idx = self.indices[name]
                if m == "POST" and len(parts) == 2:
                    _id = self._new_id()
                    idx["docs"][_id] = body
                    self._bump_seq(name, _id)
                    return 201, {"_index": name, "_id": _id, "result": "created"}
                _id = parts[2]
                if m == "PUT":
                    if "if_seq_no" in rec.query:
                        cur = idx["seq"].get(_id)
                        if cur is None or str(cur[0]) != rec.query["if_seq_no"]:
                            return 409, {"error": {"type": "version_conflict_engine_exception"}}
                    if rec.query.get("op_type") == "create" and _id in idx["docs"]:
                        return 409, {"error": {"type": "version_conflict_engine_exception"}}
                    created = _id not in idx["docs"]
                    idx["docs"][_id] = body
                    self._bump_seq(name, _id)
                    return (201 if created else 200), {"_index": name, "_id": _id,
                                                       "result": "created" if created else "updated"}
                if m == "GET":
                    if _id not in idx["docs"]:
                        return 404, {"_index": name, "_id": _id, "found": False}
                    seq, term = idx["seq"][_id]
                    return 200, {"_index": name, "_id": _id, "found": True, "_seq_no": seq,
                                 "_primary_term": term, "_source": idx["docs"][_id]}
                if m == "DELETE":
                    idx["seq"].pop(_id, None)
                    existed = idx["docs"].pop(_id, None) is not None
                    return (200 if existed else 404), {"result": "deleted" if existed else "not_found"}
            if op == "_create" and m == "PUT":
                name = names[0] if names else parts[0]
                idx = self.indices.setdefault(name, {"def": None, "docs": {}, "seq": {}})
                _id = parts[2]
                if _id in idx["docs"]:
                    return 409, {"error": {"type": "version_conflict_engine_exception"}}
                idx["docs"][_id] = body
                self._bump_seq(name, _id)
                return 201, {"_index": name, "_id": _id, "result": "created"}
            if op in ("_update", "_doc") and "if_seq_no" in rec.query and len(parts) == 3:
                name = names[0] if names else parts[0]
                cur = self.indices.get(name, {"seq": {}})["seq"].get(parts[2])
                if cur is None or str(cur[0]) != rec.query["if_seq_no"] \
                        or str(cur[1]) != rec.query.get("if_primary_term", str(cur[1])):
                    return 409, {"error": {"type": "version_conflict_engine_exception"}}
            if op == "_update" and m == "POST":
                name = names[0] if names else parts[0]
                idx = self.indices.setdefault(name, {"def": None, "docs": {}, "seq": {}})
                _id = parts[2]
                if _id not in idx["docs"]:
                    if body.get("upsert") is not None:
                        idx["docs"][_id] = body["upsert"]
                        self._bump_seq(name, _id)
                        return 201, {"_id": _id, "result": "created"}
                    return 404, {"error": {"type": "document_missing_exception"}}
                if "doc" in body:
                    idx["docs"][_id].update(body["doc"])
                else:
                    self._apply_script(idx["docs"][_id], body["script"])
                self._bump_seq(name, _id)
                return 200, {"_id": _id, "result": "updated"}
            if op == "_delete_by_query":
                q = (body or {}).get("query", {"match_all": {}})
                deleted = 0
                for n in names:
                    for _id in [i for i, s in self.indices[n]["docs"].items() if self._match(q, s, i)[0]]:
                        del self.indices[n]["docs"][_id]
                        deleted += 1
                return 200, {"deleted": deleted, "failures": []}
        raise QueryShapeError(f"{m} {path}")

    def _bulk(self, raw):
        lines = [ln for ln in raw.decode("utf-8").split("\n") if ln.strip()]
        items = []
        i = 0
        while i < len(lines):
            meta = json.loads(lines[i])
            (action, spec), = meta.items()
            name = spec["_index"]
            idx = self.indices.setdefault(name, {"def": None, "docs": {}, "seq": {}})
            if action == "delete":
                idx["docs"].pop(spec["_id"], None)
                items.append({"delete": {"_id": spec["_id"], "status": 200}})
                i += 1
                continue
            src = json.loads(lines[i + 1])
            _id = spec.get("_id") or self._new_id()
            if "if_seq_no" in spec:
                cur = idx["seq"].get(_id)
                if cur is None or cur[0] != spec["if_seq_no"]:
                    items.append({action: {"_index": name, "_id": _id, "status": 409,
                                           "error": {"type": "version_conflict_engine_exception"}}})
                    i += 2
                    continue
            if action == "update":
                if _id in idx["docs"]:
                    idx["docs"][_id].update(src.get("doc", {}))
                elif src.get("doc_as_upsert"):
                    idx["docs"][_id] = src.get("doc", {})
            else:
                idx["docs"][_id] = src
            self._bump_seq(name, _id)
            items.append({action: {"_index": name, "_id": _id, "status": 201}})
            i += 2
        return 200, {"took": 1, "errors": any("error" in next(iter(it.values())) for it in items),
                     "items": items}


def _query_text(q):
    """The free text of the multi_match/match clauses in a query (for highlight)."""
    if isinstance(q, dict):
        for kind, arg in q.items():
            if kind == "multi_match":
                return arg.get("query", "")
            if kind == "match":
                (_f, v), = arg.items()
                return v.get("query", "") if isinstance(v, dict) else v
            found = _query_text(arg)
            if found:
                return found
    if isinstance(q, list):
        for c in q:
            found = _query_text(c)
            if found:
                return found
    return ""


def _cosine(a, b):
    num = sum(x * y for x, y in zip(a, b))
    da = math.sqrt(sum(x * x for x in a)) or 1.0
    db = math.sqrt(sum(y * y for y in b)) or 1.0
    return num / (da * db)


def _project(src, spec):
    if spec is None or spec is True:
        return json.loads(json.dumps(src))
    if isinstance(spec, list):
        return {k: json.loads(json.dumps(src[k])) for k in spec if k in src}
    if isinstance(spec, dict) and "excludes" in spec:
        return {k: json.loads(json.dumps(v)) for k, v in src.items() if k not in spec["excludes"]}
    return json.loads(json.dumps(src))


# --------------------------------------------------------------------------- #
# Embeddings (Voyage native and OpenAI-compatible)
# --------------------------------------------------------------------------- #
def embed(text: str, dims: int) -> list[float]:
    """Deterministic bag-of-words vector: texts that share words are close, so
    the kNN leg ranks the same way on every implementation."""
    vec = [0.0] * dims
    for tok in _tokens(text) or ["_empty_"]:
        h = int.from_bytes(hashlib.sha256(tok.encode("utf-8")).digest()[:4], "big")
        vec[h % dims] += 1.0
    norm = math.sqrt(sum(v * v for v in vec)) or 1.0
    return [round(v / norm, 6) for v in vec]


class FakeVoyage(Fake):
    """mode keys: fail (list of statuses or "drop" consumed per request),
    reverse (answer `data` in reverse index order)."""

    name = "voyage"

    def handle(self, h, rec):
        with self.lock:
            fail = self.mode.get("fail") or []
            action = fail.pop(0) if fail else None
        if action == "drop":
            h.close_connection = True
            h.connection.shutdown(2)
            return
        if isinstance(action, int):
            h.reply(action, {"detail": f"fake failure {action}"})
            return
        if rec.method != "POST" or rec.path.rstrip("/").split("/")[-1] != "embeddings":
            h.reply(404, {"detail": "not found"})
            return
        body = rec.json() or {}
        dims = body.get("output_dimension") or body.get("dimensions") or 1024
        data = [{"object": "embedding", "index": i, "embedding": embed(t, dims)}
                for i, t in enumerate(body.get("input", []))]
        if self.mode.get("reverse"):
            data.reverse()
        h.reply(200, {"object": "list", "data": data, "model": body.get("model"),
                      "usage": {"total_tokens": 0}})


# --------------------------------------------------------------------------- #
# JWKS + Hydra token endpoint
# --------------------------------------------------------------------------- #
class FakeJWKS(Fake):
    """Serves /jwks.json from `keys` (a list of RsaKey). mode keys: status
    (answer this status), delay (seconds before answering), redirect (302 to
    this URL), raw (answer this JSON instead), no_kid (omit kid)."""

    name = "jwks"

    def __init__(self, keys):
        super().__init__()
        self.keys = list(keys)

    def handle(self, h, rec):
        delay = self.mode.get("delay")
        if delay:
            time.sleep(delay)
        if self.mode.get("redirect"):
            h.reply(302, {}, headers={"Location": self.mode["redirect"]})
            return
        if self.mode.get("status"):
            h.reply(self.mode["status"], {"error": "fake"})
            return
        if "raw" in self.mode:
            h.reply(200, self.mode["raw"])
            return
        with_kid = not self.mode.get("no_kid")
        h.reply(200, {"keys": [k.jwk(with_kid) for k in self.keys]})

    def fetches(self):
        return len(self.taken(lambda r: r.path.endswith("jwks.json")))


class FakeHydra(Fake):
    """client_credentials token endpoint that signs with the JWKS key."""

    name = "hydra"

    def __init__(self, key, issuer, clients):
        super().__init__()
        self.key = key
        self.issuer = issuer
        self.clients = dict(clients)  # client_id -> secret

    def handle(self, h, rec):
        from rsa_jwt import mint  # local import: sibling module
        if rec.method != "POST" or not rec.path.endswith("/oauth2/token"):
            h.reply(404, {"error": "not_found"})
            return
        auth = rec.header("Authorization") or ""
        form = {k: v[-1] for k, v in parse_qs(rec.body.decode("utf-8")).items()}
        try:
            cid, secret = base64.b64decode(auth.split(" ", 1)[1]).decode("utf-8").split(":", 1)
        except Exception:  # noqa: BLE001
            h.reply(401, {"error": "invalid_client"})
            return
        from urllib.parse import unquote_plus
        cid, secret = unquote_plus(cid), unquote_plus(secret)
        if self.clients.get(cid) != secret or form.get("grant_type") != "client_credentials":
            h.reply(401, {"error": "invalid_client"})
            return
        now = int(time.time())
        token = mint({"iss": self.issuer, "sub": cid, "client_id": cid,
                      "aud": [form.get("audience", "")], "iat": now, "nbf": now,
                      "exp": now + 3600, "jti": f"jti-{len(self.requests)}"}, self.key)
        h.reply(200, {"access_token": token, "token_type": "bearer", "expires_in": 3600,
                      "scope": ""})


# --------------------------------------------------------------------------- #
# Upstream for the proxy
# --------------------------------------------------------------------------- #
class FakeUpstream(Fake):
    """Echoes what the proxy forwarded. Paths:
    /mcp/sse          three SSE events 0.3 s apart, then end
    /mcp/sse-forever  an event every 0.2 s until the client goes away
    /mcp/redirect     302 to an absolute URL
    anything else     200 JSON {method, raw_path, headers, body_len, body_sha256}
    """

    name = "upstream"

    def handle(self, h, rec):
        tail = rec.path
        if tail.endswith("/sse") or tail.endswith("/sse-forever"):
            forever = tail.endswith("/sse-forever")
            h.send_response(200)
            h.send_header("Content-Type", "text/event-stream")
            h.send_header("Cache-Control", "no-cache")
            h.send_header("Transfer-Encoding", "chunked")
            h.end_headers()
            n = 0
            try:
                while forever or n < 3:
                    payload = f"event: message\ndata: {{\"n\": {n}}}\n\n".encode()
                    h.wfile.write(f"{len(payload):x}\r\n".encode() + payload + b"\r\n")
                    h.wfile.flush()
                    n += 1
                    time.sleep(0.2 if forever else 0.3)
                    if forever and n > 200:
                        break
                h.wfile.write(b"0\r\n\r\n")
                h.wfile.flush()
            except (BrokenPipeError, ConnectionResetError):
                self.note_disconnect(rec)
            return
        if tail.endswith("/redirect"):
            h.reply(302, {"moved": True}, headers={"Location": "http://127.0.0.1:9/elsewhere"})
            return
        h.reply(200, {"method": rec.method, "raw_path": rec.raw_path,
                      "headers": [[k, v] for k, v in rec.headers],
                      "body_len": len(rec.body),
                      "body_sha256": hashlib.sha256(rec.body).hexdigest()})
