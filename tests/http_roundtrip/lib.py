"""Shared plumbing for the round-trip suite: raw HTTP, an MCP client that reads
responses the way the mirror hook does, golden normalisation, the case
registry and the process launcher. Standard library only."""

from __future__ import annotations

import http.client
import json
import os
import re
import socket
import subprocess
import time
from urllib.parse import urlsplit

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
GOLDEN_DIR = os.path.join(REPO, "contracts", "golden")


# --------------------------------------------------------------------------- #
# HTTP
# --------------------------------------------------------------------------- #
class Response:
    def __init__(self, status, headers, body):
        self.status = status
        self.headers = headers  # list of (name, value)
        self.body = body

    def header(self, name):
        for k, v in self.headers:
            if k.lower() == name.lower():
                return v
        return None

    def header_all(self, name):
        return [v for k, v in self.headers if k.lower() == name.lower()]

    def json(self):
        return json.loads(self.body)

    def json_or_text(self):
        try:
            return json.loads(self.body)
        except ValueError:
            return {"_text": self.body.decode("utf-8", "replace")[:200]}

    def __repr__(self):
        return f"<Response {self.status} {self.body[:120]!r}>"


def request(method, url, *, headers=None, body=None, raw_path=None, chunked=False,
            timeout=30.0) -> Response:
    """One request on a fresh connection. raw_path is sent byte for byte, so a
    case can put %2F, dot segments or an empty query on the wire."""
    parts = urlsplit(url)
    conn = http.client.HTTPConnection(parts.hostname, parts.port, timeout=timeout)
    path = raw_path if raw_path is not None else (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
    if isinstance(body, (dict, list)):
        body = json.dumps(body).encode("utf-8")
    elif isinstance(body, str):
        body = body.encode("utf-8")
    hdrs = dict(headers or {})
    try:
        if chunked:
            conn.putrequest(method, path, skip_accept_encoding=True,
                            skip_host="host" in {k.lower() for k in hdrs})
            for k, v in hdrs.items():
                conn.putheader(k, v)
            conn.putheader("Transfer-Encoding", "chunked")
            conn.endheaders()
            step = 65536
            for i in range(0, len(body or b""), step):
                piece = body[i:i + step]
                conn.send(f"{len(piece):x}\r\n".encode() + piece + b"\r\n")
            conn.send(b"0\r\n\r\n")
        else:
            conn.putrequest(method, path, skip_accept_encoding=True,
                            skip_host="host" in {k.lower() for k in hdrs})
            for k, v in hdrs.items():
                conn.putheader(k, v)
            if body is not None and "content-length" not in {k.lower() for k in hdrs}:
                conn.putheader("Content-Length", str(len(body)))
            conn.endheaders(body)
        resp = conn.getresponse()
        data = resp.read()
        return Response(resp.status, resp.getheaders(), data)
    finally:
        conn.close()


def wait_port(port, timeout=30.0, proc=None):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if proc is not None and proc.poll() is not None:
            return False
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.1)
    return False


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


# --------------------------------------------------------------------------- #
# MCP over streamable HTTP
# --------------------------------------------------------------------------- #
def parse_payload(raw: bytes):
    """The mirror hook's rule (hooks/mirror-file-memory.rb parse_payload): take
    the `data:` lines, last first, and return the first JSON object carrying
    `result` or `error`; a body with no `data:` line is parsed whole."""
    text = raw.decode("utf-8")
    candidates = [ln[5:].lstrip() for ln in text.splitlines(keepends=True) if ln.startswith("data:")]
    if not candidates:
        candidates = [text]
    for chunk in reversed(candidates):
        try:
            parsed = json.loads(chunk)
        except ValueError:
            continue
        if isinstance(parsed, dict) and ("result" in parsed or "error" in parsed):
            return parsed
    raise ValueError(f"unparsable MCP response ({len(raw)} bytes)")


class Mcp:
    def __init__(self, url, headers=None, version="2025-06-18"):
        self.url = url
        self.headers = dict(headers or {})
        self.version = version
        self.session = None
        self.next_id = 0
        self.init_response = None

    def _post(self, body, extra=None):
        hdrs = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream"}
        hdrs.update(self.headers)
        if self.session:
            hdrs["Mcp-Session-Id"] = self.session
        if self.session and self.version >= "2025-06-18":
            hdrs["MCP-Protocol-Version"] = self.version
        hdrs.update(extra or {})
        return request("POST", self.url, headers=hdrs, body=body)

    def rpc(self, method, params=None, notify=False, extra=None):
        body = {"jsonrpc": "2.0", "method": method}
        if not notify:
            self.next_id += 1
            body["id"] = self.next_id
        if params is not None:
            body["params"] = params
        return self._post(body, extra)

    def initialize(self):
        r = self.rpc("initialize", {"protocolVersion": self.version, "capabilities": {},
                                    "clientInfo": {"name": "http-roundtrip", "version": "1"}})
        self.init_response = r
        if r.status == 200:
            self.session = r.header("mcp-session-id")
            self.rpc("notifications/initialized", notify=True)
        return r

    def call(self, name, arguments):
        """(isError, text) of content[0]."""
        r = self.rpc("tools/call", {"name": name, "arguments": arguments})
        if r.status != 200:
            raise AssertionError(f"tools/call {name}: HTTP {r.status} {r.body[:200]!r}")
        msg = parse_payload(r.body)
        if "error" in msg:
            return True, f"JSON-RPC {msg['error'].get('code')}: {msg['error'].get('message')}"
        res = msg["result"]
        text = (res.get("content") or [{}])[0].get("text")
        return bool(res.get("isError")), text

    def call_json(self, name, arguments):
        err, text = self.call(name, arguments)
        if err:
            raise AssertionError(f"{name} failed: {text}")
        return json.loads(text)

    def delete(self):
        hdrs = dict(self.headers)
        hdrs["Mcp-Session-Id"] = self.session
        return request("DELETE", self.url, headers=hdrs)


# --------------------------------------------------------------------------- #
# Normalisation for golden comparison
# --------------------------------------------------------------------------- #
_UUID_RE = re.compile(r"^[0-9a-f]{32}$")
_TS_RE = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})")
_ID_KEYS = {"id", "_id", "job_id", "doc_id", "new_id", "parent_id", "superseded_by",
            "derived_from", "session_id", "mcp-session-id"}
# Deterministic hashes: md5 of the content, compared as is (C-ES-3).
_KEEP_KEYS = {"content_hash", "doc_key", "body_sha256"}
_TS_KEYS = {"written_at", "superseded_at", "last_used_at", "expires_at", "started_at",
            "finished_at", "at", "now"}


class Normalizer:
    """Replaces run-specific values with stable placeholders. Ids are numbered
    by first appearance, so "the id remember returned is the id get echoes"
    survives normalisation while the value itself does not matter."""

    def __init__(self):
        self.ids: dict[str, str] = {}

    def _id(self, value):
        if value in ("forget", "", None) or not isinstance(value, str):
            return value
        if value not in self.ids:
            self.ids[value] = f"<id:{len(self.ids) + 1}>"
        return self.ids[value]

    def __call__(self, obj, key=None):
        if isinstance(obj, dict):
            return {k: self(v, k.lower() if isinstance(k, str) else k) for k, v in obj.items()}
        if isinstance(obj, list):
            if key == "embedding" or key == "query_vector" or (
                    len(obj) >= 16 and all(isinstance(x, float) for x in obj)):
                return f"<vector len={len(obj)}>"
            if key in _ID_KEYS:
                return [self._id(v) for v in obj]
            return [self(v, key) for v in obj]
        if isinstance(obj, float):
            return round(obj, 6)
        if isinstance(obj, str):
            if key in _KEEP_KEYS:
                return obj
            if key in _ID_KEYS or _UUID_RE.match(obj):
                return self._id(obj)
            if key in _TS_KEYS and _TS_RE.fullmatch(obj):
                return "<ts>"
            return _TS_RE.sub("<ts>", obj)
        return obj


def es_trace(requests, norm=None):
    """What an implementation sent to Elasticsearch, as comparable data."""
    norm = norm or Normalizer()
    out = []
    for r in requests:
        body = r.json()
        if body is None and r.body:
            body = [json.loads(ln) for ln in r.body.decode("utf-8").splitlines() if ln.strip()]
        out.append({"method": r.method, "path": r.path,
                    "query": {k: v for k, v in sorted(r.query.items())},
                    "body": norm(body)})
    return out


# --------------------------------------------------------------------------- #
# Cases
# --------------------------------------------------------------------------- #
CASES = []


def case(contract_id, title, env):
    def deco(fn):
        CASES.append({"id": contract_id, "title": title, "env": env, "fn": fn,
                      "name": fn.__name__})
        return fn
    return deco


class CaseFailure(AssertionError):
    pass


class Ctx:
    """Per-case handle: the environment's URLs and fakes, and the check and
    golden helpers that decide pass or fail."""

    def __init__(self, env, contract_id, name, capture):
        self.env = env
        self.contract_id = contract_id
        self.name = name
        self.capture = capture
        self.checks = 0
        self.goldens = []

    def check(self, cond, what):
        self.checks += 1
        if not cond:
            raise CaseFailure(what)

    def eq(self, got, want, what):
        self.check(got == want, f"{what}: got {got!r}, want {want!r}")

    def golden(self, label, obj, path=None):
        """Compare obj (already normalised) with contracts/golden/<id>/<case>.<label>.json
        (or `path`), or write it under --capture."""
        path = path or os.path.join(GOLDEN_DIR, self.contract_id, f"{self.name}.{label}.json")
        text = json.dumps(obj, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
        self.goldens.append(path)
        if self.capture:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(text)
            return
        if not os.path.exists(path):
            raise CaseFailure(f"golden missing: {os.path.relpath(path, REPO)} (run with --capture)")
        with open(path, encoding="utf-8") as fh:
            want = json.load(fh)
        got = json.loads(text)
        self.checks += 1
        if got != want:
            raise CaseFailure(f"golden mismatch {os.path.relpath(path, REPO)}: {first_diff(got, want)}")


def first_diff(got, want, path="$"):
    if type(got) is not type(want):
        return f"{path}: type {type(got).__name__} != {type(want).__name__} ({got!r} vs {want!r})"
    if isinstance(got, dict):
        for k in sorted(set(got) | set(want)):
            if k not in got:
                return f"{path}.{k}: missing"
            if k not in want:
                return f"{path}.{k}: unexpected {got[k]!r}"
            if got[k] != want[k]:
                return first_diff(got[k], want[k], f"{path}.{k}")
    if isinstance(got, list):
        if len(got) != len(want):
            return f"{path}: length {len(got)} != {len(want)}"
        for i, (a, b) in enumerate(zip(got, want)):
            if a != b:
                return first_diff(a, b, f"{path}[{i}]")
    return f"{path}: {got!r} != {want!r}"


# --------------------------------------------------------------------------- #
# Processes under test
# --------------------------------------------------------------------------- #
class Proc:
    def __init__(self, role, argv, cwd, env, log_dir):
        self.role = role
        self.log_path = os.path.join(log_dir, f"{role}-{int(time.time() * 1000)}.log")
        self.log = open(self.log_path, "wb")
        self.p = subprocess.Popen(argv, cwd=cwd, env=env, stdout=self.log, stderr=subprocess.STDOUT)

    def output(self) -> str:
        self.log.flush()
        with open(self.log_path, "rb") as fh:
            return fh.read().decode("utf-8", "replace")

    def stop(self):
        if self.p.poll() is None:
            self.p.terminate()
            try:
                self.p.wait(10)
            except subprocess.TimeoutExpired:
                self.p.kill()
                self.p.wait(5)
        self.log.close()


def expand(argv, mapping):
    return [a.format(**mapping) for a in argv]
