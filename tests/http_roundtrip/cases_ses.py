"""C-SES-1, -2, -3, -6, -7: the /memory/sessions/v1 sub-app, without an
archive backend (SESSION_ARCHIVE_BACKEND=none, or unset for the 503 branch).

C-SES-8 and C-SES-9 (archive objects, purge ordering) are in cases_archive.py,
C-SES-5 (the ccs client) in cases_ccs.py. C-SES-4 (redaction ruleset r1) is not
in run.py: each language's conformance test consumes the frozen vectors
(contracts/specs/C-SES-4.md)."""

from __future__ import annotations

import gzip
import hashlib
import json
import time

import lib
from common import OPERATOR, PROXY_SECRET, machine, verified
from lib import case

SID = "0f0e0d0c-0b0a-4908-8706-050403020100"
LINE = json.dumps({"type": "user", "uuid": "11111111-2222-4333-8444-555555555555", "sessionId": SID,
                   "timestamp": "2026-11-01T00:00:00.000Z", "cwd": "/work/roundtrip",
                   "message": {"role": "user", "content": "hello roundtrip"}}, separators=(",", ":"))


def sess(base, method, path, headers, body=None, raw_path=None, content=None):
    hdrs = dict(headers)
    if body is not None:
        hdrs["Content-Type"] = "application/json"
    r = lib.request(method, f"{base}/memory/sessions/v1{path}", headers=hdrs,
                    body=content if content is not None else body,
                    raw_path=f"/memory/sessions/v1{raw_path}" if raw_path else None)
    try:
        j = r.json()
    except ValueError:
        j = None
    return r.status, j


def ready(base, timeout=20.0):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        st, j = sess(base, "GET", "/status", machine("session-search-a"))
        if st == 200 and j and j.get("ready"):
            return True
        time.sleep(0.2)
    return False


def segment(lines, generation=0, offset=0, end_offset=None, sha=None):
    sent = "".join(ln + "\n" for ln in lines).encode("utf-8")
    return {"generation": generation, "offset": offset,
            "end_offset": end_offset if end_offset is not None else offset + len(sent),
            "sha256": sha or hashlib.sha256(sent).hexdigest(), "lines": lines}


def ingest_body(host="host-a", seg=None, kind="main", project_dir="-work-roundtrip", sid=SID, **file_over):
    f = {"session_id": sid, "project_dir": project_dir, "jsonl_path": "/home/u/.claude/projects/x.jsonl",
         "source": "claude", "kind": kind}
    f.update(file_over)
    return {"client": {"host": host, "redact_version": "r1"}, "file": f,
            "segment": seg or segment([LINE])}


def _mcp_sessions(ctx, key, **over):
    env = {"SESSION_ARCHIVE_BACKEND": "none"}
    env.update(over)
    base = ctx.env.mcp(key, **env)
    ctx.check(ready(base), f"{key}: session indices ready")
    return base


ROUTES = [("POST", "/ingest"), ("POST", "/blob"), ("POST", "/state"), ("POST", "/search"),
          ("GET", "/preview"), ("GET", "/archive"), ("GET", "/archive/tool-results"),
          ("DELETE", "/session"), ("DELETE", "/purged"), ("GET", "/status")]


@case("C-SES-1", "10 routes x 3 identities: scope decides 403 before the handler", "ses")
def route_scopes(ctx):
    base = _mcp_sessions(ctx, "mcp-ses")
    who = {"ingest+read (session-search-a)": machine("session-search-a"),
           "read+purge (operator)": verified(),
           "no rule (stranger)": machine("stranger")}
    rows = {}
    for method, path in ROUTES + [("GET", "/nope"), ("PUT", "/ingest")]:
        for name, hdrs in who.items():
            body = {} if method in ("POST", "DELETE") else None
            st, j = sess(base, method, path, hdrs, body=body)
            rows[f"{method} {path} / {name}"] = [st, (j or {}).get("error")]
    ctx.golden("matrix", rows)
    for method, path in ROUTES:
        ctx.eq(rows[f"{method} {path} / no rule (stranger)"], [403, "forbidden"], f"{method} {path} stranger")


@case("C-SES-2", "gate: secret unset 403, mismatch 401, encoded separators 403, 503 until ready", "ses")
def gate(ctx):
    rows = {}
    base = _mcp_sessions(ctx, "mcp-ses")
    a = machine("session-search-a")
    rows["wrong-secret"] = sess(base, "GET", "/status", machine("session-search-a", secret="nope"))
    rows["no-secret"] = sess(base, "GET", "/status", machine("session-search-a", secret=None))
    for name, raw in (("%2f", "/archive%2ftool-results"), ("%2F", "/archive%2Ftool-results"),
                      ("%5c", "/archive%5ctool-results"), ("%2e", "/%2e/status"),
                      ("dot", "/./status"), ("dotdot", "/x/../status")):
        rows[f"encoded-{name}"] = sess(base, "GET", "", a, raw_path=raw)
    b = ctx.env.mcp("mcp-ses-nosecret", PROXY_SHARED_SECRET=None, SESSION_ARCHIVE_BACKEND="none")
    rows["secret-unset"] = sess(b, "GET", "/status", machine("session-search-a", secret=None))
    ctx.env.stop("mcp-ses-nosecret")
    # Not ready: the session indices cannot be created.
    from fakes import FakeES
    es = FakeES()
    try:
        es.mode["missing"] = {"memory-session", "memory-session-message"}
        c = ctx.env.mcp("mcp-ses-notready", es=es, SESSION_ARCHIVE_BACKEND="none")
        rows["not-ready-search"] = sess(c, "POST", "/search", a, body={"q": "x"})
        st, j = sess(c, "GET", "/status", a)
        # The error text is the implementation's own diagnostic; only its presence is contract.
        rows["not-ready-status"] = [st, {"ready": j.get("ready"), "error": bool(j.get("error"))}]
        ctx.env.stop("mcp-ses-notready")
    finally:
        es.close()
    out = {k: [v[0], (v[1] or {}).get("error") if isinstance(v[1], dict) and "ready" not in v[1] else v[1]]
           for k, v in rows.items()}
    ctx.golden("gate", out)
    ctx.eq(rows["secret-unset"][0], 403, "secret unset")
    ctx.eq(rows["wrong-secret"][0], 401, "secret mismatch")
    ctx.eq(rows["not-ready-search"][0], 503, "503 before ready")


@case("C-SES-3", "limits: 8 MiB wire, 5 MiB after gunzip, 50,000 lines", "ses")
def limits(ctx):
    base = _mcp_sessions(ctx, "mcp-ses")
    a = machine("session-search-a")
    MiB = 1024 * 1024
    rows = {}
    pad = "x" * 100
    # Wire size (counted by the server itself, not only the proxy).
    rows["wire-8MiB+1"] = sess(base, "POST", "/search", a, content=b"{" + b" " * (8 * MiB - 1) + b"}")
    big = json.dumps({"q": "x", "pad": "y" * (5 * MiB)}).encode()
    rows["gzip-over-5MiB"] = sess(base, "POST", "/search", {**a, "Content-Type": "application/json"},
                                  content=gzip.compress(big))
    small = json.dumps({"q": "x"}).encode()
    rows["gzip-small"] = sess(base, "POST", "/search", {**a, "Content-Type": "application/json"},
                              content=gzip.compress(small))
    lines = [json.dumps({"type": "progress", "n": i, "p": pad[:5]}) for i in range(50_001)]
    rows["lines-50001"] = sess(base, "POST", "/ingest", a, body=ingest_body(seg=segment(lines)))
    out = {k: [v[0], (v[1] or {}).get("error")] for k, v in rows.items()}
    ctx.golden("limits", out)
    ctx.eq(out["wire-8MiB+1"], [413, "too_large"], "wire limit")
    ctx.eq(out["gzip-over-5MiB"], [413, "too_large"], "decompressed limit")


@case("C-SES-6", "ingest: response fields, retry, offset/generation rules, sha256, subagent cursor, 503",
      "ses")
def ingest_protocol(ctx):
    base = _mcp_sessions(ctx, "mcp-ses")
    ctx.env.es.reset_data()
    a = machine("session-search-a")
    rows = {}
    l1, l2 = LINE, LINE.replace("hello roundtrip", "second line")
    s1 = segment([l1])
    rows["first"] = sess(base, "POST", "/ingest", a, body=ingest_body(seg=s1))
    rows["retry-same"] = sess(base, "POST", "/ingest", a, body=ingest_body(seg=s1))
    s2 = segment([l2], offset=s1["end_offset"])
    rows["next"] = sess(base, "POST", "/ingest", a, body=ingest_body(seg=s2))
    rows["gap"] = sess(base, "POST", "/ingest", a, body=ingest_body(seg=segment([l2], offset=s2["end_offset"] + 5)))
    rows["retry-first-again"] = sess(base, "POST", "/ingest", a, body=ingest_body(seg=s1))
    rows["new-gen-nonzero"] = sess(base, "POST", "/ingest", a,
                                   body=ingest_body(seg=segment([l1], generation=1, offset=7)))
    rows["new-gen-zero"] = sess(base, "POST", "/ingest", a, body=ingest_body(seg=segment([l1], generation=1)))
    rows["stale-gen"] = sess(base, "POST", "/ingest", a, body=ingest_body(seg=segment([l1], generation=0)))
    rows["sha-mismatch"] = sess(base, "POST", "/ingest", a, body=ingest_body(seg=segment([l1], generation=1,
                                offset=0, sha="0" * 64)))
    rows["host-mismatch"] = sess(base, "POST", "/ingest", a, body=ingest_body(host="host-b"))
    rows["bad-redact-version"] = sess(base, "POST", "/ingest", a,
                                      body={**ingest_body(), "client": {"host": "host-a", "redact_version": "r0"}})
    rows["subagent"] = sess(base, "POST", "/ingest", a, body=ingest_body(
        kind="subagent", agent_id="agent-1", parent_session_id=SID, seg=segment([l1])))
    rows["subagent-own-cursor"] = sess(base, "POST", "/ingest", a, body=ingest_body(
        kind="subagent", agent_id="agent-2", parent_session_id=SID, seg=segment([l1])))
    rows["bad-json-line"] = sess(base, "POST", "/ingest", a, body=ingest_body(seg=segment(["{not json"],
                                 generation=1, offset=0)))
    # No backend configured and no explicit opt-out: main segments are refused.
    b = ctx.env.mcp("mcp-ses-nobackend", SESSION_ARCHIVE_BACKEND=None)
    ready(b)
    rows["archive-unconfigured"] = sess(b, "POST", "/ingest", a, body=ingest_body(sid=SID.replace("0f", "1f")))
    ctx.env.stop("mcp-ses-nobackend")
    norm = lib.Normalizer()
    ctx.golden("ingest", {k: [v[0], norm(v[1])] for k, v in rows.items()})
    ctx.eq(sorted(rows["first"][1]), ["archive", "indexed", "next_offset", "session_key"], "four fields")
    ctx.eq(rows["retry-same"], rows["first"], "a retry answers the same")
    ctx.eq((rows["gap"][0], rows["gap"][1]["error"]), (409, "offset_mismatch"), "gap")
    ctx.eq((rows["stale-gen"][0], rows["stale-gen"][1]["error"]), (409, "stale_generation"), "stale generation")
    ctx.eq((rows["sha-mismatch"][0], rows["sha-mismatch"][1]["error"]), (422, "sha256_mismatch"), "sha")
    ctx.eq((rows["archive-unconfigured"][0], rows["archive-unconfigured"][1]["error"]),
           (503, "archive_unavailable"), "no backend")


BAD_POLICIES = {
    "not-json": "{rules:",
    "top-level-list": "[]",
    "extra-top-key": json.dumps({"rules": [], "x": 1}),
    "rules-not-list": json.dumps({"rules": {}}),
    "rule-missing-key": json.dumps({"rules": [{"match": {"grant": "client_credentials"}, "scopes": []}]}),
    "empty-match": json.dumps({"rules": [{"match": {}, "host": None, "scopes": []}]}),
    "unknown-match-key": json.dumps({"rules": [{"match": {"aud": "x"}, "host": None, "scopes": []}]}),
    "empty-match-value": json.dumps({"rules": [{"match": {"sub": ""}, "host": None, "scopes": []}]}),
    "unknown-grant": json.dumps({"rules": [{"match": {"grant": "password"}, "host": None, "scopes": []}]}),
    "bad-host": json.dumps({"rules": [{"match": {"sub": "a"}, "host": "Host_A", "scopes": []}]}),
    "unknown-scope": json.dumps({"rules": [{"match": {"sub": "a"}, "host": None, "scopes": ["sessions:all"]}]}),
    "duplicate-scope": json.dumps({"rules": [{"match": {"sub": "a"}, "host": None,
                                              "scopes": ["sessions:read", "sessions:read"]}]}),
}


@case("C-SES-7", "SESSION_SCOPE_POLICY: strict grammar (deny-all), first match, host ownership", "ses")
def scope_policy(ctx):
    rows = {}
    # A bad policy denies everyone, including an identity a valid rule would admit.
    for name, spec in BAD_POLICIES.items():
        b = ctx.env.mcp("mcp-ses-badpolicy", SESSION_SCOPE_POLICY=spec, SESSION_ARCHIVE_BACKEND="none")
        st, j = sess(b, "GET", "/status", verified(grant="authorization_code", sub="a", client_id="c"))
        log = ctx.env.output("mcp-ses-badpolicy")
        rows[f"bad/{name}"] = [st, (j or {}).get("error"), "SESSIONS scope-policy deny-all reason=" in log]
        ctx.env.stop("mcp-ses-badpolicy")
    # First matching rule decides, even when a later rule would allow.
    first = json.dumps({"rules": [
        {"match": {"client_id": "session-search-a"}, "host": "host-a", "scopes": ["sessions:read"]},
        {"match": {"grant": "client_credentials"}, "host": "host-a", "scopes": ["sessions:ingest"]}]})
    ctx.env.es.reset_data()
    b = ctx.env.mcp("mcp-ses-first", SESSION_SCOPE_POLICY=first, SESSION_ARCHIVE_BACKEND="none")
    ready(b)
    rows["first-match/a-ingest"] = list(sess(b, "POST", "/ingest", machine("session-search-a"),
                                             body=ingest_body()))[:1]
    rows["first-match/other-ingest-allowed"] = [sess(b, "POST", "/ingest", machine("session-search-z"),
                                                     body=ingest_body())[0]]
    ctx.env.stop("mcp-ses-first")
    # Host ownership with the suite's default policy.
    base = _mcp_sessions(ctx, "mcp-ses")
    ctx.env.es.reset_data()
    st, j = sess(base, "POST", "/ingest", machine("session-search-a"), body=ingest_body())
    key = j["session_key"]
    rows["owner-ingest"] = [st]
    rows["b-writes-a-body"] = list(sess(base, "POST", "/ingest", machine("session-search-b"), body=ingest_body()))
    rows["b-writes-own-body-same-session"] = list(sess(base, "POST", "/ingest", machine("session-search-b"),
                                                       body=ingest_body(host="host-b")))
    rows["operator-ingest-no-scope"] = list(sess(base, "POST", "/ingest", verified(), body=ingest_body()))
    rows["hostless-ingest"] = list(sess(base, "POST", "/ingest", machine("session-search-hostless"),
                                        body=ingest_body()))
    rows["b-state-on-a-session"] = list(sess(base, "POST", "/state", machine("session-search-b"),
                                             body={"session_key": key, "jsonl_exists": False}))
    rows["b-preview-a-session"] = [sess(base, "GET", f"/preview?session_key={key}", machine("session-search-b"))[0]]
    rows["hostless-purge-any-host"] = list(sess(base, "DELETE", f"/session?session_key={key}",
                                                machine("session-search-hostless")))
    norm = lib.Normalizer()
    ctx.golden("policy", {k: norm(v) for k, v in rows.items()})
    for name in BAD_POLICIES:
        ctx.eq(rows[f"bad/{name}"][:2], [403, "forbidden"], f"{name}: deny-all")
    ctx.eq(rows["b-writes-a-body"][0], 403, "host B cannot write host A's body")
    ctx.eq(rows["hostless-ingest"], [403, {"error": "host_mismatch"}], "host:null cannot ingest")
    ctx.eq(rows["hostless-purge-any-host"][0], 200, "host:null purges any host")
