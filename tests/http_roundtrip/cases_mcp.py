"""C-MCP-1..10: the MCP surface of memory-mcp, spoken to directly with the
headers the proxy would set (the proxy itself is covered by C-HTTP/C-JWT)."""

from __future__ import annotations

import json
import os
import socket
import threading
import time

import lib
from common import OPERATOR, PROXY_SECRET, machine, mcp_client, settle, verified
from lib import case

VERSIONS = ["2024-11-05", "2025-06-18", "2025-11-25"]


# --------------------------------------------------------------------------- #
@case("C-MCP-1", "tools/list equals contracts/mcp-tools.json", "mcp")
def tools_list(ctx):
    base = ctx.env.mcp()
    c = mcp_client(base)
    r = c.rpc("tools/list", {})
    ctx.eq(r.status, 200, "tools/list status")
    tools = lib.parse_payload(r.body)["result"]["tools"]
    ctx.eq(sorted(t["name"] for t in tools),
           sorted(["recall", "remember", "ingest", "revise", "forget", "get", "browse", "memory_stats"]),
           "tool names")
    ctx.golden("tools", {"tools": tools}, path=os.path.join(lib.REPO, "contracts", "mcp-tools.json"))


# --------------------------------------------------------------------------- #
@case("C-MCP-2", "stateful initialize under three protocol versions", "mcp")
def initialize_versions(ctx):
    base = ctx.env.mcp()
    out = {}
    for v in VERSIONS:
        c = lib.Mcp(f"{base}/memory/mcp", verified(), v)
        r = c.initialize()
        ctx.eq(r.status, 200, f"initialize {v}")
        sid = r.header("mcp-session-id")
        ctx.check(bool(sid) and len(sid) >= 16, f"{v}: Mcp-Session-Id present ({sid!r})")
        res = lib.parse_payload(r.body)["result"]
        n = c.rpc("notifications/initialized", notify=True)
        lst = c.rpc("tools/list", {})
        ctx.eq(lst.status, 200, f"tools/list after initialize {v}")
        # A request without the session id on a stateful server is refused.
        bare = lib.request("POST", c.url, headers={**verified(), "Content-Type": "application/json",
                                                   "Accept": "application/json, text/event-stream"},
                           body={"jsonrpc": "2.0", "id": 9, "method": "tools/list"})
        out[v] = {"initialize_status": r.status,
                  "initialize_content_type": r.header("content-type"),
                  "result": {"protocolVersion": res["protocolVersion"],
                             "serverInfo": {"name": res["serverInfo"]["name"]},
                             "capabilities": res["capabilities"]},
                  "initialized_status": n.status,
                  "tools_list_status": lst.status,
                  "without_session_status": bare.status}
    ctx.golden("versions", out)


# --------------------------------------------------------------------------- #
@case("C-MCP-3", "SSE framing is readable by the mirror hook's rule", "mcp")
def sse_framing(ctx):
    base = ctx.env.mcp()
    c = mcp_client(base)
    r = c.rpc("tools/call", {"name": "memory_stats", "arguments": {}})
    ctx.eq(r.status, 200, "status")
    ctype = r.header("content-type") or ""
    ctx.check(ctype.startswith("text/event-stream"), f"content-type {ctype!r}")
    lines = r.body.decode("utf-8").splitlines()
    ctx.check("event: message" in lines, "an `event: message` line")
    ctx.check(any(ln.startswith("data: ") for ln in lines), "a `data:` line")
    msg = lib.parse_payload(r.body)
    ctx.check("result" in msg, "parse_payload yields result")
    # The rule itself: keep-alive comments and a trailing non-result event do
    # not hide the result.
    synthetic = (b": keep-alive\n\nevent: message\ndata: " + json.dumps(msg).encode() +
                 b"\n\nevent: message\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\"}\n\n")
    ctx.eq(lib.parse_payload(synthetic), msg, "rule skips non-result data lines")
    ctx.eq(lib.parse_payload(json.dumps(msg).encode()), msg, "plain JSON body accepted")


# --------------------------------------------------------------------------- #
# The 8-tool scenario shared by C-MCP-4 (responses) and C-ES-2 (what went to ES)
# --------------------------------------------------------------------------- #
LONG_DOC = "\n\n".join(
    f"Section {i}. The roundtrip document describes chunk boundaries and overlap handling. " * 6
    for i in range(1, 6))


def scenario(ctx):
    """Run every tool once (and the follow-ups) against a fresh store. Returns
    [(step, tool, arguments, response)] and [(step, es requests)]."""
    cache = getattr(ctx.env, "_scenario", None)
    if cache is not None:
        return cache
    es = ctx.env.es
    # Its own process: memory_stats reports the in-process job registry, which other
    # cases' background ingests would otherwise leave entries in.
    base = ctx.env.mcp("mcp-scenario")
    # The session indices are ensured in the background after startup; let that finish
    # so its PUTs do not land in the first step's trace.
    for _ in range(100):
        r = lib.request("GET", f"{base}/memory/sessions/v1/status", headers=verified())
        if r.status == 200 and r.json().get("ready"):
            break
        time.sleep(0.1)
    es.reset_data()
    c = mcp_client(base)
    steps = []
    traces = []

    def do(step, tool, args):
        es.clear()
        err, text = c.call(tool, args)
        if tool == "recall":
            settle(es)
        try:
            body = json.loads(text)
        except (TypeError, ValueError):
            body = text
        if tool == "browse" and isinstance(body, dict):
            # Order among equal written_at (one-second resolution) is not part of the
            # contract, and Elasticsearch does not fix it either.
            body["items"].sort(key=lambda i: (i.get("memory_type") or "", i.get("content") or "",
                                              i.get("chunk_index") or 0))
        steps.append({"step": step, "tool": tool, "arguments": args, "isError": err, "response": body})
        traces.append({"step": step, "requests": es.taken(lambda r: True)})
        return body

    fact = do("remember-fact", "remember", {"content": "Roundtrip fact: the operator drinks green tea.",
                                            "type": "fact", "tags": ["todo"]})
    do("remember-fact-dup", "remember", {"content": "Roundtrip fact: the operator drinks green tea.",
                                         "type": "fact", "tags": ["todo", "drink"]})
    do("remember-knowledge", "remember", {"content": "Elasticsearch kNN uses int8_hnsw in this store.",
                                          "type": "knowledge"})
    do("remember-episode", "remember", {"content": "Session summary: roundtrip suite captured goldens.",
                                        "type": "episode"})
    ing = do("ingest", "ingest", {"document": LONG_DOC, "dataset": "notes", "doc_key": "roundtrip/doc-1",
                                  "tags": ["design"]})
    do("recall", "recall", {"query": "green tea operator"})
    do("recall-fact", "recall", {"query": "tea", "type": "fact", "top_k": 3})
    do("recall-filter", "recall", {"query": "roundtrip", "filters": {"tags": "todo"}})
    do("get-fact", "get", {"id": fact["id"]})
    do("get-doc", "get", {"id": ing["doc_id"]})
    do("browse-knowledge", "browse", {"type": "knowledge", "limit": 5})
    do("browse-tag", "browse", {"filters": {"tags": ["todo", "design"]}})
    do("memory-stats", "memory_stats", {})
    rev = do("revise-fact", "revise", {"id": fact["id"], "content": "Roundtrip fact: the operator drinks black tea."})
    do("get-chain", "get", {"id": fact["id"], "include_chain": True})
    do("forget-doc", "forget", {"dataset": "notes", "doc_key": "roundtrip/doc-1"})
    do("forget-id", "forget", {"id": rev["new_id"]})
    do("get-missing", "get", {"id": "does-not-exist"})
    ctx.env._scenario = (steps, traces)
    ctx.env.stop("mcp-scenario")
    return ctx.env._scenario


@case("C-MCP-4", "responses of all 8 tools (recall rename, tags, provenance, degraded)", "mcp")
def tool_responses(ctx):
    steps, _ = scenario(ctx)
    norm = lib.Normalizer()
    ctx.golden("scenario", norm(steps))
    recall = next(s for s in steps if s["step"] == "recall")["response"]
    ctx.check(all("type" in h and "memory_type" not in h for h in recall["hits"]), "memory_type renamed to type")
    ctx.check(all({"tags", "provenance", "doc_id"} <= set(h) for h in recall["hits"]), "tags/provenance kept")
    ctx.check("degraded" not in recall, "no degraded key while embeddings work")
    # degraded appears only when the embedding leg fails
    ctx.env.voyage.mode["fail"] = [400]
    try:
        c = mcp_client(ctx.env.mcp("mcp-degraded"))
        out = c.call_json("recall", {"query": "tea"})
        settle(ctx.env.es)
    finally:
        ctx.env.voyage.mode.pop("fail", None)
    ctx.env.stop("mcp-degraded")
    ctx.eq(out.get("degraded"), "bm25-only", "degraded on embedding failure")
    ctx.golden("degraded", lib.Normalizer()(out))


# --------------------------------------------------------------------------- #
@case("C-MCP-5", "remember routing: 4 types x (new, tagged, duplicate)", "mcp")
def remember_routing(ctx):
    base = ctx.env.mcp()
    ctx.env.es.reset_data()
    ctx.env._scenario = None
    c = mcp_client(base)
    contents = {"fact": "Remember-5 fact {n}", "knowledge": "Remember-5 knowledge note {n}",
                "episode": "Remember-5 episode {n}", "auto": "Remember-5 general text {n}"}
    rows = []
    for typ, tmpl in contents.items():
        for variant, tags, n in (("new", None, 1), ("tagged", ["routing"], 2), ("duplicate", ["extra"], 2)):
            args = {"content": tmpl.format(n=n), "type": typ}
            if tags is not None:
                args["tags"] = tags
            err, text = c.call("remember", args)
            rows.append({"type": typ, "variant": variant, "isError": err, "response": json.loads(text)})
    err, text = c.call("remember", {"content": "auto 2026-11-28 dated", "type": "auto"})
    rows.append({"type": "auto", "variant": "dated", "isError": err, "response": json.loads(text)})
    err, text = c.call("remember", {"content": "unknown type", "type": "bogus"})
    rows.append({"type": "bogus", "variant": "unknown", "isError": err, "response": json.loads(text)})
    ctx.golden("rows", lib.Normalizer()(rows))
    keys = {k for r in rows for k in r["response"]}
    ctx.check(keys <= {"action", "id", "routed_type", "reason", "reconcile_status", "tags_added"},
              f"response keys {sorted(keys)}")


# --------------------------------------------------------------------------- #
@case("C-MCP-6", "policy_denied: and 'Error executing tool <name>:' prefixes", "mcp")
def error_prefixes(ctx):
    base = ctx.env.mcp()
    out = {}
    m = mcp_client(base, machine("memory-mirror"))
    out["policy_denied_recall"] = m.call("recall", {"query": "x"})
    u = mcp_client(base)
    out["bad_filter"] = u.call("recall", {"query": "x", "filters": {"no_such_key": "v"}})
    out["date_filter"] = u.call("browse", {"filters": {"written_at": "2026"}})
    out["browse_limit"] = u.call("browse", {"limit": 5000})
    out["unknown_tool"] = u.call("no_such_tool", {})
    out["get_missing"] = u.call("get", {"id": "missing-id"})
    out["revise_missing"] = u.call("revise", {"id": "missing-id", "content": "x"})
    ctx.check(out["policy_denied_recall"][0] and out["policy_denied_recall"][1].startswith("policy_denied:"),
              f"policy refusal text {out['policy_denied_recall']!r}")
    for k in ("bad_filter", "date_filter", "browse_limit", "get_missing"):
        err, text = out[k]
        tool = {"bad_filter": "recall", "date_filter": "browse", "browse_limit": "browse",
                "get_missing": "get"}[k]
        ctx.check(err and text.startswith(f"Error executing tool {tool}: "), f"{k}: {text!r}")
    ctx.golden("errors", {k: {"isError": v[0], "text": v[1]} for k, v in out.items()})


# --------------------------------------------------------------------------- #
POLICY_TABLE = [
    # (name, identity, tool, arguments, allowed)
    ("authz-code-any-tool", "user", "memory_stats", {}, True),
    ("authz-code-tags", "user", "ingest", {"document": "d", "dataset": "notes", "tags": ["t"]}, True),
    ("mirror-ingest-own-dataset", "memory-mirror", "ingest", {"document": "d", "dataset": "file-memory"}, True),
    ("mirror-ingest-other-dataset", "memory-mirror", "ingest", {"document": "d", "dataset": "notes"}, False),
    ("mirror-ingest-no-dataset", "memory-mirror", "ingest", {"document": "d"}, False),
    ("mirror-ingest-tags", "memory-mirror", "ingest", {"document": "d", "dataset": "file-memory", "tags": []}, False),
    ("mirror-ingest-45000", "memory-mirror", "ingest", {"document": "x" * 45000, "dataset": "file-memory"}, True),
    ("mirror-ingest-45001", "memory-mirror", "ingest", {"document": "x" * 45001, "dataset": "file-memory"}, False),
    ("mirror-ingest-doc-not-str", "memory-mirror", "ingest", {"document": ["d"], "dataset": "file-memory"}, False),
    ("mirror-ingest-dataset-list", "memory-mirror", "ingest", {"document": "d", "dataset": ["file-memory"]}, False),
    ("mirror-forget-own-dataset", "memory-mirror", "forget", {"dataset": "file-memory", "doc_key": "k"}, True),
    ("mirror-forget-other-dataset", "memory-mirror", "forget", {"dataset": "notes", "doc_key": "k"}, False),
    ("mirror-recall", "memory-mirror", "recall", {"query": "q"}, False),
    ("mirror-remember", "memory-mirror", "remember", {"content": "c"}, False),
    ("keeper-listed-no-tools", "memory-keeper", "memory_stats", {}, False),
    ("unlisted-client", "stranger", "memory_stats", {}, False),
    ("writer-second-dataset", "roundtrip-writer", "ingest", {"document": "d", "dataset": "notes"}, True),
    ("missing-grant", "nogrant", "memory_stats", {}, False),
    ("unknown-grant", "weirdgrant", "memory_stats", {}, False),
]


def _ident_headers(kind):
    if kind == "user":
        return verified()
    if kind == "nogrant":
        return verified(grant=None, sub="x", client_id="x")
    if kind == "weirdgrant":
        return verified(grant="password", sub="x", client_id="x")
    return machine(kind)


@case("C-MCP-7", "CLIENT_POLICY table, 45,000-char cap, invalid and unset policy", "mcp")
def client_policy(ctx):
    base = ctx.env.mcp()
    rows = []
    for name, who, tool, args, allowed in POLICY_TABLE:
        c = mcp_client(base, _ident_headers(who))
        err, text = c.call(tool, args)
        denied = err and text.startswith("policy_denied:")
        ctx.check(denied == (not allowed), f"{name}: allowed={allowed} got isError={err} {text[:80]!r}")
        rows.append({"case": name, "denied": denied})
    ctx.golden("table", rows)
    # Startup lines for the effective policy (C-OPS-3 checks their format).
    log = ctx.env.output("mcp")
    ctx.check("POLICY memory-mirror -> ingest,forget @ file-memory" in log, "POLICY line for memory-mirror")
    # A malformed policy denies every client_credentials call; a policy that
    # grants a tool outside DATASET_SCOPED_TOOLS is malformed.
    for key, policy in (("mcp-policy-bad", "memory-mirror=ingest@"),
                        ("mcp-policy-unscoped", "memory-mirror=recall@file-memory")):
        b = ctx.env.mcp(key, CLIENT_POLICY=policy)
        c = mcp_client(b, machine("memory-mirror"))
        err, text = c.call("ingest", {"document": "d", "dataset": "file-memory"})
        ctx.check(err and text.startswith("policy_denied:"), f"{key}: deny-all ({text[:60]!r})")
        ctx.check("AUDIT policy_invalid reason=" in ctx.env.output(key), f"{key}: AUDIT policy_invalid line")
        u = mcp_client(b)
        ctx.check(not u.call("memory_stats", {})[0], f"{key}: authorization_code unaffected")
        ctx.env.stop(key)
    # Unset = gate off.
    b = ctx.env.mcp("mcp-policy-unset", CLIENT_POLICY=None)
    c = mcp_client(b, machine("stranger"))
    ctx.check(not c.call("memory_stats", {})[0], "unset policy allows a machine call")
    ctx.check("AUDIT policy_unset" in ctx.env.output("mcp-policy-unset"), "AUDIT policy_unset line")


# --------------------------------------------------------------------------- #
@case("C-MCP-8", "provenance from X-Verified-* and the destructive-op matrix", "mcp")
def provenance_matrix(ctx):
    base = ctx.env.mcp("mcp-policy-unset", CLIENT_POLICY=None)
    es = ctx.env.es
    es.reset_data()
    ctx.env._scenario = None
    out = {"stamped": {}, "matrix": []}
    # Stamping: what reaches ES comes from the headers, never the arguments.
    for who, hdrs in (("authorization_code", verified()),
                      ("client_credentials", machine("roundtrip-writer"))):
        es.clear()
        c = mcp_client(base, hdrs)
        res = c.call_json("remember", {"content": f"provenance probe {who}", "type": "fact",
                                       "provenance": {"agent": "forged", "source_class": "user-stated"}})
        doc = es.indices["memory-fact"]["docs"][res["id"]]
        out["stamped"][who] = lib.Normalizer()(doc["provenance"])
    # Matrix: 3 grants x 3 target source classes, forget by id.
    grants = {"authorization_code": verified(), "client_credentials-own": machine("roundtrip-writer"),
              "client_credentials-other": machine("memory-keeper")}
    n = 0
    for sc in ("user-stated", "tool-output", "reflection"):
        for g, hdrs in grants.items():
            n += 1
            doc_id = f"matrix-{n}"
            es.seed("memory-fact", doc_id, {"content": f"matrix {n}", "memory_type": "fact",
                                            "provenance": {"agent": "roundtrip-writer", "source_class": sc,
                                                           "session_id": "", "written_at": "2026-01-01T00:00:00Z"}})
            c = mcp_client(base, hdrs)
            err, text = c.call("forget", {"id": doc_id})
            superseded = es.indices["memory-fact"]["docs"][doc_id].get("superseded_by")
            out["matrix"].append({"target_source_class": sc, "caller": g, "isError": err,
                                  "text": text if err else json.loads(text), "superseded_by": superseded})
    ctx.golden("provenance", lib.Normalizer()(out))
    want = {("user-stated", "authorization_code"): True, ("user-stated", "client_credentials-own"): False,
            ("user-stated", "client_credentials-other"): False, ("tool-output", "authorization_code"): True,
            ("tool-output", "client_credentials-own"): True, ("tool-output", "client_credentials-other"): False,
            ("reflection", "authorization_code"): True, ("reflection", "client_credentials-own"): True,
            ("reflection", "client_credentials-other"): False}
    for row in out["matrix"]:
        ctx.eq(row["superseded_by"] == "forget", want[(row["target_source_class"], row["caller"])],
               f"forget {row['target_source_class']} by {row['caller']}")
    ctx.eq(out["stamped"]["authorization_code"]["source_class"], "user-stated", "interactive fact")
    ctx.eq(out["stamped"]["client_credentials"]["agent"], "roundtrip-writer", "machine agent = client_id")


# --------------------------------------------------------------------------- #
COERCION = [
    ("top_k-string", "recall", {"query": "x", "top_k": "3"}),
    ("top_k-float-string", "recall", {"query": "x", "top_k": "3.5"}),
    ("top_k-null", "recall", {"query": "x", "top_k": None}),
    ("filters-json-string", "recall", {"query": "x", "filters": "{\"tags\": \"todo\"}"}),
    ("filters-null", "recall", {"query": "x", "filters": None}),
    ("include_auto-string", "recall", {"query": "x", "include_auto": "false"}),
    ("tags-json-string", "remember", {"content": "coercion tags", "type": "fact", "tags": "[\"a\"]"}),
    ("limit-string", "browse", {"limit": "2"}),
    ("include_chain-int", "get", {"id": "missing", "include_chain": 1}),
]


@case("C-MCP-9", "argument coercion accepted by the Python server", "mcp")
def coercion(ctx):
    base = ctx.env.mcp()
    c = mcp_client(base)
    rows = []
    for name, tool, args in COERCION:
        err, text = c.call(tool, args)
        if tool == "recall":
            settle(ctx.env.es)
        # Only the framing prefix is contract: the validation message after it
        # is the SDK's own wording (pydantic here).
        prefix = f"Error executing tool {tool}: "
        if err:
            ctx.check(text.startswith(prefix), f"{name}: {text[:80]!r}")
        rows.append({"case": name, "isError": err,
                     "text_prefix": prefix if err else None,
                     "keys": sorted(json.loads(text)) if not err else None})
    ctx.golden("rows", rows)


# --------------------------------------------------------------------------- #
def _open_get(url, session, headers):
    """Open the standalone GET stream and hold it; returns (socket, thread)."""
    from urllib.parse import urlsplit
    parts = urlsplit(url)
    s = socket.create_connection((parts.hostname, parts.port), timeout=30)
    lines = [f"GET {parts.path} HTTP/1.1", f"Host: {parts.hostname}:{parts.port}",
             "Accept: text/event-stream", f"Mcp-Session-Id: {session}"]
    lines += [f"{k}: {v}" for k, v in headers.items()]
    s.sendall(("\r\n".join(lines) + "\r\n\r\n").encode())
    first = s.recv(4096)

    def drain():
        try:
            while s.recv(4096):
                pass
        except OSError:
            pass
    t = threading.Thread(target=drain, daemon=True)
    t.start()
    return s, first


@case("C-MCP-10", "session lifetime: 404 unknown, idle expiry, open GET, slow call, DELETE", "mcp-idle")
def session_lifetime(ctx):
    base = ctx.env.mcp("mcp-idle", MCP_SESSION_IDLE_TIMEOUT="2")
    res = {}
    # unknown id
    bogus = lib.Mcp(f"{base}/memory/mcp", verified())
    bogus.session = "0" * 32
    res["unknown_session"] = bogus.rpc("tools/list", {}).status
    # (a) idle with nothing in flight
    c = mcp_client(base)
    time.sleep(3.0)
    res["a_idle_expired"] = c.rpc("tools/list", {}).status
    # (b) an open GET keeps the session alive; closing it starts the clock
    c = mcp_client(base)
    s, first = _open_get(c.url, c.session, verified())
    res["b_get_status_line"] = first.split(b"\r\n", 1)[0].decode()
    alive = []
    for _ in range(3):
        time.sleep(2.0)
        alive.append(c.rpc("tools/list", {}).status)
    res["b_with_get_open"] = alive
    # shutdown, not just close: the drain thread's recv holds the socket open
    # and no FIN would be sent.
    s.shutdown(socket.SHUT_RDWR)
    s.close()
    time.sleep(3.0)
    res["b_after_close"] = c.rpc("tools/list", {}).status
    # (c) a tools/call slower than the idle timeout completes; the session stays
    c = mcp_client(base)
    ctx.env.es.mode["delay"] = ("/memory-episode/_count", 6.0)
    try:
        err, _text = c.call("memory_stats", {})
    finally:
        ctx.env.es.mode.pop("delay", None)
    res["c_slow_call_ok"] = not err
    res["c_after_slow_call"] = c.rpc("tools/list", {}).status
    # (d) every request resets the clock
    c = mcp_client(base)
    seq = []
    for _ in range(4):
        time.sleep(1.5)
        seq.append(c.rpc("tools/list", {}).status)
    res["d_periodic"] = seq
    # DELETE ends the session
    res["delete"] = c.delete().status
    res["after_delete"] = c.rpc("tools/list", {}).status
    ctx.golden("lifetime", res)
    ctx.eq(res["a_idle_expired"], 404, "idle session expires")
    ctx.eq(res["b_with_get_open"], [200, 200, 200], "open GET keeps it")
    ctx.eq(res["b_after_close"], 404, "expires after GET closes")
    ctx.eq((res["c_slow_call_ok"], res["c_after_slow_call"]), (True, 200), "slow call survives")
    ctx.eq(res["d_periodic"], [200] * 4, "requests reset the clock")
    ctx.eq(res["after_delete"], 404, "DELETE ends the session")
