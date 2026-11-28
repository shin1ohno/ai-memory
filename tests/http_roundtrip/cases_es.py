"""C-ES-1..5: what the implementation does to Elasticsearch."""

from __future__ import annotations

import json
import os
import sys
import time
from datetime import datetime, timedelta, timezone

import lib
from cases_mcp import scenario
from common import machine, mcp_client, settle, verified
from fakes import FakeES, embed
from lib import case

INDEX_FILES = {"memory-fact": "memory-fact.json", "memory-knowledge": "memory-knowledge.json",
               "memory-episode": "memory-episode.json", "memory-stats": "memory-stats.json",
               "memory-session": "memory-session.json", "memory-session-message": "memory-session-message.json"}


def _wait_sessions_ready(base, timeout=20.0):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        r = lib.request("GET", f"{base}/memory/sessions/v1/status", headers=verified())
        if r.status == 200 and r.json().get("ready"):
            return r.json()
        time.sleep(0.2)
    return None


@case("C-ES-1", "index definitions, memory-all alias and session _meta.schema", "es-fresh")
def index_definitions(ctx):
    es = FakeES()
    try:
        base = ctx.env.mcp("mcp-es-fresh", es=es)
        _wait_sessions_ready(base)
        puts = {r.path.strip("/"): r.json() for r in es.taken(lambda r: r.method == "PUT")}
        aliases = [r.json() for r in es.taken(lambda r: r.path == "/_aliases")]
        out = {"indices": puts, "aliases": aliases,
               "mapping_reads": sorted({r.path for r in es.taken(lambda r: r.path.endswith("/_mapping"))})}
        ctx.golden("definitions", out)
        ctx.eq(sorted(puts), sorted(INDEX_FILES), "six indices created")
        for name, fname in INDEX_FILES.items():
            with open(os.path.join(lib.REPO, "es-indices-v2", fname), encoding="utf-8") as fh:
                want = json.load(fh)
            got = puts[name]
            # The session indices' replica count is the deployment knob
            # SESSION_INDEX_REPLICAS (0 in this suite); the files carry 1.
            if name.startswith("memory-session"):
                got = json.loads(json.dumps(got))
                want.get("settings", {}).pop("number_of_replicas", None)
                got.get("settings", {}).pop("number_of_replicas", None)
            ctx.eq(got, want, f"PUT /{name} body equals es-indices-v2/{fname}")
        ctx.eq(aliases, [{"actions": [{"add": {"index": i, "alias": "memory-all"}} for i in
                                      ("memory-fact", "memory-knowledge", "memory-episode")]}],
               "memory-all over the three content indices only")
        ctx.eq(puts["memory-session"]["mappings"]["_meta"], {"schema": "session/1"}, "session schema")
        ctx.eq(puts["memory-session-message"]["mappings"]["_meta"], {"schema": "session-message/1"},
               "message schema")
    finally:
        ctx.env.stop("mcp-es-fresh")
        es.close()


@case("C-ES-2", "REST calls per tool: method, path, query, body (refresh/retry/conflicts)", "mcp")
def rest_semantics(ctx):
    _steps, traces = scenario(ctx)
    norm = lib.Normalizer()
    out = []
    for t in traces:
        reqs = [r for r in t["requests"]
                # the use_count bump is fire-and-forget; it is compared separately below
                if not (r.path.endswith("/_update_by_query") and r.query.get("conflicts") == "proceed"
                        and "refresh" not in r.query)]
        out.append({"step": t["step"], "requests": lib.es_trace(reqs, norm)})
    bumps = [lib.es_trace([r], norm)[0] for t in traces for r in t["requests"]
             if r.path.endswith("/_update_by_query") and "refresh" not in r.query]
    ctx.golden("trace", out)
    ctx.golden("use-count-bumps", bumps)
    flat = [(r["method"], r["path"], r["query"]) for t in out for r in t["requests"]]
    ctx.check(any(q.get("refresh") == "wait_for" for _m, p, q in flat if p.endswith("/_doc")),
              "writes use refresh=wait_for")
    ctx.check(any(q.get("retry_on_conflict") == "3" for _m, _p, q in flat), "tag union retries on conflict")
    ctx.check(all(q.get("conflicts") == "proceed" for _m, p, q in flat if p.endswith("_update_by_query")),
              "update_by_query proceeds on conflicts")


def _seed_ranked(es, now):
    """50 fact documents with known text, age and use_count."""
    words = ["alpha", "bravo", "charlie", "delta", "echo"]
    for i in range(50):
        text = f"rank doc {i} " + " ".join(words[: 1 + i % 5]) + (" target" * (i % 3))
        written = now - timedelta(days=(i * 7) % 200)
        es.seed("memory-fact", f"rank-{i:02d}", {
            "content": text, "embedding": embed(text, 1024), "memory_type": "fact",
            "tags": [], "entities": [], "use_count": (i * 13) % 40,
            "provenance": {"agent": "seed", "session_id": "", "source_class": "tool-output",
                           "written_at": written.strftime("%Y-%m-%dT%H:%M:%SZ")},
            "content_hash": f"hash-{i}", "reconcile_status": "raw"})


@case("C-ES-3", "RRF (k=60) and composite score over 50 fixed documents; chunking 1200/150", "mcp")
def ranking(ctx):
    es = ctx.env.es
    base = ctx.env.mcp()
    es.reset_data()
    ctx.env._scenario = None
    now = datetime.now(timezone.utc)
    _seed_ranked(es, now)
    c = mcp_client(base)
    rows = {}
    for q, k in (("target alpha", 10), ("echo delta charlie", 50), ("bravo", 5)):
        res = c.call_json("recall", {"query": q, "type": "fact", "top_k": k, "include_auto": True})
        settle(es)
        es.reset_data()  # the bump changed use_count; reseed for the next query
        _seed_ranked(es, now)
        rows[f"{q}/top{k}"] = [[h["id"], round(h["score"], 6)] for h in res["hits"]]
    ctx.golden("ranking", rows)
    # Chunking: a 5,000-character document with paragraph breaks.
    para = ("Chunking contract sentence number {n} keeps the window honest. " * 3).strip()
    doc = "\n\n".join(para.format(n=i) for i in range(30))
    es.clear()
    res = c.call_json("ingest", {"document": doc, "dataset": "notes", "doc_key": "chunking/1"})
    bulk = es.taken(lambda r: r.path == "/_bulk")[0]
    lines = [json.loads(ln) for ln in bulk.body.decode("utf-8").splitlines() if ln.strip()]
    chunks = [ln for ln in lines[1::2]]
    out = {"chunk_count": res["chunk_count"],
           "chunks": [{"chunk_index": ch["chunk_index"], "len": len(ch["content"]),
                       "head": ch["content"][:40], "tail": ch["content"][-40:],
                       "content_hash": ch["content_hash"]} for ch in chunks]}
    ctx.golden("chunks", out)
    ctx.check(all(x["len"] <= 1200 for x in out["chunks"]), "chunks are at most 1200 characters")


@case("C-ES-4", "keeper merge_rules accept implementation-written docs and vice versa", "mcp")
def keeper_shapes(ctx):
    es = ctx.env.es
    base = ctx.env.mcp()
    es.reset_data()
    ctx.env._scenario = None
    sys.path.insert(0, os.path.join(lib.REPO, "memory-keeper"))
    try:
        import merge_rules  # noqa: PLC0415 — stdlib-only keeper module
    finally:
        sys.path.pop(0)
    c = mcp_client(base)
    a = c.call_json("remember", {"content": "Keeper shape fact A", "type": "fact", "tags": ["x"]})
    b = c.call_json("remember", {"content": "Keeper shape fact B", "type": "fact", "tags": ["y"]})
    docs = es.indices["memory-fact"]["docs"]
    src_a, src_b = docs[a["id"]], docs[b["id"]]
    required = {"content", "embedding", "memory_type", "tags", "entities", "provenance", "use_count",
                "content_hash", "reconcile_status"}
    ctx.check(required <= set(src_a), f"fact doc fields {sorted(src_a)}")
    now = "2026-01-01T00:00:00Z"
    merged = merge_rules.merged_fact_doc(src_a, src_b, a["id"], b["id"], "Keeper merged A+B",
                                         src_b["embedding"], now)
    ctx.eq(merged["tags"], ["x", "y"], "tags union")
    ctx.eq(merged["provenance"]["source_class"], "user-stated", "user-stated ratchet")
    # The reverse: a keeper-written doc is readable and revisable by the server.
    es.seed("memory-fact", "keeper-merged", merged)
    got = c.call_json("get", {"id": "keeper-merged"})
    ctx.eq(got["content"], "Keeper merged A+B", "server reads keeper doc")
    rev = c.call_json("revise", {"id": "keeper-merged", "content": "Keeper merged A+B revised"})
    ctx.check(bool(rev.get("new_id")), "server revises keeper doc")
    shape = {"server_fact_keys": sorted(src_a), "server_provenance_keys": sorted(src_a["provenance"]),
             "keeper_merged_keys": sorted(merged), "revised_keys": sorted(docs[rev["new_id"]])}
    ctx.golden("shapes", shape)


@case("C-ES-5", "least-privilege start: 403 with indices present, retries then fails when absent, "
      "sessions 503 while MCP keeps serving", "es-denied")
def least_privilege(ctx):
    out = {}
    # (1) PUT/_aliases answer 403 but everything exists: the server starts.
    es = FakeES()
    try:
        for name in ("memory-fact", "memory-knowledge", "memory-episode", "memory-stats",
                     "memory-session", "memory-session-message"):
            es.indices[name] = {"def": {"mappings": {"_meta": {"schema": {
                "memory-session": "session/1", "memory-session-message": "session-message/1"}.get(name)}}},
                "docs": {}, "seq": {}}
        es.aliases["memory-all"] = ["memory-fact", "memory-knowledge", "memory-episode"]
        es.mode["deny_create"] = True
        base = ctx.env.mcp("mcp-es-denied", es=es)
        c = mcp_client(base)
        out["present_starts"] = not c.call("memory_stats", {})[0]
        out["present_sessions_ready"] = bool(_wait_sessions_ready(base, 15))
        ctx.env.stop("mcp-es-denied")
    finally:
        es.close()
    # (2) the session indices are absent and cannot be created: MCP serves,
    # sessions answer 503 index_unavailable, /status answers 200 ready:false.
    es = FakeES()
    try:
        es.mode["missing"] = {"memory-session", "memory-session-message"}
        base = ctx.env.mcp("mcp-es-nosessions", es=es)
        c = mcp_client(base)
        out["no_sessions_tools_call_ok"] = not c.call("memory_stats", {})[0]
        r = lib.request("POST", f"{base}/memory/sessions/v1/search", headers=machine("session-search-a"),
                        body={"q": "x"})
        out["no_sessions_search"] = [r.status, r.json().get("error")]
        r = lib.request("GET", f"{base}/memory/sessions/v1/status", headers=machine("session-search-a"))
        out["no_sessions_status"] = [r.status, r.json().get("ready")]
        ctx.env.stop("mcp-es-nosessions")
    finally:
        es.close()
    # (3) 403 and absent: the start fails after the retries (10 x 3 s).
    es = FakeES()
    try:
        es.mode["deny_create"] = True
        t0 = time.monotonic()
        proc = ctx.env.mcp_proc("mcp-es-absent", ctx.env.mcp_env(es=es), wait=False)
        proc.p.wait(90)
        out["absent_exit_nonzero"] = proc.p.returncode != 0
        out["absent_put_attempts"] = len(es.taken(lambda r: r.method == "PUT" and r.path == "/memory-fact"))
        out["absent_took_at_least_27s"] = time.monotonic() - t0 >= 27
        ctx.env.stop("mcp-es-absent")
    finally:
        es.close()
    ctx.golden("startup", out)
    ctx.eq(out["present_starts"], True, "starts on 403 when indices exist")
    ctx.eq(out["no_sessions_search"], [503, "index_unavailable"], "sessions 503")
    ctx.eq(out["no_sessions_status"], [200, False], "status ready:false")
    ctx.eq((out["absent_exit_nonzero"], out["absent_put_attempts"]), (True, 10), "fails after 10 tries")
