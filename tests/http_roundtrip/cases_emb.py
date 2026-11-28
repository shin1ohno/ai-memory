"""C-EMB-1: the embedding client, seen from the fake Voyage endpoint."""

from __future__ import annotations

import json as _json
import time

import lib
from common import mcp_client, settle
from fakes import embed
from lib import case


def _bodies(voyage):
    return [r.json() for r in voyage.taken(lambda r: r.path.endswith("/embeddings"))]


@case("C-EMB-1", "Voyage and OpenAI-compatible bodies, index-order restore, retry rules, 128-item batches",
      "mcp")
def embeddings(ctx):
    voyage, es = ctx.env.voyage, ctx.env.es
    out = {}
    # Voyage shape (document, then query).
    base = ctx.env.mcp()
    es.reset_data()
    ctx.env._scenario = None
    c = mcp_client(base)
    voyage.clear()
    c.call_json("remember", {"content": "Embedding probe document", "type": "fact"})
    c.call_json("recall", {"query": "embedding probe"})
    settle(es)
    reqs = voyage.taken(lambda r: r.path.endswith("/embeddings"))
    out["voyage"] = [{"path": r.path, "authorization": (r.header("Authorization") or "").split(" ")[0],
                      "body": lib.Normalizer()(r.json())} for r in reqs]
    # OpenAI-compatible shape.
    b2 = ctx.env.mcp("mcp-openai", EMBEDDING_PROVIDER="openai", EMBEDDING_MODEL="text-embedding-3-large")
    c2 = mcp_client(b2)
    voyage.clear()
    c2.call_json("remember", {"content": "OpenAI shape probe", "type": "fact"})
    out["openai"] = [lib.Normalizer()(b) for b in _bodies(voyage)]
    ctx.env.stop("mcp-openai")
    # The response's `index` decides the order, not the array position.
    voyage.mode["reverse"] = True
    try:
        es.clear()
        doc = "\n\n".join(f"Paragraph {i} " + ("filler words " * 90) for i in range(4))
        c.call_json("ingest", {"document": doc, "dataset": "notes", "doc_key": "emb/order"})
    finally:
        voyage.mode.pop("reverse", None)
    bulk = es.taken(lambda r: r.path == "/_bulk")[0]
    lines = [_json.loads(ln) for ln in bulk.body.decode().splitlines() if ln.strip()][1::2]
    out["order_restored"] = all(d["embedding"] == embed(d["content"], 1024) for d in lines)
    out["order_chunks"] = len(lines)
    # 5xx and a dropped connection: one retry after about 0.5 s.
    for name, fail in (("5xx", [503]), ("drop", ["drop"]), ("5xx-twice", [500, 502]), ("4xx", [401])):
        voyage.clear()
        voyage.mode["fail"] = list(fail)
        t0 = time.monotonic()
        err, text = c.call("remember", {"content": f"retry probe {name}", "type": "fact"})
        took = time.monotonic() - t0
        reqs = voyage.taken(lambda r: r.path.endswith("/embeddings"))
        voyage.mode.pop("fail", None)
        gap = round(reqs[1].at - reqs[0].at, 1) if len(reqs) > 1 else None
        out[f"retry-{name}"] = {"isError": err, "attempts": len(reqs),
                                "gap_ge_0.45": gap is not None and gap >= 0.45,
                                "error_prefix": text.split(":")[0] if err else None, "took_lt_5s": took < 5}
    # More than 128 inputs: batches of 128 (and a background job: over 40 chunks).
    voyage.clear()
    big = "\n\n".join(f"Block {i:03d} " + ("x" * 1100) for i in range(129))
    res = c.call_json("ingest", {"document": big, "dataset": "notes", "doc_key": "emb/129"})
    job = res.get("job_id")
    status = None
    for _ in range(100):
        stats = c.call_json("memory_stats", {})
        jobs = [j for j in stats["ingest_jobs"] if j["job_id"] == job]
        status = jobs[0]["status"] if jobs else None
        n_chunks = jobs[0]["chunk_count"] if jobs else None
        if status in ("done", "error"):
            break
        time.sleep(0.1)
    sizes = [len(b["input"]) for b in _bodies(voyage)]
    out["batches"] = {"job_returned": bool(job), "job_status": status, "chunks": n_chunks,
                      "batch_sizes": sizes}
    ctx.golden("embeddings", out)
    ctx.eq(out["order_restored"], True, "vectors follow `index`")
    ctx.eq(out["retry-5xx"]["attempts"], 2, "5xx retried once")
    ctx.eq(out["retry-drop"]["attempts"], 2, "connection failure retried once")
    ctx.eq(out["retry-4xx"]["attempts"], 1, "4xx not retried")
    ctx.eq((out["retry-5xx-twice"]["attempts"], out["retry-5xx-twice"]["isError"]), (2, True), "gives up")
    ctx.check(n_chunks and n_chunks > 128, f"more than one batch of input ({n_chunks})")
    ctx.eq(sizes, [128] * (n_chunks // 128) + ([n_chunks % 128] if n_chunks % 128 else []), "batch sizes")
