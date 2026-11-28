"""C-SES-8 (archive objects) and C-SES-9 (purge ordering), against the fake
object stores of fake_archive.py: S3 with SigV4 and GCS with a metadata-server
token, both reached through the suite's forward proxy.

What the implementation writes is read back from the fake store, and what it
reads is planted there: an object written by another encoder (raw zstd blocks)
must read like its own, so a Python-written and a Rust-written archive stay
interchangeable (the contract's "read each other's objects")."""

from __future__ import annotations

import hashlib
import io
import json
import tarfile
import threading
import time

import fake_archive as fa
import lib
from cases_ses import LINE, SID, ingest_body, ready, segment, sess
from common import machine, verified
from lib import case

SESSION_INDEX = "memory-session"
MESSAGE_INDEX = "memory-session-message"
MiB = 1024 * 1024

LINE2 = LINE.replace("11111111-2222-4333-8444-555555555555", "21111111-2222-4333-8444-555555555555") \
            .replace("hello roundtrip", "second line of the roundtrip session")
LINE3 = json.dumps({"type": "assistant", "uuid": "31111111-2222-4333-8444-555555555555", "sessionId": SID,
                    "timestamp": "2026-11-01T00:00:01.000Z", "cwd": "/work/roundtrip",
                    "message": {"role": "assistant", "content": [{"type": "text", "text": "a reply"}]}},
                   separators=(",", ":"))
BLOBS = {"toolu_01.txt": "tool output for the roundtrip\n", "toolu_02.json": '{"k": "v"}\n'}


def _archive_mcp(ctx, key, backend, **over):
    env = ctx.env.archive.env(backend)
    env.update(over)
    base = ctx.env.mcp(key, **env)
    ctx.check(ready(base), f"{key}: session indices ready")
    return base


def _doc(ctx, key):
    es = ctx.env.es
    with es.lock:
        src = es.indices.get(SESSION_INDEX, {"docs": {}})["docs"].get(key)
        return json.loads(json.dumps(src)) if src is not None else None


def _messages(ctx, key):
    es = ctx.env.es
    with es.lock:
        docs = es.indices.get(MESSAGE_INDEX, {"docs": {}})["docs"]
        return sorted(i for i, s in docs.items() if s.get("session_key") == key)


def _blob(base, key, name, content, hdrs):
    return sess(base, "POST", "/blob", hdrs, body={
        "session_key": key, "name": name, "content": content,
        "sha256": hashlib.sha256(content.encode()).hexdigest()})


def _archive_get(base, key, hdrs, path="/archive"):
    r = lib.request("GET", f"{base}/memory/sessions/v1{path}?session_key={key}", headers=hdrs)
    return r


def _err(r):
    try:
        return [r.status, r.json().get("error")]
    except (ValueError, AttributeError):
        return [r.status, None]


def _tar(body):
    out = []
    with tarfile.open(fileobj=io.BytesIO(body), mode="r:") as tar:
        for m in tar.getmembers():
            out.append({"name": m.name, "size": m.size, "mode": oct(m.mode), "type": m.type.decode(),
                        "content": tar.extractfile(m).read().decode("utf-8")})
    return out


def _object_trace(ops, key):
    """The store operations, with the session key folded, as comparable data."""
    out = []
    for o in ops:
        name = (o.name or "").replace(key, "<session_key>")
        out.append([o.backend, o.op, o.method, name, o.status])
    return out


def archive_objects(ctx, backend):
    arch = ctx.env.archive
    arch.reset()
    ctx.env.es.reset_data()
    base = _archive_mcp(ctx, f"mcp-archive-{backend}", backend)
    a = machine("session-search-a")
    rows = {}
    s1 = segment([LINE, LINE2])
    s2 = segment([LINE3], offset=s1["end_offset"])
    st1, r1 = sess(base, "POST", "/ingest", a, body=ingest_body(seg=s1))
    st2, r2 = sess(base, "POST", "/ingest", a, body=ingest_body(seg=s2))
    rows["ingest"] = [[st1, r1], [st2, r2]]
    ctx.eq((st1, r1.get("archive"), st2, r2.get("archive")), (200, "written", 200, "written"), "two archived segments")
    key = r1["session_key"]
    prefix = f"sessions/host-a/{key}/"
    seg_names = [f"{prefix}g0/{0:012d}.jsonl.zst", f"{prefix}g0/{s1['end_offset']:012d}.jsonl.zst"]
    ctx.eq(arch.names(backend), seg_names, "object names: sessions/<host>/<session_key>/g<gen>/<offset:012d>.jsonl.zst")

    # The session doc's chunk list is the index of the objects.
    doc = _doc(ctx, key)
    chunks = [c for c in doc["archive_chunks"] if "name" not in c]
    rows["doc"] = {k: doc.get(k) for k in ("archived", "archive_complete", "archive_generation", "archive_bytes")}
    rows["chunks"] = chunks
    frames = {n.replace(key, "<session_key>"): fa.frame_header(arch.get(backend, n)) for n in seg_names}
    rows["frames"] = frames
    for n, c in zip(seg_names, chunks):
        ctx.eq(fa.frame_header(arch.get(backend, n)).get("content_size"), c["bytes"],
               f"{n}: zstd frame carries the content size")

    # Download: canonical JSONL, X-Archive-Sha256, per-chunk sha256.
    r = _archive_get(base, key, a)
    body = r.body
    rows["archive"] = {"status": r.status, "content_type": r.header("content-type"),
                       "sha_header_matches": r.header("x-archive-sha256") == hashlib.sha256(body).hexdigest(),
                       "body": body.decode("utf-8")}
    ctx.eq(r.status, 200, "archive download")
    ctx.check(rows["archive"]["sha_header_matches"], "X-Archive-Sha256 is the sha256 of the body")
    pos, pieces = 0, []
    for c in chunks:
        piece = body[pos:pos + c["bytes"]]
        ctx.eq(hashlib.sha256(piece).hexdigest(), c["sha256"], f"chunk at {c['offset']}: sha256 of its bytes")
        pieces.append(piece)
        pos += c["bytes"]
    ctx.eq(pos, len(body), "chunks cover the body")

    # Tool-results side files and their tar.
    rows["blobs"] = {n: list(_blob(base, key, n, text, a)) for n, text in BLOBS.items()}
    blob_names = sorted(f"{prefix}tool-results/{n}.zst" for n in BLOBS)
    ctx.eq(arch.names(backend, prefix + "tool-results/"), blob_names, "side-file object names")
    t = _archive_get(base, key, a, "/archive/tool-results")
    rows["tool_results"] = {"status": t.status, "content_type": t.header("content-type"),
                            "members": _tar(t.body) if t.status == 200 else None}

    originals = {n: arch.get(backend, n) for n in arch.names(backend)}

    def restore():
        arch.mode.clear()
        for n, data in originals.items():
            arch.put(backend, n, data)

    # Another encoder's frames (raw zstd blocks) read like the implementation's own.
    for n, piece in zip(seg_names, pieces):
        arch.put(backend, n, fa.frame(piece))
    r = _archive_get(base, key, a)
    rows["foreign_frames"] = [r.status, r.body == body]
    ctx.eq(rows["foreign_frames"], [200, True], "objects from another zstd encoder")
    restore()

    tamper = {}
    arch.put(backend, seg_names[0], fa.frame(b"other bytes\n" * 3))
    tamper["other-content"] = _err(_archive_get(base, key, a))
    restore()
    arch.put(backend, seg_names[0], b"not a zstd frame")
    tamper["not-zstd"] = _err(_archive_get(base, key, a))
    restore()
    arch.put(backend, seg_names[0], fa.frame(rle=(0x41, 5 * MiB + 1)))
    tamper["expands-past-5MiB"] = _err(_archive_get(base, key, a))
    restore()
    arch.mode["fail"] = {"get": 500}
    tamper["store-answers-500"] = _err(_archive_get(base, key, a))
    restore()
    arch.put(backend, blob_names[0], fa.frame(b"other tool output\n"))
    tamper["side-file-other-content"] = _err(_archive_get(base, key, a, "/archive/tool-results"))
    restore()
    arch.remove(backend, blob_names[0])
    tamper["side-file-missing"] = _err(_archive_get(base, key, a, "/archive/tool-results"))
    restore()
    # A missing segment marks the session incomplete; putting the object back
    # does not clear the mark (only a new ingest does).
    arch.remove(backend, seg_names[1])
    tamper["segment-missing"] = _err(_archive_get(base, key, a))
    tamper["segment-missing/doc"] = _doc(ctx, key).get("archive_complete")
    restore()
    tamper["segment-restored"] = _err(_archive_get(base, key, a))
    rows["tamper"] = tamper
    ctx.eq(tamper["other-content"], [409, "archive_tampered"], "sha256 mismatch")
    ctx.eq(tamper["not-zstd"], [409, "archive_tampered"], "not zstd")
    ctx.eq(tamper["expands-past-5MiB"], [409, "archive_tampered"], "5 MiB decompression cap")
    ctx.eq(tamper["store-answers-500"], [503, "archive_unavailable"], "store 5xx")
    ctx.eq(tamper["segment-missing"], [409, "archive_incomplete"], "missing segment")
    ctx.eq(tamper["segment-missing/doc"], False, "archive_complete cleared")

    # How the backend talked to the store.
    ops = arch.taken()
    ctx.eq([o for o in ops if o.backend in ("refused", "tls")], [], "no tunnel to any other host")
    ctx.eq([(o.op, o.problem) for o in ops if o.problem], [], "every request authenticated")
    if backend == "s3":
        put = next(o for o in ops if o.op == "put")
        neg = {
            "wrong-secret": fa.verify_sigv4(put.method, put.raw_path, put.headers, put.body, secret_key="x"),
            "other-body": fa.verify_sigv4(put.method, put.raw_path, put.headers, put.body + b"x"),
            "other-path": fa.verify_sigv4(put.method, put.raw_path + "x", put.headers, put.body),
        }
        ctx.check(all(neg.values()), f"SigV4 verifier negative controls: {neg}")
        rows["store"] = {"signed_headers": sorted({
            p.split("=", 1)[1] for o in ops if o.header("authorization")
            for p in o.header("authorization").split(", ") if p.startswith("SignedHeaders=")})}
    else:
        tokens = [o for o in ops if o.backend == "metadata"]
        ctx.eq(len(tokens), 1, "one metadata token fetch, then cached")
        rows["store"] = {"token_requests": len(tokens),
                         "upload_query": sorted({k for o in ops if o.op == "put"
                                                 for k in dict(p.split("=", 1) for p in
                                                               o.raw_path.split("?", 1)[1].split("&"))})}
    rows["store"]["ops"] = sorted({f"{o.op} {o.method}" for o in ops if o.backend == backend})
    norm = lib.Normalizer()
    out = norm(rows)
    out["archive"]["body"] = rows["archive"]["body"]   # canonical JSONL byte for byte, timestamps included
    ctx.golden("archive", out)
    ctx.env.stop(f"mcp-archive-{backend}")


@case("C-SES-8", "archive objects in fake S3 (SigV4): names, zstd, sha256, tar, tamper, 5 MiB cap", "ses")
def archive_objects_s3(ctx):
    archive_objects(ctx, "s3")


@case("C-SES-8", "archive objects in fake GCS (metadata token): the same contract", "ses")
def archive_objects_gcs(ctx):
    archive_objects(ctx, "gcs")


# --------------------------------------------------------------------------- #
# C-SES-9
# --------------------------------------------------------------------------- #
def _bulk_ids(rec):
    out = []
    for ln in rec.body.decode().split("\n"):
        if ln.strip():
            obj = json.loads(ln)
            if len(obj) == 1 and next(iter(obj)) in ("index", "delete", "create"):
                _id = next(iter(obj.values())).get("_id")
                if _id:
                    out.append(_id)
    return out


def _label(rec, key, ids):
    """One ES write as a timeline label, or None when it is not part of the
    purge protocol. Reads (GET of the session doc) are left out: how often an
    implementation re-reads is not the contract, the order of the writes is."""
    p = rec.path
    if p == f"/{SESSION_INDEX}/_doc/{key}" and rec.method == "PUT" and "if_seq_no" in rec.query:
        body = rec.json() or {}
        return "es: session doc conditional write" + (" (purged form)" if body.get("purged_at") else "")
    if p == f"/{SESSION_INDEX}/_create/{key}":
        return "es: session doc create"
    if p == f"/{MESSAGE_INDEX}/_delete_by_query":
        return "es: delete messages by query" if key in rec.body.decode() else None
    if p == "/_bulk" and (key in rec.body.decode() or set(_bulk_ids(rec)) & ids):
        first = json.loads(rec.body.decode().split("\n", 1)[0])
        return f"es: bulk {next(iter(first))} messages"
    return None


def _timeline(ctx, key, since, ids=frozenset()):
    items = [(r.at, _label(r, key, ids)) for r in ctx.env.es.taken(lambda r: r.at >= since)]
    items += [(o.at, f"archive: {o.op}") for o in ctx.env.archive.taken(lambda o: o.at >= since)
              if o.backend in ("s3", "gcs") and key in (o.name or "")]
    return [label for _, label in sorted(items, key=lambda x: x[0]) if label]


def _in_thread(fn):
    out = {}

    def run():
        out["result"] = fn()
    t = threading.Thread(target=run, daemon=True)
    t.start()
    return t, out


@case("C-SES-9", "purge: flip first, then objects, then messages; competing writers discard; 409 purged", "ses")
def purge_ordering(ctx):
    arch = ctx.env.archive
    arch.reset()
    ctx.env.es.reset_data()
    p1 = _archive_mcp(ctx, "mcp-purge-1", "s3")
    p2 = _archive_mcp(ctx, "mcp-purge-2", "s3")
    a, op = machine("session-search-a"), verified()
    rows = {}
    s1 = segment([LINE, LINE2])
    s2 = segment([LINE3], offset=s1["end_offset"])

    # A. One purge, observed end to end.
    st, r = sess(p1, "POST", "/ingest", a, body=ingest_body(seg=s1))
    key = r["session_key"]
    sess(p1, "POST", "/blob", a, body={"session_key": key, "name": "toolu_01.txt", "content": "x\n",
                                        "sha256": hashlib.sha256(b"x\n").hexdigest()})
    before = _doc(ctx, key)
    since = time.monotonic()
    rows["purge"] = list(sess(p2, "DELETE", f"/session?session_key={key}", op))
    timeline = _timeline(ctx, key, since)
    rows["purge_timeline"] = timeline
    flip = timeline.index("es: session doc conditional write (purged form)")
    lists = [i for i, x in enumerate(timeline) if x == "archive: list"]
    deletes = [i for i, x in enumerate(timeline) if x == "archive: delete"]
    msgs = timeline.index("es: delete messages by query")
    ctx.check(flip < min(lists) and max(lists) < min(deletes) and max(deletes) < msgs,
              f"flip, then list, then deletes, then messages: {timeline}")
    ctx.eq(arch.names("s3", f"sessions/host-a/{key}/"), [], "every object of the session deleted")
    ctx.eq(_messages(ctx, key), [], "every message deleted")
    tomb = _doc(ctx, key)
    rows["tombstone_keys"] = sorted(tomb)
    ctx.eq(sorted(tomb), ["host", "purged_at", "purged_by", "session_key"],
           "tombstone keeps only session_key, host, purged_at, purged_by")
    ctx.check(before.get("cwd") and "cwd" not in tomb and "title" not in tomb and "archive_chunks" not in tomb,
              "no title, cwd or chunk list in the tombstone")

    # Refusals: the purging process, the other process (marker only) and a restart.
    refuse = {
        "ingest (purging process)": sess(p2, "POST", "/ingest", a, body=ingest_body(seg=s2)),
        "ingest (other process)": sess(p1, "POST", "/ingest", a, body=ingest_body(seg=s2)),
        "blob": sess(p1, "POST", "/blob", a, body={"session_key": key, "name": "toolu_02.txt", "content": "y\n",
                                                   "sha256": hashlib.sha256(b"y\n").hexdigest()}),
        "state": sess(p1, "POST", "/state", a, body={"session_key": key, "jsonl_exists": False}),
        "archive": sess(p1, "GET", f"/archive?session_key={key}", a),
    }
    ctx.env.stop("mcp-purge-1")
    p1 = _archive_mcp(ctx, "mcp-purge-1", "s3")
    refuse["ingest (after restart)"] = sess(p1, "POST", "/ingest", a, body=ingest_body(seg=s1))
    rows["refusals"] = {k: [v[0], (v[1] or {}).get("error")] for k, v in refuse.items()}
    for k in ("ingest (purging process)", "ingest (other process)", "blob", "state", "ingest (after restart)"):
        ctx.eq(rows["refusals"][k], [409, "purged"], k)
    # DELETE /purged lifts the marker; the key is ingestable again.
    rows["clear"] = list(sess(p2, "DELETE", f"/purged?session_key={key}", op))
    rows["after_clear"] = {"doc": _doc(ctx, key)}
    # Re-ingest through the process that cleared the marker. Another Python
    # process that already refused this key keeps refusing it until it restarts
    # (its in-process purged set); that cache is not part of the contract.
    st, r = sess(p2, "POST", "/ingest", a, body=ingest_body(seg=s1))
    rows["after_clear"]["ingest"] = [st, (r or {}).get("archive")]
    rows["clear_again"] = list(sess(p2, "DELETE", f"/purged?session_key={key}", op))
    ctx.eq(rows["clear"][0], 200, "DELETE /purged")
    ctx.eq(rows["after_clear"], {"doc": None, "ingest": [200, "written"]}, "re-ingest after the marker is cleared")

    # B. A writer in another process loses its conditional session write to a
    #    purge that ran between its object PUT and that write.
    ctx.env.es.reset_data()
    arch.reset()
    sid_b = SID.replace("0f0e", "0b0e")
    st, r = sess(p1, "POST", "/ingest", a, body=ingest_body(seg=s1, sid=sid_b))
    key_b = r["session_key"]
    gate = ctx.env.es.hold(lambda rec: rec.path == "/_bulk" and key_b in rec.body.decode()
                           and '"index"' in rec.body.decode().split("\n", 1)[0])
    t, out = _in_thread(lambda: sess(p1, "POST", "/ingest", a, body=ingest_body(seg=s2, sid=sid_b)))
    ctx.check(gate["arrived"].wait(15), "writer reached its message bulk")
    since = time.monotonic()
    purge_b = sess(p2, "DELETE", f"/session?session_key={key_b}", op)
    ctx.env.es.release()
    t.join(30)
    held = ctx.env.es.taken(lambda rec: rec.path == "/_bulk" and key_b in rec.body.decode()
                            and '"index"' in rec.body.decode().split("\n", 1)[0])
    written = set(_bulk_ids(held[-1])) if held else set()
    rows["lost_conditional_write"] = {
        "purge": list(purge_b), "writer": [out["result"][0], (out["result"][1] or {}).get("error")],
        "timeline": _timeline(ctx, key_b, since, written),
        "objects_left": arch.names("s3", f"sessions/host-a/{key_b}/"), "messages_left": _messages(ctx, key_b)}
    ctx.eq(rows["lost_conditional_write"]["writer"], [409, "purged"], "the late writer is refused")
    ctx.eq(rows["lost_conditional_write"]["messages_left"], [], "the late writer deleted its messages")
    ctx.check(written and "es: bulk delete messages" in rows["lost_conditional_write"]["timeline"],
              "the late writer deleted its message ids after losing the conditional write")
    ctx.eq(rows["lost_conditional_write"]["objects_left"], [], "no object left")

    # C. A writer whose object PUT lands after the purge deletes that object itself.
    ctx.env.es.reset_data()
    arch.reset()
    sid_c = SID.replace("0f0e", "0c0e")
    st, r = sess(p1, "POST", "/ingest", a, body=ingest_body(seg=s1, sid=sid_c))
    key_c = r["session_key"]
    late = f"sessions/host-a/{key_c}/g0/{s1['end_offset']:012d}.jsonl.zst"
    hold = arch.hold("put", late)
    t, out = _in_thread(lambda: sess(p1, "POST", "/ingest", a, body=ingest_body(seg=s2, sid=sid_c)))
    ctx.check(hold["arrived"].wait(15), "writer reached its object PUT")
    since = time.monotonic()
    purge_c = sess(p2, "DELETE", f"/session?session_key={key_c}", op)
    arch.release()
    t.join(30)
    rows["late_object"] = {
        "purge": list(purge_c), "writer": [out["result"][0], (out["result"][1] or {}).get("error")],
        "timeline": _timeline(ctx, key_c, since),
        "objects_left": arch.names("s3", f"sessions/host-a/{key_c}/"), "messages_left": _messages(ctx, key_c)}
    ctx.eq(rows["late_object"]["writer"], [409, "purged"], "the late object's writer is refused")
    ctx.eq(rows["late_object"]["objects_left"], [], "the late object was deleted by its writer")
    ctx.env.stop("mcp-purge-1")
    ctx.env.stop("mcp-purge-2")
    norm = lib.Normalizer()
    ctx.golden("purge", norm(rows))
