"""memory-keeper reconcile tick (§6, Phase B).

Runs every ~60s under launchd (LaunchDaemon, UserName shin1ohno). Drains raw
facts oldest-first: for each raw fact, kNN top-10 on memory-fact using the
fact's STORED embedding (no re-embed), then `claude -p` adjudicates
ADD / UPDATE / NOOP. supersede semantics only (never _update content in place);
only superseded_by/at, reconcile_status, use_count, last_used_at ever mutate in
place. Emits a run_kind=reconcile stats doc to memory-stats.

Locking via fcntl.flock (LOCK_EX|LOCK_NB); exit 0 on contention. No flock(1)/
timeout(1) — macOS lacks them; subprocess timeout is inside claude_judge.
"""

from __future__ import annotations

import fcntl
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from es_client import ESClient, ESError, now_iso  # noqa: E402
import voyage_client  # noqa: E402
import claude_judge  # noqa: E402
import merge_rules  # noqa: E402


def _env(name, default):
    v = os.environ.get(name)
    return v if v not in (None, "") else default


FACT_INDEX = _env("FACT_INDEX", "memory-fact")
STATS_INDEX = _env("STATS_INDEX", "memory-stats")
KEEPER_HOST = _env("KEEPER_HOST", "mini")
RECONCILE_MODEL = _env("RECONCILE_MODEL", "sonnet")
RECONCILE_BATCH = int(_env("RECONCILE_BATCH", "10"))
PROMPT_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "prompts", "reconcile.md")


def _acquire_lock():
    state_dir = os.path.join(
        os.environ.get("HOME", "/Users/shin1ohno"), ".local", "state", "memory-keeper"
    )
    os.makedirs(state_dir, exist_ok=True)
    lock_path = os.path.join(state_dir, "reconcile.lock")
    lf = open(lock_path, "w")
    try:
        fcntl.flock(lf, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        print("reconcile: another instance holds the lock; exiting", file=sys.stderr)
        sys.exit(0)
    return lf


def _fetch_raw_facts(es):
    body = {
        "size": RECONCILE_BATCH,
        "sort": [{"provenance.written_at": {"order": "asc"}}],
        "query": {
            "bool": {
                "filter": [{"term": {"reconcile_status": "raw"}}],
                "must_not": [{"exists": {"field": "superseded_by"}}],
            }
        },
    }
    return es.search(FACT_INDEX, body)["hits"]["hits"]


def _knn_candidates(es, embedding, self_id):
    body = {
        "knn": {
            "field": "embedding",
            "query_vector": embedding,
            "k": 10,
            "num_candidates": 100,
            "filter": {"bool": {"must_not": [{"exists": {"field": "superseded_by"}}]}},
        },
        "size": 10,
        "_source": ["content", "provenance", "tags", "entities"],
    }
    hits = es.search(FACT_INDEX, body)["hits"]["hits"]
    return [h for h in hits if h["_id"] != self_id]


def _mark_reconciled(es, fid):
    es.update(FACT_INDEX, fid, {"reconcile_status": "reconciled"}, refresh="wait_for")


def _raw_backlog(es):
    q = {
        "bool": {
            "filter": [{"term": {"reconcile_status": "raw"}}],
            "must_not": [{"exists": {"field": "superseded_by"}}],
        }
    }
    return es.count(FACT_INDEX, q).get("count", 0)


def main():
    t0 = time.monotonic()
    _lock = _acquire_lock()  # noqa: F841 (held for process lifetime)
    es = ESClient()

    with open(PROMPT_PATH, "r", encoding="utf-8") as fh:
        template = fh.read()

    reconciled = 0
    guard_violations = 0
    errors = 0

    try:
        raw_hits = _fetch_raw_facts(es)
    except ESError as exc:
        print(f"reconcile: fetch failed: {exc}", file=sys.stderr)
        raw_hits = []
        errors += 1

    for hit in raw_hits:
        fid = hit["_id"]
        src = hit.get("_source", {})
        embedding = src.get("embedding")
        if not embedding:
            # ES 9.x excludes dense_vector from _source by default, so the
            # stored vector is not retrievable here. Re-embed the fact's content
            # (same voyage-3-large / document input_type as the server's remember
            # path -> equivalent vector) to drive the kNN candidate lookup.
            content = (src.get("content") or "").strip()
            if content:
                try:
                    embedding = voyage_client.embed_documents([content])[0]
                except voyage_client.VoyageUnavailable as exc:
                    print(f"reconcile: voyage down re-embedding {fid}: {exc}; leaving raw", file=sys.stderr)
                    errors += 1
                    continue
        if not embedding:
            print(f"reconcile: fact {fid} has no content/embedding; marking reconciled", file=sys.stderr)
            try:
                _mark_reconciled(es, fid)
            except ESError:
                pass
            errors += 1
            continue

        try:
            candidates = _knn_candidates(es, embedding, fid)
        except ESError as exc:
            print(f"reconcile: knn failed for {fid}: {exc}", file=sys.stderr)
            errors += 1
            continue

        if not candidates:
            try:
                _mark_reconciled(es, fid)
                reconciled += 1
            except ESError:
                errors += 1
            continue

        candidate_ids = [c["_id"] for c in candidates]
        payload = {
            "new_fact": {"content": src.get("content", "")},
            "candidates": [
                {"id": c["_id"], "content": c.get("_source", {}).get("content", "")}
                for c in candidates
            ],
        }
        prompt = template.replace("{{PAYLOAD}}", json.dumps(payload, ensure_ascii=False))

        try:
            verdict = claude_judge.judge_json(prompt, RECONCILE_MODEL, timeout=120, retries=1)
        except claude_judge.JudgeError as exc:
            print(f"reconcile: judge failed for {fid}: {exc}; leaving raw", file=sys.stderr)
            errors += 1
            continue

        action = verdict.get("verdict")
        if action not in ("ADD", "UPDATE", "NOOP"):
            print(f"reconcile: bad verdict for {fid}: {action!r}; leaving raw", file=sys.stderr)
            errors += 1
            continue

        target_id = verdict.get("target_id")
        merged = verdict.get("merged_content")

        if action == "UPDATE" and (target_id not in candidate_ids or not merged):
            # ID-integrity guard: model named an id outside the candidate set (or
            # gave no merged content) -> downgrade to ADD, count the violation.
            guard_violations += 1
            action = "ADD"

        if action in ("ADD", "NOOP"):
            try:
                _mark_reconciled(es, fid)
                reconciled += 1
                print(f"AUDIT reconcile id={fid} verdict={action}", file=sys.stderr)
            except ESError:
                errors += 1
            continue

        # UPDATE: index the merged fact FIRST (no empty window), then supersede
        # both the target candidate and the raw fact it folds in.
        target = next(c for c in candidates if c["_id"] == target_id)
        target_src = target.get("_source", {})
        try:
            new_emb = voyage_client.embed_documents([merged])[0]
        except voyage_client.VoyageUnavailable as exc:
            print(f"reconcile: voyage down for {fid}: {exc}; leaving raw", file=sys.stderr)
            errors += 1
            continue

        now = now_iso()
        # What the merged doc inherits is decided in merge_rules, shared with
        # consolidate's near-dup pass. It used to be inlined here and took the
        # TARGET's tags only, so folding a tags:["todo"] fact into an untagged one
        # left the todo unenumerable; and it took the target's provenance, which
        # could downgrade a user-stated fact to tool-output and let a machine
        # agent supersede content that came from the user.
        new_doc = merge_rules.merged_fact_doc(
            incoming_src=src,
            target_src=target_src,
            incoming_id=fid,
            target_id=target_id,
            content=merged,
            embedding=new_emb,
            now=now,
        )
        try:
            res = es.index_doc(FACT_INDEX, new_doc, refresh="wait_for")
            new_id = res["_id"]
            es.update(
                FACT_INDEX,
                target_id,
                {"superseded_by": new_id, "superseded_at": now, "reconcile_status": "reconciled"},
                refresh="wait_for",
            )
            es.update(
                FACT_INDEX,
                fid,
                {"superseded_by": new_id, "superseded_at": now, "reconcile_status": "reconciled"},
                refresh="wait_for",
            )
            reconciled += 1
            print(
                f"AUDIT reconcile id={fid} verdict=UPDATE new_id={new_id} superseded={target_id},{fid}",
                file=sys.stderr,
            )
        except ESError as exc:
            print(f"reconcile: apply UPDATE failed for {fid}: {exc}", file=sys.stderr)
            errors += 1
            continue

    try:
        backlog = _raw_backlog(es)
    except ESError:
        backlog = -1

    stats_doc = {
        "written_at": now_iso(),
        "host": KEEPER_HOST,
        "run_kind": "reconcile",
        "raw_backlog": backlog,
        "reconciled_this_run": reconciled,
        "guard_violations": guard_violations,
        "errors": errors,
        "loop_lag_ms": (time.monotonic() - t0) * 1000.0,
    }
    try:
        es.index_doc(STATS_INDEX, stats_doc, refresh="false")
    except ESError as exc:
        print(f"reconcile: stats write failed: {exc}", file=sys.stderr)


if __name__ == "__main__":
    main()
