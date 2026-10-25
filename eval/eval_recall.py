#!/usr/bin/env python3
"""Golden-set recall eval for memory-v2.

Runs every query in ``golden_set.jsonl`` through the v2 backend's ``recall``
(``es_backend.recall``, contract §4) and scores the labelled ``expect_contains``
substrings against the concatenated top-k hit contents. Prints recall@k for
several cutoffs plus a per-query pass/fail table.

Env (same as the memory-mcp server — es_backend reads these at import):
    ES_URL / ES_USER / ES_PASSWORD / ES_VERIFY_CERTS
    VOYAGE_API_KEY / VOYAGE_ENDPOINT / EMBEDDING_MODEL / EMBEDDING_DIMENSIONS
    FACT_INDEX / KNOWLEDGE_INDEX / EPISODE_INDEX / ALL_ALIAS  (index names)
Eval knobs:
    GOLDEN_SET    (default: golden_set.jsonl next to this file)
    EVAL_TOP_K    (default: 10) — top_k passed to recall
    EVAL_CUTOFFS  (default: "1,3,5,10") — recall@k report cutoffs

Note: recall bumps use_count on its top-3 hits as a fire-and-forget side
effect — run against STAGING, not a frozen production snapshot.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
GOLDEN = os.environ.get("GOLDEN_SET", os.path.join(HERE, "golden_set.jsonl"))
EVAL_TOP_K = int(os.environ.get("EVAL_TOP_K", "10"))
CUTOFFS = [int(x) for x in os.environ.get("EVAL_CUTOFFS", "1,3,5,10").split(",") if x.strip()]

# es_backend v2 lives in the sibling memory-mcp dir (contract §9).
sys.path.insert(0, os.path.join(HERE, "..", "memory-mcp"))


def load_jsonl(path: str) -> list[dict]:
    rows: list[dict] = []
    with open(path, encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise SystemExit(f"{path}:{lineno} invalid JSON: {exc}") from exc
    return rows


def _norm(text: str) -> str:
    return " ".join((text or "").lower().split())


def _hit_list(result) -> list[dict]:
    """recall (§4) returns list[dict]; tolerate the {"hits":[...]} envelope too."""
    if isinstance(result, dict):
        return result.get("hits", [])
    return result or []


def matched_at_k(hits: list[dict], phrases: list[str], k: int) -> int:
    blob = _norm(" ".join((h.get("content") or "") for h in hits[:k]))
    return sum(1 for p in phrases if _norm(p) in blob)


async def run() -> int:
    import es_backend as be  # imported here so env is read at call time, not import

    golden = load_jsonl(GOLDEN)
    if not golden:
        raise SystemExit(f"{GOLDEN} has no rows")

    fetch_k = max(EVAL_TOP_K, max(CUTOFFS))
    # phrase-level counters: matched / total per cutoff
    matched = {k: 0 for k in CUTOFFS}
    total_phrases = 0
    # full-match counters: query fully satisfied at cutoff
    full = {k: 0 for k in CUTOFFS}

    print(f"golden set: {len(golden)} queries | top_k={fetch_k} | cutoffs={CUTOFFS}\n")
    header = f"{'#':>2}  {'type':<9}  {'k=' + str(max(CUTOFFS)):<6}  query"
    print(header)
    print("-" * max(len(header), 60))

    for i, row in enumerate(golden, 1):
        query = row["query"]
        mtype = row.get("type")  # None -> memory-all
        phrases = row.get("expect_contains", []) or []
        total_phrases += len(phrases)

        hits = _hit_list(await be.recall(query, memory_type=mtype, top_k=fetch_k))

        for k in CUTOFFS:
            m = matched_at_k(hits, phrases, k)
            matched[k] += m
            if phrases and m == len(phrases):
                full[k] += 1

        kmax = max(CUTOFFS)
        m_max = matched_at_k(hits, phrases, kmax)
        mark = "PASS" if (phrases and m_max == len(phrases)) else "FAIL"
        print(f"{i:>2}  {str(mtype):<9}  {mark:<6}  {query[:52]}")

    print("\n== recall@k (phrase-level: matched substrings / total) ==")
    for k in CUTOFFS:
        rate = matched[k] / total_phrases if total_phrases else 0.0
        print(f"  recall@{k:<2} = {rate:6.3f}  ({matched[k]}/{total_phrases})")

    print("\n== full-match rate (all expect_contains present) ==")
    n = len(golden)
    for k in CUTOFFS:
        rate = full[k] / n if n else 0.0
        print(f"  full@{k:<2}   = {rate:6.3f}  ({full[k]}/{n})")

    # exit non-zero if full-match@max is below a floor, for CI gating
    floor = float(os.environ.get("EVAL_RECALL_FLOOR", "0.0"))
    achieved = full[max(CUTOFFS)] / n if n else 0.0
    return 0 if achieved >= floor else 1


def main() -> None:
    sys.exit(asyncio.run(run()))


if __name__ == "__main__":
    main()
