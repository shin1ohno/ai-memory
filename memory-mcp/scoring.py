"""Pure scoring functions for memory-mcp v2 recall (contract §4).

No I/O, no ES, no Voyage — importable and unit-testable in isolation.

The recall pipeline fuses a BM25 leg and a kNN leg with Reciprocal Rank Fusion
(client-side, because RRF/linear retrievers are Enterprise-only on ES basic),
then multiplies the fused rank by a gaussian freshness decay and a bounded
use-count boost. Multiplicative (not additive) so a weak relevance signal
cannot be masked by recency/popularity (design v3 §8, blocker #4).
"""

from __future__ import annotations

import math
from datetime import datetime, timezone

RRF_K = 60


def _extract_id(item) -> str:
    """A leg element may be an ES hit dict ({"_id": ...}) or a bare id string."""
    if isinstance(item, dict):
        return item.get("_id") or item.get("id")
    return item


def rrf_fuse(legs, k: int = RRF_K) -> dict:
    """Reciprocal Rank Fusion over one or more ranked legs.

    Each leg is an ordered list (rank 0 = best). Returns id -> Σ 1/(k+rank+1),
    summed across legs (0-based rank; contract §1/§4). Matches the legacy
    `_manual_hybrid` formula verbatim.
    """
    scores: dict = {}
    for leg in legs:
        for rank, item in enumerate(leg):
            _id = _extract_id(item)
            if _id is None:
                continue
            scores[_id] = scores.get(_id, 0.0) + 1.0 / (k + rank + 1)
    return scores


def _parse_iso(ts):
    """Parse an ES date string into a tz-aware datetime, or None."""
    if ts is None:
        return None
    if isinstance(ts, datetime):
        return ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)
    s = str(ts).strip()
    if not s:
        return None
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def freshness(ts, now, offset_days: float) -> float:
    """Gaussian recency decay in (0, 1]: exp(-0.5*(age_days/offset_days)^2).

    `ts` is an ISO date string (or datetime, or None). A None/unparseable ts is
    treated as age 0 → 1.0 (never penalise for a missing timestamp).
    """
    dt = _parse_iso(ts)
    if dt is None:
        return 1.0
    if isinstance(now, datetime) and now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    try:
        age_days = abs((now - dt).total_seconds()) / 86400.0
    except (TypeError, AttributeError):
        return 1.0
    if offset_days <= 0:
        return 1.0
    return math.exp(-0.5 * (age_days / offset_days) ** 2)


def use_boost(use_count) -> float:
    """Bounded popularity boost: min(1 + 0.2*log10(1+use_count), 1.4).

    ~1.4x at use_count=100, capped so a hot loop cannot dominate relevance.
    """
    uc = use_count or 0
    try:
        uc = int(uc)
    except (TypeError, ValueError):
        uc = 0
    if uc < 0:
        uc = 0
    return min(1.0 + 0.2 * math.log10(1 + uc), 1.4)


def composite(rrf: float, source: dict, now, memory_type=None) -> float:
    """Multiplicative composite score for a single hit (contract §4).

    final = rrf * freshness(coalesce(last_used_at, written_at), now, offset)
                * use_boost(use_count)

    offset = 30d for episodes (strong decay), else 180d.
    """
    source = source or {}
    last_used = source.get("last_used_at")
    written = (source.get("provenance") or {}).get("written_at")
    ts = last_used or written
    offset = 30.0 if memory_type == "episode" else 180.0
    fresh = freshness(ts, now, offset)
    boost = use_boost(source.get("use_count"))
    try:
        base = float(rrf)
    except (TypeError, ValueError):
        base = 0.0
    return base * fresh * boost
