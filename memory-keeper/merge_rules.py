#!/usr/bin/env python3
"""What a doc derived from two others inherits, in one place.

The keeper folds facts together in two independent places — reconcile's UPDATE
verdict and consolidate's near-dup pass — and both used to decide field-by-field
inline, in the middle of a loop that also talks to ES and a judge. That had two
consequences worth removing:

* the rules disagreed. UPDATE carried the target's tags; near-dup carried nothing
  at all, because it only wrote a `superseded_by` pointer and let the loser's tags
  disappear with it. A `tags:["todo"]` fact that got folded into an untagged one
  stopped being enumerable by browse(filters={"tags": "todo"}) — the routing key
  the TODO pipeline runs on (docs/todo-management.md), and the rot it records as a
  real six-week incident.
* nothing could be asserted without a live ES, so neither rule had a test.

These functions are pure: dicts in, dict out, no I/O. Rationale for the rules
themselves is docs/adr/0008-keeper-merge-field-inheritance.md.
"""

from __future__ import annotations

from es_client import content_hash

USER_STATED = "user-stated"


def union_tags(*tag_lists) -> list:
    """Sorted union of every list given.

    Union rather than a side-preference: a tag is a routing key, so any rule that
    picks one side can drop one, while a union provably cannot. It is also
    monotone, idempotent and commutative, which is what makes it safe to replay
    and safe under two writers. Sorted so the stored keyword array is stable and
    an assertion on it is not list-order flaky.
    """
    out: set[str] = set()
    for tags in tag_lists:
        for t in (tags or []):
            out.add(t)
    return sorted(out)


def merged_provenance(a: dict | None, b: dict | None, now: str) -> dict:
    """Provenance for a doc derived from `a` and `b`; `b` wins ties.

    `user-stated` is a one-way ratchet everywhere else in the store: identity's
    authorize_supersede refuses a non-interactive supersede of a user-stated doc,
    and the server re-stamps user-stated on an interactive revise. The keeper's
    merge was the one place that could quietly undo it — folding a user-stated
    fact into a tool-output one produced a tool-output doc, so a machine agent
    could then supersede content that came from the user.

    So: if exactly one side is user-stated, that side's identity is inherited.
    Otherwise `b` wins, which for both callers is the surviving/target doc — i.e.
    byte-identical to the previous behaviour. Deliberately NOT a ranking over the
    other classes (tool-output, reflection, auto-capture, migration, promoted):
    they are authz-equivalent, so ordering them would only shuffle which service
    account keeps cleanup rights, for no security gain.

    Always emits the full four-key shape. consolidate's promotion path omitted
    session_id entirely, making promoted facts the only ones missing the key.
    """
    a = dict(a or {})
    b = dict(b or {})
    if a.get("source_class") == USER_STATED and b.get("source_class") != USER_STATED:
        winner = a
    else:
        winner = b
    return {
        "agent": winner.get("agent", ""),
        "session_id": winner.get("session_id", ""),
        "source_class": winner.get("source_class", ""),
        "written_at": now,
    }


def _derived_fact_doc(content: str, embedding, tags: list, entities: list,
                      provenance: dict, derived_from: list, now: str) -> dict:
    """The shared shape. use_count starts at 0 and last_used_at is absent.

    Both match es_backend.revise, the server-side analog of this operation
    (supersede the old, index the new, record derived_from). The old UPDATE path
    stamped last_used_at=now, which asserted a use event that never happened;
    dropping the key lets scoring.composite fall back to provenance.written_at,
    which is `now` here — same freshness, one fewer fiction.
    """
    return {
        "content": content,
        "embedding": embedding,
        "memory_type": "fact",
        "tags": tags,
        "entities": entities,
        "provenance": provenance,
        "reconcile_status": "reconciled",
        "content_hash": content_hash(content),
        "derived_from": derived_from,
        "use_count": 0,
    }


def merged_fact_doc(incoming_src: dict, target_src: dict, incoming_id: str,
                    target_id: str, content: str, embedding, now: str) -> dict:
    """The doc reconcile's UPDATE verdict indexes, folding incoming into target.

    `content` is the judge's merged text, so it is passed in rather than chosen
    here; everything else about the surviving doc is decided by the rules above.
    """
    return _derived_fact_doc(
        content=content,
        embedding=embedding,
        tags=union_tags(incoming_src.get("tags"), target_src.get("tags")),
        entities=union_tags(incoming_src.get("entities"), target_src.get("entities")),
        provenance=merged_provenance(incoming_src.get("provenance"),
                                     target_src.get("provenance"), now),
        derived_from=[target_id, incoming_id],
        now=now,
    )


def near_dup_merge_doc(older_src: dict, newer_src: dict, older_id: str,
                       newer_id: str, embedding, now: str) -> dict:
    """The doc consolidate's near-dup pass indexes in place of a bare pointer.

    Above the supersede threshold the two texts are near-identical by
    construction, so the survivor's content is taken verbatim — there is nothing
    to synthesise, which is why this needs neither an embedding call (the
    survivor's vector is already in the caller's map) nor a judge call. What it
    buys is the loser's tags, which the pointer-only write dropped on the floor.
    """
    return _derived_fact_doc(
        content=newer_src.get("content", ""),
        embedding=embedding,
        tags=union_tags(older_src.get("tags"), newer_src.get("tags")),
        entities=union_tags(older_src.get("entities"), newer_src.get("entities")),
        provenance=merged_provenance(older_src.get("provenance"),
                                     newer_src.get("provenance"), now),
        derived_from=[older_id, newer_id],
        now=now,
    )


def promoted_fact_doc(claim: str, embedding, supporting_srcs: list, now: str,
                      derived_from: list) -> dict:
    """The doc consolidate's promotion phase indexes from corroborated episodes.

    Provenance stays synthesized (agent "memory-keeper", source_class "promoted"):
    that classification is meaningful and changing it moves who may later
    forget/revise the fact, which is a separate decision from tag preservation.
    reconcile_status stays "raw" on purpose so the claim re-enters reconcile.

    Tags are NOT inherited from the supporting episodes. Episode tags are the
    high-cardinality vocabulary — the retro skill writes a per-session unique key
    — and promotion loses no routing key by leaving them behind, because the
    episodes keep their own tags and are not deleted. `supporting_srcs` is taken
    anyway so the signature does not have to change if that is ever revisited.
    """
    doc = _derived_fact_doc(
        content=claim,
        embedding=embedding,
        tags=[],
        entities=[],
        provenance={"agent": "memory-keeper", "session_id": "",
                    "source_class": "promoted", "written_at": now},
        derived_from=list(derived_from),
        now=now,
    )
    doc["reconcile_status"] = "raw"
    return doc
