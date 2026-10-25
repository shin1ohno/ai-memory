#!/usr/bin/env python3
"""Regression tests for what the keeper's merges inherit.

The keeper folds facts together in two places and both used to lose tags:

* reconcile's UPDATE verdict indexed a merged doc carrying the TARGET's tags
  only, so folding a tags:["todo"] fact into an untagged one left the todo
  unenumerable by browse(filters={"tags": "todo"}).
* consolidate's near-dup pass wrote nothing but a `superseded_by` pointer on the
  older doc, so everything the loser carried — tags included — was orphaned
  behind the supersede. This is the DOMINANT path: reconcile's prompt prefers
  NOOP for paraphrases and NOOP does not supersede, so duplicates survive
  reconcile and arrive here to be removed.

The same UPDATE block also took the target's provenance, which could downgrade a
`user-stated` fact to `tool-output` — the one place in the store that could undo
the user-stated ratchet identity.authorize_supersede enforces everywhere else.

Two kinds of assertion, both needed:

1. on the pure functions in merge_rules — what the merged document contains.
2. on the ES QUERY BODY consolidate sends — that it actually asks for `tags`.
   Without (2) a green (1) proves nothing: the fields would union with [] because
   the search never fetched them, and the fix would ship inert. That is exactly
   how #885 shipped a fixed tags helper behind a write path that still dropped
   them.

Dependency-free: the keeper is stdlib-only, so only its own siblings need
stubbing (ES client, voyage, the judge). Nothing here talks to ES, and the
process-wide lock is never taken — main() is not called.

Usage: python3 test_merge_rules.py
"""

from __future__ import annotations

import os
import sys
import types

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
# identity lives with the MCP server; the authz assertions below use the REAL
# matrix rather than a copy of it. A second hand-ported copy of a security rule
# is a worse risk than the import (es_client already carries one verbatim port
# with no drift test).
sys.path.insert(0, os.path.join(HERE, "..", "memory-mcp"))

import merge_rules  # noqa: E402

PASS = 0
FAIL = 0


def check(name: str, condition: bool, detail: str = "") -> None:
    global PASS, FAIL
    if condition:
        PASS += 1
        print(f"ok   {name}")
    else:
        FAIL += 1
        print(f"FAIL {name}" + (f" — {detail}" if detail else ""))


NOW = "2026-08-17T12:00:00Z"


# --------------------------------------------------------------------------- #
# 1. union_tags
# --------------------------------------------------------------------------- #
def test_union_tags():
    check("a union keeps both sides' tags",
          merge_rules.union_tags(["todo"], ["work"]) == ["todo", "work"])
    check("a union deduplicates",
          merge_rules.union_tags(["todo"], ["todo"]) == ["todo"])
    check("a union is sorted, so the stored array is stable",
          merge_rules.union_tags(["z"], ["a"]) == ["a", "z"])
    check("None and [] are absorbed",
          merge_rules.union_tags(None, [], ["todo"]) == ["todo"])


# --------------------------------------------------------------------------- #
# 2. reconcile's UPDATE merge
# --------------------------------------------------------------------------- #
def _merged(incoming, target):
    return merge_rules.merged_fact_doc(
        incoming_src=incoming, target_src=target,
        incoming_id="raw-1", target_id="tgt-1",
        content="merged text", embedding=[0.1], now=NOW)


def test_update_merge_keeps_the_incoming_tag():
    doc = _merged({"tags": ["todo"]}, {"tags": []})
    check("the incoming doc's tag survives an UPDATE merge",
          doc["tags"] == ["todo"], f"got {doc['tags']!r}")


def test_update_merge_keeps_the_target_tag():
    doc = _merged({"tags": []}, {"tags": ["retro"]})
    check("the target's tag survives an UPDATE merge",
          doc["tags"] == ["retro"], f"got {doc['tags']!r}")


def test_update_merge_records_both_parents():
    doc = _merged({"tags": []}, {"tags": []})
    check("derived_from records both parents",
          doc["derived_from"] == ["tgt-1", "raw-1"], f"got {doc['derived_from']!r}")
    check("the merged doc is already reconciled",
          doc["reconcile_status"] == "reconciled", f"got {doc!r}")


def test_merged_doc_does_not_fake_a_use_event():
    doc = _merged({}, {})
    check("use_count starts at 0, as revise does", doc["use_count"] == 0)
    check("last_used_at is absent rather than a fabricated now",
          "last_used_at" not in doc, f"got {sorted(doc)!r}")


# --------------------------------------------------------------------------- #
# 3. provenance: user-stated is a one-way ratchet
# --------------------------------------------------------------------------- #
def _prov(source_class, agent):
    return {"agent": agent, "session_id": "s", "source_class": source_class}


def test_user_stated_incoming_wins():
    doc = _merged({"provenance": _prov("user-stated", "sh1")},
                  {"provenance": _prov("tool-output", "svcB")})
    check("a user-stated incoming doc is not downgraded by the merge",
          doc["provenance"]["source_class"] == "user-stated",
          f"got {doc['provenance']!r}")
    check("its agent comes with it",
          doc["provenance"]["agent"] == "sh1", f"got {doc['provenance']!r}")


def test_user_stated_target_is_preserved():
    doc = _merged({"provenance": _prov("tool-output", "svcA")},
                  {"provenance": _prov("user-stated", "sh1")})
    check("a user-stated target stays user-stated",
          doc["provenance"]["source_class"] == "user-stated",
          f"got {doc['provenance']!r}")


def test_two_machine_classes_keep_todays_behaviour():
    doc = _merged({"provenance": _prov("tool-output", "svcA")},
                  {"provenance": _prov("reflection", "svcB")})
    check("with neither side user-stated the target still wins (no new ranking)",
          doc["provenance"]["agent"] == "svcB"
          and doc["provenance"]["source_class"] == "reflection",
          f"got {doc['provenance']!r}")


def test_provenance_is_always_four_keys():
    doc = _merged({}, {})
    check("provenance always carries the full shape, so session_id cannot vanish",
          sorted(doc["provenance"]) == ["agent", "session_id", "source_class",
                                        "written_at"],
          f"got {sorted(doc['provenance'])!r}")
    check("written_at is the merge time", doc["provenance"]["written_at"] == NOW)


def test_the_ratchet_holds_against_the_real_authz_matrix():
    """Whatever the merge produces must not be superseder-able by a machine
    agent when either input was user-stated. Asserted against identity's own
    matrix, not a restatement of it."""
    try:
        import identity
    except Exception as exc:  # pragma: no cover - import shape is the test
        check("identity imports for the authz assertion", False, str(exc))
        return
    combos = [
        (_prov("user-stated", "sh1"), _prov("tool-output", "svcB")),
        (_prov("tool-output", "svcA"), _prov("user-stated", "sh1")),
        (_prov("user-stated", "sh1"), _prov("user-stated", "sh1b")),
    ]
    machine_allowed = []
    for incoming, target in combos:
        p = _merged({"provenance": incoming}, {"provenance": target})["provenance"]
        # The machine agent asks as ITSELF (agent == the merged doc's agent), the
        # most permissive case client_credentials ever gets.
        if identity.authorize_supersede(identity.GRANT_CLIENT_CREDS, p["agent"],
                                        p["source_class"], p["agent"]):
            machine_allowed.append((incoming["source_class"],
                                    target["source_class"], p["source_class"]))
    check("a merge involving user-stated content is never machine-supersedable",
          not machine_allowed, f"allowed: {machine_allowed!r}")
    # Control: with no user-stated side, a machine agent CAN still clean up its
    # own doc — the ratchet must not confiscate that.
    p = _merged({"provenance": _prov("tool-output", "svcA")},
                {"provenance": _prov("tool-output", "svcB")})["provenance"]
    check("a machine agent keeps cleanup rights on a purely machine merge",
          identity.authorize_supersede(identity.GRANT_CLIENT_CREDS, p["agent"],
                                       p["source_class"], p["agent"]),
          f"got {p!r}")


# --------------------------------------------------------------------------- #
# 4. consolidate's near-dup merge
# --------------------------------------------------------------------------- #
def test_near_dup_merge_rescues_the_loser_tag():
    doc = merge_rules.near_dup_merge_doc(
        older_src={"content": "old text", "tags": ["todo"]},
        newer_src={"content": "new text", "tags": []},
        older_id="old-1", newer_id="new-1", embedding=[0.2], now=NOW)
    check("the older doc's tag survives a near-dup merge",
          doc["tags"] == ["todo"], f"got {doc['tags']!r}")
    check("the survivor's content is taken verbatim",
          doc["content"] == "new text", f"got {doc['content']!r}")
    check("derived_from records both sides",
          doc["derived_from"] == ["old-1", "new-1"], f"got {doc['derived_from']!r}")
    check("the merged doc does not re-enter reconcile",
          doc["reconcile_status"] == "reconciled", f"got {doc!r}")


def test_near_dup_merge_reuses_the_survivor_vector():
    doc = merge_rules.near_dup_merge_doc(
        older_src={"content": "a"}, newer_src={"content": "b"},
        older_id="o", newer_id="n", embedding=["SURVIVOR-VEC"], now=NOW)
    check("the caller's vector is used as-is (no re-embed)",
          doc["embedding"] == ["SURVIVOR-VEC"], f"got {doc['embedding']!r}")


# --------------------------------------------------------------------------- #
# 5. promotion keeps its own provenance, and no episode tags
# --------------------------------------------------------------------------- #
def test_promoted_doc_shape():
    doc = merge_rules.promoted_fact_doc(
        claim="c", embedding=[0.3],
        supporting_srcs=[{"tags": ["retro", "retro-20260817-abc"]}],
        now=NOW, derived_from=["ep-1", "ep-2"])
    check("a promoted fact re-enters reconcile", doc["reconcile_status"] == "raw")
    check("promotion does not import the episodes' tag vocabulary",
          doc["tags"] == [], f"got {doc['tags']!r}")
    check("promotion keeps its own provenance classification",
          doc["provenance"]["source_class"] == "promoted"
          and doc["provenance"]["agent"] == "memory-keeper",
          f"got {doc['provenance']!r}")
    check("a promoted fact's provenance still carries session_id",
          "session_id" in doc["provenance"], f"got {doc['provenance']!r}")


# --------------------------------------------------------------------------- #
# 6. the query bodies actually ask ES for tags
# --------------------------------------------------------------------------- #
def _stub_keeper_deps():
    """Install stubs for consolidate's siblings and return the recorder."""
    calls: list[tuple[str, dict]] = []

    class _StubES:
        def __init__(self, *a, **kw):
            pass

        def search(self, index, body):
            calls.append((index, body))
            return {"hits": {"hits": []}}

        def index_doc(self, index, doc, refresh=None):
            return {"_id": "new-1"}

        def update(self, index, doc_id, doc, refresh=None):
            return {}

        def count(self, index, query):
            return {"count": 0}

    voyage = types.ModuleType("voyage_client")
    voyage.embed_documents = lambda texts: [[0.0] for _ in texts]
    voyage.VoyageUnavailable = type("VoyageUnavailable", (Exception,), {})
    sys.modules["voyage_client"] = voyage

    judge = types.ModuleType("claude_judge")
    judge.JudgeError = type("JudgeError", (Exception,), {})
    judge.judge_json = lambda *a, **kw: {}
    sys.modules["claude_judge"] = judge
    return _StubES, calls


def test_near_dup_queries_ask_for_tags():
    StubES, calls = _stub_keeper_deps()
    import consolidate  # noqa: E402  (after the stubs)

    consolidate._near_dup(StubES(), NOW)
    bodies = [b for _, b in calls]
    check("the near-dup scan asks ES for tags",
          bodies and "tags" in bodies[0].get("_source", []),
          f"got {bodies[0].get('_source') if bodies else None!r}")
    # The per-neighbour kNN body is only reachable with facts in the scan, so
    # assert on the source text that BOTH _source lists carry tags — the second
    # one is the easy half to forget, and forgetting it unions with [].
    src = open(os.path.join(HERE, "consolidate.py"), encoding="utf-8").read()
    check("both _source lists in the near-dup path include tags",
          src.count('"_source": ["content", "embedding", "provenance", "tags", "entities"]') == 2,
          "expected the scan body and the kNN body to match")


# --------------------------------------------------------------------------- #
TESTS = [
    test_union_tags,
    test_update_merge_keeps_the_incoming_tag,
    test_update_merge_keeps_the_target_tag,
    test_update_merge_records_both_parents,
    test_merged_doc_does_not_fake_a_use_event,
    test_user_stated_incoming_wins,
    test_user_stated_target_is_preserved,
    test_two_machine_classes_keep_todays_behaviour,
    test_provenance_is_always_four_keys,
    test_the_ratchet_holds_against_the_real_authz_matrix,
    test_near_dup_merge_rescues_the_loser_tag,
    test_near_dup_merge_reuses_the_survivor_vector,
    test_promoted_doc_shape,
    test_near_dup_queries_ask_for_tags,
]

for t in TESTS:
    try:
        t()
    except Exception as exc:  # a raising test is a failure, not an abort
        FAIL += 1
        print(f"FAIL {t.__name__} — raised {type(exc).__name__}: {exc}")

print(f"---- pass={PASS} fail={FAIL}")
sys.exit(1 if FAIL else 0)
