#!/usr/bin/env python3
"""Golden-fixture tests for sessions_parse (design spec §6.1, C1).

The JSONL below is SYNTHETIC: it reproduces the record and block shapes Claude
Code writes (user/assistant text, string content, tool_use, tool_result as a
string and as a block list, thinking, isMeta, isCompactSummary, attachment,
ai-title, custom-title, summary, relocated, an unknown record type, an unknown
block type, a noise-prefixed user message) with invented content. Stdlib only.

Usage: python3 test_sessions_parse.py
"""

from __future__ import annotations

import json
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import sessions_parse as sp  # noqa: E402

SID = "11111111-2222-3333-4444-555555555555"
SK = "sk_" + "a" * 32
CWD = "/home/dev/work/demo.repo"
NEW_CWD = "/home/dev/moved/demo_repo"


def rec(**kw):
    base = {"sessionId": SID, "cwd": CWD, "version": "2.1.0", "gitBranch": "main",
            "entrypoint": "cli", "timestamp": "2026-10-01T10:00:00Z"}
    base.update(kw)
    return json.dumps(base, ensure_ascii=False)


LONG = "H" * 2000 + "MIDDLE" + "T" * 2000
FIXTURE = [
    rec(type="attachment", uuid="a0", attachment={"type": "hook", "content": "injected"}),
    rec(type="user", uuid="u1", timestamp="2026-10-01T10:00:01Z",
        message={"role": "user", "content":
                 "<system-reminder>ignore me</system-reminder>\n<command-name>/x</command-name>"
                 "  Find the worktree bug"}),
    rec(type="assistant", uuid="a1", parentUuid="u1", timestamp="2026-10-01T10:00:02Z",
        message={"role": "assistant", "id": "msg_1", "content": [
            {"type": "thinking", "thinking": "private reasoning"},
            {"type": "text", "text": "Looking at it."},
            {"type": "tool_use", "id": "t1", "name": "Bash",
             "input": {"command": "git status", "description": "status", "timeout": 5}},
        ]}),
    rec(type="user", uuid="u2", parentUuid="a1", timestamp="2026-10-01T10:00:03Z",
        message={"role": "user", "content": [
            {"type": "tool_result", "tool_use_id": "t1", "content": LONG}]}),
    rec(type="assistant", uuid="a2", timestamp="2026-10-01T10:00:04Z",
        message={"role": "assistant", "id": "msg_1", "content": [
            {"type": "tool_use", "id": "t2", "name": "Read", "input": {"file_path": "/x/y.py"}}]}),
    rec(type="user", uuid="u3", timestamp="2026-10-01T10:00:05Z",
        message={"role": "user", "content": [
            {"type": "tool_result", "tool_use_id": "t2",
             "content": [{"type": "text", "text": "line one"}, {"type": "image", "source": {}}]}]}),
    rec(type="user", uuid="m1", isMeta=True, message={"role": "user", "content": "meta"}),
    rec(type="user", uuid="c1", isCompactSummary=True, message={"role": "user", "content": "summary"}),
    rec(type="assistant", uuid="a3", timestamp="2026-10-01T10:00:06Z",
        message={"role": "assistant", "content": [{"type": "hologram", "data": 1},
                                                  {"type": "text", "text": "done"}]}),
    rec(type="ai-title", aiTitle="AI chosen title"),
    rec(type="summary", summary="An old summary"),
    rec(type="relocated", relocatedCwd=NEW_CWD),
    rec(type="mystery-record", uuid="z1"),
    "not json at all",
    rec(type="user", uuid="u4", gitBranch="feature/x", version="2.1.9",
        timestamp="2026-10-01T10:00:07Z",
        message={"role": "user", "content": [{"type": "text", "text": "thanks"}]}),
]


class Golden(unittest.TestCase):
    def setUp(self):
        self.res = sp.parse_lines(SK, "main", FIXTURE, 1000, host="pro-dev", session_id=SID,
                                  redact_version="r1")
        self.docs = {d["uuid"]: d for d in self.res["docs"]}

    def test_indexed_records(self):
        self.assertEqual(sorted(self.docs), ["a1", "a2", "a3", "u1", "u2", "u3", "u4"])

    def test_noise_stripped_and_counted(self):
        self.assertEqual(self.docs["u1"]["text"], "Find the worktree bug")
        self.assertEqual(self.res["counters"]["skipped_noise"], 1)

    def test_thinking_never_indexed(self):
        self.assertEqual(self.docs["a1"]["text"], "Looking at it.")
        self.assertNotIn("private reasoning", json.dumps(self.res["docs"]))

    def test_tool_use_fields(self):
        tt = self.docs["a1"]["tool_text"]
        self.assertEqual(tt, "Bash git status status")
        self.assertEqual(self.docs["a1"]["tool_names"], ["Bash"])
        self.assertEqual(self.docs["a2"]["tool_text"], "Read /x/y.py")

    def test_tool_result_head_tail(self):
        tt = self.docs["u2"]["tool_text"]
        self.assertEqual(tt, "H" * 1536 + "…" + "T" * 512)
        self.assertNotIn("MIDDLE", tt)
        self.assertIsNone(self.docs["u2"]["text"])
        self.assertEqual(self.docs["u3"]["tool_text"], "line one")

    def test_meta_and_compact_skipped(self):
        self.assertNotIn("m1", self.docs)
        self.assertNotIn("c1", self.docs)
        self.assertEqual(self.res["counters"]["skipped_meta"], 2)

    def test_unknown_types_counted(self):
        self.assertEqual(self.res["counters"]["unknown_types"],
                         {"mystery-record": 1, "block:hologram": 1})
        self.assertEqual(self.docs["a3"]["text"], "done")
        self.assertEqual(self.res["counters"]["invalid_lines"], 1)

    def test_doc_fields(self):
        d = self.docs["a1"]
        self.assertEqual(d["_id"], sp.doc_id(SK, "a1"))
        self.assertEqual(d["message_id"], "msg_1")
        self.assertEqual(self.docs["a2"]["message_id"], "msg_1")
        self.assertEqual(d["parent_uuid"], "u1")
        self.assertEqual(d["role"], "assistant")
        self.assertEqual(d["host"], "pro-dev")
        self.assertEqual(d["cwd"], CWD)
        self.assertTrue(d["interactive"])
        self.assertFalse(d["is_sidechain"])
        self.assertEqual(d["embedding_status"], "pending")
        self.assertEqual(self.docs["u2"]["embedding_status"], "none")
        self.assertEqual(d["line_offset"], 1000 + 2)
        self.assertEqual(d["redact_version"], "r1")

    def test_delta(self):
        delta = self.res["delta"]
        self.assertEqual(delta["first_cwd"], CWD)
        self.assertEqual(delta["cwd_candidates"], [NEW_CWD])
        self.assertEqual(delta["git_branch"], "feature/x")
        self.assertEqual(delta["cc_version"], "2.1.9")
        self.assertEqual(delta["entrypoint"], "cli")
        self.assertEqual(delta["started_at"], "2026-10-01T10:00:00Z")
        self.assertEqual(delta["updated_at"], "2026-10-01T10:00:07Z")
        self.assertEqual(delta["message_count"], 7)
        self.assertEqual(delta["text_message_count"], 4)

    def test_subagent_is_sidechain(self):
        res = sp.parse_lines(SK, "subagent", FIXTURE[1:3], 0, host="h", session_id=SID,
                             agent_id="abc")
        self.assertTrue(all(d["is_sidechain"] and d["agent_id"] == "abc" for d in res["docs"]))

    def test_headless_entrypoint_not_interactive(self):
        lines = [rec(type="user", uuid="x", entrypoint="sdk-cli",
                     message={"role": "user", "content": "hello"})]
        res = sp.parse_lines(SK, "main", lines, 0, host="h", session_id=SID)
        self.assertFalse(res["docs"][0]["interactive"])
        # a later segment without the first record inherits the known entrypoint
        later = [json.dumps({"type": "user", "uuid": "y",
                             "message": {"role": "user", "content": "more"}})]
        res2 = sp.parse_lines(SK, "main", later, 5, host="h", session_id=SID,
                              known_entrypoint="cli")
        self.assertTrue(res2["docs"][0]["interactive"])


class Titles(unittest.TestCase):
    def merge(self, *titles_list):
        s = None
        for titles in titles_list:
            s = sp.merge_session(s, {"titles": titles}, project_dir="p")
        return s

    def test_fallback_order(self):
        self.assertEqual(self.merge({"first-user": "hello"})["title_source"], "first-user")
        s = self.merge({"first-user": "hello"}, {"summary": "sum"})
        self.assertEqual((s["title"], s["title_source"]), ("sum", "summary"))
        s = self.merge({"summary": "sum"}, {"ai-title": "ai"})
        self.assertEqual(s["title_source"], "ai-title")
        s = self.merge({"custom-title": "mine"}, {"ai-title": "ai2"}, {"summary": "s"})
        self.assertEqual((s["title"], s["title_source"]), ("mine", "custom-title"))

    def test_last_wins_within_source_first_user_keeps_first(self):
        s = self.merge({"ai-title": "one"}, {"ai-title": "two"})
        self.assertEqual(s["title"], "two")
        s = self.merge({"first-user": "first"}, {"first-user": "second"})
        self.assertEqual(s["title"], "first")

    def test_golden_title_and_truncation(self):
        res = sp.parse_lines(SK, "main", FIXTURE, 0, host="h", session_id=SID)
        s = sp.merge_session(None, res["delta"], project_dir="p")
        self.assertEqual((s["title"], s["title_source"]), ("AI chosen title", "ai-title"))
        long = self.merge({"first-user": "x " * 200})
        self.assertLessEqual(len(long["title"]), 120)


class ResumeCwd(unittest.TestCase):
    def test_encoding(self):
        self.assertEqual(sp.encode_cwd("/home/dev/work/demo.repo"), "-home-dev-work-demo-repo")

    def test_relocated_candidate_matches_parent_dir(self):
        res = sp.parse_lines(SK, "main", FIXTURE, 0, host="h", session_id=SID)
        s = sp.merge_session(None, res["delta"], project_dir=sp.encode_cwd(NEW_CWD))
        self.assertEqual(s["cwd"], CWD)
        self.assertEqual(s["cwd_candidates"], [CWD, NEW_CWD])
        self.assertEqual(s["resume_cwd"], NEW_CWD)
        self.assertTrue(s["resume_cwd_verified"])

    def test_first_cwd_when_it_matches(self):
        res = sp.parse_lines(SK, "main", FIXTURE, 0, host="h", session_id=SID)
        s = sp.merge_session(None, res["delta"], project_dir=sp.encode_cwd(CWD))
        self.assertEqual(s["resume_cwd"], CWD)
        self.assertTrue(s["resume_cwd_verified"])

    def test_unverified_fallback(self):
        res = sp.parse_lines(SK, "main", FIXTURE, 0, host="h", session_id=SID)
        s = sp.merge_session(None, res["delta"], project_dir="-somewhere-else")
        self.assertEqual(s["resume_cwd"], CWD)
        self.assertFalse(s["resume_cwd_verified"])

    def test_cwd_kept_across_segments(self):
        res = sp.parse_lines(SK, "main", FIXTURE, 0, host="h", session_id=SID)
        s = sp.merge_session(None, res["delta"], project_dir="p")
        later = sp.parse_lines(SK, "main", [rec(type="user", uuid="q", cwd="/elsewhere",
                                                 message={"role": "user", "content": "x"})],
                               99, host="h", session_id=SID)
        s2 = sp.merge_session(s, later["delta"], project_dir="p")
        self.assertEqual(s2["cwd"], CWD)


if __name__ == "__main__":
    unittest.main(verbosity=1)
