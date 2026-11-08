"""Codex native rollout indexing, including retries and segment boundaries."""

import json
import unittest

import sessions_parse as sp

SID = "019aaaaa-1111-7111-8111-111111111111"
CWD = "/work/demo"


def record(kind, payload, ts="2026-10-25T00:00:01Z"):
    return json.dumps({"type": kind, "timestamp": ts, "payload": payload})


def meta(source="vscode"):
    return record("session_meta", {"id": SID, "cwd": CWD, "source": source,
                                   "cli_version": "0.162.1", "git": {"branch": "feature/x"}})


def message(role, text, **extra):
    return record("response_item", dict(type="message", role=role,
                                       content=[{"type": "input_text", "text": text}], **extra))


class CodexParse(unittest.TestCase):
    def parse(self, lines, start_offset=0, **kw):
        return sp.parse_lines("sk_" + "a" * 32, "main", lines, start_offset, host="pro-dev", session_id=SID, **kw)

    def test_conversation_tools_and_noise(self):
        lines = [meta(), message("developer", "injected developer context"),
                 message("user", "# AGENTS.md instructions\nignore"),
                 message("user", "Find the WiFi regression"),
                 message("assistant", "private analysis", channel="analysis"),
                 record("response_item", {"type": "reasoning", "summary": "private reasoning"}),
                 record("event_msg", {"type": "agent_message", "message": "duplicate event text"}),
                 message("assistant", "I found the cause"),
                 record("response_item", {"type": "function_call", "name": "exec_command",
                                          "arguments": '{"cmd":"git status"}', "call_id": "c1"}),
                 record("response_item", {"type": "function_call_output", "call_id": "c1",
                                          "output": "H" * 2000 + "middle" + "T" * 2000})]
        parsed = self.parse(lines)
        docs = parsed["docs"]
        self.assertEqual(len(docs), 4)
        self.assertEqual([d["text"] for d in docs if d.get("text")],
                         ["Find the WiFi regression", "I found the cause"])
        self.assertTrue(all(d["interactive"] for d in docs))
        self.assertTrue(all(d["cwd"] == CWD for d in docs))
        self.assertIn("git status", docs[2]["tool_text"])
        self.assertNotIn("middle", docs[3]["tool_text"])
        self.assertTrue(docs[3]["tool_text"].endswith("T" * 512))
        session = sp.merge_session(None, parsed["delta"], project_dir="codex-" + sp.encode_cwd(CWD))
        self.assertEqual(session["entrypoint"], "codex-vscode")
        self.assertEqual(session["title"], "Find the WiFi regression")
        self.assertEqual(session["git_branch"], "feature/x")
        self.assertTrue(session["resume_cwd_verified"])
        self.assertEqual(self.parse(lines)["docs"], docs)

    def test_later_segment_retains_source_and_cwd(self):
        parsed = self.parse([message("assistant", "later segment")],
                            known_entrypoint="codex-cli", known_cwd=CWD)
        self.assertEqual(parsed["docs"][0]["cwd"], CWD)
        self.assertEqual(parsed["docs"][0]["text"], "later segment")
        self.assertTrue(parsed["docs"][0]["interactive"])

    def test_sources_and_tombstones(self):
        for source, interactive in (("exec", False), ({"subAgent": {}}, False),
                                    ("appServer", True), ("cli", True)):
            parsed = self.parse([meta(source), message("user", "hello"),
                                 json.dumps({"type": "session-search-tombstone", "reason": "unmasked_secret"})])
            self.assertEqual(parsed["docs"][0]["interactive"], interactive)
            self.assertEqual(parsed["delta"]["tombstones"], 1)

    def test_masked_header_does_not_hide_later_messages(self):
        parsed = self.parse([json.dumps({"type": "session-search-tombstone"}),
                             message("user", "still searchable", id=123)], source="codex")
        self.assertEqual(parsed["docs"][0]["text"], "still searchable")
        self.assertEqual(parsed["delta"]["tombstones"], 1)
        self.assertEqual(parsed["delta"]["entrypoint"], "codex-unknown")

    def test_unknown_sources_are_interactive_but_explicit_subagents_are_not(self):
        for source in (None, "future_source", {"custom": "desktop"}):
            parsed = self.parse([meta(source), message("user", "old conversation")])
            self.assertEqual(parsed["delta"]["entrypoint"], "codex-unknown")
            self.assertTrue(parsed["docs"][0]["interactive"])
        for source in ({"subagent": {}}, {"subAgent": {}}):
            self.assertFalse(self.parse([meta(source), message("user", "worker")])["docs"][0]["interactive"])

    def test_fork_parent_context_is_excluded_across_every_segment_boundary(self):
        parent = "019bbbbb-1111-7111-8111-111111111111"
        for subagent in (False, True):
            header = json.loads(meta({"subagent": {}} if subagent else "cli"))
            header["payload"]["forked_from_id"] = parent
            if subagent:
                header["payload"]["subagent_history_start_ordinal"] = 5
            rows = [header, json.loads(meta("exec")), json.loads(message("user", "parent question")),
                    json.loads(record("response_item", {"type": "function_call", "name": "parent_tool",
                                                         "arguments": "parent command"})),
                    json.loads(record("event_msg", {"type": "thread_settings_applied", "thread_id": parent})),
                    json.loads(record("event_msg", {"type": "thread_settings_applied", "thread_id": SID})),
                    json.loads(message("user", "child question")),
                    json.loads(message("assistant", "child answer")),
                    json.loads(record("response_item", {"type": "function_call", "name": "child_tool",
                                                         "arguments": "child command"}))]
            rows[1]["payload"]["id"] = parent
            for ordinal, row in enumerate(rows):
                row["ordinal"] = ordinal
            lines = [json.dumps(r) for r in rows]
            for cut in range(1, len(lines)):
                first = self.parse(lines[:cut], source="codex")
                second = self.parse(lines[cut:], start_offset=10000, source="codex",
                                    known_entrypoint=first["delta"]["entrypoint_effective"],
                                    known_cwd=CWD, codex_state=first["codex_state"])
                docs = first["docs"] + second["docs"]
                self.assertEqual([d["text"] for d in docs if d["text"]], ["child question", "child answer"])
                self.assertNotIn("parent question", json.dumps(docs))
                self.assertNotIn("parent command", json.dumps(docs))
                self.assertEqual(docs[-1]["tool_names"], ["child_tool"])
                self.assertTrue(all(d["interactive"] == (not subagent) for d in docs))
                session = sp.merge_session(None, first["delta"], project_dir="codex-" + sp.encode_cwd(CWD))
                session = sp.merge_session(session, second["delta"], project_dir="codex-" + sp.encode_cwd(CWD))
                self.assertEqual(session["title"], "child question")


if __name__ == "__main__":
    unittest.main()
