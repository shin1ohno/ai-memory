#!/usr/bin/env python3
"""Freeze the Python session contract; no network or production credentials.

Run with the server's Python/Unicode version. --client-tree supplies the real
ccs Shipper for line expectations (session-search 527735d or later).
The committed vectors are data; --check replays them without regenerating them.

The Rust loop must iterate to a fixed point with the real _MAX_PASSES = 8
limit. One-pass truncation is detected. A two-pass mutant remains unresolved:
no three-pass witness has yet been found; passing this finite corpus does not
prove that shortening the limit is equivalent or authorize that change.
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import platform
import random
import re
import sys
import subprocess
import tempfile
import types
import unicodedata
import unittest

HERE = Path(__file__).resolve().parent
SERVER = HERE.parent
KEY = b"test-key-not-a-secret"
SEED = 20261109
BOUNDARIES = ["", " ", "\n", "\t", "a", "Z", "0", "_", "-", ".", "+", "/", ":", "=", '"', "'", "`", ",", ";", "&", "@", "(", "\\",
              "é", "\u0301", "\u200d", "\u200c", "½", "٣", "ı", "İ", "ſ", "K", "\x1c", "\x1f", "\x85", "\xa0", "\u3000",
              "\u2028", "\u2029", "🙂", "中", "²", "‿", "\ufe0f", "٠", "Ⅰ"]
SAMPLES = {
    "aws-key": "AKIA" + "Z" * 16,
    "github-token": "ghp_" + "A" * 36,
    "github-pat": "github_pat_" + "a_" * 31,
    "anthropic-key": "sk-ant-" + "a" * 24,
    "openai-key": "sk-proj-" + "b" * 24,
    "slack-token": "xoxb-" + "1" * 12,
    "google-api-key": "AIza" + "C" * 35,
    "gitlab-token": "glpat-" + "d" * 20,
    "jwt": "eyJ" + "e" * 10 + "." + "f" * 10 + "." + "g" * 10,
    "bearer": "Authorization: Bearer " + "h" * 20,
    "private-key": "-----BEGIN OPENSSH PRIVATE KEY-----\nQUFBQQ==\n-----END OPENSSH PRIVATE KEY-----",
    "cfg-kv": "DB_PASSWORD=hunter2hunter2",
    "cfg-json": '"client_secret": "va\\"lue with space"',
    "url-credential": "https://alice:wonderland99@example.com/x",
}
CROSS = {"aws-key", "github-token", "google-api-key", "jwt", "bearer", "url-credential", "cfg-kv"}


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, str(path))
    result = importlib.util.module_from_spec(spec)
    sys.modules[name] = result
    spec.loader.exec_module(result)
    return result


def blob(path):
    return blob_bytes(Path(path).read_bytes())


def blob_bytes(data):
    return hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()


def dumps(value):
    # ASCII JSON also carries invalid UTF-8 test inputs safely as hex strings.
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"))


def pack(value):
    """Use the contract's $repeat notation; preserve object insertion order."""
    if isinstance(value, str) and len(value) > 256:
        match = re.fullmatch(r"(.{1,64}?)\1{7,}", value, re.DOTALL)
        if match:
            return {"$repeat": [match.group(1), len(value) // len(match.group(1))]}
    if isinstance(value, list):
        return [pack(v) for v in value]
    if isinstance(value, dict):
        return {k: pack(v) for k, v in value.items()}
    return value


def expand(value):
    if isinstance(value, dict):
        if list(value) == ["$repeat"]:
            text, count = value["$repeat"]
            if not isinstance(text, str) or type(count) is not int or not 0 <= count <= 10_000_001:
                raise ValueError("invalid $repeat")
            return text * count
        return {k: expand(v) for k, v in value.items()}
    if isinstance(value, list):
        return [expand(v) for v in value]
    return value


def project_codex(rec):
    # session_codex.py:125-128: the client does not consume generated IDs.
    out = {k: v for k, v in rec.items() if k in
           ("type", "cwd", "entrypoint", "timestamp", "gitBranch", "version")}
    if "message" in rec:
        out["message"] = {"content": rec["message"]["content"]}
    return out


def evaluate(sr, sc, op, value, key=KEY, kwargs=None):
    kwargs = kwargs or {}
    if op in ("redact_text", "redact_record"):
        output, counts = getattr(sr, op)(value, key, **kwargs)
        return {"output": output, "counts": counts}
    if op in ("detect_text", "detect_record"):
        return getattr(sr, op)(value, **kwargs)
    if op == "normalize":
        return project_codex(sc.normalize(value, **kwargs))
    if op == "index_sequence":
        state = sc.IndexState(value["session_id"], value.get("saved"))
        steps = []
        for rec in value["records"]:
            accepted = state.accept(rec)
            steps.append({"accept": accepted, "state": dict(state.state)})
            # Exercise serialization/resumption after every event.
            state = sc.IndexState(value["session_id"], json.loads(dumps(state.state)))
        return steps
    if op == "mask_line":
        return line_result(LINE_ORACLE, sr, value, key)
    raise ValueError("unknown operation " + op)


def in_domain(value):
    stack = [(value, 1)]
    while stack:
        v, depth = stack.pop()
        if depth > 64:
            return False
        if isinstance(v, str) and re.search(r"[\ud800-\udfff]", v):
            return False
        if isinstance(v, dict):
            stack.extend((x, depth + 1) for x in v.values())
        elif isinstance(v, list):
            stack.extend((x, depth + 1) for x in v)
    return True


def legacy_vectors(sr):
    """Capture actual inputs from the existing tests, not their expectations.

    The legacy 10,000-deep and exception/empty-key cases remain in the server
    suite; they are outside section 3.1's <=64/scalar/value-result domain.
    """
    tests = module("_conformance_legacy_redact", SERVER / "test_session_redact.py")
    tests.sr = sr
    captured, originals = [], {}
    names = ("redact_text", "redact_record", "detect_text", "detect_record", "_one_pass")
    active = [False]
    def wrap(name, original):
        def call(value, *args, **kw):
            nested = active[0]
            active[0] = True
            try:
                out = original(value, *args, **kw)
            finally:
                active[0] = nested
            if not nested and in_domain(value):
                key = args[0] if name.startswith("redact_") and args else KEY
                options = dict(kw)
                if name == "_one_pass":
                    key, options = args[0], {}
                captured.append(("redact_text" if name == "_one_pass" else name,
                                 value, key, options))
            return out
        return call
    try:
        for name in names:
            originals[name] = getattr(sr, name)
            setattr(sr, name, wrap(name, originals[name]))
        result = unittest.TextTestRunner(stream=io.StringIO()).run(
            unittest.defaultTestLoader.loadTestsFromModule(tests))
        if not result.wasSuccessful():
            raise RuntimeError("existing redactor suite failed: " + repr(result.errors + result.failures))
    finally:
        for name, original in originals.items():
            setattr(sr, name, original)
    for i, (op, value, key, kwargs) in enumerate(captured):
        yield "legacy/%05d" % i, op, value, key, kwargs


def adversarial_inputs(sr):
    # Every case/space transformation changes its input. These are witnesses,
    # not blind substitutions across unrelated token families.
    folds = [("Authorization: Bearer " + "h" * 20, "Authorization", "authorızatıon"),
             ("Authorization: Bearer " + "h" * 20, "Authorization", "authorİzation"),
             ("PASSWORD=abcdefghij", "PASSWORD", "PAſſWORD"),
             ("secret=abcdefghij", "secret", "ſecret"),
             ("api_key=abcdefghij", "key", "Key"),
             ("api_key=abcdefghij", "key", "Key"),
             ("api_key=abcdefghij", "api", "apı"),
             ("api_key=abcdefghij", "api", "apİ")]
    for i, (base, before, after) in enumerate(folds):
        changed = base.replace(before, after)
        assert changed != base
        for op in ("redact_text", "detect_text"):
            yield "case/witness/%d/%s" % (i, op), op, changed, KEY, {}
        yield "case/dict/%d" % i, "redact_record", {changed.split("=")[0]: "abcdefghij"}, KEY, {}
    for i, char in enumerate(("\x1c", "\x1d", "\x1e", "\x1f", "\x85")):
        # Whitespace ending a value differs from the deliberately narrower
        # [space/tab] separators. Both positive and negative cases are frozen.
        for j, base in enumerate(("secret=abcdefghij tail", "Authorization: Bearer " + "h" * 20 + " tail",
                                  "secret =abcdefghij", "https://alice:abcdefghij @host")):
            changed = base.replace(" ", char)
            assert changed != base
            for op in ("redact_text", "detect_text"):
                yield "space/witness/%d/%d/%s" % (i, j, op), op, changed, KEY, {}
    tokens = ["ASIA" + "A" * 16] + ["gh" + c + "_" + "A" * 36 for c in "pousr"]
    tokens += ["xox" + c + "-" + "1" * 10 for c in "abprs"]
    tokens += ["Authorization=Bearer " + "h" * 16, "sk-" + "a" * 20]
    for i, text in enumerate(tokens):
        for op in ("redact_text", "detect_text"):
            yield "branch/token/%d/%s" % (i, op), op, text, KEY, {}
    for word in ("secret", "token", "passwd", "password", "apikey", "api_key", "api-key", "credential", "private"):
        for op in ("redact_text", "detect_text"):
            yield "branch/cfg/%s/%s" % (word, op), op, word + "=abcdefghij", KEY, {}
        for name in (word, "!" + word + "!", "x" * 41 + word, word + "x" * 41):
            for op in ("redact_record", "detect_record"):
                yield "branch/key/%s/%s" % (name, op), op, {name: "abcdefghij"}, KEY, {}
    # Value-size boundaries for every tagged branch, plus private-key/bearer.
    for prefix, minimum in (("AKIA", 16), ("ASIA", 16), ("gho_", 36), ("github_pat_", 60),
                            ("sk-ant-", 20), ("sk-proj-", 20), ("sk-", 20), ("xoxa-", 10),
                            ("AIza", 35), ("glpat-", 20), ("Authorization=Bearer ", 16), ("passwd=", 8)):
        for size in (minimum - 1, minimum, minimum + 1):
            for op in ("redact_text", "detect_text"):
                yield "length/%s/%d/%s" % (prefix, size, op), op, prefix + "A" * size, KEY, {}
    for delta in (-1, 0, 1):
        value = ["a" * 999999, "b" * 1000000, "c" * 1000000, "d" * 1000000, "e" * (1 + delta)]
        record = {"a": "a" * (999996 + delta), "b": "b" * 1000000, "c": "c" * 1000000, "d": "d" * 1000000}
        for op in ("redact_record", "detect_record"):
            yield "budget/list/%+d/%s" % (delta, op), op, value, KEY, {}
            yield "budget/keys/%+d/%s" % (delta, op), op, record, KEY, {}
    for op in ("redact_record", "detect_record"):
        yield "budget/secret-key-take/" + op, op, {"plain": "aaaa", "password": "s" * 3999987}, KEY, {}
    witnesses = ['password="client_secret": ""client_secret": "token: aaaaaaaaaaaa"']
    for i, text in enumerate(witnesses):
        for op in ("redact_text", "detect_text"):
            yield "fixed-point/%d/%s" % (i, op), op, text, KEY, {}


def redactor_inputs(sr):
    for name, sample in SAMPLES.items():
        pairs = ((a, b) for a in BOUNDARIES for b in BOUNDARIES) if name in CROSS else (
            [(a, "") for a in BOUNDARIES] + [("", b) for b in BOUNDARIES])
        for i, (left, right) in enumerate(pairs):
            for op in ("redact_text", "detect_text"):
                yield "boundary/%s/%04d/%s" % (name, i, op), op, left + sample + right, KEY, {}
        # Preserve all earlier transformations that really changed the sample.
        # Only the previous no-op substitutions are excluded from the count.
        for i, (before, after) in enumerate((("Authorization", "authorızatıon"), ("Authorization", "authorİzation"),
                                            ("PASSWORD", "PAſſWORD"), ("secret", "ſecret"), ("key", "Key"), ("key", "Key"))):
            changed = sample.replace(before, after)
            if changed != sample:
                yield "case/%s/%d" % (name, i), "redact_text", changed, KEY, {}
        for i, whitespace in enumerate(("\x1c", "\x1d", "\x1e", "\x1f", "\x85")):
            changed = sample.replace(" ", whitespace)
            if changed != sample:
                yield "space/%s/%d" % (name, i), "redact_text", changed, KEY, {}
    yield from adversarial_inputs(sr)
    for n in (sr.MAX_VALUE_CHARS - 1, sr.MAX_VALUE_CHARS, sr.MAX_VALUE_CHARS + 1):
        for op in ("redact_text", "detect_text"):
            yield "value-cap/%d/%s" % (n, op), op, "x" * n, KEY, {}
    records = [
        {"password=aaaaaaaa1": 1, "password=bbbbbbbb2": 2},
        {"password": "hunter2hunter2", "a": 1},
        {SAMPLES["github-token"]: 1, "plain": 2},
        {"k" * 129 + "secret": "abcdefghij"},
        {"a": "x" * 999999, "b": "y" * 999999, "c": "z" * 999999,
         "d": "w" * 999999, "password": "abcdefghij", "e": "q" * 999999},
        {"password": "abcdefghij", "a": "x" * 999999, "b": "y" * 999999,
         "c": "z" * 999999, "d": "w" * 999999, "e": "q" * 999999},
    ]
    nested = SAMPLES["github-token"]
    for depth in range(1, 65):
        records.append(nested)
        nested = {"k": nested} if depth % 2 else [nested]
    for i, rec in enumerate(records):
        for op in ("redact_record", "detect_record"):
            yield "record/%d/%s" % (i, op), op, rec, KEY, {}
    rnd = random.Random(SEED)
    frags = list(SAMPLES.values()) + BOUNDARIES
    for i in range(200):
        s = "".join(rnd.choice(frags) for _ in range(rnd.randint(1, 12)))
        yield "seed/%d" % i, "redact_text", s, KEY, {}
    yield from legacy_vectors(sr)


def line_oracle(source):
    """Compile the exact frozen client methods, without its CLI/network imports.

    The header contains the complete source and its git blob. The client CI
    compares it with live ingest.py; --client-tree makes the server check do so
    too. This is source extraction, not a second implementation of masking.
    """
    tree = ast.parse(source)
    nodes = []
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name in ("tombstone", "_tomb_line"):
            nodes.append(node)
        elif isinstance(node, ast.Assign) and any(
                isinstance(t, ast.Name) and t.id in ("TOMBSTONE_TYPE", "_SURROGATE_RE") for t in node.targets):
            nodes.append(node)
        elif isinstance(node, ast.ClassDef) and node.name == "Shipper":
            node.body = [n for n in node.body if isinstance(n, ast.FunctionDef)
                         and n.name in ("_mask_line", "_mask_chunk")]
            nodes.append(node)
    ns = {"json": json, "re": re, "util": types.SimpleNamespace(log=lambda *a: None)}
    exec(compile(ast.Module(body=nodes, type_ignores=[]), "<frozen ingest.py>", "exec"), ns)
    return types.SimpleNamespace(**ns)


def line_result(oracle, sr, value, key=KEY):
    routes, counts = [], {}
    def call(name):
        def invoke(*args):
            routes.append("text" if name == "redact_text" else "record")
            output, hits = getattr(sr, name)(*args)
            counts.update(hits)
            return output, hits
        return invoke
    shipper = oracle.Shipper.__new__(oracle.Shipper)
    shipper.redactor = types.SimpleNamespace(redact_text=call("redact_text"), redact_record=call("redact_record"))
    shipper.key, shipper.stats = key, {"tombstones": 0}
    sent, offsets = shipper._mask_chunk(bytes.fromhex(value["hex"]) + b"\n", value["offset"])
    route = "skip" if not sent else "tombstone" if shipper.stats["tombstones"] else routes[0]
    return {"route": route, "output": sent[0] if sent else None, "counts": counts, "offsets": offsets}


def strict_oracle():
    # Read the real server parser without importing its web/storage services.
    tree = ast.parse((SERVER / "sessions_app.py").read_text())
    names = {"_BadLine", "_no_duplicate_keys", "_reject_constant", "strict_load"}
    nodes = [n for n in tree.body if isinstance(n, (ast.FunctionDef, ast.ClassDef)) and n.name in names]
    ns = {"json": json, "re": re, "MAX_RECORD_DEPTH": 64, "_SURROGATE_RE": re.compile(r"[\ud800-\udfff]")}
    # The constant is extracted too, so mutations of the actual source apply.
    nodes[:0] = [n for n in tree.body if isinstance(n, ast.Assign) and any(
        isinstance(t, ast.Name) and t.id == "MAX_RECORD_DEPTH" for t in n.targets)]
    exec(compile(ast.Module(body=nodes, type_ignores=[]), "<sessions_app.py parser>", "exec"), ns)
    return types.SimpleNamespace(**ns)


def server_result(oracle, value):
    try:
        _, strings = oracle.strict_load(bytes.fromhex(value["hex"]).decode("utf-8", "replace"))
        return {"strict_load": "accept", "strings": strings}
    except oracle._BadLine as exc:
        return {"strict_load": "reject", "reason": exc.kind}


def rust_line_contract(oracle, value, python_expect):
    """Only the approved raw-input D2/D3 policy; never a Python oracle.

    Preserve duplicate pairs so overwritten values cannot hide a surrogate or
    excessive depth. Container roots have depth 1; scalar children add 1.
    """
    class Pairs(list):
        pass
    digits = [0]
    def integer(s):
        digits[0] = max(digits[0], len(s.lstrip("-")))
        return 0  # no Python integer limit; only measure the raw digit count
    try:
        rec = json.loads(bytes.fromhex(value["hex"]).decode("utf-8", "replace"),
                         object_pairs_hook=Pairs, parse_int=integer)
    except ValueError:
        return [], {}, python_expect
    stack, depth_max, surrogate = [(rec, 1)], 0, False
    while stack:
        v, depth = stack.pop()
        depth_max = max(depth_max, depth)
        if isinstance(v, Pairs):
            for k, x in v:
                surrogate |= bool(re.search(r"[\ud800-\udfff]", k))
                stack.append((x, depth + 1))
        elif isinstance(v, list):
            stack.extend((x, depth + 1) for x in v)
        elif isinstance(v, str):
            surrogate |= bool(re.search(r"[\ud800-\udfff]", v))
    facts = {"raw_max_depth": depth_max, "max_integer_digits": digits[0], "raw_lone_surrogate": surrogate}
    if surrogate:
        tag, reason = "D2", "surrogate"
    elif depth_max > 64:
        tag, reason = "D3", "too-deep"
    elif digits[0] > 4300:
        tag, reason = "D3", "invalid-json"
    else:
        return [], facts, python_expect
    return [tag], facts, {"route": "tombstone", "output": oracle._tomb_line(reason, [], value["offset"]),
                          "counts": {}, "offsets": [value["offset"]]}


def line_vectors(client, sr):
    sys.path.insert(0, str(client))
    module("ccs.session_codex", client / "vendor/memory-mcp/session_codex.py")
    from ccs import ingest
    frozen = line_oracle((client / "ccs/ingest.py").read_text())
    server = strict_oracle()
    lines = [b'{}', b'null', b'false', b'42', b'"plain"', b'{"x":1,"x":2}',
             b'{"x":NaN}', b'{"x":Infinity}', b'{"x":1e400}', b'{"n":01}',
             b'{"x":}', b'{"x":"\\uD800"}', b'{"x":"\\uDC00"}',
             b'{"x":"\\ud83d\\ude00"}', b'{"secret":"\\ud800abcdefghij"}',
             b'{"x":"\\ud800","x":"overwritten"}', b'\xff\xc0\xaf secret=abcdefghij',
             b'{"x":"\xed\xa0\x80"}', b'{"x":"\xe2\x82"}',
             b'{"$serde_json::private::Number":"123"}',
             b'{"$serde_json::private::RawValue":"{}"}', b'{"x":true} trailing',
             b'[1,2,]', b'{"x":1e}', b'1' * 4301,
             b'', b' \t\r', b'\x1c', b'{"n":' + b'1' * 4301 + b'}',
             b'{"n":' + b'1' * 4301 + b',"n":0}']
    for depth in (63, 64, 65, 66, 127, 128, 129, 130):
        for leaf in ('"plain"', '"ghp_' + 'A' * 36 + '"'):
            # Objects reach strict_load's depth guard; keep array-root controls.
            lines.append(('{"k":' * (depth - 1) + leaf + '}' * (depth - 1)).encode())
            lines.append(('[' * (depth - 1) + leaf + ']' * (depth - 1)).encode())
    lines.append(('{"x":' + '[' * 128 + '0' + ']' * 128 + ',"x":0}').encode())
    old_log = ingest.util.log
    ingest.util.log = lambda *args: None
    try:
        for i, raw in enumerate(lines):
            value = {"hex": raw.hex(), "offset": i * 17}
            expected = line_result(ingest, sr, value)
            if expected != line_result(frozen, sr, value):
                raise ValueError("frozen methods differ from live client")
            tags, facts, rust_expected = rust_line_contract(frozen, value, expected)
            yield {"id": "line/%03d" % i, "op": "mask_line", "input": value,
                   "expect": expected, "compat": tags, "raw_facts": facts,
                   "rust_expect": rust_expected, "server_expect": server_result(server, value)}
    finally:
        ingest.util.log = old_log


def codex_vectors(sc):
    sid, parent = "child", "parent"
    def rec(kind, payload, **extra):
        return dict(type=kind, timestamp="2026-10-25T00:00:00Z", payload=payload, **extra)
    rows = [rec("session_meta", {"id": sid, "cwd": "/work/日本語", "source": source,
                                  "git": {"branch": "main"}, "cli_version": "0.162.1"})
            for source in ("cli", "vscode", "appServer", "exec", None, "future", {"subagent": {}}, {"subAgent": {}})]
    for role in ("user", "assistant", "system", "developer"):
        for channel in (None, "analysis", "final"):
            for content in ("hello", [{"type": "input_text", "text": "hello"}, {"type": "image"}],
                            "# AGENTS.md instructions\nignored", "<environment_context>ignored", None):
                rows.append(rec("response_item", {"type": "message", "role": role, "channel": channel, "content": content}))
    for kind in ("function_call", "custom_tool_call", "function_call_output", "custom_tool_call_output"):
        for content in ("echo hello", {"a": 1, "b": "日本語"}, None):
            rows.append(rec("response_item", {"type": kind, "arguments": content, "input": content, "output": content}))
    rows.extend([rec("turn_context", {"cwd": "/new"}), rec("event_msg", {"type": "user_message"}),
                 rec("world_state", {}), rec("response_item", None), {"type": "session-search-tombstone", "reason": "surrogate"}])
    rows.extend(rec("response_item", {"type": "message", "role": "assistant", "content": content})
                for content in ([{"type": "output_text", "text": "out"}],
                                [{"type": "text", "text": "one"}, {"type": "input_text", "text": "two"}],
                                [None, "bad", {"type": "text", "text": 123}],
                                "  # AGENTS.md instructions ignored", "  <environment_context>ignored"))
    rows.extend([rec("turn_context", {"cwd": ""}), rec("session_meta", {"id": sid, "git": "bad"}),
                 rec("response_item", {"type": "custom_tool_call", "name": "custom", "input": "real", "arguments": "wrong"}),
                 rec("response_item", {"type": "function_call", "name": "shell", "arguments": "real", "input": "wrong"})])
    for i, row in enumerate(rows):
        yield {"id": "normalize/%03d" % i, "op": "normalize", "input": row,
               "kwargs": {"position": i, "entrypoint": "codex-cli", "cwd": "/old"},
               "expect": evaluate(None, sc, "normalize", row, kwargs={"position": i, "entrypoint": "codex-cli", "cwd": "/old"})}
    for i, extras in enumerate(({}, {"subagent_history_start_ordinal": 0}, {"subagent_history_start_ordinal": 1}, {"forked_from_id": parent}, {"subagent_history_start_ordinal": 4},
                               {"ccs_index_start_ordinal": 3, "subagent_history_start_ordinal": 99},
                               {"subagent_history_start_ordinal": -1}, {"subagent_history_start_ordinal": True})):
        sequence = [rec("session_meta", dict(id=sid, **extras)), rec("session_meta", {"id": parent}),
                    rec("response_item", {"type": "message", "role": "user", "content": "inherited"}),
                    rec("event_msg", {"type": "thread_settings_applied", "thread_id": parent}),
                    rec("event_msg", {"type": "thread_settings_applied", "thread_id": sid}),
                    rec("response_item", {"type": "message", "role": "user", "content": "child"}),
                    {"type": "session-search-tombstone"}, rec("session_meta", {"id": sid, "forked_from_id": parent})]
        for ordinal in (None, -1, True, 0, 1, 3, 7):
            seq = [dict(r, ordinal=ordinal) for r in sequence]
            value = {"session_id": sid, "saved": {"future_field": "keep"}, "records": seq}
            yield {"id": "index/%d/%s" % (i, ordinal), "op": "index_sequence", "input": value,
                   "expect": evaluate(None, sc, "index_sequence", value)}

    # An ancestor may precede the first child header. A later ancestor-only
    # fixture cannot distinguish the ID guard from the header_seen guard.
    for foreign in ({"id": parent}, {"id": parent, "forked_from_id": "ancestor"}, {}, None):
        value = {"session_id": sid, "saved": {"future_field": "keep"}, "records": [
            rec("session_meta", foreign), rec("session_meta", {"id": sid}),
            rec("response_item", {"type": "message", "role": "user", "content": "child"})]}
        yield {"id": "index/foreign-first/%s" % dumps(foreign), "op": "index_sequence", "input": value,
               "expect": evaluate(None, sc, "index_sequence", value)}


def write_corpus(path, format_name, ruleset, source, vectors, minimum, extra=None):
    body = b"".join((dumps(pack(v)) + "\n").encode() for v in vectors)
    count = body.count(b"\n")
    if count < minimum:
        raise ValueError("not enough vectors")
    header = {"format": format_name, "ruleset": ruleset, "source_blob": blob(source),
              "python": platform.python_version(), "unicode": unicodedata.unidata_version,
              "hmac_key_hex": KEY.hex(), "seed": SEED, "min_vectors": minimum,
              "vectors": count, "sha256_of_vectors": hashlib.sha256(body).hexdigest()}
    header.update(extra or {})
    path.write_bytes((dumps(header) + "\n").encode() + body)
    print("GENERATED %s vectors=%d bytes=%d" % (path.name, count, path.stat().st_size))


def check(path, kind, client=None):
    global LINE_ORACLE
    sr = module("_conformance_redact", SERVER / "session_redact.py")
    sc = module("_conformance_codex", SERVER / "session_codex.py")
    source = SERVER / ("session_" + kind + ".py")
    data = path.read_bytes()
    head, body = data.split(b"\n", 1)
    header = json.loads(head)
    expected_format = "ccs-%s-conformance/1" % kind
    if header["format"] != expected_format or header["source_blob"] != blob(source):
        raise ValueError("format/source_blob mismatch")
    if kind == "redact":
        if header["client_source_blob"] != blob_bytes(header["client_source"].encode()):
            raise ValueError("client_source_blob mismatch (frozen source)")
        if client and header["client_source_blob"] != blob(client / "ccs/ingest.py"):
            raise ValueError("client_source_blob mismatch (live source)")
        if header["server_parser_source_blob"] != blob(SERVER / "sessions_app.py"):
            raise ValueError("server_parser_source_blob mismatch")
        LINE_ORACLE = line_oracle(header["client_source"])
        server = strict_oracle()
    lines = body.splitlines()
    minimum = 8000 if kind == "redact" else 100
    if header["min_vectors"] < minimum or not lines or len(lines) != header["vectors"] or len(lines) < header["min_vectors"]:
        raise ValueError("vector count mismatch")
    if hashlib.sha256(body).hexdigest() != header["sha256_of_vectors"]:
        raise ValueError("sha256_of_vectors mismatch")
    failures, seen = [], set()
    for line in lines:
        v = expand(json.loads(line))
        if v["id"] in seen:
            raise ValueError("duplicate vector id")
        seen.add(v["id"])
        key = bytes.fromhex(v.get("hmac_key_hex", header["hmac_key_hex"]))
        got = evaluate(sr, sc, v["op"], v["input"], key, v.get("kwargs"))
        if v["op"] == "mask_line":
            tags, facts, rust_expected = rust_line_contract(LINE_ORACLE, v["input"], got)
            if (tags != v["compat"] or facts != v["raw_facts"]
                    or dumps(rust_expected) != dumps(v["rust_expect"])
                    or server_result(server, v["input"]) != v["server_expect"]):
                failures.append(v["id"] + "/line-contract")
                print("FAIL mismatch " + v["id"] + "/line-contract", file=sys.stderr)
        # JSON encoding compares types AND key order, unlike Python ==.
        if dumps(got) != dumps(v["expect"]):
            failures.append(v["id"])
            print("FAIL mismatch " + v["id"], file=sys.stderr)
    print("---- pass=%d fail=%d" % (len(lines) - len(failures), len(failures)))
    return 1 if failures else 0


def negative_control(path, kind, client=None):
    """N8: change one expected character, repair the checksum, require mismatch.

    Exercise the same executable runner CI invokes. Rehashing makes this a
    behavioral negative control, not merely an integrity-check rejection.
    """
    header, *rows = path.read_bytes().splitlines()
    header = json.loads(header)
    for i, raw in enumerate(rows):
        row = json.loads(raw)
        if isinstance(row.get("expect"), dict) and isinstance(row["expect"].get("output"), str):
            output = row["expect"]["output"]
            if output:
                row["expect"]["output"] = ("!" if output[0] != "!" else "?") + output[1:]
                break
        if kind == "codex" and isinstance(row.get("expect"), dict) and "type" in row["expect"]:
            row["expect"]["type"] = "!" + row["expect"]["type"][1:]
            break
    else:
        raise ValueError("N8 has no mutable expected string")
    rows[i] = dumps(row).encode()
    body = b"\n".join(rows) + b"\n"
    header["sha256_of_vectors"] = hashlib.sha256(body).hexdigest()
    with tempfile.TemporaryDirectory(prefix="ccs-n8-") as tmp:
        changed = Path(tmp) / path.name
        changed.write_bytes(dumps(header).encode() + b"\n" + body)
        command = [sys.executable, "-B", str(SERVER / ("test_session_" + kind + "_conformance.py")),
                   "--corpus", str(changed), "--no-n8"]
        if client:
            command += ["--client-tree", str(client)]
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    expected_error = "FAIL mismatch " + row["id"]
    if result.returncode != 1 or expected_error not in result.stderr:
        raise ValueError("N8 failed to reject changed expectation: " + result.stdout + result.stderr)
    print("N8 PASS: one expected character changed; checksum repaired; child exit=1; " + expected_error)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--client-tree", type=Path)
    parser.add_argument("--check", choices=("redact", "codex"))
    parser.add_argument("--corpus", type=Path)
    parser.add_argument("--no-n8", action="store_true", help="internal negative-control child only")
    args = parser.parse_args()
    if args.check:
        filename = "session_redact_r1.jsonl" if args.check == "redact" else "session_codex_v1.jsonl"
        path = args.corpus or HERE / filename
        result = check(path, args.check, args.client_tree)
        if result == 0 and not args.no_n8:
            negative_control(path, args.check, args.client_tree)
        return result
    if not args.client_tree:
        parser.error("generation requires --client-tree pointing to the real ccs sources")
    sr = module("_conformance_redact", SERVER / "session_redact.py")
    sc = module("_conformance_codex", SERVER / "session_codex.py")
    vectors = []
    for ident, op, value, key, kwargs in redactor_inputs(sr):
        v = {"id": ident, "op": op, "input": value, "expect": evaluate(sr, sc, op, value, key, kwargs)}
        if key != KEY:
            v["hmac_key_hex"] = key.hex()
        if kwargs:
            v["kwargs"] = kwargs
        vectors.append(v)
    vectors.extend(line_vectors(args.client_tree.resolve(), sr))
    write_corpus(HERE / "session_redact_r1.jsonl", "ccs-redact-conformance/1", "r1",
                 SERVER / "session_redact.py", vectors, 8000,
                 {"client_source_blob": blob(args.client_tree / "ccs/ingest.py"),
                  "client_source": (args.client_tree / "ccs/ingest.py").read_text(),
                  "server_parser_source_blob": blob(SERVER / "sessions_app.py")})
    write_corpus(HERE / "session_codex_v1.jsonl", "ccs-codex-conformance/1", "v1",
                 SERVER / "session_codex.py", codex_vectors(sc), 100)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (ValueError, KeyError, TypeError) as exc:
        print("FAIL corpus: " + str(exc), file=sys.stderr)
        sys.exit(1)
