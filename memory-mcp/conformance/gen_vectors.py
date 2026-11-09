#!/usr/bin/env python3
"""Freeze the Python session contract; no network or production credentials.

Run with the server's Python/Unicode version. --client-tree supplies the real
ccs Shipper for line expectations (session-search 527735d or later).
The committed vectors are data; --check replays them without regenerating them.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import platform
import random
import re
import sys
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
    data = Path(path).read_bytes()
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
        # Replay the frozen line contract using server functions. Generation
        # uses Shipper._mask_line and Shipper._mask_chunk instead (below).
        raw = bytes.fromhex(value["hex"])
        text = raw.decode("utf-8", "replace")
        try:
            rec = json.loads(text)
        except ValueError:
            route = "text"
            output, counts = sr.redact_text(text, key)
        else:
            route = "record"
            rec, counts = sr.redact_record(rec, key)
            output = json.dumps(rec, ensure_ascii=False, separators=(",", ":"))
        if re.search(r"[\ud800-\udfff]", output):
            route = "tombstone"
            output = dumps({"type": "session-search-tombstone", "reason": "surrogate",
                            "kinds": [], "line_offset": value["offset"]})
        return {"route": route, "output": output, "counts": counts}
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


def redactor_inputs(sr):
    for name, sample in SAMPLES.items():
        pairs = ((a, b) for a in BOUNDARIES for b in BOUNDARIES) if name in CROSS else (
            [(a, "") for a in BOUNDARIES] + [("", b) for b in BOUNDARIES])
        for i, (left, right) in enumerate(pairs):
            for op in ("redact_text", "detect_text"):
                yield "boundary/%s/%04d/%s" % (name, i, op), op, left + sample + right, KEY, {}
        for i, (before, after) in enumerate((("Authorization", "authorızatıon"), ("Authorization", "authorİzation"),
                                            ("PASSWORD", "PAſſWORD"), ("secret", "ſecret"), ("key", "Key"), ("key", "Key"))):
            yield "case/%s/%d" % (name, i), "redact_text", sample.replace(before, after), KEY, {}
        for i, whitespace in enumerate(("\x1c", "\x1d", "\x1e", "\x1f", "\x85")):
            yield "space/%s/%d" % (name, i), "redact_text", sample.replace(" ", whitespace), KEY, {}
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


def line_vectors(client, sr):
    sys.path.insert(0, str(client))
    module("ccs.session_codex", client / "vendor/memory-mcp/session_codex.py")
    from ccs import ingest
    shipper = ingest.Shipper.__new__(ingest.Shipper)
    shipper.redactor, shipper.key = sr, KEY
    shipper.stats = {"tombstones": 0}
    lines = [b'{}', b'null', b'false', b'42', b'"plain"', b'{"x":1,"x":2}',
             b'{"x":NaN}', b'{"x":Infinity}', b'{"x":1e400}', b'{"n":01}',
             b'{"x":}', b'{"x":"\\uD800"}', b'{"x":"\\uDC00"}',
             b'{"x":"\\ud83d\\ude00"}', b'{"secret":"\\ud800abcdefghij"}',
             b'{"x":"\\ud800","x":"overwritten"}', b'\xff\xc0\xaf secret=abcdefghij',
             b'{"x":"\xed\xa0\x80"}', b'{"x":"\xe2\x82"}',
             b'{"$serde_json::private::Number":"123"}',
             b'{"$serde_json::private::RawValue":"{}"}', b'{"x":true} trailing',
             b'[1,2,]', b'{"x":1e}', b'1' * 4301]
    for depth in (63, 64, 65, 66):
        for leaf in ('"plain"', '"ghp_' + 'A' * 36 + '"'):
            lines.append(('[' * (depth - 1) + leaf + ']' * (depth - 1)).encode())
    # Suppress logging only: expectations still come from the real methods.
    old_log = ingest.util.log
    ingest.util.log = lambda *args: None
    try:
        for i, raw in enumerate(lines):
            off = i * 17
            masked, counts = shipper._mask_line(raw)
            sent, _ = shipper._mask_chunk(raw + b"\n", off)
            try:
                json.loads(raw.decode("utf-8", "replace"))
                route = "record"
            except ValueError:
                route = "text"
            if sent[0] != masked:
                route = "tombstone"
            yield {"id": "line/%03d" % i, "op": "mask_line", "input": {"hex": raw.hex(), "offset": off},
                   "expect": {"route": route, "output": sent[0], "counts": counts}}
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
    for i, row in enumerate(rows):
        yield {"id": "normalize/%03d" % i, "op": "normalize", "input": row,
               "kwargs": {"position": i, "entrypoint": "codex-cli", "cwd": "/old"},
               "expect": evaluate(None, sc, "normalize", row, kwargs={"position": i, "entrypoint": "codex-cli", "cwd": "/old"})}
    for i, extras in enumerate(({}, {"forked_from_id": parent}, {"subagent_history_start_ordinal": 4},
                               {"ccs_index_start_ordinal": 3, "subagent_history_start_ordinal": 99},
                               {"subagent_history_start_ordinal": -1}, {"subagent_history_start_ordinal": True})):
        sequence = [rec("session_meta", dict(id=sid, **extras)), rec("session_meta", {"id": parent}),
                    rec("response_item", {"type": "message", "role": "user", "content": "inherited"}),
                    rec("event_msg", {"type": "thread_settings_applied", "thread_id": parent}),
                    rec("event_msg", {"type": "thread_settings_applied", "thread_id": sid}),
                    rec("response_item", {"type": "message", "role": "user", "content": "child"}),
                    {"type": "session-search-tombstone"}, rec("session_meta", {"id": sid, "forked_from_id": parent})]
        for ordinal in (None, -1, True, 7):
            seq = [dict(r, ordinal=ordinal) for r in sequence]
            value = {"session_id": sid, "saved": {"future_field": "keep"}, "records": seq}
            yield {"id": "index/%d/%s" % (i, ordinal), "op": "index_sequence", "input": value,
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


def check(path, kind):
    sr = module("_conformance_redact", SERVER / "session_redact.py")
    sc = module("_conformance_codex", SERVER / "session_codex.py")
    source = SERVER / ("session_" + kind + ".py")
    data = path.read_bytes()
    head, body = data.split(b"\n", 1)
    header = json.loads(head)
    expected_format = "ccs-%s-conformance/1" % kind
    if header["format"] != expected_format or header["source_blob"] != blob(source):
        raise ValueError("format/source_blob mismatch")
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
        # JSON encoding compares types AND key order, unlike Python ==.
        if dumps(got) != dumps(v["expect"]):
            failures.append(v["id"])
            print("FAIL mismatch " + v["id"], file=sys.stderr)
    print("---- pass=%d fail=%d" % (len(lines) - len(failures), len(failures)))
    return 1 if failures else 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--client-tree", type=Path)
    parser.add_argument("--check", choices=("redact", "codex"))
    parser.add_argument("--corpus", type=Path)
    args = parser.parse_args()
    if args.check:
        filename = "session_redact_r1.jsonl" if args.check == "redact" else "session_codex_v1.jsonl"
        return check(args.corpus or HERE / filename, args.check)
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
                 {"client_source_blob": blob(args.client_tree / "ccs/ingest.py")})
    write_corpus(HERE / "session_codex_v1.jsonl", "ccs-codex-conformance/1", "v1",
                 SERVER / "session_codex.py", codex_vectors(sc), 100)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (ValueError, KeyError, TypeError) as exc:
        print("FAIL corpus: " + str(exc), file=sys.stderr)
        sys.exit(1)
