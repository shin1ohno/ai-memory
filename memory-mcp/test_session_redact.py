#!/usr/bin/env python3
"""Tests for session_redact (design spec §6.2, ruleset r1).

Every fake secret here is synthetic and obviously fake (runs of one letter);
none matches a real key checksum. Stdlib only: runs on a bare python3.

Usage: python3 test_session_redact.py
"""

from __future__ import annotations

import json
import os
import random
import re
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import session_redact as sr  # noqa: E402

KEY = b"test-key-not-a-secret"
TAGGED_RE = re.compile(r"\[REDACTED:([a-z-]+):([0-9a-f]{8})\]")
UNTAGGED_RE = re.compile(r"\[REDACTED:([a-z-]+)\]")

A36 = "A" * 36
# kind -> (positive text, negative text)
VECTORS = {
    "aws-key": ("id AKIA" + "Z" * 16 + " end", "id AKIA" + "Z" * 10 + " end"),
    "github-token": ("tok ghp_" + A36 + " end", "tok ghp_" + "A" * 10 + " end"),
    "anthropic-key": ("k=sk-ant-" + "a" * 24, "k=sk-ant-abc"),
    "openai-key": ("k sk-proj-" + "b" * 24, "k sk-abc def"),
    "slack-token": ("xoxb-" + "1" * 12, "xoxb-123"),
    "google-api-key": ("AIza" + "C" * 35, "AIza" + "C" * 20),
    "gitlab-token": ("glpat-" + "d" * 20, "glpat-short"),
    "jwt": ("eyJ" + "e" * 10 + "." + "f" * 10 + "." + "g" * 10, "eyJabc.def.ghi"),
    "bearer": ("Authorization: Bearer " + "h" * 20, "Authorization: Bearer short"),
    "private-key": ("-----BEGIN OPENSSH PRIVATE KEY-----\nQUFBQQ==\n-----END OPENSSH PRIVATE KEY-----",
                    "-----BEGIN PUBLIC KEY-----\nQUFB\n-----END PUBLIC KEY-----"),
    "config-secret": ("DB_PASSWORD=hunter2hunter2", "DB_PASSWORD=short"),
    "url-credential": ("https://alice:wonderland99@example.com/x", "https://example.com/x"),
}


def redact(s):
    return sr.redact_text(s, KEY)[0]


class Vectors(unittest.TestCase):
    def test_positive_and_negative_per_kind(self):
        for kind, (pos, neg) in VECTORS.items():
            with self.subTest(kind=kind):
                out, counts = sr.redact_text(pos, KEY)
                self.assertIn(kind, counts, out)
                self.assertIn(f"[REDACTED:{kind}", out)
                self.assertEqual(sr.detect_record({"t": pos}), [kind])
                nout, ncounts = sr.redact_text(neg, KEY)
                self.assertEqual(nout, neg)
                self.assertEqual(ncounts, {})
                self.assertEqual(sr.detect_record({"t": neg}), [])

    def test_anthropic_before_openai(self):
        out, counts = sr.redact_text("sk-ant-" + "a" * 30, KEY)
        self.assertEqual(list(counts), ["anthropic-key"])
        self.assertTrue(out.startswith("[REDACTED:anthropic-key:"))

    def test_github_pat(self):
        out, counts = sr.redact_text("github_pat_" + "Q" * 60, KEY)
        self.assertEqual(counts, {"github-token": 1})

    def test_only_value_is_replaced(self):
        self.assertEqual(redact("Authorization: Bearer " + "h" * 20),
                         "Authorization: Bearer [REDACTED:bearer]")
        self.assertEqual(redact('"Authorization": "Bearer ' + "h" * 20 + '"'),
                         '"Authorization": "Bearer [REDACTED:bearer]"')
        self.assertEqual(redact("DB_PASSWORD=hunter2hunter2 next"),
                         "DB_PASSWORD=[REDACTED:config-secret] next")
        self.assertEqual(redact('{"api_key": "long secret value"}'),
                         '{"api_key": "[REDACTED:config-secret]"}')
        self.assertEqual(redact("password: hunter2hunter2"), "password: [REDACTED:config-secret]")
        self.assertEqual(redact("https://alice:wonderland99@example.com/x"),
                         "https://alice:[REDACTED:url-credential]@example.com/x")

    def test_private_key_block_replaced_whole(self):
        pgp = "-----BEGIN PGP PRIVATE KEY BLOCK-----\nlQ==\n-----END PGP PRIVATE KEY BLOCK-----"
        self.assertEqual(redact("a " + pgp + " b"), "a [REDACTED:private-key] b")
        truncated = "x -----BEGIN RSA PRIVATE KEY-----\nMIIEow"
        self.assertEqual(redact(truncated), "x [REDACTED:private-key]")

    def test_placeholder_values_are_not_masked(self):
        for v in ("${DB_PASSWORD}", "<your-password-here>", "xxxxxxxxxxxx", "***********",
                  "[REDACTED:config-secret]"):
            with self.subTest(v=v):
                s = f"DB_PASSWORD={v}"
                self.assertEqual(redact(s), s)
                self.assertEqual(sr.detect_record({"t": s}), [])

    def test_low_entropy_kinds_untagged(self):
        for kind in ("bearer", "private-key", "config-secret", "url-credential"):
            out = redact(VECTORS[kind][0])
            self.assertTrue(UNTAGGED_RE.search(out), out)
            self.assertFalse(TAGGED_RE.search(out), out)

    def test_tagged_kinds_carry_hmac8(self):
        tok = "ghp_" + A36
        out1, out2 = redact(tok), redact(tok)
        self.assertEqual(out1, out2)
        m = TAGGED_RE.fullmatch(out1)
        self.assertIsNotNone(m)
        other = sr.redact_text(tok, b"another-key")[0]
        self.assertNotEqual(out1, other)

    def test_dict_key_secret(self):
        rec = {"input": {"password": "hunter2hunter2", "count": 12, "ok": True, "x": None}}
        out, counts = sr.redact_record(rec, KEY)
        self.assertEqual(out["input"]["password"], "[REDACTED:config-secret]")
        self.assertEqual(out["input"]["count"], 12)
        self.assertIs(out["input"]["ok"], True)
        self.assertEqual(rec["input"]["password"], "hunter2hunter2", "input must not be mutated")
        self.assertEqual(sr.detect_record(rec), ["config-secret"])
        self.assertEqual(sr.detect_record(out), [])

    def test_structure_preserved(self):
        rec = {"type": "user", "message": {"content": [{"type": "text", "text": "hi ghp_" + A36}]},
               "n": [1, 2.5, False]}
        out, counts = sr.redact_record(rec, KEY)
        self.assertEqual(set(out), set(rec))
        self.assertEqual(out["n"], [1, 2.5, False])
        self.assertTrue(out["message"]["content"][0]["text"].startswith("hi [REDACTED:github-token:"))
        self.assertEqual(counts, {"github-token": 1})


class FixedPoint(unittest.TestCase):
    FRAGMENTS = [v[0] for v in VECTORS.values()] + [v[1] for v in VECTORS.values()] + [
        "[REDACTED:bearer]", "[REDACTED:github-token:0123abcd]", "Authorization: Bearer ",
        "token=", "password: ", '"secret": "', '"', " ", "\n", "=", ":", "@", "/", "-", "_",
        "日本語のテキスト", "worktree", "ghp_", "sk-", "eyJ", "https://", "x" * 20, "A" * 16,
    ]

    def test_redact_is_idempotent_and_detector_clean(self):
        rnd = random.Random(20261006)
        for _ in range(3000):
            s = "".join(rnd.choice(self.FRAGMENTS) for _ in range(rnd.randint(1, 12)))
            once = redact(s)
            self.assertEqual(redact(once), once, repr(s))
            self.assertEqual(sr.detect_record({"t": once}), [], repr(s))

    def test_prefilter_is_exact(self):
        """The anchor prefilter may only skip strings no rule can change."""
        for kind, (pos, _neg) in VECTORS.items():
            self.assertTrue(sr._ANCHOR_RE.search(pos), kind)
        rnd = random.Random(7)
        alphabet = list("abcAKISgh_pusr-kxoIzlteyJ:/=@ \"'.BEGN") + ["-----BEGIN ", "Bearer "]
        skipped = 0
        for _ in range(20000):
            s = "".join(rnd.choice(alphabet) for _ in range(rnd.randint(1, 40)))
            if not sr._ANCHOR_RE.search(s):
                skipped += 1
                counts = {}
                self.assertEqual(sr._one_pass(s, KEY, counts), s, repr(s))
                self.assertEqual(counts, {}, repr(s))
        self.assertGreater(skipped, 1000)

    def test_detector_ignores_placeholders(self):
        for s in ("Authorization: Bearer [REDACTED:bearer]",
                  "[REDACTED:github-token:0123abcd]",
                  "token=[REDACTED:config-secret]",
                  "https://a:[REDACTED:url-credential]@h"):
            self.assertEqual(sr.detect_record({"t": s}), [], s)
            self.assertEqual(sr.detect_text(s), [], s)


class Deep(unittest.TestCase):
    def _leaf(self, root, depth, key):
        cur = root
        for _ in range(depth):
            cur = cur[key] if isinstance(cur, dict) else cur[0]
        return cur

    def test_10000_deep_list(self):
        root = []
        cur = root
        for _ in range(10000):
            nxt = []
            cur.append(nxt)
            cur = nxt
        cur.append("ghp_" + A36)
        out, counts = sr.redact_record(root, KEY)
        self.assertEqual(counts, {"github-token": 1})
        leaf = self._leaf(out, 10000, None)
        self.assertTrue(leaf[0].startswith("[REDACTED:github-token:"))
        self.assertEqual(sr.detect_record(root), ["github-token"])
        self.assertEqual(sr.detect_record(out), [])

    def test_10000_deep_dict(self):
        root = {}
        cur = root
        for _ in range(10000):
            cur["k"] = {}
            cur = cur["k"]
        cur["k"] = "DB_PASSWORD=hunter2hunter2"
        out, _ = sr.redact_record(root, KEY)
        self.assertEqual(self._leaf(out, 10001, "k"), "DB_PASSWORD=[REDACTED:config-secret]")


class Keys(unittest.TestCase):
    def test_load_key(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "hmac.key")
            with self.assertRaises(sr.KeyMissing):
                sr.load_key(p)
            open(p, "wb").close()
            with self.assertRaises(sr.KeyMissing):
                sr.load_key(p)
            with open(p, "wb") as fh:
                fh.write(b"abc123\n")
            self.assertEqual(sr.load_key(p), b"abc123")

    def test_empty_key_fails_closed(self):
        with self.assertRaises(sr.KeyMissing):
            sr.redact_text("x", b"")

    def test_unknown_version(self):
        with self.assertRaises(ValueError):
            sr.redact_text("x", KEY, "r0")
        with self.assertRaises(ValueError):
            sr.detect_record({}, "r9")
        self.assertEqual(sr.RULESET_VERSION, "r1")


class Adversarial(unittest.TestCase):
    """ReDoS: every pattern is linear on hostile input. Before the fix,
    `eyJ-` * 2000, a run of letters (URL scheme) and `"token` * 1600 each took
    0.6-1.5 s at 8 KB and grew quadratically; at 200 KB they would run for
    minutes. The bound is generous for a slow CI runner and still far below
    what a quadratic pattern needs at this size."""

    N = 200_000
    BOUND_S = 3.0

    def rep(self, s):
        return (s * (self.N // len(s) + 1))[:self.N]

    def test_wall_clock_bound(self):
        cases = ["eyJ-", "eyJaaaaaaaa.", "a", "a://b:", '"token', '"token": "', "token",
                 "-----BEGIN A ", "authorization: bearer ", "-ghp_" + "A" * 40 + "_", "sk-",
                 "xoxb-", "[REDACTED:", 'token=eyJ-a://ghp_sk-"secret": "']
        import time
        for c in cases:
            with self.subTest(case=c[:20]):
                s = self.rep(c)
                t = time.monotonic()
                sr.detect_text(s)
                redact(s)
                self.assertLess(time.monotonic() - t, self.BOUND_S)
        for prefix, filler in (("token", " "), ("authorization:", " "), ("a://b:", "c:"),
                               ('"token": "', "x\\")):
            s = prefix + self.rep(filler)
            t = time.monotonic()
            sr.detect_text(s)
            self.assertLess(time.monotonic() - t, self.BOUND_S, prefix)

    def test_scaling_is_linear(self):
        import time

        def cost(n):
            s = ("eyJ-" * (n // 4)) + ("a" * n) + ('"token' * (n // 6))
            t = time.monotonic()
            sr.detect_text(s)
            return time.monotonic() - t

        small, big = cost(20_000), cost(160_000)
        # 8x the input: linear ≈ 8x, quadratic ≈ 64x
        self.assertLess(big, max(small, 0.005) * 24)


class Caps(unittest.TestCase):
    def test_oversize_value_is_never_scanned_or_shipped(self):
        s = "ghp_" + "A" * 36 + " " + "x" * sr.MAX_VALUE_CHARS
        out, counts = sr.redact_text(s, KEY)
        self.assertEqual((out, counts), ("[REDACTED:oversize]", {"oversize": 1}))
        self.assertEqual(sr.detect_text(s), ["oversize"])
        self.assertEqual(sr.detect_record({"t": s}), ["oversize"])
        self.assertEqual(sr.detect_record({"t": out}), [])

    def test_record_total_cap(self):
        chunk = "y" * (sr.MAX_VALUE_CHARS - 1)
        rec = {f"k{i}": chunk for i in range(5)}
        self.assertEqual(sr.detect_record(rec), ["oversize"])
        out, counts = sr.redact_record(rec, KEY)
        self.assertEqual(set(counts), {"oversize"})
        masked = [k for k, v in out.items() if v == "[REDACTED:oversize]"]
        self.assertEqual(len(masked), counts["oversize"])
        self.assertLessEqual(sum(len(v) for v in out.values()), sr.MAX_RECORD_CHARS)
        self.assertEqual(sr.detect_record(out), [])

    def test_blob_cap_is_the_callers(self):
        s = "z" * (sr.MAX_VALUE_CHARS + 10)
        self.assertEqual(sr.detect_text(s), ["oversize"])
        self.assertEqual(sr.detect_text(s, max_chars=5_000_000), [])


class Keys2(unittest.TestCase):
    def test_secret_in_dict_key_is_detected_and_masked(self):
        tok = "ghp_" + A36
        rec = {"input": {tok: 1, "DB_PASSWORD=hunter2hunter2": 2, "plain": 3}}
        self.assertEqual(sr.detect_record(rec), ["config-secret", "github-token"])
        out, _ = sr.redact_record(rec, KEY)
        keys = list(out["input"])
        self.assertNotIn(tok, json.dumps(out))
        self.assertTrue(keys[0].startswith("[REDACTED:github-token:"))
        self.assertEqual(keys[1], "DB_PASSWORD=[REDACTED:config-secret]")
        self.assertEqual(out["input"]["plain"], 3)
        self.assertEqual(sr.detect_record(out), [])

    def test_colliding_masked_keys_are_kept_apart(self):
        rec = {"password=aaaaaaaa1": 1, "password=bbbbbbbb2": 2}
        out, _ = sr.redact_record(rec, KEY)
        self.assertEqual(sorted(out.values()), [1, 2])
        self.assertEqual(len(out), 2)


if __name__ == "__main__":
    unittest.main(verbosity=1)
