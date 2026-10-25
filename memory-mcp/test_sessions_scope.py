#!/usr/bin/env python3
"""SESSION_SCOPE_POLICY decision matrix (design spec §7.6, identity.py).

grant × client_id × sub × scope against the contract policy, plus the
fail-closed cases: unset, empty and every malformed shape = deny-all, and the
existing CLIENT_POLICY behaviour is untouched. Stdlib only (identity.py imports
nothing third-party).

Usage: python3 test_sessions_scope.py
"""

from __future__ import annotations

import itertools
import json
import os
import subprocess
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
os.environ.pop("SESSION_SCOPE_POLICY", None)

import identity  # noqa: E402

POLICY = {"rules": [
    {"match": {"grant": "client_credentials", "client_id": "session-search-pro-dev"},
     "host": "pro-dev", "scopes": ["sessions:ingest", "sessions:read"]},
    {"match": {"grant": "authorization_code", "client_id": "tailnet:nXXXX"},
     "host": "air", "scopes": ["sessions:ingest", "sessions:read", "sessions:purge"]},
    {"match": {"grant": "authorization_code", "sub": "operator@example.com"},
     "host": None, "scopes": ["sessions:read", "sessions:purge"]},
]}
RULES = identity.parse_session_scope_policy(json.dumps(POLICY))

GRANTS = ["client_credentials", "authorization_code", "", "password"]
CLIENTS = ["session-search-pro-dev", "tailnet:nXXXX", "memory-mirror", "claude-ai", ""]
SUBS = ["operator@example.com", "someone@example.com", "session-search-pro-dev", ""]
SCOPES = ["sessions:ingest", "sessions:read", "sessions:purge", "sessions:admin"]


def expected(grant, client_id, sub, scope):
    if grant == "client_credentials" and client_id == "session-search-pro-dev":
        return (scope in ("sessions:ingest", "sessions:read"), "pro-dev")
    if grant == "authorization_code" and client_id == "tailnet:nXXXX":
        return (scope in ("sessions:ingest", "sessions:read", "sessions:purge"), "air")
    if grant == "authorization_code" and sub == "operator@example.com":
        return (scope in ("sessions:read", "sessions:purge"), None)
    return (False, None)


class Matrix(unittest.TestCase):
    def test_full_matrix(self):
        n = 0
        for grant, cid, sub, scope in itertools.product(GRANTS, CLIENTS, SUBS, SCOPES):
            ident = {"grant": grant, "client_id": cid, "sub": sub}
            ok, host = identity.authorize_session_scope(ident, scope, RULES)
            want_ok, want_host = expected(grant, cid, sub, scope)
            self.assertEqual(ok, want_ok, (grant, cid, sub, scope))
            if ok:
                self.assertEqual(host, want_host, (grant, cid, sub, scope))
            else:
                self.assertIsNone(host)
            n += 1
        self.assertEqual(n, 4 * 5 * 4 * 4)

    def test_memory_mirror_gets_nothing(self):
        for scope in SCOPES:
            self.assertEqual(identity.authorize_session_scope(
                {"grant": "client_credentials", "client_id": "memory-mirror", "sub": "memory-mirror"},
                scope, RULES), (False, None))

    def test_first_match_wins(self):
        rules = identity.parse_session_scope_policy(json.dumps({"rules": [
            {"match": {"sub": "u@example.com"}, "host": None, "scopes": ["sessions:read"]},
            {"match": {"sub": "u@example.com"}, "host": "air", "scopes": ["sessions:purge"]}]}))
        ident = {"grant": "authorization_code", "client_id": "c", "sub": "u@example.com"}
        self.assertEqual(identity.authorize_session_scope(ident, "sessions:read", rules), (True, None))
        self.assertEqual(identity.authorize_session_scope(ident, "sessions:purge", rules), (False, None))


class FailClosed(unittest.TestCase):
    MALFORMED = [
        "", "not json", "[]", "{}", '{"rules": {}}', '{"rules": [], "extra": 1}',
        '{"rules": [{"match": {}, "host": null, "scopes": ["sessions:read"]}]}',
        '{"rules": [{"match": {"grant": "client_credentials"}, "host": null}]}',
        '{"rules": [{"match": {"tenant": "x"}, "host": null, "scopes": []}]}',
        '{"rules": [{"match": {"grant": "implicit"}, "host": null, "scopes": []}]}',
        '{"rules": [{"match": {"sub": ""}, "host": null, "scopes": []}]}',
        '{"rules": [{"match": {"sub": 5}, "host": null, "scopes": []}]}',
        '{"rules": [{"match": {"sub": "a"}, "host": "Air", "scopes": []}]}',
        '{"rules": [{"match": {"sub": "a"}, "host": "a/b", "scopes": []}]}',
        '{"rules": [{"match": {"sub": "a"}, "host": null, "scopes": ["sessions:root"]}]}',
        '{"rules": [{"match": {"sub": "a"}, "host": null, "scopes": ["sessions:read", "sessions:read"]}]}',
        '{"rules": [{"match": {"sub": "a"}, "host": null, "scopes": "sessions:read"}]}',
        '{"rules": [{"match": {"sub": "a"}, "host": null, "scopes": [], "note": 1}]}',
    ]

    def test_unset_and_malformed_deny_all(self):
        ident = {"grant": "authorization_code", "client_id": "tailnet:nXXXX", "sub": "a"}
        rules, err = identity._load_session_scope_policy(None)
        self.assertIsNone(rules)
        self.assertEqual(identity.authorize_session_scope(ident, "sessions:read", rules), (False, None))
        for spec in self.MALFORMED:
            with self.subTest(spec=spec):
                rules, err = identity._load_session_scope_policy(spec)
                self.assertIsNone(rules)
                self.assertTrue(err)
                for scope in SCOPES:
                    self.assertEqual(identity.authorize_session_scope(ident, scope, rules),
                                     (False, None))

    def test_active_policy_from_env_unset_is_deny_all(self):
        self.assertIsNone(identity._SESSION_SCOPE_POLICY)
        ident = {"grant": "client_credentials", "client_id": "session-search-pro-dev", "sub": "x"}
        self.assertEqual(identity.authorize_session_scope(ident, "sessions:read"), (False, None))
        self.assertTrue(identity.session_scope_policy_lines()[0].startswith(
            "SESSIONS scope-policy deny-all"))

    def test_env_loading_in_subprocess(self):
        """The env value is read at import: a valid one is active, a malformed
        one is deny-all with a reason line."""
        code = ("import identity,json;print(json.dumps([identity.authorize_session_scope("
                "{'grant':'client_credentials','client_id':'session-search-pro-dev','sub':''},"
                "'sessions:ingest'), identity.session_scope_policy_lines()]))")
        for spec, want in ((json.dumps(POLICY), [True, "pro-dev"]), ('{"rules": 1}', [False, None])):
            env = dict(os.environ, SESSION_SCOPE_POLICY=spec)
            out = subprocess.run([sys.executable, "-c", code], cwd=HERE, env=env,
                                 capture_output=True, text=True, check=True).stdout
            decision, lines = json.loads(out)
            self.assertEqual(decision, want)
            self.assertFalse(any("POLICY " in ln for ln in lines), lines)


class ClientPolicyUntouched(unittest.TestCase):
    def test_client_policy_still_refuses_sessions_tools(self):
        with self.assertRaises(identity.PolicyError):
            identity.parse_client_policy("memory-mirror=sessions:ingest@file-memory")
        pol = identity.parse_client_policy("memory-mirror=ingest,forget@file-memory")
        ok, _ = identity.authorize_tool({"grant": "client_credentials", "client_id": "memory-mirror"},
                                        "ingest", {"dataset": "file-memory", "document": "x"}, pol)
        self.assertTrue(ok)


if __name__ == "__main__":
    unittest.main(verbosity=1)
