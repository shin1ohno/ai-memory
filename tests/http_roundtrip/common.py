"""Identities and request helpers shared by the case modules."""

from __future__ import annotations

import json
import time

import lib

# Fixed, obviously fake identities. Nothing here is a credential of a real
# system; the values only have to agree between the fakes and the processes.
ISSUER = "https://issuer.example.test"
OPERATOR = "operator@example.test"
PROXY_SECRET = "roundtrip-proxy-secret"
MIRROR_SECRET = "roundtrip-mirror-secret"
CLIENT_POLICY = ("memory-keeper=;monitoring-prober=;memory-mirror=ingest,forget@file-memory;"
                 "roundtrip-writer=ingest,forget@notes|file-memory;session-search-a=")
SESSION_SCOPE_POLICY = json.dumps({"rules": [
    {"match": {"grant": "client_credentials", "client_id": "session-search-a"},
     "host": "host-a", "scopes": ["sessions:ingest", "sessions:read"]},
    {"match": {"grant": "client_credentials", "client_id": "session-search-b"},
     "host": "host-b", "scopes": ["sessions:ingest", "sessions:read"]},
    {"match": {"grant": "authorization_code", "sub": OPERATOR},
     "host": None, "scopes": ["sessions:read", "sessions:purge"]},
    {"match": {"client_id": "session-search-hostless"},
     "host": None, "scopes": ["sessions:ingest", "sessions:read", "sessions:purge"]},
]})
ALLOWED_CLIENT_IDS = "memory-keeper,monitoring-prober,memory-mirror,roundtrip-writer,session-search-a"



CONNECTOR = "claude-connector"


def verified(grant="authorization_code", sub=OPERATOR, client_id=CONNECTOR, secret=PROXY_SECRET):
    """The headers the proxy sets upstream (C-HTTP-7). A client_credentials
    identity has sub == client_id (C-JWT-4)."""
    h = {}
    if grant is not None:
        h["X-Verified-Grant"] = grant
    if sub is not None:
        h["X-Verified-Sub"] = sub
    if client_id is not None:
        h["X-Verified-Client-Id"] = client_id
    if secret is not None:
        h["X-Proxy-Secret"] = secret
    return h


def machine(client_id, secret=PROXY_SECRET):
    return verified("client_credentials", client_id, client_id, secret)


def mcp_client(base, headers=None, version="2025-06-18", init=True):
    c = lib.Mcp(f"{base}/memory/mcp", headers if headers is not None else verified(), version)
    if init:
        r = c.initialize()
        if r.status != 200:
            raise AssertionError(f"initialize: HTTP {r.status} {r.body[:200]!r}")
    return c


def settle(es, timeout=3.0):
    """Wait for recall's fire-and-forget use_count bump to land, so the next
    step sees a deterministic store."""
    es.wait_for(lambda r: r.path.endswith("/_update_by_query") and r.query.get("conflicts") == "proceed"
                and "refresh" not in r.query, timeout)
    time.sleep(0.05)


def token_claims(sub, client_id, aud=None, **extra):
    now = int(time.time())
    claims = {"iss": ISSUER, "sub": sub, "client_id": client_id, "iat": now, "nbf": now,
              "exp": now + 600, "jti": f"jti-{now}"}
    if aud is not None:
        claims["aud"] = aud
    claims.update(extra)
    return claims
