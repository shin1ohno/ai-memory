"""C-JWT-1..6: token verification in the proxy, against the fake JWKS."""

from __future__ import annotations

import math
import threading
import time

import lib
from common import ISSUER, OPERATOR
from lib import case
from rsa_jwt import mint

_DROP = object()


def _claims(**over):
    now = int(time.time())
    c = {"iss": ISSUER, "sub": OPERATOR, "client_id": "claude-connector", "iat": now, "nbf": now,
         "exp": now + 600, "jti": "jti-1"}
    for k, v in over.items():
        if v is _DROP:
            c.pop(k, None)
        else:
            c[k] = v
    return c


def status_of(base, token):
    return lib.request("GET", base + "/mcp", headers={"Authorization": f"Bearer {token}"}).status


@case("C-JWT-1", "RS256 only, issuer required, leeway 0, aud not part of signature check", "proxy")
def basic_validation(ctx):
    base = ctx.env.proxy()
    k1 = ctx.env.keys[0]
    now = int(time.time())
    probes = {
        "valid": mint(_claims(), k1),
        "expired-1s": mint(_claims(exp=now - 1), k1),
        "nbf-future": mint(_claims(nbf=now + 30), k1),
        "iat-future": mint(_claims(iat=now + 30), k1),
        "wrong-issuer": mint(_claims(iss="https://other.example.test"), k1),
        "missing-iss": mint(_claims(iss=_DROP), k1),
        "alg-HS256": mint(_claims(), k1, alg="HS256", hs_secret=b"roundtrip-hs-key"),
        "alg-none": mint(_claims(), k1, alg="none"),
        "tampered-signature": mint(_claims(), k1, tamper=True),
        "aud-unrelated": mint(_claims(aud="unrelated-audience"), k1),
    }
    rows = {name: status_of(base, tok) for name, tok in probes.items()}
    # With enforcement off (MEMORY_AUDIENCES empty), aud plays no part at all.
    inert = ctx.env.proxy("proxy-inert", MEMORY_AUDIENCES="")
    rows["inert-aud-unrelated"] = status_of(inert, mint(_claims(aud="unrelated-audience",
                                                                sub="anyone@example.test"), k1))
    ctx.env.stop("proxy-inert")
    ctx.golden("statuses", rows)
    want = {"valid": 200, "aud-unrelated": 200, "inert-aud-unrelated": 200}
    for name, st in rows.items():
        ctx.eq(st, want.get(name, 401), name)


@case("C-JWT-2", "kid selects the key; no or unknown kid falls back to the first key", "proxy-2keys")
def kid_selection(ctx):
    jwks = ctx.env.jwks
    k1, k2, k3 = ctx.env.keys
    jwks.keys = [k1, k2]
    try:
        base = ctx.env.proxy("proxy-2keys")
        rows = {
            "kid-k1": status_of(base, mint(_claims(), k1)),
            "kid-k2": status_of(base, mint(_claims(), k2)),
            "no-kid-signed-by-first": status_of(base, mint(_claims(), k1, kid=None)),
            "no-kid-signed-by-second": status_of(base, mint(_claims(), k2, kid=None)),
            "unknown-kid-signed-by-first": status_of(base, mint(_claims(), k1, kid="zzz")),
            "unknown-kid-signed-by-second": status_of(base, mint(_claims(), k2, kid="zzz")),
        }
        # A JWKS entry without kid is stored under "default".
        jwks.keys = [k3]
        ctx.env.stop("proxy-2keys")
        base = ctx.env.proxy("proxy-2keys")
        rows["jwk-without-kid"] = status_of(base, mint(_claims(), k3, kid=None))
        rows["jwk-without-kid-token-kid-default"] = status_of(base, mint(_claims(), k3, kid="default"))
    finally:
        jwks.keys = [k1]
        ctx.env.stop("proxy-2keys")
    ctx.golden("statuses", rows)
    ctx.eq(rows["no-kid-signed-by-second"], 401, "fallback is the first key only")
    ctx.eq(rows["kid-k2"], 200, "kid match")


@case("C-JWT-3", "a signature mismatch forces one JWKS refetch (rotation)", "proxy-rotate")
def rotation(ctx):
    jwks = ctx.env.jwks
    k1, k2 = ctx.env.keys[0], ctx.env.keys[1]
    jwks.keys = [k1]
    try:
        base = ctx.env.proxy("proxy-rotate")
        jwks.clear()
        first = status_of(base, mint(_claims(), k1))
        after_first = jwks.fetches()
        jwks.keys = [k2]  # the issuer rotated
        rotated = status_of(base, mint(_claims(), k2))
        after_rotate = jwks.fetches()
        # An old-key token now fails; a repeat within the negative-cache window
        # does not refetch again.
        old1 = status_of(base, mint(_claims(), k1))
        mid = jwks.fetches()
        old2 = status_of(base, mint(_claims(), k1))
        end = jwks.fetches()
    finally:
        jwks.keys = [k1]
        ctx.env.stop("proxy-rotate")
    rows = {"first": first, "fetches_after_first": after_first, "rotated_token": rotated,
            "fetches_after_rotation": after_rotate, "old_key_after_rotation": old1,
            "fetches_after_old": mid, "old_key_again": old2, "fetches_end": end}
    ctx.golden("rotation", rows)
    ctx.eq((first, rotated), (200, 200), "accepted before and after rotation")
    ctx.eq(after_rotate - after_first, 1, "exactly one forced refetch")


@case("C-JWT-4", "grant = (sub == client_id); aud str/list/missing x 2 grants", "proxy")
def grant_matrix(ctx):
    base = ctx.env.proxy()
    k1 = ctx.env.keys[0]
    rows = {}
    auds = (("str-memory", "memory"), ("list-memory", ["x", "memory"]),
            ("list-url", ["https://issuer.example.test/memory"]), ("missing", _DROP), ("empty-list", []),
            ("str-other", "other"))
    for aud_name, aud in auds:
        for grant, sub, cid in (("client_credentials", "memory-mirror", "memory-mirror"),
                                ("authorization_code", OPERATOR, "claude-connector")):
            tok = mint(_claims(aud=aud, sub=sub, client_id=cid), k1)
            r = lib.request("GET", base + "/mcp", headers={"Authorization": f"Bearer {tok}"})
            fwd = None
            if r.status == 200:
                fwd = {k.lower(): v for k, v in r.json()["headers"]}.get("x-verified-grant")
            rows[f"{grant}/{aud_name}"] = {"status": r.status, "x_verified_grant": fwd}
    # No client_id claim: sub != "" so the token counts as authorization_code.
    tok = mint(_claims(client_id=_DROP), k1)
    r = lib.request("GET", base + "/mcp", headers={"Authorization": f"Bearer {tok}"})
    rows["no-client_id"] = {"status": r.status, "x_verified_grant":
                            {k.lower(): v for k, v in r.json()["headers"]}.get("x-verified-grant")}
    ctx.golden("matrix", rows)
    ctx.eq(rows["client_credentials/missing"]["status"], 403, "machine token needs aud")
    ctx.eq(rows["authorization_code/missing"]["status"], 200, "human token does not")


@case("C-JWT-5", "single JWKS fetch under 50 concurrent requests; keys kept while JWKS fails; no redirect",
      "proxy-jwks")
def jwks_cache(ctx):
    jwks = ctx.env.jwks
    k1 = ctx.env.keys[0]
    rows = {}
    try:
        jwks.mode["delay"] = 0.5
        jwks.clear()
        base = ctx.env.proxy("proxy-jwks")
        tok = mint(_claims(), k1)
        results = []

        def one():
            results.append(status_of(base, tok))
        threads = [threading.Thread(target=one) for _ in range(50)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        jwks.mode.pop("delay", None)
        rows["concurrent_statuses"] = sorted(set(results))
        rows["concurrent_fetches"] = jwks.fetches()
        jwks.mode["status"] = 500
        rows["while_jwks_fails"] = status_of(base, tok)
        jwks.mode.pop("status", None)
        ctx.env.stop("proxy-jwks")
        # A redirecting JWKS is not followed: no keys, token rejected.
        before = len(jwks.taken(lambda r: r.path == "/redirect-target"))
        jwks.mode["redirect"] = f"{jwks.url}/redirect-target"
        base = ctx.env.proxy("proxy-jwks")
        rows["redirected_jwks"] = status_of(base, tok)
        rows["redirect_target_fetched"] = len(jwks.taken(lambda r: r.path == "/redirect-target")) - before
    finally:
        jwks.mode.clear()
        ctx.env.stop("proxy-jwks")
    ctx.golden("cache", rows)
    ctx.eq(rows["concurrent_fetches"], 1, "one fetch for 50 concurrent requests")
    ctx.eq(rows["while_jwks_fails"], 200, "cached key kept")
    ctx.eq((rows["redirected_jwks"], rows["redirect_target_fetched"]), (401, 0), "redirect not followed")


def _aligned(frac=0.1):
    """Sleep until the wall clock's fractional second is `frac`; return N."""
    now = time.time()
    n = math.floor(now)
    target = n + frac if now - n < frac else n + 1 + frac
    time.sleep(target - now)
    return math.floor(target)


@case("C-JWT-6", "exp/nbf/iat truncation like PyJWT; iss/sub/jti types", "proxy")
def time_claims(ctx):
    base = ctx.env.proxy()
    k1 = ctx.env.keys[0]
    probes = [("exp=N", "exp", 0.0, 401), ("exp=N+0.6", "exp", 0.6, 401), ("exp=N+1", "exp", 1.0, 200),
              ("exp=N+1.6", "exp", 1.6, 200), ("nbf=N+0.6", "nbf", 0.6, 200), ("nbf=N+1.6", "nbf", 1.6, 401),
              ("iat=N+0.6", "iat", 0.6, 200), ("iat=N+1.6", "iat", 1.6, 401)]
    rows = {}
    # Warm the key cache so the timed requests do not include a JWKS fetch.
    status_of(base, mint(_claims(), k1))
    for name, claim, delta, want in probes:
        st = None
        for _attempt in range(3):
            n = _aligned(0.1)
            value = n + delta if delta != int(delta) else n + int(delta)
            over = {claim: value}
            if claim != "exp":
                over["exp"] = n + 600
            tok = mint(_claims(**over), k1)
            st = status_of(base, tok)
            if time.time() < n + 1:  # decided within the same second: keep it
                break
        rows[name] = st
        ctx.eq(st, want, name)
    for name, over in (("iss-list", {"iss": [ISSUER]}), ("sub-number", {"sub": 12345}),
                       ("jti-number", {"jti": 7})):
        rows[name] = status_of(base, mint(_claims(**over), k1))
        ctx.eq(rows[name], 401, name)
    ctx.golden("statuses", rows)
