"""C-HTTP-1..10: the auth proxy's HTTP surface, in front of the echo upstream."""

from __future__ import annotations

import json
import socket
import time
from urllib.parse import urlsplit

import lib
from common import ISSUER, OPERATOR, PROXY_SECRET, token_claims
from lib import case
from rsa_jwt import mint

VOLATILE = {"date", "server", "content-length", "transfer-encoding", "connection", "keep-alive"}


def bearer(ctx, sub=OPERATOR, client_id="claude-connector", aud=None, key=None, **extra):
    tok = mint(token_claims(sub, client_id, aud, **extra), key or ctx.env.keys[0])
    return {"Authorization": f"Bearer {tok}"}


def machine_bearer(ctx, client_id, aud=("memory",), **extra):
    return bearer(ctx, client_id, client_id, list(aud) if aud is not None else None, **extra)


def stable_headers(resp):
    return sorted([k.lower(), v] for k, v in resp.headers if k.lower() not in VOLATILE)


@case("C-HTTP-1", "OPTIONS is 204 with the five CORS headers, no auth", "proxy")
def options(ctx):
    base = ctx.env.proxy()
    ctx.env.upstream.clear()
    out = {}
    for path in ("/mcp", "/sessions/v1/status", "/anything"):
        r = lib.request("OPTIONS", base + path)
        ctx.eq(r.status, 204, f"OPTIONS {path}")
        out[path] = stable_headers(r)
    ctx.eq(len({json.dumps(v) for v in out.values()}), 1, "same headers on every path")
    ctx.golden("headers", out["/mcp"])
    ctx.eq(len(ctx.env.upstream.taken(lambda r: r.method == "OPTIONS")), 0, "not forwarded")


@case("C-HTTP-2", "/health is {\"status\":\"ok\"} with CORS, no auth", "proxy")
def health(ctx):
    base = ctx.env.proxy()
    r = lib.request("GET", base + "/health")
    ctx.eq(r.status, 200, "status")
    ctx.eq(r.json(), {"status": "ok"}, "body")
    ctx.golden("response", {"status": r.status, "body": r.json(), "headers": stable_headers(r)})


@case("C-HTTP-3", "/.well-known/oauth-protected-resource fixed; other .well-known 404, not forwarded", "proxy")
def well_known(ctx):
    base = ctx.env.proxy()
    up = ctx.env.upstream
    up.clear()
    r = lib.request("GET", base + "/.well-known/oauth-protected-resource")
    ctx.eq(r.status, 200, "metadata status")
    body = r.json()
    ctx.eq(body["resource"], f"{ISSUER}/memory", "resource = issuer + PATH_PREFIX")
    rows = {"metadata": {"status": r.status, "body": body, "headers": stable_headers(r)}}
    for name, raw in (("openid-configuration", "/.well-known/openid-configuration"),
                      ("oauth-authorization-server", "/.well-known/oauth-authorization-server"),
                      ("dot-segment-escape", "/.well-known/../mcp"),
                      ("encoded-dot-segment", "/.well-known/%2e%2e/mcp")):
        x = lib.request("GET", base, raw_path=raw)
        rows[name] = {"status": x.status, "body": x.json() if x.body else None}
    ctx.golden("responses", rows)
    ctx.eq(len(up.taken()), 0, "nothing under .well-known reaches the upstream")


@case("C-HTTP-4", "401/403 JSON-RPC bodies and WWW-Authenticate", "proxy")
def auth_errors(ctx):
    base = ctx.env.proxy()
    up = ctx.env.upstream
    rows = {}
    probes = {
        "no-bearer": {},
        "basic-scheme": {"Authorization": "Basic dXNlcjpwYXNz"},
        "garbage-token": {"Authorization": "Bearer not-a-jwt"},
        "wrong-audience": machine_bearer(ctx, "memory-mirror", aud=("someone-else",)),
        "client-not-allowed": machine_bearer(ctx, "stranger-client"),
        "subject-not-allowed": bearer(ctx, sub="intruder@example.test"),
        "ok-human": bearer(ctx),
        "ok-machine": machine_bearer(ctx, "memory-mirror"),
    }
    for name, hdrs in probes.items():
        up.clear()
        r = lib.request("POST", base + "/mcp", headers={**hdrs, "Content-Type": "application/json"}, body={})
        rows[name] = {"status": r.status, "www_authenticate": r.header("www-authenticate"),
                      "body": r.json() if r.status != 200 else None,
                      "forwarded": len(up.taken())}
    ctx.golden("responses", rows)
    ctx.eq(rows["no-bearer"]["status"], 401, "no bearer")
    ctx.eq(rows["garbage-token"]["body"]["error"]["code"], -32001, "invalid token code")
    ctx.eq(rows["wrong-audience"]["body"]["error"]["code"], -32003, "forbidden code")
    ctx.eq([rows[k]["forwarded"] for k in probes], [0, 0, 0, 0, 0, 0, 1, 1], "only accepted requests forwarded")


@case("C-HTTP-5", "body limits: 1 MiB, 8 MiB under /sessions/v1/, chunked, escapes", "proxy")
def body_limits(ctx):
    base = ctx.env.proxy()
    auth = bearer(ctx)
    MiB = 1024 * 1024
    rows = {}
    probes = [
        ("mcp-1MiB", "/mcp", MiB, False),
        ("mcp-1MiB+1", "/mcp", MiB + 1, False),
        ("mcp-1MiB+1-chunked", "/mcp", MiB + 1, True),
        ("mcp-1MiB-chunked", "/mcp", MiB, True),
        ("sessions-8MiB", "/sessions/v1/ingest", 8 * MiB, False),
        ("sessions-8MiB+1", "/sessions/v1/ingest", 8 * MiB + 1, False),
        ("sessions-8MiB+1-chunked", "/sessions/v1/ingest", 8 * MiB + 1, True),
        ("sessions-percent-1MiB+1", "/sessions/v1/%69ngest", MiB + 1, False),
        ("sessions-dot-1MiB+1", "/sessions/v1/./ingest", MiB + 1, False),
        ("sessions-dotdot-1MiB+1", "/sessions/v1/../v1/ingest", MiB + 1, False),
        ("sessions-percent-2F-1MiB", "/sessions/v1%2Fingest", MiB, False),
    ]
    for name, path, size, chunked in probes:
        r = lib.request("POST", base, raw_path=path, headers={**auth, "Content-Type": "application/octet-stream"},
                        body=b"a" * size, chunked=chunked, timeout=60)
        rows[name] = {"status": r.status, "body": r.json() if r.status == 413 else None,
                      "upstream_body_len": r.json().get("body_len") if r.status == 200 else None}
    # Over the limit without a token is a 401, not a 413: limits apply after auth.
    r = lib.request("POST", base + "/mcp", body=b"a" * (MiB + 1))
    rows["unauthenticated-1MiB+1"] = {"status": r.status, "body": None, "upstream_body_len": None}
    ctx.golden("responses", rows)
    ctx.eq(rows["mcp-1MiB"]["status"], 200, "1 MiB passes")
    ctx.eq(rows["mcp-1MiB+1-chunked"]["status"], 413, "chunked over limit")
    ctx.eq(rows["sessions-8MiB+1"]["status"], 413, "8 MiB + 1")
    ctx.eq(rows["sessions-percent-1MiB+1"]["status"], 413, "percent escape gets 1 MiB")


@case("C-HTTP-6", "Content-Encoding: empty/identity allowed, others 415; upstream down 502", "proxy")
def content_encoding(ctx):
    base = ctx.env.proxy()
    auth = bearer(ctx)
    rows = {}
    for name, value in (("absent", None), ("empty", ""), ("identity", "identity"), ("IDENTITY", "IDENTITY"),
                        ("padded", " identity "), ("gzip", "gzip")):
        hdrs = {**auth, "Content-Type": "application/json"}
        if value is not None:
            hdrs["Content-Encoding"] = value
        r = lib.request("POST", base + "/mcp", headers=hdrs, body={"k": 1})
        rows[name] = {"status": r.status, "body": r.json_or_text() if r.status != 200 else None}
    # Upstream unreachable: a port nothing listens on.
    dead = ctx.env.proxy("proxy-dead-upstream", upstream=f"http://127.0.0.1:{lib.free_port()}/memory")
    r = lib.request("POST", dead + "/mcp", headers={**auth, "Content-Type": "application/json"}, body={})
    rows["upstream-down"] = {"status": r.status, "body": r.json()}
    ctx.env.stop("proxy-dead-upstream")
    ctx.golden("responses", rows)
    # Not compared: `br`. aiohttp refuses it with its own 400 before the handler
    # runs (no Brotli wheel), so the Python answer is not the proxy's rule
    # (contracts/specs/C-HTTP-6.md records the observation).
    ctx.eq([rows[k]["status"] for k in ("absent", "empty", "identity", "IDENTITY", "padded", "gzip")],
           [200, 200, 200, 200, 200, 415], "statuses")
    ctx.eq(rows["upstream-down"]["status"], 502, "upstream down")


@case("C-HTTP-7", "spoofed X-Verified-*/X-Proxy-Secret/forwarding headers replaced; Host not forwarded", "proxy")
def header_rewrite(ctx):
    base = ctx.env.proxy()
    spoof = {"X-Verified-Sub": "forged@example.test", "X-Verified-Grant": "authorization_code",
             "X-Verified-Client-Id": "forged", "x-verified-extra": "forged", "X-Proxy-Secret": "forged",
             "X-Forwarded-For": "203.0.113.9", "X-Forwarded-Host": "evil.example.test",
             "Forwarded": "for=203.0.113.9", "X-Forwarded-Proto": "wss", "Host": "evil.example.test",
             "X-Custom": "kept", "Connection": "keep-alive"}
    out = {}
    for name, hdrs in (("human", bearer(ctx)), ("machine", machine_bearer(ctx, "memory-mirror"))):
        r = lib.request("POST", base + "/mcp?x=1", headers={**hdrs, **spoof, "Content-Type": "application/json"},
                        body={"k": 1})
        ctx.eq(r.status, 200, f"{name} status")
        got = {k.lower(): v for k, v in r.json()["headers"]}
        # Headers the proxy's HTTP client adds on its own (aiohttp here) are not
        # part of the contract; the Rust client will add different ones.
        for k in ("content-length", "user-agent", "accept", "accept-encoding"):
            got.pop(k, None)
        if got.get("host", "").startswith("127.0.0.1:"):
            got["host"] = "<upstream host:port>"
        if got.get("x-proxy-secret") == PROXY_SECRET:
            got["x-proxy-secret"] = "<proxy secret>"
        out[name] = dict(sorted(got.items()))
    # https only when the front says exactly https
    r = lib.request("GET", base + "/mcp", headers={**bearer(ctx), "X-Forwarded-Proto": "https"})
    out["proto-https"] = {k.lower(): v for k, v in r.json()["headers"]}.get("x-forwarded-proto")
    ctx.golden("forwarded", out)
    h = out["human"]
    ctx.eq(h["x-verified-sub"], OPERATOR, "sub from token")
    ctx.eq(h["x-proxy-secret"], "<proxy secret>", "secret set by the proxy")
    ctx.check("authorization" not in h and "x-verified-extra" not in h and "forwarded" not in h,
              "dropped headers")


def _sse_events(base, path, headers, stop_after=None):
    parts = urlsplit(base)
    s = socket.create_connection((parts.hostname, parts.port), timeout=10)
    req = [f"GET {path} HTTP/1.1", f"Host: {parts.hostname}", "Accept: text/event-stream"]
    req += [f"{k}: {v}" for k, v in headers.items()]
    s.sendall(("\r\n".join(req) + "\r\n\r\n").encode())
    t0 = time.monotonic()
    arrivals = []
    buf = b""
    while True:
        chunk = s.recv(65536)
        if not chunk:
            break
        buf += chunk
        while b"data: " in buf:
            i = buf.index(b"data: ")
            j = buf.find(b"\n", i)
            if j < 0:
                break
            arrivals.append((round(time.monotonic() - t0, 2), buf[i + 6:j].decode()))
            buf = buf[j:]
        if stop_after and len(arrivals) >= stop_after:
            break
        if buf.endswith(b"0\r\n\r\n"):
            break
    return s, arrivals


@case("C-HTTP-8", "SSE is streamed chunk by chunk; client disconnect closes the upstream", "proxy")
def sse_stream(ctx):
    base = ctx.env.proxy()
    s, arrivals = _sse_events(base, "/mcp/sse", bearer(ctx))
    s.close()
    ctx.eq([a[1] for a in arrivals], ['{"n": 0}', '{"n": 1}', '{"n": 2}'], "three events in order")
    gaps = [b[0] - a[0] for a, b in zip(arrivals, arrivals[1:])]
    ctx.check(all(g >= 0.2 for g in gaps), f"events arrive as sent, not buffered (gaps {gaps})")
    up = ctx.env.upstream
    up.clear()
    s, arrivals = _sse_events(base, "/mcp/sse-forever", bearer(ctx), stop_after=2)
    s.shutdown(socket.SHUT_RDWR)
    s.close()
    t0 = time.monotonic()
    while not up.disconnects and time.monotonic() - t0 < 5:
        time.sleep(0.05)
    ctx.check(bool(up.disconnects), "upstream stream closed after the client went away")
    ctx.golden("stream", {"events": [a[1] for a in arrivals], "upstream_closed": bool(up.disconnects)})


PATHS = ["/mcp", "/mcp?", "/mcp?a=1&b=2", "/mcp?q=", "/mcp?=x", "/mcp/", "/mcp//double",
         "/mcp/%2F", "/mcp/a%20b", "/mcp/%E6%97%A5%E6%9C%AC", "/mcp?q=%E6%97%A5&r=a+b",
         "/sessions/v1/status?host=a", "/other/path", "/mcp;param=1"]


@case("C-HTTP-9", "/mcp and path_qs forwarded to UPSTREAM_URL + path_qs (14 patterns)", "proxy")
def path_forwarding(ctx):
    base = ctx.env.proxy()
    rows = {}
    for p in PATHS:
        r = lib.request("GET", base, raw_path=p, headers=bearer(ctx))
        rows[p] = {"status": r.status, "upstream_raw_path": r.json().get("raw_path") if r.status == 200 else None}
    ctx.golden("paths", rows)
    ctx.eq(rows["/mcp"]["upstream_raw_path"], "/memory/mcp", "prefix from UPSTREAM_URL")


@case("C-HTTP-10", "query strings never reach the proxy's log", "proxy")
def no_query_logging(ctx):
    base = ctx.env.proxy()
    sentinel = "SENTINEL-c8f2a1"
    lib.request("GET", base + f"/mcp?q={sentinel}", headers=bearer(ctx))
    lib.request("GET", base + f"/mcp?q={sentinel}")  # the unauthenticated branch logs too
    lib.request("GET", base + f"/sessions/v1/preview?q={sentinel}", headers=bearer(ctx))
    time.sleep(0.3)
    log = ctx.env.output("proxy")
    ctx.check(sentinel not in log, "sentinel absent from proxy stdout/stderr")
    ctx.check("/sessions/v1/preview" in log, "the path itself is logged (positive control)")
