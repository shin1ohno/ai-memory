#!/usr/bin/env python3
"""Auth proxy for OpenMemory MCP server.

Validates OIDC (Ory Hydra) OAuth tokens (RS256 via JWKS) and proxies authenticated
requests to the upstream openmemory-api service.
"""

import json
import logging
import os
import time
from urllib.request import urlopen

import jwt
import jwt.algorithms
from aiohttp import web, ClientSession, ClientTimeout

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(name)s %(levelname)s %(message)s",
)
logger = logging.getLogger("auth-proxy")

# ── OpenTelemetry tracing ──────────────────────────────────────────────
# Env-driven (OTEL_EXPORTER_OTLP_ENDPOINT / _CERTIFICATE / _HEADERS,
# OTEL_SERVICE_NAME, DEPLOYMENT_ENVIRONMENT). When OTLP endpoint is unset
# the BatchSpanProcessor still attaches, but its exporter silently no-ops —
# acceptable for local dev. Logs are NOT instrumented (only spans).

from opentelemetry import trace
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.instrumentation.aiohttp_server import AioHttpServerInstrumentor
from opentelemetry.instrumentation.aiohttp_client import AioHttpClientInstrumentor

_service_name = os.environ.get("OTEL_SERVICE_NAME", "ai-memory-auth-proxy")
_resource = Resource.create({
    "service.name": _service_name,
    "deployment.environment": os.environ.get("DEPLOYMENT_ENVIRONMENT", "home"),
})
_provider = TracerProvider(resource=_resource)
_provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter()))
trace.set_tracer_provider(_provider)

# Server instrumentation must be applied before web.Application() is built.
# Client instrumentation applies globally to all aiohttp ClientSession instances.
AioHttpServerInstrumentor().instrument()
AioHttpClientInstrumentor().instrument()

OIDC_ISSUER = os.environ.get("OIDC_ISSUER", "https://mcp.ohno.be")
OIDC_JWKS_URL = os.environ.get(
    "OIDC_JWKS_URL", "https://mcp.ohno.be/.well-known/jwks.json"
)
UPSTREAM_URL = os.environ.get("UPSTREAM_URL", "http://openmemory-api:8765")
PORT = int(os.environ.get("PORT", "8766"))
# Public path prefix used by the reverse proxy (e.g. "/memory")
PATH_PREFIX = os.environ.get("PATH_PREFIX", "")

# ── v2 identity enforcement config (env-gated) ─────────────────────────
# All three default to empty. When MEMORY_AUDIENCES is empty the enforcement
# matrix in handle() is INERT (the v1 memory units are unaffected) — only
# identity injection still runs. Comma-separated lists → sets of trimmed values.
MEMORY_AUDIENCES = {
    a.strip() for a in os.environ.get("MEMORY_AUDIENCES", "").split(",") if a.strip()
}
ALLOWED_SUBS = {
    s.strip() for s in os.environ.get("ALLOWED_SUBS", "").split(",") if s.strip()
}
ALLOWED_CLIENT_IDS = {
    c.strip() for c in os.environ.get("ALLOWED_CLIENT_IDS", "").split(",") if c.strip()
}

# Shared secret with the upstream server (identity.py require_proxy_secret).
# When set, every proxied request carries it as X-Proxy-Secret, so a local
# process that reaches the server's loopback port directly cannot forge the
# X-Verified-* headers. Empty = no header (the server's check is inert too).
PROXY_SHARED_SECRET = os.environ.get("PROXY_SHARED_SECRET", "")
HEADER_PROXY_SECRET = "X-Proxy-Secret"

# Request body limits (design spec §7.2 "Body limits"). 8 MiB only under the
# session search API, 1 MiB everywhere else. Enforced while reading, so a
# chunked body without Content-Length is cut off at the limit, and only ever
# after authentication. The path is the one this proxy receives (nginx strips
# the /memory location prefix).
BODY_LIMIT_DEFAULT = 1024 * 1024
BODY_LIMIT_SESSIONS = 8 * 1024 * 1024
SESSIONS_PATH_PREFIX = "/sessions/v1/"
BODY_READ_CHUNK = 64 * 1024


def body_limit(request) -> int:
    """8 MiB for /sessions/v1/..., 1 MiB otherwise. A path with a dot segment
    or a percent escape never gets the larger limit, whatever it decodes to."""
    raw = request.raw_path.split("?", 1)[0]
    if (raw.startswith(SESSIONS_PATH_PREFIX) and "%" not in raw
            and not any(seg in (".", "..") for seg in raw.split("/"))):
        return BODY_LIMIT_SESSIONS
    return BODY_LIMIT_DEFAULT


class BodyTooLarge(Exception):
    pass


async def read_body_bounded(request, limit: int) -> bytes:
    """The request body, or BodyTooLarge as soon as it exceeds `limit` (by the
    declared Content-Length or by the bytes actually received)."""
    if request.content_length is not None and request.content_length > limit:
        raise BodyTooLarge()
    buf = bytearray()
    async for chunk in request.content.iter_chunked(BODY_READ_CHUNK):
        buf += chunk
        if len(buf) > limit:
            raise BodyTooLarge()
    return bytes(buf)


# ── JWKS-based token verifier ──────────────────────────────────────────


class TokenVerifier:
    """Verifies RS256 JWTs using a remote JWKS endpoint."""

    def __init__(self, jwks_url: str, issuer: str, cache_ttl: int = 300):
        self._jwks_url = jwks_url
        self._issuer = issuer
        self._cache_ttl = cache_ttl
        self._keys: dict = {}
        self._fetched_at: float = 0

    def _fetch_keys(self) -> None:
        try:
            with urlopen(self._jwks_url, timeout=10) as resp:
                data = json.loads(resp.read())
            self._keys = {}
            for jwk_data in data.get("keys", []):
                kid = jwk_data.get("kid", "default")
                self._keys[kid] = jwt.algorithms.RSAAlgorithm.from_jwk(
                    json.dumps(jwk_data)
                )
            self._fetched_at = time.monotonic()
            logger.info("Fetched %d key(s) from JWKS", len(self._keys))
        except Exception:
            logger.exception("Failed to fetch JWKS from %s", self._jwks_url)

    def _ensure_keys(self, force: bool = False) -> None:
        expired = time.monotonic() - self._fetched_at > self._cache_ttl
        if force or not self._keys or expired:
            self._fetch_keys()

    def _pick_key(self, token: str):
        """Select the signing key for the token (by kid or first available)."""
        if not self._keys:
            return None
        try:
            header = jwt.get_unverified_header(token)
            kid = header.get("kid")
            if kid and kid in self._keys:
                return self._keys[kid]
        except Exception:
            pass
        return next(iter(self._keys.values()))

    def verify(self, token: str) -> dict | None:
        """Verify a JWT token. Retries with fresh JWKS on signature failure."""
        self._ensure_keys()
        key = self._pick_key(token)
        if key is None:
            return None
        try:
            return jwt.decode(
                token,
                key,
                algorithms=["RS256"],
                issuer=self._issuer,
                options={"verify_aud": False},
            )
        except jwt.InvalidSignatureError:
            self._ensure_keys(force=True)
            key = self._pick_key(token)
            if key is None:
                return None
            try:
                return jwt.decode(
                    token,
                    key,
                    algorithms=["RS256"],
                    issuer=self._issuer,
                    options={"verify_aud": False},
                )
            except Exception as exc:
                logger.warning("Token verify failed after JWKS refresh: %s", exc)
                return None
        except Exception as exc:
            logger.warning("Token verification failed: %s", exc)
            return None


verifier = TokenVerifier(OIDC_JWKS_URL, OIDC_ISSUER)


# ── CORS helpers ─────────────────────────────────────────────────────

CORS_HEADERS = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization, Accept",
    "Access-Control-Expose-Headers": "WWW-Authenticate",
    "Access-Control-Max-Age": "86400",
}


def add_cors(headers: dict) -> dict:
    """Merge CORS headers into response headers."""
    merged = dict(headers)
    merged.update(CORS_HEADERS)
    return merged


# ── Request handling ───────────────────────────────────────────────────

# Resource identifier — distinct from the issuer root to avoid MCP client confusion
RESOURCE_ID = f"{OIDC_ISSUER}{PATH_PREFIX}" if PATH_PREFIX else OIDC_ISSUER

WWW_AUTH = (
    f'Bearer resource_metadata="{RESOURCE_ID}/.well-known/oauth-protected-resource"'
)

HOP_BY_HOP = frozenset(
    ("host", "authorization", "transfer-encoding", "connection", "keep-alive")
)

# MCP uses JSON-RPC 2.0, whose error objects require a numeric `code`. Returning
# a plain {"error": "..."} body on 401 makes MCP clients reject the response
# with "code: Field required" before they can act on the WWW-Authenticate
# header, so 401s must ship a JSON-RPC 2.0 envelope.
JSONRPC_UNAUTHORIZED = -32001
# 403 identity-enforcement rejections (v2 audience/subject matrix). Distinct
# code so MCP clients can tell "not authenticated" (-32001) from "authenticated
# but not permitted for this resource" (-32003).
JSONRPC_FORBIDDEN = -32003


def jsonrpc_error(code: int, message: str, status: int, headers: dict) -> web.Response:
    return web.json_response(
        {"jsonrpc": "2.0", "id": None, "error": {"code": code, "message": message}},
        status=status,
        headers=headers,
    )


async def handle(request: web.Request) -> web.StreamResponse:
    logger.info("%s %s", request.method, request.path)

    # ── CORS preflight — no auth required ──
    if request.method == "OPTIONS":
        return web.Response(status=204, headers=CORS_HEADERS)

    # ── Health endpoint — no auth required ──
    if request.path == "/health":
        return web.json_response({"status": "ok"}, headers=CORS_HEADERS)

    # ── .well-known — no auth required (MCP/OAuth discovery) ──
    if request.path.startswith("/.well-known/"):
        if request.path == "/.well-known/oauth-protected-resource":
            return web.json_response(
                {
                    "resource": RESOURCE_ID,
                    "authorization_servers": [OIDC_ISSUER],
                    "scopes_supported": ["mcp:read", "mcp:write", "mcp:admin"],
                    "bearer_methods_supported": ["header"],
                },
                headers=add_cors({"Cache-Control": "public, max-age=3600"}),
            )
        # Proxy other .well-known paths to upstream without auth
        session: ClientSession = request.app["http_client"]
        url = f"{UPSTREAM_URL}{request.path_qs}"
        upstream = await session.request("GET", url, timeout=ClientTimeout(total=10))
        content = await upstream.read()
        await upstream.release()
        return web.Response(
            body=content,
            status=upstream.status,
            content_type=upstream.headers.get("Content-Type", "application/json"),
            headers=CORS_HEADERS,
        )

    # ── Authenticate ──
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        logger.info("No Bearer token for %s %s", request.method, request.path)
        return jsonrpc_error(
            JSONRPC_UNAUTHORIZED,
            "unauthorized",
            401,
            add_cors({"WWW-Authenticate": WWW_AUTH}),
        )

    claims = verifier.verify(auth[7:])
    if claims is None:
        logger.warning("Invalid token for %s %s", request.method, request.path)
        return jsonrpc_error(
            JSONRPC_UNAUTHORIZED,
            "invalid_token",
            401,
            add_cors({
                "WWW-Authenticate": (
                    f'Bearer error="invalid_token",'
                    f' resource_metadata="{RESOURCE_ID}'
                    f'/.well-known/oauth-protected-resource"'
                )
            }),
        )

    logger.info("Authenticated %s %s (sub=%s)", request.method, request.path, claims.get("sub", "?"))

    # ── v2 identity enforcement + injection (env-gated) ────────────────────
    # Grant classification (per contract §3):
    #   client_credentials  ⟺  sub == client_id   (machine token, e.g. keeper)
    #   authorization_code  ⟺  sub != client_id   (human; sub = Google email)
    # `grant` is computed UNCONDITIONALLY so the X-Verified-* headers flow to
    # upstream even in staging where MEMORY_AUDIENCES is unset (no enforcement).
    #
    # Enforcement matrix — applied ONLY when MEMORY_AUDIENCES is non-empty:
    #   client_credentials → require (aud ∩ MEMORY_AUDIENCES) AND
    #                        client_id ∈ ALLOWED_CLIENT_IDS  else 403 forbidden_audience
    #   authorization_code → require sub ∈ ALLOWED_SUBS       else 403 forbidden_subject
    # claude.ai tokens carry aud=[] → aud is NOT required for authorization_code.
    # `aud` may be a str or a list → normalized to a list before the set test.
    sub = claims.get("sub", "")
    client_id = claims.get("client_id", "")
    grant = "client_credentials" if sub == client_id else "authorization_code"

    if MEMORY_AUDIENCES:
        raw_aud = claims.get("aud", [])
        aud = [raw_aud] if isinstance(raw_aud, str) else list(raw_aud or [])
        if grant == "client_credentials":
            if not (set(aud) & MEMORY_AUDIENCES) or client_id not in ALLOWED_CLIENT_IDS:
                logger.warning(
                    "forbidden_audience: client_id=%s aud=%s for %s %s",
                    client_id, aud, request.method, request.path,
                )
                return jsonrpc_error(
                    JSONRPC_FORBIDDEN, "forbidden_audience", 403, add_cors({})
                )
        else:  # authorization_code
            if sub not in ALLOWED_SUBS:
                logger.warning(
                    "forbidden_subject: sub=%s for %s %s",
                    sub, request.method, request.path,
                )
                return jsonrpc_error(
                    JSONRPC_FORBIDDEN, "forbidden_subject", 403, add_cors({})
                )

    # ── Proxy to upstream ──
    url = f"{UPSTREAM_URL}{request.path_qs}"
    # Strip any inbound X-Verified-* headers (spoof defense) before injecting our
    # own — the proxy is the only trusted source of these identity headers.
    # X-Proxy-Secret is stripped the same way: only this proxy may set it.
    fwd_headers = {
        k: v
        for k, v in request.headers.items()
        if k.lower() not in HOP_BY_HOP
        and not k.lower().startswith("x-verified-")
        and k.lower() != HEADER_PROXY_SECRET.lower()
    }
    fwd_headers["X-Verified-Sub"] = sub
    fwd_headers["X-Verified-Client-Id"] = client_id
    fwd_headers["X-Verified-Grant"] = grant
    if PROXY_SHARED_SECRET:
        fwd_headers[HEADER_PROXY_SECRET] = PROXY_SHARED_SECRET

    session = request.app["http_client"]
    body = None
    # aiohttp decompresses an encoded request body on read while the client's
    # Content-Length still counts the compressed bytes, so a forwarded
    # Content-Encoding request stalls instead of failing. No caller needs it
    # (the session-search client sends gzip without the header and the server
    # recognises it by magic bytes), so refuse it up front on every path.
    ce = request.headers.get("Content-Encoding", "").strip().lower()
    if ce and ce != "identity":
        logger.warning("Refusing request Content-Encoding %r for %s %s", ce, request.method, request.path)
        return web.json_response({"error": "unsupported_content_encoding"}, status=415, headers=CORS_HEADERS)
    if request.can_read_body:
        limit = body_limit(request)
        try:
            body = await read_body_bounded(request, limit)
        except BodyTooLarge:
            logger.warning("Body over %d bytes for %s %s", limit, request.method, request.path)
            return web.json_response({"error": "too_large"}, status=413, headers=CORS_HEADERS)
        # The body is forwarded as bytes, so the client's Content-Length (absent
        # on a chunked request) must not travel with it; aiohttp sets its own.
        fwd_headers = {k: v for k, v in fwd_headers.items() if k.lower() != "content-length"}

    try:
        upstream = await session.request(
            request.method,
            url,
            headers=fwd_headers,
            data=body,
            timeout=ClientTimeout(total=300, connect=10),
        )
    except Exception as exc:
        logger.error("Upstream request failed: %s", exc)
        return jsonrpc_error(
            -32000,
            "upstream_error",
            502,
            CORS_HEADERS,
        )

    ct = upstream.headers.get("Content-Type", "")
    resp_headers = {
        k: v for k, v in upstream.headers.items() if k.lower() not in HOP_BY_HOP
    }
    resp_headers = add_cors(resp_headers)

    logger.info("Upstream responded %d (%s) for %s %s", upstream.status, ct, request.method, request.path)

    # Streaming response (MCP Streamable HTTP returns chunked SSE for long-running
    # tool calls, application/json for single-RPC responses — handle both transparently).
    if "text/event-stream" in ct:
        response = web.StreamResponse(status=upstream.status, headers=resp_headers)
        await response.prepare(request)
        try:
            async for chunk in upstream.content.iter_any():
                if request.transport is None or request.transport.is_closing():
                    logger.info("Downstream transport closing for %s", request.path)
                    break
                await response.write(chunk)
        except ConnectionResetError:
            logger.info("Client disconnected for %s", request.path)
        except Exception as exc:
            logger.warning("Stream error: %s", exc)
        finally:
            upstream.close()
        return response

    # Regular responses
    content = await upstream.read()
    await upstream.release()
    # No response-body logging: on /sessions/v1/ the body is transcript text
    # (design spec §8 row 22). The status line above is the whole record.
    return web.Response(body=content, status=upstream.status, headers=resp_headers)


# ── App lifecycle ──────────────────────────────────────────────────────


async def on_startup(app: web.Application) -> None:
    app["http_client"] = ClientSession()
    logger.info("Auth proxy started (prefix=%s, upstream=%s)", PATH_PREFIX, UPSTREAM_URL)


async def on_cleanup(app: web.Application) -> None:
    await app["http_client"].close()


app = web.Application()
app.on_startup.append(on_startup)
app.on_cleanup.append(on_cleanup)
app.router.add_route("*", "/{path_info:.*}", handle)

if __name__ == "__main__":
    web.run_app(app, host="0.0.0.0", port=PORT)
