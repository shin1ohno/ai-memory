"""Identity + server-side destructive-op authorization for memory-mcp v2.

The auth-proxy (contract §3) validates the OIDC-JWT, strips any inbound
`x-verified-*` spoofs, and injects three verified headers:

    X-Verified-Sub        the token `sub` (email for authorization_code)
    X-Verified-Client-Id  the token `client_id`
    X-Verified-Grant      "authorization_code" | "client_credentials"

Provenance is stamped server-side FROM these headers (never from tool args), so
a caller cannot forge which agent wrote a memory. This module holds the pure
authz matrix + a stderr/journald audit line. It intentionally imports no
Starlette so it stays importable anywhere (es_backend imports authorize_supersede).

It also holds the per-client tool policy (CLIENT_POLICY, bottom of the file):
which tools and datasets a client_credentials caller may use. The gate that
applies it to every tools/call lives in policy_mcp.PolicyFastMCP.
"""

from __future__ import annotations

import hmac
import os
import re
import sys
import time

HEADER_SUB = "x-verified-sub"
HEADER_CLIENT_ID = "x-verified-client-id"
HEADER_GRANT = "x-verified-grant"

GRANT_AUTHZ_CODE = "authorization_code"
GRANT_CLIENT_CREDS = "client_credentials"


HEADER_PROXY_SECRET = "x-proxy-secret"

# Env-gated shared secret between the auth proxy and this server. UNSET = inert,
# so existing deployments are unaffected.
#
# WHY THIS EXISTS. Everything below trusts the x-verified-* headers completely:
# they decide write provenance, and they decide who may forget or revise a
# document. The only thing stopping a caller from writing them itself is that the
# server listens on loopback and the proxy is the sole reachable listener. On a
# single-purpose host that is enough. On a host that also runs autonomous coding
# agents it is not: any local process can reach loopback, and forging
# `x-verified-grant: authorization_code` there buys the ability to fabricate a
# `user-stated` fact -- which the recall tool explicitly tells the model it may
# treat as instruction rather than data. That turns a local write into prompt
# injection with elevated trust.
#
# With this set, forging an identity additionally requires reading the server's
# environment file, which is the same bar as reading its ES credential.
_PROXY_SHARED_SECRET = os.environ.get("PROXY_SHARED_SECRET", "")


class AuthzError(Exception):
    """Raised when a caller is not permitted to supersede/revise a target doc."""


class ProxyAuthError(Exception):
    """Raised when PROXY_SHARED_SECRET is configured and the request did not come
    through the proxy that holds it."""


def _now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _get_header(headers, name: str) -> str:
    """Case-insensitive header lookup tolerant of Starlette Headers or a plain
    dict. Returns "" when absent (or when headers is None)."""
    if headers is None:
        return ""
    # Starlette Headers.get is already case-insensitive; try common casings for
    # a plain dict, then fall back to a full scan.
    try:
        val = headers.get(name)
        if val is None:
            val = headers.get(name.title())
        if val is None:
            for k, v in headers.items():
                if str(k).lower() == name:
                    return v or ""
        return val or ""
    except AttributeError:
        return ""


def require_proxy_secret(headers) -> None:
    """Reject anything that did not come through the trusted proxy.

    No-op unless PROXY_SHARED_SECRET is set, so this is opt-in per deployment.
    Constant-time compare: the value is a fixed secret checked on every request,
    which is exactly the shape a timing oracle needs."""
    if not _PROXY_SHARED_SECRET:
        return
    got = _get_header(headers, HEADER_PROXY_SECRET)
    # Compared as bytes: compare_digest raises TypeError on a non-ASCII str, which
    # would surface as a 500 instead of a clean rejection for a hostile header.
    if not got or not hmac.compare_digest(
        got.encode("utf-8", "surrogateescape"),
        _PROXY_SHARED_SECRET.encode("utf-8", "surrogateescape"),
    ):
        print("AUDIT proxy_secret_rejected", file=sys.stderr, flush=True)
        raise ProxyAuthError("request did not come through the auth proxy")


def parse_identity(headers) -> dict:
    """Read the three verified headers and derive the provenance agent.

    provenance.agent = client_id (client_credentials) or sub (authorization_code),
    per contract §3. Never sourced from tool arguments.

    Gated on require_proxy_secret: this is the single chokepoint every request
    passes through before an identity exists, so enforcing here means no code path
    can derive provenance from headers that bypassed the proxy.
    """
    require_proxy_secret(headers)
    sub = _get_header(headers, HEADER_SUB)
    client_id = _get_header(headers, HEADER_CLIENT_ID)
    grant = _get_header(headers, HEADER_GRANT)
    if grant == GRANT_CLIENT_CREDS:
        agent = client_id or "unknown-client"
    else:
        agent = sub or "unknown-user"
    return {"sub": sub, "client_id": client_id, "grant": grant, "agent": agent}


def build_provenance(ident: dict, session_id: str = "", source_class: str = "tool-output") -> dict:
    """Build the provenance sub-document stamped server-side from `parse_identity`
    output. source_class ∈ {user-stated, tool-output, reflection, auto-capture,
    migration, promoted}."""
    return {
        "agent": ident.get("agent", "unknown"),
        "session_id": session_id or "",
        "source_class": source_class,
        "written_at": _now_iso(),
    }


def authorize_supersede(grant: str, agent: str, target_source_class, target_agent) -> bool:
    """Destructive-op authorization matrix (contract §3).

    - target source_class == "user-stated": only interactive (authorization_code)
      tokens may forget/revise it.
    - authorization_code: may forget/revise anything.
    - client_credentials: may forget/revise ONLY docs whose provenance.agent
      matches its own verified client id.
    - anything else: deny.
    """
    if target_source_class == "user-stated":
        return grant == GRANT_AUTHZ_CODE
    if grant == GRANT_AUTHZ_CODE:
        return True
    if grant == GRANT_CLIENT_CREDS:
        return bool(agent) and agent == target_agent
    return False


def audit_supersede(target_id, agent: str, grant: str) -> None:
    """Emit an audit line for every supersede/revise (contract §3). Goes to
    stderr, which the systemd unit routes to journald."""
    print(f"AUDIT supersede id={target_id} by={agent} grant={grant}",
          file=sys.stderr, flush=True)


# --------------------------------------------------------------------------- #
# Per-client tool policy (CLIENT_POLICY)
# --------------------------------------------------------------------------- #
# The proxy decides WHO may reach this server (ALLOWED_CLIENT_IDS); this decides
# WHAT a machine client may do once here. Without it every client_credentials
# token could call every tool, so a leaked mirror credential would read and
# write the whole store. authorization_code (the claude.ai connector) is not
# subject to it.
#
# Format, set in memory-mcp-v2.service (NOT the SSM-generated .env, whose
# regeneration guard only looks at VOYAGE_API_KEY):
#
#     client=tool,tool@dataset|dataset;client=
#
# `client=` with no tools means "known, may call nothing". Once the variable is
# set, the gate is fail-closed throughout: a malformed policy, a client that is
# not listed, and a missing or unrecognised grant header all deny every call
# rather than guessing. Set to the empty string it is an empty policy (every
# client_credentials call denied).
#
# UNSET is different: the gate is off and every call behaves as it did before
# the policy existed, announced by an `AUDIT policy_unset` startup line. This
# server code is shared with deployments whose units predate the policy (the
# work store); enforcing an absent policy there would deny every machine call,
# reads included, on their next deploy. CT119's unit sets it, and
# test_client_policy.py fails if that line goes missing.
CLIENT_POLICY_ENV = "CLIENT_POLICY"

# The only tools a policy may grant: the ones whose dataset scope is actually
# enforced — ingest by its `dataset` argument here, forget by that argument
# here and by the resolved document's dataset in es_backend.supersede. recall
# and browse take a dataset only inside `filters`, get and revise take a bare
# id, memory_stats is store-wide; granting any of them `@file-memory` would log
# a scope the gate does not enforce, so the parser refuses them. Extend this
# set only together with real dataset scoping for the added tool.
DATASET_SCOPED_TOOLS = frozenset({"ingest", "forget"})

# Every policy refusal carries exactly this text. The caller learns that it was
# refused, not which constraint refused it; the reason stays server-side.
POLICY_DENIED_MESSAGE = "policy_denied: this client is not permitted to make this call"

# Longest `ingest` document a client_credentials caller may send, in characters.
# Bounds the size — and the Voyage embedding spend — of any single write a leaked
# machine token can make. The file-memory mirror hook skips notes over the same
# limit with a WARN, so the two sides must change together.
#
# This is the whole effective limit: a restricted ingest never takes the
# background-job path (server.ingest passes background=False whenever
# allowed_datasets is not None), because a failed job is visible only through
# memory_stats, which no restricted client is granted — the caller would be
# told nothing while the note never landed. Synchronous, the result is always
# {doc_id, chunk_count} or a tool error. 45000 characters chunk to at most 84
# chunks (worst case measured against chunk_text's 1200/150 windows), one
# Voyage batch (voyage.BATCH_MAX = 128), so the request stays one embed call.
RESTRICTED_INGEST_MAX_CHARS = 45000

_CLIENT_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")
_TOOL_RE = re.compile(r"[a-z_][a-z0-9_]*")
_DATASET_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")

_DENY = (False, POLICY_DENIED_MESSAGE)
_ACTIVE = object()  # sentinel: "use the policy loaded from the environment"


class _PolicyUnset:
    def __repr__(self) -> str:
        return "POLICY_UNSET"


# The loaded policy when CLIENT_POLICY is not in the environment at all: the
# gate is off (see the note on CLIENT_POLICY_ENV). Distinct from None (set but
# invalid: deny every client_credentials call) and {} (set but empty: same).
POLICY_UNSET = _PolicyUnset()


class PolicyError(ValueError):
    """CLIENT_POLICY is malformed."""


def _split_tokens(part: str, sep: str, pattern, kind: str, client: str) -> tuple:
    tokens = part.split(sep)
    for tok in tokens:
        if not pattern.fullmatch(tok):
            raise PolicyError(f"client {client}: invalid {kind} {tok!r}")
    if len(set(tokens)) != len(tokens):
        raise PolicyError(f"client {client}: duplicate {kind}")
    return tuple(tokens)


def parse_client_policy(spec: str) -> dict:
    """Parse a CLIENT_POLICY value strictly.

    Grammar (no whitespace anywhere; `;` separates entries):

        entry    := client "=" [tools ["@" datasets]]
        tools    := tool ("," tool)*
        datasets := dataset ("|" dataset)*

    A tool list without `@datasets` grants no dataset, so any call that names
    one is refused. Only DATASET_SCOPED_TOOLS may be granted. The empty string
    is an empty policy (no machine client may do anything). Anything else that
    does not match — including a duplicate client, tool or dataset, a tool
    outside DATASET_SCOPED_TOOLS, and an empty entry from a stray `;` — raises
    PolicyError, so a typo can only ever narrow what a client may do.

    Returns {client_id: {"tools": tuple, "datasets": tuple}}.
    """
    if spec == "":
        return {}
    policy: dict = {}
    for entry in spec.split(";"):
        client, eq, rest = entry.partition("=")
        if not eq:
            raise PolicyError(f"entry {entry!r}: missing '='")
        if not _CLIENT_ID_RE.fullmatch(client):
            raise PolicyError(f"entry {entry!r}: invalid client id")
        if client in policy:
            raise PolicyError(f"client {client}: listed twice")
        tools_part, at, datasets_part = rest.partition("@")
        tools = _split_tokens(tools_part, ",", _TOOL_RE, "tool", client) if tools_part else ()
        unscoped = sorted(set(tools) - DATASET_SCOPED_TOOLS)
        if unscoped:
            raise PolicyError(
                f"client {client}: tool(s) {','.join(unscoped)} are not dataset-scoped"
                f" (grantable: {','.join(sorted(DATASET_SCOPED_TOOLS))})")
        datasets: tuple = ()
        if at:
            if not tools:
                raise PolicyError(f"client {client}: datasets without tools")
            datasets = _split_tokens(datasets_part, "|", _DATASET_RE, "dataset", client)
        policy[client] = {"tools": tools, "datasets": datasets}
    return policy


def _load_client_policy(spec):
    """(policy, error) for the raw environment value. spec None (not set) =
    POLICY_UNSET, the gate is off; policy None = invalid, which denies every
    client_credentials call."""
    if spec is None:
        return POLICY_UNSET, ""
    try:
        return parse_client_policy(spec), ""
    except PolicyError as exc:
        return None, str(exc)


_CLIENT_POLICY, _CLIENT_POLICY_ERROR = _load_client_policy(
    os.environ.get(CLIENT_POLICY_ENV))


def unknown_policy_tools(policy, registered) -> list:
    """Tool names the policy grants that the server does not register — a tool
    renamed or removed under a policy that still grants it. check_client_policy
    treats that as an invalid policy rather than a silent partial denial."""
    if not isinstance(policy, dict):
        return []
    granted = {t for entry in policy.values() for t in entry["tools"]}
    return sorted(granted - set(registered))


def policy_lines(policy, error: str = "") -> list:
    """The startup lines describing the effective policy (journald)."""
    if policy is POLICY_UNSET:
        return [f"AUDIT policy_unset {CLIENT_POLICY_ENV} is not set: the per-client"
                " tool gate is OFF and every client_credentials call is allowed"]
    if policy is None:
        return [f"AUDIT policy_invalid reason={error or 'unknown'} "
                "client_credentials=deny-all"]
    if not policy:
        return ["POLICY (none): every client_credentials call is denied"]
    return [
        f"POLICY {client} -> {','.join(entry['tools']) or '(none)'}"
        f" @ {'|'.join(entry['datasets']) or '(none)'}"
        for client, entry in policy.items()
    ]


def check_client_policy(registered_tools) -> None:
    """Validate the loaded policy against the server's registered tool names and
    log the effective policy. Called once at server startup."""
    global _CLIENT_POLICY, _CLIENT_POLICY_ERROR
    unknown = unknown_policy_tools(_CLIENT_POLICY, registered_tools)
    if unknown:
        _CLIENT_POLICY = None
        _CLIENT_POLICY_ERROR = f"unknown tool(s) {','.join(unknown)}"
    for line in policy_lines(_CLIENT_POLICY, _CLIENT_POLICY_ERROR):
        print(line, file=sys.stderr, flush=True)


def _effective_policy(policy):
    return _CLIENT_POLICY if policy is _ACTIVE else policy


def _policy_entry(ident: dict, pol):
    """The entry of a resolved policy governing a client_credentials identity,
    or None."""
    if not isinstance(pol, dict):
        return None
    return pol.get((ident or {}).get("client_id") or "")


def _dataset_allowed(dataset, allowed) -> bool:
    # Exact str match only: a list, a number or a JSON-encoded string is not a
    # dataset name, whatever pydantic would later coerce it into.
    return isinstance(dataset, str) and dataset in allowed


def authorize_tool(ident: dict, name, arguments, policy=_ACTIVE) -> tuple:
    """Pure policy decision for one tools/call. Returns (ok, reason); reason is
    POLICY_DENIED_MESSAGE on refusal, "" otherwise.

    - authorization_code: always allowed (the interactive connector).
    - client_credentials: the client must be listed, the tool granted, and:
        * no `tags` (a restricted caller may not set or clear routing keys);
        * any `dataset` argument must be one of its datasets;
        * `ingest` must name an allowed dataset and send a str document of at
          most RESTRICTED_INGEST_MAX_CHARS characters.
      forget-by-id is scoped in es_backend.supersede (allowed_datasets), where
      the target document's dataset is known.
    - any other grant value, including a missing header: denied.
    - CLIENT_POLICY not set at all (POLICY_UNSET): every call allowed, as
      before the policy existed.

    `arguments` is the raw JSON object from the request, before FastMCP's
    pydantic coercion, so the checks see exactly what the client sent.
    """
    pol = _effective_policy(policy)
    if pol is POLICY_UNSET:
        return True, ""
    grant = (ident or {}).get("grant", "")
    if grant == GRANT_AUTHZ_CODE:
        return True, ""
    if grant != GRANT_CLIENT_CREDS:
        return _DENY
    entry = _policy_entry(ident, pol)
    if entry is None:
        return _DENY
    if not isinstance(name, str) or name not in entry["tools"]:
        return _DENY
    args = {} if arguments is None else arguments
    if not isinstance(args, dict):
        return _DENY
    if args.get("tags") is not None:
        return _DENY
    if args.get("dataset") is not None and not _dataset_allowed(args["dataset"], entry["datasets"]):
        return _DENY
    if name == "ingest":
        if not _dataset_allowed(args.get("dataset"), entry["datasets"]):
            return _DENY
        document = args.get("document")
        if not isinstance(document, str) or len(document) > RESTRICTED_INGEST_MAX_CHARS:
            return _DENY
    return True, ""


def allowed_datasets(ident: dict, policy=_ACTIVE):
    """Datasets a caller may touch: None = unrestricted (authorization_code, or
    CLIENT_POLICY not set), otherwise a frozenset — empty for anyone the policy
    does not grant. Not None also means "restricted caller" to server.ingest,
    which then keeps the ingest synchronous."""
    pol = _effective_policy(policy)
    if pol is POLICY_UNSET:
        return None
    grant = (ident or {}).get("grant", "")
    if grant == GRANT_AUTHZ_CODE:
        return None
    if grant != GRANT_CLIENT_CREDS:
        return frozenset()
    entry = _policy_entry(ident, pol)
    return frozenset(entry["datasets"]) if entry else frozenset()


_AUDIT_TOKEN_RE = re.compile(r"[^A-Za-z0-9._@:/-]")


def _audit_token(value) -> str:
    """Render a client-controlled value safely on one log line: no whitespace or
    control characters (no forged extra lines), bounded length, and only the
    TYPE of a non-string."""
    if value is None or value == "":
        return "-"
    if not isinstance(value, str):
        return f"<{type(value).__name__}>"
    token = _AUDIT_TOKEN_RE.sub("?", value)
    return token if len(token) <= 64 else token[:64] + "..."


def audit_policy_deny(tool, client, dataset) -> None:
    """One line per policy refusal. Carries the tool, the client and the
    dataset only — never the arguments, which may hold the document itself."""
    print(f"AUDIT deny tool={_audit_token(tool)} client={_audit_token(client)}"
          f" dataset={_audit_token(dataset)}", file=sys.stderr, flush=True)


# --------------------------------------------------------------------------- #
# Session-search scope policy (SESSION_SCOPE_POLICY, design spec §7.6)
# --------------------------------------------------------------------------- #
# The /memory/sessions/v1 sub-app has its own default-deny gate. CLIENT_POLICY
# is deliberately NOT extended for it: that parser refuses any tool outside
# DATASET_SCOPED_TOOLS, and an unknown tool voids the whole policy, which would
# lock memory-mirror out of the MCP server.
#
# Value: JSON {"rules": [{"match": {...}, "host": str|null, "scopes": [...]}]}.
# `match` keys are optional individually (grant, client_id, sub) and ANDed; an
# empty match is refused because it would hand its scopes to every identity,
# memory-mirror included. The FIRST matching rule decides; no match = deny.
# `host: null` = the identity owns no host (read/purge only; every write that
# needs a host is 403). Unset, empty, or malformed in any way = deny-all: a
# typo can only ever narrow what a caller may do.
SESSION_SCOPE_POLICY_ENV = "SESSION_SCOPE_POLICY"
SESSION_SCOPES = frozenset({"sessions:ingest", "sessions:read", "sessions:purge"})
_SESSION_MATCH_KEYS = frozenset({"grant", "client_id", "sub"})
_SESSION_HOST_RE = re.compile(r"^[a-z0-9-]{1,63}$")
_KNOWN_GRANTS = frozenset({GRANT_AUTHZ_CODE, GRANT_CLIENT_CREDS})


class SessionPolicyError(ValueError):
    """SESSION_SCOPE_POLICY is malformed."""


def parse_session_scope_policy(spec: str) -> tuple:
    """Parse strictly. Returns a tuple of {"match": dict, "host": str|None,
    "scopes": frozenset}. Raises SessionPolicyError on anything unexpected."""
    import json  # noqa: PLC0415 — keeps identity's module-level imports unchanged

    try:
        data = json.loads(spec)
    except (TypeError, ValueError) as exc:
        raise SessionPolicyError(f"not JSON: {exc.__class__.__name__}") from None
    if not isinstance(data, dict) or set(data) != {"rules"} or not isinstance(data["rules"], list):
        raise SessionPolicyError('top level must be exactly {"rules": [...]}')
    rules = []
    for i, r in enumerate(data["rules"]):
        if not isinstance(r, dict) or set(r) != {"match", "host", "scopes"}:
            raise SessionPolicyError(f"rule {i}: keys must be exactly match, host, scopes")
        m = r["match"]
        if not isinstance(m, dict) or not m or not set(m) <= _SESSION_MATCH_KEYS:
            raise SessionPolicyError(f"rule {i}: match must be a non-empty object over grant/client_id/sub")
        for k, v in m.items():
            if not isinstance(v, str) or not v:
                raise SessionPolicyError(f"rule {i}: match.{k} must be a non-empty string")
        if "grant" in m and m["grant"] not in _KNOWN_GRANTS:
            raise SessionPolicyError(f"rule {i}: unknown grant")
        host = r["host"]
        if host is not None and (not isinstance(host, str) or not _SESSION_HOST_RE.fullmatch(host)):
            raise SessionPolicyError(f"rule {i}: invalid host")
        scopes = r["scopes"]
        if (not isinstance(scopes, list) or not all(isinstance(s, str) for s in scopes)
                or len(set(scopes)) != len(scopes) or not set(scopes) <= SESSION_SCOPES):
            raise SessionPolicyError(f"rule {i}: scopes must be distinct values of {sorted(SESSION_SCOPES)}")
        rules.append({"match": dict(m), "host": host, "scopes": frozenset(scopes)})
    return tuple(rules)


def _load_session_scope_policy(spec):
    """(rules, error). rules None = deny-all (unset, empty or malformed)."""
    if spec is None or spec == "":
        return None, "unset"
    try:
        return parse_session_scope_policy(spec), ""
    except SessionPolicyError as exc:
        return None, str(exc)


_SESSION_SCOPE_POLICY, _SESSION_SCOPE_POLICY_ERROR = _load_session_scope_policy(
    os.environ.get(SESSION_SCOPE_POLICY_ENV))


def _session_rule_matches(match: dict, ident: dict) -> bool:
    return all((ident or {}).get(k, "") == v for k, v in match.items())


def authorize_session_scope(ident: dict, scope: str, policy=_ACTIVE) -> tuple:
    """(allowed, host) for one sessions route. The first rule whose match fits
    the verified identity decides; its host is the caller's host (None for a
    host-less identity). No matching rule, an unknown grant, an unknown scope,
    or an unusable policy = (False, None)."""
    rules = _SESSION_SCOPE_POLICY if policy is _ACTIVE else policy
    if not isinstance(rules, tuple) or scope not in SESSION_SCOPES:
        return False, None
    if (ident or {}).get("grant", "") not in _KNOWN_GRANTS:
        return False, None
    for r in rules:
        if _session_rule_matches(r["match"], ident):
            if scope in r["scopes"]:
                return True, r["host"]
            return False, None
    return False, None


def session_scope_policy_lines(policy=_ACTIVE, error=None) -> list:
    """Startup lines for journald. Deliberately avoids the `POLICY ` token the
    CLIENT_POLICY lines use, so tooling that counts those is unaffected."""
    rules = _SESSION_SCOPE_POLICY if policy is _ACTIVE else policy
    err = _SESSION_SCOPE_POLICY_ERROR if error is None else error
    if not isinstance(rules, tuple):
        return [f"SESSIONS scope-policy deny-all reason={_audit_token(err or 'unknown')}"]
    return [f"SESSIONS scope-rule {i} match={','.join(sorted(r['match']))}"
            f" host={r['host'] or '-'} scopes={','.join(sorted(r['scopes'])) or '-'}"
            for i, r in enumerate(rules)] or ["SESSIONS scope-policy (no rules): deny-all"]


def proxy_secret_configured() -> bool:
    """The sessions gate refuses every request unless the proxy shared secret is
    set: without it any local process could forge the identity headers."""
    return bool(_PROXY_SHARED_SECRET)
