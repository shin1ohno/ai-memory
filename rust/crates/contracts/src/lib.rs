//! The external contracts of ai-memory as Rust values.
//!
//! Every item here restates a value or rule from `contracts/specs/<ID>.md`, which in turn
//! points at the Python implementation it was read from. Nothing in this crate does I/O; the
//! services (auth-proxy, server, session-maint) take their constants and pure decisions from
//! here so that one place answers "what did we promise".
//!
//! The tests at the bottom compare these values with the language-independent artifacts in
//! `contracts/` (`constants.json`, `mcp-tools.json`) and with the tables the round-trip suite
//! runs against the Python implementation, so a drift on either side fails `cargo test`.

#![forbid(unsafe_code)]

/// C-MCP-1 .. C-MCP-10, C-HOOK-3.
pub mod mcp {
    /// C-MCP-1: the eight tools, in registration order.
    pub const TOOL_NAMES: [&str; 8] = [
        "recall",
        "remember",
        "ingest",
        "revise",
        "forget",
        "get",
        "browse",
        "memory_stats",
    ];

    /// C-MCP-2: protocol versions that must complete `initialize`.
    pub const PROTOCOL_VERSIONS: [&str; 3] = ["2024-11-05", "2025-06-18", "2025-11-25"];

    /// C-MCP-2: the streamable HTTP endpoint below the server's root.
    pub const MCP_PATH: &str = "/memory/mcp";

    /// C-MCP-6: the whole text of every CLIENT_POLICY refusal.
    pub const POLICY_DENIED_MESSAGE: &str =
        "policy_denied: this client is not permitted to make this call";

    /// C-HOOK-3: the prefix the mirror hook matches on.
    pub const POLICY_DENIED_PREFIX: &str = "policy_denied:";

    /// C-MCP-6: the text of a failure inside a tool body is this prefix plus the message.
    pub fn tool_error_prefix(tool: &str) -> String {
        format!("Error executing tool {tool}: ")
    }

    /// C-MCP-6: the text for a tool name the server does not register.
    pub fn unknown_tool_message(tool: &str) -> String {
        format!("Unknown tool: {tool}")
    }

    /// C-MCP-7, C-HOOK-3: the only tools a CLIENT_POLICY may grant.
    pub const DATASET_SCOPED_TOOLS: [&str; 2] = ["forget", "ingest"];

    /// C-MCP-7, C-HOOK-3: the longest `ingest` document a restricted caller may send, in
    /// characters (Unicode scalar values, as Python's `len`).
    pub const RESTRICTED_INGEST_MAX_CHARS: usize = 45_000;

    /// C-MCP-10: `MCP_SESSION_IDLE_TIMEOUT` default, in seconds.
    pub const DEFAULT_SESSION_IDLE_TIMEOUT_SECS: u64 = 1800;

    /// C-MCP-10: open sessions; one more is answered 503.
    pub const MAX_SESSIONS: usize = 10_000;

    /// C-MCP-4: recall's hit carries the stored `memory_type` under this key.
    pub const RECALL_TYPE_KEY: &str = "type";

    /// C-MCP-4: the only `degraded` value.
    pub const DEGRADED_BM25_ONLY: &str = "bm25-only";
}

/// C-MCP-8, C-JWT-4, C-HTTP-7: who the caller is and how that is carried upstream.
pub mod identity {
    use serde::{Deserialize, Serialize};

    pub const HEADER_SUB: &str = "x-verified-sub";
    pub const HEADER_CLIENT_ID: &str = "x-verified-client-id";
    pub const HEADER_GRANT: &str = "x-verified-grant";
    /// Every inbound header with this prefix is dropped by the proxy (C-HTTP-7).
    pub const HEADER_VERIFIED_PREFIX: &str = "x-verified-";
    pub const HEADER_PROXY_SECRET: &str = "x-proxy-secret";

    /// C-JWT-4: `client_credentials` exactly when `sub == client_id`.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(rename_all = "snake_case")]
    pub enum Grant {
        AuthorizationCode,
        ClientCredentials,
    }

    impl Grant {
        pub fn classify(sub: &str, client_id: &str) -> Grant {
            if sub == client_id {
                Grant::ClientCredentials
            } else {
                Grant::AuthorizationCode
            }
        }

        pub fn as_str(self) -> &'static str {
            match self {
                Grant::AuthorizationCode => "authorization_code",
                Grant::ClientCredentials => "client_credentials",
            }
        }

        /// The `X-Verified-Grant` value; anything else (including absent) is no grant,
        /// which every policy denies.
        pub fn from_header(value: &str) -> Option<Grant> {
            match value {
                "authorization_code" => Some(Grant::AuthorizationCode),
                "client_credentials" => Some(Grant::ClientCredentials),
                _ => None,
            }
        }
    }

    /// C-MCP-8: `provenance.source_class` values.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(rename_all = "kebab-case")]
    pub enum SourceClass {
        UserStated,
        ToolOutput,
        Reflection,
        AutoCapture,
        Migration,
        Promoted,
    }

    /// C-MCP-8: the provenance sub-document, stamped from the verified headers only.
    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
    pub struct Provenance {
        pub agent: String,
        pub session_id: String,
        pub source_class: SourceClass,
        pub written_at: String,
    }

    /// C-MCP-8: `client_id` for a machine caller, `sub` otherwise, with the Python fallbacks.
    pub fn agent(grant: Option<Grant>, sub: &str, client_id: &str) -> String {
        match grant {
            Some(Grant::ClientCredentials) if !client_id.is_empty() => client_id.to_owned(),
            Some(Grant::ClientCredentials) => "unknown-client".to_owned(),
            _ if !sub.is_empty() => sub.to_owned(),
            _ => "unknown-user".to_owned(),
        }
    }

    /// C-MCP-8: may `grant`/`agent` forget or revise a target with this provenance?
    pub fn authorize_supersede(
        grant: Option<Grant>,
        agent: &str,
        target_source_class: Option<&str>,
        target_agent: Option<&str>,
    ) -> bool {
        if target_source_class == Some("user-stated") {
            return grant == Some(Grant::AuthorizationCode);
        }
        match grant {
            Some(Grant::AuthorizationCode) => true,
            Some(Grant::ClientCredentials) => !agent.is_empty() && Some(agent) == target_agent,
            None => false,
        }
    }
}

/// C-HTTP-1 .. C-HTTP-10: the proxy's HTTP surface.
pub mod http {
    use serde::{Deserialize, Serialize};

    /// C-HTTP-1: exactly these five, on every proxy-generated response.
    pub const CORS_HEADERS: [(&str, &str); 5] = [
        ("Access-Control-Allow-Origin", "*"),
        (
            "Access-Control-Allow-Methods",
            "GET, POST, PUT, DELETE, OPTIONS",
        ),
        (
            "Access-Control-Allow-Headers",
            "Content-Type, Authorization, Accept",
        ),
        ("Access-Control-Expose-Headers", "WWW-Authenticate"),
        ("Access-Control-Max-Age", "86400"),
    ];

    /// C-HTTP-4.
    pub const JSONRPC_UNAUTHORIZED: i64 = -32001;
    pub const JSONRPC_FORBIDDEN: i64 = -32003;
    /// C-HTTP-6: upstream unreachable (HTTP 502).
    pub const JSONRPC_UPSTREAM_ERROR: i64 = -32000;

    pub const HEALTH_PATH: &str = "/health";
    pub const PROTECTED_RESOURCE_PATH: &str = "/.well-known/oauth-protected-resource";
    pub const WELL_KNOWN_PREFIX: &str = "/.well-known/";
    pub const PROTECTED_RESOURCE_CACHE_CONTROL: &str = "public, max-age=3600";

    /// C-HTTP-3: the fixed metadata document.
    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
    pub struct ProtectedResourceMetadata {
        pub resource: String,
        pub authorization_servers: Vec<String>,
        pub scopes_supported: Vec<String>,
        pub bearer_methods_supported: Vec<String>,
    }

    impl ProtectedResourceMetadata {
        pub fn new(issuer: &str, path_prefix: &str) -> Self {
            ProtectedResourceMetadata {
                resource: resource_id(issuer, path_prefix),
                authorization_servers: vec![issuer.to_owned()],
                scopes_supported: ["mcp:read", "mcp:write", "mcp:admin"]
                    .map(String::from)
                    .to_vec(),
                bearer_methods_supported: vec!["header".to_owned()],
            }
        }
    }

    /// C-HTTP-3: OIDC_ISSUER + PATH_PREFIX.
    pub fn resource_id(issuer: &str, path_prefix: &str) -> String {
        format!("{issuer}{path_prefix}")
    }

    /// C-HTTP-4: the `WWW-Authenticate` value of a 401.
    pub fn www_authenticate(resource_id: &str, invalid_token: bool) -> String {
        let meta = format!("{resource_id}/.well-known/oauth-protected-resource");
        if invalid_token {
            format!("Bearer error=\"invalid_token\", resource_metadata=\"{meta}\"")
        } else {
            format!("Bearer resource_metadata=\"{meta}\"")
        }
    }

    /// C-HTTP-5.
    pub const BODY_LIMIT_DEFAULT: usize = 1024 * 1024;
    pub const BODY_LIMIT_SESSIONS: usize = 8 * 1024 * 1024;
    pub const SESSIONS_PATH_PREFIX: &str = "/sessions/v1/";

    /// C-HTTP-5: the limit for a raw request target (path and query as received). A path
    /// with a percent escape or a dot segment never gets the larger limit.
    pub fn body_limit(raw_target: &str) -> usize {
        let path = raw_target.split('?').next().unwrap_or("");
        let larger = path.starts_with(SESSIONS_PATH_PREFIX)
            && !path.contains('%')
            && !path.split('/').any(|seg| seg == "." || seg == "..");
        if larger {
            BODY_LIMIT_SESSIONS
        } else {
            BODY_LIMIT_DEFAULT
        }
    }

    /// C-HTTP-6: a request `Content-Encoding` the proxy forwards (empty or `identity`, after
    /// trimming and lower-casing). Everything else is 415.
    pub fn content_encoding_allowed(value: &str) -> bool {
        let v = value.trim().to_ascii_lowercase();
        v.is_empty() || v == "identity"
    }

    /// C-HTTP-6: `X-Forwarded-Proto` is `https` only when the front says exactly that.
    pub fn forwarded_proto<'a>(claimed: &str, own_scheme: &'a str) -> &'a str {
        if claimed.trim().eq_ignore_ascii_case("https") {
            "https"
        } else {
            own_scheme
        }
    }

    /// C-HTTP-7: request headers never forwarded as received (the proxy writes its own
    /// forwarding and identity headers).
    pub const HOP_BY_HOP: [&str; 5] = [
        "host",
        "authorization",
        "transfer-encoding",
        "connection",
        "keep-alive",
    ];
    pub const FORWARDING: [&str; 4] = [
        "x-forwarded-proto",
        "x-forwarded-for",
        "x-forwarded-host",
        "forwarded",
    ];
}

/// C-JWT-1 .. C-JWT-6.
pub mod jwt {
    pub const ALGORITHM: &str = "RS256";
    /// C-JWT-5.
    pub const JWKS_TTL_SECS: u64 = 300;
    pub const JWKS_RETRY_AFTER_FAILURE_SECS: u64 = 30;
    pub const JWKS_FETCH_TIMEOUT_SECS: u64 = 10;
    /// C-JWT-3: a still-invalid signature does not force another fetch for this long.
    pub const FORCED_REFRESH_BACKOFF_SECS: u64 = 30;
    /// C-JWT-2: the key name of a JWKS entry without `kid`.
    pub const DEFAULT_KID: &str = "default";

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum TimeClaimError {
        Expired,
        NotYetValid,
        IssuedInFuture,
    }

    /// C-JWT-6: PyJWT 2.15.1's comparison. Each claim is truncated toward zero
    /// (`f64::trunc`, Python's `int()`); `now` keeps its fraction. Reject `exp <= now`,
    /// `nbf > now`, `iat > now`. The caller decides beforehand what a missing or non-numeric
    /// claim means (plan 2.3: the Rust proxy requires a numeric `exp`).
    pub fn check_time_claims(
        exp: Option<f64>,
        nbf: Option<f64>,
        iat: Option<f64>,
        now: f64,
    ) -> Result<(), TimeClaimError> {
        if let Some(exp) = exp
            && exp.trunc() <= now
        {
            return Err(TimeClaimError::Expired);
        }
        if let Some(iat) = iat
            && iat.trunc() > now
        {
            return Err(TimeClaimError::IssuedInFuture);
        }
        if let Some(nbf) = nbf
            && nbf.trunc() > now
        {
            return Err(TimeClaimError::NotYetValid);
        }
        Ok(())
    }
}

/// C-ES-1 .. C-ES-5.
pub mod es {
    pub const FACT_INDEX: &str = "memory-fact";
    pub const KNOWLEDGE_INDEX: &str = "memory-knowledge";
    pub const EPISODE_INDEX: &str = "memory-episode";
    pub const STATS_INDEX: &str = "memory-stats";
    pub const ALL_ALIAS: &str = "memory-all";
    /// C-ES-1: `memory-all` covers these and nothing else.
    pub const ALIAS_MEMBERS: [&str; 3] = [FACT_INDEX, KNOWLEDGE_INDEX, EPISODE_INDEX];
    pub const SESSION_INDEX: &str = "memory-session";
    pub const SESSION_MESSAGE_INDEX: &str = "memory-session-message";
    pub const SCHEMA_SESSION: &str = "session/1";
    pub const SCHEMA_MESSAGE: &str = "session-message/1";

    /// C-ES-5: startup attempts and the pause between them.
    pub const STARTUP_RETRIES: u32 = 10;
    pub const STARTUP_RETRY_DELAY_SECS: u64 = 3;

    /// C-ES-3.
    pub const RRF_K: f64 = 60.0;
    pub const CHUNK_SIZE: usize = 1200;
    pub const CHUNK_OVERLAP: usize = 150;
    pub const FRESHNESS_OFFSET_DAYS_EPISODE: f64 = 30.0;
    pub const FRESHNESS_OFFSET_DAYS_OTHER: f64 = 180.0;
    pub const USE_BOOST_CAP: f64 = 1.4;
    /// Background ingest job above this many chunks (C-MCP-4, unrestricted callers only).
    pub const INGEST_JOB_THRESHOLD: usize = 40;
    pub const BROWSE_MAX_LIMIT: usize = 1000;
    pub const EPISODE_TTL_DAYS: i64 = 90;
    /// The non-null `superseded_by` marker of a logical delete.
    pub const FORGET_SENTINEL: &str = "forget";
    /// recall fetches this many candidates per leg.
    pub fn recall_fetch(top_k: usize) -> usize {
        (5 * top_k).max(50)
    }

    /// C-ES-3: `1/(k + rank + 1)` per leg, summed; `rank` is 0-based.
    pub fn rrf_term(rank: usize) -> f64 {
        1.0 / (RRF_K + rank as f64 + 1.0)
    }

    /// C-ES-3: `exp(-0.5 * (age_days / offset_days)^2)`.
    pub fn freshness(age_days: f64, offset_days: f64) -> f64 {
        if offset_days <= 0.0 {
            return 1.0;
        }
        (-0.5 * (age_days.abs() / offset_days).powi(2)).exp()
    }

    /// C-ES-3: `min(1 + 0.2 * log10(1 + use_count), 1.4)`, negative counts as 0.
    pub fn use_boost(use_count: i64) -> f64 {
        let uc = use_count.max(0) as f64;
        (1.0 + 0.2 * (1.0 + uc).log10()).min(USE_BOOST_CAP)
    }
}

/// C-SES-1 .. C-SES-9.
pub mod sessions {
    use serde::{Deserialize, Serialize};

    pub const MOUNT: &str = "/memory/sessions/v1";
    /// C-SES-3.
    pub const WIRE_MAX: usize = 8 * 1024 * 1024;
    pub const DECOMPRESSED_MAX: usize = 5 * 1024 * 1024;
    pub const SEGMENT_MAX_LINES: usize = 50_000;
    pub const MAX_RECORD_DEPTH: usize = 64;
    pub const SEGMENT_MAX_WAITERS: usize = 4;
    /// C-SES-4: the redaction ruleset this contract freezes.
    pub const REDACT_VERSION: &str = "r1";

    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
    pub enum Scope {
        #[serde(rename = "sessions:ingest")]
        Ingest,
        #[serde(rename = "sessions:read")]
        Read,
        #[serde(rename = "sessions:purge")]
        Purge,
    }

    /// C-SES-1: the fixed route table. Anything else is 403 `forbidden`.
    pub const ROUTES: [(&str, &str, Scope); 10] = [
        ("POST", "/ingest", Scope::Ingest),
        ("POST", "/blob", Scope::Ingest),
        ("POST", "/state", Scope::Ingest),
        ("POST", "/search", Scope::Read),
        ("GET", "/preview", Scope::Read),
        ("GET", "/archive", Scope::Read),
        ("GET", "/archive/tool-results", Scope::Read),
        ("DELETE", "/session", Scope::Purge),
        ("DELETE", "/purged", Scope::Purge),
        ("GET", "/status", Scope::Read),
    ];

    pub fn route_scope(method: &str, path: &str) -> Option<Scope> {
        ROUTES
            .iter()
            .find(|(m, p, _)| *m == method && *p == path)
            .map(|(_, _, s)| *s)
    }

    /// C-SES-2: a raw path that never names a route, whatever it decodes to.
    pub fn path_refused(raw_path: &str) -> bool {
        let low = raw_path
            .split('?')
            .next()
            .unwrap_or("")
            .to_ascii_lowercase();
        low.contains("%2f")
            || low.contains("%5c")
            || low.contains("%2e")
            || low.split('/').any(|seg| seg == "." || seg == "..")
    }

    /// Error codes in `{"error": <code>}` bodies (C-SES-2, -3, -6, -7, -8, -9).
    pub mod errors {
        pub const GATE_UNCONFIGURED: &str = "gate_unconfigured";
        pub const UNAUTHENTICATED: &str = "unauthenticated";
        pub const FORBIDDEN: &str = "forbidden";
        pub const INDEX_UNAVAILABLE: &str = "index_unavailable";
        pub const TOO_LARGE: &str = "too_large";
        pub const TOO_MANY_LINES: &str = "too_many_lines";
        pub const HOST_MISMATCH: &str = "host_mismatch";
        pub const OFFSET_MISMATCH: &str = "offset_mismatch";
        pub const STALE_GENERATION: &str = "stale_generation";
        pub const SHA256_MISMATCH: &str = "sha256_mismatch";
        pub const ARCHIVE_UNAVAILABLE: &str = "archive_unavailable";
        pub const ARCHIVE_TAMPERED: &str = "archive_tampered";
        pub const ARCHIVE_INCOMPLETE: &str = "archive_incomplete";
        pub const PURGED: &str = "purged";
        pub const BUSY: &str = "busy";
    }

    /// C-SES-6: the whole success body of `POST /ingest`.
    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct IngestResponse {
        pub session_key: String,
        pub indexed: u64,
        pub next_offset: u64,
        pub archive: String,
    }
}

/// C-EMB-1.
pub mod embedding {
    pub const DEFAULT_ENDPOINT: &str = "https://api.voyageai.com/v1";
    pub const DEFAULT_MODEL: &str = "voyage-3-large";
    pub const DEFAULT_DIMENSIONS: usize = 1024;
    pub const BATCH_MAX: usize = 128;
    /// One retry on 5xx or a transport failure, after this pause; 4xx is not retried.
    pub const RETRY_DELAY_MS: u64 = 500;
    pub const ATTEMPTS: u32 = 2;
}

/// C-MAINT-1.
pub mod maint {
    pub const RUN_ARG: &str = "run";
    pub const EXIT_USAGE: i32 = 64;
    pub const EXIT_ERRORS: i32 = 1;
    pub const RETENTION_DAYS: i64 = 365;
    pub const MARKER_DAYS: i64 = 30;
    pub const RUN_KIND: &str = "session-maint";
    pub const DEFAULT_LOCK: &str = "/run/lock/memory-session-maint.lock";
}

/// C-OPS-1, C-OPS-2.
pub mod ops {
    pub const UNIT_SERVER: &str = "memory-mcp-v2";
    pub const UNIT_PROXY: &str = "memory-v2-proxy";
    pub const SERVER_LISTEN: &str = "127.0.0.1:8010";
    pub const PROXY_PORT: u16 = 8767;
    pub const APM_SERVICE_NAME: &str = "ai-memory-auth-proxy";
    /// Required: the server does not start without these.
    pub const REQUIRED_SERVER_ENV: [&str; 3] = ["ES_URL", "ES_PASSWORD", "VOYAGE_API_KEY"];
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    const CONSTANTS_JSON: &str = include_str!("../../../../contracts/constants.json");
    const MCP_TOOLS_JSON: &str = include_str!("../../../../contracts/mcp-tools.json");

    #[test]
    fn constants_json_agrees() {
        let c: Value = serde_json::from_str(CONSTANTS_JSON).unwrap();
        assert_eq!(
            c["restricted_ingest_max_chars"],
            mcp::RESTRICTED_INGEST_MAX_CHARS as u64
        );
        assert_eq!(c["policy_denied_prefix"], mcp::POLICY_DENIED_PREFIX);
        assert!(mcp::POLICY_DENIED_MESSAGE.starts_with(mcp::POLICY_DENIED_PREFIX));
        let tools: Vec<&str> = c["dataset_scoped_tools"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        assert_eq!(tools, mcp::DATASET_SCOPED_TOOLS);
    }

    #[test]
    fn mcp_tools_json_names() {
        let t: Value = serde_json::from_str(MCP_TOOLS_JSON).unwrap();
        let mut got: Vec<&str> = t["tools"]
            .as_array()
            .unwrap()
            .iter()
            .map(|x| x["name"].as_str().unwrap())
            .collect();
        let mut want = mcp::TOOL_NAMES.to_vec();
        got.sort_unstable();
        want.sort_unstable();
        assert_eq!(got, want);
    }

    /// The C-HTTP-5 probes of tests/http_roundtrip/cases_http.py.
    #[test]
    fn body_limits() {
        use http::{BODY_LIMIT_DEFAULT as D, BODY_LIMIT_SESSIONS as S, body_limit};
        for (path, want) in [
            ("/mcp", D),
            ("/sessions/v1/ingest", S),
            ("/sessions/v1/ingest?x=%2F", S),
            ("/sessions/v1/%69ngest", D),
            ("/sessions/v1/./ingest", D),
            ("/sessions/v1/../v1/ingest", D),
            ("/sessions/v1%2Fingest", D),
            ("/sessions/v1", D),
        ] {
            assert_eq!(body_limit(path), want, "{path}");
        }
    }

    /// The C-HTTP-6 rows (`br` excluded, see contracts/specs/C-HTTP-6.md).
    #[test]
    fn content_encoding() {
        for (v, ok) in [
            ("", true),
            ("identity", true),
            ("IDENTITY", true),
            (" identity ", true),
            ("gzip", false),
        ] {
            assert_eq!(http::content_encoding_allowed(v), ok, "{v:?}");
        }
    }

    /// The C-JWT-6 table, with now = N + 0.1.
    #[test]
    fn time_claims() {
        use jwt::{TimeClaimError::*, check_time_claims as c};
        let n = 1_800_000_000.0_f64;
        let now = n + 0.1;
        let far = Some(n + 600.0);
        assert_eq!(c(Some(n), None, None, now), Err(Expired));
        assert_eq!(c(Some(n + 0.6), None, None, now), Err(Expired));
        assert_eq!(c(Some(n + 1.0), None, None, now), Ok(()));
        assert_eq!(c(Some(n + 1.6), None, None, now), Ok(()));
        assert_eq!(c(far, Some(n + 0.6), None, now), Ok(()));
        assert_eq!(c(far, Some(n + 1.6), None, now), Err(NotYetValid));
        assert_eq!(c(far, None, Some(n + 0.6), now), Ok(()));
        assert_eq!(c(far, None, Some(n + 1.6), now), Err(IssuedInFuture));
    }

    /// The C-MCP-8 matrix of tests/http_roundtrip/cases_mcp.py.
    #[test]
    fn supersede_matrix() {
        use identity::{Grant::*, authorize_supersede as a};
        let own = "roundtrip-writer";
        for (sc, human, machine_own, machine_other) in [
            ("user-stated", true, false, false),
            ("tool-output", true, true, false),
            ("reflection", true, true, false),
        ] {
            assert_eq!(
                a(
                    Some(AuthorizationCode),
                    "operator@example.test",
                    Some(sc),
                    Some(own)
                ),
                human,
                "{sc}"
            );
            assert_eq!(
                a(Some(ClientCredentials), own, Some(sc), Some(own)),
                machine_own,
                "{sc}"
            );
            assert_eq!(
                a(
                    Some(ClientCredentials),
                    "memory-keeper",
                    Some(sc),
                    Some(own)
                ),
                machine_other,
                "{sc}"
            );
            assert!(!a(None, own, Some(sc), Some(own)), "{sc}");
        }
    }

    #[test]
    fn grant_and_agent() {
        use identity::{Grant, agent};
        assert_eq!(
            Grant::classify("memory-mirror", "memory-mirror"),
            Grant::ClientCredentials
        );
        assert_eq!(
            Grant::classify("operator@example.test", "connector"),
            Grant::AuthorizationCode
        );
        assert_eq!(Grant::from_header("password"), None);
        assert_eq!(
            agent(Some(Grant::ClientCredentials), "x", "memory-mirror"),
            "memory-mirror"
        );
        assert_eq!(agent(None, "", ""), "unknown-user");
    }

    #[test]
    fn session_routes_and_paths() {
        use sessions::{Scope, path_refused, route_scope};
        assert_eq!(route_scope("GET", "/status"), Some(Scope::Read));
        assert_eq!(route_scope("PUT", "/ingest"), None);
        for p in [
            "/archive%2ftool-results",
            "/archive%2Ftool-results",
            "/archive%5ctool-results",
            "/%2e/status",
            "/./status",
            "/x/../status",
        ] {
            assert!(path_refused(p), "{p}");
        }
        assert!(!path_refused("/archive/tool-results?x=%2f"));
    }

    #[test]
    fn scoring_formulas() {
        assert!((es::rrf_term(0) - 1.0 / 61.0).abs() < 1e-15);
        assert_eq!(es::use_boost(0), 1.0);
        assert_eq!(es::use_boost(1_000_000), es::USE_BOOST_CAP);
        assert_eq!(es::freshness(0.0, 180.0), 1.0);
        assert_eq!(es::recall_fetch(3), 50);
        assert_eq!(es::recall_fetch(20), 100);
    }

    #[test]
    fn protected_resource_document() {
        let m = http::ProtectedResourceMetadata::new("https://issuer.example.test", "/memory");
        let v = serde_json::to_value(&m).unwrap();
        assert_eq!(v["resource"], "https://issuer.example.test/memory");
        assert_eq!(
            http::www_authenticate(&m.resource, true),
            "Bearer error=\"invalid_token\", resource_metadata=\"https://issuer.example.test/memory/.well-known/oauth-protected-resource\""
        );
    }
}
