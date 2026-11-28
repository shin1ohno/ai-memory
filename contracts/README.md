# ai-memory external contracts

The contracts a replacement implementation must keep, one file per contract ID under `specs/`. The IDs
are those of the Rust migration plan, section 2. Each spec states the contract, points at the Python
implementation it was read from (`612b1cb`, `path:line`), and names the round-trip case that checks it.

`setup:` refers to the shin1ohno/setup repository, `session-search:` and `home-monitor:` to those
repositories.

## Status

These specs are drafts for the W1 freeze. The freeze itself waits for the Phase 0 measurement window
(M5) and the claude.ai connector observation (M6); either can still add to C-MCP-2. Until then the files
may change in ordinary pull requests.

Coverage by `tests/http_roundtrip/run.py` against the Python implementation: 36 covered,
8 partial, 6 not covered by the suite (50 IDs). "Partial" and "not
covered" are explained in each spec's Notes or Test section.

## Machine-readable artifacts

| File | Contract | Written by |
|---|---|---|
| `mcp-tools.json` | C-MCP-1: the `tools/list` result | `run.py --capture` |
| `constants.json` | C-HOOK-3: values shared by the hook and the server | `run.py --capture` |
| `golden/<ID>/*.json` | recorded responses and requests, normalised | `run.py --capture` |
| `../memory-mcp/conformance/session_redact_r1.jsonl` | C-SES-4: redaction vectors | `memory-mcp/conformance/gen_vectors.py` |

Golden normalisation (`tests/http_roundtrip/lib.py`, `Normalizer`): ids, uuids and session ids become
`<id:N>` numbered by first appearance (equal ids stay equal), ISO timestamps become `<ts>`, vectors become
`<vector len=N>`, floats are rounded to 6 decimals; `content_hash` and `doc_key` are kept. The plan named
only `id`, `job_id`, `written_at` and `Mcp-Session-Id`; parent ids (`doc_id`, `new_id`, `parent_id`,
`superseded_by`, `derived_from`) are random uuids too, and the other timestamps are clock values, so they
are normalised the same way.

## Index

### 2.1 MCP tools and responses

| ID | Contract | Round-trip coverage |
|---|---|---|
| [C-MCP-1](specs/C-MCP-1.md) | Tool definitions | covered |
| [C-MCP-2](specs/C-MCP-2.md) | Stateful Streamable HTTP | covered |
| [C-MCP-3](specs/C-MCP-3.md) | Response framing | covered |
| [C-MCP-4](specs/C-MCP-4.md) | Tool responses | covered |
| [C-MCP-5](specs/C-MCP-5.md) | remember routing | covered |
| [C-MCP-6](specs/C-MCP-6.md) | Error text prefixes | covered |
| [C-MCP-7](specs/C-MCP-7.md) | CLIENT_POLICY | covered |
| [C-MCP-8](specs/C-MCP-8.md) | Provenance and the destructive-op matrix | covered |
| [C-MCP-9](specs/C-MCP-9.md) | Argument coercion | covered |
| [C-MCP-10](specs/C-MCP-10.md) | Session lifetime | partial |

### 2.2 HTTP routes and the sessions API

| ID | Contract | Round-trip coverage |
|---|---|---|
| [C-HTTP-1](specs/C-HTTP-1.md) | CORS preflight | covered |
| [C-HTTP-2](specs/C-HTTP-2.md) | Health | covered |
| [C-HTTP-3](specs/C-HTTP-3.md) | OAuth protected-resource metadata | covered |
| [C-HTTP-4](specs/C-HTTP-4.md) | 401 and 403 bodies | covered |
| [C-HTTP-5](specs/C-HTTP-5.md) | Body limits | covered |
| [C-HTTP-6](specs/C-HTTP-6.md) | Content-Encoding and upstream failure | covered |
| [C-HTTP-7](specs/C-HTTP-7.md) | Header rewriting | covered |
| [C-HTTP-8](specs/C-HTTP-8.md) | SSE streaming | covered |
| [C-HTTP-9](specs/C-HTTP-9.md) | Listener and path forwarding | partial |
| [C-HTTP-10](specs/C-HTTP-10.md) | No query strings in logs | covered |
| [C-SES-1](specs/C-SES-1.md) | Session routes and scopes | covered |
| [C-SES-2](specs/C-SES-2.md) | Session gate | covered |
| [C-SES-3](specs/C-SES-3.md) | Session limits | partial |
| [C-SES-4](specs/C-SES-4.md) | Redaction ruleset r1 | not covered by run.py |
| [C-SES-5](specs/C-SES-5.md) | ccs client round trip | not covered by run.py |
| [C-SES-6](specs/C-SES-6.md) | Ingest protocol | partial |
| [C-SES-7](specs/C-SES-7.md) | SESSION_SCOPE_POLICY | covered |
| [C-SES-8](specs/C-SES-8.md) | Archive objects | not covered by run.py |
| [C-SES-9](specs/C-SES-9.md) | Purge ordering | not covered by run.py |

### 2.3 JWT verification

| ID | Contract | Round-trip coverage |
|---|---|---|
| [C-JWT-1](specs/C-JWT-1.md) | Signature and issuer | covered |
| [C-JWT-2](specs/C-JWT-2.md) | Key selection | covered |
| [C-JWT-3](specs/C-JWT-3.md) | Rotation | covered |
| [C-JWT-4](specs/C-JWT-4.md) | Grant classification and audience matrix | covered |
| [C-JWT-5](specs/C-JWT-5.md) | JWKS fetching | partial |
| [C-JWT-6](specs/C-JWT-6.md) | Time claims and claim types | covered |

### 2.4 Elasticsearch

| ID | Contract | Round-trip coverage |
|---|---|---|
| [C-ES-1](specs/C-ES-1.md) | Index definitions | covered |
| [C-ES-2](specs/C-ES-2.md) | REST semantics | covered |
| [C-ES-3](specs/C-ES-3.md) | Ranking and chunking | covered |
| [C-ES-4](specs/C-ES-4.md) | Documents the keeper reads and writes | covered |
| [C-ES-5](specs/C-ES-5.md) | Least-privilege start | covered |

### 2.5 Mirror hook

| ID | Contract | Round-trip coverage |
|---|---|---|
| [C-HOOK-1](specs/C-HOOK-1.md) | Mirror token | covered |
| [C-HOOK-2](specs/C-HOOK-2.md) | Mirror ingest and forget | covered |
| [C-HOOK-3](specs/C-HOOK-3.md) | Shared constants | covered |
| [C-HOOK-4](specs/C-HOOK-4.md) | Production --check | not covered by run.py |

### 2.6 Operations

| ID | Contract | Round-trip coverage |
|---|---|---|
| [C-OPS-1](specs/C-OPS-1.md) | Units, ports and names | partial |
| [C-OPS-2](specs/C-OPS-2.md) | Environment variables | partial |
| [C-OPS-3](specs/C-OPS-3.md) | Audit lines | covered |
| [C-OPS-4](specs/C-OPS-4.md) | External probe path | not covered by run.py |

### 2.7 Scheduled work and external APIs

| ID | Contract | Round-trip coverage |
|---|---|---|
| [C-MAINT-1](specs/C-MAINT-1.md) | Session maintenance run | partial |
| [C-EMB-1](specs/C-EMB-1.md) | Embedding client | covered |
