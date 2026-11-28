# HTTP round-trip suite

Language-independent tests for the contracts in `contracts/specs/`. Standard library only.
`make test-http` runs it against the Python services of this checkout.

| File | What it holds |
|---|---|
| `run.py` | Entry point: starts the fakes, launches the implementation from a profile, runs the cases, compares with `contracts/golden/` |
| `profiles/python.json` | How to start the Python server, proxy and session-maint. A Rust profile names its binaries the same way; the environment variables are the contract (C-OPS-2) |
| `fakes.py` | Fake Elasticsearch (the query shapes memory-mcp sends), Voyage, JWKS, Hydra and an echo upstream; each records what it received |
| `fake_archive.py` | Fake S3 (SigV4 checked) and GCS (metadata-server token) object stores behind a local forward proxy that terminates TLS for the storage hosts; zstd frames from raw/RLE blocks |
| `tls_ca.py` | A per-run CA and leaf certificate written out in DER (stdlib only); the implementation trusts it through `SSL_CERT_FILE` |
| `ccs_pin.json` | The session-search (ccs) commit that C-SES-5 runs |
| `rsa_jwt.py` | RS256 keys and tokens without third-party packages; keys live only in memory for one run |
| `lib.py` | Raw HTTP, an MCP client that reads responses with the mirror hook's rule, golden normalisation, the case registry |
| `common.py` | The suite's fixed fake identities and policies |
| `cases_*.py` | One module per contract group; every case is tagged with its contract ID |
| `check_goldens.py` | Refuses golden files with secrets, tokens, personal data or local paths |

## Workflow

```
.venv/bin/python tests/http_roundtrip/run.py                 # compare with the goldens
.venv/bin/python tests/http_roundtrip/run.py --only C-JWT    # one group
.venv/bin/python tests/http_roundtrip/run.py --capture       # rewrite goldens from the Python services
python3 tests/http_roundtrip/check_goldens.py --self-test && python3 tests/http_roundtrip/check_goldens.py
```

C-SES-5 runs the ccs CLI from a session-search checkout: set `HTTP_ROUNDTRIP_CCS_REPO` to one that
has the commit in `ccs_pin.json` (default: `../session-search` next to this repository). The case
extracts that commit with `git archive`, writes a ccs config whose endpoint is the proxy under test,
and fails when the commit is not available.

The archive cases (C-SES-8, C-SES-9, C-SES-5) give the server `HTTPS_PROXY`, `HTTP_PROXY`,
`NO_PROXY=127.0.0.1,localhost` and `SSL_CERT_FILE`: the backends have fixed storage hostnames and no
endpoint setting, so an implementation must honour these variables (as httpx does) to be tested.
The proxy refuses tunnels to any other host, and the cases fail if one is attempted.

Capture only from the Python implementation, read the diff of every changed golden, and run
`check_goldens.py` before committing. Nothing here talks to a real backend: every process the
suite starts gets an environment built from scratch that points at the fakes on 127.0.0.1.

A case is a function decorated with `@case("<contract id>", "<title>", "<env>")`; it fails by
raising (`ctx.check`, `ctx.eq`, `ctx.golden`). Prefer recording the contract's observable answer
(status, body, what a fake received) over implementation details; normalise values that differ
per run in `lib.Normalizer`, and say so in the spec when the plan text named fewer.
