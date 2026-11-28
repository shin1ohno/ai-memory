# HTTP round-trip suite

Language-independent tests for the contracts in `contracts/specs/`. Standard library only.
`make test-http` runs it against the Python services of this checkout.

| File | What it holds |
|---|---|
| `run.py` | Entry point: starts the fakes, launches the implementation from a profile, runs the cases, compares with `contracts/golden/` |
| `profiles/python.json` | How to start the Python server, proxy and session-maint. A Rust profile names its binaries the same way; the environment variables are the contract (C-OPS-2) |
| `fakes.py` | Fake Elasticsearch (the query shapes memory-mcp sends), Voyage, JWKS, Hydra and an echo upstream; each records what it received |
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

Capture only from the Python implementation, read the diff of every changed golden, and run
`check_goldens.py` before committing. Nothing here talks to a real backend: every process the
suite starts gets an environment built from scratch that points at the fakes on 127.0.0.1.

A case is a function decorated with `@case("<contract id>", "<title>", "<env>")`; it fails by
raising (`ctx.check`, `ctx.eq`, `ctx.golden`). Prefer recording the contract's observable answer
(status, body, what a fake received) over implementation details; normalise values that differ
per run in `lib.Normalizer`, and say so in the spec when the plan text named fewer.
