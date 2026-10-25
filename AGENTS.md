# AGENTS.md

Index, not documentation. Read the files it points to, not the tree. The envelope's
`context_refs` name the files that constrain your task; start there.

## Where things are

| You need | Look at |
|---|---|
| MCP server (recall / remember / ingest, authorization) | `memory-mcp/` (`server.py`, `identity.py`, `policy_mcp.py`) |
| Keeper (reconciles raw writes) | `memory-keeper/` |
| Auth proxy in front of the server | `auth-proxy/proxy.py` |
| What ships to the host | `memory-mcp/MANIFEST`, `memory-keeper/MANIFEST` |
| systemd units and env generation | `systemd/`, `generate_env_v2.sh` |
| Elasticsearch index definitions | `es-indices-v2/` |
| File-memory mirror client | `hooks/mirror-file-memory.rb`, `bin/register-memory-mirror` |
| Why the repository exists and how it is deployed | ADR 0013, https://github.com/shin1ohno/setup/blob/main/docs/adr/0013-ai-memory-own-repo.md |

## How to run things

| Task | Command |
|---|---|
| All tests | `make test` |
| Tests affected by your change | `make test-affected` |
| Distribution check (MANIFEST files alone import cleanly) | `make check-distribution` |

Tests are plain `python3 <file>` suites picked up by glob (`memory-mcp/test_*.py`,
`memory-keeper/test_*.py`, `tests/test_*.py`), so a new suite needs no Makefile change.
The envelope's `test_command` is run after you finish, outside your sandbox; it is the gate.

## Rules reviewers enforce

- Behaviour-preserving changes keep every existing test green; new behaviour comes with a test.
- No new dependency: `requirements*.txt` are changed by humans only.
- Comments explain why, at the density of the surrounding code. Do not narrate the diff.

## Changed by humans only

`Makefile` and every path in `.github/agent-protected.txt` are changed only by humans:
the Makefile is the CI definition, and the listed files hold authorization, credentials or
the distribution boundary. A patch that touches one is refused, as is any edit to `.github/`,
`spine-github/`, `AGENTS.md` or `CLAUDE.md`. If your task seems to need one, stop and say so
in the pull request description.
