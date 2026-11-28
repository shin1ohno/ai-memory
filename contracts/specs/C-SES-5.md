# C-SES-5: ccs client round trip

Plan section 2.2. Python reference: `612b1cb` (unchanged at `17debf2`). Round-trip coverage: **covered**.

## Contract

The ccs client (session-search) talks to the sessions API as `session-search:ccs/api.py` does; its own test
suite, pointed at the target URL, must pass.

The round trip checks the client side of that: ccs's own CLI, at the commit pinned in
`tests/http_roundtrip/ccs_pin.json`, with a config whose endpoint is the auth proxy under test (in front of
the memory-mcp under test) and whose token URL is a client_credentials token endpoint:

- `ccs ingest --file` ships the transcript and its tool-results side files (three archive objects);
- `ccs status`, `ccs search <q>` (finds the session), `ccs preview <key> <q>` succeed;
- with the local transcript gone, `ccs resume <key> --print --to DIR` restores it from the archive byte
  for byte (equal to `GET /archive`) together with the side files;
- `ccs purge` without `sessions:purge` fails and the session stays.

## Python reference

- `session-search:ccs/api.py:1,121`
- `session-search:ccs/ingest.py:10,355-358`
- `memory-mcp/sessions_app.py` (the server side, through `auth-proxy/proxy.py`)

## Test

case `ccs_round_trip` (`tests/http_roundtrip/cases_ccs.py`). The target-URL switch is ccs's own config
file (`endpoint`, which ccs accepts as `http://127.0.0.1` for tests): the case writes it with the
proxy's URL. The ccs source is extracted with `git archive` from the checkout named by
`HTTP_ROUNDTRIP_CCS_REPO` (default `../session-search`); without the pinned commit the case fails.

## Notes

- What runs is ccs's CLI, not session-search's own test suite: those tests assert on their in-process
  fake server and have no target-URL switch. Running them against a live server needs a change in the
  session-search repository, outside this repository.
- The fixture lines carry `entrypoint: "cli"`: search hides non-interactive sessions unless `--all`.
