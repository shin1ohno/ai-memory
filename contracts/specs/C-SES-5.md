# C-SES-5: ccs client round trip

Plan section 2.2. Python reference: `612b1cb`. Round-trip coverage: **not covered by run.py**.

## Contract

The ccs client (session-search) talks to the sessions API as `session-search:ccs/api.py` does; its own test
suite, pointed at the target URL, must pass.

## Python reference

- `session-search:ccs/api.py:1,121`
- `session-search:ccs/ingest.py:10,355-358`

## Test

Not in run.py: needs ccs's suite with a target-URL switch.
