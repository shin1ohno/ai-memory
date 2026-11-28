# C-OPS-4: External probe path

Plan section 2.6. Python reference: `612b1cb`. Round-trip coverage: **not covered by run.py**.

## Contract

setup's mcp-probe (initialize with 2024-11-05, tools/list, a recall) succeeds against the deployed URL in
every phase.

## Python reference

- `setup:cookbooks/mcp-probe/files/probe.py:62,281-288,331`

## Test

Not in run.py: probe.py is run against the host at cutover.
