# C-HOOK-3: Shared constants

Plan section 2.5. Python reference: `612b1cb`. Round-trip coverage: **covered**.

## Contract

`contracts/constants.json` holds the values the hook and the server must agree on:
`restricted_ingest_max_chars` 45000, `policy_denied_prefix` `policy_denied:`, `dataset_scoped_tools`
[forget, ingest]. The hook source and the running server must both match it.

## Python reference

- `hooks/mirror-file-memory.rb:114,860`
- `memory-mcp/identity.py:203-222`
- `memory-mcp/test_contract_constants.py`

## Test

case `constants` (source text and the server's 45,000 / 45,001).
