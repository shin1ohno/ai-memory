# C-HOOK-1: Mirror token

Plan section 2.5. Python reference: `612b1cb`. Round-trip coverage: **covered**.

## Contract

The mirror hook gets a token with `client_credentials` (client_secret_basic, `audience=memory`) and checks
`aud` includes `memory`, `sub == client_id` and a lifetime of 3600 s; the proxy accepts it end to end.

## Python reference

- `hooks/mirror-file-memory.rb:114-130`
- `hooks/mirror-file-memory.rb:320-345`
- `hooks/mirror-file-memory.rb:867-930 (--check)`
- `bin/register-memory-mirror:72-75`

## Test

case `token_roundtrip`: `ruby hooks/mirror-file-memory.rb --check` against fake Hydra -> proxy -> server.
