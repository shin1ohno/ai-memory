# C-HOOK-4: Production --check

Plan section 2.5. Python reference: `612b1cb`. Round-trip coverage: **outside run.py (accepted 2026-11-28)**.

## Contract

Right after each cutover, `ruby ~/.claude/hooks/mirror-file-memory.rb --check` on a personal host passes
against the production URL.

## Python reference

- `hooks/mirror-file-memory.rb:246-251 (https required)`
- `hooks/mirror-file-memory.rb:867-930`

## Test

Outside run.py, by owner decision on 2026-11-28. Alternative verification: at each cutover (plan 4.7),
right after the switch, run `ruby ~/.claude/hooks/mirror-file-memory.rb --check` on a personal host
against the production URL; it must exit 0. The suite cannot do this: the check requires https and the
production issuer. Its local half is covered by C-HOOK-1, whose case runs the same `--check` against
fake Hydra, the proxy and the server under test.
