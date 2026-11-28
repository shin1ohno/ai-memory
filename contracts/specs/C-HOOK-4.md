# C-HOOK-4: Production --check

Plan section 2.5. Python reference: `612b1cb`. Round-trip coverage: **not covered by run.py**.

## Contract

Right after each cutover, `ruby ~/.claude/hooks/mirror-file-memory.rb --check` on a personal host passes
against the production URL.

## Python reference

- `hooks/mirror-file-memory.rb:246-251 (https required)`
- `hooks/mirror-file-memory.rb:867-930`

## Test

Not in run.py: it runs against production over https at cutover (plan 4.7).
