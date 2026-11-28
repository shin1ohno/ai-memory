# C-OPS-3: Audit lines

Plan section 2.6. Python reference: `612b1cb`. Round-trip coverage: **covered**.

## Contract

stderr carries `AUDIT deny tool=<t> client=<c> dataset=<d>` (client-controlled values sanitised to one
token), `AUDIT policy_invalid reason=... client_credentials=deny-all`, `AUDIT policy_unset ...`,
`POLICY <client> -> <tools> @ <datasets>`, `AUDIT supersede id=<id> by=<agent> grant=<grant>` and the
`SESSIONS scope-rule ...` lines.

## Python reference

- `memory-mcp/identity.py:161-165,328-342,440-459,558-567`

## Test

case `audit_lines`.
