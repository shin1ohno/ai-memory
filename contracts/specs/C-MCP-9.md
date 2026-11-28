# C-MCP-9: Argument coercion

Plan section 2.1. Python reference: `612b1cb`. Round-trip coverage: **covered**.

## Contract

Arguments are coerced the way the Python server's pydantic validation does: a numeric string for an int
(`top_k: "3"`), a JSON string for a dict or list (`filters: "{...}"`, `tags: "[...]"`), a string boolean, and
null for an optional dict are accepted; `top_k: "3.5"` and `top_k: null` are refused with
`Error executing tool <name>: `. Which inputs are accepted is the contract; the validation message after the
prefix is not. CLIENT_POLICY sees the raw arguments before coercion (C-MCP-7).

## Python reference

- `memory-mcp/identity.py:391-392 (policy sees raw arguments)`
- `memory-mcp/server.py:145-147 (signatures)`

## Test

case `coercion` (9 inputs).

## Notes

Where a new implementation is stricter, it is loosened to match (plan 2.1).
