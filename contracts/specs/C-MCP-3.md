# C-MCP-3: Response framing

Plan section 2.1. Python reference: `612b1cb`. Round-trip coverage: **covered**.

## Contract

A request sent with `Accept: application/json, text/event-stream` may be answered either as an SSE body
(`event: message` / `data: {...}` lines, `Content-Type: text/event-stream`) or as a plain JSON body.
Clients read it with the mirror hook's rule: take the `data:` lines, last first, and use the first JSON
object that has `result` or `error`; with no `data:` line, parse the body whole. Keep-alive comments and
non-result events must not hide the result.

## Python reference

- `hooks/mirror-file-memory.rb:493-511 (parse_payload)`
- `tests/http_roundtrip/lib.py (parse_payload, same rule)`

## Test

case `sse_framing`.

## Notes

The Python server answers SSE. The rule, not the framing choice, is the contract.
