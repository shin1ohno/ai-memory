# C-HTTP-6: Content-Encoding and upstream failure

Plan section 2.2. Python reference: `612b1cb`. Round-trip coverage: **covered**.

## Contract

A request `Content-Encoding` that is empty or `identity` after strip and lower-casing is accepted; any other
value answers 415 `{"error":"unsupported_content_encoding"}` on every path. An upstream that cannot be
reached answers 502 with the JSON-RPC body code -32000 `upstream_error`.

## Python reference

- `auth-proxy/proxy.py:497-505`
- `auth-proxy/proxy.py:527-546`

## Test

case `content_encoding`.

## Notes

Observed, not compared: with `Content-Encoding: br` the Python proxy answers 400 from aiohttp before the handler runs (no Brotli wheel installed), so the rule above never sees it. A new implementation answers 415 as the rule says.
