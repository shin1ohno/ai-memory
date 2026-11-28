# C-HTTP-8: SSE streaming

Plan section 2.2. Python reference: `612b1cb`. Round-trip coverage: **covered**.

## Contract

An upstream `text/event-stream` response is streamed chunk by chunk, not buffered; when the client goes
away the upstream response is closed.

## Python reference

- `auth-proxy/proxy.py:556-573`
- `home-monitor:scripts/mcp-proxy.conf.tftpl:210-211 (nginx side)`

## Test

case `sse_stream`: three events 0.3 s apart arrive with gaps of at least 0.2 s; after a client disconnect the fake upstream observes its stream closing.
