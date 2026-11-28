# C-SES-3: Session limits

Plan section 2.2. Python reference: `612b1cb`. Round-trip coverage: **partial**.

## Contract

8 MiB on the wire (413 `too_large`), 5 MiB after gunzip (a body starting with the gzip magic is
decompressed; over: 413 `too_large`), at most 50,000 lines per segment (413 `too_many_lines`), record depth
64, and at most 4 queued segment jobs (503 `busy`).

## Python reference

- `memory-mcp/sessions_app.py:73-74`
- `memory-mcp/sessions_app.py:573-600`
- `memory-mcp/sessions_app.py:662-673,754`
- `memory-mcp/sessions_app.py:795-830`

## Test

case `limits`: wire, gunzip, small gzip, 50,001 lines.

## Notes

Not exercised yet: the ±1 boundaries, depth 64 and the 4-waiter queue.
