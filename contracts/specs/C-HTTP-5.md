# C-HTTP-5: Body limits

Plan section 2.2. Python reference: `612b1cb`. Round-trip coverage: **covered**.

## Contract

After authentication the body is limited while it is read (Content-Length or received bytes, chunked
included): 8 MiB when the raw path starts with `/sessions/v1/` and contains no `%` and no `.`/`..` segment,
1 MiB otherwise. Over the limit: 413 `{"error":"too_large"}`. Without a valid token the answer is 401, not
413.

## Python reference

- `auth-proxy/proxy.py:93-128`
- `auth-proxy/proxy.py:506-515`

## Test

case `body_limits` (11 probes + unauthenticated).
