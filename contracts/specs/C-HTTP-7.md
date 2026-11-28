# C-HTTP-7: Header rewriting

Plan section 2.2. Python reference: `612b1cb`. Round-trip coverage: **covered**.

## Contract

Inbound `X-Verified-*` (any suffix), `X-Proxy-Secret`, `X-Forwarded-Proto/-For/-Host`, `Forwarded`, `Host`,
`Authorization` and hop-by-hop headers are not forwarded. The proxy sets `X-Verified-Sub`,
`X-Verified-Client-Id`, `X-Verified-Grant` from the verified token, `X-Proxy-Secret` when
PROXY_SHARED_SECRET is set, `X-Forwarded-For` to the peer address, and `X-Forwarded-Proto` to `https` only
when the inbound value is exactly `https` (else its own scheme). Other headers pass through.

## Python reference

- `auth-proxy/proxy.py:330-351`
- `auth-proxy/proxy.py:471-493`

## Test

case `header_rewrite`.

## Notes

Headers the proxy's own HTTP client adds (User-Agent, Accept, Accept-Encoding) are outside the contract and dropped from the golden.
