# C-JWT-5: JWKS fetching

Plan section 2.3. Python reference: `612b1cb`. Round-trip coverage: **partial**.

## Contract

Keys are cached for 300 s; concurrent requests share one fetch; a slow refresh does not stall requests that
have cached keys; a failed fetch keeps the old keys and retries after 30 s; an empty but valid JWKS is
authoritative (rechecked after 30 s); a redirect is not followed; fetch timeout 10 s.

## Python reference

- `auth-proxy/proxy.py:134-251`

## Test

case `jwks_cache`: 50 concurrent requests, JWKS failing, redirect.

## Notes

The 300 s TTL itself is not waited out in the suite.
