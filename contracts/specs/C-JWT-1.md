# C-JWT-1: Signature and issuer

Plan section 2.3. Python reference: `612b1cb`. Round-trip coverage: **covered**.

## Contract

Only RS256 is accepted (HS256, none and a tampered signature are 401). `iss` must be present and equal
OIDC_ISSUER. No leeway: a token expired one second ago, or with `nbf`/`iat` in the future, is 401. `aud` is
not part of signature verification (with MEMORY_AUDIENCES empty any aud passes).

## Python reference

- `auth-proxy/proxy.py:270-272 (decode options)`
- `auth-proxy/proxy.py:274-298 (verify)`

## Test

case `basic_validation`.
