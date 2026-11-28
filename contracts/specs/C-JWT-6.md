# C-JWT-6: Time claims and claim types

Plan section 2.3. Python reference: `612b1cb`. Round-trip coverage: **covered**.

## Contract

`exp`, `nbf`, `iat` are compared like PyJWT 2.15.1: the claim truncated toward zero, the current time with
its fraction; reject `exp <= now`, `nbf > now`, `iat > now`. `iss` must be a string; `sub` and `jti`, when
present, strings.

## Python reference

- `auth-proxy/proxy.py:270-272`
- `plan evidence/rust/pyjwt-api_jwt-2.15.1.py:401,435,456,477,492,506,512`

## Test

case `time_claims`: requests aligned to N+0.1 s, retried when the decision spills past N+1.

## Notes

The plan's three intentional changes (exp required, non-numeric time claims refused, single-flight JWKS) are Rust-side tightenings; this suite records the Python answers, so a Rust run must treat those rows as known differences.
