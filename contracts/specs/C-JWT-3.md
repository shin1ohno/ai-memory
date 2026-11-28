# C-JWT-3: Rotation

Plan section 2.3. Python reference: `612b1cb`. Round-trip coverage: **covered**.

## Contract

A signature mismatch forces one JWKS refetch and one more verification; a still-invalid signature opens a
30-second window in which further mismatches do not refetch.

## Python reference

- `auth-proxy/proxy.py:281-294`

## Test

case `rotation` (fetch counts).
