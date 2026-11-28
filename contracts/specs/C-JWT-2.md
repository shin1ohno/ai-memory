# C-JWT-2: Key selection

Plan section 2.3. Python reference: `612b1cb`. Round-trip coverage: **covered**.

## Contract

The key is the JWKS entry whose `kid` equals the token header's `kid`; with no kid or an unknown kid the
first key of the JWKS is used. A JWKS entry without `kid` is stored as `default`. Non-RSA entries are
skipped.

## Python reference

- `auth-proxy/proxy.py:199-210`
- `auth-proxy/proxy.py:259-268`

## Test

case `kid_selection`.
