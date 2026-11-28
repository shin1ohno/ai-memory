# C-JWT-4: Grant classification and audience matrix

Plan section 2.3. Python reference: `612b1cb`. Round-trip coverage: **covered**.

## Contract

`grant = client_credentials` when `sub == client_id`, else `authorization_code`. With MEMORY_AUDIENCES set:
client_credentials needs `aud` (string or list) to intersect MEMORY_AUDIENCES and client_id in
ALLOWED_CLIENT_IDS; authorization_code needs sub in ALLOWED_SUBS and no aud. With MEMORY_AUDIENCES empty
nothing is enforced but the grant is still computed and forwarded.

## Python reference

- `auth-proxy/proxy.py:430-467`
- `systemd/memory-v2-proxy.service:27,37,42`

## Test

case `grant_matrix`.
