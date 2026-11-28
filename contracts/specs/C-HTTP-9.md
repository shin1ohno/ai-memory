# C-HTTP-9: Listener and path forwarding

Plan section 2.2. Python reference: `612b1cb`. Round-trip coverage: **partial**.

## Contract

The proxy listens on `0.0.0.0:PORT` (8767 in the unit) and forwards every authenticated request to
`UPSTREAM_URL + path_qs` (the raw path and query as received; an empty `?` is dropped), method and body
unchanged. Redirects from the upstream go back to the client as is (not followed).

## Python reference

- `auth-proxy/proxy.py:68,472,527-538,624`
- `systemd/memory-v2-proxy.service:16-17`
- `home-monitor:devices.tf:398`

## Test

case `path_forwarding` (14 raw paths).

## Notes

The bind address 0.0.0.0 is not checked by the suite (it connects on 127.0.0.1); C-OPS-1 checks the listener on the host.
