# C-MCP-7: CLIENT_POLICY

Plan section 2.1. Python reference: `612b1cb`. Round-trip coverage: **covered**.

## Contract

Grammar `client=tool,tool@dataset|dataset;...`, no whitespace. Only `ingest` and `forget` may be granted
(DATASET_SCOPED_TOOLS); any other tool, a duplicate, a stray `;`, or datasets without tools makes the
policy invalid. Unset = gate off (`AUDIT policy_unset` at startup). Set but invalid = every
client_credentials call denied (`AUDIT policy_invalid reason=...`). authorization_code is never gated. A
client_credentials call is allowed only when the client is listed, the tool granted, no `tags` argument,
any `dataset` argument is a granted string, and for ingest the dataset is granted and `document` is a
string of at most 45,000 characters. A restricted ingest is always synchronous (never a job_id). Missing or
unknown grant header = deny.

## Python reference

- `memory-mcp/identity.py:168-299 (grammar, parser)`
- `memory-mcp/identity.py:328-354 (startup lines)`
- `memory-mcp/identity.py:375-437 (authorize_tool, allowed_datasets)`
- `memory-mcp/server.py:258-266 (restricted ingest is synchronous)`
- `systemd/memory-mcp-v2.service:41 (deployed value)`

## Test

case `client_policy`: 19-row table through HTTP, invalid and unscoped policies, unset policy.

## Notes

The plan asks to convert the 116 cases of memory-mcp/test_client_policy.py into a language-independent table. This suite carries a 19-row table that exercises every branch of authorize_tool over HTTP; converting all 116 rows is left for the freeze PR (report.md, remaining work).
