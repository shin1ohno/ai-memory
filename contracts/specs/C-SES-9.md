# C-SES-9: Purge ordering

Plan section 2.2. Python reference: `612b1cb`. Round-trip coverage: **not covered by run.py**.

## Contract

Purge flips the session doc to a marker with a conditional write first, then deletes objects, then
messages; a competing writer loses the conditional write and removes what it wrote; purged sessions refuse
ingest/blob/state with 409 `purged` (also after restart, from the marker); `DELETE /purged` clears the
marker; the tombstone keeps no title, cwd or chunk list.

## Python reference

- `memory-mcp/sessions_app.py:423-545`
- `memory-mcp/sessions_app.py:1414-1461`

## Test

Not in run.py yet: the ordering checks need the fake archive of C-SES-8.

## Notes

C-SES-7's case exercises one purge (`DELETE /session`) and its response shape.
