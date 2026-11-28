# C-SES-9: Purge ordering

Plan section 2.2. Python reference: `612b1cb` (unchanged at `17debf2`). Round-trip coverage: **covered**.

## Contract

Purge flips the session doc to a marker with a conditional write first, then deletes objects, then
messages; a competing writer loses the conditional write and removes what it wrote; purged sessions refuse
ingest/blob/state with 409 `purged` (also after restart, from the marker); `DELETE /purged` clears the
marker; the tombstone keeps no title, cwd or chunk list.

In detail, as the round trip checks it (two server processes on one ES and one archive):

- `DELETE /session` answers `{"deleted_docs", "deleted_objects"}`. Its writes happen in this order: the
  session doc's conditional write (`if_seq_no`) to the purged form, the object list (paged), one delete
  per object, then `_delete_by_query` on the messages.
- The tombstone has exactly `session_key`, `host`, `purged_at`, `purged_by`.
- After a purge, ingest, blob and state answer 409 `purged` from the purging process, from another
  process that only sees the marker, and after a restart. `GET /archive` answers 404 `not_found`.
- `DELETE /purged` answers `{"cleared": true}` and removes the marker; the key can be ingested again;
  a second `DELETE /purged` answers 404 `not_purged`.
- A writer in another process whose ingest is in flight when the purge runs:
  - its object PUT landed before the purge, it loses its conditional session write: it deletes its message
    ids (`_bulk` delete) and its object, and answers 409 `purged`;
  - its object PUT lands after the purge: it re-reads the doc, deletes its object, and answers 409 `purged`.
  Either way no object and no message of the session is left.

## Python reference

- `memory-mcp/sessions_app.py:423-545` (write-then-verify, guarded write, tombstone, flip)
- `memory-mcp/sessions_app.py:1414-1461` (`DELETE /session`, `DELETE /purged`)

## Test

case `purge_ordering` (`tests/http_roundtrip/cases_archive.py`), with the fake S3 of C-SES-8. The two
competing writers are made deterministic by holding the first writer's request in the fake (ES `_bulk`,
or the archive PUT) until the purge has answered.

## Notes

- The timeline compares writes only. How often an implementation re-reads the session doc is not the
  contract.
- Observed, not part of the contract: a Python process that refused a key keeps refusing it after
  another process clears the marker, until it restarts (its in-process purged set). The case re-ingests
  through the process that cleared the marker.
- C-SES-7's case also exercises one purge (`DELETE /session`) and its response shape.
- remask's object rewrite and its rollback on ES errors are outside this contract's case (PR #38 owns
  `sessions_maint.py`).
