# C-SES-6: Ingest protocol

Plan section 2.2. Python reference: `612b1cb`. Round-trip coverage: **partial**.

## Contract

Request `{client:{host, redact_version}, file:{session_id, project_dir, jsonl_path, source, kind, [agent_id,
parent_session_id]}, segment:{generation, offset, end_offset, sha256, lines}}`. `client.host` must be the
caller's host (403 `host_mismatch`); `segment.sha256` is sha256 of the lines each followed by `\n` (422
`sha256_mismatch`); a bad line is 422 with `lines` and `kinds`. Success answers exactly `session_key`,
`indexed`, `next_offset`, `archive`. A retry of an accepted segment answers the same; within a generation
only the next offset is accepted (else 409 `offset_mismatch` with `expected_offset`); an older generation is
409 `stale_generation`; a newer one only at offset 0. A subagent stream has its own cursor. With no archive
backend configured and no `SESSION_ARCHIVE_BACKEND=none`, main segments are 503 `archive_unavailable`.

## Python reference

- `memory-mcp/sessions_app.py:999-1215 (ingest)`
- `memory-mcp/sessions_archive.py:292-300 (archive_disabled)`
- `session-search:ccs/ingest.py:10,355-358`

## Test

case `ingest_protocol` with `SESSION_ARCHIVE_BACKEND=none` (and unset for the 503).

## Notes

Not exercised yet: archive-dependent parts (the same object id on retry, invalidation of later chunks in the archive) need a fake S3/GCS; see C-SES-8.
