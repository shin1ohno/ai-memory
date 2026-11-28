# C-SES-8: Archive objects

Plan section 2.2. Python reference: `612b1cb`. Round-trip coverage: **not covered by run.py**.

## Contract

Object names, zstd level 3 with content size, canonical JSONL, per-chunk sha256, `X-Archive-Sha256`, the
tool-results tar; `archive_tampered` / `archive_incomplete` (409) and the 5 MiB decompression cap. Python and
Rust must read each other's objects.

## Python reference

- `memory-mcp/sessions_archive.py:75-145`
- `memory-mcp/sessions_app.py:736-745,1316-1403 (archive reads; handlers at 1367, 1377)`

## Test

Not in run.py yet: needs fake S3 (SigV4) and GCS backends.
