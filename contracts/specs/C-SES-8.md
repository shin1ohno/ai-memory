# C-SES-8: Archive objects

Plan section 2.2. Python reference: `612b1cb` (unchanged at `17debf2`). Round-trip coverage: **covered**.

## Contract

Object names, zstd level 3 with content size, canonical JSONL, per-chunk sha256, `X-Archive-Sha256`, the
tool-results tar; `archive_tampered` / `archive_incomplete` (409) and the 5 MiB decompression cap. Python and
Rust must read each other's objects.

In detail, as the round trip checks it against both backends (`SESSION_ARCHIVE_BACKEND=s3` and `gcs`):

- A main segment is one object, `sessions/<host>/<session_key>/g<generation>/<offset:012d>.jsonl.zst`; a
  tool-results side file is `sessions/<host>/<session_key>/tool-results/<name>.zst`.
- Each object is one zstd frame whose header carries the content size, equal to the chunk's `bytes` in
  the session doc. The chunk's `sha256` is the sha256 of the decompressed bytes.
- `GET /archive` answers the highest generation's chunks concatenated (`application/x-ndjson`), the
  canonical JSONL byte for byte (golden), with `X-Archive-Sha256` = sha256 of the body.
- `GET /archive/tool-results` answers a tar (`application/x-tar`): one regular member per side file,
  sorted by name, mode `0600`, the stored content.
- Reading accepts any valid zstd frame: frames of raw blocks written by another encoder read the same.
- A chunk whose bytes do not match its sha256, an object that is not zstd, or one that expands past
  5 MiB: 409 `archive_tampered`. A missing segment object: 409 `archive_incomplete`, and the session doc's
  `archive_complete` becomes false (it stays 409 after the object comes back). A missing side file: 409
  `archive_incomplete`. The store answering 5xx: 503 `archive_unavailable`.
- s3: virtual-hosted `https://<bucket>.s3.<region>.amazonaws.com`, every request SigV4 header-signed over
  `host;x-amz-content-sha256;x-amz-date` with the body's sha256; ListObjectsV2 with continuation tokens.
  gcs: `https://storage.googleapis.com` JSON API (`uploadType=media` upload, `alt=media` read, paged
  list), with a bearer token fetched once from the metadata server (`Metadata-Flavor: Google`).

## Python reference

- `memory-mcp/sessions_archive.py:75-145` (names, compress, bounded decompress)
- `memory-mcp/sessions_archive.py:162-298` (GCS and S3 backends), `memory-mcp/sessions_sigv4.py:81-93`
- `memory-mcp/sessions_app.py:736-745,1316-1403 (archive reads; handlers at 1367, 1377)`

## Test

cases `archive_objects_s3` and `archive_objects_gcs` (`tests/http_roundtrip/cases_archive.py`), against
the fake stores in `tests/http_roundtrip/fake_archive.py`. The fake S3 verifies each SigV4 signature from
the bytes on the wire with its own code (not `sessions_sigv4`); the case also runs the verifier's
negative controls (wrong secret, other body, other path).

## Notes

- Reaching the fakes: the backends have fixed hostnames and no endpoint setting, so the suite gives the
  server `HTTPS_PROXY` / `HTTP_PROXY` (with `NO_PROXY=127.0.0.1,localhost`) and a per-run CA in
  `SSL_CERT_FILE`; its proxy terminates TLS for the two storage hosts and refuses any other tunnel. An
  implementation is testable only if its HTTP client honours these variables, as httpx does. That is a
  test-harness requirement, not part of the production contract.
- zstd level 3 is not observable in the frame and is not tested; interchangeability is tested by reading
  frames from another encoder. Only the frame header (magic, content size) of the implementation's own
  objects is recorded, not their compressed bytes, so a different zstd library can pass.
- remask (`sessions_maint.py`) rewrites archive objects; its rollback is not exercised here (PR #38).
