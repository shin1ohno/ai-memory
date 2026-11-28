# C-ES-3: Ranking and chunking

Plan section 2.4. Python reference: `612b1cb`. Round-trip coverage: **covered**.

## Contract

RRF with k=60 over the BM25 and kNN legs (each `max(50, 5*top_k)`), multiplied by a gaussian freshness
(offset 30 days for episodes, 180 otherwise, on `last_used_at` or `provenance.written_at`) and
`min(1+0.2*log10(1+use_count), 1.4)`; one hit per document. Chunks are 1200-character windows with 150
overlap preferring paragraph, line, sentence, space breaks past half the window; `content_hash` is md5 of
the text.

## Python reference

- `memory-mcp/scoring.py:27-118`
- `memory-mcp/es_backend.py:114-140`
- `memory-mcp/es_backend.py:576-594 (RRF, composite, one hit per doc_id)`

## Test

case `ranking`: 3 queries over 50 seeded documents (scores to 6 decimals) and a 30-paragraph ingest.
