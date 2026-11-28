# C-EMB-1: Embedding client

Plan section 2.7. Python reference: `612b1cb`. Round-trip coverage: **covered**.

## Contract

`EMBEDDING_PROVIDER=voyage` (default) posts `{model, input, input_type: document|query, output_dimension}`
to `VOYAGE_ENDPOINT/embeddings` with `Authorization: Bearer <VOYAGE_API_KEY>`; `openai` posts
`{model, input, dimensions}`. Vectors are ordered by the response's `index`. A 5xx or connection failure is
retried once after 0.5 s; a 4xx is not retried. Inputs are sent in batches of at most 128.

## Python reference

- `memory-mcp/voyage.py:27-107`

## Test

case `embeddings`.

## Notes

The plan's "129 inputs -> 2 batches" is exercised with a document that chunks to 145 inputs (128 + 17).
