# C-HOOK-2: Mirror ingest and forget

Plan section 2.5. Python reference: `612b1cb`. Round-trip coverage: **covered**.

## Contract

A sweep ingests each memory note with `dataset=file-memory` and `doc_key=<host>/<project-slug>/<basename>`
and no tags; a deleted note is forgotten by `(dataset, doc_key)`, scoped to the caller's own
`provenance.agent`.

## Python reference

- `hooks/mirror-file-memory.rb:516-540`
- `hooks/mirror-file-memory.rb:640,658`

## Test

case `ingest_forget`.
