# C-SES-1: Session routes and scopes

Plan section 2.2. Python reference: `612b1cb`. Round-trip coverage: **covered**.

## Contract

`/memory/sessions/v1` has exactly ten routes, each needing one scope: `POST /ingest`, `POST /blob`,
`POST /state` (sessions:ingest); `POST /search`, `GET /preview`, `GET /archive`,
`GET /archive/tool-results`, `GET /status` (sessions:read); `DELETE /session`, `DELETE /purged`
(sessions:purge). Any other method/path is 403 `forbidden`, as is a route whose scope the caller lacks.

## Python reference

- `memory-mcp/sessions_app.py:86-101 (ROUTES)`
- `memory-mcp/sessions_app.py:1519-1550 (gate)`
- `memory-mcp/server.py:384 (mount)`

## Test

case `route_scopes`: 12 method/paths x 3 identities.
