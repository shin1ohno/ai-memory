"""Async embedding client for memory-mcp v2 (contract §4).

The single external-AI dependency. 1024 dims, cosine. Two provider shapes,
selected by EMBEDDING_PROVIDER (default "voyage"):

- "voyage" (default): Voyage's native /embeddings body with asymmetric
  input_type (query vs document) and output_dimension. This is what the hosted
  es-memory (CT119) uses — unchanged.
- "openai": OpenAI-compatible /embeddings body ({model, input, dimensions}, no
  input_type — OpenAI/Vertex embeddings are symmetric). Used by the air local
  store routed through Mercari's LiteLLM gateway (litellm.mercari.in) so work
  content embeds via a sanctioned egress path instead of api.voyageai.com. The
  bearer key still comes from VOYAGE_API_KEY (holds the LiteLLM key on this path).

No official SDK — raw httpx against the REST endpoint (design v3: no voyageai
package). One retry on 5xx/timeout, then raise VoyageUnavailable. recall catches
this and degrades to BM25-only; write paths re-raise as an MCP tool error (503).
"""

from __future__ import annotations

import asyncio
import os

import httpx

VOYAGE_API_KEY = os.environ["VOYAGE_API_KEY"]
VOYAGE_ENDPOINT = os.environ.get("VOYAGE_ENDPOINT", "https://api.voyageai.com/v1").rstrip("/")
EMBEDDING_MODEL = os.environ.get("EMBEDDING_MODEL", "voyage-3-large")
# "voyage" (native input_type/output_dimension) or "openai" (OpenAI-compatible
# {model, input, dimensions}). Default keeps hosted es-memory on Voyage.
EMBEDDING_PROVIDER = os.environ.get("EMBEDDING_PROVIDER", "voyage").lower()
# Contract fixes the output dimension at 1024 (int8_hnsw index). EMBEDDING_DIMENSIONS
# is read for parity with the ES mapping; both default to 1024.
OUTPUT_DIMENSION = int(os.environ.get("EMBEDDING_DIMENSIONS", "1024"))
BATCH_MAX = 128


class VoyageUnavailable(Exception):
    """Raised when an embedding cannot be obtained (5xx/timeout after 1 retry,
    or a non-retryable 4xx such as a bad key)."""


_client = httpx.AsyncClient(
    base_url=VOYAGE_ENDPOINT,
    headers={"Authorization": f"Bearer {VOYAGE_API_KEY}"},
    timeout=httpx.Timeout(connect=5.0, read=30.0, write=30.0, pool=5.0),
)


async def _post_embeddings(inputs: list[str], input_type: str) -> list[list[float]]:
    """POST a single batch (<=128) to /embeddings and return vectors ordered by
    the response `index` field. 1 retry on transient failure."""
    if not inputs:
        return []
    if EMBEDDING_PROVIDER == "openai":
        # OpenAI-compatible (LiteLLM): symmetric, `dimensions` (not
        # `output_dimension`), no `input_type`. input_type is accepted but ignored.
        body = {
            "model": EMBEDDING_MODEL,
            "input": inputs,
            "dimensions": OUTPUT_DIMENSION,
        }
    else:
        body = {
            "model": EMBEDDING_MODEL,
            "input": inputs,
            "input_type": input_type,
            "output_dimension": OUTPUT_DIMENSION,
        }
    last_exc: Exception | None = None
    for attempt in range(2):  # initial try + 1 retry
        try:
            resp = await _client.post("/embeddings", json=body)
        except (httpx.TimeoutException, httpx.TransportError) as exc:
            last_exc = exc
            if attempt == 0:
                await asyncio.sleep(0.5)
            continue
        if resp.status_code >= 500:
            last_exc = VoyageUnavailable(f"Voyage {resp.status_code}: {resp.text[:200]}")
            if attempt == 0:
                await asyncio.sleep(0.5)
            continue
        if resp.status_code >= 400:
            # 4xx (bad key, bad request) is not retryable — surface immediately.
            raise VoyageUnavailable(f"Voyage {resp.status_code}: {resp.text[:200]}")
        data = resp.json().get("data", [])
        return [item["embedding"] for item in sorted(data, key=lambda d: d["index"])]
    raise VoyageUnavailable("Voyage embeddings unavailable after retry") from last_exc


async def embed_query(text: str) -> list[float]:
    """Embed a single query string (input_type='query')."""
    out = await _post_embeddings([text], "query")
    return out[0]


async def embed_documents(texts: list[str], batch: int = BATCH_MAX) -> list[list[float]]:
    """Embed stored content in batches of <=128 (input_type='document')."""
    if not texts:
        return []
    batch = min(batch, BATCH_MAX)
    results: list[list[float]] = []
    for i in range(0, len(texts), batch):
        results.extend(await _post_embeddings(texts[i:i + batch], "document"))
    return results
