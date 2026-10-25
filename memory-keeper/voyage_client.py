"""Stdlib-only Voyage AI embedding client for the memory-keeper worker.

POST {VOYAGE_ENDPOINT}/embeddings with model=voyage-3-large, output_dimension=1024,
Bearer auth. 1 retry on 5xx/timeout, then raise VoyageUnavailable. Matches the
server-side voyage.py contract (§4) so keeper-generated vectors are compatible
with server-generated vectors (same model + dims + input_type semantics).
"""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request


class VoyageUnavailable(Exception):
    pass


def _post_embeddings(payload, timeout=30):
    endpoint = os.environ.get("VOYAGE_ENDPOINT", "https://api.voyageai.com/v1").rstrip("/")
    key = os.environ.get("VOYAGE_API_KEY", "")
    url = endpoint + "/embeddings"
    data = json.dumps(payload).encode("utf-8")
    headers = {"Authorization": f"Bearer {key}", "Content-Type": "application/json"}
    last = None
    for attempt in range(2):  # initial try + 1 retry
        try:
            req = urllib.request.Request(url, data=data, method="POST", headers=headers)
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            last = exc
            if 500 <= exc.code < 600 and attempt == 0:
                time.sleep(1.0)
                continue
            raise VoyageUnavailable(f"Voyage HTTP {exc.code}") from exc
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            last = exc
            if attempt == 0:
                time.sleep(1.0)
                continue
            raise VoyageUnavailable(f"Voyage request failed: {exc}") from exc
    raise VoyageUnavailable(f"Voyage unavailable: {last}")


def _embed(texts, input_type):
    model = os.environ.get("EMBEDDING_MODEL", "voyage-3-large")
    payload = {
        "model": model,
        "input": list(texts),
        "input_type": input_type,
        "output_dimension": 1024,
    }
    resp = _post_embeddings(payload)
    data = sorted(resp.get("data", []), key=lambda d: d.get("index", 0))
    return [d["embedding"] for d in data]


def embed_query(text):
    return _embed([text], "query")[0]


def embed_documents(texts, batch=128):
    texts = list(texts)
    out = []
    for i in range(0, len(texts), batch):
        out.extend(_embed(texts[i : i + batch], "document"))
    return out
