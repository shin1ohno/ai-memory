"""Minimal stdlib-only Elasticsearch client for the memory-keeper worker (mini).

No third-party deps (runs under macOS system /usr/bin/python3). Basic auth,
TLS verification off (self-signed home CA), JSON + NDJSON bodies. Only the
verbs the keeper needs: search / count / get / index / update / update_by_query
/ delete_by_query / bulk.

content_hash is ported VERBATIM from
the retired v1 es_backend.py (removed with the v1 stack; in git history) so facts written by
the keeper dedup against facts written by the server.
"""

from __future__ import annotations

import base64
import hashlib
import json
import math
import os
import ssl
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone


def now_iso() -> str:
    """UTC ISO8601 with a trailing Z (ES strict_date_optional_time compatible)."""
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def content_hash(text: str) -> str:
    # Ported verbatim from es-memory-mcp/es_backend.py::content_hash.
    return hashlib.md5(text.encode("utf-8")).hexdigest()


def cosine(a, b) -> float:
    """Pure-python cosine similarity between two equal-length float vectors."""
    if not a or not b or len(a) != len(b):
        return 0.0
    dot = 0.0
    na = 0.0
    nb = 0.0
    for x, y in zip(a, b):
        dot += x * y
        na += x * x
        nb += y * y
    if na == 0.0 or nb == 0.0:
        return 0.0
    return dot / (math.sqrt(na) * math.sqrt(nb))


class ESError(Exception):
    def __init__(self, status, body):
        super().__init__(f"ES HTTP {status}: {str(body)[:400]}")
        self.status = status
        self.body = body


class ESClient:
    def __init__(self, timeout: int = 30):
        self.base = os.environ.get("ES_URL", "https://192.168.1.77:9200").rstrip("/")
        user = os.environ.get("ES_USER", "elastic")
        pw = os.environ.get("ES_PASSWORD", "")
        token = base64.b64encode(f"{user}:{pw}".encode("utf-8")).decode("ascii")
        self._auth = f"Basic {token}"
        self._timeout = timeout
        verify = os.environ.get("ES_VERIFY_CERTS", "false").strip().lower() in ("1", "true", "yes")
        ctx = ssl.create_default_context()
        if not verify:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        self._ctx = ctx

    def _request(self, method, path, body=None, params=None):
        url = self.base + path
        if params:
            url = url + "?" + urllib.parse.urlencode(params)
        headers = {"Authorization": self._auth}
        data = None
        if body is not None:
            if isinstance(body, str):
                data = body.encode("utf-8")
                headers["Content-Type"] = "application/x-ndjson"
            else:
                data = json.dumps(body).encode("utf-8")
                headers["Content-Type"] = "application/json"
        req = urllib.request.Request(url, data=data, method=method, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=self._timeout, context=self._ctx) as resp:
                raw = resp.read().decode("utf-8")
                return json.loads(raw) if raw else {}
        except urllib.error.HTTPError as exc:
            raw = exc.read().decode("utf-8", "replace")
            raise ESError(exc.code, raw)

    # --- read ---
    def search(self, index, body):
        return self._request("POST", f"/{index}/_search", body)

    def count(self, index, query):
        return self._request("POST", f"/{index}/_count", {"query": query})

    def get(self, index, doc_id):
        return self._request("GET", f"/{index}/_doc/{urllib.parse.quote(str(doc_id), safe='')}")

    # --- write ---
    def index_doc(self, index, doc, refresh=None):
        params = {"refresh": refresh} if refresh is not None else None
        return self._request("POST", f"/{index}/_doc", doc, params=params)

    def update(self, index, doc_id, doc, refresh=None):
        params = {"refresh": refresh} if refresh is not None else None
        return self._request(
            "POST",
            f"/{index}/_update/{urllib.parse.quote(str(doc_id), safe='')}",
            {"doc": doc},
            params=params,
        )

    def update_by_query(self, index, body, refresh=None, conflicts="proceed"):
        params = {"conflicts": conflicts}
        if refresh is not None:
            params["refresh"] = refresh
        return self._request("POST", f"/{index}/_update_by_query", body, params=params)

    def delete_by_query(self, index, body, refresh=None, conflicts="proceed"):
        params = {"conflicts": conflicts}
        if refresh is not None:
            params["refresh"] = refresh
        return self._request("POST", f"/{index}/_delete_by_query", body, params=params)

    def bulk(self, lines, refresh=None):
        ndjson = "\n".join(json.dumps(line) for line in lines) + "\n"
        params = {"refresh": refresh} if refresh is not None else None
        return self._request("POST", "/_bulk", ndjson, params=params)
