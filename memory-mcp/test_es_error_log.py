#!/usr/bin/env python3
"""The ES-ERROR line names the kind of failure and never the content.

ES error bodies quote the failing input: a mapping error previews the field
value, a query-parse error echoes the query. The server's stderr goes to a
persistent log file on the host, so the line may carry the status, the method,
the ES path (without its query string), the configured ES user, `error.type`,
the root-cause types and the LENGTH of `reason` — and nothing from the body or
the request. Each case plants a marker in every place content could leak from
(reason, root_cause reason, caused_by, the request body, the query string) and
asserts the marker is absent from stderr while the diagnostic fields are there.

Needs the server venv (imports es_backend.py, which needs httpx).

Usage: python3 test_es_error_log.py
"""

from __future__ import annotations

import asyncio
import contextlib
import io
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
for k, v in (("ES_URL", "http://127.0.0.1:9200"), ("ES_PASSWORD", "stub-password"),
             ("ES_USER", "memory_mcp"), ("VOYAGE_API_KEY", "stub")):
    os.environ.setdefault(k, v)

import httpx  # noqa: E402

import es_backend as be  # noqa: E402

MARKER = "MARKER-7f3c9e1d-secret-document-text"

PASS = 0
FAIL = 0


def check(name: str, condition: bool, detail: str = "") -> None:
    global PASS, FAIL
    if condition:
        PASS += 1
        print(f"ok   {name}")
    else:
        FAIL += 1
        print(f"FAIL {name}" + (f" — {detail}" if detail else ""))


def run_es_call(status: int, content: bytes, method: str, path: str,
                body: dict | None, content_type: str = "application/json"):
    """Send one request through the real `_es_json` against a canned ES reply.

    Returns (stderr text, the exception `_es_json` raised or None).
    """

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(status, content=content,
                              headers={"content-type": content_type})

    async def go():
        client = httpx.AsyncClient(base_url=be.ES_URL,
                                   transport=httpx.MockTransport(handler))
        saved, be._es = be._es, client
        try:
            return await be._es_json(method, path, body)
        finally:
            be._es = saved
            await client.aclose()

    err = io.StringIO()
    exc = None
    with contextlib.redirect_stderr(err):
        try:
            asyncio.run(go())
        except Exception as e:  # noqa: BLE001 — the test inspects it
            exc = e
    return err.getvalue(), exc


def es_line(stderr: str) -> str:
    lines = [ln for ln in stderr.splitlines() if ln.startswith("ES-ERROR ")]
    return lines[0] if len(lines) == 1 else f"<{len(lines)} ES-ERROR lines: {stderr!r}>"


def test_marker_capture_positive_control():
    # The capture below must be able to see a marker at all, or every
    # "marker absent" assertion would pass vacuously.
    err = io.StringIO()
    with contextlib.redirect_stderr(err):
        print(f"control {MARKER}", file=sys.stderr, flush=True)
    check("positive control: a marker printed to stderr is captured",
          MARKER in err.getvalue())


def test_authz_reject_names_the_variant_not_the_reason():
    reason = (f"action [indices:data/write/update/byquery] is unauthorized for "
              f"user [memory_mcp] with roles [memory_rw] on indices "
              f"[memory-knowledge], {MARKER}")
    body = {"error": {"root_cause": [{"type": "security_exception", "reason": reason}],
                      "type": "security_exception", "reason": reason},
            "status": 403}
    stderr, exc = run_es_call(
        403, json.dumps(body).encode(), "POST",
        f"/memory-knowledge/_update_by_query?refresh=true&q={MARKER}",
        {"query": {"term": {"doc_key": MARKER}}})
    line = es_line(stderr)
    check("403: the call still raises HTTPStatusError",
          isinstance(exc, httpx.HTTPStatusError), repr(exc))
    check("403: marker absent from stderr", MARKER not in stderr, line)
    check("403: status, method and path without query string",
          "ES-ERROR status=403 POST /memory-knowledge/_update_by_query es_user=" in line, line)
    check("403: configured ES user, not the password",
          "es_user=memory_mcp" in line and "stub-password" not in stderr, line)
    check("403: error.type and root-cause type",
          "error_type=security_exception root_cause=security_exception" in line, line)
    check("403: reason length, not reason", f"reason_len={len(reason)}" in line, line)
    check("403: no body= field any more", "body=" not in line, line)


def test_mapping_error_does_not_preview_the_document():
    reason = f"failed to parse field [content] of type [text] in document with id 'x'. Preview of field's value: '{MARKER}'"
    body = {"error": {
        "root_cause": [{"type": "document_parsing_exception", "reason": reason},
                       {"type": "document_parsing_exception", "reason": reason}],
        "type": "document_parsing_exception", "reason": reason,
        "caused_by": {"type": "illegal_argument_exception", "reason": MARKER}},
        "status": 400}
    stderr, exc = run_es_call(400, json.dumps(body).encode(), "POST",
                              "/memory-fact/_doc?refresh=wait_for",
                              {"content": MARKER})
    line = es_line(stderr)
    check("400 mapping: raises", isinstance(exc, httpx.HTTPStatusError), repr(exc))
    check("400 mapping: marker absent from stderr", MARKER not in stderr, line)
    check("400 mapping: duplicate root-cause types collapse",
          "error_type=document_parsing_exception root_cause=document_parsing_exception reason_len=" in line,
          line)


def test_query_parse_error_does_not_echo_the_search_term():
    reason = f"Failed to parse query [{MARKER}]"
    body = {"error": {"root_cause": [{"type": "query_shard_exception", "reason": reason}],
                      "type": "search_phase_execution_exception",
                      "reason": "all shards failed",
                      "failed_shards": [{"reason": {"type": "query_shard_exception",
                                                    "reason": reason}}]},
            "status": 400}
    stderr, _ = run_es_call(400, json.dumps(body).encode(), "POST",
                            "/memory-all/_search",
                            {"query": {"match": {"content": MARKER}}})
    line = es_line(stderr)
    check("400 query: marker absent from stderr", MARKER not in stderr, line)
    check("400 query: top-level and root-cause types both named",
          "error_type=search_phase_execution_exception root_cause=query_shard_exception "
          f"reason_len={len('all shards failed')}" in line, line)


def test_non_json_body_is_not_echoed():
    html = f"<html><body>502 Bad Gateway {MARKER}</body></html>".encode()
    stderr, exc = run_es_call(502, html, "GET", "/memory-fact/_count", None,
                              content_type="text/html")
    line = es_line(stderr)
    check("non-JSON: raises", isinstance(exc, httpx.HTTPStatusError), repr(exc))
    check("non-JSON: marker absent from stderr", MARKER not in stderr, line)
    check("non-JSON: only the body length",
          f"error_type=? root_cause=? reason_len=? body_len={len(html)}" in line, line)


def test_string_error_and_hostile_type_fields():
    stderr, _ = run_es_call(500, json.dumps({"error": MARKER, "status": 500}).encode(),
                            "POST", "/_bulk", None)
    line = es_line(stderr)
    check("string error: marker absent", MARKER not in stderr, line)
    check("string error: length only",
          f"error_type=? root_cause=? reason_len={len(MARKER)}" in line, line)

    snake = "marker_7f3c9e1d_secret_document_text"  # identifier-shaped, no _exception
    body = {"error": {"type": f"x {MARKER}", "reason": 7,
                      "root_cause": [{"type": MARKER.replace("-", "_")}, {"type": snake},
                                     "not-a-dict"]}}
    stderr, _ = run_es_call(400, json.dumps(body).encode(), "POST", "/memory-all/_search", None)
    line = es_line(stderr)
    check("hostile types: marker absent",
          MARKER not in stderr and MARKER.replace("-", "_") not in stderr
          and snake not in stderr, line)
    check("hostile types: replaced by ?",
          "error_type=? root_cause=? reason_len=?" in line, line)


def test_success_logs_nothing():
    stderr, exc = run_es_call(200, json.dumps({"count": 3, "q": MARKER}).encode(),
                              "GET", "/memory-fact/_count", None)
    check("200: no exception", exc is None, repr(exc))
    check("200: nothing on stderr", stderr == "", repr(stderr))


if __name__ == "__main__":
    test_marker_capture_positive_control()
    test_authz_reject_names_the_variant_not_the_reason()
    test_mapping_error_does_not_preview_the_document()
    test_query_parse_error_does_not_echo_the_search_term()
    test_non_json_body_is_not_echoed()
    test_string_error_and_hostile_type_fields()
    test_success_logs_nothing()
    print(f"\n---- pass={PASS} fail={FAIL}")
    sys.exit(1 if FAIL else 0)
