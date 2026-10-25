"""AWS Signature Version 4 request signing, stdlib only (design spec §6.5).

The personal session archive lives in S3, and the memory-mcp venv deliberately
carries no AWS SDK (requirements-v2.txt). sessions_archive.S3Backend signs its
httpx requests with this module.

Header-based signing only. The canonical URI is taken as given (already
percent-encoded by the caller, segment by segment), which is S3's rule: S3 does
not double-encode the path and does not normalise it. Tested against the AWS
published `get-vanilla` vector in test_sessions_sigv4.py.
"""

from __future__ import annotations

import hashlib
import hmac
from urllib.parse import quote

ALGORITHM = "AWS4-HMAC-SHA256"
EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()


def _hmac(key: bytes, msg: str) -> bytes:
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_query(params) -> str:
    """params: iterable of (name, value) pairs, unencoded."""
    pairs = sorted((quote(str(k), safe="-_.~"), quote(str(v), safe="-_.~")) for k, v in params)
    return "&".join(f"{k}={v}" for k, v in pairs)


def _canonical_headers(headers: dict) -> tuple[str, str]:
    norm: dict[str, str] = {}
    for k, v in headers.items():
        name = k.strip().lower()
        val = " ".join(str(v).strip().split())
        norm[name] = f"{norm[name]},{val}" if name in norm else val
    names = sorted(norm)
    return "".join(f"{n}:{norm[n]}\n" for n in names), ";".join(names)


def canonical_request(method: str, path: str, query: str, headers: dict,
                      payload_hash: str) -> tuple[str, str]:
    """(canonical request, signed header list)."""
    canon_headers, signed = _canonical_headers(headers)
    creq = "\n".join([method.upper(), path or "/", query, canon_headers, signed, payload_hash])
    return creq, signed


def string_to_sign(amz_date: str, scope: str, creq: str) -> str:
    return "\n".join([ALGORITHM, amz_date, scope, sha256_hex(creq.encode("utf-8"))])


def signing_key(secret_key: str, date: str, region: str, service: str) -> bytes:
    k = _hmac(("AWS4" + secret_key).encode("utf-8"), date)
    k = _hmac(k, region)
    k = _hmac(k, service)
    return _hmac(k, "aws4_request")


def authorization(method: str, path: str, query: str, headers: dict, payload_hash: str, *,
                  access_key: str, secret_key: str, region: str, service: str,
                  amz_date: str) -> str:
    """The Authorization header value. `headers` must already contain every
    header that will be sent and signed (host, x-amz-date, and for S3
    x-amz-content-sha256)."""
    date = amz_date[:8]
    scope = f"{date}/{region}/{service}/aws4_request"
    creq, signed = canonical_request(method, path, query, headers, payload_hash)
    sts = string_to_sign(amz_date, scope, creq)
    sig = hmac.new(signing_key(secret_key, date, region, service), sts.encode("utf-8"),
                   hashlib.sha256).hexdigest()
    return f"{ALGORITHM} Credential={access_key}/{scope}, SignedHeaders={signed}, Signature={sig}"


def sign_headers(method: str, host: str, path: str, query: str, payload: bytes, *,
                 access_key: str, secret_key: str, region: str, service: str = "s3",
                 amz_date: str, extra_headers: dict | None = None) -> dict:
    """Headers for an S3 request: host, x-amz-date, x-amz-content-sha256,
    any extra headers, and Authorization."""
    payload_hash = sha256_hex(payload)
    headers = {"host": host, "x-amz-date": amz_date, "x-amz-content-sha256": payload_hash}
    for k, v in (extra_headers or {}).items():
        headers[k.lower()] = v
    headers["authorization"] = authorization(
        method, path, query, headers, payload_hash, access_key=access_key,
        secret_key=secret_key, region=region, service=service, amz_date=amz_date)
    return headers
