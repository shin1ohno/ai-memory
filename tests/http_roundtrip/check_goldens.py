#!/usr/bin/env python3
"""Refuse golden files that carry secrets, tokens or personal data.

Run after every `run.py --capture` and before committing contracts/. It scans
contracts/golden/** and the JSON files directly under contracts/ for:

  - the suite's own test credentials (common.py), which must never be recorded;
  - JWTs, PEM blocks, bearer/basic credentials, AWS-style key ids;
  - long hex or base64 runs that are not one of the documented deterministic
    hashes (md5 content_hash, the sha256 of a sessions segment, sk_ keys);
  - e-mail addresses outside example.test, private IPv4 addresses, the
    production host names, and local file-system paths (run logs, home directories).

Prints one line per finding and a summary; exit status 1 when anything is found.
`--self-test` runs the scanner's positive and negative controls instead.
Standard library only.
"""

from __future__ import annotations

import glob
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, HERE)

import common  # noqa: E402

TEST_SECRETS = {
    "proxy secret": common.PROXY_SECRET,
    "mirror client secret": common.MIRROR_SECRET,
    "ES password": "roundtrip-es-password",
    "Voyage key": "roundtrip-voyage-key",
    "HS256 test key": "roundtrip-hs-key",
    "S3 test secret key": "roundtrip-s3-secret-key",
    "GCS test token": "roundtrip-gcs-access-token",
    "ccs client secret": "roundtrip-ccs-client-secret",
    "ccs HMAC key": "roundtrip-ccs-hmac-key",
}
PATTERNS = {
    "jwt": re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"),
    "pem": re.compile(r"-----BEGIN [A-Z ]+-----"),
    # A WWW-Authenticate challenge (`Bearer resource_metadata=...`, `Bearer error=...`)
    # is not a credential; anything else after the scheme is.
    "bearer credential": re.compile(r"(?i)\b(bearer|basic)\s+(?!resource_metadata=|error=)[A-Za-z0-9._~+/=-]{12,}"),
    "aws key id": re.compile(r"\b(AKIA|ASIA)[A-Z0-9]{16}\b"),
    "email": re.compile(r"[A-Za-z0-9._%+-]+@([A-Za-z0-9-]+\.)+[A-Za-z]{2,}"),
    "private ipv4": re.compile(r"\b(10|192\.168|172\.(1[6-9]|2\d|3[01]))\.\d{1,3}\.\d{1,3}(\.\d{1,3})?\b"),
    "production host": re.compile(r"(?i)\b([a-z0-9-]+\.)*ohno\.be\b|\bmcp-proxy\b|\bct ?119\b"),
    "local path": re.compile(r"(/home/|/Users/|/tmp/|/private/var/)[^\s\"']*"),
    "long base64": re.compile(r"[A-Za-z0-9+/_-]{48,}={0,2}"),
    "long hex": re.compile(r"\b[0-9a-f]{40,}\b"),
}
# Deterministic values the contracts record on purpose: md5 content hashes (32 hex,
# below the 40-character threshold), sha256 of a synthetic segment, opaque session keys.
ALLOWED = [
    re.compile(r"^[0-9a-f]{64}$"),           # sha256 of synthetic test bytes
    re.compile(r"^sk_[a-z2-7]{32}$"),        # sessions_app.make_session_key of synthetic input
]


def allowed(token: str) -> bool:
    return any(p.match(token) for p in ALLOWED)


def scan_text(path, text):
    findings = []
    for label, secret in TEST_SECRETS.items():
        if secret in text:
            findings.append((label, secret))
    for label, pat in PATTERNS.items():
        for m in pat.finditer(text):
            token = m.group(0)
            if label == "email" and token.lower().endswith("@example.test"):
                continue
            if label in ("long hex", "long base64") and allowed(token):
                continue
            findings.append((label, token[:80]))
    return [(path, label, tok) for label, tok in findings]


SELF_TEST = {
    "jwt": '{"t": "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ4In0.c2lnbmF0dXJl"}',
    "proxy secret": '{"x-proxy-secret": "%s"}' % common.PROXY_SECRET,
    "mirror client secret": "MEMORY_MIRROR_CLIENT_SECRET=%s" % common.MIRROR_SECRET,
    "pem": "-----BEGIN RSA PRIVATE KEY-----",
    "bearer credential": '{"authorization": "Bearer abcdefghijklmnop.qrstuv"}',
    "aws key id": "AKIAABCDEFGHIJKLMNOP",
    "email": '{"sub": "someone@gmail.com"}',
    "private ipv4": "http://192.168.1.83:9100",
    "production host": "https://mcp.ohno.be/memory",
    "local path": '{"log": "/tmp/http-roundtrip-x/mcp.log"}',
    "long base64": "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVphYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5eg==",
    "long hex": "0123456789abcdef0123456789abcdef01234567",
}


def self_test():
    """Positive and negative controls: each planted sample must be found under its
    label, and the allowed shapes and challenge strings must not be."""
    bad = 0
    for label, sample in SELF_TEST.items():
        got = {lab for _p, lab, _t in scan_text("sample", sample)}
        ok = label in got
        bad += not ok
        print(f"{'ok  ' if ok else 'MISS'} positive {label}: found {sorted(got)}")
    for sample in ('Bearer resource_metadata="https://issuer.example.test/x"',
                   'Bearer error="invalid_token", resource_metadata="x"', "operator@example.test",
                   "sk_cl5ipwq6ren5qn6azv6mbwnlxtrqycq7", "a" * 0 + "f" * 64):
        got = scan_text("sample", sample)
        ok = not got
        bad += not ok
        print(f"{'ok  ' if ok else 'HIT '} negative {sample[:40]!r}: {got}")
    print(f"check_goldens --self-test: failures={bad}")
    return 1 if bad else 0


def main():
    if "--self-test" in sys.argv[1:]:
        return self_test()
    files = sorted(glob.glob(os.path.join(REPO, "contracts", "golden", "**", "*.json"), recursive=True))
    files += sorted(glob.glob(os.path.join(REPO, "contracts", "*.json")))
    findings = []
    for path in files:
        with open(path, encoding="utf-8") as fh:
            text = fh.read()
        json.loads(text)  # every golden must be valid JSON
        findings += scan_text(os.path.relpath(path, REPO), text)
    for path, label, tok in findings:
        print(f"FINDING {label}: {path}: {tok}")
    print(f"check_goldens: files={len(files)} findings={len(findings)}")
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
