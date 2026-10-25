#!/usr/bin/env python3
"""sessions_sigv4 against the AWS published SigV4 test suite.

Vector: `get-vanilla` from the AWS Signature Version 4 test suite, as published
in awslabs/aws-c-auth:
https://github.com/awslabs/aws-c-auth/tree/main/tests/aws-signing-test-suite/v4/get-vanilla
(header-canonical-request.txt, header-string-to-sign.txt,
header-signed-request.txt). The credentials are AWS's own documented example
pair, not a real key.

Usage: python3 test_sessions_sigv4.py
"""

from __future__ import annotations

import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import sessions_sigv4 as sv  # noqa: E402

ACCESS_KEY = "AKIDEXAMPLE"
SECRET_KEY = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
AMZ_DATE = "20150830T123600Z"
HEADERS = {"Host": "example.amazonaws.com", "X-Amz-Date": AMZ_DATE}

EXPECTED_CREQ = (
    "GET\n/\n\n"
    "host:example.amazonaws.com\nx-amz-date:20150830T123600Z\n\n"
    "host;x-amz-date\n"
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
EXPECTED_STS = (
    "AWS4-HMAC-SHA256\n20150830T123600Z\n20150830/us-east-1/service/aws4_request\n"
    "bb579772317eb040ac9ed261061d46c1f17a8133879d6129b6e1c25292927e63")
EXPECTED_AUTH = (
    "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, "
    "SignedHeaders=host;x-amz-date, "
    "Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31")


class GetVanilla(unittest.TestCase):
    def test_canonical_request(self):
        creq, signed = sv.canonical_request("GET", "/", "", HEADERS, sv.EMPTY_SHA256)
        self.assertEqual(creq, EXPECTED_CREQ)
        self.assertEqual(signed, "host;x-amz-date")

    def test_string_to_sign(self):
        creq, _ = sv.canonical_request("GET", "/", "", HEADERS, sv.EMPTY_SHA256)
        self.assertEqual(sv.string_to_sign(AMZ_DATE, "20150830/us-east-1/service/aws4_request", creq),
                         EXPECTED_STS)

    def test_authorization(self):
        got = sv.authorization("GET", "/", "", HEADERS, sv.EMPTY_SHA256, access_key=ACCESS_KEY,
                               secret_key=SECRET_KEY, region="us-east-1", service="service",
                               amz_date=AMZ_DATE)
        self.assertEqual(got, EXPECTED_AUTH)


class Helpers(unittest.TestCase):
    def test_query_is_sorted_and_encoded(self):
        self.assertEqual(sv.canonical_query([("prefix", "sessions/a b"), ("list-type", "2")]),
                         "list-type=2&prefix=sessions%2Fa%20b")

    def test_sign_headers_s3_shape(self):
        h = sv.sign_headers("PUT", "b.s3.ap-northeast-1.amazonaws.com", "/sessions/x", "", b"data",
                            access_key=ACCESS_KEY, secret_key=SECRET_KEY,
                            region="ap-northeast-1", amz_date=AMZ_DATE)
        self.assertEqual(h["x-amz-content-sha256"], sv.sha256_hex(b"data"))
        self.assertIn("SignedHeaders=host;x-amz-content-sha256;x-amz-date", h["authorization"])
        self.assertIn("/ap-northeast-1/s3/aws4_request", h["authorization"])


if __name__ == "__main__":
    unittest.main(verbosity=1)
