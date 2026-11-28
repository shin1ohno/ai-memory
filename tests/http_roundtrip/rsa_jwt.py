"""RS256 keys and JWTs with the standard library only.

The round-trip suite must run on a bare python3 and against any implementation,
so it cannot import PyJWT or cryptography to mint the tokens it sends. RSA
PKCS#1 v1.5 signing is a modular exponentiation over a fixed DigestInfo prefix,
which is small enough to write out. Keys are generated per run and never
written to disk: nothing secret is ever committed with the suite.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets

# DER prefix of DigestInfo for SHA-256 (RFC 8017 section 9.2, note 1).
_SHA256_PREFIX = bytes.fromhex("3031300d060960864801650304020105000420")

_SMALL_PRIMES = [p for p in range(3, 2000, 2) if all(p % d for d in range(3, int(p ** 0.5) + 1, 2))]


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _int_bytes(n: int) -> bytes:
    return n.to_bytes((n.bit_length() + 7) // 8, "big")


def _probable_prime(n: int, rounds: int = 40) -> bool:
    for p in _SMALL_PRIMES:
        if n % p == 0:
            return n == p
    d, r = n - 1, 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for _ in range(rounds):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def _prime(bits: int, e: int) -> int:
    while True:
        c = secrets.randbits(bits) | (1 << (bits - 1)) | (1 << (bits - 2)) | 1
        if c % e != 1 and _probable_prime(c):
            return c


class RsaKey:
    """A 2048-bit RSA key pair held in memory for one run."""

    def __init__(self, kid: str | None, bits: int = 2048):
        self.kid = kid
        self.e = 65537
        while True:
            p, q = _prime(bits // 2, self.e), _prime(bits // 2, self.e)
            n = p * q
            if p != q and n.bit_length() == bits:
                break
        self.n = n
        self.d = pow(self.e, -1, (p - 1) * (q - 1))
        self.size = (n.bit_length() + 7) // 8

    def jwk(self, with_kid: bool = True) -> dict:
        out = {"kty": "RSA", "alg": "RS256", "use": "sig",
               "n": b64url(_int_bytes(self.n)), "e": b64url(_int_bytes(self.e))}
        if with_kid and self.kid is not None:
            out["kid"] = self.kid
        return out

    def sign(self, message: bytes) -> bytes:
        t = _SHA256_PREFIX + hashlib.sha256(message).digest()
        em = b"\x00\x01" + b"\xff" * (self.size - len(t) - 3) + b"\x00" + t
        return pow(int.from_bytes(em, "big"), self.d, self.n).to_bytes(self.size, "big")


def _segment(obj: dict) -> str:
    return b64url(json.dumps(obj, separators=(",", ":")).encode("utf-8"))


def mint(claims: dict, key: RsaKey | None, *, alg: str = "RS256", kid="__key__",
         hs_secret: bytes = b"", tamper: bool = False) -> str:
    """A compact JWT. kid="__key__" uses the key's own kid, None omits it."""
    header = {"alg": alg, "typ": "JWT"}
    if kid == "__key__":
        kid = key.kid if key is not None else None
    if kid is not None:
        header["kid"] = kid
    signing_input = f"{_segment(header)}.{_segment(claims)}".encode("ascii")
    if alg == "RS256":
        sig = key.sign(signing_input)
    elif alg == "HS256":
        sig = hmac.new(hs_secret, signing_input, hashlib.sha256).digest()
    elif alg == "none":
        sig = b""
    else:
        raise ValueError(alg)
    if tamper:
        sig = bytes([sig[0] ^ 1]) + sig[1:]
    return signing_input.decode("ascii") + "." + b64url(sig)
