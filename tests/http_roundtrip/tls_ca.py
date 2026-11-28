"""A throwaway certificate authority with the standard library only.

The archive backends (C-SES-8) talk https to fixed hostnames
(<bucket>.s3.<region>.amazonaws.com, storage.googleapis.com). The suite reaches
them through its own forward proxy (fake_archive.FakeArchive), which terminates
TLS with a leaf certificate this module issues. The implementation under test
trusts the CA through SSL_CERT_FILE.

Python's ssl module cannot create certificates, and the suite must not depend
on `cryptography` or an openssl binary, so the X.509 DER is written out here:
a v3 CA (basicConstraints CA:true, keyCertSign) and a leaf signed by it
(SAN dNSName, serverAuth, CA:false), both sha256WithRSAEncryption and both with
key identifiers, which is what strict verifiers (OpenSSL's X509_STRICT,
webpki/rustls) require. Keys are generated per run; the PEM files live in the
run's temporary directory and are removed with it. Nothing here is committed.
"""

from __future__ import annotations

import base64
import hashlib
import os
import secrets
import time

from rsa_jwt import _SHA256_PREFIX, _prime


# --------------------------------------------------------------------------- #
# DER
# --------------------------------------------------------------------------- #
def _len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def _tlv(tag: int, body: bytes) -> bytes:
    return bytes([tag]) + _len(len(body)) + body


def _int(n: int) -> bytes:
    b = n.to_bytes(max(1, (n.bit_length() + 8) // 8), "big")  # leading 0 keeps it positive
    return _tlv(0x02, b)


def _seq(*parts: bytes) -> bytes:
    return _tlv(0x30, b"".join(parts))


def _oid(dotted: str) -> bytes:
    nums = [int(x) for x in dotted.split(".")]
    out = bytearray([40 * nums[0] + nums[1]])
    for n in nums[2:]:
        chunk = [n & 0x7F]
        n >>= 7
        while n:
            chunk.append(0x80 | (n & 0x7F))
            n >>= 7
        out += bytes(reversed(chunk))
    return _tlv(0x06, bytes(out))


def _bits(data: bytes, unused: int = 0) -> bytes:
    return _tlv(0x03, bytes([unused]) + data)


def _octets(data: bytes) -> bytes:
    return _tlv(0x04, data)


def _utc(t: float) -> bytes:
    return _tlv(0x17, time.strftime("%y%m%d%H%M%SZ", time.gmtime(t)).encode("ascii"))


def _name(cn: str) -> bytes:
    return _seq(_tlv(0x31, _seq(_oid("2.5.4.3"), _tlv(0x0C, cn.encode("utf-8")))))


_SHA256_RSA = _seq(_oid("1.2.840.113549.1.1.11"), b"\x05\x00")
_RSA = _seq(_oid("1.2.840.113549.1.1.1"), b"\x05\x00")


def _ext(oid: str, value: bytes, critical: bool = False) -> bytes:
    return _seq(_oid(oid), *([b"\x01\x01\xff"] if critical else []), _octets(value))


# --------------------------------------------------------------------------- #
# Keys and certificates
# --------------------------------------------------------------------------- #
class _Key:
    def __init__(self, bits: int = 2048):
        self.e = 65537
        while True:
            p, q = _prime(bits // 2, self.e), _prime(bits // 2, self.e)
            if p != q and (p * q).bit_length() == bits:
                break
        self.p, self.q, self.n = p, q, p * q
        self.d = pow(self.e, -1, (p - 1) * (q - 1))
        self.size = (self.n.bit_length() + 7) // 8

    def public_der(self) -> bytes:
        return _seq(_int(self.n), _int(self.e))

    def spki(self) -> bytes:
        return _seq(_RSA, _bits(self.public_der()))

    def key_id(self) -> bytes:
        return hashlib.sha1(self.public_der()).digest()  # RFC 5280 4.2.1.2 method (1)

    def sign(self, message: bytes) -> bytes:
        t = _SHA256_PREFIX + hashlib.sha256(message).digest()
        em = b"\x00\x01" + b"\xff" * (self.size - len(t) - 3) + b"\x00" + t
        return pow(int.from_bytes(em, "big"), self.d, self.n).to_bytes(self.size, "big")

    def private_pem(self) -> str:
        p, q, d = self.p, self.q, self.d
        der = _seq(_int(0), _int(self.n), _int(self.e), _int(d), _int(p), _int(q),
                   _int(d % (p - 1)), _int(d % (q - 1)), _int(pow(q, -1, p)))
        return _pem("RSA PRIVATE KEY", der)


def _pem(label: str, der: bytes) -> str:
    b64 = base64.b64encode(der).decode("ascii")
    lines = [b64[i:i + 64] for i in range(0, len(b64), 64)]
    return f"-----BEGIN {label}-----\n" + "\n".join(lines) + f"\n-----END {label}-----\n"


def _cert(subject_cn: str, subject_key: _Key, issuer_cn: str, issuer_key: _Key, exts: list) -> bytes:
    now = time.time()
    tbs = _seq(
        _tlv(0xA0, _int(2)),                       # v3
        _int(secrets.randbits(63) | 1),
        _SHA256_RSA,
        _name(issuer_cn),
        _seq(_utc(now - 3600), _utc(now + 2 * 86400)),
        _name(subject_cn),
        subject_key.spki(),
        _tlv(0xA3, _seq(*exts)),
    )
    return _seq(tbs, _SHA256_RSA, _bits(issuer_key.sign(tbs)))


class TlsCa:
    """issue(hosts, dir) writes ca.pem, leaf.pem and leaf.key and returns their
    paths. Generating the two 2048-bit keys takes a few seconds of pure Python,
    so the fake archive creates its CA lazily, once per run."""

    def __init__(self):
        self.key = _Key()
        cn = "http-roundtrip test CA"
        self.cn = cn
        kid = self.key.key_id()
        self.der = _cert(cn, self.key, cn, self.key, [
            _ext("2.5.29.19", _seq(b"\x01\x01\xff"), critical=True),       # CA:true
            _ext("2.5.29.15", _bits(b"\x06", 1), critical=True),           # keyCertSign, cRLSign
            _ext("2.5.29.14", _octets(kid)),
            _ext("2.5.29.35", _seq(_tlv(0x80, kid))),
        ])

    def issue(self, hosts: list[str], directory: str) -> dict:
        leaf = _Key()
        san = _seq(*[_tlv(0x82, h.encode("ascii")) for h in hosts])
        der = _cert(hosts[0], leaf, self.cn, self.key, [
            _ext("2.5.29.19", _seq(), critical=True),                      # CA:false
            _ext("2.5.29.15", _bits(b"\xa0", 5), critical=True),           # digitalSignature, keyEncipherment
            _ext("2.5.29.37", _seq(_oid("1.3.6.1.5.5.7.3.1"))),            # serverAuth
            _ext("2.5.29.17", san),
            _ext("2.5.29.14", _octets(leaf.key_id())),
            _ext("2.5.29.35", _seq(_tlv(0x80, self.key.key_id()))),
        ])
        paths = {"ca": os.path.join(directory, "roundtrip-ca.pem"),
                 "cert": os.path.join(directory, "roundtrip-leaf.pem"),
                 "key": os.path.join(directory, "roundtrip-leaf.key")}
        for k, text in (("ca", _pem("CERTIFICATE", self.der)), ("cert", _pem("CERTIFICATE", der)),
                        ("key", leaf.private_pem())):
            fd = os.open(paths[k], os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w", encoding="ascii") as fh:
                fh.write(text)
        return paths
