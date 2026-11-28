"""Fake session-archive object stores (C-SES-8, C-SES-9), standard library only.

The archive backends address fixed hosts over https:
  s3:  https://<bucket>.s3.<region>.amazonaws.com   (SigV4-signed REST)
  gcs: https://storage.googleapis.com               (JSON API, bearer token)
       http://metadata.google.internal              (the token)
Neither backend has an endpoint setting, so the suite does not redirect them by
configuration. It runs one local forward proxy and hands the implementation
HTTPS_PROXY / HTTP_PROXY (NO_PROXY keeps 127.0.0.1 direct) and SSL_CERT_FILE
pointing at a CA issued for this run (tls_ca). A CONNECT to one of the storage
hosts is answered by terminating TLS with a leaf for that host and serving the
fake store inside the tunnel; a CONNECT anywhere else is refused (403) and
recorded, so an implementation that tries to reach a real host fails the case
instead of leaving the machine.

FakeArchive records every request with the operation it maps to, checks S3
SigV4 signatures independently of the implementation's signer (canonical
request rebuilt from the bytes on the wire), checks the GCS bearer token, and
pages list results one name per page so that pagination is exercised.

Behaviour switches (`mode`):
  fail  {op: status}       answer this status for put/get/delete/list
  hold  {"op", "match"}    stop the first matching request until release()

zstd: the suite has no zstd codec (stdlib only, Python 3.12). `frame()` writes
a valid zstd frame from raw and RLE blocks, which every decoder must read;
`frame_header()` reads the header fields of any frame.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import ssl
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qsl, quote, unquote, urlsplit
from xml.sax.saxutils import escape

from tls_ca import TlsCa

S3_BUCKET = "roundtrip-archive"
S3_REGION = "us-east-1"
S3_ACCESS_KEY = "ROUNDTRIPACCESSKEYID"
S3_SECRET_KEY = "roundtrip-s3-secret-key"
GCS_BUCKET = "roundtrip-archive-gcs"
GCS_TOKEN = "roundtrip-gcs-access-token"
S3_HOST = f"{S3_BUCKET}.s3.{S3_REGION}.amazonaws.com"
GCS_HOST = "storage.googleapis.com"
METADATA_HOST = "metadata.google.internal"

_CA = None
_CA_LOCK = threading.Lock()


def _ca():
    global _CA
    with _CA_LOCK:
        if _CA is None:
            _CA = TlsCa()
        return _CA


# --------------------------------------------------------------------------- #
# zstd frames (RFC 8878)
# --------------------------------------------------------------------------- #
ZSTD_MAGIC = b"\x28\xb5\x2f\xfd"
_BLOCK_MAX = 128 * 1024


def frame(data: bytes = b"", *, rle: tuple[int, int] | None = None, content_size: bool = True) -> bytes:
    """A single-segment zstd frame of raw blocks holding `data`, or, with
    rle=(byte, count), RLE blocks expanding to `count` copies of `byte`
    (a few bytes on the wire for any size: the decompression-cap probe)."""
    total = rle[1] if rle else len(data)
    if content_size:
        header = ZSTD_MAGIC + bytes([0xE0]) + total.to_bytes(8, "little")   # FCS 8 bytes, single segment
    else:
        header = ZSTD_MAGIC + bytes([0x00, 0x58])                          # window descriptor: 8 MiB
    blocks = bytearray()
    if rle:
        byte, left = rle
        while True:
            n = min(left, _BLOCK_MAX)
            left -= n
            blocks += (int(left == 0) | (1 << 1) | (n << 3)).to_bytes(3, "little") + bytes([byte])
            if left == 0:
                break
    else:
        pos = 0
        while True:
            piece = data[pos:pos + _BLOCK_MAX]
            pos += len(piece)
            last = pos >= len(data)
            blocks += (int(last) | (len(piece) << 3)).to_bytes(3, "little") + piece
            if last:
                break
    return header + bytes(blocks)


def frame_header(obj: bytes) -> dict:
    """The fields of a zstd frame header that the archive contract names."""
    if obj[:4] != ZSTD_MAGIC or len(obj) < 6:
        return {"zstd": False}
    fhd = obj[4]
    fcs_flag, single, checksum, dict_flag = fhd >> 6, (fhd >> 5) & 1, (fhd >> 2) & 1, fhd & 3
    pos = 5 + (0 if single else 1) + (0, 1, 2, 4)[dict_flag]
    size = (1 if single else 0, 2, 4, 8)[fcs_flag]
    content = None
    if size:
        content = int.from_bytes(obj[pos:pos + size], "little") + (256 if size == 2 else 0)
    return {"zstd": True, "content_size": content, "checksum": bool(checksum),
            "dictionary": dict_flag != 0}


# --------------------------------------------------------------------------- #
# SigV4 verification (independent of memory-mcp/sessions_sigv4.py)
# --------------------------------------------------------------------------- #
def _aws_quote(s: str) -> str:
    return quote(s, safe="-_.~")


def verify_sigv4(method: str, raw_path: str, headers: list, body: bytes, *,
                 access_key=S3_ACCESS_KEY, secret_key=S3_SECRET_KEY, region=S3_REGION) -> str | None:
    """None when the request carries a valid S3 SigV4 header signature, else
    the reason. The canonical request is rebuilt from what arrived."""
    hmap: dict[str, list[str]] = {}
    for k, v in headers:
        hmap.setdefault(k.lower(), []).append(v)
    auth = (hmap.get("authorization") or [""])[0]
    if not auth.startswith("AWS4-HMAC-SHA256 "):
        return "no AWS4-HMAC-SHA256 authorization"
    fields = dict(p.strip().split("=", 1) for p in auth[len("AWS4-HMAC-SHA256 "):].split(","))
    try:
        ak, date, reg, service, term = fields["Credential"].split("/")
        signed = fields["SignedHeaders"].split(";")
        signature = fields["Signature"]
    except (KeyError, ValueError):
        return "malformed authorization"
    amz_date = (hmap.get("x-amz-date") or [""])[0]
    if ak != access_key or reg != region or service != "s3" or term != "aws4_request":
        return "credential scope"
    if amz_date[:8] != date:
        return "x-amz-date outside the credential date"
    for required in ("host", "x-amz-date", "x-amz-content-sha256"):
        if required not in signed:
            return f"{required} not signed"
    if signed != sorted(signed):
        return "signed headers not sorted"
    if (hmap.get("x-amz-content-sha256") or [""])[0] != hashlib.sha256(body).hexdigest():
        return "x-amz-content-sha256 does not match the body"
    parts = urlsplit(raw_path)
    query = sorted((_aws_quote(unquote(k)), _aws_quote(unquote(v)))
                   for k, v in parse_qsl(parts.query, keep_blank_values=True))
    canon_headers = "".join(f"{n}:{','.join(' '.join(v.strip().split()) for v in hmap.get(n, []))}\n"
                            for n in signed)
    creq = "\n".join([method, parts.path or "/", "&".join(f"{k}={v}" for k, v in query),
                      canon_headers, ";".join(signed), hmap["x-amz-content-sha256"][0]])
    scope = f"{date}/{region}/s3/aws4_request"
    sts = "\n".join(["AWS4-HMAC-SHA256", amz_date, scope, hashlib.sha256(creq.encode()).hexdigest()])
    k = ("AWS4" + secret_key).encode()
    for part in (date, region, "s3", "aws4_request"):
        k = hmac.new(k, part.encode(), hashlib.sha256).digest()
    want = hmac.new(k, sts.encode(), hashlib.sha256).hexdigest()
    return None if hmac.compare_digest(want, signature) else "signature mismatch"


# --------------------------------------------------------------------------- #
# The proxy and the stores
# --------------------------------------------------------------------------- #
class Op:
    def __init__(self, backend, op, method, raw_path, headers, body, name=None):
        self.backend = backend      # s3 | gcs | metadata | refused
        self.op = op                # put | get | delete | list | token | connect | other
        self.method = method
        self.raw_path = raw_path
        self.headers = headers
        self.body = body
        self.name = name
        self.at = time.monotonic()
        self.status = None
        self.problem = None         # signature / token problem, None when fine

    def header(self, name):
        for k, v in self.headers:
            if k.lower() == name.lower():
                return v
        return None


class _Base(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_args):
        pass

    def _body(self):
        if self.headers.get("Transfer-Encoding", "").lower() == "chunked":
            out = bytearray()
            while True:
                size = int(self.rfile.readline().strip() or b"0", 16)
                if size == 0:
                    self.rfile.readline()
                    return bytes(out)
                out += self.rfile.read(size)
                self.rfile.readline()
        n = self.headers.get("Content-Length")
        return self.rfile.read(int(n)) if n else b""

    def reply(self, op, status, body=b"", ctype="application/json"):
        if isinstance(body, (dict, list)):
            body = json.dumps(body).encode()
        op.status = status
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)


class _Storage(_Base):
    """One TLS tunnel's requests, served by the store for `self.server.tunnel_host`."""

    def __init__(self, sock, addr, server, host):
        self.tunnel_host = host
        super().__init__(sock, addr, server)

    def _dispatch(self):
        fake = self.server.fake
        body = self._body()
        headers = list(self.headers.items())
        if self.tunnel_host == S3_HOST:
            fake._s3(self, self.command, self.path, headers, body)
        else:
            fake._gcs(self, self.command, self.path, headers, body)

    do_GET = do_PUT = do_POST = do_DELETE = do_HEAD = _dispatch


class _Proxy(_Base):
    def do_CONNECT(self):
        fake = self.server.fake
        host, _, port = self.path.rpartition(":")
        op = Op("refused", "connect", "CONNECT", self.path, list(self.headers.items()), b"")
        if host not in (S3_HOST, GCS_HOST) or port != "443":
            fake._record(op)
            self.reply(op, 403, {"error": "the suite refuses tunnels to other hosts"})
            return
        self.send_response(200, "Connection Established")
        self.end_headers()
        self.wfile.flush()
        try:
            tls = fake.tls.wrap_socket(self.connection, server_side=True)
        except (ssl.SSLError, OSError) as exc:
            op.backend, op.problem = "tls", f"{exc.__class__.__name__}: {exc}"
            fake._record(op)
            self.close_connection = True
            return
        try:
            _Storage(tls, self.client_address, self.server, host)
        finally:
            self.close_connection = True
            try:
                tls.close()
            except OSError:
                pass

    def _plain(self):
        fake = self.server.fake
        body = self._body()
        parts = urlsplit(self.path)
        headers = list(self.headers.items())
        if parts.hostname == METADATA_HOST:
            op = Op("metadata", "token", self.command, self.path, headers, body)
            fake._record(op)
            if self.headers.get("Metadata-Flavor") != "Google":
                op.problem = "Metadata-Flavor missing"
                self.reply(op, 403, {"error": "Metadata-Flavor: Google required"})
            elif parts.path != "/computeMetadata/v1/instance/service-accounts/default/token":
                self.reply(op, 404, {"error": "not found"})
            else:
                self.reply(op, 200, {"access_token": GCS_TOKEN, "expires_in": 3599, "token_type": "Bearer"})
            return
        op = Op("refused", "other", self.command, self.path, headers, body)
        fake._record(op)
        self.reply(op, 403, {"error": "the suite refuses plain requests to other hosts"})

    do_GET = do_PUT = do_POST = do_DELETE = do_HEAD = _plain


class FakeArchive:
    def __init__(self, workdir: str):
        os.makedirs(workdir, exist_ok=True)
        self.paths = _ca().issue([S3_HOST, GCS_HOST], workdir)
        self.tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.tls.load_cert_chain(self.paths["cert"], self.paths["key"])
        self.lock = threading.RLock()
        self.objects: dict[tuple[str, str], bytes] = {}    # (backend, name) -> bytes
        self.ops: list[Op] = []
        self.mode: dict = {}
        self._hold = None
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), _Proxy)
        self.httpd.daemon_threads = True
        self.httpd.fake = self
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    # -- what the implementation is given --------------------------------- #
    def env(self, backend: str) -> dict:
        env = {"HTTPS_PROXY": self.url, "HTTP_PROXY": self.url, "NO_PROXY": "127.0.0.1,localhost",
               "SSL_CERT_FILE": self.paths["ca"], "SESSION_ARCHIVE_BACKEND": backend}
        if backend == "s3":
            env.update({"SESSION_ARCHIVE_BUCKET": S3_BUCKET, "SESSION_ARCHIVE_AWS_REGION": S3_REGION,
                        "SESSION_ARCHIVE_AWS_ACCESS_KEY_ID": S3_ACCESS_KEY,
                        "SESSION_ARCHIVE_AWS_SECRET_ACCESS_KEY": S3_SECRET_KEY})
        elif backend == "gcs":
            env["SESSION_ARCHIVE_BUCKET"] = GCS_BUCKET
        return env

    # -- case helpers ----------------------------------------------------- #
    def reset(self):
        with self.lock:
            self.objects.clear()
            self.ops.clear()
            self.mode.clear()

    def names(self, backend, prefix=""):
        with self.lock:
            return sorted(n for b, n in self.objects if b == backend and n.startswith(prefix))

    def get(self, backend, name):
        with self.lock:
            return self.objects.get((backend, name))

    def put(self, backend, name, data):
        with self.lock:
            self.objects[(backend, name)] = bytes(data)

    def remove(self, backend, name):
        with self.lock:
            self.objects.pop((backend, name), None)

    def taken(self, pred=lambda o: True):
        with self.lock:
            return [o for o in self.ops if pred(o)]

    def hold(self, op, match=""):
        """Stop the next `op` request whose object name contains `match`
        until release(); arrived() waits until it is being held."""
        with self.lock:
            self._hold = {"op": op, "match": match, "arrived": threading.Event(),
                          "go": threading.Event()}
            return self._hold

    def release(self):
        with self.lock:
            h, self._hold = self._hold, None
        if h:
            h["go"].set()

    def close(self):
        self.release()
        self.httpd.shutdown()
        self.httpd.server_close()

    # -- internals -------------------------------------------------------- #
    def _record(self, op):
        with self.lock:
            self.ops.append(op)

    def _gate(self, op):
        with self.lock:
            h = self._hold
            hit = h is not None and h["op"] == op.op and h["match"] in (op.name or "") \
                and not h["arrived"].is_set()
            if hit:
                h["arrived"].set()
        if hit:
            h["go"].wait(30)
        return self.mode.get("fail", {}).get(op.op)

    def _s3(self, h, method, raw_path, headers, body):
        parts = urlsplit(raw_path)
        query = dict(parse_qsl(parts.query, keep_blank_values=True))
        name = unquote(parts.path[1:]) if parts.path not in ("", "/") else None
        kind = {"PUT": "put", "GET": "get", "DELETE": "delete"}.get(method, "other")
        if method == "GET" and name is None and query.get("list-type") == "2":
            kind = "list"
        op = Op("s3", kind, method, raw_path, headers, body, name if kind != "list" else query.get("prefix"))
        op.problem = verify_sigv4(method, raw_path, headers, body)
        if h.headers.get("Host") != S3_HOST:
            op.problem = op.problem or "Host header is not the virtual-hosted bucket host"
        self._record(op)
        if op.problem:
            h.reply(op, 403, b"<Error><Code>SignatureDoesNotMatch</Code></Error>", "application/xml")
            return
        fail = self._gate(op)
        if fail:
            h.reply(op, fail, b"<Error><Code>InternalError</Code></Error>", "application/xml")
            return
        if kind == "put":
            self.put("s3", name, body)
            h.reply(op, 200, b"", "application/xml")
        elif kind == "get":
            data = self.get("s3", name)
            if data is None:
                h.reply(op, 404, b"<Error><Code>NoSuchKey</Code></Error>", "application/xml")
            else:
                h.reply(op, 200, data, "application/octet-stream")
        elif kind == "delete":
            self.remove("s3", name)
            h.reply(op, 204, b"", "application/xml")
        elif kind == "list":
            names = self.names("s3", query.get("prefix", ""))
            after = query.get("continuation-token")
            if after:
                after = base64.urlsafe_b64decode(after.encode()).decode()
                names = [n for n in names if n > after]
            page, more = names[:1], len(names) > 1
            xml = ('<?xml version="1.0" encoding="UTF-8"?>'
                   '<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">'
                   f"<Name>{S3_BUCKET}</Name><Prefix>{escape(query.get('prefix', ''))}</Prefix>"
                   f"<KeyCount>{len(page)}</KeyCount><IsTruncated>{'true' if more else 'false'}</IsTruncated>"
                   + "".join(f"<Contents><Key>{escape(n)}</Key></Contents>" for n in page)
                   + (f"<NextContinuationToken>{base64.urlsafe_b64encode(page[-1].encode()).decode()}"
                      "</NextContinuationToken>" if more else "")
                   + "</ListBucketResult>")
            h.reply(op, 200, xml.encode(), "application/xml")
        else:
            h.reply(op, 400, b"<Error><Code>NotImplemented</Code></Error>", "application/xml")

    def _gcs(self, h, method, raw_path, headers, body):
        parts = urlsplit(raw_path)
        query = dict(parse_qsl(parts.query, keep_blank_values=True))
        segs = parts.path.split("/")
        kind, name = "other", None
        upload = f"/upload/storage/v1/b/{GCS_BUCKET}/o"
        base = f"/storage/v1/b/{GCS_BUCKET}/o"
        if method == "POST" and parts.path == upload and query.get("uploadType") == "media":
            kind, name = "put", query.get("name")
        elif method == "GET" and parts.path == base:
            kind, name = "list", query.get("prefix")
        elif parts.path.startswith(base + "/") and len(segs) == 7:
            name = unquote(segs[6])
            kind = {"GET": "get", "DELETE": "delete"}.get(method, "other")
            if kind == "get" and query.get("alt") != "media":
                kind = "other"
        op = Op("gcs", kind, method, raw_path, headers, body, name)
        if h.headers.get("Authorization") != f"Bearer {GCS_TOKEN}":
            op.problem = "bearer token missing or wrong"
        self._record(op)
        if op.problem:
            h.reply(op, 401, {"error": {"code": 401}})
            return
        fail = self._gate(op)
        if fail:
            h.reply(op, fail, {"error": {"code": fail}})
            return
        if kind == "put":
            self.put("gcs", name, body)
            h.reply(op, 200, {"bucket": GCS_BUCKET, "name": name, "size": str(len(body))})
        elif kind == "get":
            data = self.get("gcs", name)
            if data is None:
                h.reply(op, 404, {"error": {"code": 404}})
            else:
                h.reply(op, 200, data, "application/octet-stream")
        elif kind == "delete":
            if self.get("gcs", name) is None:
                h.reply(op, 404, {"error": {"code": 404}})
            else:
                self.remove("gcs", name)
                h.reply(op, 204)
        elif kind == "list":
            names = self.names("gcs", name or "")
            after = query.get("pageToken")
            if after:
                after = base64.urlsafe_b64decode(after.encode()).decode()
                names = [n for n in names if n > after]
            out = {"items": [{"name": n} for n in names[:1]]}
            if len(names) > 1:
                out["nextPageToken"] = base64.urlsafe_b64encode(names[0].encode()).decode()
            h.reply(op, 200, out)
        else:
            h.reply(op, 400, {"error": {"code": 400}})
