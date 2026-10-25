"""Session archive object storage (design spec §6.5 "Archive layout" / "Storage").

The archive is a masked copy of each main JSONL (and its tool-results/ side
files), compressed with zstd, kept for one year so a session can be resumed
from another host or after Claude Code's 30-day local cleanup.

Two backends, no SDK, selected by environment:

    SESSION_ARCHIVE_BACKEND = gcs | s3      (unset = archive disabled)
    SESSION_ARCHIVE_BUCKET  = <bucket>
    # s3 only
    SESSION_ARCHIVE_AWS_ACCESS_KEY_ID / SESSION_ARCHIVE_AWS_SECRET_ACCESS_KEY /
    SESSION_ARCHIVE_AWS_REGION

- gcs (work): httpx + an access token from the GCE metadata server (the instance
  SA already has objectAdmin on the bucket);
- s3 (personal): httpx + stdlib SigV4 (sessions_sigv4).

Every object name is built by `object_name`, from parts validated against the
§6.5 regexes. The result always starts with `sessions/`, has no dot segment, and
each segment is percent-quoted. Nothing from a request body reaches a name
without passing through it.

`zstandard` is imported lazily so that a server venv without it (work, until
its pip guard is updated) still imports sessions_app; archive calls then fail
with ArchiveUnavailable and the ingest is answered 503, holding the client's
cursor.
"""

from __future__ import annotations

import os
import re
import time
from datetime import datetime, timezone
from urllib.parse import quote
from xml.etree import ElementTree

import httpx

import sessions_sigv4

HOST_RE = re.compile(r"^[a-z0-9-]{1,63}$")
SESSION_ID_RE = re.compile(r"^[0-9a-f-]{36}$")
TOOL_RESULT_NAME_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9._-]{0,127}$")
SESSION_KEY_RE = re.compile(r"^sk_[a-z2-7]{32}$")

PREFIX = "sessions/"
ZSTD_LEVEL = 3
# A chunk is at most 5 MiB of masked input (the ingest decompression cap); a
# tool-results side file is bounded by the same wire limit.
MAX_CHUNK_OUTPUT = 5 * 1024 * 1024


class ArchiveError(Exception):
    pass


class ArchiveUnavailable(ArchiveError):
    """Backend not configured, zstandard missing, or the store answered 5xx /
    could not be reached."""


class ArchiveNotFound(ArchiveError):
    pass


class InvalidName(ArchiveError, ValueError):
    pass


# --------------------------------------------------------------------------- #
# Names
# --------------------------------------------------------------------------- #
def object_name(host: str, session_key: str, *, generation: int | None = None,
                offset: int | None = None, tool_result: str | None = None) -> str:
    """The single builder of archive object names.

    segment:     sessions/<host>/<session_key>/g<generation>/<offset:012d>.jsonl.zst
    side file:   sessions/<host>/<session_key>/tool-results/<name>.zst
    prefix only: sessions/<host>/<session_key>/      (both None)
    """
    if not isinstance(host, str) or not HOST_RE.fullmatch(host):
        raise InvalidName("invalid host")
    if not isinstance(session_key, str) or not SESSION_KEY_RE.fullmatch(session_key):
        raise InvalidName("invalid session_key")
    segs = [host, session_key]
    tail = ""
    if tool_result is not None:
        if generation is not None or offset is not None:
            raise InvalidName("tool_result excludes generation/offset")
        if not isinstance(tool_result, str) or not TOOL_RESULT_NAME_RE.fullmatch(tool_result):
            raise InvalidName("invalid tool-results name")
        segs += ["tool-results", f"{tool_result}.zst"]
    elif generation is not None or offset is not None:
        if (not isinstance(generation, int) or isinstance(generation, bool) or generation < 0
                or not isinstance(offset, int) or isinstance(offset, bool) or offset < 0
                or offset >= 10 ** 12):
            raise InvalidName("invalid generation/offset")
        segs += [f"g{generation}", f"{offset:012d}.jsonl.zst"]
    else:
        tail = "/"
    for s in segs:
        if s in ("", ".", "..") or "/" in s:
            raise InvalidName("invalid segment")
    name = PREFIX + "/".join(quote(s, safe="") for s in segs) + tail
    if not name.startswith(PREFIX) or any(p in (".", "..") for p in name.split("/")):
        raise InvalidName("name escapes sessions/")
    return name


# --------------------------------------------------------------------------- #
# Compression (bounded)
# --------------------------------------------------------------------------- #
def _zstd():
    try:
        import zstandard  # noqa: PLC0415 — lazy on purpose, see module doc
    except ImportError as exc:
        raise ArchiveUnavailable("zstandard is not installed") from exc
    return zstandard


def compress(data: bytes) -> bytes:
    return _zstd().ZstdCompressor(level=ZSTD_LEVEL, write_content_size=True).compress(data)


def decompress(data: bytes, max_output_size: int = MAX_CHUNK_OUTPUT) -> bytes:
    """Bounded: a frame that would expand past max_output_size raises
    ArchiveError instead of allocating it."""
    zstd = _zstd()
    dctx = zstd.ZstdDecompressor()
    out = bytearray()
    try:
        reader = dctx.stream_reader(data)
        while True:
            block = reader.read(65536)
            if not block:
                break
            out += block
            if len(out) > max_output_size:
                raise ArchiveError("archive object exceeds the decompression limit")
    except zstd.ZstdError as exc:
        raise ArchiveError("archive object is not valid zstd") from exc
    return bytes(out)


# --------------------------------------------------------------------------- #
# Backends
# --------------------------------------------------------------------------- #
_TIMEOUT = httpx.Timeout(connect=5.0, read=30.0, write=30.0, pool=5.0)


def _check(resp, what: str) -> None:
    if resp.status_code == 404:
        raise ArchiveNotFound(what)
    if resp.status_code >= 400:
        # Status only: the body of a storage error can echo the object name and
        # nothing in it helps more than the code.
        raise ArchiveUnavailable(f"{what}: storage answered {resp.status_code}")


class GCSBackend:
    """Google Cloud Storage JSON API with a metadata-server token."""

    METADATA_TOKEN_URL = ("http://metadata.google.internal/computeMetadata/v1/"
                          "instance/service-accounts/default/token")
    API = "https://storage.googleapis.com"

    def __init__(self, bucket: str, client: httpx.AsyncClient | None = None):
        self.bucket = bucket
        self._client = client or httpx.AsyncClient(timeout=_TIMEOUT)
        self._token = ""
        self._token_exp = 0.0

    async def _auth(self) -> dict:
        if not self._token or time.time() > self._token_exp - 60:
            try:
                r = await self._client.get(self.METADATA_TOKEN_URL,
                                           headers={"Metadata-Flavor": "Google"})
            except httpx.HTTPError as exc:
                raise ArchiveUnavailable("metadata token unavailable") from exc
            if r.status_code != 200:
                raise ArchiveUnavailable(f"metadata token: {r.status_code}")
            data = r.json()
            self._token = data["access_token"]
            self._token_exp = time.time() + float(data.get("expires_in", 300))
        return {"Authorization": f"Bearer {self._token}"}

    def _obj(self, name: str) -> str:
        return f"{self.API}/storage/v1/b/{quote(self.bucket, safe='')}/o/{quote(name, safe='')}"

    async def _req(self, method, url, what, **kw):
        try:
            return await self._client.request(method, url, headers=await self._auth(), **kw)
        except httpx.HTTPError as exc:
            raise ArchiveUnavailable(f"{what}: {exc.__class__.__name__}") from exc

    async def put(self, name: str, data: bytes) -> None:
        url = (f"{self.API}/upload/storage/v1/b/{quote(self.bucket, safe='')}/o"
               f"?uploadType=media&name={quote(name, safe='')}")
        r = await self._req("POST", url, "put", content=data)
        _check(r, "put")

    async def get(self, name: str) -> bytes:
        r = await self._req("GET", self._obj(name) + "?alt=media", "get")
        _check(r, "get")
        return r.content

    async def delete(self, name: str) -> None:
        r = await self._req("DELETE", self._obj(name), "delete")
        if r.status_code != 404:
            _check(r, "delete")

    async def list(self, prefix: str) -> list[str]:
        names: list[str] = []
        token = ""
        while True:
            url = (f"{self.API}/storage/v1/b/{quote(self.bucket, safe='')}/o"
                   f"?prefix={quote(prefix, safe='')}&fields=items(name),nextPageToken")
            if token:
                url += f"&pageToken={quote(token, safe='')}"
            r = await self._req("GET", url, "list")
            _check(r, "list")
            data = r.json()
            names += [i["name"] for i in data.get("items", [])]
            token = data.get("nextPageToken", "")
            if not token:
                return names


class S3Backend:
    """S3 REST API (virtual-hosted style) signed with stdlib SigV4."""

    def __init__(self, bucket: str, region: str, access_key: str, secret_key: str,
                 client: httpx.AsyncClient | None = None):
        self.bucket = bucket
        self.region = region
        self.host = f"{bucket}.s3.{region}.amazonaws.com"
        self._ak = access_key
        self._sk = secret_key
        self._client = client or httpx.AsyncClient(timeout=_TIMEOUT)

    async def _req(self, method: str, path: str, query: list, payload: bytes, what: str):
        amz_date = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        q = sessions_sigv4.canonical_query(query)
        headers = sessions_sigv4.sign_headers(
            method, self.host, path, q, payload, access_key=self._ak, secret_key=self._sk,
            region=self.region, amz_date=amz_date)
        url = f"https://{self.host}{path}" + (f"?{q}" if q else "")
        try:
            return await self._client.request(method, url, headers=headers, content=payload or None)
        except httpx.HTTPError as exc:
            raise ArchiveUnavailable(f"{what}: {exc.__class__.__name__}") from exc

    @staticmethod
    def _path(name: str) -> str:
        # object_name already quoted each segment; quote again with "/" safe so
        # the signed path equals the path on the wire (S3 does not double-encode).
        return "/" + quote(name, safe="/-_.~%")

    async def put(self, name: str, data: bytes) -> None:
        _check(await self._req("PUT", self._path(name), [], data, "put"), "put")

    async def get(self, name: str) -> bytes:
        r = await self._req("GET", self._path(name), [], b"", "get")
        _check(r, "get")
        return r.content

    async def delete(self, name: str) -> None:
        r = await self._req("DELETE", self._path(name), [], b"", "delete")
        if r.status_code != 404:
            _check(r, "delete")

    async def list(self, prefix: str) -> list[str]:
        names: list[str] = []
        token = ""
        ns = "{http://s3.amazonaws.com/doc/2006-03-01/}"
        while True:
            query = [("list-type", "2"), ("prefix", prefix)]
            if token:
                query.append(("continuation-token", token))
            r = await self._req("GET", "/", query, b"", "list")
            _check(r, "list")
            root = ElementTree.fromstring(r.content)
            names += [e.text for e in root.iter(f"{ns}Key") if e.text]
            nxt = root.find(f"{ns}NextContinuationToken")
            token = nxt.text if nxt is not None and nxt.text else ""
            if not token:
                return names


def archive_disabled(env=None) -> bool:
    """True only when the operator explicitly turned the archive off with
    SESSION_ARCHIVE_BACKEND=none. Unset is NOT disabled: ingest then refuses
    main-transcript segments with 503 until a backend is configured."""
    env = os.environ if env is None else env
    return env.get("SESSION_ARCHIVE_BACKEND", "") == "none"


def backend_from_env(env=None):
    """The configured backend, or None when SESSION_ARCHIVE_BACKEND is unset or
    "none". Ingest treats unset as "not ready" (503) and "none" as an explicit
    search-only deployment (archive:"skipped"); see archive_disabled(). A
    set-but-invalid configuration raises, so a typo cannot silently disable the
    archive."""
    env = os.environ if env is None else env
    kind = env.get("SESSION_ARCHIVE_BACKEND", "")
    if not kind or kind == "none":
        return None
    bucket = env.get("SESSION_ARCHIVE_BUCKET", "")
    if not bucket:
        raise ValueError("SESSION_ARCHIVE_BUCKET is required")
    if kind == "gcs":
        return GCSBackend(bucket)
    if kind == "s3":
        ak = env.get("SESSION_ARCHIVE_AWS_ACCESS_KEY_ID", "")
        sk = env.get("SESSION_ARCHIVE_AWS_SECRET_ACCESS_KEY", "")
        region = env.get("SESSION_ARCHIVE_AWS_REGION", "")
        if not (ak and sk and region):
            raise ValueError("s3 archive needs SESSION_ARCHIVE_AWS_{ACCESS_KEY_ID,SECRET_ACCESS_KEY,REGION}")
        return S3Backend(bucket, region, ak, sk)
    raise ValueError(f"unknown SESSION_ARCHIVE_BACKEND {kind!r}")


class MemoryBackend:
    """In-process store with the backend interface. Used by the tests; never
    selected by backend_from_env."""

    def __init__(self):
        self.objects: dict[str, bytes] = {}

    async def put(self, name, data):
        self.objects[name] = bytes(data)

    async def get(self, name):
        if name not in self.objects:
            raise ArchiveNotFound("get")
        return self.objects[name]

    async def delete(self, name):
        self.objects.pop(name, None)

    async def list(self, prefix):
        return sorted(n for n in self.objects if n.startswith(prefix))
