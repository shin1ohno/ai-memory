"""C-SES-5: the ccs client (shin1ohno/session-search) against the server under test.

ccs's endpoint lives only in its config file, so the target URL is the switch:
the case writes a ccs config whose endpoint is the proxy under test (which
forwards to the memory-mcp under test) and whose token URL is the suite's fake
Hydra, then runs ccs's own CLI at the commit pinned in ccs_pin.json:
ingest --file, status, search, preview, resume (from the archive, after the
local transcript is gone) and purge. Nothing in ccs is patched or imported
into the suite's process; it runs as a separate process with a disposable HOME.

The ccs source comes from a git checkout of session-search named by
HTTP_ROUNDTRIP_CCS_REPO (default: a session-search checkout next to this
repository). The pinned commit is extracted with `git archive`, so the
checkout's own working tree and branch do not matter. Without a checkout that
has the pinned commit the case fails: C-SES-5 is not skipped silently.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import subprocess
import sys
import tarfile

import lib
from cases_archive import BLOBS, LINE2, LINE3, _archive_mcp, _doc
from cases_ses import LINE, SID
from lib import case

HERE = os.path.dirname(os.path.abspath(__file__))
CCS_CLIENT_ID = "session-search-a"
CCS_SECRET = "roundtrip-ccs-client-secret"
CCS_HMAC_KEY = "roundtrip-ccs-hmac-key"


def _interactive(line):
    """The fixture lines as an interactive Claude Code CLI session writes them
    (search hides headless sessions unless --all)."""
    rec = json.loads(line)
    rec["entrypoint"] = "cli"
    return json.dumps(rec, separators=(",", ":"))


FIXTURE = [_interactive(ln) for ln in (LINE, LINE2, LINE3)]


def pin():
    with open(os.path.join(HERE, "ccs_pin.json"), encoding="utf-8") as fh:
        return json.load(fh)


def ccs_repo():
    return os.environ.get("HTTP_ROUNDTRIP_CCS_REPO") or os.path.join(os.path.dirname(lib.REPO), "session-search")


def stage_ccs(dest):
    """ccs/ plus the two vendored server modules, as deploy-pinned.sh stages them."""
    commit = pin()["commit"]
    repo = ccs_repo()
    p = subprocess.run(["git", "-C", repo, "archive", "--format=tar", commit, "ccs", "vendor/memory-mcp"],
                       capture_output=True)
    if p.returncode != 0:
        raise lib.CaseFailure(f"ccs {commit[:12]} not available from {repo} (set HTTP_ROUNDTRIP_CCS_REPO "
                              f"to a session-search checkout that has it): {p.stderr.decode()[:200]}")
    with tarfile.open(fileobj=io.BytesIO(p.stdout), mode="r:") as tar:
        tar.extractall(dest, filter="data")
    for name in ("session_redact.py", "session_codex.py"):
        with open(os.path.join(dest, "vendor", "memory-mcp", name), "rb") as src, \
                open(os.path.join(dest, "ccs", name), "wb") as dst:
            dst.write(src.read())
    return commit


def _write(path, text, mode=0o600):
    os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(text)


class Ccs:
    def __init__(self, root, endpoint, token_url):
        self.root = root
        self.home = os.path.join(root, "home")
        self.stage = os.path.join(root, "python")
        os.makedirs(self.home, mode=0o700)
        os.makedirs(self.stage)
        self.commit = stage_ccs(self.stage)
        cfg_dir = os.path.join(self.home, ".config", "session-search")
        _write(os.path.join(cfg_dir, "client.secret"), CCS_SECRET + "\n")
        _write(os.path.join(cfg_dir, "hmac.key"), CCS_HMAC_KEY + "\n")
        _write(os.path.join(cfg_dir, "config.json"), json.dumps({
            "endpoint": endpoint, "host_label": "host-a",
            "auth": {"type": "client_credentials", "token_url": token_url, "client_id": CCS_CLIENT_ID,
                     "secret_file": os.path.join(cfg_dir, "client.secret")},
            "hmac_key_file": os.path.join(cfg_dir, "hmac.key")}))
        self.projects = os.path.join(self.home, ".claude", "projects")

    def env(self):
        return {"HOME": self.home, "PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "TMPDIR": self.root,
                "PYTHONPATH": self.stage, "PYTHONDONTWRITEBYTECODE": "1", "NO_PROXY": "*",
                "CODEX_HOME": os.path.join(self.home, ".codex")}

    def run(self, *args, timeout=60):
        p = subprocess.run([sys.executable, "-m", "ccs", *args], env=self.env(), cwd=self.home,
                           capture_output=True, timeout=timeout)
        return p.returncode, p.stdout.decode("utf-8", "replace"), p.stderr.decode("utf-8", "replace")


def _tail_log(ccs, n=6):
    try:
        with open(os.path.join(ccs.home, ".claude", "session-search.log"), encoding="utf-8") as fh:
            return " | ".join(ln.strip() for ln in fh.readlines()[-n:])
    except OSError:
        return "(no ccs log)"


def _json(text):
    try:
        return json.loads(text)
    except ValueError:
        return None


@case("C-SES-5", "ccs CLI (pinned commit) against proxy + server under test: ingest, search, resume", "ses")
def ccs_round_trip(ctx):
    arch = ctx.env.archive
    arch.reset()
    ctx.env.es.reset_data()
    ctx.env.hydra.clients[CCS_CLIENT_ID] = CCS_SECRET
    mcp = _archive_mcp(ctx, "mcp-ccs", "s3")
    proxy = ctx.env.proxy("proxy-ccs", upstream=mcp)  # the proxy forwards the full path
    ccs = Ccs(os.path.join(ctx.env.log_dir, "ccs"), f"{proxy}/memory/sessions/v1",
              f"{ctx.env.hydra.url}/oauth2/token")
    rows = {}   # the commit itself is ccs_pin.json's; a 40-hex id would trip check_goldens

    sdir = os.path.join(ccs.projects, "-work-roundtrip")
    jsonl = os.path.join(sdir, f"{SID}.jsonl")
    _write(jsonl, "".join(ln + "\n" for ln in FIXTURE))
    for name, text in BLOBS.items():
        _write(os.path.join(sdir, SID, "tool-results", name), text)

    code, out, err = ccs.run("ingest", "--file", jsonl)
    rows["ingest"] = {"exit": code}
    ctx.eq(code, 0, f"ccs ingest --file: {err[-400:]}")
    state = _json(open(os.path.join(ccs.home, ".claude", "session-search", "state.json")).read()) or {}
    entries = list((state.get("files") or {}).values())
    ctx.eq(len(entries), 1, "ccs recorded one shipped file")
    key = entries[0].get("session_key")
    ctx.check(key is not None, f"ccs shipped the transcript: {_tail_log(ccs)}")
    doc = _doc(ctx, key)
    rows["server_doc"] = {k: doc.get(k) for k in ("host", "project_dir", "message_count", "archived",
                                                    "archive_complete", "archive_bytes")}
    rows["objects"] = [n.replace(key, "<session_key>") for n in arch.names("s3")]
    ctx.eq(len(arch.names("s3", f"sessions/host-a/{key}/tool-results/")), len(BLOBS), "ccs shipped the side files")

    code, out, err = ccs.run("status")
    rows["status"] = {"exit": code}
    ctx.eq(code, 0, f"ccs status: {err[-400:]}")

    code, out, err = ccs.run("search", "roundtrip")
    found = _json(out) or {}
    rows["search"] = {"exit": code, "keys": [s.get("session_key") for s in found.get("sessions", [])]}
    ctx.eq(code, 0, f"ccs search: {err[-400:]}")
    ctx.check(key in rows["search"]["keys"], "ccs search finds the session")

    code, out, err = ccs.run("preview", key, "hello")
    prev = _json(out) or {}
    rows["preview"] = {"exit": code, "session_key": (prev.get("session") or {}).get("session_key"),
                       "snippets": len(prev.get("snippets") or [])}
    ctx.eq(code, 0, f"ccs preview: {err[-400:]}")

    # Resume from the archive: the local transcript and its side files are gone.
    os.remove(jsonl)
    for name in BLOBS:
        os.remove(os.path.join(sdir, SID, "tool-results", name))
    restore_to = os.path.join(ccs.root, "restore-cwd")
    os.makedirs(restore_to)
    code, out, err = ccs.run("resume", key, "--print", "--to", restore_to)
    rows["resume"] = {"exit": code}
    ctx.eq(code, 0, f"ccs resume --print: {err[-400:]}")
    restored = None
    for dirpath, _dirs, files in os.walk(ccs.projects):
        for f in files:
            if f == f"{SID}.jsonl":
                restored = os.path.join(dirpath, f)
    ctx.check(restored is not None, "ccs restored the transcript from the archive")
    with open(restored, "rb") as fh:
        data = fh.read()
    archive = lib.request("GET", f"{mcp}/memory/sessions/v1/archive?session_key={key}",
                          headers={"X-Verified-Grant": "client_credentials", "X-Verified-Sub": CCS_CLIENT_ID,
                                   "X-Verified-Client-Id": CCS_CLIENT_ID,
                                   "X-Proxy-Secret": ctx.env.proxy_env("")["PROXY_SHARED_SECRET"]})
    rows["resume"]["restored_matches_archive"] = data == archive.body
    rows["resume"]["restored_sha256"] = hashlib.sha256(data).hexdigest()
    side = {}
    for name in BLOBS:
        p = os.path.join(os.path.dirname(restored), SID, "tool-results", name)
        side[name] = open(p, encoding="utf-8").read() if os.path.exists(p) else None
    rows["resume"]["side_files"] = side
    ctx.check(rows["resume"]["restored_matches_archive"], "restored transcript is the archive's bytes")

    # session-search-a holds sessions:ingest and sessions:read only.
    code, out, err = ccs.run("purge", key)
    rows["purge_without_scope"] = {"exit": code, "doc_still_there": _doc(ctx, key) is not None}
    ctx.check(code != 0 and rows["purge_without_scope"]["doc_still_there"], "purge refused without the scope")

    ctx.env.stop("proxy-ccs")
    ctx.env.stop("mcp-ccs")
    ctx.golden("ccs", lib.Normalizer()(rows))
