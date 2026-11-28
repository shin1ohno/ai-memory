#!/usr/bin/env python3
"""Language-independent round-trip tests for ai-memory's external contracts.

Each case is tagged with a contract ID from contracts/README.md. The suite
starts the fakes it needs (Elasticsearch, Voyage, JWKS, Hydra, an echo
upstream) in this process, launches the implementation under test from an
implementation profile, and talks to it over HTTP only. The same cases run
against the Python implementation (profiles/python.json, the default) and,
later, the Rust one: a profile names the command lines; the environment
variables the processes read are themselves part of the contract (C-OPS-2).

Golden responses live in contracts/golden/<contract-id>/. They are captured
from the Python implementation with --capture and compared afterwards after
the normalisation in lib.Normalizer (ids, uuids and timestamps become
placeholders; floats are compared to six decimals).

Usage:
  run.py                       run every case against the Python profile
  run.py --only C-JWT-1,C-HTTP  run the cases whose ID starts with these
  run.py --profile FILE        use another implementation profile
  run.py --capture             (re)write the golden files
  run.py --list                list the cases and exit

Standard library only. Output: one `PASS|FAIL <id> <case>` line per case and a
final `---- pass=N fail=F` line; the exit status is 1 when anything failed.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import traceback

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import lib  # noqa: E402
from fakes import FakeES, FakeHydra, FakeJWKS, FakeUpstream, FakeVoyage  # noqa: E402
from rsa_jwt import RsaKey  # noqa: E402

from common import (ALLOWED_CLIENT_IDS, CLIENT_POLICY, ISSUER, MIRROR_SECRET, OPERATOR,  # noqa: E402
                    PROXY_SECRET, SESSION_SCOPE_POLICY)


class Runner:
    def __init__(self, profile: dict, log_dir: str):
        self.profile = profile
        self.log_dir = log_dir
        t0 = time.monotonic()
        self.keys = [RsaKey("k1"), RsaKey("k2"), RsaKey(None)]
        self.keygen_s = time.monotonic() - t0
        self.es = FakeES()
        self.voyage = FakeVoyage()
        self.jwks = FakeJWKS([self.keys[0]])
        self.upstream = FakeUpstream()
        self.hydra = FakeHydra(self.keys[0], ISSUER, {"memory-mirror": MIRROR_SECRET})
        self.procs: dict[str, lib.Proc] = {}
        self.urls: dict[str, str] = {}
        self._archive = None

    @property
    def archive(self):
        """The fake object stores (C-SES-8/9), created on first use: issuing its
        TLS certificates costs a few seconds of pure-Python RSA."""
        if self._archive is None:
            from fake_archive import FakeArchive
            self._archive = FakeArchive(os.path.join(self.log_dir, "archive-tls"))
        return self._archive

    # -- environment of the processes under test -------------------------- #
    def _base_env(self):
        env = {k: os.environ[k] for k in ("PATH", "HOME", "LANG", "LC_ALL", "TMPDIR") if k in os.environ}
        env.update({
            "PYTHONUNBUFFERED": "1",
            "MEMORY_MCP_METRICS_FILE": os.path.join(self.log_dir, "memory_mcp.prom"),
            "MEMORY_PROXY_METRICS_FILE": os.path.join(self.log_dir, "memory_proxy.prom"),
            "MEMORY_PROXY_JWKS_METRICS_FILE": os.path.join(self.log_dir, "memory_proxy_jwks.prom"),
            "OTEL_SDK_DISABLED": "true",
            "OTEL_EXPORTER_OTLP_ENDPOINT": "http://127.0.0.1:9",
        })
        return env

    def mcp_env(self, es=None, voyage=None, **over):
        env = self._base_env()
        env.update({
            "ES_URL": (es or self.es).url, "ES_USER": "roundtrip", "ES_PASSWORD": "roundtrip-es-password",
            "VOYAGE_API_KEY": "roundtrip-voyage-key", "VOYAGE_ENDPOINT": (voyage or self.voyage).url,
            "EMBEDDING_DIMENSIONS": "1024",
            "FACT_INDEX": "memory-fact", "KNOWLEDGE_INDEX": "memory-knowledge",
            "EPISODE_INDEX": "memory-episode", "STATS_INDEX": "memory-stats", "ALL_ALIAS": "memory-all",
            "CLIENT_POLICY": CLIENT_POLICY, "PROXY_SHARED_SECRET": PROXY_SECRET,
            "SESSION_SCOPE_POLICY": SESSION_SCOPE_POLICY, "SESSION_INDEX_REPLICAS": "0",
        })
        for k, v in over.items():
            if v is None:
                env.pop(k, None)
            else:
                env[k] = v
        return env

    def proxy_env(self, upstream_url, **over):
        env = self._base_env()
        env.update({
            "OIDC_ISSUER": ISSUER, "OIDC_JWKS_URL": f"{self.jwks.url}/.well-known/jwks.json",
            "UPSTREAM_URL": upstream_url, "PATH_PREFIX": "/memory",
            "MEMORY_AUDIENCES": "https://issuer.example.test/memory,memory",
            "ALLOWED_SUBS": OPERATOR, "ALLOWED_CLIENT_IDS": ALLOWED_CLIENT_IDS,
            "PROXY_SHARED_SECRET": PROXY_SECRET,
        })
        for k, v in over.items():
            if v is None:
                env.pop(k, None)
            else:
                env[k] = v
        return env

    # -- process control ------------------------------------------------- #
    def _start(self, key, role, env, wait=True):
        if key in self.urls:
            return self.urls[key]
        spec = self.profile[role]
        port = lib.free_port()
        mapping = {"repo": lib.REPO, "port": port}
        env = dict(env)
        for k, v in spec.get("env", {}).items():
            env[k] = v.format(**mapping)
        proc = lib.Proc(key, lib.expand(spec["argv"], mapping), spec["cwd"].format(**mapping), env,
                        self.log_dir)
        self.procs[key] = proc
        if not wait:
            return proc
        if not lib.wait_port(port, 40, proc.p):
            raise RuntimeError(f"{key} did not start; log:\n{proc.output()[-3000:]}")
        self.urls[key] = f"http://127.0.0.1:{port}"
        return self.urls[key]

    def mcp(self, key="mcp", **over):
        return self._start(key, "mcp", self.mcp_env(**over))

    def mcp_proc(self, key, env, wait=True):
        """Start without caching readiness (startup-behaviour cases)."""
        return self._start(key, "mcp", env, wait=wait)

    def proxy(self, key="proxy", upstream=None, **over):
        return self._start(key, "proxy", self.proxy_env(upstream or self.upstream.url + "/memory", **over))

    def stop(self, key):
        proc = self.procs.pop(key, None)
        self.urls.pop(key, None)
        if proc:
            proc.stop()

    def output(self, key):
        return self.procs[key].output()

    def close(self):
        for key in list(self.procs):
            self.stop(key)
        for f in (self.es, self.voyage, self.jwks, self.upstream, self.hydra):
            f.close()
        if self._archive is not None:
            self._archive.close()


def load_cases():
    import cases_emb  # noqa: F401
    import cases_es  # noqa: F401
    import cases_hook  # noqa: F401
    import cases_http  # noqa: F401
    import cases_jwt  # noqa: F401
    import cases_mcp  # noqa: F401
    import cases_ops  # noqa: F401
    import cases_ses  # noqa: F401
    import cases_archive  # noqa: F401  (after cases_ses, which it imports)
    import cases_ccs  # noqa: F401
    return lib.CASES


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--profile", default=os.path.join(HERE, "profiles", "python.json"))
    ap.add_argument("--only", default="")
    ap.add_argument("--capture", action="store_true")
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--keep-logs", action="store_true")
    args = ap.parse_args(argv)

    cases = load_cases()
    if args.only:
        prefixes = [p.strip() for p in args.only.split(",") if p.strip()]
        cases = [c for c in cases if any(c["id"] == p or c["id"].startswith(p + "-") or c["id"].startswith(p)
                                         for p in prefixes)]
    if args.list:
        for c in cases:
            print(f"{c['id']:<11} {c['name']:<44} {c['title']}")
        return 0

    with open(args.profile, encoding="utf-8") as fh:
        profile = json.load(fh)
    log_dir = tempfile.mkdtemp(prefix="http-roundtrip-")
    rev = subprocess.run(["git", "-C", lib.REPO, "rev-parse", "--short", "HEAD"],
                         capture_output=True, text=True).stdout.strip() or "unknown"
    print(f"http_roundtrip: profile={os.path.basename(args.profile)} impl={profile.get('name')} "
          f"repo={rev} capture={args.capture} cases={len(cases)} logs={log_dir}")
    runner = Runner(profile, log_dir)
    passed = failed = 0
    per_id: dict[str, list[int]] = {}
    try:
        for c in cases:
            ctx = lib.Ctx(runner, c["id"], c["name"], args.capture)
            t0 = time.monotonic()
            try:
                c["fn"](ctx)
                status = "PASS"
                passed += 1
                detail = f"checks={ctx.checks}"
            except Exception as exc:  # noqa: BLE001 — report and continue
                status = "FAIL"
                failed += 1
                detail = f"{exc.__class__.__name__}: {exc}"
                if not isinstance(exc, lib.CaseFailure):
                    detail += "\n" + "".join(traceback.format_exc().splitlines(True)[-6:])
            per_id.setdefault(c["id"], [0, 0])[0 if status == "PASS" else 1] += 1
            print(f"{status} {c['id']:<11} {c['name']} ({time.monotonic() - t0:.2f}s) {detail}", flush=True)
    finally:
        runner.close()
        if not args.keep_logs and failed == 0:
            shutil.rmtree(log_dir, ignore_errors=True)
    ids = sorted(per_id)
    print(f"contract ids exercised ({len(ids)}): {' '.join(ids)}")
    print(f"---- pass={passed} fail={failed}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
