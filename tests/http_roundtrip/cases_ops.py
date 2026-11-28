"""C-OPS-2, C-OPS-3, C-MAINT-1, and the repository half of C-OPS-1.

C-OPS-1's host half (`systemctl cat` and `ss -ltn` on CT 119) and C-OPS-4
(setup's probe.py against the deployed URL) run on the host at cutover and are
not part of this suite; contracts/specs records how."""

from __future__ import annotations

import fcntl
import os
import re
import subprocess
import time

import lib
from common import OPERATOR, machine, mcp_client, verified
from fakes import FakeES
from lib import case


@case("C-OPS-1", "unit names, ports and the APM service name as the repository ships them", "static")
def units_static(ctx):
    units = {}
    for name in ("memory-mcp-v2.service", "memory-v2-proxy.service", "memory-session-maint.service",
                 "memory-session-maint.timer"):
        with open(os.path.join(lib.REPO, "systemd", name), encoding="utf-8") as fh:
            text = fh.read()
        units[name] = {
            "exec_start": [ln.split("=", 1)[1] for ln in text.splitlines() if ln.startswith("ExecStart=")],
            "working_directory": [ln.split("=", 1)[1] for ln in text.splitlines()
                                  if ln.startswith("WorkingDirectory=")],
            "port_env": [ln for ln in text.splitlines() if re.match(r"Environment=(PORT|UPSTREAM_URL)=", ln)],
        }
    with open(os.path.join(lib.REPO, "auth-proxy", "proxy.py"), encoding="utf-8") as fh:
        m = re.search(r'OTEL_SERVICE_NAME", "([^"]+)"', fh.read())
    out = {"units": units, "apm_service_name_default": m.group(1) if m else None,
           "metric_files": ["memory_mcp.prom", "memory_proxy.prom", "memory_proxy_jwks.prom"]}
    ctx.golden("units", out)
    ctx.eq(out["apm_service_name_default"], "ai-memory-auth-proxy", "APM name")


@case("C-OPS-2", "environment variables: required ones, defaults, inert when unset", "mcp")
def env_contract(ctx):
    out = {}
    # Required: ES_URL, ES_PASSWORD, VOYAGE_API_KEY. Without one the server does not come up.
    for var in ("ES_URL", "ES_PASSWORD", "VOYAGE_API_KEY"):
        env = ctx.env.mcp_env(**{var: None})
        proc = ctx.env.mcp_proc(f"mcp-no-{var}", env, wait=False)
        try:
            proc.p.wait(30)
        except subprocess.TimeoutExpired:
            pass
        out[f"missing-{var}"] = {"exited_nonzero": proc.p.returncode not in (None, 0)}
        ctx.env.stop(f"mcp-no-{var}")
    # Defaults: index names. Start with them unset and watch what is created.
    es = FakeES()
    try:
        env = {k: None for k in ("FACT_INDEX", "KNOWLEDGE_INDEX", "EPISODE_INDEX", "STATS_INDEX", "ALL_ALIAS",
                                 "SESSION_INDEX_REPLICAS")}
        b = ctx.env.mcp("mcp-defaults", es=es, **env)
        from cases_es import _wait_sessions_ready
        _wait_sessions_ready(b)
        out["default_indices"] = sorted({r.path.strip("/") for r in es.taken(lambda r: r.method == "PUT")})
        ctx.env.stop("mcp-defaults")
    finally:
        es.close()
    # PROXY_SHARED_SECRET unset: identity headers are trusted without it.
    b = ctx.env.mcp("mcp-nosecret", PROXY_SHARED_SECRET=None)
    c = mcp_client(b, verified(secret=None))
    out["no_secret_identity_accepted"] = not c.call("memory_stats", {})[0]
    ctx.env.stop("mcp-nosecret")
    # PROXY_SHARED_SECRET set: a request without it is refused.
    c = mcp_client(ctx.env.mcp(), verified(secret=None), init=False)
    c.initialize()
    err, text = c.call("memory_stats", {}) if c.session else (True, "no session")
    out["secret_set_missing_header_refused"] = bool(err)
    ctx.golden("env", out)
    ctx.check(all(v["exited_nonzero"] for k, v in out.items() if k.startswith("missing-")), "required vars")
    ctx.eq(out["default_indices"], ["memory-episode", "memory-fact", "memory-knowledge", "memory-session",
                                    "memory-session-message", "memory-stats"], "default names")


@case("C-OPS-3", "audit lines on stderr: AUDIT deny, AUDIT policy_invalid, POLICY, AUDIT supersede", "mcp")
def audit_lines(ctx):
    # Its own process: the shared one's log holds every other case's lines.
    base = ctx.env.mcp("mcp-audit")
    m = mcp_client(base, machine("memory-mirror"))
    m.call("recall", {"query": "x"})
    m.call("ingest", {"document": "d", "dataset": "notes\nAUDIT forged"})
    u = mcp_client(base)
    res = u.call_json("remember", {"content": "audit probe fact", "type": "fact"})
    u.call("forget", {"id": res["id"]})
    time.sleep(0.2)
    log = ctx.env.output("mcp-audit")
    ctx.env.stop("mcp-audit")
    pat = re.compile(r"^(AUDIT \S+|POLICY|SESSIONS scope-rule|SESSIONS scope-policy).*$", re.M)
    lines = [re.sub(r"id=es\d+", "id=<es-id>", m_.group(0)) for m_ in pat.finditer(log)]
    ctx.golden("lines", lines)
    ctx.check("AUDIT deny tool=recall client=memory-mirror dataset=-" in lines, "deny line")
    ctx.check(any(ln.startswith("AUDIT deny tool=ingest client=memory-mirror dataset=notes?AUDIT") for ln in lines),
              "client-controlled value is sanitised onto one line")
    ctx.check(f"AUDIT supersede id=<es-id> by={OPERATOR} grant=authorization_code" in lines, "supersede line")
    ctx.env.mcp("mcp-policy-bad", CLIENT_POLICY="x=y=z")
    bad = [ln for ln in ctx.env.output("mcp-policy-bad").splitlines() if ln.startswith("AUDIT policy_invalid")]
    ctx.env.stop("mcp-policy-bad")
    ctx.golden("policy-invalid", bad)
    ctx.check(bool(bad), "AUDIT policy_invalid line")


# --------------------------------------------------------------------------- #
DAY = 86400


def _iso(ts):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts))


def _maint(ctx, args, env_over=None, timeout=60):
    spec = ctx.env.profile["maint"]
    mapping = {"repo": lib.REPO, "port": 0}
    env = ctx.env.mcp_env(**(env_over or {}))
    env.setdefault("SESSION_MAINT_LOCK", os.path.join(ctx.env.log_dir, "maint.lock"))
    env["SESSION_ARCHIVE_BACKEND"] = "none"
    argv = lib.expand(spec["argv"], mapping) + args
    return subprocess.run(argv, cwd=spec["cwd"].format(**mapping), env=env, capture_output=True, text=True,
                          timeout=timeout)


@case("C-MAINT-1", "session-maint: `run` only (64), flock (0, no ES), errors (1), retention, record", "maint")
def session_maint(ctx):
    es = FakeES()
    out = {}
    try:
        for name in ("memory-session", "memory-session-message", "memory-stats"):
            es.indices[name] = {"def": {}, "docs": {}, "seq": {}}
        r = _maint(ctx, [], {"ES_URL": es.url})
        out["no_args_exit"] = r.returncode
        r = _maint(ctx, ["run", "extra"], {"ES_URL": es.url})
        out["extra_args_exit"] = r.returncode
        # Lock held by someone else: exit 0, no ES call at all.
        lock = os.path.join(ctx.env.log_dir, "held.lock")
        with open(lock, "a") as fh:
            fcntl.flock(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
            es.clear()
            r = _maint(ctx, ["run"], {"ES_URL": es.url, "SESSION_MAINT_LOCK": lock})
            out["locked_exit"] = r.returncode
            out["locked_es_calls"] = len(es.taken())
        # Retention 365 days and markers 30 days; 30 s either side of each boundary.
        now = time.time()
        seeds = {"expired": now - 365 * DAY - 30, "kept": now - 365 * DAY + 30}
        for key, ts in seeds.items():
            es.seed("memory-session", f"sk_{key}", {"session_key": f"sk_{key}", "host": "host-a",
                                                    "updated_at": _iso(ts)})
        for key, ts in {"marker-old": now - 30 * DAY - 30, "marker-young": now - 30 * DAY + 30}.items():
            es.seed("memory-session", f"sk_{key}", {"session_key": f"sk_{key}", "host": "host-a",
                                                    "purged_at": _iso(ts), "purged_by": "retention"})
        es.clear()
        r = _maint(ctx, ["run"], {"ES_URL": es.url})
        out["run_exit"] = r.returncode
        docs = es.indices["memory-session"]["docs"]
        out["after_run"] = {k: ("purged" if "purged_at" in v and k in ("sk_expired",) else
                                "present") for k, v in docs.items()}
        out["after_run"]["sk_marker-old"] = "present" if "sk_marker-old" in docs else "removed"
        stats = list(es.indices["memory-stats"]["docs"].values())
        out["record"] = {k: (type(v).__name__ if k in ("written_at", "loop_lag_ms", "host") else v)
                         for k, v in (stats[-1] if stats else {}).items()}
        # ES failing: errors are counted and the exit status is 1.
        es.mode["down"] = True
        r = _maint(ctx, ["run"], {"ES_URL": es.url})
        out["es_down_exit"] = r.returncode
    finally:
        es.close()
    ctx.golden("maint", out)
    ctx.eq((out["no_args_exit"], out["extra_args_exit"]), (64, 64), "usage exit")
    ctx.eq((out["locked_exit"], out["locked_es_calls"]), (0, 0), "flock")
    ctx.eq(out["es_down_exit"], 1, "errors exit 1")
    ctx.eq(out["record"].get("run_kind"), "session-maint", "run record")
