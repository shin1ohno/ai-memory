"""C-HOOK-1..3: the file-memory mirror hook against the whole local chain
(fake Hydra -> proxy -> memory-mcp -> fake ES). C-HOOK-4 is the production
`--check` after cutover and is not run here (it needs https, :249)."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile

import lib
from common import MIRROR_SECRET
from lib import case

CONSTANTS = os.path.join(lib.REPO, "contracts", "constants.json")


def _chain(ctx):
    mcp = ctx.env.mcp()
    return ctx.env.proxy("proxy-chain", upstream=mcp + "/memory")


def _hook_env(ctx, proxy_url, home):
    cfg = os.path.join(home, "memory-mirror.json")
    creds = os.path.join(home, "client.env")
    with open(creds, "w", encoding="utf-8") as fh:
        fh.write(f"MEMORY_MIRROR_CLIENT_ID=memory-mirror\nMEMORY_MIRROR_CLIENT_SECRET={MIRROR_SECRET}\n")
    os.chmod(creds, 0o600)
    with open(cfg, "w", encoding="utf-8") as fh:
        json.dump({"enabled": True, "dataset": "file-memory", "host": "roundtrip-host",
                   "url": f"{proxy_url}/mcp",
                   "auth": {"type": "client_credentials", "token_url": f"{ctx.env.hydra.url}/oauth2/token",
                            "audience": "memory", "credentials_file": creds}}, fh)
    # HOME stays the real one (a version manager's ruby shim reads its config
    # from there); every path the hook writes is redirected below instead.
    env = {k: os.environ[k] for k in ("PATH", "LANG", "LC_ALL", "HOME") if k in os.environ}
    env.update({"MEMORY_MIRROR_CONFIG": cfg,
                "MEMORY_MIRROR_STATE": os.path.join(home, "state.json"),
                "MEMORY_MIRROR_LOCK": os.path.join(home, "mirror.lock"),
                "MEMORY_MIRROR_LOG": os.path.join(home, "mirror.log"),
                "MEMORY_MIRROR_CLAUDE_JSON": os.path.join(home, "claude.json"),
                "MEMORY_MIRROR_PROJECTS_DIR": os.path.join(home, "projects"),
                "MEMORY_MIRROR_HOST": "roundtrip-host"})
    return env


def _ruby(args, env):
    hook = os.path.join(lib.REPO, "hooks", "mirror-file-memory.rb")
    return subprocess.run(["ruby", "-E", "UTF-8", hook] + args, env=env, capture_output=True, text=True,
                          timeout=120)


@case("C-HOOK-1", "client_credentials token from Hydra (audience memory, TTL 3600) accepted end to end", "chain")
def token_roundtrip(ctx):
    proxy = _chain(ctx)
    home = tempfile.mkdtemp(prefix="hook-")
    try:
        ctx.env.hydra.clear()
        r = _ruby(["--check"], _hook_env(ctx, proxy, home))
        lines = [ln for ln in r.stdout.splitlines() if ln.startswith(("ok ", "FAIL"))]
        ctx.check(r.returncode == 0, f"--check exit {r.returncode}: {r.stdout[-800:]} {r.stderr[-800:]}")
        tok_reqs = ctx.env.hydra.taken(lambda q: q.path.endswith("/oauth2/token"))
        form = tok_reqs[0].body.decode() if tok_reqs else ""
        ctx.check("grant_type=client_credentials" in form and "audience=memory" in form, f"token form {form!r}")
        # Run-specific values (paths, ports, timestamps) are cut off; the check
        # names are the contract.
        names = [re.sub(r"(credentials file|issued by|session opened at) .*$", r"\1 <local>", ln)
                 for ln in lines]
        ctx.golden("check-lines", names)
        ctx.check(len(names) >= 10 and not any(n.startswith("FAIL") for n in names), f"check lines {names}")
    finally:
        shutil.rmtree(home, ignore_errors=True)


@case("C-HOOK-2", "hook ingest/forget (dataset file-memory) arguments and responses", "chain")
def ingest_forget(ctx):
    proxy = _chain(ctx)
    es = ctx.env.es
    es.reset_data()
    ctx.env._scenario = None
    home = tempfile.mkdtemp(prefix="hook-")
    try:
        env = _hook_env(ctx, proxy, home)
        note_dir = os.path.join(home, "projects", "-work-roundtrip", "memory")
        os.makedirs(note_dir)
        note = os.path.join(note_dir, "roundtrip-note.md")
        with open(note, "w", encoding="utf-8") as fh:
            fh.write("---\nname: roundtrip-note\ndescription: probe\n---\n\nA mirrored note body.\n")
        es.clear()
        r1 = _ruby(["--sweep"], env)
        bulk = es.taken(lambda q: q.path == "/_bulk")
        body_lines = [json.loads(ln) for q in bulk for ln in q.body.decode().splitlines() if ln.strip()][1::2]
        os.remove(note)
        es.clear()
        r2 = _ruby(["--sweep"], env)
        forgets = es.taken(lambda q: q.path.endswith("/_update_by_query") and "refresh" in q.query)
        state = json.load(open(env["MEMORY_MIRROR_STATE"], encoding="utf-8"))
        out = {"sweep1_exit": r1.returncode, "sweep2_exit": r2.returncode,
               "ingested": [{"dataset": d["dataset"], "doc_key": d["doc_key"],
                             "source_class": d["provenance"]["source_class"], "agent": d["provenance"]["agent"],
                             "tags": d["tags"]} for d in body_lines],
               "forget_queries": [lib.Normalizer()(q.json()["query"]) for q in forgets],
               "state_after_delete": state}
        ctx.golden("sweep", out)
        ctx.eq(out["ingested"][0]["doc_key"], "roundtrip-host/-work-roundtrip/roundtrip-note", "doc_key")
        ctx.eq(out["ingested"][0]["agent"], "memory-mirror", "provenance agent")
        ctx.eq((r1.returncode, r2.returncode), (0, 0), "sweeps succeed")
    finally:
        shutil.rmtree(home, ignore_errors=True)


@case("C-HOOK-3", "contracts/constants.json agrees with the hook source and the server's behaviour", "mcp")
def constants(ctx):
    with open(os.path.join(lib.REPO, "hooks", "mirror-file-memory.rb"), encoding="utf-8") as fh:
        hook = fh.read()
    observed = {
        "restricted_ingest_max_chars": int(re.search(r"^MAX_CHARS\s*=\s*([\d_]+)", hook, re.M).group(1)
                                           .replace("_", "")),
        "policy_denied_prefix": re.search(r'e\.text\.start_with\?\("([^"]+)"\)', hook).group(1),
        "dataset_scoped_tools": sorted(set(re.findall(r'client\.call\("(ingest|forget)"', hook))),
    }
    ctx.golden("constants", observed, path=CONSTANTS)
    from common import machine, mcp_client
    c = mcp_client(ctx.env.mcp(), machine("memory-mirror"))
    n = observed["restricted_ingest_max_chars"]
    ok_err, _ = c.call("ingest", {"document": "y" * n, "dataset": "file-memory", "doc_key": "const/max"})
    over_err, over_text = c.call("ingest", {"document": "y" * (n + 1), "dataset": "file-memory",
                                            "doc_key": "const/over"})
    ctx.eq(ok_err, False, f"{n} characters accepted")
    ctx.check(over_err and over_text.startswith(observed["policy_denied_prefix"]),
              f"{n + 1} characters refused with the prefix ({over_text[:40]!r})")
