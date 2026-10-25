#!/usr/bin/env bash

# Black-box tests for hooks/mirror-file-memory.rb. A python3 fake stands in for
# both the OAuth token endpoint and the streamable-HTTP MCP server on
# 127.0.0.1; it records every request to a JSONL log, and each case asserts on
# that log plus the hook's stdout (the additionalContext the agent would see),
# its log file and its state file. Every case runs in its own throwaway HOME.
#
# Covered: server-name config resolution (headersHelper token), Bearer from a
# client_credentials token, refusal of a non-https url, token failure surfaced
# as additionalContext, the first-bulk guard, per-item state (a sweep killed
# mid-run keeps what it finished), the session-start time budget, a Japanese
# payload under a locale-less env, forget by (dataset, doc_key), the 45,000
# character cap (client_credentials only; the server form keeps its 512 KB
# guard), the local credentials-file check, the trailing-slash redirect,
# --check against an enforcing and a non-enforcing server, and that neither the
# client secret nor any token reaches stdout or the log.
#
# Usage: bash test-mirror-file-memory.sh <path-to-mirror-file-memory.rb>

set -uo pipefail
case "${1:?path to mirror-file-memory.rb}" in
  /*) HOOK="$1" ;;
  *) HOOK="$PWD/$1" ;;
esac
# Resolve the real interpreter once: a version-manager shim (rbenv / mise) on
# PATH can fail once HOME points at a throwaway directory.
RUBY="${RUBY:-$(ruby -e 'print RbConfig.ruby')}"
D=$(mktemp -d)
SERVER_PID=""
trap 'kill "$SERVER_PID" 2>/dev/null; rm -rf "$D"' EXIT
pass=0; fail=0
SECRET="s3cr3t-Value-0123456789abcdefXYZ"
ALL_OUT="$D/all-output.txt"
: > "$ALL_OUT"

# --- fake token + MCP server -------------------------------------------------

cat > "$D/fake.py" <<'PY'
import base64, json, os, sys, threading, time, uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, unquote_plus

D = sys.argv[1]
LOG = os.path.join(D, "requests.jsonl")
BEHAVIOR = os.path.join(D, "behavior.json")
LOCK = threading.Lock()
LIVE = {}  # doc_id -> (dataset, doc_key)


def behavior():
    try:
        with open(BEHAVIOR) as f:
            return json.load(f)
    except Exception:
        return {}


def record(entry):
    with LOCK:
        with open(LOG, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")


def b64url(obj):
    return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def reply(self, code, body=b"", headers=None, ctype="application/json"):
        self.send_response(code)
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        raw = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        b = behavior()
        if self.path == "/oauth2/token":
            return self.token(raw, b)
        if self.path == "/memory/mcp/":
            record({"path": self.path})
            return self.reply(307, headers={"Location": "/memory/mcp"})
        if self.path == "/memory/mcp":
            return self.mcp(raw, b)
        record({"path": self.path})
        self.reply(404)

    def token(self, raw, b):
        auth = self.headers.get("Authorization", "")
        basic = ""
        if auth.startswith("Basic "):
            user, _, pw = base64.b64decode(auth[6:]).decode().partition(":")
            basic = unquote_plus(user) + ":" + unquote_plus(pw)
        form = {k: v[0] for k, v in parse_qs(raw.decode()).items()}
        record({"path": "/oauth2/token", "basic": basic, "form": form})
        status = b.get("token_status", 200)
        if status != 200:
            body = {"error": "invalid_client", "error_description": "LEAKY-DESCRIPTION"}
            return self.reply(status, json.dumps(body).encode())
        cid = basic.split(":", 1)[0]
        now = int(time.time())
        claims = {"sub": cid, "client_id": cid, "aud": [form.get("audience", "")],
                  "iat": now, "exp": now + b.get("ttl", 3600)}
        tok = b64url({"alg": "none", "typ": "JWT"}) + "." + b64url(claims) + ".c2ln"
        self.reply(200, json.dumps({"access_token": tok, "token_type": "bearer",
                                    "expires_in": 3600}).encode())

    def mcp(self, raw, b):
        msg = json.loads(raw.decode("utf-8"))
        method = msg.get("method")
        entry = {"path": "/memory/mcp", "auth": self.headers.get("Authorization", ""), "rpc": method}
        if method == "tools/call":
            entry["tool"] = msg["params"]["name"]
            entry["args"] = msg["params"].get("arguments", {})
        record(entry)
        if method == "initialize":
            return self.sse(msg["id"], {"protocolVersion": "2025-06-18", "capabilities": {},
                                        "serverInfo": {"name": "fake", "version": "0"}},
                            {"mcp-session-id": "sess-1"})
        if method and method.startswith("notifications/"):
            return self.reply(202)
        if method == "tools/call":
            return self.tool(msg["id"], entry["tool"], entry["args"], b)
        self.reply(400)

    def sse(self, rid, result, headers=None):
        payload = json.dumps({"jsonrpc": "2.0", "id": rid, "result": result}, ensure_ascii=False)
        body = ("event: message\ndata: " + payload + "\n\n").encode("utf-8")
        self.reply(200, body, headers, ctype="text/event-stream")

    def result(self, rid, obj, is_error=False):
        text = obj if isinstance(obj, str) else json.dumps(obj)
        self.sse(rid, {"content": [{"type": "text", "text": text}], "isError": is_error})

    def tool(self, rid, name, args, b):
        if b.get("policy") == "enforce":
            ds = args.get("dataset")
            if name not in ("ingest", "forget") or (ds is not None and ds != "file-memory"):
                return self.result(rid, "policy_denied: not permitted for this client", True)
        if name == "ingest":
            key = args.get("doc_key", "")
            if any(s in key for s in b.get("slow_keys", [])):
                time.sleep(b.get("slow_seconds", 30))
            if b.get("ingest_delay"):
                time.sleep(b["ingest_delay"])
            if any(s in key for s in b.get("fail_keys", [])):
                return self.result(rid, "ingest failed: backend unavailable", True)
            doc_id = uuid.uuid4().hex
            with LOCK:
                for k, v in list(LIVE.items()):
                    if v == (args.get("dataset"), key):
                        del LIVE[k]
                LIVE[doc_id] = (args.get("dataset"), key)
            return self.result(rid, {"doc_id": doc_id, "chunk_count": 1})
        if name == "forget":
            with LOCK:
                if args.get("id"):
                    n = 1 if LIVE.pop(args["id"], None) else 0
                else:
                    target = (args.get("dataset"), args.get("doc_key"))
                    ids = [k for k, v in LIVE.items() if v == target]
                    for k in ids:
                        del LIVE[k]
                    n = len(ids)
            return self.result(rid, {"superseded_count": n})
        if name == "recall":
            return self.result(rid, {"hits": []})
        return self.result(rid, "unknown tool " + name, True)


srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
srv.daemon_threads = True
with open(os.path.join(D, "port.tmp"), "w") as f:
    f.write(str(srv.server_address[1]))
os.rename(os.path.join(D, "port.tmp"), os.path.join(D, "port"))
srv.serve_forever()
PY

# count [field=value | field~substring | field!] ... -> matching request records
cat > "$D/q.py" <<'PY'
import json, sys

log, *conds = sys.argv[1:]


def get(rec, path):
    cur = rec
    for p in path.split("."):
        if not isinstance(cur, dict) or p not in cur:
            return None
        cur = cur[p]
    return cur


try:
    with open(log, encoding="utf-8") as f:
        lines = f.read().splitlines()
except FileNotFoundError:
    lines = []
n = 0
for line in lines:
    rec = json.loads(line)
    ok = True
    for c in conds:
        eq, tl = c.find("="), c.find("~")
        if c.endswith("!"):
            ok = ok and get(rec, c[:-1]) is None
        elif tl != -1 and (eq == -1 or tl < eq):
            k, v = c.split("~", 1)
            val = get(rec, k)
            ok = ok and val is not None and v in str(val)
        else:
            k, v = c.split("=", 1)
            ok = ok and str(get(rec, k)) == v
    n += ok
print(n)
PY

python3 "$D/fake.py" "$D" 2> "$D/server.err" &
SERVER_PID=$!
for _ in $(seq 1 50); do [ -f "$D/port" ] && break; sleep 0.1; done
if [ ! -f "$D/port" ]; then
  echo "FAIL fake server did not start:"; cat "$D/server.err"; exit 1
fi
PORT=$(cat "$D/port")
MCP_URL="http://127.0.0.1:$PORT/memory/mcp"
TOKEN_URL="http://127.0.0.1:$PORT/oauth2/token"

# --- helpers ------------------------------------------------------------------

t() { # t <name> <command...>  — pass when the command exits 0
  local name="$1"; shift
  if "$@"; then
    pass=$((pass+1)); printf 'ok   %s\n' "$name"
  else
    fail=$((fail+1)); printf 'FAIL %s\n' "$name"
  fi
}
not() { ! "$@"; }
count() { python3 "$D/q.py" "$D/requests.jsonl" "$@"; }
is() { [ "$1" = "$2" ]; }
reset_server() { # reset_server [behavior-json]
  local b='{}'
  [ $# -gt 0 ] && b="$1"
  : > "$D/requests.jsonl"
  printf '%s' "$b" > "$D/behavior.json"
}

mkhome() { # mkhome <name>  — sets H to a fresh HOME with valid credentials
  H="$D/$1"
  mkdir -p "$H/.claude/projects/proj/memory" "$H/.config/memory-mirror"
  printf 'MEMORY_MIRROR_CLIENT_ID=memory-mirror\nMEMORY_MIRROR_CLIENT_SECRET=%s\n' "$SECRET" \
    > "$H/.config/memory-mirror/client.env"
  chmod 600 "$H/.config/memory-mirror/client.env"
}
new_config() { # new_config <url> <token_url>
  cat > "$H/.claude/memory-mirror.json" <<EOF
{"enabled": true, "dataset": "file-memory", "host": "testhost",
 "url": "$1",
 "auth": {"type": "client_credentials", "token_url": "$2", "audience": "memory",
          "credentials_file": "~/.config/memory-mirror/client.env"}}
EOF
}
note() { printf '%s\n' "$2" > "$H/.claude/projects/proj/memory/$1.md"; }
note_path() { printf '%s' "$H/.claude/projects/proj/memory/$1.md"; }
state_file() { printf '%s' "$H/.claude/memory-mirror-state.json"; }
state_keys() {
  python3 -c 'import json,sys; print(" ".join(sorted(json.load(open(sys.argv[1])))))' "$(state_file)"
}
hook_write() { # PostToolUse for a Write of note <name>
  printf '{"tool_name":"Write","tool_input":{"file_path":"%s"}}' "$(note_path "$1")" |
    HOME="$H" MEMORY_MIRROR_HOST=oldhost "$RUBY" "$HOOK" 2>>"$D/stderr.txt" | tee -a "$ALL_OUT"
}
sweep() { HOME="$H" "$RUBY" "$HOOK" --sweep "$@" 2>>"$D/stderr.txt" | tee -a "$ALL_OUT"; }

# --- server-name config (work overlay) ----------------------------------------

mkhome old
printf '{"server": "memory-work", "dataset": "file-memory", "enabled": true}\n' > "$H/.claude/memory-mirror.json"
printf '#!/bin/sh\nprintf %s\n' "'{\"Authorization\": \"Bearer helper-token\"}'" > "$H/helper.sh"
chmod +x "$H/helper.sh"
printf '{"mcpServers": {"memory-work": {"type": "http", "url": "%s", "headersHelper": "%s"}}}\n' \
  "$MCP_URL" "$H/helper.sh" > "$H/.claude.json"
note a "old format note"
reset_server
out=$(hook_write a)
t "server form: ingest carries the headersHelper token" \
  is "$(count tool=ingest 'auth=Bearer helper-token' args.doc_key=oldhost/proj/a args.dataset=file-memory)" 1
t "server form: no token endpoint call" is "$(count path=/oauth2/token)" 0
t "server form: success is silent" test -z "$out"
t "server form: helper token never logged" not grep -q helper-token "$H/.claude/memory-mirror.log"
# The 45,000-character cap is the restricted client's server policy; the
# memory-work store behind the server form has none, so only the 512 KB body
# guard applies there.
python3 -c 'print("x" * 45100)' > "$(note_path long)"
python3 -c 'print("x" * 530000)' > "$(note_path huge)"
reset_server
out=$(hook_write long)
t "server form: a 45,100-char note is still sent" is "$(count tool=ingest args.doc_key=oldhost/proj/long)" 1
t "server form: no size report for it" test -z "$out"
reset_server
out=$(hook_write huge)
t "server form: a note past 512 KB is not sent" is "$(count tool=ingest args.doc_key=oldhost/proj/huge)" 0
t "server form: 512 KB guard reported in bytes" grep -q 'exceed 524288 bytes' <<<"$out"
rm -f "$(note_path long)" "$(note_path huge)"

# --- client_credentials: Bearer ------------------------------------------------

mkhome bearer
new_config "$MCP_URL" "$TOKEN_URL"
note a "new format note"
reset_server
out=$(hook_write a)
t "token request: client_secret_basic, grant and audience" \
  is "$(count path=/oauth2/token "basic=memory-mirror:$SECRET" form.grant_type=client_credentials form.audience=memory)" 1
t "token request: no scope parameter" is "$(count path=/oauth2/token 'form.scope!')" 1
t "ingest carries the fetched Bearer token" is "$(count tool=ingest 'auth~Bearer eyJ' args.doc_key=testhost/proj/a)" 1
t "config host is the doc_key prefix" is "$(count tool=ingest 'args.document~source_host: testhost')" 1
t "Bearer success is silent" test -z "$out"
t "PostToolUse never creates the state file" test ! -e "$(state_file)"

# --- non-https url refused ------------------------------------------------------

mkhome insecure
new_config "http://localhost:$PORT/memory/mcp" "$TOKEN_URL"
note a "x"
reset_server
out=$(hook_write a)
t "http:// url refused before any request" is "$(count)" 0
t "refusal reaches the agent as PostToolUse context" grep -q '"hookEventName":"PostToolUse"' <<<"$out"
t "refusal names https" grep -q 'must be an https' <<<"$out"

new_config "$MCP_URL" "http://localhost:$PORT/oauth2/token"
reset_server
out=$(hook_write a)
t "http:// token_url refused too" grep -q 'auth.token_url. must be an https' <<<"$out"

# --- token failure ---------------------------------------------------------------

mkhome tokfail
new_config "$MCP_URL" "$TOKEN_URL"
note a "x"
echo '{}' > "$(state_file)"
reset_server '{"token_status": 401}'
out=$(sweep --session-start)
t "token failure surfaced as SessionStart context" grep -q '"hookEventName":"SessionStart"' <<<"$out"
t "token failure names status and OAuth error code" grep -q 'token endpoint answered HTTP 401 (invalid_client)' <<<"$out"
t "no MCP call after a token failure" is "$(count path=/memory/mcp)" 0
t "error_description is never surfaced" not grep -q LEAKY-DESCRIPTION <<<"$out"
t "error_description is never logged" not grep -q LEAKY-DESCRIPTION "$H/.claude/memory-mirror.log"

# --- first-bulk guard ----------------------------------------------------------

mkhome bulk
new_config "$MCP_URL" "$TOKEN_URL"
for i in $(seq 1 21); do note "n$i" "note $i"; done
reset_server
out=$(sweep --session-start)
t "first bulk: session start sends nothing" is "$(count path=/oauth2/token)" 0
t "first bulk: agent is told to run --sweep by hand" grep -q -- '--sweep' <<<"$out"
t "first bulk: no state file created" test ! -e "$(state_file)"
out=$(sweep); rc=$?
t "first bulk: manual --sweep imports all 21" is "$(count tool=ingest)" 21
t "first bulk: manual --sweep records all 21" is "$(state_keys | wc -w | tr -d ' ')" 21
t "first bulk: manual --sweep exits 0" is "$rc" 0
reset_server
out=$(sweep --session-start)
t "steady state: nothing sent, nothing said" test -z "$out" -a "$(count)" = 0

# --- per-item state (sweep killed mid-run) -------------------------------------

mkhome kill
new_config "$MCP_URL" "$TOKEN_URL"
note a1 "one"; note a2 "two"; note a3-slow "three"
reset_server '{"slow_keys": ["a3-slow"], "slow_seconds": 30}'
HOME="$H" "$RUBY" "$HOOK" --sweep >/dev/null 2>&1 &
pid=$!
for _ in $(seq 1 100); do
  [ "$(count tool=ingest args.doc_key=testhost/proj/a3-slow)" = 1 ] && break
  sleep 0.1
done
kill -9 "$pid" 2>/dev/null; wait "$pid" 2>/dev/null
t "killed sweep kept the items it finished" is "$(state_keys)" "testhost/proj/a1 testhost/proj/a2"

# --- session-start time budget ---------------------------------------------------

mkhome budget
new_config "$MCP_URL" "$TOKEN_URL"
note b1 "one"; note b2 "two"; note b3 "three"
echo '{}' > "$(state_file)"
reset_server '{"ingest_delay": 1.2}'
out=$(HOME="$H" MEMORY_MIRROR_SESSION_BUDGET=1 "$RUBY" "$HOOK" --sweep --session-start 2>/dev/null)
t "budget: session start stops after the budget" is "$(count tool=ingest)" 1
t "budget: stop is reported" grep -q 'session-start budget' <<<"$out"
t "budget: finished item is in state" is "$(state_keys)" "testhost/proj/b1"

# --- Japanese payload, locale-less env ---------------------------------------------

mkhome ja
new_config "$MCP_URL" "$TOKEN_URL"
JA="日本語のメモ：ミラー試験"
note ja "$JA"
reset_server
out=$(printf '{"tool_name":"Write","tool_input":{"file_path":"%s","content":"%s"}}' "$(note_path ja)" "$JA" |
  env -i PATH="$PATH" HOME="$H" "$RUBY" "$HOOK" 2>&1)
t "Japanese note arrives intact without a UTF-8 locale" is "$(count tool=ingest "args.document~$JA")" 1
t "Japanese payload: silent" test -z "$out"

# --- deletion -> forget by (dataset, doc_key) ----------------------------------

mkhome del
new_config "$MCP_URL" "$TOKEN_URL"
note d1 "keep"; note d2 "drop"
reset_server
sweep >/dev/null
rm "$(note_path d2)"
reset_server
sweep >/dev/null
t "deleted note forgotten by (dataset, doc_key)" \
  is "$(count tool=forget args.dataset=file-memory args.doc_key=testhost/proj/d2 'args.id!')" 1
t "state drops the forgotten key" is "$(state_keys)" "testhost/proj/d1"

# --- 45,000 character cap ----------------------------------------------------------

mkhome big
new_config "$MCP_URL" "$TOKEN_URL"
note small "small"
python3 -c 'print("あ" * 20000)' > "$(note_path wide)"
python3 -c 'print("あ" * 46000)' > "$(note_path big)"
echo '{}' > "$(state_file)"
reset_server
out=$(sweep --session-start)
t "cap: oversized note not sent" is "$(count tool=ingest args.doc_key=testhost/proj/big)" 0
t "cap: 60 KB of Japanese under 45,000 chars is sent" is "$(count tool=ingest args.doc_key=testhost/proj/wide)" 1
t "cap: reported to the agent" grep -q 'exceed 45000 characters' <<<"$out"
t "cap: logged at WARN" grep -q 'WARN skipped testhost/proj/big' "$H/.claude/memory-mirror.log"
reset_server
out=$(sweep --session-start)
t "cap: steady state stays offline" is "$(count)" 0
t "cap: still reported until it shrinks" grep -q 'testhost/proj/big' <<<"$out"

# --- local credentials-file check -------------------------------------------------

mkhome perm
new_config "$MCP_URL" "$TOKEN_URL"
note p "x"
sweep >/dev/null
chmod 644 "$H/.config/memory-mirror/client.env"
reset_server
out=$(sweep --session-start)
t "creds: loose mode reported on a steady-state sweep" grep -q 'mode 0644' <<<"$out"
t "creds: steady-state check is local" is "$(count)" 0
printf 'MEMORY_MIRROR_CLIENT_ID=memory-mirror\n' > "$H/.config/memory-mirror/client.env"
chmod 600 "$H/.config/memory-mirror/client.env"
out=$(sweep --session-start)
t "creds: missing secret key reported" grep -q 'lacks MEMORY_MIRROR_CLIENT_SECRET' <<<"$out"

# --- trailing-slash redirect ---------------------------------------------------------

mkhome slash
new_config "$MCP_URL/" "$TOKEN_URL"
note s "x"
reset_server
out=$(hook_write s)
t "3xx: reported with the trailing-slash cause" grep -q 'trailing slash' <<<"$out"
t "3xx: redirect not followed" is "$(count tool=ingest)" 0

# --- --check ---------------------------------------------------------------------------

mkhome chk
new_config "$MCP_URL" "$TOKEN_URL"
reset_server '{"policy": "enforce"}'
out=$(HOME="$H" "$RUBY" "$HOOK" --check 2>&1); rc=$?
printf '%s\n' "$out" >> "$ALL_OUT"
t "--check: passes against an enforcing server" is "$rc" 0
t "--check: three denials by policy_denied:" is "$(grep -c 'denied with policy_denied:' <<<"$out")" 3
t "--check: forgot by id and by (dataset, doc_key)" \
  test "$(count tool=forget 'args.id~')" -ge 1 -a "$(count tool=forget args.doc_key=testhost/_selftest/roundtrip)" -ge 1
t "--check: never prints the token" not grep -q 'eyJ' <<<"$out"

reset_server '{"policy": "open"}'
out=$(HOME="$H" "$RUBY" "$HOOK" --check 2>&1); rc=$?
printf '%s\n' "$out" >> "$ALL_OUT"
t "--check: fails when a denial succeeds" not is "$rc" 0
t "--check: says the policy is not in force" grep -q 'NOT denied' <<<"$out"
t "--check: removes the unexpected write" grep -q 'cleaned up the unexpected write' <<<"$out"

reset_server '{"policy": "enforce", "ttl": 7200}'
out=$(HOME="$H" "$RUBY" "$HOOK" --check 2>&1); rc=$?
t "--check: wrong token lifetime fails" not is "$rc" 0

# --- secrets never leave ---------------------------------------------------------------

cat "$D"/*/.claude/memory-mirror.log >> "$D/all-logs.txt" 2>/dev/null
t "client secret never in stdout" not grep -q "$SECRET" "$ALL_OUT"
t "client secret never in stderr" not grep -q "$SECRET" "$D/stderr.txt"
t "client secret never logged" not grep -q "$SECRET" "$D/all-logs.txt"
t "no token in any log" not grep -q 'eyJ' "$D/all-logs.txt"

printf '\n%d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
