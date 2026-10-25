#!/usr/bin/env bash
# Run Claude Code on a Claude subscription inside the Agent Workflow Firewall (awf).
#
# The agent step of every Claude node calls this. It gives the agent exactly three things:
# the checked-out working tree, the subscription token, and network access to the domains
# in AWF_ALLOW_DOMAINS. It gives it NO GitHub token and does not allow github.com, so the
# agent cannot write to GitHub at all; every write happens later in a deterministic job.
#
# Environment (inputs):
#   CLAUDE_CODE_OAUTH_TOKEN  required. From `claude setup-token`; uses the subscription,
#                            not API billing
#   CLAUDE_PROMPT_FILE       required. Prompt text, read inside the sandbox
#   CLAUDE_ALLOWED_TOOLS     required. Comma-separated --allowedTools list for this node
#   CLAUDE_MAX_TURNS         default 30
#   CLAUDE_PERMISSION_MODE   default acceptEdits. The review node uses `default`, so only the
#                            tools in CLAUDE_ALLOWED_TOOLS run at all
#   AGENT_TIMEOUT_MIN        default 20. awf kills the agent after this many minutes
#   AWF_ALLOW_DOMAINS        default api.anthropic.com. Add a package registry only if the
#                            repo's tests need one inside the sandbox
#   AGENT_WORKDIR            default $GITHUB_WORKSPACE. The tree the agent works in; the
#                            pull-request nodes check the PR head out below the workspace so
#                            the default branch's scripts stay beside it, not inside it
#   AGENT_OUT_DIR            default $AGENT_WORKDIR/.agent-out. Where the agent writes its
#                            non-code outputs; the result JSON lands here too
#
# Outputs, in AGENT_OUT_DIR: claude-result.json (claude's stdout) and claude-stderr.log
# (claude's stderr). classify_failure.py reads both when this step fails, to tell a usage or
# rate limit (retry later) from everything else (hand to a human).
#
# Versions are pinned and the awf binary is SHA256-verified against the release's own
# checksums.txt, rather than piping an install script from a moving branch into sudo.
set -euo pipefail

AWF_VERSION="v0.28.23"
AWF_SHA256="f5635f3a9246205667f794ed9f4ad19dc4863950b1458f6f8213162c8db379d3"
CLAUDE_CODE_VERSION="2.1.280"

: "${CLAUDE_CODE_OAUTH_TOKEN:?CLAUDE_CODE_OAUTH_TOKEN is not set (run claude setup-token and store it as a repository secret)}"
: "${CLAUDE_PROMPT_FILE:?CLAUDE_PROMPT_FILE is not set}"
: "${CLAUDE_ALLOWED_TOOLS:?CLAUDE_ALLOWED_TOOLS is not set}"
: "${GITHUB_WORKSPACE:?run inside GitHub Actions}"
: "${RUNNER_TEMP:?run inside GitHub Actions}"
MAX_TURNS="${CLAUDE_MAX_TURNS:-30}"
PERMISSION_MODE="${CLAUDE_PERMISSION_MODE:-acceptEdits}"
TIMEOUT_MIN="${AGENT_TIMEOUT_MIN:-20}"
ALLOW_DOMAINS="${AWF_ALLOW_DOMAINS:-api.anthropic.com}"
WORKDIR="${AGENT_WORKDIR:-$GITHUB_WORKSPACE}"
OUT_DIR="${AGENT_OUT_DIR:-$WORKDIR/.agent-out}"
case "$PERMISSION_MODE" in acceptEdits|default) ;; *) echo "::error::unsupported permission mode $PERMISSION_MODE"; exit 1 ;; esac
mkdir -p "$OUT_DIR"

echo "::group::install Claude Code $CLAUDE_CODE_VERSION"
npm install --global --no-audit --no-fund "@anthropic-ai/claude-code@$CLAUDE_CODE_VERSION" >/dev/null
claude --version
echo "::endgroup::"

echo "::group::install awf $AWF_VERSION (sha256-verified)"
curl -fsSL -o "$RUNNER_TEMP/awf" "https://github.com/github/gh-aw-firewall/releases/download/$AWF_VERSION/awf-linux-x64"
echo "$AWF_SHA256  $RUNNER_TEMP/awf" | sha256sum --check --status || {
  echo "::error::awf binary does not match the pinned SHA256; refusing to run it"; exit 1; }
sudo install -m 0755 "$RUNNER_TEMP/awf" /usr/local/bin/awf
awf --version
echo "::endgroup::"

# The token reaches the sandbox through a mode-600 env file outside the workspace, so it is
# neither on a command line (visible in the process list) nor inside the mounted tree.
ENV_FILE="$RUNNER_TEMP/claude-agent.env"
umask 077
{
  printf 'CLAUDE_CODE_OAUTH_TOKEN=%s\n' "$CLAUDE_CODE_OAUTH_TOKEN"
  printf 'CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1\n'
  printf 'DISABLE_AUTOUPDATER=1\n'
} > "$ENV_FILE"
trap 'rm -f "$ENV_FILE"' EXIT

# The command runs inside the container. Writing it to a file avoids three layers of
# quoting; the prompt is read there, not interpolated here.
INNER="$OUT_DIR/.run-inner.sh"
cat > "$INNER" <<EOF
#!/usr/bin/env bash
set -uo pipefail
command -v claude >/dev/null || { echo "claude is not visible inside the sandbox"; exit 127; }
cd "$WORKDIR"
claude -p "\$(cat "$CLAUDE_PROMPT_FILE")" \\
  --allowedTools "$CLAUDE_ALLOWED_TOOLS" \\
  --permission-mode "$PERMISSION_MODE" \\
  --max-turns "$MAX_TURNS" \\
  --output-format json < /dev/null > "$OUT_DIR/claude-result.json" 2> "$OUT_DIR/claude-stderr.log"
EOF
chmod 0755 "$INNER"

echo "allowed domains: $ALLOW_DOMAINS"
echo "allowed tools:   $CLAUDE_ALLOWED_TOOLS"
set +e
sudo -E awf \
  --allow-domains "$ALLOW_DOMAINS" \
  --agent-timeout "$TIMEOUT_MIN" \
  --container-workdir "$WORKDIR" \
  --env-file "$ENV_FILE" \
  -- bash "$INNER"
rc=$?
set -e
rm -f "$INNER"

# Firewall log summary on every run: a blocked domain the agent needed shows up here, and so
# does an attempt to reach something it should not.
if awf logs summary --help >/dev/null 2>&1; then
  # The runner user owns the step summary file, so the redirect deliberately stays outside sudo.
  # shellcheck disable=SC2024
  sudo awf logs summary >> "${GITHUB_STEP_SUMMARY:-/dev/null}" 2>/dev/null || true
fi

if [ -s "$OUT_DIR/claude-result.json" ] && command -v jq >/dev/null; then
  jq -r '"result: \(.subtype // "?")  turns: \(.num_turns // "?")  is_error: \(.is_error // "?")"' \
    "$OUT_DIR/claude-result.json" || true
fi
# stderr goes to a file so the failure classifier can read it; on failure, show its tail
# here too, since that file is not uploaded and the step log is where a human looks first.
if [ "$rc" -ne 0 ] && [ -s "$OUT_DIR/claude-stderr.log" ]; then
  echo "the agent run exited $rc; last 20 lines of claude's stderr:"
  tail -n 20 "$OUT_DIR/claude-stderr.log" || true
fi
exit "$rc"
