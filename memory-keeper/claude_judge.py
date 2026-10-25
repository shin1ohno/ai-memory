"""claude -p (subscription) judge for the memory-keeper worker.

Pure inference: no MCP tools, no elevated permissions. Invocation contract (§6):
  [CLAUDE_BIN, "-p", prompt, "--output-format", "json", "--model", model,
   "--strict-mcp-config", "--mcp-config", "{}"]
via subprocess.run(capture_output=True, timeout=120). The `--output-format json`
envelope wraps the model text in a "result" field; strip any code fences, then
parse the inner strict JSON verdict. 1 retry on failure, else raise JudgeError so
the caller can leave the fact raw (re-picked next tick).
"""

from __future__ import annotations

import json
import os
import re
import subprocess


class JudgeError(Exception):
    pass


def _strip_fences(text):
    s = text.strip()
    if s.startswith("```"):
        s = re.sub(r"^```[a-zA-Z0-9_-]*[ \t]*\n?", "", s)
        s = re.sub(r"\n?```$", "", s)
    return s.strip()


def _run_once(prompt, model, timeout):
    claude_bin = os.environ.get("CLAUDE_BIN", "/Users/shin1ohno/.local/bin/claude")
    cmd = [
        claude_bin,
        "-p",
        prompt,
        "--output-format",
        "json",
        "--model",
        model,
        "--strict-mcp-config",
        "--mcp-config",
        # claude >=2.1 requires an mcpServers record; "{}" is rejected with
        # "mcpServers: expected record, received undefined". Empty servers =
        # no tools, matching the pure-inference judge contract (§6).
        '{"mcpServers": {}}',
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    if proc.returncode != 0:
        raise JudgeError(f"claude exit {proc.returncode}: {(proc.stderr or '')[:400]}")
    try:
        envelope = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        raise JudgeError(f"claude envelope not JSON: {exc}")
    inner = envelope.get("result")
    if not isinstance(inner, str):
        raise JudgeError("claude envelope missing string 'result'")
    return _strip_fences(inner)


def judge_json(prompt, model, timeout=120, retries=1):
    """Run claude -p and return the parsed inner JSON. Raise JudgeError after
    `retries` retries if the call fails or the inner payload is not valid JSON."""
    last = None
    for _ in range(retries + 1):
        try:
            inner = _run_once(prompt, model, timeout)
            return json.loads(inner)
        except (JudgeError, json.JSONDecodeError, subprocess.TimeoutExpired, OSError) as exc:
            last = exc
    raise JudgeError(f"claude judge failed after {retries + 1} attempts: {last}")
