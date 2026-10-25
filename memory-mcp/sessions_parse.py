"""Claude Code transcript parser (design spec §6.1, C1). Pure, no I/O.

Turns raw (already masked) JSONL lines into message docs for
`memory-session-message` (§7.1.2) and a per-segment session delta that
`merge_session` folds into the `memory-session` doc (§7.1.1).

Lenient by design: an unknown record type, an unknown content-block type, or a
line that is not a JSON object is counted and skipped, never raised (§8 row 4 —
Claude Code changes its format without notice). The counters surface in
`/status`.
"""

from __future__ import annotations

import hashlib
import json
import re

PARSER_VERSION = "p1"

INDEXED_TYPES = frozenset({"user", "assistant"})
# Record types that are known and deliberately not indexed as messages. Anything
# else lands in unknown_types.
KNOWN_OTHER_TYPES = frozenset({
    "attachment", "ai-title", "custom-title", "summary", "system", "relocated",
    "file-history-snapshot", "queue-operation", "progress", "result",
    "session-search-tombstone",
})
KNOWN_BLOCK_TYPES = frozenset({"text", "thinking", "redacted_thinking", "tool_use",
                               "tool_result", "image", "document"})

NOISE_TAGS = ("system-reminder", "command-name", "command-message", "command-args",
              "local-command-stdout", "local-command-stderr", "task-notification",
              "bash-stdout", "bash-stderr")
_NOISE_RE = re.compile(
    r"\A\s*<(" + "|".join(re.escape(t) for t in NOISE_TAGS) + r")\b[^>]*>[\s\S]*?</\1>\s*")

TOOL_INPUT_FIELDS = ("command", "file_path", "path", "pattern", "url", "query", "description")
TOOL_INPUT_CAP = 2048
TOOL_RESULT_HEAD = 1536
TOOL_RESULT_TAIL = 512
TITLE_MAX = 120
INTERACTIVE_ENTRYPOINTS = frozenset({"cli", "claude-desktop"})

# Title source priority, highest first (§6.1).
TITLE_PRIORITY = {"custom-title": 4, "ai-title": 3, "summary": 2, "first-user": 1}


def encode_cwd(cwd: str) -> str:
    """Claude Code's project directory name for a cwd (§6.1; 210/210 measured)."""
    return re.sub(r"[^A-Za-z0-9-]", "-", cwd)


def doc_id(session_key: str, uuid: str) -> str:
    return hashlib.sha1(f"{session_key}:{uuid}".encode("utf-8")).hexdigest()


def strip_noise(text: str) -> tuple[str, bool]:
    """Remove the leading injected blocks (§6.1). Returns (text, stripped?)."""
    stripped = False
    while True:
        m = _NOISE_RE.match(text)
        if not m:
            break
        text = text[m.end():]
        stripped = True
    return text.strip(), stripped


def _cap_bytes(s: str, n: int) -> str:
    b = s.encode("utf-8")
    if len(b) <= n:
        return s
    return b[:n].decode("utf-8", "ignore")


def head_tail(s: str, head: int = TOOL_RESULT_HEAD, tail: int = TOOL_RESULT_TAIL) -> str:
    """First `head` + "…" + last `tail` bytes, UTF-8 safe (§3.2 decision)."""
    b = s.encode("utf-8")
    if len(b) <= head + tail:
        return s
    return b[:head].decode("utf-8", "ignore") + "…" + b[-tail:].decode("utf-8", "ignore")


def _tool_result_text(content) -> str:
    if isinstance(content, str):
        return content
    parts = []
    if isinstance(content, list):
        for blk in content:
            if isinstance(blk, dict) and blk.get("type") == "text" and isinstance(blk.get("text"), str):
                parts.append(blk["text"])
    return "\n".join(parts)


def _extract(message, counters) -> tuple[list[str], list[str], list[str], bool]:
    """(text parts, tool parts, tool names, noise_stripped) from message.content."""
    texts: list[str] = []
    tools: list[str] = []
    names: list[str] = []
    noise = False
    content = message.get("content") if isinstance(message, dict) else None
    if isinstance(content, str):
        t, noise = strip_noise(content)
        if t:
            texts.append(t)
        return texts, tools, names, noise
    if not isinstance(content, list):
        return texts, tools, names, noise
    for blk in content:
        if not isinstance(blk, dict):
            continue
        bt = blk.get("type")
        if bt == "text":
            raw = blk.get("text")
            if isinstance(raw, str):
                t, n = strip_noise(raw)
                noise = noise or n
                if t:
                    texts.append(t)
        elif bt == "tool_use":
            name = blk.get("name")
            seg = []
            if isinstance(name, str) and name:
                names.append(name)
                seg.append(name)
            inp = blk.get("input")
            if isinstance(inp, dict):
                for f in TOOL_INPUT_FIELDS:
                    v = inp.get(f)
                    if isinstance(v, str) and v:
                        seg.append(_cap_bytes(v, TOOL_INPUT_CAP))
            if seg:
                tools.append(" ".join(seg))
        elif bt == "tool_result":
            t = _tool_result_text(blk.get("content"))
            if t:
                tools.append(head_tail(t))
        elif bt in KNOWN_BLOCK_TYPES:
            pass  # thinking is never indexed; images are dropped
        else:
            key = f"block:{bt if isinstance(bt, str) else type(bt).__name__}"
            counters["unknown_types"][key] = counters["unknown_types"].get(key, 0) + 1
    return texts, tools, names, noise


def new_counters() -> dict:
    return {"unknown_types": {}, "skipped_noise": 0, "skipped_meta": 0,
            "invalid_lines": 0, "missing_uuid": 0, "tombstones": 0}


def parse_lines(session_key: str, kind: str, lines: list, start_offset: int, *,
                host: str, session_id: str, agent_id: str | None = None,
                known_entrypoint: str | None = None, redact_version: str = "") -> dict:
    """Parse one segment.

    `lines` are the masked JSON lines of the segment, in file order.
    `known_entrypoint` is the session's entrypoint from earlier segments (the
    first record decides `interactive`, and a later segment does not see it).

    Returns {"docs": [...], "delta": {...}, "counters": {...}}. Each doc carries
    `_id`. `line_offset` is `start_offset + line index`: monotonic and unique
    within a generation (every line occupies at least one byte), which is all
    ordering and generation purge need; it is not a byte position, because the
    masked line lengths differ from the raw ones the cursor counts.
    """
    counters = new_counters()
    docs: list[dict] = []
    delta = {
        "first_cwd": None, "cwd_candidates": [], "git_branch": None, "entrypoint": None,
        "cc_version": None, "started_at": None, "updated_at": None,
        "titles": {}, "message_count": 0, "text_message_count": 0, "tombstones": 0,
    }
    entrypoint = known_entrypoint
    for idx, line in enumerate(lines):
        try:
            rec = json.loads(line) if isinstance(line, str) else None
        except ValueError:
            rec = None
        if not isinstance(rec, dict):
            counters["invalid_lines"] += 1
            continue
        rtype = rec.get("type")
        ts = rec.get("timestamp") if isinstance(rec.get("timestamp"), str) else None
        if ts:
            if delta["started_at"] is None or ts < delta["started_at"]:
                delta["started_at"] = ts
            if delta["updated_at"] is None or ts > delta["updated_at"]:
                delta["updated_at"] = ts
        cwd = rec.get("cwd") if isinstance(rec.get("cwd"), str) else None
        if cwd and delta["first_cwd"] is None:
            delta["first_cwd"] = cwd
        rel = rec.get("relocatedCwd")
        if isinstance(rel, str) and rel and rel not in delta["cwd_candidates"]:
            delta["cwd_candidates"].append(rel)
        if isinstance(rec.get("gitBranch"), str):
            delta["git_branch"] = rec["gitBranch"]
        if isinstance(rec.get("version"), str):
            delta["cc_version"] = rec["version"]
        if isinstance(rec.get("entrypoint"), str) and delta["entrypoint"] is None:
            delta["entrypoint"] = rec["entrypoint"]
            if entrypoint is None:
                entrypoint = rec["entrypoint"]

        if rtype == "custom-title" and isinstance(rec.get("customTitle"), str):
            delta["titles"]["custom-title"] = rec["customTitle"]
            continue
        if rtype == "ai-title" and isinstance(rec.get("aiTitle"), str):
            delta["titles"]["ai-title"] = rec["aiTitle"]
            continue
        if rtype == "summary" and isinstance(rec.get("summary"), str):
            delta["titles"]["summary"] = rec["summary"]
            continue
        if rtype == "session-search-tombstone":
            counters["tombstones"] += 1
            delta["tombstones"] += 1
            continue
        if rtype not in INDEXED_TYPES:
            if rtype not in KNOWN_OTHER_TYPES:
                key = rtype if isinstance(rtype, str) else f"<{type(rtype).__name__}>"
                counters["unknown_types"][key] = counters["unknown_types"].get(key, 0) + 1
            continue
        if rec.get("isMeta") is True or rec.get("isCompactSummary") is True:
            counters["skipped_meta"] += 1
            continue
        uuid = rec.get("uuid")
        if not isinstance(uuid, str) or not uuid:
            counters["missing_uuid"] += 1
            continue
        msg = rec.get("message") if isinstance(rec.get("message"), dict) else {}
        texts, tools, names, noise = _extract(msg, counters)
        if noise:
            counters["skipped_noise"] += 1
        text = "\n".join(texts)
        if rtype == "user" and text and "first-user" not in delta["titles"] \
                and not rec.get("isSidechain") and not tools:
            delta["titles"]["first-user"] = text
        delta["message_count"] += 1
        if text:
            delta["text_message_count"] += 1
        role = msg.get("role") if isinstance(msg.get("role"), str) else rtype
        doc = {
            "_id": doc_id(session_key, uuid),
            "session_key": session_key,
            "session_id": session_id,
            "host": host,
            "cwd": cwd,
            "interactive": entrypoint in INTERACTIVE_ENTRYPOINTS,
            "uuid": uuid,
            "parent_uuid": rec.get("parentUuid") if isinstance(rec.get("parentUuid"), str) else None,
            "message_id": msg.get("id") if isinstance(msg.get("id"), str) else None,
            "role": role,
            "ts": ts,
            "is_sidechain": bool(rec.get("isSidechain")) or kind == "subagent",
            "agent_id": agent_id or (rec.get("agentId") if isinstance(rec.get("agentId"), str) else None),
            "text": text or None,
            "tool_text": "\n".join(tools) or None,
            "tool_names": sorted(set(names)),
            "embedding_status": "pending" if text else "none",
            "line_offset": start_offset + idx,
            "redact_version": redact_version,
        }
        docs.append(doc)
    delta["entrypoint_effective"] = entrypoint
    return {"docs": docs, "delta": delta, "counters": counters}


def choose_resume_cwd(cwd_candidates: list, project_dir: str) -> tuple[str | None, bool]:
    """The candidate (first cwd, then each relocatedCwd in order) whose encoding
    equals the JSONL's parent directory name; else the first cwd, unverified."""
    for c in cwd_candidates:
        if isinstance(c, str) and encode_cwd(c) == project_dir:
            return c, True
    first = cwd_candidates[0] if cwd_candidates else None
    return first, False


def _truncate_title(t: str) -> str:
    t = " ".join(t.split())
    return t if len(t) <= TITLE_MAX else t[:TITLE_MAX]


def merge_session(existing: dict | None, delta: dict, *, project_dir: str) -> dict:
    """Fold a segment delta into the session doc fields (pure).

    Title: highest-priority source wins; within the same source the later
    segment wins, except first-user which keeps the first one seen."""
    s = dict(existing or {})
    if delta.get("first_cwd") and not s.get("cwd"):
        s["cwd"] = delta["first_cwd"]
    cands = list(s.get("cwd_candidates") or [])
    if s.get("cwd") and s["cwd"] not in cands:
        cands.insert(0, s["cwd"])
    for c in delta.get("cwd_candidates") or []:
        if c not in cands:
            cands.append(c)
    s["cwd_candidates"] = cands
    rc, ok = choose_resume_cwd(cands, project_dir)
    s["resume_cwd"] = rc
    s["resume_cwd_verified"] = ok
    for f in ("git_branch", "cc_version"):
        if delta.get(f):
            s[f] = delta[f]
    if delta.get("entrypoint") and not s.get("entrypoint"):
        s["entrypoint"] = delta["entrypoint"]
    s["interactive"] = s.get("entrypoint") in INTERACTIVE_ENTRYPOINTS
    if delta.get("started_at") and (not s.get("started_at") or delta["started_at"] < s["started_at"]):
        s["started_at"] = delta["started_at"]
    if delta.get("updated_at") and (not s.get("updated_at") or delta["updated_at"] > s["updated_at"]):
        s["updated_at"] = delta["updated_at"]
    cur = TITLE_PRIORITY.get(s.get("title_source") or "", 0)
    for src in ("custom-title", "ai-title", "summary", "first-user"):
        t = (delta.get("titles") or {}).get(src)
        if not t:
            continue
        p = TITLE_PRIORITY[src]
        if p > cur or (p == cur and src != "first-user"):
            s["title"] = _truncate_title(t)
            s["title_source"] = src
            cur = p
        break  # only the best source in this segment competes
    s["parser_version"] = PARSER_VERSION
    return s
