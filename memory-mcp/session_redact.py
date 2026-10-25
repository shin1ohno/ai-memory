"""Secret masking for Claude Code session transcripts (design spec §6.2, C2).

Single source of truth for BOTH sides of the session-search pipeline:

- the client (`ccs ingest`) masks every record before any byte leaves the host;
- the server (sessions_app) re-scans every received line in detect-only mode and
  rejects anything the declared ruleset still finds (422).

The client cookbook copies this file byte-for-byte into the `ccs` package, and
bin/check-memory-v2-manifest fails CI when the two copies differ. Keep it
stdlib-only and free of any import from this directory.

Frozen API (shared contract):

    RULESET_VERSION = "r1"
    load_key(path) -> bytes                     raises KeyMissing
    redact_record(record, key, version) -> (masked deep copy, {kind: count})
    redact_text(text, key, version) -> (masked text, {kind: count})
    detect_record(record, version) -> [kind, ...]   unmasked hits only

Two properties are load-bearing and covered by test_session_redact.py:

1. Fixed point: redact(redact(x)) == redact(x). Every rule runs only on the
   text OUTSIDE existing `[REDACTED:...]` placeholders, so a placeholder can
   never be matched again (without this, `bearer`'s `\\S{16,}` matches a
   24-character placeholder and the server re-scan rejects already-masked input).
2. Iterative walk: records are traversed with an explicit stack, so a
   10,000-deep structure cannot raise RecursionError.

Values are never logged or returned by the detector — only kind names.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import re

RULESET_VERSION: str = "r1"
SUPPORTED_VERSIONS = frozenset({"r1"})


class KeyMissing(Exception):
    """The HMAC key file is absent, unreadable or empty. Callers fail closed:
    nothing is shipped and no cursor moves."""


def load_key(path: str) -> bytes:
    """Read the per-boundary HMAC key. Surrounding whitespace (a trailing
    newline from `echo` or SSM) is not part of the key."""
    try:
        with open(os.path.expanduser(path), "rb") as fh:
            key = fh.read().strip()
    except OSError as exc:
        raise KeyMissing(f"hmac key unreadable: {exc.__class__.__name__}") from None
    if not key:
        raise KeyMissing("hmac key is empty")
    return key


# --------------------------------------------------------------------------- #
# Input caps (enforced BEFORE any regex runs)
# --------------------------------------------------------------------------- #
# Every rule below is linear in the input (see the ReDoS notes on each), and
# these caps bound the size of the one string a single regex call sees and the
# total a record may carry. Over a cap nothing is matched: redaction replaces
# the string with `[REDACTED:oversize]` and detection reports `oversize`, so an
# oversized value is never shipped and never accepted unscanned.
MAX_VALUE_CHARS = 1_000_000
MAX_RECORD_CHARS = 4_000_000
MAX_KEY_NAME_CHARS = 128
OVERSIZE = "[REDACTED:oversize]"

# --------------------------------------------------------------------------- #
# Ruleset r1
# --------------------------------------------------------------------------- #
# A placeholder this module (or an older client of it) produced. Text inside one
# is never scanned again.
PLACEHOLDER_RE = re.compile(r"\[REDACTED:[a-z0-9-]+(?::[0-9a-f]{8})?\]")

# ReDoS discipline. Python's `re` backtracks, so a pattern is only safe when the
# set of start positions that can reach an expensive (backtracking) part is
# small. Patterns whose character class contains a non-word character ('-',
# '.', '+') would otherwise start inside every run (`eyJ-eyJ-eyJ-...`,
# `aaaa...` for a URL scheme) and rescan the rest of the run from each start:
# quadratic. Those start only at the beginning of a run (negative lookbehind
# over the same class), and keyword prefixes/suffixes are bounded ({0,40}).
#
# Kinds whose matched value is high-entropy: tagged with an 8-hex HMAC so that a
# leaked token can be traced across sessions. Order matters: anthropic-key must
# run before openai-key (both start with `sk-`).
_TAGGED = (
    ("aws-key", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")),
    ("github-token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b|\bgithub_pat_[A-Za-z0-9_]{60,}\b")),
    ("anthropic-key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}")),
    ("openai-key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}")),
    ("slack-token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}")),
    ("google-api-key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("gitlab-token", re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}")),
    ("jwt", re.compile(r"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}")),
)

# A truncated block (BEGIN without END, e.g. a capped tool_result) is masked to
# the end of the string: half a private key is still a private key.
_PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN [A-Z ]{0,40}PRIVATE KEY(?: BLOCK)?-----"
    r"(?:[\s\S]*?-----END [A-Z ]{0,40}PRIVATE KEY(?: BLOCK)?-----|[\s\S]*\Z)")

# Only the value is replaced; the header name stays readable. Also accepts the
# JSON / dict spelling `"Authorization": "Bearer ..."`.
_BEARER_RE = re.compile(
    r"(?i)(\bauthorization[\"']?[ \t]{0,16}[:=][ \t]{0,16}[\"']?bearer[ \t]+)([^\s\"']{16,})")

_URL_CRED_RE = re.compile(
    r"(?i)(?<![a-z0-9+.-])([a-z][a-z0-9+.-]{0,31}://[^\s/:@]+:)([^\s/@]+)(@)")

_CFG_KEY = (r"[A-Za-z0-9_.-]{0,40}(?:secret|token|passw(?:or)?d|api[_-]?key|credential|private)"
            r"[A-Za-z0-9_.-]{0,40}")
_CFG_KEY_RE = re.compile(r"(?i)" + _CFG_KEY)
# "KEY": "VALUE" (value may contain spaces and escaped quotes)
_CFG_JSON_RE = re.compile(r'(?i)("' + _CFG_KEY + r'"[ \t]{0,16}:[ \t]{0,16}")((?:[^"\\]|\\.)*)(")')
# KEY=VALUE / KEY: VALUE, optionally quoted key and value
_CFG_KV_RE = re.compile(
    r"(?i)(?<![A-Za-z0-9_.-])(" + _CFG_KEY + r"[\"']?[ \t]{0,16}[:=][ \t]{0,16}[\"']?)([^\s\"'`,;&]+)")

_CFG_MIN_LEN = 8
_LOW_ENTROPY = ("bearer", "private-key", "config-secret", "url-credential")


def _is_value_placeholder(value: str) -> bool:
    v = value.strip()
    low = v.lower()
    return (v.startswith("${") or v.startswith("<") or low.startswith("xxx")
            or v.startswith("***") or v.startswith("[REDACTED"))


def _cfg_value_maskable(value: str) -> bool:
    return len(value) >= _CFG_MIN_LEN and not _is_value_placeholder(value)


def _check_version(version: str) -> None:
    if version not in SUPPORTED_VERSIONS:
        raise ValueError(f"unsupported redact ruleset version {version!r}")


def _tag(key: bytes, value: str) -> str:
    return hmac.new(key, value.encode("utf-8", "surrogatepass"), hashlib.sha256).hexdigest()[:8]


def _outside_placeholders(text: str, fn) -> str:
    """Apply fn to every stretch of text that is not an existing placeholder."""
    out = []
    pos = 0
    for m in PLACEHOLDER_RE.finditer(text):
        if m.start() > pos:
            out.append(fn(text[pos:m.start()]))
        out.append(m.group(0))
        pos = m.end()
    if pos < len(text):
        out.append(fn(text[pos:]))
    return "".join(out)


def _one_pass(text: str, key: bytes, counts: dict) -> str:
    """One application of every rule, in order."""

    def bump(kind):
        counts[kind] = counts.get(kind, 0) + 1

    def rule(regex, kind, repl_fn):
        nonlocal text

        def sub(segment):
            def r(m):
                bump(kind)
                return repl_fn(m)
            return regex.sub(r, segment)

        text = _outside_placeholders(text, sub)

    rule(_PRIVATE_KEY_RE, "private-key", lambda m: "[REDACTED:private-key]")
    for kind, regex in _TAGGED:
        rule(regex, kind, lambda m, kind=kind: f"[REDACTED:{kind}:{_tag(key, m.group(0))}]")
    rule(_BEARER_RE, "bearer", lambda m: m.group(1) + "[REDACTED:bearer]")
    rule(_URL_CRED_RE, "url-credential",
         lambda m: m.group(1) + "[REDACTED:url-credential]" + m.group(3))

    def cfg(regex, value_group, tail):
        nonlocal text

        def sub(segment):
            def r(m):
                if not _cfg_value_maskable(m.group(value_group)):
                    return m.group(0)
                bump("config-secret")
                return m.group(1) + "[REDACTED:config-secret]" + (m.group(3) if tail else "")
            return regex.sub(r, segment)

        text = _outside_placeholders(text, sub)

    cfg(_CFG_JSON_RE, 2, True)
    cfg(_CFG_KV_RE, 2, False)
    return text


_MAX_PASSES = 8

# Exact prefilter: every rule above needs at least one of these literals to
# match (private-key "-----BEGIN", aws AKIA/ASIA, github gh?_ / github_pat_,
# anthropic/openai "sk-", slack "xox?-", google "AIza", gitlab "glpat-", jwt
# "eyJ", bearer "authorization", url-credential "://", config-secret its key
# words). A string with none of them cannot change, so it skips the rule chain;
# that keeps the per-string cost of the common short values (uuids, timestamps)
# to one linear scan. Keep this in step with the rules: test_session_redact.py
# asserts every positive vector passes the prefilter.
_ANCHOR_RE = re.compile(
    r"-----BEGIN|AKIA|ASIA|gh[pousr]_|github_pat_|sk-|xox[abprs]-|AIza|glpat-|eyJ|://"
    r"|(?i:authorization|secret|token|passw|api[_-]?key|credential|private)")


def _mask_text(text: str, key: bytes, counts: dict, max_chars: int = MAX_VALUE_CHARS) -> str:
    """The capped fixed-point loop shared by redaction and detection."""
    if len(text) > max_chars:
        counts["oversize"] = counts.get("oversize", 0) + 1
        return OVERSIZE
    if not _ANCHOR_RE.search(text):
        return text
    for _ in range(_MAX_PASSES):
        new = _one_pass(text, key, counts)
        if new == text:
            break
        text = new
    return text


def redact_text(text: str, key: bytes, version: str = RULESET_VERSION) -> tuple[str, dict[str, int]]:
    """Mask every secret in one string. Repeats until nothing changes, so the
    result is a fixed point of the ruleset. A string over MAX_VALUE_CHARS is
    replaced whole by `[REDACTED:oversize]` without being scanned."""
    _check_version(version)
    if not key:
        raise KeyMissing("hmac key is empty")
    counts: dict[str, int] = {}
    return _mask_text(text, key, counts), counts


# Detection masks a throwaway copy with this key and keeps only the counts, so
# that it sees exactly what redaction would: once a rule has replaced a token, a
# later rule cannot count the same bytes again (`sk-ant-...` is not also an
# openai-key hit).
_DETECT_KEY = b"detect-only"


def _dict_key_secret(name, value) -> bool:
    """A str value stored under a secret-looking dict key (`{"password": "..."}`
    in a tool input) is masked whole: the text rules only see `KEY=VALUE`
    spellings inside a string, not the JSON structure around it."""
    return (isinstance(name, str) and isinstance(value, str)
            and len(name) <= MAX_KEY_NAME_CHARS
            and _CFG_KEY_RE.fullmatch(name) is not None
            and _cfg_value_maskable(value))


def _walk(record, on_str, on_key):
    """Iterative deep copy. on_str(value, dict_key_or_None) returns the new
    string; on_key(key) the new dict key (keys can carry secrets too). dicts and
    lists are copied; every other scalar is shared."""
    holder = [record]
    stack = [(holder, 0, None)]
    while stack:
        parent, k, name = stack.pop()
        v = parent[k]
        if isinstance(v, str):
            parent[k] = on_str(v, name)
        elif isinstance(v, dict):
            new = {}
            originals = []
            for ok, ov in v.items():
                nk = on_key(ok) if isinstance(ok, str) else ok
                if nk in new:  # two masked keys collapsed to one placeholder
                    i = 2
                    while f"{nk}#{i}" in new:
                        i += 1
                    nk = f"{nk}#{i}"
                new[nk] = ov
                originals.append((nk, ok))
            parent[k] = new
            for nk, ok in originals:
                stack.append((new, nk, ok))
        elif isinstance(v, list):
            new = list(v)
            parent[k] = new
            for i in range(len(new)):
                stack.append((new, i, None))
    return holder[0]


class _Budget:
    """Per-record total of scanned characters (MAX_RECORD_CHARS)."""

    def __init__(self):
        self.used = 0

    def take(self, n: int) -> bool:
        self.used += n
        return self.used <= MAX_RECORD_CHARS


def _record_pass(record, key: bytes, counts: dict, check=None):
    budget = _Budget()

    def text(value):
        if check is not None:
            check()
        if not budget.take(len(value)):
            counts["oversize"] = counts.get("oversize", 0) + 1
            return OVERSIZE
        return _mask_text(value, key, counts)

    def on_str(value, name):
        if _dict_key_secret(name, value):
            budget.take(len(value))
            counts["config-secret"] = counts.get("config-secret", 0) + 1
            return "[REDACTED:config-secret]"
        return text(value)

    return _walk(record, on_str, text)


def redact_record(record, key: bytes, version: str = RULESET_VERSION) -> tuple[object, dict[str, int]]:
    """Mask every str value AND every dict key inside a parsed JSON record. The
    nesting and the non-string values are never altered; a key changes only when
    it carried a secret. Strings over MAX_VALUE_CHARS, and every string after
    the record's first MAX_RECORD_CHARS characters, become `[REDACTED:oversize]`."""
    _check_version(version)
    if not key:
        raise KeyMissing("hmac key is empty")
    counts: dict[str, int] = {}
    return _record_pass(record, key, counts), counts


def detect_record(record, version: str = RULESET_VERSION, _check=None) -> list[str]:
    """Kinds of secrets still present (unmasked) anywhere in the record —
    values and dict keys — sorted. Placeholders are ignored. `oversize` means a
    string or the record exceeds the caps and was not scanned, which the server
    rejects like a hit. Kind names only, never values."""
    _check_version(version)
    counts: dict[str, int] = {}
    # _check (server only): called before each string is scanned, so a caller's
    # wall-clock budget can stop a record mid-way; it raises to abort.
    _record_pass(record, _DETECT_KEY, counts, _check)
    return sorted(counts)


def detect_text(text: str, version: str = RULESET_VERSION,
                max_chars: int = MAX_VALUE_CHARS) -> list[str]:
    """detect_record for one bare string (the /blob content, whose cap is the
    caller's to choose)."""
    _check_version(version)
    counts: dict[str, int] = {}
    _mask_text(text, _DETECT_KEY, counts, max_chars)
    return sorted(counts)


__all__ = ["RULESET_VERSION", "KeyMissing", "load_key", "redact_record",
           "redact_text", "detect_record", "detect_text", "PLACEHOLDER_RE",
           "MAX_VALUE_CHARS", "MAX_RECORD_CHARS"]
