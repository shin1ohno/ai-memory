#!/usr/bin/env python3
"""Measure redaction on JSONL files modified within --days (default 30).

Pass transcript files or directories explicitly. Segments follow the client's
4 MiB raw-input cap and contain complete lines. Oversize and partial lines are
counted separately; they are not included in latency percentiles. Only the
redactor calls are timed, excluding reads and JSON decoding. Output is one JSON
object with numeric values, never paths, records, secrets or masked contents.
The ephemeral HMAC key requires no credential file and is never persisted.
"""
from __future__ import annotations

import argparse
import json
import math
import os
from pathlib import Path
import stat
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'memory-mcp'))
from session_redact import redact_record, redact_text

SEGMENT_BYTES = 4 * 1024 * 1024


class Parser(argparse.ArgumentParser):
    def error(self, message):
        # argparse's default diagnostic includes untrusted path arguments.
        raise ValueError('invalid arguments')


def percentile(values, fraction):
    return sorted(values)[max(0, math.ceil(len(values) * fraction) - 1)] if values else 0.0


def measure(paths, days=30, segment_bytes=SEGMENT_BYTES, now=None):
    if days <= 0 or not math.isfinite(days) or segment_bytes <= 0:
        raise ValueError('invalid window')
    result = dict(files=0, skipped_old=0, skipped_nonregular=0, errors=0,
                  segments=0, records=0, bytes=0, masks=0, oversize_lines=0, partial_lines=0)
    cutoff = (time.time() if now is None else now) - days * 86400
    samples = []
    seen = set()
    key = os.urandom(32)
    for item in paths:
        item = Path(item)
        candidates = item.rglob('*.jsonl') if item.is_dir() and not item.is_symlink() else [item]
        try:
            for path in candidates:
                try:
                    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
                    with os.fdopen(fd, 'rb') as source:
                        info = os.fstat(source.fileno())
                        if not stat.S_ISREG(info.st_mode):
                            result['skipped_nonregular'] += 1
                            continue
                        identity = (info.st_dev, info.st_ino)
                        if identity in seen:
                            continue
                        seen.add(identity)
                        if info.st_mtime < cutoff:
                            result['skipped_old'] += 1
                            continue
                        result['files'] += 1
                        size = 0
                        seconds = 0.0
                        while True:
                            line = source.readline(segment_bytes + 1)
                            if not line:
                                break
                            if len(line) > segment_bytes:
                                if size:
                                    samples.append(seconds)
                                    size, seconds = 0, 0.0
                                while not line.endswith(b'\n'):
                                    line = source.readline(segment_bytes + 1)
                                    if not line:
                                        break
                                result['oversize_lines' if line.endswith(b'\n') else 'partial_lines'] += 1
                                continue
                            if not line.endswith(b'\n'):
                                result['partial_lines'] += 1
                                break
                            if size + len(line) > segment_bytes:
                                samples.append(seconds)
                                size, seconds = 0, 0.0
                            text = line.decode('utf-8', 'replace')
                            try:
                                record = json.loads(text)
                                operation = redact_record
                            except ValueError:
                                record, operation = text, redact_text
                            started = time.perf_counter()
                            _, counts = operation(record, key)
                            seconds += time.perf_counter() - started
                            size += len(line)
                            result['records'] += 1
                            result['bytes'] += len(line)
                            result['masks'] += sum(counts.values())
                        if size:
                            samples.append(seconds)
                except (OSError, ValueError, RecursionError):
                    result['errors'] += 1
        except OSError:
            result['errors'] += 1
    result.update(segments=len(samples), p50_seconds=percentile(samples, .5),
                  p95_seconds=percentile(samples, .95), max_seconds=max(samples, default=0.0))
    return result


def main():
    parser = Parser(description=__doc__)
    parser.add_argument('paths', nargs='+')
    parser.add_argument('--days', type=float, default=30)
    try:
        args = parser.parse_args()
        result = measure(args.paths, days=args.days)
    except (ValueError, OSError):
        print(json.dumps({'errors': 1}))
        return 1
    print(json.dumps(result, sort_keys=True))
    return int(bool(result['errors']))


if __name__ == '__main__':
    raise SystemExit(main())
