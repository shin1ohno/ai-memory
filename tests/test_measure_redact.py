#!/usr/bin/env python3
"""Numeric-only output and bounded transcript segment semantics."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest

SCRIPT = Path(__file__).resolve().parent.parent / 'eval/measure_redact.py'
spec = importlib.util.spec_from_file_location('measure_redact', SCRIPT)
measure = importlib.util.module_from_spec(spec)
spec.loader.exec_module(measure)


class Measurement(unittest.TestCase):
    def test_numeric_cli_output_and_no_content_or_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'PRIVATE-PATH.jsonl'
            path.write_text(json.dumps({'content': 'PRIVATE-CONTENT', 'password': 'synthetic-value'})+'\n')
            run = subprocess.run([sys.executable, str(SCRIPT), str(path)], capture_output=True, text=True)
            self.assertEqual(run.returncode, 0, run.stderr)
            data = json.loads(run.stdout)
            self.assertTrue(all(isinstance(v, (int, float)) for v in data.values()))
            self.assertEqual(data['records'], 1)
            self.assertEqual(data['masks'], 1)
            self.assertEqual(run.stderr, '')
            for marker in ['PRIVATE', 'synthetic-value', directory, 'REDACTED']:
                self.assertNotIn(marker, run.stdout + run.stderr)

    def test_window_segments_partial_oversize_and_dedup(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            recent = root/'recent.jsonl'
            recent.write_bytes(b'{}\n{}\n{}\n' + b'x'*20 + b'\n' + b'{}\npartial')
            old = root/'old.jsonl'
            old.write_text('{}\n')
            os.utime(old, (1, 1))
            data = measure.measure([root, recent], segment_bytes=6, now=time.time())
            self.assertEqual(data['files'], 1)
            self.assertEqual(data['records'], 4)
            self.assertEqual(data['segments'], 3)
            self.assertEqual(data['skipped_old'], 1)
            self.assertEqual(data['oversize_lines'], 1)
            self.assertEqual(data['partial_lines'], 1)
            self.assertGreaterEqual(data['max_seconds'], data['p95_seconds'])

    def test_partial_line_is_not_measured(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'input.jsonl'
            path.write_text('{}\n{}')
            data = measure.measure([path])
            self.assertEqual(data['records'], 1)
            self.assertEqual(data['partial_lines'], 1)

    def test_errors_are_numeric_and_do_not_disclose_the_path(self):
        run = subprocess.run([sys.executable, str(SCRIPT), '/missing/PRIVATE-PATH'], capture_output=True, text=True)
        self.assertEqual(run.returncode, 1)
        self.assertEqual(json.loads(run.stdout)['errors'], 1)
        self.assertNotIn('PRIVATE', run.stdout + run.stderr)
        self.assertEqual(run.stderr, '')

    def test_quantiles_use_nearest_rank(self):
        self.assertEqual(measure.percentile([4, 1, 2, 3], .5), 2)
        self.assertEqual(measure.percentile([4, 1, 2, 3], .95), 4)
        self.assertEqual(measure.percentile([], .5), 0)


if __name__ == '__main__':
    unittest.main()
