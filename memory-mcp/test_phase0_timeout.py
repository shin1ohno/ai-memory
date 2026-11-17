#!/usr/bin/env python3
"""The real SDK receives the session-idle setting; invalid values fail closed."""
import os
from pathlib import Path
import subprocess
import sys
import unittest


class Timeout(unittest.TestCase):
    def run_setting(self, value):
        env = dict(PATH=os.defpath, ES_URL='http://127.0.0.1:9', ES_PASSWORD='test',
                   VOYAGE_API_KEY='test', MEMORY_MCP_METRICS_FILE='')
        if value is not None:
            env['MCP_SESSION_IDLE_TIMEOUT'] = value
        code = 'import sys; sys.path.insert(0, sys.argv[1]); import server; print(server.mcp.session_manager.session_idle_timeout)'
        return subprocess.run([sys.executable, '-I', '-c', code, str(Path(__file__).resolve().parent)],
                              env=env, capture_output=True, text=True, timeout=10)

    def test_default_and_override(self):
        for value, expected in [(None,1800),('2',2),('0.5',.5)]:
            result = self.run_setting(value)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(float(result.stdout.strip()), expected)

    def test_nonfinite_or_nonpositive_settings_are_rejected(self):
        for value in ['0','-1','nan','inf','not-a-number']:
            result = self.run_setting(value)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('ValueError', result.stderr)


if __name__ == '__main__':
    unittest.main()
