"""memory-keeper-health.sh must expose the reconcile unit's exit status.

From 2026-08-26 to 2026-08-29 the reconcile unit crashed on every tick while the
backlog and stats-age metrics stayed flat. These cases run the real script with a
PATH holding only stubs and the handful of tools it needs, so a host's systemctl
cannot leak in and "systemctl missing" is a real condition.
"""
import os
import re
import shutil
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "memory-keeper-health.sh"
TOOLS = ("date", "grep", "head", "mkdir", "mktemp", "mv", "rm", "chmod", "cat")
METRIC = "memory_keeper_reconcile_last_exit_code"

CURL = """#!/bin/sh
case "$*" in
  *_count*) echo '{"count":3}' ;;
  *_search*) echo '{"fields":{"written_at":["1000"]}}' ;;
esac
"""


def executable(path, body):
    path.write_text(body)
    path.chmod(path.stat().st_mode | stat.S_IXUSR)


def run(systemctl=None):
    """Run the script and return {metric: value} from the textfile it wrote."""
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        bin_dir, textfile = root / "bin", root / "textfile"
        bin_dir.mkdir()
        for tool in TOOLS:
            os.symlink(shutil.which(tool), bin_dir / tool)
        executable(bin_dir / "curl", CURL)
        if systemctl is not None:
            executable(bin_dir / "systemctl", systemctl)
        env = {
            "PATH": str(bin_dir),
            "ENV_FILE": str(root / "absent"),
            "ES_PASSWORD": "fixture-only",
            "TEXTFILE_DIR": str(textfile),
        }
        bash = shutil.which("bash")
        subprocess.run([bash, str(SCRIPT)], env=env, check=True, capture_output=True)
        body = (textfile / "memory-keeper-health.prom").read_text()
    return body, dict(re.findall(r"^(memory_keeper_\w+) (-?\d+)$", body, re.M))


def unit(status, started):
    return (
        "#!/bin/sh\n"
        f"echo ExecMainStatus={status}\n"
        f"echo ExecMainStartTimestampMonotonic={started}\n"
    )


class ReconcileExitCode(unittest.TestCase):
    def test_exit_status_zero(self):
        self.assertEqual(run(unit(0, 123456))[1][METRIC], "0")

    def test_non_zero_exit_status(self):
        self.assertEqual(run(unit(7, 123456))[1][METRIC], "7")

    def test_never_started_is_unknown(self):
        self.assertEqual(run(unit(0, 0))[1][METRIC], "-1")

    def test_systemctl_failure_is_unknown(self):
        self.assertEqual(run("#!/bin/sh\nexit 1\n")[1][METRIC], "-1")

    def test_missing_systemctl_is_unknown(self):
        self.assertEqual(run(None)[1][METRIC], "-1")

    def test_textfile_declares_the_metric(self):
        body, _ = run(unit(0, 123456))
        self.assertIn(f"# HELP {METRIC} ", body)
        self.assertIn(f"# TYPE {METRIC} gauge", body)

    def test_existing_metrics_are_unchanged(self):
        _, metrics = run(unit(0, 123456))
        self.assertEqual(metrics["memory_keeper_raw_backlog"], "3")
        self.assertGreater(int(metrics["memory_keeper_stats_age_seconds"]), 0)
        self.assertIn("memory_keeper_health_scrape_timestamp_seconds", metrics)


if __name__ == "__main__":
    unittest.main()
