"""deployment-semgrep.sh gives the same answer from any checkout path and working directory, and
names a tool it cannot find."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
SECURITY = Path("tests/security")


class DeploymentSemgrepFixturesTest(unittest.TestCase):
    def test_a_long_checkout_path_does_not_hide_the_rule_ids(self):
        # Semgrep's text report prefixes each rule id with the dotted path of the rules directory as
        # seen from the working directory and wraps at a fixed width. Started from outside the
        # repository root, the script found each id split over two lines and said "fixture missed".
        directory = ROOT / "build/operator-test-runs"
        directory.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="deployment-semgrep-", dir=directory) as folder:
            checkout = Path(folder) / ("checkout-" + "d" * 150)
            (checkout / SECURITY).mkdir(parents=True)
            shutil.copy2(ROOT / SECURITY / "deployment-semgrep.sh", checkout / SECURITY)
            shutil.copytree(ROOT / SECURITY / "deployment-rules", checkout / SECURITY / "deployment-rules")
            result = subprocess.run(
                ["bash", str(checkout / SECURITY / "deployment-semgrep.sh")],
                cwd=folder, capture_output=True, text=True, timeout=300, check=False,
            )
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertIn("PASS:", result.stdout)

    def test_a_missing_jq_is_reported_as_missing(self):
        # The rule ids are looked up with jq. Without jq the script ran the whole scan and then
        # stopped at the first lookup with bash's "line 25: jq: command not found" (twice, status
        # 127, errexit inside the failure branch). It now names the tool before it scans.
        directory = ROOT / "build/operator-test-runs"
        directory.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="deployment-semgrep-", dir=directory) as folder:
            result = subprocess.run(
                ["bash", str(ROOT / SECURITY / "deployment-semgrep.sh")],
                cwd=folder, env=dict(os.environ, PATH=path_without("jq", folder)),
                capture_output=True, text=True, timeout=300, check=False,
            )
        self.assertEqual(127, result.returncode, result.stdout + result.stderr)
        self.assertIn("jq is not installed", result.stderr)
        self.assertNotIn("fixture missed", result.stderr)
        self.assertNotIn("PASS:", result.stdout)


def path_without(tool, folder):
    """A directory to use as PATH: every command of the current PATH, in its order, except tool."""
    commands = Path(folder) / "commands"
    commands.mkdir()
    for directory in os.environ["PATH"].split(os.pathsep):
        try:
            entries = sorted(os.scandir(directory), key=lambda entry: entry.name)
        except OSError:
            continue
        for entry in entries:
            link = commands / entry.name
            # os.access answers False for what this account may not run or even look at.
            if entry.name != tool and not link.is_symlink() and os.access(entry.path, os.X_OK) and not os.path.isdir(entry.path):
                link.symlink_to(entry.path)
    return str(commands)


if __name__ == "__main__":
    unittest.main()
