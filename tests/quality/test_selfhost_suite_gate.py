"""The operator gate must fail when unittest skips a required check."""

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRATCH = ROOT / "build/operator-test-runs"


class SelfhostSuiteGateTest(unittest.TestCase):
    def run_suite(self, body):
        SCRATCH.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=SCRATCH) as directory:
            folder = Path(directory)
            (folder / "chronicle_ops.py").write_text("")
            (folder / "test_required.py").write_text(
                "import unittest\nclass RequiredTest(unittest.TestCase):\n"
                "    def test_required(self):\n        " + body + "\n"
            )
            script = folder / "run.sh"
            script.write_text(
                'source "$ROOT_DIR/tests/security/lib/selfhost-python.sh"\n'
                'run_selfhost_python_suite discover -s "$SELFHOST_PYTHON_PACKAGE" -v\n'
            )
            return subprocess.run(
                ["bash", str(script)],
                env={**os.environ, "ROOT_DIR": str(ROOT), "SELFHOST_PYTHON_PACKAGE": str(folder)},
                capture_output=True, text=True, check=False,
            )

    def test_required_check_runs(self):
        result = self.run_suite("self.assertEqual(2, 1 + 1)")
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn("Ran 1 test", result.stderr)

    def test_skipped_required_check_fails(self):
        result = self.run_suite("self.skipTest('required interpreter absent')")
        self.assertNotEqual(0, result.returncode, result.stderr)
        self.assertIn("required interpreter absent", result.stderr)

    def test_failed_required_check_fails(self):
        result = self.run_suite("self.fail('required check failed')")
        self.assertNotEqual(0, result.returncode, result.stderr)
        self.assertIn("required check failed", result.stderr)


if __name__ == "__main__":
    unittest.main()
