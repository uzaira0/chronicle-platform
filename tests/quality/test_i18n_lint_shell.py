"""The iOS lint invocation receives existing source directories and refuses an empty target list."""

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


class I18nLintShellTest(unittest.TestCase):
    def run_lint(self, with_source):
        scratch = ROOT / "build/operator-test-runs"
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as directory:
            root = Path(directory)
            (root / "scripts").mkdir()
            shutil.copyfile(ROOT / "scripts/i18n-lint.sh", root / "scripts/i18n-lint.sh")
            ios = root / "chronicle-ios"
            (ios / "lint/i18n").mkdir(parents=True)
            (ios / "lint/i18n/semgrep.yml").write_text("rules: []\n")
            (ios / "scripts").mkdir()
            (ios / "scripts/i18n-lint-selftest.sh").write_text("exit 0\n")
            if with_source:
                (ios / "ChronicleScreenTimeReport").mkdir()
            commands = root / "commands"
            commands.mkdir()
            for name, body in {
                "ast-grep": 'printf "ast-grep 0.51.0\\n"\n',
                "jq": "exit 0\n",
                "semgrep": 'printf "%s\\n" "$@" > "$LINT_CALLS"\n',
            }.items():
                path = commands / name
                path.write_text("#!/bin/bash\n" + body)
                path.chmod(0o755)
            calls = root / "calls.txt"
            result = subprocess.run(["bash", str(root / "scripts/i18n-lint.sh"), "ios"],
                                    env={**os.environ, "PATH": str(commands) + os.pathsep + os.environ["PATH"],
                                         "LINT_CALLS": str(calls)}, capture_output=True, text=True, check=False)
            return result, calls.read_text().splitlines() if calls.exists() else []

    def test_only_existing_ios_source_directories_are_passed_as_arguments(self):
        result, calls = self.run_lint(True)
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual("ChronicleScreenTimeReport", calls[-1])
        self.assertNotIn("chronicle", calls)

    def test_missing_ios_source_directories_fail_without_running_a_blanket_scan(self):
        result, calls = self.run_lint(False)
        self.assertNotEqual(0, result.returncode)
        self.assertIn("source directories missing", result.stderr)
        self.assertEqual([], calls)


if __name__ == "__main__":
    unittest.main()
