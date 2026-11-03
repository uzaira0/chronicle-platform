"""Security consumes isolated Python suites and completed server test evidence."""

from pathlib import Path
import shutil
import runpy
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class GateVerificationTests(unittest.TestCase):
    def test_python_suite_isolates_user_site(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            suite = root / "tests/selfhost-py"
            suite.mkdir(parents=True)
            (root / "selfhost").mkdir()
            (root / "selfhost/chronicle_ops.py").touch()
            (suite / "test_fixture.py").write_text(
                "import site, unittest\nclass Fixture(unittest.TestCase):\n"
                "    def test_isolated(self):\n        self.assertFalse(site.ENABLE_USER_SITE)\n"
                "        with open(__file__ + '.calls', 'a') as log: log.write('x')\n")
            script = ('source "$1"\nROOT_DIR="$2"\n'
                      'run_selfhost_python_suite test_fixture.Fixture.test_isolated\n')
            result = subprocess.run(["bash", "-eu", "-s", "--", str(ROOT / "tests/security/lib/selfhost-python.sh"), directory],
                                    input=script, text=True, capture_output=True, timeout=10)
            self.assertEqual(0, result.returncode, result.stdout + result.stderr)
            self.assertIn("Ran 1 test", result.stderr)
            self.assertEqual("x", (suite / "test_fixture.py.calls").read_text())

    def test_auth_layer_requires_complete_passing_server_xml_without_gradle(self):
        classes = runpy.run_path(str(ROOT / "tests/security/lib/auth-test-results.py"))["REQUIRED_CLASSES"]
        self.assertEqual(5, len(classes))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "gradlew").write_text("#!/bin/sh\necho Gradle-must-not-run >&2\nexit 42\n")
            (root / "gradlew").chmod(0o755)
            (root / "tests/security/lib").mkdir(parents=True)
            checker = ROOT / "tests/security/lib/auth-test-results.py"
            if checker.exists():
                shutil.copy2(checker, root / "tests/security/lib" / checker.name)
            results = root / "chronicle-server/build/test-results/test"
            results.mkdir(parents=True)
            script = 'source "$1"\nROOT_DIR="$2"\nrun_auth_behavior_tests\n'
            for outcome in ("missing", "passed", "failed", "skipped"):
                for path in results.glob("*.xml"):
                    path.unlink()
                if outcome != "missing":
                    for name in classes:
                        bad = name == classes[-1]
                        failure = '<failure message="unsafe policy"/>' if outcome == "failed" and bad else ''
                        skipped = '<skipped/>' if outcome == "skipped" and bad else ''
                        (results / f"TEST-example.{name}.xml").write_text(
                            f'<testsuite name="example.{name}" tests="1" failures="{int(bool(failure))}" errors="0" skipped="{int(bool(skipped))}">'
                            f'<testcase name="behavior" classname="example.{name}">{failure}{skipped}</testcase></testsuite>')
                result = subprocess.run(["bash", "-s", "--", str(ROOT / "tests/security/run-all-security.sh"), directory],
                                        input=script, text=True, capture_output=True, timeout=10)
                with self.subTest(outcome=outcome):
                    self.assertEqual(outcome == "passed", result.returncode == 0, result.stdout + result.stderr)
                    self.assertNotIn("Gradle-must-not-run", result.stderr)
