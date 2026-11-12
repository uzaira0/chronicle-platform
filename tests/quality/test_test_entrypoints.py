"""Test inventories follow executable discovery commands, including native init scripts."""

import importlib
import sys
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tests/security"))
CHECK = importlib.import_module("check-suite-inventory")


class TestEntrypointsTest(unittest.TestCase):
    def test_new_python_typescript_and_gradle_tests_need_real_runner_commands(self):
        scratch = ROOT / "build/operator-test-runs"
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as directory:
            root = Path(directory)
            names = ("tests/quality/test_first.py", "chronicle/scripts/test-mapping.py",
                     "chronicle/scripts/test-runtime.gradle", "chronicle-web/src/modern/example.test.ts")
            paths = set()
            for name in names:
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("")
                paths.add(path)
            (root / names[2]).write_text("tasks.register('verifyRuntime') { doLast { assert true } }")
            checker = getattr(CHECK, "script_test_coverage", None)
            self.assertIsNotNone(checker, "Native test entrypoint inventory is missing")
            self.assertEqual(paths, checker(root, []))
            commands = [
                'python3 -m unittest discover -s "$ROOT_DIR/tests/quality" -p "test_*.py"',
                'python3 "$ROOT_DIR/chronicle/scripts/test-mapping.py"',
                './gradlew -I scripts/test-runtime.gradle verifyRuntime',
                'bun test src/modern scripts',
            ]
            nodes = [{"text": text, "file": str(root / "scripts/local-ci.sh")} for text in commands]
            nodes[2]["cwd"] = str(root / "chronicle")
            nodes[3]["cwd"] = str(root / "chronicle-web")
            self.assertEqual(set(), checker(root, nodes))
            nodes[1]["text"] = ('uv run --no-project --python python3 --with-requirements requirements.txt '
                                'python "$ROOT_DIR/chronicle/scripts/test-mapping.py"')
            self.assertEqual(set(), checker(root, nodes))
            self.assertEqual({root / names[1]}, checker(root, nodes[:1] + nodes[2:]))
            self.assertEqual({root / names[2]}, checker(root, nodes[:2] + nodes[3:]))
            nodes[2]["text"] = './gradlew -I scripts/test-runtime.gradle help'
            self.assertEqual({root / names[2]}, checker(root, nodes))
            nodes[2]["text"] = commands[2]
            with patch.object(CHECK, "script_invocations", return_value=nodes[:1] + nodes[2:]):
                self.assertIn(root / names[1], CHECK.coverage(root))

    def test_discovery_pattern_is_not_an_exemption_for_other_test_files(self):
        scratch = ROOT / "build/operator-test-runs"
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as directory:
            root = Path(directory)
            path = root / "tests/quality/test-other.py"
            path.parent.mkdir(parents=True)
            path.write_text("")
            checker = getattr(CHECK, "script_test_coverage", None)
            self.assertIsNotNone(checker, "Native test entrypoint inventory is missing")
            node = {"text": 'python3 -m unittest discover -s "$ROOT_DIR/tests/quality" -p "test_*.py"',
                    "file": str(root / "scripts/local-ci.sh")}
            self.assertEqual({path}, checker(root, [node]))
            nested = root / "tests/quality/nested/test_nested.py"
            nested.parent.mkdir()
            nested.write_text("")
            self.assertEqual({path, nested}, checker(root, [node]))
            (nested.parent / "__init__.py").write_text("")
            self.assertEqual({path}, checker(root, [node]))

    def test_load_loop_globs_cover_imported_helpers_without_hiding_unselected_modules(self):
        scratch = ROOT / "build/operator-test-runs"
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as directory:
            root = Path(directory).resolve()
            load = root / "tests/load"
            load.mkdir(parents=True)
            (load / "chronicle-load-test.js").write_text('import "./client.js"; export default function () {}\n')
            (load / "k6-example.js").write_text('export default function () {}\n')
            (load / "client.js").write_text('import http from "k6/http"; export const client = http;\n')
            ci = root / "scripts/local-ci.sh"
            ci.parent.mkdir()
            ci.write_text('for candidate in "$ROOT_DIR"/tests/load/chronicle-load-test.js "$ROOT_DIR"/tests/load/k6-*.js; do k6 run "$candidate"; done\n')
            nodes = CHECK.layers.shell_nodes(ci, ("command", "for_statement"))
            with patch.object(CHECK, "script_invocations", return_value=nodes):
                self.assertEqual(set(), CHECK.coverage(root))
                orphan = load / "unselected.js"
                orphan.write_text('export default function () {}\n')
                self.assertEqual({orphan}, CHECK.coverage(root))

    def test_relative_bun_targets_use_the_actual_shell_working_directory(self):
        scratch = ROOT / "build/operator-test-runs"
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as directory:
            root = Path(directory)
            path = root / "chronicle-web/src/modern/example.test.ts"
            path.parent.mkdir(parents=True)
            path.write_text("")
            ci = root / "scripts/local-ci.sh"
            ci.parent.mkdir()
            ci.write_text('job_web() { (cd "$ROOT_DIR/chronicle-web" && bun test src/modern scripts); }\n')
            nodes = CHECK.layers.shell_nodes(ci, ("command",))
            self.assertEqual(set(), CHECK.script_test_coverage(root, nodes))
            ci.write_text('job_web() { (cd "$ROOT_DIR/chronicle-web" && "$WEB_DIR/node_modules/.bin/bun" test src/modern scripts); }\n')
            self.assertEqual(set(), CHECK.script_test_coverage(root, CHECK.layers.shell_nodes(ci, ("command",))))
            ci.write_text('job_web() { (cd "$ROOT_DIR" && bun test scripts); }\n')
            self.assertEqual({path}, CHECK.script_test_coverage(root, CHECK.layers.shell_nodes(ci, ("command",))))

    def test_a_security_script_needs_a_runner_that_a_gate_reaches(self):
        # 2026-11-11: operator-secret-edge-guardrails.sh had failed since 2026-10-19 and
        # observability-guardrails.sh since 2026-10-22, and no job, hook or test ran either.
        scratch = ROOT / "build/operator-test-runs"
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as directory:
            root = Path(directory)
            security = root / "tests/security"
            security.mkdir(parents=True)
            (root / "scripts").mkdir()
            (root / "scripts/local-ci.sh").write_text(
                'job_security_layers() { bash "$ROOT_DIR/tests/security/run-all-security.sh" deploy; }\n')
            runner = security / "run-all-security.sh"
            layers = ('run_security_step "deploy.direct" -- "$ROOT_DIR/tests/security/direct-guardrails.sh"\n'
                      'for suite in looped-one looped-two; do\n'
                      '  run_security_step "deploy.$suite" -- bash "$ROOT_DIR/tests/security/$suite.sh"\n'
                      'done\n'
                      'for suite in "$ROOT_DIR"/tests/security/operator-*.sh; do bash "$suite"; done\n'
                      '# "$ROOT_DIR/tests/security/commented-guardrails.sh"\n')
            runner.write_text(layers)
            for name in ("direct-guardrails.sh", "looped-one.sh", "looped-two.sh", "operator-first.sh", *CHECK.HOST_PROBES):
                (security / name).write_text("")
            check = CHECK.security_script_coverage
            self.assertEqual(set(), check(root))

            def orphan(name):
                path = security / name
                path.write_text("")
                return path

            commented = orphan("commented-guardrails.sh")
            self.assertEqual({commented}, check(root))
            commented.unlink()
            # Documentation, a Makefile and a deployment playbook are not gates.
            documented = orphan("documented-guardrails.sh")
            (root / "docs").mkdir()
            (root / "docs/audit.md").write_text("tests/security/documented-guardrails.sh\n")
            (root / "Makefile").write_text("check:\n\ttests/security/documented-guardrails.sh\n")
            (root / "deploy").mkdir()
            (root / "deploy/tasks.yml").write_text("- command: tests/security/documented-guardrails.sh\n")
            self.assertEqual({documented}, check(root))
            documented.unlink()
            # A test that starts the script owns it; a test that only reads its text does not.
            probe = orphan("fixture-probe.sh")
            test = root / "tests/quality/test_fixture_probe.py"
            test.parent.mkdir()
            test.write_text("text = (ROOT / 'tests/security/fixture-probe.sh').read_text()\n")
            self.assertEqual({probe}, check(root))
            test.write_text("import subprocess\nsubprocess.run(['bash', str(ROOT / 'tests/security/fixture-probe.sh')])\n")
            self.assertEqual(set(), check(root))
            # A script reached only through another script that has no runner is not reached.
            chained = orphan("chained-guardrails.sh")
            middle = orphan("middle-guardrails.sh")
            middle.write_text('bash "$ROOT_DIR/tests/security/chained-guardrails.sh"\n')
            self.assertEqual({chained, middle}, check(root))
            runner.write_text(layers + 'bash "$ROOT_DIR/tests/security/middle-guardrails.sh"\n')
            self.assertEqual(set(), check(root))
            # A Python program that discovery does not pick up needs a runner as well.
            program = orphan("fixture_checks.py")
            unmatched = orphan("fixture_test.py")
            self.assertEqual({program, unmatched}, check(root))
            test.write_text("import subprocess\nimport fixture_checks\n"
                            "subprocess.run(['bash', str(ROOT / 'tests/security/fixture-probe.sh')])\n"
                            "subprocess.run(['python3', str(ROOT / 'tests/security/fixture_test.py')])\n")
            self.assertEqual(set(), check(root))
            # A host probe leaves the table when a gate starts it.
            listed = security / sorted(CHECK.HOST_PROBES)[0]
            runner.write_text(runner.read_text() + f'bash "$ROOT_DIR/tests/security/{listed.name}"\n')
            self.assertEqual({listed}, check(root))

    def test_every_security_script_in_this_repository_has_a_runner(self):
        self.assertEqual(set(), {path.relative_to(ROOT).as_posix() for path in CHECK.security_script_coverage(ROOT)})
        # ... and the table of host probes names no file that has been removed.
        self.assertEqual([], [name for name in CHECK.HOST_PROBES if not (ROOT / "tests/security" / name).is_file()])


if __name__ == "__main__":
    unittest.main()
