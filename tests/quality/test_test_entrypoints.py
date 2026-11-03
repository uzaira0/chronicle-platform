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


if __name__ == "__main__":
    unittest.main()
