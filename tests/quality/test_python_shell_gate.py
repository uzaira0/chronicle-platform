import importlib.util
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest

ROOT = Path(__file__).resolve().parents[2]


class PythonShellGateTests(unittest.TestCase):
    def test_every_tracked_python_and_shell_file_is_checked_and_failures_propagate(self):
        spec = importlib.util.spec_from_file_location("gate", ROOT / "scripts/check-python-shell.py")
        gate = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(gate)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            subprocess.run(["git", "init", "-q", str(root)], check=True)
            for name in ("scripts/a.py", "tests/b.py", "scripts/a.sh", "tests/security/fixtures/invalid.sh"):
                target = root / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text("")
            subprocess.run(["git", "-C", str(root), "add", "."], check=True)
            calls = []
            def tool(command, **kwargs):
                calls.append(command)
                return SimpleNamespace(returncode=int(command[0] == "shellcheck"))
            self.assertEqual(1, gate.check(root, tool))
            self.assertEqual(["ruff", "check", "--select", "F", str(root / "scripts/a.py"), str(root / "tests/b.py")], calls[0])
            self.assertEqual(["shellcheck", "-S", "warning", str(root / "scripts/a.sh")], calls[1])


if __name__ == "__main__":
    unittest.main()
