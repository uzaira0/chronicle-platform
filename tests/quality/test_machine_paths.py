import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class MachinePathTests(unittest.TestCase):
    def test_cached_machine_paths_fail_but_private_records_and_message_data_do_not(self):
        spec = importlib.util.spec_from_file_location("machine_paths", ROOT / "scripts/check-machine-paths.py")
        checker = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(checker)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            subprocess.run(["git", "init", "-q", str(root)], check=True)
            home = "/".join(("", "home", "fixture", "checkout"))
            (root / ".publishignore").write_text("private/\n")
            (root / "private").mkdir()
            (root / "private/report.md").write_text(f"`{home}/file`\n")
            (root / "example.py").write_text(f'message = "Error at {home}/Main.java:42"\n')
            (root / "portable.sh").write_text('work="$CHRONICLE_PUBLISH_WORK"\n')
            subprocess.run(["git", "-C", str(root), "add", "."], check=True)
            self.assertEqual([], checker.scan(root))
            (root / "bad.py").write_text(f'from pathlib import Path\np = Path("{home}/data")\n')
            (root / "bad.sh").write_text(f"work={home}/output\n")
            subprocess.run(["git", "-C", str(root), "add", "."], check=True)
            self.assertEqual(["bad.py", "bad.sh"], checker.scan(root))
            (root / "bad.py").write_text('p = os.environ["INPUT"]\n')
            self.assertEqual(["bad.py", "bad.sh"], checker.scan(root))
            (root / ".publishignore").write_text("private/*\n!private/keep.md\n")
            (root / "private/keep.md").write_text(f"`{home}/file`\n")
            subprocess.run(["git", "-C", str(root), "add", "."], check=True)
            self.assertEqual(["bad.sh", "private/keep.md"], checker.scan(root))


if __name__ == "__main__":
    unittest.main()
