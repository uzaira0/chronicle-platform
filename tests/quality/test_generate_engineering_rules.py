"""Rule inventory and fixture coverage follow the loaded rule configurations."""

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/generate-engineering-rules.py"


class EngineeringRulesTest(unittest.TestCase):
    def run_generator(self, root, *args):
        return subprocess.run([sys.executable, str(SCRIPT), "--root", str(root), *args],
                              text=True, capture_output=True, check=False)

    def test_generated_inventory_and_missing_fixture_and_drift_are_checked(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            files = {
                "sgconfig.yml": "ruleDirs: [rules]\ntestConfigs: [{testDir: fixtures}]\n",
                "rules/example.yml": "id: example\nmessage: Keep the owner.\nnote: 'Blind spots: indirect calls.'\n",
                "fixtures/example.yml": "id: example\nvalid: ['safe()']\ninvalid: ['unsafe()']\n",
                "mobile/sgconfig.yml": "ruleDirs: [rules]\ntestConfigs: [{testDir: tests}]\n",
                "mobile/rules/local.yml": "id: local\nmessage: Submodule owner.\nnote: 'Blind spots: aliases.'\n",
                "mobile/tests/local.yml": "id: local\nvalid: ['safe()']\ninvalid: ['unsafe()']\n",
                "tests/security/semgrep/example.yml": "rules: [{id: shell-example, message: Checked argv.}]\n",
                "tests/security/semgrep-tests/example.py": "# ruleid: shell-example\nunsafe()\n# ok: shell-example\nsafe()\n",
            }
            for name, value in files.items():
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(value)
            generated = self.run_generator(root)
            self.assertEqual(0, generated.returncode, generated.stderr)
            document = root / "docs/engineering-rules.md"
            self.assertIn("example | Keep the owner. | ast-grep | rules/example.yml", document.read_text())
            self.assertIn("shell-example | Checked argv. | semgrep", document.read_text())
            self.assertIn("local | Submodule owner. | ast-grep | mobile/rules/local.yml", document.read_text())
            self.assertEqual(0, self.run_generator(root, "--check").returncode)
            document.write_text(document.read_text() + "stale\n")
            stale = self.run_generator(root, "--check")
            self.assertNotEqual(0, stale.returncode)
            self.assertIn("is stale", stale.stderr)
            (root / "fixtures/example.yml").write_text("id: example\nvalid: ['safe()']\n")
            missing = self.run_generator(root)
            self.assertNotEqual(0, missing.returncode)
            self.assertIn("example: missing invalid fixtures", missing.stderr)
            (root / "fixtures/example.yml").write_text(files["fixtures/example.yml"])
            (root / "tests/security/semgrep-tests/example.py").write_text("# ok: shell-example\nsafe()\n")
            self.assertIn("shell-example: missing ruleid fixtures", self.run_generator(root).stderr)
            (root / "tests/security/semgrep-tests/example.py").write_text("# ruleid: shell-example\nunsafe()\n")
            self.assertIn("shell-example: missing ok fixtures", self.run_generator(root).stderr)
            (root / "tests/security/semgrep-tests/example.py").write_text(files["tests/security/semgrep-tests/example.py"])
            (root / "rules/example.yml").write_text("id: example\nmessage: Keep the owner.\n")
            self.assertIn("example: missing Blind spots note", self.run_generator(root).stderr)


if __name__ == "__main__":
    unittest.main()
