"""Python and shell environment overrides must appear in the operator settings inventory."""

from pathlib import Path
import tempfile
import unittest

from chronicle_ops.config_inventory import undocumented_runtime_settings


class ConfigInventoryTests(unittest.TestCase):
    def test_planted_python_and_shell_overrides_fail_until_documented(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / 'chronicle_ops').mkdir()
            (root / 'overlays').mkdir()
            (root / 'docker-compose.yml').write_text('services:\n  backend:\n    environment:\n      INTERNAL: fixed\n')
            (root / 'chronicle').write_text('export GENERATED=local\nprintf "%s" "${SHELL_OVERRIDE:-default}"\n')
            (root / 'chronicle_ops/probe.py').write_text('import os\n'
                'NAME="NAMED_OVERRIDE"\nos.getenv("PYTHON_OVERRIDE")\nos.environ.get(NAME)\n'
                'os.environ["INTERNAL"]\nos.environ.get("GENERATED")\n')
            expected = ['NAMED_OVERRIDE', 'PYTHON_OVERRIDE', 'SHELL_OVERRIDE']
            self.assertEqual(expected, undocumented_runtime_settings(root, []))
            self.assertEqual([], undocumented_runtime_settings(root, expected))

    def test_unexported_shell_local_cannot_hide_a_python_environment_override(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / 'chronicle_ops').mkdir()
            (root / 'docker-compose.yml').write_text('services: {}\n')
            (root / 'chronicle').write_text('COLLISION=local\n')
            (root / 'chronicle_ops/probe.py').write_text('import os\nos.environ.get("COLLISION")\n')
            self.assertEqual(['COLLISION'], undocumented_runtime_settings(root, []))

    def test_input_read_before_local_assignment_still_requires_documentation(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / 'chronicle_ops').mkdir()
            (root / 'docker-compose.yml').write_text('services: {}\n')
            (root / 'chronicle').write_text('printf "%s" "${INPUT:-}"\nINPUT=computed\n')
            self.assertEqual(['INPUT'], undocumented_runtime_settings(root, []))


if __name__ == '__main__':
    unittest.main()
