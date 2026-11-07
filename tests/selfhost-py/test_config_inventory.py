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


    def test_imported_names_are_resolved_and_package_handoffs_are_internal(self):
        # A reader naming another module's constant was invisible; a value the package sets for
        # its own child process (os.environ[NAME] = ...) is not an operator setting.
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / 'chronicle_ops').mkdir()
            (root / 'docker-compose.yml').write_text('services: {}\n')
            (root / 'chronicle').write_text('true\n')
            (root / 'chronicle_ops/names.py').write_text('SETTING = "IMPORTED_OVERRIDE"\nHANDOFF = "PARENT_TO_CHILD"\n')
            (root / 'chronicle_ops/reader.py').write_text('import os\nfrom .names import HANDOFF, SETTING\n'
                                                          'os.environ.get(SETTING)\nos.environ.get(HANDOFF)\n')
            (root / 'chronicle_ops/writer.py').write_text('import os\nfrom .names import HANDOFF\nos.environ[HANDOFF] = "x"\n')
            self.assertEqual(['IMPORTED_OVERRIDE'], undocumented_runtime_settings(root, []))

    def test_every_compose_variable_is_documented_or_supplied_by_the_bundle(self):
        import re
        from chronicle_ops.config_inventory import COMPOSE_SUPPLIED
        from chronicle_ops.envfile import read_env
        root = Path(__file__).resolve().parents[2] / 'selfhost'
        documented = set(read_env(root / '.env.example'))
        example = (root / '.env.example').read_text()
        documented |= set(re.findall(r'^#\s*([A-Z][A-Z0-9_]*)=', example, re.MULTILINE))
        files = [root / 'docker-compose.yml', *root.glob('overlays/*.yml'), *root.glob('monitoring/*.yml')]
        read = {name for path in files for name in re.findall(r'\$\{([A-Z][A-Z0-9_]*)', path.read_text())}
        self.assertEqual(set(), read - documented - COMPOSE_SUPPLIED)
        self.assertIn('CHRONICLE_ALERT_EGRESS', COMPOSE_SUPPLIED)
        self.assertIn('CHRONICLE_CORE_PREFIX', documented)
        self.assertIn('PUBLIC_PROBE_MEM_LIMIT', documented)

    def test_only_the_release_fetcher_uses_the_operator_proxy(self):
        from chronicle_ops.config_inventory import proxy_violations
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / 'chronicle_ops').mkdir()
            probe = root / 'chronicle_ops/probe.py'
            update = root / 'chronicle_ops/update.py'
            update.write_text('run(["curl", "--fail", url])\n')
            probe.write_text('run(["curl", *trust,\n     "--noproxy", "*", url])\n')
            self.assertEqual([], proxy_violations(root))
            probe.write_text('run(["curl", "--silent", url])\n')
            self.assertEqual(['chronicle_ops/probe.py:1 probes the deployment through the proxy'], proxy_violations(root))
            probe.write_text('x = 1\n')
            update.write_text('run(["curl", "--noproxy", "*", url])\n')
            self.assertEqual(['chronicle_ops/update.py:1 connections off the host ignore HTTPS_PROXY'], proxy_violations(root))
            # update --check's destination probe takes the proxy too, and may not bypass it.
            update.write_text('run(["curl", "--fail", url])\n')
            (root / 'chronicle_ops/egress.py').write_text('run(["curl", "--silent", url])\n')
            self.assertEqual([], proxy_violations(root))
            (root / 'chronicle_ops/egress.py').write_text('run(["curl", "--noproxy", "*", url])\n')
            self.assertEqual(['chronicle_ops/egress.py:1 connections off the host ignore HTTPS_PROXY'], proxy_violations(root))
            (root / 'chronicle_ops/egress.py').write_text('x = 1\n')
            update.write_text('x = 1\n')
            self.assertEqual(['chronicle_ops/update.py has no release download'], proxy_violations(root))

if __name__ == '__main__':
    unittest.main()
