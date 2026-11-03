import runpy
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "selfhost"))
from chronicle_ops.common import run
from chronicle_ops.reconcile import ENABLED_ENV
from update_fixture import prepare_update
from selfhost_fixture import bundle_fixture_files, copy_selfhost_fixture
import test_secret_generation as setup_fixture


class LauncherTests(unittest.TestCase):
    def test_rotation_usage_errors_exit_two_before_loading_settings(self):
        for arguments in ([], ['--unknown'], ['jwt', 'extra', 'extra'],
                          ['recover'], ['recover', '--forward', '--rollback'], ['jwt', '--forward']):
            with self.subTest(arguments=arguments), tempfile.TemporaryDirectory() as folder:
                host = Path(folder)
                copy_selfhost_fixture(host)
                result = run(['bash', str(host / 'chronicle'), 'rotate-secret', *arguments],
                             capture=True, stderr=subprocess.PIPE, timeout=10)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertIn('usage:', result.stderr.lower())
                self.assertNotIn('run ./chronicle setup', result.stderr)

    def setUp(self):
        disabled = patch.dict(os.environ, {ENABLED_ENV: "false"})
        disabled.start()
        self.addCleanup(disabled.stop)

    def test_update_check_is_read_only_and_pre_reset_apply_is_refused(self):
        from chronicle_ops.release import UPDATE_AVAILABLE_EXIT
        for latest, expected in [('1.2.4', UPDATE_AVAILABLE_EXIT), ('1.2.3', 0)]:
            with self.subTest(latest=latest), tempfile.TemporaryDirectory() as folder:
                fixture = prepare_update(Path(folder), latest)
                metadata = fixture.root / 'http/latest.json'
                catalog = json.loads(metadata.read_text())
                catalog[0]['body'] = 'UNVERIFIED_RUN_THIS_SENTINEL\x1b[2J'
                metadata.write_text(json.dumps(catalog))
                result = fixture.invoke('--check')
                self.assertEqual(expected, result.returncode, result.stderr)
                self.assertNotIn('UNVERIFIED_RUN_THIS_SENTINEL', result.stdout + result.stderr)
                self.assertEqual([], list(fixture.release.rglob('__pycache__')))
                refused = fixture.invoke()
                self.assertNotEqual(0, refused.returncode)
                self.assertIn('fresh install', refused.stderr)
                self.assertFalse((fixture.root / 'handoff').exists())
                self.assertEqual([], list((fixture.root / 'releases').glob('*.tar.gz*')))

    def test_update_storage_uses_saved_floor_and_state_without_moving_bundle_origin(self):
        with tempfile.TemporaryDirectory() as folder:
            fixture = prepare_update(Path(folder), '1.2.4')
            state = fixture.root / 'deployment-state'
            (fixture.host / '.env').write_text(
                f"COMPOSE_PROJECT_NAME=study-production\nCHRONICLE_STATE_DIR='{state}'\nMIN_FREE_DISK_GIB=999999\n")
            fixture.environment['MIN_FREE_DISK_GIB'] = '0'
            result = fixture.invoke()
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('fresh install', result.stderr)
            self.assertFalse((fixture.root / 'handoff').exists())
            self.assertEqual(list((fixture.root / 'releases').glob('*.tar.gz*')), [])

    def test_update_check_rejects_superseded_bundle_before_fetching_metadata(self):
        with tempfile.TemporaryDirectory() as folder:
            fixture = prepare_update(Path(folder), '1.2.4')
            active = fixture.root / 'active'
            active.mkdir()
            (fixture.root / 'deployment-state/.chronicle-owner').write_text(str(active))
            (fixture.root / 'http/latest.json').unlink()
            result = fixture.invoke('--check')
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('superseded', result.stderr)
            self.assertNotIn('latest.json', result.stderr)

    def test_release_signing_caddy_and_backup_sbom_regressions(self):
        import runpy
        checks = runpy.run_path(str(ROOT / "tests/security/selfhost-monitoring.py"))
        for name in ("test_release_signatures", "test_caddy_default_log_masks_handler_ips",
                     "test_mobile_snat_abuse_limits", "test_backup_sbom_inventory"):
            with self.subTest(check=name):
                checks[name]()

    def test_package_sources_import_on_python_39(self):
        interpreter = shutil.which('python3.9')
        if interpreter is None:
            self.skipTest('Python 3.9 unavailable')
        for path in (ROOT / 'selfhost/chronicle_ops').glob('*.py'):
            with self.subTest(module=path.name):
                run([interpreter, '-c', 'import importlib, sys; importlib.import_module(sys.argv[1])',
                     'chronicle_ops.' + path.stem], capture=True, stderr=subprocess.PIPE, check=True,
                    env=dict(os.environ, PYTHONPATH=str(ROOT / 'selfhost')), timeout=10)

    def test_release_bundle_contains_the_operator_package(self):
        builder = runpy.run_path(str(ROOT / 'scripts/build-selfhost-release.py'))
        with tempfile.TemporaryDirectory() as folder:
            bundle = Path(folder) / 'bundle'
            tracked = builder['tracked_source_paths'](ROOT) | {'selfhost/' + name for name in bundle_fixture_files(builder)}
            builder['copy_bundle_inputs'](bundle, None, tracked)
            package = bundle / 'selfhost/chronicle_ops'
            self.assertEqual({path.relative_to(ROOT / 'selfhost/chronicle_ops') for path in (ROOT / 'selfhost/chronicle_ops').rglob('*.py')},
                             {path.relative_to(package) for path in package.rglob('*.py')})
            # The operator can prepare a canary without this checkout or site packages.
            result = subprocess.run([sys.executable, '-S', str(bundle / 'tests/deployment/selfhost-client.py'), '--help'],
                                    cwd=folder, capture_output=True, text=True)
            self.assertEqual(0, result.returncode, result.stderr)


class LauncherSetupTests(setup_fixture.SelfhostSetupFixture):
    def test_declining_resetup_succeeds_and_preserves_settings(self):
        self.run_setup()
        before = (self.host / '.env').read_bytes()
        result = run(['bash', str(self.host / 'chronicle'), 'setup'], input='n\n',
                     env=self.environment, capture=True, stderr=subprocess.PIPE, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('Keeping existing .env.', result.stdout)
        self.assertEqual((self.host / '.env').read_bytes(), before)

    def test_setup_prints_the_installed_public_fingerprint_and_docs_match(self):
        fingerprint = subprocess.run(['ssh-keygen', '-lf', str(ROOT / 'selfhost/release-signing.pub')],
                                     check=True, capture_output=True, text=True).stdout.split()[1]
        for document in ('SECURITY.md', 'selfhost/README.md'):
            self.assertIn(fingerprint, (ROOT / document).read_text())
        result = self.run_setup()
        self.assertIn(fingerprint, result.stdout)
        self.assertIn('Public key shipped in the bundle', result.stdout)
        self.assertIn("email or message from your study's Chronicle contact", result.stdout)
        self.assertIn('If it differs, stop. Do not install.', result.stdout)
