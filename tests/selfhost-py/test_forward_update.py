"""The reset is a floor; later releases keep a supported in-place path."""
import gzip
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from chronicle_ops import release, dump
from chronicle_ops.__main__ import argument_parser
from test_restore import DUMP


def next_version(version):
    major, minor, patch_number = version.split('.')
    return f'{major}.{minor}.{int(patch_number) + 1}'


class ForwardPolicyTests(unittest.TestCase):
    def test_upgrade_accepts_extended_startup_waits_before_any_mutation(self):
        from chronicle_ops.upgrade import Upgrade
        for timeout in ('3600', '7200', '18446744073709551616'):
            with self.subTest(timeout=timeout), patch.dict(os.environ, UPGRADE_WAIT_TIMEOUT_SECONDS=timeout):
                operation = Upgrade(Path('/old'), Path('/new'), Path('/state'), {})
                self.assertEqual(timeout, operation.timeout)
        for timeout in ('0', '01', '-1', 'nan', 'inf', '1.5', ' ', '3600\n'):
            with self.subTest(timeout=timeout), patch.dict(os.environ, UPGRADE_WAIT_TIMEOUT_SECONDS=timeout), \
                 self.assertRaisesRegex(ValueError, 'UPGRADE_WAIT_TIMEOUT_SECONDS must be a positive integer'):
                Upgrade(Path('/old'), Path('/new'), Path('/state'), {'UPGRADE_WAIT_TIMEOUT_SECONDS': '5400'})

    def test_upgrade_wait_resolves_environment_then_settings_then_generic_wait(self):
        """`./chronicle update` does not source .env, so the settings file is read directly."""
        from chronicle_ops.upgrade import Upgrade
        cases = (
            ('default', {}, {}, '3600'),
            ('generic wait', {}, {'START_WAIT_TIMEOUT_SECONDS': '7200'}, '7200'),
            ('file only', {}, {'UPGRADE_WAIT_TIMEOUT_SECONDS': '5400', 'START_WAIT_TIMEOUT_SECONDS': '7200'}, '5400'),
            ('environment over file', {'UPGRADE_WAIT_TIMEOUT_SECONDS': '9000'},
             {'UPGRADE_WAIT_TIMEOUT_SECONDS': '5400', 'START_WAIT_TIMEOUT_SECONDS': '7200'}, '9000'),
            ('empty file value is unset', {},
             {'UPGRADE_WAIT_TIMEOUT_SECONDS': '', 'START_WAIT_TIMEOUT_SECONDS': '7200'}, '7200'),
            ('empty environment value is unset', {'UPGRADE_WAIT_TIMEOUT_SECONDS': ''},
             {'UPGRADE_WAIT_TIMEOUT_SECONDS': '5400'}, '5400'),
            ('empty environment falls back to generic wait', {'UPGRADE_WAIT_TIMEOUT_SECONDS': ''},
             {'START_WAIT_TIMEOUT_SECONDS': '7200'}, '7200'),
            ('both overrides empty use the default', {'UPGRADE_WAIT_TIMEOUT_SECONDS': ''},
             {'UPGRADE_WAIT_TIMEOUT_SECONDS': ''}, '3600'),
            ('quoted file value', {}, {'UPGRADE_WAIT_TIMEOUT_SECONDS': "'5400' # update wait"}, '5400'),
            ('quoted empty file value is unset', {},
             {'UPGRADE_WAIT_TIMEOUT_SECONDS': '"" # generic wait', 'START_WAIT_TIMEOUT_SECONDS': '7200'}, '7200'),
            ('environment bypasses invalid file value', {'UPGRADE_WAIT_TIMEOUT_SECONDS': '9000'},
             {'UPGRADE_WAIT_TIMEOUT_SECONDS': 'invalid'}, '9000'),
            ('upgrade bypasses invalid generic wait', {},
             {'UPGRADE_WAIT_TIMEOUT_SECONDS': '5400', 'START_WAIT_TIMEOUT_SECONDS': 'invalid'}, '5400'),
        )
        for name, environment, settings, expected in cases:
            with self.subTest(name), patch.dict(os.environ, environment, clear=True):
                self.assertEqual(expected, Upgrade(Path('/old'), Path('/new'), Path('/state'), settings).timeout)
        for name, settings in (('UPGRADE', {'UPGRADE_WAIT_TIMEOUT_SECONDS': '0', 'START_WAIT_TIMEOUT_SECONDS': '7200'}),
                               ('UPGRADE', {'UPGRADE_WAIT_TIMEOUT_SECONDS': "' '"}),
                               ('UPGRADE', {'UPGRADE_WAIT_TIMEOUT_SECONDS': '"01"'}),
                               ('START', {'UPGRADE_WAIT_TIMEOUT_SECONDS': '', 'START_WAIT_TIMEOUT_SECONDS': '1.5'}),
                               ('START', {'START_WAIT_TIMEOUT_SECONDS': ''})):
            with self.subTest(invalid=name), patch.dict(os.environ, {}, clear=True), \
                 self.assertRaisesRegex(ValueError, f'{name}_WAIT_TIMEOUT_SECONDS must be a positive integer'):
                Upgrade(Path('/old'), Path('/new'), Path('/state'), settings)

    def test_extracted_candidate_measures_storage_with_active_release_image(self):
        from chronicle_ops import common, upgrade
        from chronicle_ops.envfile import read_env, set_env_values
        from chronicle_ops.update import extract_release
        from test_update import ExtractReleaseTests
        fixture = ExtractReleaseTests()
        fixture.VERSION = release.UPGRADE_FROM_MINIMUM
        fixture.NAME = 'chronicle-selfhost-' + fixture.VERSION
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        archive = fixture.archive()
        candidate = extract_release(archive, fixture.NAME, fixture.VERSION) / 'selfhost'
        self.assertFalse((candidate / '.env').exists())
        previous = fixture.bundle / 'selfhost'
        state = fixture.root / 'state'
        state.mkdir()
        active_image = 'fixture/active-postgres@sha256:' + 'b' * 64
        (previous / '.env').write_text(set_env_values('', {
            'POSTGRES_IMAGE': active_image,
            'COMPOSE_FILE': 'docker-compose.yml:overlays/mode-local-https.yml',
            'COMPOSE_PROJECT_NAME': 'fixture', 'DASHBOARD_PASSWORD_HASH': '$2synthetic',
        }, require_existing=False))
        (previous / '.env').chmod(0o600)
        settings = read_env(previous / '.env')
        disk = SimpleNamespace(f_bavail=30, f_frsize=common.GIB, f_files=100_000, f_favail=100_000)
        measured = []
        def measure(command, **_kwargs):
            if command[:2] == ['docker', 'info']:
                return SimpleNamespace(stdout='/fixture/docker-data')
            self.assertFalse((candidate / '.env').exists())
            self.assertEqual(active_image, command[command.index('--entrypoint') + 2])
            measured.append(command)
            return SimpleNamespace(stdout='header\ndisk 40000000 0 30000000 0% /storage\n'
                                   'header\ndisk 100000 0 100000 0% /storage\n')
        def stat(path):
            if Path(path) == state:
                return disk
            raise FileNotFoundError(path)
        class ConfigStageReached(Exception):
            pass
        operation = upgrade.Upgrade(previous, candidate, state, settings)
        origin = Path.cwd()
        try:
            os.chdir(candidate)
            with patch.dict(os.environ, {'CHRONICLE_RECONCILE_ENABLED': 'false'}, clear=True), \
                 patch.object(common, 'database_volume_path', return_value=None), \
                 patch.object(common.os, 'statvfs', side_effect=stat), \
                 patch.object(common, 'run', side_effect=measure), \
                 patch('chronicle_ops.update.show_changelog'), \
                 patch.object(operation, 'dc', side_effect=ConfigStageReached), \
                 self.assertRaises(ConfigStageReached):
                operation.prepare()
        finally:
            os.chdir(origin)
        self.assertEqual(1, len(measured))
        self.assertTrue((candidate / '.env').is_file())
        self.assertEqual(0o600, (candidate / '.env').stat().st_mode & 0o777)

    def test_floor_accepts_same_version_repair_and_forward_update(self):
        floor = release.UPGRADE_FROM_MINIMUM
        target = {'release_version': next_version(floor), release.UPGRADE_FLOOR_KEY: floor}
        release.require_upgrade(floor, target)
        release.require_upgrade(target['release_version'], target)

    def test_floor_and_downgrade_are_refused(self):
        floor = release.UPGRADE_FROM_MINIMUM
        target = {'release_version': floor, release.UPGRADE_FLOOR_KEY: floor}
        with self.assertRaisesRegex(ValueError, 'fresh install required.*UPGRADE-ROLLBACK.md'):
            release.require_upgrade('2026.10.9', target)
        with self.assertRaisesRegex(ValueError, 'downgrade'):
            release.require_upgrade(next_version(floor), target)

    def test_update_parser_accepts_apply_check_and_explicit_version(self):
        parser = argument_parser()
        for args in (['update'], ['update', '--check'], ['update', release.UPGRADE_FROM_MINIMUM]):
            self.assertEqual('update', parser.parse_args(args).command)

    def test_restore_accepts_older_post_reset_and_refuses_newer_before_mutation(self):
        floor = release.UPGRADE_FROM_MINIMUM
        newer = next_version(floor)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'backup.sql.gz'
            path.write_bytes(gzip.compress(DUMP))
            dump.stamp_backup(path, floor)
            dump.require_restore_version(path, newer)
            path.write_bytes(gzip.compress(DUMP))
            dump.stamp_backup(path, newer)
            with self.assertRaisesRegex(ValueError, 'newer release'):
                dump.require_restore_version(path, floor)
            path.write_bytes(gzip.compress(DUMP))
            dump.stamp_backup(path, '0.0.0')
            with self.assertRaisesRegex(ValueError, 'fresh install required'):
                dump.require_restore_version(path, newer)
            path.write_bytes(gzip.compress(DUMP))
            with self.assertRaisesRegex(ValueError, 'fresh install required'):
                dump.require_restore_version(path, newer)  # Every post-reset producer stamps its release.

    def test_documented_shell_update_parser_uses_python_contract(self):
        from test_documented_commands import DocumentedCommandTests
        check = DocumentedCommandTests()
        for args in (['update'], ['update', '--check'], ['update', release.UPGRADE_FROM_MINIMUM]):
            result = check.validate(args)
            self.assertEqual(0, result.returncode, result.stderr)


class PublishedMigrationTests(unittest.TestCase):
    def test_release_builder_preserves_every_published_migration(self):
        from chronicle_ops.migrations import migration_hashes, require_published_migrations
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory)
            migrations = source / 'chronicle-server/src/main/resources/db/migration'
            migrations.mkdir(parents=True)
            baseline = migrations / 'V1__fresh_schema.sql'
            baseline.write_text('CREATE TABLE kept(id integer);\n')
            published = migration_hashes(source)
            require_published_migrations(published, published)
            (migrations / 'V2__new.sql').write_text('ALTER TABLE kept ADD COLUMN label text;\n')
            require_published_migrations(published, migration_hashes(source))
            baseline.write_text('CREATE TABLE changed(id integer);\n')
            with self.assertRaisesRegex(ValueError, 'published migration changed'):
                require_published_migrations(published, migration_hashes(source))
            baseline.unlink()
            with self.assertRaisesRegex(ValueError, 'published migration changed'):
                require_published_migrations(published, migration_hashes(source))


class InterruptedUpdateTests(unittest.TestCase):
    def test_interrupted_before_migration_restarts_previous_and_releases_fence(self):
        from chronicle_ops.upgrade import PREPARED, UPGRADE_LOCK, recover_update
        from chronicle_ops.reconcile import RECOVERY_FILE
        from chronicle_ops.receipts import write_json
        from types import SimpleNamespace
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            previous, candidate, state = root / 'old', root / 'new', root / 'state'
            for folder in (previous, candidate, state):
                folder.mkdir()
            (previous / '.env').write_text('COMPOSE_FILE=docker-compose.yml:overlays/mode-local-https.yml\n')
            (candidate / '.env').write_text('candidate settings')
            marker = state / UPGRADE_LOCK
            marker.mkdir()
            write_json(marker / RECOVERY_FILE, dict(previous=str(previous), owner=str(candidate), phase=PREPARED))
            origin = Path.cwd()
            try:
                os.chdir(previous)
                with patch('chronicle_ops.upgrade.compose_release', return_value=SimpleNamespace(returncode=0, stdout='postgres\nbackend\nweb\nmigrate\nca-export')) as dc, patch('chronicle_ops.upgrade.run'):
                    self.assertTrue(recover_update(state))
                startup = next(call.args for call in dc.call_args_list if 'up' in call.args)
                self.assertNotIn('ca-export', startup)
                self.assertTrue(any('ca-export' in call.args for call in dc.call_args_list))
                self.assertFalse(marker.exists())
                self.assertFalse((candidate / '.env').exists())
            finally:
                os.chdir(origin)


class LedgerMigrationTests(unittest.TestCase):
    def test_committed_ledger_freezes_published_files_without_tags(self):
        from chronicle_ops.migrations import (MIGRATION_LEDGER, migration_hashes,
                                              record_publication, require_immutable_migrations)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            migrations = root / 'chronicle-server/src/main/resources/db/migration'
            migrations.mkdir(parents=True)
            baseline = migrations / 'V1__fresh_schema.sql'
            baseline.write_text('SELECT 1;\n')
            baseline.write_text('SELECT 2;\n')
            require_immutable_migrations(root)  # No publication: V1 remains editable.
            manifest = {"release_version": release.UPGRADE_FROM_MINIMUM + '-rc.1',
                        release.MIGRATIONS_KEY: migration_hashes(root)}
            record_publication(root, manifest)
            self.assertTrue((root / MIGRATION_LEDGER).is_file())
            require_immutable_migrations(root)
            baseline.write_text('SELECT 3;\n')
            for source in (None, root):  # engineering checkout and release-builder source snapshot
                with self.subTest(source=source), self.assertRaisesRegex(ValueError, 'published migration changed'):
                    require_immutable_migrations(root, source)
            with self.assertRaisesRegex(ValueError, 'published migration changed'):
                record_publication(root, dict(manifest, migrations=migration_hashes(root)))

    def test_publication_ledger_is_append_only_and_well_formed(self):
        from chronicle_ops.migrations import MIGRATION_LEDGER, migration_hashes, published_migrations
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            migrations = root / 'chronicle-server/src/main/resources/db/migration'
            migrations.mkdir(parents=True)
            (migrations / 'V1__fresh_schema.sql').write_text('SELECT 1;\n')
            manifest = root / 'manifest.json'
            version = release.UPGRADE_FROM_MINIMUM
            manifest.write_text(json.dumps({'release_version': version, release.MIGRATIONS_KEY: migration_hashes(root)}))
            # publish-images.sh records the release through the module's command line after the signed release exists.
            command = [sys.executable, '-s', '-m', 'chronicle_ops.migrations', str(root), str(manifest)]
            environment = dict(os.environ, PYTHONDONTWRITEBYTECODE='1', PYTHONPATH=str(Path(__file__).resolve().parents[2] / 'selfhost'))
            self.assertEqual(0, subprocess.run(command, env=environment, capture_output=True, timeout=30).returncode)
            self.assertEqual({version: migration_hashes(root)}, published_migrations(root))
            (migrations / 'V2__add_index.sql').write_text('SELECT 2;\n')
            manifest.write_text(json.dumps({'release_version': version, release.MIGRATIONS_KEY: migration_hashes(root)}))
            replaced = subprocess.run(command, env=environment, capture_output=True, text=True, timeout=30)
            self.assertEqual(1, replaced.returncode)
            self.assertIn('ValueError: publication ledger cannot replace a release inventory', replaced.stderr)
            self.assertEqual({'V1__fresh_schema.sql'}, set(published_migrations(root)[version]))
            (root / MIGRATION_LEDGER).write_text('[]')
            with self.assertRaisesRegex(ValueError, 'publication ledger must map release versions to migration hashes'):
                published_migrations(root)


class CandidateDiscoveryTests(unittest.TestCase):
    def test_installed_reader_accepts_future_image_and_file_contract(self):
        from test_release import complete_manifest_fixture
        from chronicle_ops.images import IMAGE_INPUTS_KEY
        with tempfile.TemporaryDirectory() as directory:
            bundle = Path(directory)
            (bundle / 'selfhost').mkdir()
            manifest = bundle / 'release-manifest.json'
            manifest.write_text(json.dumps(dict(release_version=release.UPGRADE_FROM_MINIMUM)))
            complete_manifest_fixture(bundle)
            data = json.loads(manifest.read_text())
            data['images']['future-worker'] = 'fixture/worker@sha256:' + 'd' * 64
            data[IMAGE_INPUTS_KEY]['future-worker'] = 'a' * 40
            for name in ('rotate-secret.sh', '.env.example'):
                (bundle / 'selfhost' / name).unlink()
                del data['files']['selfhost/' + name]
            manifest.write_text(json.dumps(data))
            read, _ = release.read_manifest(manifest, True, discovery=True)
            self.assertEqual(data['images'], read['images'])


class FailedPreparationTests(unittest.TestCase):
    def test_failed_exec_removes_its_handoff_and_download(self):
        import shutil
        from chronicle_ops.update import HANDOFF_FILE, apply_update, release_assets
        from chronicle_ops.envfile import read_env
        from chronicle_ops.release import UPDATE_DIRECTORY_PREFIX
        from update_fixture import prepare_update
        version = next_version(release.UPGRADE_FROM_MINIMUM)
        with tempfile.TemporaryDirectory() as directory:
            fixture = prepare_update(Path(directory), version)
            catalog = json.loads((fixture.root / 'http/latest.json').read_text())[0]
            assets = release_assets(catalog, f'chronicle-selfhost-{version}.tar.gz')
            def download(assets, destination):
                for asset in assets.all():
                    shutil.copy2(fixture.root / 'http' / asset.name, destination / asset.name)
            with patch('chronicle_ops.update.download_assets', side_effect=download), \
                 patch.dict(os.environ, fixture.environment), \
                 patch('chronicle_ops.update.show_changelog', side_effect=AssertionError('candidate owns its notes')), \
                 patch('chronicle_ops.update.exec_candidate', side_effect=OSError('exec refused')), \
                 self.assertRaisesRegex(OSError, 'exec refused'):
                apply_update(fixture.host, read_env(fixture.host / '.env'), assets, version,
                             release.UPGRADE_FROM_MINIMUM)
            self.assertFalse((fixture.root / 'deployment-state' / HANDOFF_FILE).exists())
            self.assertEqual([], list((fixture.root / 'releases').glob(UPDATE_DIRECTORY_PREFIX + '*')))

    def test_prepare_failure_removes_private_settings_and_staged_wrapper(self):
        from chronicle_ops.update import HANDOFF_FILE, apply_candidate
        from chronicle_ops.release import UPDATE_DIRECTORY_PREFIX
        from chronicle_ops.receipts import write_json
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            previous, state = root / 'previous', root / 'state'
            candidate = root / (UPDATE_DIRECTORY_PREFIX + 'fixture') / 'bundle/selfhost'
            for path in (previous, state, candidate):
                path.mkdir(parents=True)
            (previous / '.env').write_text('CHRONICLE_STATE_DIR=' + str(state) + '\n')
            (previous / '.env').chmod(0o600)
            write_json(state / HANDOFF_FILE, dict(previous=str(previous), owner=str(candidate)))
            def fail_prepare(operation):
                (operation.candidate / '.env').write_text('private fixture settings')
                raise ValueError('pull failed')
            def inspect_staging(*_args, **_kwargs):
                self.assertTrue(candidate.parent.exists(), 'image cleanup needs the candidate inventory')
                self.assertFalse((candidate / '.env').exists())
            origin = Path.cwd()
            try:
                os.chdir(candidate)
                with patch('chronicle_ops.upgrade.Upgrade.prepare', fail_prepare), \
                     patch('chronicle_ops.upgrade.finish_operation'), \
                     patch('chronicle_ops.release.cleanup_releases', side_effect=inspect_staging):
                    self.assertEqual(1, apply_candidate(previous))
                self.assertFalse((candidate / '.env').exists())
                self.assertFalse(candidate.parent.parent.exists())
                self.assertFalse((state / HANDOFF_FILE).exists())
            finally:
                os.chdir(origin)




class ExplicitVersionTests(unittest.TestCase):
    def test_build_metadata_selects_the_exact_requested_publication(self):
        from chronicle_ops.update import select_release
        versions = [release.UPGRADE_FROM_MINIMUM + suffix for suffix in ('+first', '+second')]
        catalog = [dict(tag_name='v' + version, draft=False, prerelease=False) for version in versions]
        self.assertEqual(catalog[1], select_release(catalog, versions[1]))
        with self.assertRaisesRegex(ValueError, 'missing or ambiguous'):
            select_release(catalog, release.UPGRADE_FROM_MINIMUM)


class SignedUpdateTests(unittest.TestCase):
    def test_foreign_signature_is_refused_before_handoff_or_backup(self):
        from update_fixture import prepare_update
        with tempfile.TemporaryDirectory() as directory:
            fixture = prepare_update(Path(directory), next_version(release.UPGRADE_FROM_MINIMUM), 'foreign-signature')
            manifest = fixture.release / 'release-manifest.json'
            manifest.write_text(json.dumps(dict(release_version=release.UPGRADE_FROM_MINIMUM)))
            result = fixture.invoke()
            self.assertNotEqual(0, result.returncode)
            self.assertIn('invalid release signature', result.stderr)
            self.assertFalse((Path(directory) / 'deployment-state' / '.chronicle-upgrade.lock').exists())
            self.assertFalse((Path(directory) / 'handoff').exists())


class MigrationGateTests(unittest.TestCase):
    def test_builder_rejects_a_published_edit(self):
        import runpy
        import tarfile
        from types import SimpleNamespace
        from chronicle_ops.migrations import migration_hashes, record_publication
        repository = Path(__file__).resolve().parents[2]
        builder = runpy.run_path(str(repository / 'scripts/build-selfhost-release.py'))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            migrations = root / 'chronicle-server/src/main/resources/db/migration'
            migrations.mkdir(parents=True)
            baseline = migrations / 'V1__fresh_schema.sql'
            baseline.write_text('SELECT 1;\n')
            (root / 'CHANGELOG.md').write_text('## [' + release.UPGRADE_FROM_MINIMUM + ']\n\nFixture\n')
            record_publication(root, dict(release_version=release.UPGRADE_FROM_MINIMUM,
                                          migrations=migration_hashes(root)))
            def archive(_root, _revision, _context, output, *, submodules):
                self.assertIn('chronicle-server', submodules)
                self.assertNotIn('chronicle', submodules)
                self.assertNotIn('chronicle-ios', submodules)
                with tarfile.open(fileobj=output, mode='w') as source:
                    source.add(root / 'chronicle-server', arcname='chronicle-server')
                    source.add(root / 'CHANGELOG.md', arcname='CHANGELOG.md')
            class GuardPassed(Exception):
                pass
            def after_guard(*_args, **_kwargs):
                raise GuardPassed()
            args = SimpleNamespace(version=release.UPGRADE_FROM_MINIMUM, source_revision='a' * 40,
                                   output_dir=root / 'out')
            build_env = dict(ROOT=root, parse_args=lambda: args, require_committed_release_source=lambda *_: None,
                             tracked_source_paths=lambda *_: set(), validate_inputs=lambda *_: {}, archive_source=archive)
            with patch.dict(builder['main'].__globals__, build_env):
                # Stop at the next build stage after the real migration guard accepts the control.
                with patch.dict(builder['main'].__globals__, dict(copy_bundle_inputs=after_guard)):
                    with self.assertRaises(GuardPassed):
                        builder['main']()
                baseline.write_text('SELECT 2;\n')
                for gate in (builder['main'],):
                    with self.subTest(gate=gate.__module__), self.assertRaisesRegex(ValueError, 'published migration changed'):
                        gate()


class SignedDownloadTests(unittest.TestCase):
    """The installed key, the signature and the checksum are verified before anything is extracted or run."""

    def setUp(self):
        from update_fixture import prepare_update
        from chronicle_ops.update import release_assets
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.root = Path(folder.name)
        self.version = next_version(release.UPGRADE_FROM_MINIMUM)
        self.fixture = prepare_update(self.root, self.version)
        self.catalog = json.loads((self.root / 'http/latest.json').read_text())[0]
        self.assets = release_assets(self.catalog, f'chronicle-selfhost-{self.version}.tar.gz')
        self.archive = self.root / 'http' / self.assets.archive.name

    def apply(self, host=None, executed=None):
        import shutil
        from chronicle_ops.envfile import read_env
        from chronicle_ops.update import apply_update
        host = host or self.fixture.host
        def download(assets, destination):
            for asset in assets.all():
                shutil.copy2(self.root / 'http' / asset.name, destination / asset.name)
        with patch('chronicle_ops.update.download_assets', side_effect=download), \
             patch('chronicle_ops.update.require_storage'), \
             patch('chronicle_ops.update.exec_candidate', side_effect=executed or AssertionError('candidate executed')):
            apply_update(host, read_env(host / '.env'), self.assets, self.version, release.UPGRADE_FROM_MINIMUM)

    def sign(self, key='fixture-signing-key'):
        import subprocess
        from chronicle_ops.release import RELEASE_SIGNER
        self.fixture.signature.unlink()
        subprocess.run(['ssh-keygen', '-Y', 'sign', '-n', RELEASE_SIGNER, '-f', str(self.root / key),
                        str(self.fixture.checksum)], check=True, capture_output=True)

    def assert_nothing_staged(self):
        from chronicle_ops.release import UPDATE_DIRECTORY_PREFIX
        from chronicle_ops.update import HANDOFF_FILE
        self.assertFalse((self.root / 'deployment-state' / HANDOFF_FILE).exists())
        self.assertEqual([], list(self.root.rglob(UPDATE_DIRECTORY_PREFIX + '*')))

    def test_tampered_or_foreign_downloads_are_refused_before_extraction(self):
        import hashlib
        checksum = self.fixture.checksum.read_text()
        key = (self.fixture.host / 'release-signing.pub').read_text()
        def foreign():
            self.sign('other-signing-key')
        def two_entries():
            self.fixture.checksum.write_text(checksum + hashlib.sha256(b'other').hexdigest() + '  other.tar.gz\n')
            self.sign()
        def tampered_archive():
            with self.archive.open('ab') as archive:
                archive.write(b'appended after signing')
        def missing_key():
            (self.fixture.host / 'release-signing.pub').unlink()
        def rsa_key():
            (self.fixture.host / 'release-signing.pub').write_text('ssh-rsa AAAAB3NzaC1yc2E fixture\n')
        def two_keys():
            (self.fixture.host / 'release-signing.pub').write_text(key.strip() + '\n' + key)
        for change, message in ((foreign, 'invalid release signature; nothing extracted or executed'),
                                (two_entries, 'bad checksum file: expected one SHA-256 entry for the release archive'),
                                (tampered_archive, 'bad checksum: release archive verification failed; nothing extracted'),
                                (missing_key, 'missing installed release-signing.pub'),
                                (rsa_key, 'invalid installed release-signing.pub'),
                                (two_keys, 'invalid installed release-signing.pub')):
            original = {path: path.read_bytes() for path in (self.archive, self.fixture.checksum, self.fixture.signature,
                                                             self.fixture.host / 'release-signing.pub')}
            change()
            with self.subTest(change.__name__):
                with self.assertRaisesRegex(ValueError, message):
                    self.apply()
                self.assert_nothing_staged()
            for path, content in original.items():
                path.write_bytes(content)

    def test_repair_from_an_updated_release_stages_beside_it_with_a_durable_handoff(self):
        from chronicle_ops.update import HANDOFF_FILE
        wrapper = self.root / 'releases' / 'chronicle-update-previous'
        wrapper.mkdir()
        self.fixture.release.rename(wrapper / self.fixture.release.name)
        host = wrapper / self.fixture.release.name / 'selfhost'
        state = self.root / 'deployment-state'
        staged = {}
        def exec_candidate(candidate, previous):
            staged.update(candidate=candidate, previous=previous,
                          handoff=json.loads((state / HANDOFF_FILE).read_text()),
                          launcher=(candidate / 'chronicle').is_file())
            raise OSError('exec fixture')
        with self.assertRaisesRegex(OSError, 'exec fixture'):
            self.apply(host, exec_candidate)
        self.assertEqual(self.root / 'releases', staged['candidate'].parents[2])
        self.assertEqual(f'chronicle-selfhost-{self.version}', staged['candidate'].parent.name)
        self.assertEqual((host, True), (staged['previous'], staged['launcher']))
        self.assertEqual(dict(previous=str(host), owner=str(staged['candidate'])), staged['handoff'])
        self.assertFalse((state / HANDOFF_FILE).exists())
        self.assertEqual(['chronicle-update-previous'], [path.name for path in (self.root / 'releases').iterdir()])

    def test_update_command_verifies_the_signed_bundle_and_hands_off_to_its_launcher(self):
        import io
        import subprocess
        from chronicle_ops.__main__ import run_cli
        from chronicle_ops.release import UPDATE_DIRECTORY_PREFIX
        from chronicle_ops.update import HANDOFF_FILE
        (self.fixture.release / 'release-manifest.json').write_text(json.dumps(dict(release_version=release.UPGRADE_FROM_MINIMUM)))
        state = self.root / 'deployment-state'
        def curl(url, output=subprocess.PIPE, max_bytes=None):
            if output is subprocess.PIPE:
                return json.dumps([self.catalog]).encode()
            output.write((self.root / 'http' / url.rsplit('/', 1)[1]).read_bytes())
        handed = []
        def execv(program, argv):
            handed.append((program, argv, json.loads((state / HANDOFF_FILE).read_text()), os.access(program, os.X_OK)))
            raise OSError('exec fixture')
        origin = Path.cwd()
        try:
            os.chdir(self.fixture.host)
            with patch('chronicle_ops.update.curl', side_effect=curl), patch('chronicle_ops.update.require_storage'), \
                 patch('chronicle_ops.release.compose_projects', return_value=[]), \
                 patch('chronicle_ops.update.os.execv', side_effect=execv), patch('chronicle_ops.__main__.signal.signal'), \
                 patch('sys.stdout', new_callable=io.StringIO) as output, patch('sys.stderr', new_callable=io.StringIO) as errors:
                status = run_cli(['update'])
        finally:
            os.chdir(origin)
        self.assertEqual((1, f'Current: {release.UPGRADE_FROM_MINIMUM}; selected: {self.version}\n',
                          'error: update failed: exec fixture\n'), (status, output.getvalue(), errors.getvalue()))
        [(launcher, argv, handoff, executable)] = handed
        self.assertEqual([launcher, 'update', '--apply-from', str(self.fixture.host)], argv)
        self.assertEqual(dict(previous=str(self.fixture.host), owner=str(Path(launcher).parent)), handoff)
        self.assertTrue(launcher.endswith(f'/chronicle-selfhost-{self.version}/selfhost/chronicle') and executable)
        self.assertFalse((state / HANDOFF_FILE).exists())
        self.assertEqual([], list(self.root.rglob(UPDATE_DIRECTORY_PREFIX + '*')))

    def test_unavailable_or_unlisted_signature_stops_the_download(self):
        import subprocess
        from chronicle_ops.update import download_assets, release_assets
        signature = self.assets.signature
        for failed, expected in ((signature.url, ValueError), (self.assets.checksum.url, subprocess.CalledProcessError)):
            def curl(url, *_args, **_kwargs):
                if url == failed:
                    raise subprocess.CalledProcessError(22, 'curl')
            with self.subTest(failed=failed), tempfile.TemporaryDirectory(dir=self.root) as folder, \
                 patch('chronicle_ops.update.curl', side_effect=curl):
                with self.assertRaises(expected) as caught:
                    download_assets(self.assets, Path(folder))
                if expected is ValueError:
                    self.assertEqual('missing or unavailable release signature; nothing extracted or executed', str(caught.exception))
        for assets, message in (([a for a in self.catalog['assets'] if a['name'] != signature.name],
                                 f'missing or ambiguous release signature asset: {signature.name}'),
                                (self.catalog['assets'] + [dict(name=self.assets.archive.name, browser_download_url='https://mirror.example/x')],
                                 f'missing or ambiguous release asset: {self.assets.archive.name}')):
            with self.subTest(message), self.assertRaisesRegex(ValueError, message):
                release_assets(dict(self.catalog, assets=assets), self.assets.archive.name)


class CandidateCleanupTests(unittest.TestCase):
    def test_verified_update_survives_an_incomplete_release_cleanup(self):
        import io
        from chronicle_ops.__main__ import run_cli
        from chronicle_ops.update import HANDOFF_FILE
        from chronicle_ops.release import UPDATE_DIRECTORY_PREFIX
        from chronicle_ops.receipts import write_json
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ):
            root = Path(directory)
            previous, state = root / 'previous', root / 'state'
            candidate = root / (UPDATE_DIRECTORY_PREFIX + 'fixture') / 'bundle/selfhost'
            for path in (previous, state, candidate):
                path.mkdir(parents=True)
            (previous / '.env').write_text('CHRONICLE_STATE_DIR=' + str(state) + '\n')
            (previous / '.env').chmod(0o600)
            write_json(state / HANDOFF_FILE, dict(previous=str(previous), owner=str(candidate)))
            origin = Path.cwd()
            try:
                os.chdir(candidate)
                with patch('chronicle_ops.upgrade.recover_update', return_value=False), \
                     patch('chronicle_ops.upgrade.upgrade', return_value=0), \
                     patch('chronicle_ops.release.cleanup_releases', side_effect=OSError('Device or resource busy')), \
                     patch('chronicle_ops.__main__.signal.signal'), \
                     patch('sys.stderr', new_callable=io.StringIO) as errors:
                    self.assertEqual(0, run_cli(['update', '--apply-from', str(previous)]))
                self.assertIn('release cleanup incomplete: Device or resource busy; retry ./chronicle cleanup', errors.getvalue())
                self.assertTrue(candidate.is_dir())
                self.assertFalse((state / HANDOFF_FILE).exists())
            finally:
                os.chdir(origin)


class FakeStack:
    """Docker as the upgrade sees it: Compose for each release directory and the docker CLI."""

    def __init__(self):
        self.calls, self.postgres, self.health = [], 'postgres-1', 'healthy'
        self.server_version, self.image_version = '180001', 'postgres (PostgreSQL) 18.1'
        self.running, self.exited, self.logs = ['postgres'], '', ''
        self.failures = {}

    def compose(self, directory, _project, _names, *args, **_kwargs):
        self.calls.append((Path(directory).parent.name, args))
        failure = self.failures.get(args[:2]) or self.failures.get(args[:1])
        if failure:
            raise failure
        if args == ('ps', '-q', 'postgres'):
            output = self.postgres
        elif args == ('config', '--format', 'json'):
            output = json.dumps({'services': {'postgres': {'image': 'fixture/postgres@sha256:' + 'b' * 64}}})
        elif args == ('config', '--services'):
            output = 'postgres\nbackend\nweb\nmigrate\nca-export\n'
        elif args[:3] == ('ps', '--status', 'running'):
            output = '\n'.join(self.running)
        elif args[:2] == ('ps', '-a'):
            output = self.exited
        elif args[:1] == ('logs',):
            output = self.logs
        else:
            output = ''
        return SimpleNamespace(returncode=0, stdout=output)

    def run(self, args, **_kwargs):
        import subprocess
        self.calls.append(('docker', tuple(args)))
        failure = self.failures.get((args[0],))
        if failure:
            raise failure
        output = {'inspect': self.health, 'run': self.image_version}.get(args[1], '') if args[0] == 'docker' else ''
        return subprocess.CompletedProcess(args, 0, output)

    def started(self, release):
        return any(call == (release, args) for call in self.calls for args in [call[1]] if args[:1] == ('up',))


class UpgradeTransactionTests(unittest.TestCase):
    """`./chronicle update` after the handoff: prepare, quiesced dump, start, commit or automatic recovery."""

    def setUp(self):
        import shutil
        from test_release import complete_manifest_fixture
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        root = Path(folder.name).resolve()
        self.old_version, self.new_version = release.UPGRADE_FROM_MINIMUM, next_version(release.UPGRADE_FROM_MINIMUM)
        old_bundle = root / 'releases' / f'chronicle-selfhost-{self.old_version}'
        new_bundle = root / 'releases' / 'chronicle-update-fixture' / f'chronicle-selfhost-{self.new_version}'
        for bundle, version in ((old_bundle, self.old_version), (new_bundle, self.new_version)):
            (bundle / 'selfhost').mkdir(parents=True)
            (bundle / 'release-manifest.json').write_text(json.dumps(dict(release_version=version)))
            (bundle / 'CHANGELOG.md').write_text(f'## [{self.new_version}]\n- candidate note\n\n## [{self.old_version}]\n- installed note\n')
            shutil.copytree(Path(__file__).resolve().parents[2] / 'selfhost/overlays', bundle / 'selfhost/overlays')
            complete_manifest_fixture(bundle)
        self.previous, self.candidate = old_bundle / 'selfhost', new_bundle / 'selfhost'
        self.state = root / 'state'
        (self.state / 'backups').mkdir(parents=True)
        (self.previous / '.env').write_text(
            f"COMPOSE_PROJECT_NAME=fixture\nCHRONICLE_STATE_DIR='{self.state}'\nRELEASE_VERSION={self.old_version}\n"
            "COMPOSE_FILE=docker-compose.yml:overlays/mode-local-https.yml:overlays/backups.yml\n"
            "DASHBOARD_PASSWORD_HASH='$2b$12$fixturefixturefixturefixtu'\n")
        (self.previous / '.env').chmod(0o600)
        origin = Path.cwd()
        self.addCleanup(os.chdir, origin)
        os.chdir(self.candidate)
        self.stack = FakeStack()
        self.dumps = []
        self.rollbacks = []
        self.installed = []
        for active in (patch.dict(os.environ, CHRONICLE_RECONCILE_ENABLED='false'),
                       patch('chronicle_ops.upgrade.compose_release', side_effect=self.stack.compose),
                       patch('chronicle_ops.upgrade.run', side_effect=self.stack.run),
                       patch('chronicle_ops.upgrade.postgres_sql', side_effect=lambda *_: self.stack.server_version),
                       patch('chronicle_ops.upgrade.require_storage'),
                       patch('chronicle_ops.upgrade.rollback_dump', side_effect=self.dump),
                       patch('chronicle_ops.release.compose_projects', return_value=[]),
                       patch('chronicle_ops.reconcile.install', side_effect=lambda *args: self.installed.append(args)),
                       patch('chronicle_ops.restore.rollback', side_effect=self.rollback)):
            active.start()
            self.addCleanup(active.stop)
        self.dump_result = 'ok'
        self.rollback_status = 0

    def dump(self, command, partial, **_kwargs):
        stopped = [args for _, args in self.stack.calls if args[:1] == ('stop',)]
        self.dumps.append((command, stopped))
        partial.write_bytes(b'partial dump')
        if self.dump_result != 'ok':
            raise ValueError('database dump failed')
        return 'c' * 64

    def rollback(self, previous, dump, digest, assume_yes):
        self.rollbacks.append((previous, dump, digest, assume_yes))
        return self.rollback_status

    def upgrade(self):
        import io
        from chronicle_ops.upgrade import upgrade
        with patch('sys.stdout', new_callable=io.StringIO) as output, patch('sys.stderr', new_callable=io.StringIO) as errors:
            status = upgrade(self.previous, self.candidate)
        return status, output.getvalue(), errors.getvalue()

    def receipt(self):
        from chronicle_ops.receipts import OPERATOR_RECEIPTS_DIR
        [path] = (self.state / OPERATOR_RECEIPTS_DIR / 'operations').glob('*-upgrade-*.json')
        data = json.loads(path.read_text())
        return data['outcome'], data['failureCategory']

    def assert_previous_running_again(self):
        from chronicle_ops.ingress import fence_path
        from chronicle_ops.reconcile import UPGRADE_LOCK
        self.assertFalse((self.state / UPGRADE_LOCK).exists())
        self.assertFalse(fence_path(self.state).exists())

    def test_verified_update_dumps_after_writers_stop_then_commits_the_candidate(self):
        from chronicle_ops.envfile import read_env, value
        from chronicle_ops.release import CERTIFICATE_MARKER
        from chronicle_ops.ingress import fence_path
        from chronicle_ops.reconcile import UPGRADE_LOCK
        status, output, _ = self.upgrade()
        self.assertEqual(0, status, output)
        self.assertIn(f'## [{self.new_version}]\n- candidate note', output)
        self.assertTrue(output.endswith(f'Update verified. Run future commands from: {self.candidate}\n'))
        [(_, stopped)] = self.dumps
        self.assertEqual([('stop', 'backend', 'web', 'migrate', 'ca-export')], stopped)
        [backup] = (self.state / 'backups').glob('pre-upgrade-*.sql.gz')
        self.assertEqual(b'partial dump', backup.read_bytes())
        self.assertEqual([], list((self.state / 'backups').glob('*.partial')))
        self.assertEqual(self.new_version, value(read_env(self.candidate / '.env'), 'RELEASE_VERSION'))
        self.assertEqual(self.new_version, os.environ['CHRONICLE_OPS_VERSION'])
        self.assertTrue(self.stack.started(f'chronicle-selfhost-{self.new_version}'))
        self.assertTrue((self.state / CERTIFICATE_MARKER).is_file())
        self.assertEqual([(self.candidate / 'chronicle', self.state, 'fixture')], self.installed)
        self.assertFalse((self.state / UPGRADE_LOCK).exists())
        self.assertFalse(fence_path(self.state).exists())
        self.assertEqual(('success', 'none'), self.receipt())

    def test_unsafe_starting_points_are_refused_before_the_previous_release_stops(self):
        import subprocess
        def candidate_settings():
            (self.candidate / '.env').write_text('COMPOSE_PROJECT_NAME=fixture\n')
        def postgres_stopped():
            self.stack.postgres = ''
        def postgres_unhealthy():
            self.stack.health = 'starting'
        def major_change():
            self.stack.server_version = '170005'
        def unparsable_image():
            self.stack.image_version = 'pg_ctl version unknown'
        def subnet_conflict():
            self.stack.failures[('python3',)] = subprocess.CalledProcessError(1, 'network-subnet.py check')
        for change, message in (
                (candidate_settings, 'new release file inventory is not exact in '),
                (postgres_stopped, 'previous PostgreSQL container is not running'),
                (postgres_unhealthy, 'previous PostgreSQL is not healthy'),
                (major_change, 'automatic update refuses a PostgreSQL major change; see docs/UPGRADE-ROLLBACK.md'),
                (unparsable_image, 'could not parse the PostgreSQL version in fixture/postgres@sha256:'),
                (subnet_conflict, "Command 'network-subnet.py check' returned non-zero exit status 1.")):
            with self.subTest(change.__name__):
                self.setUp()
                change()
                status, output, _ = self.upgrade()
                self.assertEqual(1, status)
                self.assertIn('Update failed: ' + message, output)
                self.assertEqual([], [args for release_name, args in self.stack.calls
                                      if release_name == f'chronicle-selfhost-{self.old_version}' and args[:1] in (('stop',), ('down',))])
                self.assertEqual([], self.dumps)
                self.assert_previous_running_again()
                self.assertEqual(('failure', 'upgrade_failed'), self.receipt())

    def test_failed_quiesce_or_dump_restarts_the_previous_release_without_a_backup(self):
        for problem, message in (('writers', 'application writers did not stop; database dump was not started'),
                                 ('backups', 'unsafe or missing backups directory'),
                                 ('dump', 'database dump failed')):
            with self.subTest(problem):
                self.setUp()
                if problem == 'writers':
                    self.stack.running = ['postgres', 'backend']
                elif problem == 'backups':
                    (self.state / 'backups').rename(self.state / 'elsewhere')
                    (self.state / 'backups').symlink_to(self.state / 'elsewhere')
                else:
                    self.dump_result = 'fail'
                status, output, _ = self.upgrade()
                self.assertEqual(1, status)
                self.assertIn('Update failed: ' + message, output)
                self.assertIn(f'Previous release recovered with its data: {self.previous}', output)
                self.assertTrue(self.stack.started(f'chronicle-selfhost-{self.old_version}'))
                self.assertEqual([], list(self.state.glob('backups/*.sql.gz*')) + list(self.state.glob('elsewhere/*')))
                self.assertEqual(len(self.dumps), int(problem == 'dump'))
                self.assert_previous_running_again()
                self.assertEqual([], self.rollbacks)

    def test_failed_migration_keeps_its_log_and_rolls_back_to_the_pre_update_dump(self):
        import subprocess
        from chronicle_ops.receipts import OPERATOR_RECEIPTS_DIR
        from chronicle_ops.reconcile import UPGRADE_LOCK
        for restored in (0, 1):
            with self.subTest(rollback_status=restored):
                self.setUp()
                self.rollback_status = restored
                self.stack.failures[('up',)] = subprocess.CalledProcessError(1, 'docker compose up')
                self.stack.exited = 'migrate 1\ndb-init 0\n'
                self.stack.logs = '2026-10-31T12:00:00Z INFO Flyway starting\nERROR Migration V9__survey.sql failed\n'
                status, output, _ = self.upgrade()
                self.assertEqual(1, status)
                self.assertIn('migrate failed:\nERROR Migration V9__survey.sql failed\nFull migrate log: ', output)
                self.assertNotIn('Flyway starting', output)
                [log] = (self.state / OPERATOR_RECEIPTS_DIR / 'failed-services').glob('*-migrate.log')
                self.assertEqual(self.stack.logs, log.read_text())
                [backup] = (self.state / 'backups').glob('pre-upgrade-*.sql.gz')
                self.assertEqual([(self.previous, '/backups/' + backup.name, 'c' * 64, True)], self.rollbacks)
                self.assertEqual(('failure', 'migration_failed'), self.receipt())
                if restored == 0:
                    self.assertIn(f'Previous release recovered with its data: {self.previous}', output)
                else:
                    self.assertIn('Automatic rollback incomplete: automatic rollback failed; retain recovery state. '
                                  'See docs/UPGRADE-ROLLBACK.md', output)
                    self.assertTrue((self.state / UPGRADE_LOCK).is_dir())

    def test_unreadable_service_status_still_rolls_back_and_reports_the_update_failure(self):
        import subprocess
        self.stack.failures[('up',)] = subprocess.CalledProcessError(1, 'docker compose up')
        self.stack.failures[('ps', '-a')] = subprocess.CalledProcessError(1, 'docker compose ps')
        status, output, errors = self.upgrade()
        self.assertEqual(1, status)
        self.assertIn("could not save the failed services' logs: Command 'docker compose ps' returned non-zero exit status 1.", errors)
        self.assertEqual(('failure', 'upgrade_failed'), self.receipt())
        [backup] = (self.state / 'backups').glob('pre-upgrade-*.sql.gz')
        self.assertEqual([(self.previous, '/backups/' + backup.name, 'c' * 64, True)], self.rollbacks)
        self.assertIn(f'Previous release recovered with its data: {self.previous}', output)

    def test_restart_after_a_committed_update_finishes_on_the_candidate(self):
        import io
        from chronicle_ops.receipts import write_json
        from chronicle_ops.reconcile import RECOVERY_FILE, STOP_MARKER, UPGRADE_LOCK
        from chronicle_ops.ingress import close_ingress, fence_path
        from chronicle_ops.upgrade import COMMITTED, recover_update
        marker = self.state / UPGRADE_LOCK
        marker.mkdir()
        write_json(marker / RECOVERY_FILE, dict(previous=str(self.previous), owner=str(self.candidate),
                                                phase=COMMITTED, settings_archive='settings.tar'))
        stale = marker.with_name(marker.name + '.completed')
        (stale / 'leftover').mkdir(parents=True)
        (self.state / STOP_MARKER).write_text('')
        close_ingress(self.state)
        with patch('sys.stdout', new_callable=io.StringIO) as output:
            self.assertTrue(recover_update(self.state))
        self.assertEqual(f'Committed release recovered: {self.candidate}\n', output.getvalue())
        self.assertIn(('docker', (str(self.candidate / 'chronicle'), 'verify')), self.stack.calls)
        self.assertEqual(self.candidate, Path.cwd())
        self.assertFalse(fence_path(self.state).exists())
        self.assertFalse((self.state / STOP_MARKER).exists())
        self.assertFalse(marker.exists())
        self.assertFalse(stale.exists())
        self.assertEqual([], self.rollbacks)
