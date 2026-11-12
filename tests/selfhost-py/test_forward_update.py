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
            'POSTGRES_PASSWORD': 'fixture-owner', 'POSTGRES_APP_PASSWORD': 'fixture-app',
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


class PostCommitMajorRollbackTests(unittest.TestCase):
    """./chronicle rollback after a committed PostgreSQL major update: the previous release starts
    on its own (older-major) volumes, so the dump must be restored into those, not the current ones."""

    def test_the_dump_is_restored_into_the_volumes_the_previous_release_starts_on(self):
        import io
        from types import SimpleNamespace
        from chronicle_ops.restore import rollback
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            old, current, state = root / 'old/selfhost', root / 'new/selfhost', root / 'state'
            for folder in (old / 'chronicle_ops', current, state / 'backups'):
                folder.mkdir(parents=True)
            (old / 'chronicle_ops/__main__.py').touch()
            (old / '.env.example').write_text('COMPOSE_PROJECT_NAME=fixture\nCOMPOSE_FILE=\nCHRONICLE_STATE_DIR=\n')
            for folder in (old, current):
                (folder / '.env').write_text(f"COMPOSE_PROJECT_NAME=fixture\nCHRONICLE_STATE_DIR='{state}'\n"
                                             'COMPOSE_FILE=docker-compose.yml:overlays/mode-local-https.yml\n')
                (folder / '.env').chmod(0o600)
            def config(directory, _project, _names, *args, **_kwargs):
                suffix = '_18' if Path(directory) == current else ''
                return SimpleNamespace(returncode=0, stdout=json.dumps({'services': {'postgres': {'volumes': [
                    {'type': 'volume', 'source': 'postgres_data' + suffix, 'target': '/data/db'}]}},
                    'volumes': {'postgres_data' + suffix: {'name': 'fixture_postgres_data' + suffix}}}))
            events = []
            class FakeRestore:
                def __init__(fake, *args, **kwargs):
                    fake.lock = state / 'no-restore-lock'
                def execute(fake):
                    events.append(('restore', Path.cwd(), os.environ.get('COMPOSE_FILE')))
                    return 0
            origin = Path.cwd()
            os.chdir(current)
            self.addCleanup(os.chdir, origin)
            with patch.dict(os.environ), \
                 patch('chronicle_ops.release.compose_release', side_effect=config), \
                 patch('chronicle_ops.release.require_current_owner'), \
                 patch('chronicle_ops.restore.announce_discarded_data'), \
                 patch('chronicle_ops.restore.Restore', FakeRestore), \
                 patch('chronicle_ops.restore.compose', side_effect=lambda *args, **_: events.append(('compose', *args))), \
                 patch('chronicle_ops.reconcile.install'), \
                 patch('chronicle_ops.upgrade.start_release', side_effect=lambda directory, *_: events.append(('start', directory))), \
                 patch('chronicle_ops.upgrade.verify_release'), \
                 patch('sys.stdout', new_callable=io.StringIO):
                self.assertEqual(0, rollback(str(old), '/backups/pre-upgrade-1.sql.gz', 'c' * 64, True))
            order = [event[0] for event in events]
            self.assertEqual(['compose', 'restore', 'start'], order)
            self.assertEqual(('restore', old, 'docker-compose.yml:overlays/mode-local-https.yml'), events[1])
            self.assertEqual(('start', old), events[2])


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
                with patch('chronicle_ops.upgrade.compose_release', return_value=SimpleNamespace(returncode=0, stdout='postgres\nbackend\nweb\nmigrate\nca-export')) as dc, \
                     patch('chronicle_ops.upgrade.run', return_value=SimpleNamespace(returncode=0, stdout='')):
                    self.assertTrue(recover_update(state))
                startup = next(call.args for call in dc.call_args_list if 'up' in call.args)
                self.assertNotIn('ca-export', startup)
                self.assertTrue(any('ca-export' in call.args for call in dc.call_args_list))
                self.assertFalse(marker.exists())
                self.assertFalse((candidate / '.env').exists())
            finally:
                os.chdir(origin)


class InterruptedUpdateRerunTests(unittest.TestCase):
    """The operator only ever runs ./chronicle update: one rerun after a killed update must finish it."""

    def rerun(self, phase, recovered, **journal):
        from chronicle_ops.update import apply_candidate
        from chronicle_ops.upgrade import UPGRADE_LOCK
        from chronicle_ops.reconcile import RECOVERY_FILE
        from chronicle_ops.release import UPDATE_DIRECTORY_PREFIX
        from chronicle_ops.receipts import write_json
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        root = Path(directory.name).resolve()
        previous, state = root / 'previous', root / 'state'
        candidate = root / (UPDATE_DIRECTORY_PREFIX + 'fixture') / 'bundle/selfhost'
        for path in (previous, state, candidate):
            path.mkdir(parents=True)
        (previous / '.env').write_text('CHRONICLE_STATE_DIR=' + str(state) + '\n')
        (previous / '.env').chmod(0o600)
        marker = state / UPGRADE_LOCK
        marker.mkdir()
        write_json(marker / RECOVERY_FILE, dict(previous=str(previous), owner=str(candidate), phase=phase, **journal))
        def recover(state_dir):  # the real recovery clears the journal and serves `recovered`
            (Path(state_dir) / UPGRADE_LOCK / RECOVERY_FILE).unlink()
            Path(state_dir, UPGRADE_LOCK).rmdir()
            return {'previous': previous, 'candidate': candidate}[recovered]
        calls = []
        def upgrade(old, new):
            calls.append((Path(old).resolve(), Path(new).resolve(), Path.cwd().resolve()))
            return 0
        origin = Path.cwd()
        self.addCleanup(os.chdir, origin)
        os.chdir(candidate)
        with patch('chronicle_ops.upgrade.recover_update', side_effect=recover), \
             patch('chronicle_ops.upgrade.upgrade', side_effect=upgrade), \
             patch('chronicle_ops.release.current_owner', return_value=candidate), \
             patch('chronicle_ops.release.cleanup_releases'):
            status = apply_candidate(previous)
        return status, calls, previous, candidate

    def test_rerun_after_a_kill_before_the_commit_recovers_then_updates(self):
        from chronicle_ops.upgrade import PREPARED
        from chronicle_ops.reconcile import RECOVERY_PHASE
        for phase in (PREPARED, RECOVERY_PHASE):
            with self.subTest(phase=phase):
                status, calls, previous, candidate = self.rerun(phase, 'previous')
                self.assertEqual(0, status)
                self.assertEqual([(previous, candidate, candidate)], calls)

    def test_rerun_after_a_kill_after_the_commit_only_finishes_it(self):
        from chronicle_ops.upgrade import COMMITTED
        status, calls, _, _ = self.rerun(COMMITTED, 'candidate')
        self.assertEqual((0, []), (status, calls))

    def test_a_rollback_of_a_failed_update_is_not_retried(self):
        # The update already failed (its verification, say) and was rolling back when it died: the
        # recovery finishes the rollback and reports the failure instead of retrying the same release.
        from chronicle_ops.upgrade import PREPARED
        from chronicle_ops.restore import ROLLBACK_PHASES
        for phase in (PREPARED, ROLLBACK_PHASES[0], ROLLBACK_PHASES[-1]):
            with self.subTest(phase=phase):
                status, calls, _, _ = self.rerun(phase, 'previous', failed=True)
                self.assertEqual((1, []), (status, calls))

    def test_a_killed_recovery_of_an_interrupted_update_still_carries_on(self):
        # The first rerun was itself killed mid-rollback: the next one finishes it and updates.
        from chronicle_ops.restore import ROLLBACK_PHASES
        status, calls, previous, candidate = self.rerun(ROLLBACK_PHASES[1], 'previous')
        self.assertEqual(0, status)
        self.assertEqual([(previous, candidate, candidate)], calls)

    def test_upgrade_marks_its_journal_failed_only_for_a_real_failure(self):
        from chronicle_ops import upgrade as module
        from chronicle_ops.upgrade import Interrupted, PREPARED, UPGRADE_LOCK, upgrade
        from chronicle_ops.reconcile import RECOVERY_FILE
        from chronicle_ops.receipts import write_json
        unwritable = OSError('No space left on device')
        cases = ((ValueError('candidate verify failed'), True, None), (Interrupted(15), False, None),
                 (ValueError('candidate verify failed'), False, unwritable))  # the rollback still runs
        for error, failed, mark_error in cases:
            with self.subTest(error=type(error).__name__, mark_error=mark_error), tempfile.TemporaryDirectory() as folder:
                root = Path(folder).resolve()
                previous, candidate, state = root / 'previous', root / 'candidate', root / 'state'
                for path in (previous, candidate, state):
                    path.mkdir()
                (previous / '.env').write_text('CHRONICLE_STATE_DIR=' + str(state) + '\n')
                (previous / '.env').chmod(0o600)
                seen = []
                class Failing:
                    failed_services = []
                    def __init__(self, *_):
                        (state / UPGRADE_LOCK).mkdir()
                        write_json(state / UPGRADE_LOCK / RECOVERY_FILE,
                                   dict(previous=str(previous), owner=str(candidate), phase=PREPARED))
                    def prepare(self):
                        raise error
                def recover(state_dir):
                    seen.append(json.loads((Path(state_dir) / UPGRADE_LOCK / RECOVERY_FILE).read_text()))
                    return previous
                origin = Path.cwd()
                self.addCleanup(os.chdir, origin)
                with patch.object(module, 'Upgrade', Failing), \
                     patch.object(module, 'require_current_owner'), \
                     patch.object(module, 'recover_update', side_effect=recover), \
                     patch.object(module, 'finish_operation'), \
                     patch.object(module, 'mark_failed', side_effect=mark_error) if mark_error else patch.dict({}), \
                     patch.dict(os.environ):
                    status = upgrade(previous, candidate)
                self.assertNotEqual(0, status)
                self.assertEqual(1, len(seen))
                self.assertEqual(failed, seen[0].get('failed', False))


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
            # publish-images.sh --promote goes through the module's command line: with --check while the
            # release is still a draft (the same refusals, nothing written), then without it once the
            # release is public.
            command = [sys.executable, '-s', '-m', 'chronicle_ops.migrations', str(root), str(manifest)]
            check = [*command[:4], '--check', *command[4:]]
            environment = dict(os.environ, PYTHONDONTWRITEBYTECODE='1', PYTHONPATH=str(Path(__file__).resolve().parents[2] / 'selfhost'))
            self.assertEqual(0, subprocess.run(check, env=environment, capture_output=True, timeout=30).returncode)
            self.assertFalse((root / MIGRATION_LEDGER).exists())
            self.assertEqual(0, subprocess.run(command, env=environment, capture_output=True, timeout=30).returncode)
            self.assertEqual({version: migration_hashes(root)}, published_migrations(root))
            (migrations / 'V2__add_index.sql').write_text('SELECT 2;\n')
            manifest.write_text(json.dumps({'release_version': version, release.MIGRATIONS_KEY: migration_hashes(root)}))
            for refused in (check, command):
                replaced = subprocess.run(refused, env=environment, capture_output=True, text=True, timeout=30)
                self.assertEqual(1, replaced.returncode)
                # One line an operator can read, not a traceback.
                self.assertEqual('error: ValueError: publication ledger cannot replace a release inventory\n', replaced.stderr)
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
            self.assertEqual([], staged_releases(fixture.root / 'releases'))

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
                             tracked_source_paths=lambda *_: set(), validate_inputs=lambda *_: {}, archive_source=archive,
                             require_database_volume_continuity=lambda *_: None)
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
        from chronicle_ops.update import HANDOFF_FILE
        self.assertFalse((self.root / 'deployment-state' / HANDOFF_FILE).exists())
        self.assertEqual([], staged_releases(self.root))

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
        self.assertEqual(self.root / 'releases' / release.RELEASES_DIRECTORY, staged['candidate'].parents[2])
        self.assertEqual(f'chronicle-selfhost-{self.version}', staged['candidate'].parent.name)
        self.assertEqual((host, True), (staged['previous'], staged['launcher']))
        self.assertEqual(dict(previous=str(host), owner=str(staged['candidate'])), staged['handoff'])
        self.assertFalse((state / HANDOFF_FILE).exists())
        self.assertEqual(['chronicle-update-previous'], [path.name for path in (self.root / 'releases').iterdir()
                                                         if path.name != release.RELEASES_DIRECTORY])
        self.assertEqual([], list((self.root / 'releases' / release.RELEASES_DIRECTORY).iterdir()))

    def test_update_command_verifies_the_signed_bundle_and_hands_off_to_its_launcher(self):
        import io
        import subprocess
        from chronicle_ops.__main__ import run_cli
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
        self.assertEqual([], staged_releases(self.root))

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


def staged_releases(root):
    """Release directories an update left staged: 2026.11.2's chronicle-update-* and chronicle-releases/<version>."""
    root = Path(root)
    return sorted([*root.rglob(release.UPDATE_DIRECTORY_PREFIX + '*'), *root.rglob(release.RELEASES_DIRECTORY + '/*')])


class FakeStack:
    """Docker as the upgrade sees it: Compose for each release directory and the docker CLI."""

    def __init__(self):
        self.calls, self.postgres, self.health = [], 'postgres-1', 'healthy'
        self.server_version, self.image_version = '180001', 'postgres (PostgreSQL) 18.1'
        self.running, self.exited, self.logs = ['postgres'], '', ''
        self.failures = {}
        self.host = dict(engine='29.8.2', containerd='2.2.10', runc='1.3.6', kernel='6.12.95')
        self.volume_suffix, self.previous_release, self.database_bytes = '', None, '1048576'
        # ./chronicle verify: FAIL lines the previous release prints, and checks the candidate fails.
        self.previous_failures, self.candidate_failures, self.verifies = [], [], []
        self.previous_verify_error = None  # raised by the previous release's verify, e.g. a timeout
        self.previous_dir = None  # an absolute <previous>/chronicle verify is the previous release's
        self.core_prefix = '10.252.4'  # what network-subnet.py select-core answers on this host
        # Operator Compose files: the services each adds, and the database volume suffix it sets.
        self.overlay_services, self.overlay_volumes = {}, {}
        self.selections = []  # (release, Compose file names, arguments) of every Compose call
        self.refuse = lambda args: None  # an exception for Compose arguments that should fail

    def compose(self, directory, _project, names, *args, **_kwargs):
        self.calls.append((Path(directory).parent.name, args))
        self.selections.append((Path(directory).parent.name, tuple(names), args))
        added = [service for name in names for service in self.overlay_services.get(name, [])]
        failure = self.failures.get(args[:2]) or self.failures.get(args[:1]) or self.refuse(args)
        if failure:
            raise failure
        if args == ('ps', '-q', 'postgres'):
            output = self.postgres
        elif args == ('config', '--format', 'json'):
            # Database volumes as Compose renders them; a release for a new PostgreSQL major names its own.
            suffix = self.volume_suffix if Path(directory).parent.name != self.previous_release else ''
            suffix = next((self.overlay_volumes[name] for name in names if name in self.overlay_volumes), suffix)
            output = json.dumps({'services': {'postgres': {'image': 'fixture/postgres@sha256:' + 'b' * 64, 'volumes': [
                dict(type='volume', source='postgres_data' + suffix, target='/data/db'),
                dict(type='volume', source='postgres_tde_keyring' + suffix, target='/var/lib/postgresql/tde-keyring'),
                dict(type='volume', source='postgres_tls', target='/etc/postgres-tls')]}},
                'volumes': {name: dict(name='fixture_' + name) for name in (
                    'postgres_data' + suffix, 'postgres_tde_keyring' + suffix, 'postgres_tls')}})
        elif args == ('config', '--services'):
            output = 'postgres\nbackend\nweb\nmigrate\nca-export\n' + ''.join(service + '\n' for service in added)
        elif args[:3] == ('ps', '--status', 'running'):
            output = '\n'.join(self.running)
        elif args[:2] == ('ps', '-a'):
            output = self.exited
        elif args[:1] == ('logs',):
            output = self.logs
        else:
            output = ''
        return SimpleNamespace(returncode=0, stdout=output)

    def run(self, args, **kwargs):
        import subprocess
        self.calls.append(('docker', tuple(args)))
        failure = self.failures.get((args[0],))
        if isinstance(failure, subprocess.CalledProcessError) and not kwargs.get('check'):
            return subprocess.CompletedProcess(args, failure.returncode, '')  # as common.run without check
        if failure:
            raise failure
        if len(args) == 2 and Path(args[0]).name == 'chronicle' and args[1] == 'verify':
            return self.verify(args, kwargs)
        server = json.dumps({'Version': self.host['engine'], 'Components': [
            {'Name': 'containerd', 'Version': self.host['containerd']}, {'Name': 'runc', 'Version': self.host['runc']}]})
        if args[0] == 'python3' and 'select-core' in args:
            return subprocess.CompletedProcess(args, 0, self.core_prefix + '\n')
        output = {'inspect': self.health, 'run': self.image_version, 'version': server,
                  'info': self.host.get('architecture', 'x86_64') if '{{.Architecture}}' in args else self.host['kernel'],
                  }.get(args[1], '') if args[0] == 'docker' else ''
        return subprocess.CompletedProcess(args, 0, output)

    def verify(self, args, kwargs):
        """./chronicle verify of either release. The previous release (2026.11.2 and older) prints
        FAIL for every failed check; the candidate's verify reads the baseline (verify.reporter)."""
        import io
        import subprocess
        from chronicle_ops.verify import BASELINE_ENV, reporter
        baseline = json.loads(os.environ.get(BASELINE_ENV) or '[]')
        previous = kwargs.get('cwd') or (self.previous_dir and Path(args[0]).parent == self.previous_dir)
        self.verifies.append((kwargs.get('cwd') or Path(args[0]).parent, baseline))
        if previous and self.previous_verify_error:
            raise self.previous_verify_error
        failures = self.previous_failures if previous else self.candidate_failures
        with patch('sys.stdout', new_callable=io.StringIO) as output:
            report, failed = reporter([] if previous else baseline)
            for message in failures:
                report(False, message)
        status = int(failed())
        if status and kwargs.get('check'):
            raise subprocess.CalledProcessError(status, args, output.getvalue())
        return subprocess.CompletedProcess(args, status, output.getvalue())

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
            "DASHBOARD_PASSWORD_HASH='$2b$12$fixturefixturefixturefixtu'\n"
            "POSTGRES_PASSWORD=fixture-owner\nPOSTGRES_APP_PASSWORD=fixture-app\n")
        (self.previous / '.env').chmod(0o600)
        origin = Path.cwd()
        self.addCleanup(os.chdir, origin)
        os.chdir(self.candidate)
        self.stack = FakeStack()
        self.stack.previous_dir = self.previous
        self.dumps = []
        self.rollbacks = []
        self.installed = []
        for active in (patch.dict(os.environ, CHRONICLE_RECONCILE_ENABLED='false'),
                       patch('chronicle_ops.upgrade.compose_release', side_effect=self.stack.compose),
                       patch('chronicle_ops.upgrade.run', side_effect=self.stack.run),
                       patch('chronicle_ops.upgrade.postgres_sql', side_effect=lambda *_: self.stack.server_version),
                       patch('chronicle_ops.upgrade.require_storage'),
                       patch('chronicle_ops.upgrade.rollback_dump', side_effect=self.dump),
                       # A failing fixture verification is final here; test_verify_settle covers the reruns.
                       patch('chronicle_ops.upgrade.VERIFY_SETTLE_SECONDS', 0),
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
        self.assertTrue(output.endswith(f'Update verified. This deployment now runs from: {self.candidate}\n'))
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

    def test_update_from_a_release_without_internal_networks_converges_with_no_operator_step(self):
        """2026.11.2 had one bridge for everything. The update picks the core subnet itself, removes
        the previous release's networks with its containers, and only then lets the candidate's
        Compose create the internal ones; a rollback does the same in reverse (restore.Rollback)."""
        from chronicle_ops.envfile import read_env, value
        from chronicle_ops.restore import Rollback
        self.assertNotIn('CHRONICLE_CORE_PREFIX', (self.previous / '.env').read_text())
        status, output, errors = self.upgrade()
        self.assertEqual(0, status, output + errors)
        self.assertEqual('10.252.4', value(read_env(self.candidate / '.env'), 'CHRONICLE_CORE_PREFIX'))
        self.assertIn('CHRONICLE_CORE_PREFIX was not set', errors)
        selections = [args for release, args in self.stack.calls if release == 'docker' and 'select-core' in args]
        self.assertEqual([('python3', str(self.candidate / 'network-subnet.py'), 'select-core', '172.28.0.0/16', 'fixture')],
                         selections)
        order = [(release, args[:2]) for release, args in self.stack.calls if args[:1] in (('down',), ('up',))]
        previous, candidate = f'chronicle-selfhost-{self.old_version}', f'chronicle-selfhost-{self.new_version}'
        self.assertEqual((previous, ('down', '--remove-orphans')), order[0])
        self.assertEqual(candidate, order[1][0])
        self.assertEqual('up', order[1][1][0])
        # Rollback: the candidate's down removes its internal networks before the previous release
        # starts; interrupted while starting, the rerun resumes there without repeating anything.
        record = json.loads(json.dumps(dict(previous=str(self.previous), owner=str(self.candidate), phase='rollback-restore',
                                            dump='/backups/pre-upgrade-1.sql.gz', sha256='c' * 64)))
        (self.previous / '.env.example').write_text('COMPOSE_PROJECT_NAME=\nCOMPOSE_FILE=\nCHRONICLE_STATE_DIR=\n')
        # The fixture's candidate template lacks these lines; a real bundle's has them.
        from chronicle_ops.envfile import set_env_values
        candidate_env = self.candidate / '.env'
        candidate_env.write_text(set_env_values(candidate_env.read_text(), {
            'CHRONICLE_STATE_DIR': str(self.state), 'COMPOSE_PROJECT_NAME': 'fixture'}, require_existing=False))
        (self.state / '.chronicle-upgrade.lock').mkdir(exist_ok=True)
        events, starts = [], iter([OSError('Docker daemon restarted'), None])
        def start(directory, *_args):
            events.append(('up', Path(directory)))
            failure = next(starts)
            if failure:
                raise failure
        class Restored:
            def __init__(restore, *_args, **_kwargs):
                restore.lock = self.state / 'no-restore-lock'
            def execute(restore):
                events.append(('restore', Path.cwd()))
                return 0
        with patch('chronicle_ops.restore.compose', side_effect=lambda *args, **_: events.append(args)), \
             patch('chronicle_ops.restore.Restore', Restored), \
             patch('chronicle_ops.upgrade.start_release', side_effect=start), \
             patch('chronicle_ops.upgrade.verify_release', side_effect=lambda launcher, _baseline: events.append(('verify', launcher))), \
             patch('chronicle_ops.reconcile.install', side_effect=lambda launcher, *_args, **_: events.append(('owner', launcher))), \
             patch('sys.stderr', new_callable=__import__('io').StringIO):
            with self.assertRaisesRegex(OSError, 'Docker daemon restarted'):
                Rollback(self.previous, self.candidate, self.state, dict(record), True).execute()
            resumed = json.loads((self.state / '.chronicle-upgrade.lock/recovery.json').read_text())
            self.assertEqual('rollback-owner', resumed['phase'])
            first = list(events)
            self.assertEqual([('restore', self.candidate), ('down', '--remove-orphans'),
                              ('owner', self.previous / 'chronicle'), ('up', self.previous)], first)
            events.clear()
            self.assertEqual(0, Rollback(self.previous, self.candidate, self.state, resumed, True).execute())
        self.assertEqual([('up', self.previous), ('verify', self.previous / 'chronicle')], events)
        self.assertFalse((self.state / '.chronicle-upgrade.lock').exists())

    def test_an_unreadable_network_table_never_stops_the_update(self):
        self.stack.core_prefix = 'not-a-prefix'
        status, output, errors = self.upgrade()
        self.assertEqual(0, status, output + errors)
        from chronicle_ops.envfile import read_env, value
        self.assertEqual('10.252.0', value(read_env(self.candidate / '.env'), 'CHRONICLE_CORE_PREFIX'))
        self.assertIn('could not check the host\'s networks for the internal core network', errors)

    def test_outdated_engine_containerd_runc_and_kernel_only_warn_during_update(self):
        self.stack.host = dict(engine='27.5.1', containerd='1.7.28', runc='1.1.12', kernel='5.4.0-200-generic')
        status, output, errors = self.upgrade()
        self.assertEqual(0, status, output + errors)
        self.assertTrue(output.endswith(f'Update verified. This deployment now runs from: {self.candidate}\n'))
        import re
        errors = re.sub(r'\x1b\[[0-9;]*m', '', errors)
        for named in ('Docker Engine 27.5.1', 'containerd 1.7.28', 'runc 1.1.12', 'kernel 5.4.0-200-generic'):
            self.assertIn('warning: ' + named, errors)
        self.assertIn('CVE-2026-53362', errors)

    def test_a_non_amd64_docker_daemon_only_warns_during_update(self):
        """The release images are linux/amd64 only. A fresh setup refuses another architecture; an
        update never does: the deployment already runs, and update must never be broken."""
        self.stack.host = dict(self.stack.host, architecture='aarch64')
        status, output, errors = self.upgrade()
        self.assertEqual(0, status, output + errors)
        self.assertTrue(output.endswith(f'Update verified. This deployment now runs from: {self.candidate}\n'))
        import re
        errors = re.sub(r'\x1b\[[0-9;]*m', '', errors)
        self.assertRegex(errors, r'warning: .*aarch64.*linux/amd64')

    def test_edited_bundled_files_are_kept_with_a_diff_and_the_update_continues(self):
        files = json.loads((self.previous.parent / 'release-manifest.json').read_text())['files']
        edited = self.previous / 'docker-compose.yml'
        self.assertIn('selfhost/docker-compose.yml', files)
        edited.write_text(edited.read_text() + '# operator: pin the lab proxy\n')
        (self.previous / 'restore.sh').unlink()
        status, output, errors = self.upgrade()
        self.assertEqual(0, status, output + errors)
        kept = self.state / 'local-edits' / self.old_version
        self.assertEqual(edited.read_text(), (kept / 'selfhost/docker-compose.yml').read_text())
        diff = (kept / 'selfhost/docker-compose.yml.diff').read_text()
        self.assertIn('+# operator: pin the lab proxy', diff)
        self.assertEqual(0o600, (kept / 'selfhost/docker-compose.yml').stat().st_mode & 0o777)
        self.assertIn('selfhost/docker-compose.yml was edited', errors)
        self.assertIn('selfhost/restore.sh is missing', errors)

    def test_update_migrates_settings_it_can_derive(self):
        from chronicle_ops.envfile import read_env, value
        settings = self.previous / '.env'
        (self.previous / 'overlays/lab.yml').write_text('services: {}\n')
        text = settings.read_text().replace(
            'COMPOSE_FILE=docker-compose.yml:overlays/mode-local-https.yml:overlays/backups.yml',
            'COMPOSE_FILE=docker-compose.yml:overlays/mode-local-https.yml:overlays/backups.yml:overlays/backups.yml:overlays/lab.yml:')
        text = text.replace("DASHBOARD_PASSWORD_HASH='$2b$12$fixturefixturefixturefixtu'",
                            "DASHBOARD_PASSWORD_HASH='correct horse battery staple'")
        settings.write_text(text + 'POSTGRES_LOCK_TIMEOUT=45000\nMETRICS_PASSWORD=\n')
        hashed = []
        with patch('chronicle_ops.upgrade.caddy_hash', side_effect=lambda image, text: hashed.append(text) or '$2a$14$derived'):
            status, output, errors = self.upgrade()
        self.assertEqual(0, status, output + errors)
        self.assertEqual(['correct horse battery staple'], hashed)
        migrated = read_env(self.candidate / '.env')
        self.assertEqual('45000', value(migrated, 'POSTGRES_LOCK_TIMEOUT_MS'))
        self.assertNotIn('POSTGRES_LOCK_TIMEOUT', migrated)
        self.assertGreaterEqual(len(value(migrated, 'METRICS_PASSWORD')), 32)
        self.assertEqual('$2a$14$derived', value(migrated, 'DASHBOARD_PASSWORD_HASH'))
        # The fixture template has no COMPOSE_FILE line; the candidate starts with the normalised selection.
        self.assertEqual('docker-compose.yml:overlays/mode-local-https.yml:overlays/backups.yml', os.environ['COMPOSE_FILE'])
        self.assertEqual('services: {}\n', (self.state / 'local-edits' / self.old_version / 'selfhost/overlays/lab.yml').read_text())
        for note in ('POSTGRES_LOCK_TIMEOUT', 'METRICS_PASSWORD', 'DASHBOARD_PASSWORD_HASH', 'overlays/lab.yml'):
            self.assertIn(note, errors)
        self.assertNotIn('correct horse battery staple', output + errors)

    def operator_overlay(self, name, text='services: {}\n'):
        (self.previous / name).write_text(text)
        settings = self.previous / '.env'
        settings.write_text(settings.read_text().replace(
            'overlays/backups.yml\n', f'overlays/backups.yml:{name}\n'))

    def test_the_previous_release_is_stopped_dumped_and_restarted_with_its_operator_overlays(self):
        """The candidate leaves an operator overlay out, but the release that ran with it is stopped,
        dumped, removed and (on rollback) restarted with it: a writer it adds is quiesced too."""
        import subprocess
        self.operator_overlay('overlays/lab.yml')
        self.stack.overlay_services['overlays/lab.yml'] = ['lab-writer']
        status, output, errors = self.upgrade()
        self.assertEqual(0, status, output + errors)
        [(_, stopped)] = self.dumps
        self.assertIn('lab-writer', stopped[0])
        previous = f'chronicle-selfhost-{self.old_version}'
        self.assertTrue(all('overlays/lab.yml' in names for release_name, names, _ in self.stack.selections if release_name == previous))
        self.assertFalse(any('overlays/lab.yml' in names for release_name, names, _ in self.stack.selections if release_name != previous))
        # Interrupted before the dump: the previous release restarts with the overlay.
        self.setUp()
        self.operator_overlay('overlays/lab.yml')
        self.stack.failures[('stop',)] = subprocess.CalledProcessError(1, 'docker compose stop')
        status, output, _ = self.upgrade()
        self.assertEqual(1, status)
        restarts = [names for release_name, names, args in self.stack.selections if release_name == previous and args[:1] == ('up',)]
        self.assertTrue(restarts)
        self.assertTrue(all('overlays/lab.yml' in names for names in restarts))

    def test_an_operator_overlay_that_moves_the_database_is_refused_before_anything_stops(self):
        self.operator_overlay('overlays/lab-volume.yml')
        self.stack.overlay_volumes['overlays/lab-volume.yml'] = '_lab'
        status, output, _ = self.upgrade()
        self.assertEqual(1, status)
        self.assertIn('fixture_postgres_data_lab', output)
        self.assertIn('(set by overlays/lab-volume.yml)', output)
        self.assertFalse([args for _, args in self.stack.calls if args[:1] in (('stop',), ('down',))])
        self.assertEqual([], self.dumps)

    def test_a_monitoring_image_the_registry_cannot_serve_only_warns(self):
        import subprocess
        settings = self.previous / '.env'
        settings.write_text(settings.read_text().replace('overlays/backups.yml\n', 'overlays/backups.yml:overlays/monitoring.yml\n'))
        self.stack.overlay_services['overlays/monitoring.yml'] = ['grafana']
        self.stack.refuse = lambda args: (subprocess.CalledProcessError(18, 'docker compose pull grafana')
                                          if args[:1] == ('pull',) and ('grafana' in args or not args[3:]) else None)
        status, output, errors = self.upgrade()
        self.assertEqual(0, status, output + errors)
        self.assertIn('could not pull the monitoring images', errors)
        pulls = [args for _, args in self.stack.calls if args[:1] == ('pull',)]
        self.assertEqual(2, len(pulls), pulls)
        self.assertNotIn('grafana', pulls[0])
        self.assertIn('backend', pulls[0])
        # A core image the registry cannot serve still stops the update before anything stops.
        self.setUp()
        self.stack.refuse = lambda args: (subprocess.CalledProcessError(18, 'docker compose pull')
                                          if args[:1] == ('pull',) and ('backend' in args or not args[3:]) else None)
        status, output, _ = self.upgrade()
        self.assertEqual(1, status)
        self.assertFalse([args for _, args in self.stack.calls if args[:1] == ('stop',)])

    def test_update_refuses_only_a_setting_it_cannot_derive_before_anything_stops(self):
        settings = self.previous / '.env'
        settings.write_text(settings.read_text().replace('POSTGRES_APP_PASSWORD=fixture-app', 'POSTGRES_APP_PASSWORD='))
        status, output, _ = self.upgrade()
        self.assertEqual(1, status)
        self.assertIn('POSTGRES_APP_PASSWORD is empty', output)
        self.assertFalse([args for _, args in self.stack.calls if args[:1] == ('stop',)])

    def test_a_check_already_failing_before_the_update_does_not_roll_it_back(self):
        backups = '/srv/backups is 775 — every local account can read the full database (want 0700)'
        self.stack.previous_failures = [backups, '3 table(s) still on plain heap']
        self.stack.candidate_failures = [backups.replace('775', '755'), '2 table(s) still on plain heap']
        status, output, errors = self.upgrade()
        self.assertEqual(0, status, output + errors)
        self.assertEqual(str(self.previous), str(self.stack.verifies[0][0]))
        self.assertIn('2 checks already failed before this update', errors)

    def test_a_check_that_got_worse_rolls_the_update_back(self):
        self.stack.previous_failures = ['1 table(s) still on plain heap']
        self.stack.candidate_failures = ['100 table(s) still on plain heap']
        status, output, _ = self.upgrade()
        self.assertEqual(1, status)
        self.assertIn('verification failed: 100 table(s) still on plain heap', output)
        self.assertEqual(1, len(self.rollbacks))

    def test_a_pre_update_verification_that_could_not_run_reports_later_failures_without_rolling_back(self):
        """"Could not run" is not "nothing failed": the baseline is unknown, recorded as such in the
        journal, and a check failing after the update is reported instead of undoing the update."""
        import subprocess
        from chronicle_ops.reconcile import RECOVERY_FILE, UPGRADE_LOCK
        journals = []
        real_save = __import__('chronicle_ops.upgrade', fromlist=['Upgrade']).Upgrade.save
        def save(operation):
            journals.append(dict(operation.recovery))
            return real_save(operation)
        self.stack.previous_verify_error = subprocess.TimeoutExpired('./chronicle verify', 600)
        self.stack.candidate_failures = ['Database volume storage encryption check']
        with patch('chronicle_ops.upgrade.Upgrade.save', save):
            status, output, errors = self.upgrade()
        self.assertEqual(0, status, output + errors)
        self.assertIn('could not run the pre-update verification', errors)
        self.assertIn('1 verification check(s) fail after the update: Database volume storage encryption check', errors)
        self.assertTrue(journals)
        self.assertTrue(all(journal['baseline'] is None for journal in journals))
        self.assertFalse((self.state / UPGRADE_LOCK / RECOVERY_FILE).exists())
        self.assertEqual([], self.rollbacks)

    def test_an_interrupted_update_recovers_with_its_pre_update_baseline(self):
        """A resumed recovery verifies the previous release (which knows no baseline and prints FAIL
        for every failed check) against the baseline the update recorded."""
        import io
        from chronicle_ops.receipts import write_json
        from chronicle_ops.reconcile import RECOVERY_FILE, UPGRADE_LOCK
        from chronicle_ops.upgrade import PREPARED, recover_update
        failing = 'Database volume storage encryption check'
        marker = self.state / UPGRADE_LOCK
        marker.mkdir()
        write_json(marker / RECOVERY_FILE, dict(previous=str(self.previous), owner=str(self.candidate),
                                                phase=PREPARED, baseline=[failing]))
        self.stack.previous_failures = [failing]
        os.chdir(self.previous)
        with patch('sys.stdout', new_callable=io.StringIO) as output, patch('sys.stderr', new_callable=io.StringIO):
            self.assertEqual(self.previous, recover_update(self.state))
        self.assertIn(f'Previous release recovered with its data: {self.previous}', output.getvalue())
        self.assertFalse(marker.exists())
        self.stack.previous_failures = [failing, '0 tables are encrypted']
        marker.mkdir()
        write_json(marker / RECOVERY_FILE, dict(previous=str(self.previous), owner=str(self.candidate),
                                                phase=PREPARED, baseline=[failing]))
        with patch('sys.stdout', new_callable=io.StringIO), patch('sys.stderr', new_callable=io.StringIO), \
             self.assertRaisesRegex(ValueError, 'verification failed: 0 tables are encrypted'):
            recover_update(self.state)

    def test_a_check_the_update_breaks_still_rolls_it_back(self):
        self.stack.previous_failures = ['/srv/backups is 755 — every local account can read the full database (want 0700)']
        self.stack.candidate_failures = ['0 tables are encrypted']
        status, output, _ = self.upgrade()
        self.assertEqual(1, status)
        self.assertEqual(1, len(self.rollbacks), output)

    def major_bump(self, suffix='_18'):
        """A synthetic PostgreSQL 17 -> 18 release: the candidate image is 18 and, when suffix is
        set, its Compose file names new database volumes as a major-bump release must."""
        self.stack.server_version, self.stack.volume_suffix = '170005', suffix
        self.stack.previous_release = self.previous.parent.name
        restored = []
        class FakeRestore:
            def __init__(fake, root, backups, dump, digest, timeout, no_start, assume_yes, **options):
                fake.arguments = dict(root=root, dump=dump, digest=digest, no_start=no_start, **options)
            def execute(fake):
                restored.append((fake.arguments, [args for _, args in self.stack.calls]))
                return 0
        active = patch('chronicle_ops.upgrade.Restore', FakeRestore)
        active.start()
        self.addCleanup(active.stop)
        return restored

    def test_a_postgresql_major_bump_restores_into_new_volumes_and_keeps_the_old_ones(self):
        restored = self.major_bump()
        status, output, errors = self.upgrade()
        self.assertEqual(0, status, output + errors)
        [(arguments, calls_before)] = restored
        self.assertEqual(['c' * 64, True, False], [arguments['digest'], arguments['no_start'], arguments['rollback']])
        self.assertEqual(self.old_version, arguments['target_version'])
        self.assertTrue(arguments['dump'].startswith('/backups/pre-upgrade-'))
        self.assertEqual(1, len(self.dumps))  # dumped once, before the restore
        candidate = self.candidate.parent.name
        # Only the new PostgreSQL is running when the dump is restored; the application starts after.
        self.assertIn(('up', '-d', '--wait'), [args[:3] for _, args in self.stack.calls if args[-1:] == ('postgres',)])
        self.assertFalse([call for call in calls_before if call[0] == 'up' and 'backend' in call])
        self.assertTrue(self.stack.started(candidate))
        # The 17 volumes are never removed: rollback reattaches them through the previous release.
        self.assertFalse([args for _, args in self.stack.calls if '-v' in args or 'volume' in args and 'rm' in args])
        self.assertIn('fixture_postgres_data', errors)
        self.assertIn('kept', errors)

    def test_a_major_bump_that_reuses_the_old_volumes_is_refused_before_anything_stops(self):
        self.major_bump(suffix='')
        status, output, _ = self.upgrade()
        self.assertEqual(1, status)
        self.assertIn('PostgreSQL 17 to 18 needs new database volumes', output)
        self.assertFalse([args for _, args in self.stack.calls if args[:1] == ('stop',)])

    def test_a_failed_major_bump_rolls_back_onto_the_untouched_old_volumes(self):
        from chronicle_ops.restore import Rollback
        import subprocess
        self.major_bump()
        self.stack.failures[('up',)] = subprocess.CalledProcessError(1, 'docker compose up')
        status, output, _ = self.upgrade()
        self.assertEqual(1, status)
        [(_previous, _dump, _digest, _yes)] = self.rollbacks
        # The journal tells rollback that the previous release's own volumes still hold the data.
        record = json.loads((self.state / '.chronicle-upgrade.lock/recovery.json').read_text())
        self.assertTrue(record['fresh_database'])
        rollback = Rollback.__new__(Rollback)
        rollback.record, rollback.state, rollback.current = record, self.state, self.candidate
        with patch('chronicle_ops.restore.Restore.execute', side_effect=AssertionError('restored into the new volumes')):
            rollback.restore_database()
            # An interrupted restore into the new volumes is abandoned with them.
            from chronicle_ops.reconcile import RESTORE_LOCK
            (self.state / RESTORE_LOCK).mkdir()
            (self.state / RESTORE_LOCK / 'phase').write_text('restoring\n')
            rollback.restore_database()
        self.assertFalse((self.state / RESTORE_LOCK).exists())

    def test_the_candidates_volumes_are_listed_before_secrets_init_creates_its_own(self):
        """secrets-init runs in the preflight and creates the new release's credential volumes; listed
        after it, they would count as existing and a rollback would leave them behind."""
        status, output, errors = self.upgrade()
        self.assertEqual(0, status, output + errors)
        calls = [args for _, args in self.stack.calls]
        listing = next(index for index, args in enumerate(calls) if list(args[:3]) == ['docker', 'volume', 'ls'])
        secrets = next(index for index, args in enumerate(calls) if 'secrets-init' in args)
        guard = next(index for index, args in enumerate(calls) if 'config-guard' in args)
        self.assertLess(listing, secrets)
        self.assertLess(secrets, guard)

    def test_a_rolled_back_update_removes_only_the_volumes_its_candidate_created(self):
        """Its secrets and new-major database volumes go with the rollback, so a retry starts as the
        first attempt did; a volume that existed before the update is never in that list."""
        import subprocess
        from chronicle_ops.restore import Rollback
        self.major_bump()
        self.stack.failures[('up',)] = subprocess.CalledProcessError(1, 'docker compose up')
        real_run = self.stack.run
        def run(args, **kwargs):
            if list(args[:3]) == ['docker', 'volume', 'ls']:
                return subprocess.CompletedProcess(args, 0, 'fixture_postgres_tls\nfixture_postgres_tde_keyring_18\n')
            return real_run(args, **kwargs)
        with patch('chronicle_ops.upgrade.run', side_effect=run):
            status, _output, _ = self.upgrade()
        self.assertEqual(1, status)
        record = json.loads((self.state / '.chronicle-upgrade.lock/recovery.json').read_text())
        self.assertEqual(['fixture_postgres_data_18'], record['created_volumes'])
        rollback = Rollback.__new__(Rollback)
        rollback.record = record
        removed = []
        with patch('chronicle_ops.restore.compose') as compose, \
             patch('chronicle_ops.common.run', side_effect=lambda args, **_: removed.append(args)
                   or subprocess.CompletedProcess(args, 0, '')):
            rollback.stop_candidate()
        compose.assert_called_once_with('down', '--remove-orphans', check=True)
        self.assertEqual([['docker', 'volume', 'rm', '--force', 'fixture_postgres_data_18']], removed)

    def test_a_failing_subnet_check_never_stops_the_update(self):
        import subprocess
        self.stack.failures[('python3',)] = subprocess.CalledProcessError(1, 'network-subnet.py check')
        status, output, errors = self.upgrade()
        self.assertEqual(0, status, output + errors)
        self.assertTrue(any(call[1][:1] == ('python3',) and call[1][2:] == ('check',) for call in self.stack.calls))

    def test_update_without_linux_cron_warns_and_commits(self):
        os.environ['CHRONICLE_RECONCILE_ENABLED'] = 'true'  # setUp's patch.dict restores it.
        with patch('chronicle_ops.reconcile.platform.system', return_value='Darwin'):
            status, output, errors = self.upgrade()
        self.assertEqual(0, status, output + errors)
        self.assertIn('automatic reconciliation is unavailable', errors)
        self.assertTrue(output.endswith(f'Update verified. This deployment now runs from: {self.candidate}\n'))

    def test_unsafe_starting_points_are_refused_before_the_previous_release_stops(self):
        def postgres_stopped():
            self.stack.postgres = ''
        def postgres_unhealthy():
            self.stack.health = 'starting'
        def major_change():  # a major bump whose release reuses the old volumes
            self.stack.server_version = '170005'
        def unparsable_image():
            self.stack.image_version = 'pg_ctl version unknown'
        for change, message in (
                (postgres_stopped, 'previous PostgreSQL container is not running'),
                (postgres_unhealthy, 'previous PostgreSQL is not healthy'),
                (major_change, 'PostgreSQL 17 to 18 needs new database volumes'),
                (unparsable_image, 'could not parse the PostgreSQL version in fixture/postgres@sha256:')):
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

    def test_a_rerun_after_an_interrupted_prepare_derives_the_settings_again(self):
        """Interrupted after the candidate's .env was written but before the journal existed: the
        previous release never stopped, so the rerun discards those settings and prepares again."""
        from chronicle_ops.envfile import read_env, value
        (self.candidate / '.env').write_text('COMPOSE_PROJECT_NAME=fixture\nRELEASE_VERSION=interrupted\n')
        (self.candidate / '.env').chmod(0o600)
        status, output, errors = self.upgrade()
        self.assertEqual(0, status, output + errors)
        self.assertIn('an earlier update attempt was interrupted while preparing', errors)
        self.assertEqual(self.new_version, value(read_env(self.candidate / '.env'), 'RELEASE_VERSION'))
        self.assertTrue(self.stack.started(f'chronicle-selfhost-{self.new_version}'))

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

    def owner(self):
        from chronicle_ops.release import OWNER_FILE
        marker = self.state / OWNER_FILE
        return Path(marker.read_text().strip()) if marker.is_file() else None

    def test_a_kill_after_the_commit_leaves_ownership_and_the_front_door_for_the_rerun(self):
        """Both are written before the durable commit, so the process dying anywhere after it
        leaves the original directory forwarding to the new release; the rerun only finishes."""
        from chronicle_ops.reconcile import RECOVERY_FILE, UPGRADE_LOCK
        from chronicle_ops.release import FRONT_DOOR_FILE, is_front_door
        from chronicle_ops.upgrade import COMMITTED, recover_update

        class Killed(BaseException):
            pass

        with patch('chronicle_ops.upgrade.clear_recovery', side_effect=Killed), self.assertRaises(Killed):
            self.upgrade()
        self.assertEqual(COMMITTED, json.loads((self.state / UPGRADE_LOCK / RECOVERY_FILE).read_text())['phase'])
        self.assertEqual(self.candidate, self.owner())
        self.assertTrue(is_front_door(self.previous / 'chronicle'))
        self.assertEqual(str(self.previous), (self.state / FRONT_DOOR_FILE).read_text().strip())
        import io
        with patch('sys.stdout', new_callable=io.StringIO) as output:
            self.assertEqual(self.candidate, recover_update(self.state))
        self.assertIn(f'Committed release recovered: {self.candidate}', output.getvalue())
        self.assertFalse((self.state / UPGRADE_LOCK).exists())
        self.assertEqual([], self.rollbacks)

    def test_a_front_door_that_cannot_be_written_rolls_the_update_back(self):
        self.previous.chmod(0o555)
        self.addCleanup(self.previous.chmod, 0o755)
        status, output, errors = self.upgrade()
        self.assertEqual(1, status, output + errors)
        self.assertIn('Update failed: ', output)
        self.assertEqual(1, len(self.rollbacks))
        self.assertNotIn('Update verified', output)

    def test_an_ownership_failure_rolls_the_update_back_instead_of_committing(self):
        from chronicle_ops import release as releases
        real = releases.set_current_owner

        def refuse_candidate(directory, state):
            if Path(directory).resolve() == self.candidate:
                raise OSError('Read-only file system')
            return real(directory, state)
        with patch('chronicle_ops.release.set_current_owner', side_effect=refuse_candidate):
            status, output, errors = self.upgrade()
        self.assertEqual(1, status, output + errors)
        self.assertIn('Update failed: Read-only file system', output)
        self.assertEqual(1, len(self.rollbacks))
        self.assertNotEqual(self.candidate, self.owner())

    def test_a_failure_after_the_commit_finishes_forward_and_never_deletes_the_owning_release(self):
        import io

        from chronicle_ops import ingress
        from chronicle_ops.receipts import write_json
        from chronicle_ops.update import HANDOFF_FILE, apply_candidate
        write_json(self.state / HANDOFF_FILE, {'previous': str(self.previous), 'owner': str(self.candidate)})
        opened = []

        def open_once_failing(state):
            opened.append(state)
            if len(opened) == 1:
                raise OSError('No space left on device')
            return ingress.open_ingress(state)
        with patch('chronicle_ops.upgrade.open_ingress', side_effect=open_once_failing), \
             patch('sys.stdout', new_callable=io.StringIO) as output, \
             patch('sys.stderr', new_callable=io.StringIO) as errors:
            status = apply_candidate(self.previous)
        self.assertEqual(0, status, output.getvalue() + errors.getvalue())
        self.assertIn(f'Committed release recovered: {self.candidate}', output.getvalue())
        self.assertTrue((self.candidate / '.env').is_file())
        self.assertTrue((self.candidate / 'chronicle').is_file())
        self.assertEqual(self.candidate, self.owner())
        self.assertEqual([], self.rollbacks)

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
