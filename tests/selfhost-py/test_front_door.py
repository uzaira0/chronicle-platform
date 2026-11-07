"""The directory the operator installed stays the one place they run ./chronicle.

After a verified update, the operator's original selfhost/chronicle forwards to the release that
owns the deployment (state/.chronicle-owner), so `./chronicle update` is the only command an
operator ever needs. The first update to this release is staged and executed by an installed
2026.11.2, so the handoff is checked against 2026.11.2's own update.py from its git tag."""

import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from chronicle_ops import release

ROOT = Path(__file__).resolve().parents[2]
INSTALLED = '2026.11.2'

# Runs 2026.11.2's apply_update in its own interpreter: download is a local copy, storage is not
# measured, and os.execv is recorded and then ends the process as a real exec would (no finally).
STAGE_WITH_INSTALLED = r'''
import json, os, shutil, sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from chronicle_ops import update
from chronicle_ops.envfile import read_env
host, http, version, current, record = map(str, sys.argv[2:7])
def download(assets, destination):
    for asset in assets.all():
        shutil.copy2(Path(http) / asset.name, Path(destination) / asset.name)
def execv(program, argv):
    Path(record).write_text(json.dumps([program, argv, os.getcwd()]))
    sys.stdout.flush()
    os._exit(0)
update.download_assets = download
update.require_storage = lambda *args, **kwargs: None
update.os.execv = execv
catalog = json.loads((Path(http) / 'latest.json').read_text())[0]
assets = update.release_assets(catalog, f'chronicle-selfhost-{version}.tar.gz')
update.apply_update(Path(host), read_env(Path(host) / '.env'), assets, version, current)
'''


def installed_package(folder, tag=INSTALLED):
    archive = subprocess.run(['git', '-C', str(ROOT), 'archive', '--format=tar', tag, 'selfhost/chronicle_ops'],
                             capture_output=True, check=True).stdout
    with tarfile.open(fileobj=io.BytesIO(archive)) as members:
        members.extractall(folder, **({'filter': 'data'} if hasattr(tarfile, 'data_filter') else {}))
    return Path(folder) / 'selfhost'


class FrontDoorTests(unittest.TestCase):
    def setUp(self):
        from update_fixture import prepare_update
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.root = Path(folder.name).resolve()
        self.version = '2026.11.6'
        self.fixture = prepare_update(self.root, self.version)
        self.host = self.fixture.host
        self.state = self.root / 'deployment-state'
        (self.host / 'chronicle').write_text('#!/usr/bin/env bash\necho "installed release: $*"\n')
        (self.host / 'chronicle').chmod(0o755)

    def stage_with_installed_release(self):
        exec_record = self.root / 'exec.json'
        with tempfile.TemporaryDirectory() as package:
            result = subprocess.run([sys.executable, '-I', '-c', STAGE_WITH_INSTALLED, str(installed_package(package)),
                                     str(self.host), str(self.root / 'http'), self.version, release.UPGRADE_FROM_MINIMUM,
                                     str(exec_record)], cwd=self.host, capture_output=True, text=True, timeout=60)
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        return json.loads(exec_record.read_text())

    def apply_as_candidate(self, candidate, previous):
        """This release's apply step, as the exec above starts it: in the candidate, with the
        transaction itself (covered by test_forward_update) replaced by its commit step, which
        records the owner and installs the front door before the durable commit."""
        from chronicle_ops.__main__ import run_cli
        def upgraded(previous, staged):
            release.transfer_deployment(staged, release.front_door_target(previous, self.state), self.state)
            return 0
        origin = Path.cwd()
        os.chdir(candidate)
        try:
            with patch('chronicle_ops.upgrade.recover_update', return_value=False), \
                 patch('chronicle_ops.upgrade.upgrade', side_effect=upgraded), \
                 patch('chronicle_ops.release.compose_projects', return_value=[]), \
                 patch('chronicle_ops.__main__.signal.signal'), \
                 patch('sys.stdout', new_callable=io.StringIO) as output, \
                 patch('sys.stderr', new_callable=io.StringIO) as errors:
                status = run_cli(['update', '--apply-from', str(previous)])
        finally:
            os.chdir(origin)
        return status, output.getvalue(), errors.getvalue()

    def forward(self, *arguments):
        return subprocess.run(['bash', str(self.host / 'chronicle'), *arguments], cwd=self.root,
                              capture_output=True, text=True, timeout=30)

    def test_an_update_started_by_2026_11_2_installs_the_front_door(self):
        program, argv, _ = self.stage_with_installed_release()
        candidate = Path(program).parent
        self.assertEqual([program, 'update', '--apply-from', str(self.host)], argv)
        self.assertTrue((candidate / 'chronicle_ops/update.py').is_file())
        status, output, errors = self.apply_as_candidate(candidate, self.host)
        self.assertEqual(0, status, output + errors)
        self.assertIn(f'Keep running ./chronicle from {self.host}', output)
        self.assertEqual(str(self.host), (self.state / release.FRONT_DOOR_FILE).read_text().strip())
        self.assertEqual('#!/usr/bin/env bash\necho "installed release: $*"\n', (self.host / 'chronicle.release').read_text())
        # The front door runs the owner's launcher from the owner's directory.
        (candidate / 'chronicle').write_text('#!/usr/bin/env bash\necho "owner $(pwd -P): $*"\n')
        result = self.forward('update', '--check')
        self.assertEqual((0, f'owner {candidate}: update --check\n'), (result.returncode, result.stdout), result.stderr)
        self.assertEqual(f'owner {candidate}: \n', self.forward().stdout)  # no arguments, even under bash 3.2
        # After a rollback the installed release owns the deployment again and runs itself.
        release.set_current_owner(self.host, self.state)
        self.assertEqual('installed release: status\n', self.forward('status').stdout)

    def test_a_second_update_keeps_the_same_front_door(self):
        program, _, _ = self.stage_with_installed_release()
        first = Path(program).parent
        self.assertEqual(0, self.apply_as_candidate(first, self.host)[0])
        shutil.copy2(self.host / '.env', first / '.env')  # the committed release's settings
        second = self.root / 'releases/chronicle-releases/2026.11.6/chronicle-selfhost-2026.11.6/selfhost'
        shutil.copytree(first, second, symlinks=True)
        (self.state / '.chronicle-update-handoff.json').write_text(json.dumps(dict(previous=str(first), owner=str(second))))
        status, output, errors = self.apply_as_candidate(second, first)
        self.assertEqual(0, status, output + errors)
        self.assertEqual(str(self.host), (self.state / release.FRONT_DOOR_FILE).read_text().strip())
        self.assertIn(f'Keep running ./chronicle from {self.host}', output)
        (second / 'chronicle').write_text('#!/usr/bin/env bash\necho "second: $*"\n')
        self.assertEqual('second: x\n', self.forward('x').stdout)

    def test_this_release_stages_updates_under_chronicle_releases(self):
        from chronicle_ops.envfile import read_env
        from chronicle_ops.update import apply_update, release_assets
        catalog = json.loads((self.root / 'http/latest.json').read_text())[0]
        assets = release_assets(catalog, f'chronicle-selfhost-{self.version}.tar.gz')
        executed = []
        def download(assets, destination):
            for asset in assets.all():
                shutil.copy2(self.root / 'http' / asset.name, destination / asset.name)
        with patch('chronicle_ops.update.download_assets', side_effect=download), \
             patch('chronicle_ops.update.require_storage'), \
             patch('chronicle_ops.update.exec_candidate', side_effect=lambda candidate, previous: executed.append(candidate)
                   or (_ for _ in ()).throw(OSError('exec fixture'))):
            with self.assertRaisesRegex(OSError, 'exec fixture'):
                apply_update(self.host, read_env(self.host / '.env'), assets, self.version, release.UPGRADE_FROM_MINIMUM)
        self.assertEqual([self.root / f'releases/chronicle-releases/{self.version}/chronicle-selfhost-{self.version}/selfhost'],
                         executed)
        self.assertFalse((self.root / f'releases/chronicle-releases/{self.version}').exists())  # a failed exec unstages

    def test_the_forwarder_is_not_reported_as_an_operator_edit(self):
        from test_release import complete_manifest_fixture
        bundle = self.root / f'installed/chronicle-selfhost-{release.UPGRADE_FROM_MINIMUM}'
        (bundle / 'selfhost').mkdir(parents=True)
        (bundle / 'release-manifest.json').write_text(json.dumps(dict(release_version=release.UPGRADE_FROM_MINIMUM)))
        complete_manifest_fixture(bundle)
        manifest = json.loads((bundle / 'release-manifest.json').read_text())
        release.install_front_door(bundle / 'selfhost', self.state)
        with patch('sys.stderr', new_callable=io.StringIO) as errors:
            self.assertEqual([], release.preserve_local_edits(bundle, manifest, bundle, self.state))
        self.assertEqual('', errors.getvalue())
        (bundle / 'selfhost/chronicle.release').write_text('edited\n')
        with patch('sys.stderr', new_callable=io.StringIO) as errors:
            self.assertEqual(['selfhost/chronicle'], [name for name, _ in release.preserve_local_edits(bundle, manifest, bundle, self.state)])

    def test_a_front_door_the_operator_moved_is_replaced_by_the_running_release(self):
        """The record names a directory that is gone: the update installs the front door where the
        operator runs ./chronicle now and rewrites the record, instead of failing on every update."""
        (self.state / release.FRONT_DOOR_FILE).write_text(str(self.root / 'moved-away/selfhost') + '\n')
        with patch('sys.stderr', new_callable=io.StringIO) as errors:
            front = release.front_door_target(self.host, self.state)
        self.assertEqual(self.host, front)
        self.assertIn('no longer exists', errors.getvalue())
        candidate = self.root / 'releases/chronicle-releases/2026.11.6/chronicle-selfhost-2026.11.6/selfhost'
        candidate.mkdir(parents=True)
        (candidate / 'chronicle').write_text('#!/usr/bin/env bash\necho "owner: $*"\n')
        (candidate / 'chronicle').chmod(0o755)
        release.transfer_deployment(candidate, front, self.state)
        self.assertEqual(str(self.host), (self.state / release.FRONT_DOOR_FILE).read_text().strip())
        self.assertEqual('owner: status\n', self.forward('status').stdout)

    def test_the_front_door_refuses_to_guess_when_no_release_owns_the_deployment(self):
        """A lost or stale ownership marker never runs the old launcher against a newer stack."""
        candidate = self.root / 'releases/chronicle-releases/2026.11.6/chronicle-selfhost-2026.11.6/selfhost'
        candidate.mkdir(parents=True)
        (candidate / 'chronicle').write_text('#!/usr/bin/env bash\necho "owner: $*"\n')
        (candidate / 'chronicle').chmod(0o755)
        release.transfer_deployment(candidate, self.host, self.state)
        for marker in ('', str(self.root / 'deleted-release/selfhost')):
            with self.subTest(marker=marker or 'missing'):
                (self.state / release.OWNER_FILE).unlink(missing_ok=True)
                if marker:
                    (self.state / release.OWNER_FILE).write_text(marker + '\n')
                result = self.forward('up')
                self.assertEqual(1, result.returncode, result.stdout)
                self.assertNotIn('installed release', result.stdout)
                self.assertIn('no release owns this deployment', result.stderr)
                self.assertIn(str(candidate), result.stderr)

    def test_cleanup_counts_repeated_stagings_of_one_version_once(self):
        """Interrupted attempts at one version leave <version>.<n> copies; they never push an older
        release out of the kept set, and the copies themselves are removed."""
        releases = self.root / 'releases' / release.RELEASES_DIRECTORY
        bundles = {}
        for staging, version in (('2026.11.3', '2026.11.3'), ('2026.11.4', '2026.11.4'), ('2026.11.6', '2026.11.6'),
                                 ('2026.11.6.1', '2026.11.6'), ('2026.11.6.2', '2026.11.6')):
            bundle = releases / staging / f'chronicle-selfhost-{version}'
            (bundle / 'selfhost').mkdir(parents=True)
            (bundle / 'release-manifest.json').write_text(json.dumps({'release_version': version, 'images': {}}))
            bundles[staging] = bundle
        release.set_current_owner(bundles['2026.11.6'] / 'selfhost', self.state)
        with patch('chronicle_ops.release.compose_projects', return_value=[]), \
             patch('sys.stdout', new_callable=io.StringIO) as output:
            release.cleanup_releases(self.root / 'releases', self.state)
        removed = sorted(line.split()[2] for line in output.getvalue().splitlines() if line.startswith('Would remove '))
        self.assertEqual(sorted(str(bundles[name]) for name in ('2026.11.6.1', '2026.11.6.2')), removed)


if __name__ == '__main__':
    unittest.main()
