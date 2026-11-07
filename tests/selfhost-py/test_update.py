"""Stable discovery uses version order and never performs an in-place upgrade."""
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from chronicle_ops.update import latest_stable_release


class UpdateTests(unittest.TestCase):
    def test_asset_rich_catalog_can_exceed_the_single_metadata_limit(self):
        from unittest.mock import patch
        from chronicle_ops.release import UPGRADE_FROM_MINIMUM
        from chronicle_ops.update import MAX_METADATA_BYTES, fetch_published_releases
        rows = [dict(tag_name=UPGRADE_FROM_MINIMUM, draft=False, prerelease=False,
                     body='x' * (MAX_METADATA_BYTES + 1))]
        payload = json.dumps(rows).encode()
        def bounded_download(_url, *, max_bytes=MAX_METADATA_BYTES):
            self.assertLessEqual(len(payload), max_bytes)
            return payload
        with patch('chronicle_ops.update.curl', side_effect=bounded_download):
            self.assertEqual(rows, fetch_published_releases())

    def test_catalog_order_cannot_downgrade_the_selected_stable_release(self):
        releases = [dict(tag_name=tag, draft=draft, prerelease=prerelease) for tag, draft, prerelease in (
            ('1.2.3', False, False), ('1.2.4', False, False), ('2.0.0', True, False), ('3.0.0-rc.1', False, True))]
        for catalog in (releases, list(reversed(releases))):
            self.assertEqual(releases[1], latest_stable_release(catalog))

    def test_fixture_produces_the_release_catalog_without_a_consumer_shim(self):
        root = Path(__file__).resolve().parents[2]
        with tempfile.TemporaryDirectory() as folder:
            fixture = Path(folder)
            result = subprocess.run(['bash', str(root / 'tests/security/lib/selfhost-fixtures.sh'),
                                     'update-fixture', str(fixture), '2.0.0'],
                                    capture_output=True, text=True, timeout=10)
            self.assertEqual(0, result.returncode, result.stderr)
            catalog = json.loads((fixture / 'http/latest.json').read_text())
            self.assertEqual('2.0.0', latest_stable_release(catalog)['tag_name'])

    def test_stability_uses_the_shared_version_owner_for_all_tag_forms(self):
        from chronicle_ops.update import is_stable_release
        for version, expected in (('1.2.3', True), ('v1.2.3+build', True),
                                  ('1.2.3-rc.1', False), ('v1.2.3-2', False)):
            with self.subTest(version=version):
                self.assertEqual(expected, is_stable_release(version))

    def test_no_stable_release_is_an_error(self):
        with self.assertRaises(ValueError):
            latest_stable_release([])


class ExtractReleaseTests(unittest.TestCase):
    """The downloaded archive is attacker-controlled until extraction finishes: refuse before writing."""
    NAME, VERSION = 'chronicle-selfhost-2.0.0', '2.0.0'

    def setUp(self):
        from test_release import complete_manifest_fixture
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.root = Path(folder.name)
        self.assets = self.root / 'assets'
        self.assets.mkdir()
        self.bundle = self.root / 'source'
        self.bundle.mkdir()
        (self.bundle / 'release-manifest.json').write_text(json.dumps({'release_version': self.VERSION}))
        complete_manifest_fixture(self.bundle)

    def archive(self, *extra):
        import io
        import tarfile
        path = self.assets / 'release.tar.gz'
        with tarfile.open(path, 'w:gz') as archive:
            def add(name, data=b'', **fields):
                member = tarfile.TarInfo(name)
                member.size, member.mode = len(data), fields.pop('mode', 0o644)
                for key, setting in fields.items():
                    setattr(member, key, setting)
                archive.addfile(member, io.BytesIO(data) if member.isfile() else None)
            archive.add(self.bundle, arcname=self.NAME)
            for name, fields in extra:
                add(name, **fields)
        return path

    def test_escaping_linked_duplicate_or_foreign_members_are_refused_before_any_file_is_written(self):
        import tarfile
        from chronicle_ops.update import extract_release
        escape = self.root / 'escaped'
        for label, member in (
                ('parent traversal', (f'{self.NAME}/../escaped', dict(data=b'x'))),
                ('absolute path', (str(escape), dict(data=b'x'))),
                ('outside the release prefix', ('other/escaped', dict(data=b'x'))),
                ('symlink', (f'{self.NAME}/selfhost/link', dict(type=tarfile.SYMTYPE, linkname=str(escape)))),
                ('hard link', (f'{self.NAME}/selfhost/link', dict(type=tarfile.LNKTYPE, linkname='/etc/passwd'))),
                ('device', (f'{self.NAME}/selfhost/device', dict(type=tarfile.CHRTYPE))),
                ('duplicate', (f'{self.NAME}/selfhost/chronicle', dict(data=b'replaced')))):
            with self.subTest(label), tempfile.TemporaryDirectory(dir=self.root) as folder:
                self.assets = Path(folder)
                with self.assertRaisesRegex(ValueError, 'unsafe or duplicate release archive member'):
                    extract_release(self.archive(member), self.NAME, self.VERSION)
                self.assertEqual(['release.tar.gz'], sorted(path.name for path in self.assets.iterdir()))
                self.assertFalse(escape.exists())

    def test_member_count_and_unpacked_size_limits_stop_before_extraction(self):
        import tarfile
        from unittest.mock import patch
        from chronicle_ops.update import extract_release
        with tarfile.open(self.archive()) as archive:
            members = archive.getmembers()
        for limit, maximum in (('MAX_ARCHIVE_MEMBERS', len(members)),
                                ('MAX_UNPACKED_BYTES', sum(member.size for member in members))):
            with self.subTest(limit), tempfile.TemporaryDirectory(dir=self.root) as folder:
                self.assets = Path(folder)
                archive = self.archive()
                with patch(f'chronicle_ops.update.{limit}', maximum - 1), \
                        self.assertRaisesRegex(ValueError, 'too many members|unpacks to more than'):
                    extract_release(archive, self.NAME, self.VERSION)
                self.assertEqual(['release.tar.gz'], sorted(path.name for path in self.assets.iterdir()))
                with patch(f'chronicle_ops.update.{limit}', maximum):
                    self.assertEqual(self.assets / self.NAME, extract_release(archive, self.NAME, self.VERSION))

    def test_downloads_stop_at_their_byte_limit(self):
        import threading
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
        from unittest.mock import patch
        from chronicle_ops.update import ReleaseAsset, ReleaseAssets, download_assets

        class Assets(BaseHTTPRequestHandler):
            def do_GET(self):
                body = b'x' * (4096 if self.path == '/archive' else 16)
                self.send_response(200)
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass

        server = ThreadingHTTPServer(('127.0.0.1', 0), Assets)
        self.addCleanup(server.server_close)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.shutdown)
        base = 'http://127.0.0.1:%d/' % server.server_address[1]
        assets = ReleaseAssets(*(ReleaseAsset(name, base + name) for name in ('archive', 'checksum', 'signature')))
        for limit, completed in ((4095, False), (4096, True)):
            destination = self.root / f'download-{limit}'
            destination.mkdir()
            with self.subTest(limit=limit), patch('chronicle_ops.update.MAX_ARCHIVE_BYTES', limit), \
                    patch.dict('os.environ', NO_PROXY='127.0.0.1', no_proxy='127.0.0.1', HOME=str(self.root),
                               CURL_HOME=str(self.root), XDG_CONFIG_HOME=str(self.root)):
                if completed:
                    download_assets(assets, destination)
                    self.assertEqual(4096, (destination / 'archive').stat().st_size)
                else:
                    with self.assertRaises(subprocess.CalledProcessError):
                        download_assets(assets, destination)
                    self.assertEqual(0, (destination / 'archive').stat().st_size)

    def test_archive_without_its_manifest_or_launcher_is_refused_before_extraction(self):
        import json as json_module
        from chronicle_ops.update import extract_release
        for label, change, message in (
                ('no manifest', lambda: (self.bundle / 'release-manifest.json').unlink(), 'missing new release manifest'),
                ('other version', lambda: (self.bundle / 'release-manifest.json').write_text(
                    json_module.dumps({'release_version': '2.0.1'})), 'does not match the requested release version'),
                ('launcher not executable', lambda: (self.bundle / 'selfhost/chronicle').chmod(0o644),
                 'missing executable selfhost/chronicle'),
                ('no launcher', lambda: (self.bundle / 'selfhost/chronicle').unlink(), 'missing executable selfhost/chronicle')):
            with self.subTest(label), tempfile.TemporaryDirectory(dir=self.root) as folder:
                saved = {path: path.read_bytes() for path in (self.bundle / 'release-manifest.json', self.bundle / 'selfhost/chronicle')}
                change()
                self.assets = Path(folder)
                try:
                    with self.assertRaisesRegex(ValueError, message):
                        extract_release(self.archive(), self.NAME, self.VERSION)
                finally:
                    for path, content in saved.items():
                        path.write_bytes(content)
                    (self.bundle / 'selfhost/chronicle').chmod(0o755)
                self.assertEqual(['release.tar.gz'], sorted(path.name for path in self.assets.iterdir()))


class ChangelogTests(unittest.TestCase):
    """`./chronicle update` prints the verified notes of every release the operator is crossing."""

    def changelog(self, text):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        bundle = Path(folder.name)
        (bundle / 'CHANGELOG.md').write_text(text)
        return bundle

    def show(self, bundle, current='2026.10.23', target='2026.11.2'):
        import io
        from contextlib import redirect_stdout
        from chronicle_ops.update import show_changelog
        with redirect_stdout(io.StringIO()) as output:
            show_changelog(bundle, current, target)
        return output.getvalue()

    def test_notes_cover_every_release_from_the_installed_one_through_the_target(self):
        bundle = self.changelog('# Changelog\n\n## [Unreleased]\n- unpublished work\n\n'
                                '## [2026.11.2]\n### Fixed\n- target note\n\n## [2026.11.1]\n\n'
                                '## [2026.10.23]\n- installed note\n\n## [2026.10.18]\n- older note\n')
        self.assertEqual('Verified bundle changelog (2026.10.23 through 2026.11.2):\n'
                         '\n## [2026.11.2]\n### Fixed\n- target note\n'
                         '\n## [2026.11.1]\n(no release notes)\n'
                         '\n## [2026.10.23]\n- installed note\n', self.show(bundle))

    def test_missing_ambiguous_or_misordered_notes_stop_the_update(self):
        for text, message in (
                ('## [2026.11.1]\n- not the target\n', 'exactly one entry for the target release'),
                ('## [2026.11.2]\n- first\n## [2026.11.2]\n- again\n', 'exactly one entry for the target release'),
                ('## [2026.10.23]\n- installed\n## [2026.11.2]\n- target\n', 'not ordered newest first')):
            with self.subTest(text=text), self.assertRaisesRegex(ValueError, message):
                self.show(self.changelog(text))
        bundle = self.changelog('## [2026.11.2]\n- target\n')
        (bundle / 'notes.md').write_text((bundle / 'CHANGELOG.md').read_text())
        (bundle / 'CHANGELOG.md').unlink()
        with self.assertRaisesRegex(ValueError, 'missing a regular CHANGELOG.md'):
            self.show(bundle)
        (bundle / 'CHANGELOG.md').symlink_to(bundle / 'notes.md')
        with self.assertRaisesRegex(ValueError, 'missing a regular CHANGELOG.md'):
            self.show(bundle)


class UpdateCommandTests(unittest.TestCase):
    """`./chronicle update [--check]` from the active release, up to the signed download."""

    def setUp(self):
        from unittest.mock import patch
        from chronicle_ops.common import LOCK_FD_ENV
        from chronicle_ops.release import UPGRADE_FROM_MINIMUM
        import os
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.root = Path(folder.name).resolve()
        self.current = UPGRADE_FROM_MINIMUM
        self.release = self.root / 'releases' / f'chronicle-selfhost-{self.current}'
        self.selfhost = self.release / 'selfhost'
        self.selfhost.mkdir(parents=True)
        self.state = self.root / 'state'
        self.state.mkdir()
        (self.release / 'release-manifest.json').write_text(json.dumps({'release_version': self.current}))
        self.env = self.selfhost / '.env'
        self.env.write_text(f"COMPOSE_PROJECT_NAME=fixture\nCHRONICLE_STATE_DIR='{self.state}'\n")
        self.env.chmod(0o600)
        origin = Path.cwd()
        self.addCleanup(os.chdir, origin)
        os.chdir(self.selfhost)
        for active in (patch.dict(os.environ, CHRONICLE_RELEASES_URL='https://updates.example.cl/releases?per_page=100'),
                       patch('chronicle_ops.release.compose_projects', return_value=[]),
                       patch('chronicle_ops.__main__.signal.signal')):
            active.start()
            self.addCleanup(active.stop)
        os.environ.pop(LOCK_FD_ENV, None)
        self.pages = {}

    def catalog(self, *tags, url='https://updates.example.cl/releases?per_page=100', **flags):
        def assets(tag):
            name = f"chronicle-selfhost-{tag.removeprefix('v')}.tar.gz"
            return [dict(name=item, browser_download_url='https://updates.example.cl/' + item)
                    for item in (name, name + '.sha256', name + '.sha256.sig')]
        self.pages[url] = [dict(tag_name=tag, draft=False, prerelease=False, assets=assets(tag), **flags) for tag in tags]

    def cli(self, *args):
        import io
        from unittest.mock import patch
        from chronicle_ops.__main__ import run_cli
        def download(url, *_args, **_kwargs):
            return json.dumps(self.pages[url]).encode()
        with patch('chronicle_ops.update.curl', side_effect=download), \
             patch('chronicle_ops.egress.first_unreachable', return_value=None), \
             patch('sys.stdout', new_callable=io.StringIO) as output, patch('sys.stderr', new_callable=io.StringIO) as errors:
            status = run_cli(['update', *args])
        return status, output.getvalue(), errors.getvalue()

    def test_scheduled_check_reports_a_newer_release_without_taking_the_lock(self):
        from chronicle_ops.common import OPERATION_LOCK
        from chronicle_ops.release import UPDATE_AVAILABLE_EXIT
        self.catalog('v2026.10.30', 'v2026.11.1-rc.1', self.current)
        self.assertEqual((UPDATE_AVAILABLE_EXIT, f'Current: {self.current}; selected: v2026.10.30\n', ''), self.cli('--check'))
        self.catalog(self.current)
        self.assertEqual((0, f'Current: {self.current}; selected: {self.current}\n', ''), self.cli('--check'))
        self.assertFalse((self.state / OPERATION_LOCK).exists())

    def test_a_release_candidate_below_the_reset_floor_must_be_reinstalled_not_updated(self):
        from chronicle_ops.common import OPERATION_LOCK
        from chronicle_ops.release import FRESH_INSTALL_REQUIRED, UPDATE_AVAILABLE_EXIT
        (self.release / 'release-manifest.json').write_text(json.dumps({'release_version': self.current + '-rc.1'}))
        self.catalog('v2026.10.30')
        self.assertEqual((1, '', 'error: update failed: ' + FRESH_INSTALL_REQUIRED + '\n'), self.cli())
        self.assertFalse((self.state / OPERATION_LOCK).exists())  # refused before the lock or any download
        # The scheduled check still reports what is available.
        self.assertEqual(UPDATE_AVAILABLE_EXIT, self.cli('--check')[0])

    def test_check_reads_every_catalog_page_before_choosing(self):
        from chronicle_ops.release import UPDATE_AVAILABLE_EXIT
        from chronicle_ops.update import RELEASES_PAGE_SIZE
        self.pages['https://updates.example.cl/releases?per_page=100'] = [
            dict(tag_name=f'2026.10.30-rc.{number}', draft=False, prerelease=True) for number in range(RELEASES_PAGE_SIZE)]
        self.catalog('2026.11.4', '2026.10.18', url='https://updates.example.cl/releases?per_page=100&page=2')
        self.assertEqual((UPDATE_AVAILABLE_EXIT, f'Current: {self.current}; selected: 2026.11.4\n', ''), self.cli('--check'))

    def test_a_catalog_that_never_ends_is_cut_off(self):
        # AF-P8: a mirror that returns full pages forever must not keep update --check looping;
        # fetch_published_releases then tries the next source.
        from unittest.mock import patch

        from chronicle_ops import update
        from chronicle_ops.update import MAX_CATALOG_PAGES, RELEASES_PAGE_SIZE
        requested = []
        full_page = [{'tag_name': f'2026.10.30-rc.{number}', 'draft': False, 'prerelease': True}
                     for number in range(RELEASES_PAGE_SIZE)]
        def download(url, *_args, **_kwargs):
            requested.append(url)
            return json.dumps(full_page).encode()
        with patch('chronicle_ops.update.curl', side_effect=download), \
             self.assertRaisesRegex(ValueError, f'more than {MAX_CATALOG_PAGES} pages'):
            update.catalog_releases('https://updates.example.cl/releases?per_page=100')
        self.assertEqual(MAX_CATALOG_PAGES, len(requested))

    def test_malformed_catalog_or_installation_fails_before_any_change(self):
        import os
        from chronicle_ops.common import OPERATION_LOCK
        manifest = self.release / 'release-manifest.json'
        cases = (
            # Every release source fails (the fake knows no GitHub URL); the configured one is named first.
            ('catalog object', lambda: self.pages.update({'https://updates.example.cl/releases?per_page=100': {'tag_name': '2026.11.4'}}),
             'no release source answered; updates.example.cl: release catalog must be an array; '
             "api.github.com: 'https://api.github.com/repos/uzaira0/methodic/releases?per_page=100'; "
             "github.com: 'https://github.com/uzaira0/methodic/releases.atom'"),
            # A malformed row is skipped with a warning; with nothing else published there is nothing to select.
            ('unflagged draft', lambda: self.pages.update({'https://updates.example.cl/releases?per_page=100': [{'tag_name': '2026.11.4'}]}),
             'no published stable releases'),
            ('no manifest', lambda: manifest.unlink(), f'missing current release manifest: {manifest}'),
            ('manifest without version', lambda: manifest.write_text('{}'), 'missing release_version or release tag'),
        )
        for label, change, message in cases:
            saved, url = manifest.read_text() if manifest.exists() else None, os.environ['CHRONICLE_RELEASES_URL']
            self.catalog('2026.11.4')
            change()
            for args in (('--check',), ()):
                with self.subTest(label, args=args):
                    status, _, errors = self.cli(*args)
                    self.assertEqual(1, status)
                    self.assertTrue(errors.endswith(f'error: update failed: {message}\n'), errors)
            self.assertEqual([], [path.name for path in self.state.iterdir() if path.name != OPERATION_LOCK and
                                  not path.name.startswith('.chronicle-owner')])
            manifest.write_text(saved or json.dumps({'release_version': self.current}))
            self.env.chmod(0o600)
            os.environ['CHRONICLE_RELEASES_URL'] = url

    def real_curl_cli(self, *args):
        import io
        from unittest.mock import patch
        from chronicle_ops.__main__ import run_cli
        with patch('chronicle_ops.update.run', side_effect=AssertionError('curl started')), \
             patch('sys.stdout', new_callable=io.StringIO) as output, patch('sys.stderr', new_callable=io.StringIO) as errors:
            status = run_cli(['update', *args])
        return status, output.getvalue(), errors.getvalue()

    def test_explicit_older_release_is_refused_as_a_downgrade(self):
        self.catalog('2026.11.4', '2026.10.18')
        older = self.release.with_name('chronicle-selfhost-2026.11.4')
        self.release.rename(older)
        self.selfhost = older / 'selfhost'
        import os
        os.chdir(self.selfhost)
        (older / 'release-manifest.json').write_text(json.dumps({'release_version': '2026.11.4'}))
        status, output, errors = self.cli('v2026.10.18')
        self.assertEqual(1, status)
        self.assertEqual('Current: 2026.11.4; selected: 2026.10.18\n', output)
        self.assertEqual('error: update failed: downgrade refused; use guarded rollback with its pre-update dump\n', errors)

    def test_rerun_resumes_the_recorded_candidate_before_downloading_again(self):
        import fcntl
        import os
        from unittest.mock import patch
        from chronicle_ops.common import LOCK_FD_ENV, OPERATION_LOCK
        from chronicle_ops.reconcile import RECOVERY_FILE, UPGRADE_LOCK
        from chronicle_ops.update import HANDOFF_FILE
        candidate = self.root / 'releases/chronicle-update-x/chronicle-selfhost-2026.11.4/selfhost'
        candidate.mkdir(parents=True)
        (candidate / 'chronicle').write_text('')  # a live handoff; a dead one is cleared (test_update_breakers)
        handoff = dict(previous=str(self.selfhost), owner=str(candidate))
        (self.state / HANDOFF_FILE).write_text(json.dumps(handoff))
        recovery = dict(previous=str(self.selfhost), owner=str(self.root / 'recorded/selfhost'))
        for record, expected in ((None, candidate), (recovery, self.root / 'recorded/selfhost')):
            if record:
                (self.state / UPGRADE_LOCK).mkdir()
                (self.state / UPGRADE_LOCK / RECOVERY_FILE).write_text(json.dumps(record))
            seen = []
            def exec_candidate(program, argv):
                descriptor = int(os.environ[LOCK_FD_ENV])
                probe = os.open(self.state / OPERATION_LOCK, os.O_RDWR)
                try:
                    with self.assertRaises(BlockingIOError):
                        fcntl.flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)
                finally:
                    os.close(probe)
                seen.append((program, argv, os.get_inheritable(descriptor)))
                raise OSError('exec fixture')
            with self.subTest(record=record), patch('chronicle_ops.update.os.execv', side_effect=exec_candidate):
                self.assertEqual((1, '', 'error: update failed: exec fixture\n'), self.cli())
            launcher = str(expected / 'chronicle')
            self.assertEqual([(launcher, [launcher, 'update', '--apply-from', str(self.selfhost)], True)], seen)
            self.assertNotIn(LOCK_FD_ENV, os.environ)

    def test_update_refuses_when_settings_move_the_state_while_it_waits_for_the_lock(self):
        from unittest.mock import patch
        from chronicle_ops import common
        moved = self.root / 'moved-state'
        moved.mkdir()
        acquire = common.acquire_operation_lock
        def setup_ran_meanwhile(state, *args, **kwargs):
            descriptor = acquire(state, *args, **kwargs)
            self.env.write_text(f"COMPOSE_PROJECT_NAME=fixture\nCHRONICLE_STATE_DIR='{moved}'\n")
            return descriptor
        self.catalog('2026.11.4')
        with patch('chronicle_ops.update.acquire_operation_lock', side_effect=setup_ran_meanwhile):
            self.assertEqual((1, '', 'error: update failed: state changed while acquiring lock; retry update\n'), self.cli())
