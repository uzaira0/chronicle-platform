"""`./chronicle update` never needs the operator: each case is one row of the update breaker table.

The rule: update fails only when continuing would lose data. Anything about the environment is a
warning; every failure rolls back automatically, leaves the stack serving and exits non-zero."""
import io
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from chronicle_ops import update as updater
from chronicle_ops.reconcile import RECOVERY_FILE, UPGRADE_LOCK

ROOT = Path(__file__).resolve().parents[2]


class Reached(Exception):
    """Raised by a patched step to prove update got past every earlier refusal."""


def install(root, version='2026.11.2', mode=0o600, state=None):
    bundle = root / f'chronicle-selfhost-{version}'
    selfhost = bundle / 'selfhost'
    selfhost.mkdir(parents=True)
    (bundle / 'release-manifest.json').write_text(json.dumps({'release_version': version}))
    state = state or root / 'state'
    state.mkdir(exist_ok=True)
    (selfhost / '.env').write_text(f"COMPOSE_PROJECT_NAME=fixture\nCHRONICLE_STATE_DIR='{state}'\n")
    (selfhost / '.env').chmod(mode)
    return selfhost, state


def run_update(selfhost, **patches):
    origin = Path.cwd()
    os.chdir(selfhost)
    try:
        with patch('chronicle_ops.update.require_current_owner'), \
             patch('chronicle_ops.update.fetch_published_releases', side_effect=Reached), \
             patch('sys.stderr', new_callable=io.StringIO) as errors:
            try:
                updater.update()
            except Reached:
                return 'reached', errors.getvalue()
            except ValueError as error:
                return str(error), errors.getvalue()
    finally:
        os.chdir(origin)
    return 'returned', ''


class ExitAndHandoffTests(unittest.TestCase):
    def test_env_mode_is_repaired_instead_of_refused(self):
        with tempfile.TemporaryDirectory() as folder:
            selfhost, _ = install(Path(folder).resolve(), mode=0o644)
            outcome, _ = run_update(selfhost)
            self.assertEqual('reached', outcome)
            self.assertEqual(0o600, (selfhost / '.env').stat().st_mode & 0o777)

    def test_a_handoff_to_a_deleted_candidate_is_cleared_and_update_continues(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder).resolve()
            selfhost, state = install(root)
            gone = root / 'chronicle-update-x/chronicle-selfhost-2026.11.5/selfhost'
            handoff = state / updater.HANDOFF_FILE
            handoff.write_text(json.dumps({'previous': str(selfhost), 'owner': str(gone)}))
            outcome, errors = run_update(selfhost)
            self.assertEqual('reached', outcome)
            self.assertFalse(handoff.exists())
            self.assertIn('no longer exists', errors)

    def test_a_completed_automatic_rollback_exits_non_zero(self):
        from chronicle_ops.receipts import write_json
        from chronicle_ops.upgrade import PREPARED
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder).resolve()
            previous, state = install(root)
            candidate = root / 'chronicle-update-x/chronicle-selfhost-2026.11.5/selfhost'
            candidate.mkdir(parents=True)
            (candidate / '.env').write_text((previous / '.env').read_text())
            journal = state / UPGRADE_LOCK
            journal.mkdir()
            record = {'previous': str(previous), 'owner': str(candidate), 'phase': PREPARED}
            write_json(journal / RECOVERY_FILE, record)
            (state / updater.HANDOFF_FILE).write_text(json.dumps(record))
            origin = Path.cwd()
            os.chdir(candidate)
            try:
                with patch('chronicle_ops.upgrade.start_release'), \
                     patch('chronicle_ops.upgrade.run', return_value=subprocess.CompletedProcess([], 0)), \
                     patch('chronicle_ops.release.cleanup_releases'), \
                     patch('sys.stdout', new_callable=io.StringIO) as output:
                    status = updater.apply_candidate(previous)
            finally:
                os.chdir(origin)
            self.assertIn(f'Previous release recovered with its data: {previous}', output.getvalue())
            self.assertNotEqual(0, status)
            self.assertFalse(journal.exists())


class NoCronHostTests(unittest.TestCase):
    """macOS trials and Linux hosts without cron run updates; reconciliation is just unavailable."""

    def test_setup_turns_reconciliation_off_for_a_new_install_without_linux_cron(self):
        from chronicle_ops.envfile import read_env, value
        from chronicle_ops.setup_env import SETUP_FIELDS, write_setup_environment
        values = dict.fromkeys(SETUP_FIELDS, '')
        values.update(COMPOSE_FILE='docker-compose.yml', CHRONICLE_STATE_DIR='.')
        records = b''.join(f'{key}={item}\0'.encode() for key, item in values.items())
        for system, expected in (('Darwin', 'false'), ('Linux', 'true')):
            with self.subTest(system=system), tempfile.TemporaryDirectory() as folder:
                directory = Path(folder)
                (directory / '.env.example').write_text('CHRONICLE_RECONCILE_ENABLED=true\nDOMAIN=\n')
                origin = Path.cwd()
                os.chdir(directory)
                try:
                    with patch('sys.stdin', io.TextIOWrapper(io.BytesIO(records))), \
                         patch('chronicle_ops.setup_env.apply_setup_memory', side_effect=lambda text, *_: text), \
                         patch('chronicle_ops.reconcile.platform.system', return_value=system), \
                         patch('chronicle_ops.reconcile.shutil.which', return_value='/usr/bin/tool'), \
                         patch('chronicle_ops.reconcile.run', return_value=subprocess.CompletedProcess([], 0)), \
                         patch('sys.stdout', new_callable=io.StringIO):
                        write_setup_environment()
                finally:
                    os.chdir(origin)
                self.assertEqual(expected, value(read_env(directory / '.env'), 'CHRONICLE_RECONCILE_ENABLED'))

    def test_schedule_install_without_cron_warns_and_still_moves_ownership(self):
        from chronicle_ops import reconcile
        from chronicle_ops.release import OWNER_FILE
        with tempfile.TemporaryDirectory() as folder:
            state = Path(folder).resolve()
            launcher = state / 'release/chronicle'
            launcher.parent.mkdir()
            with patch.dict(os.environ, {reconcile.ENABLED_ENV: 'true'}), \
                 patch('chronicle_ops.reconcile.platform.system', return_value='Darwin'), \
                 patch('sys.stderr', new_callable=io.StringIO) as errors:
                reconcile.install(launcher, state, 'fixture')
            self.assertEqual(str(launcher.parent), (state / OWNER_FILE).read_text().strip())
            self.assertIn('automatic reconciliation is unavailable', errors.getvalue())


    def test_host_action_names_why_reconciliation_cannot_run(self):
        from chronicle_ops.__main__ import main
        for enabled, system, expected in (('true', 'Darwin', 'automatic reconciliation requires a Linux operator crontab\n'),
                                          ('false', 'Darwin', ''),
                                          ('true', 'Linux', '')):
            with self.subTest(enabled=enabled, system=system), tempfile.TemporaryDirectory() as folder, \
                 patch.dict(os.environ, {'CHRONICLE_RECONCILE_ENABLED': enabled, 'CHRONICLE_OPS_STATE': folder}), \
                 patch('chronicle_ops.reconcile.platform.system', return_value=system), \
                 patch('chronicle_ops.reconcile.shutil.which', return_value='/usr/bin/tool'), \
                 patch('chronicle_ops.reconcile.run', return_value=subprocess.CompletedProcess([], 0)), \
                 patch('sys.argv', ['chronicle_ops', 'reconcile', 'host']), \
                 patch('sys.stdout', new_callable=io.StringIO) as output:
                self.assertEqual(0, main())
            self.assertEqual(expected, output.getvalue())

    def test_doctor_warns_when_reconciliation_is_enabled_but_unavailable(self):
        from test_monitoring_startup import LauncherTests
        launcher = LauncherTests()
        for reason, expected in (('automatic reconciliation requires a Linux operator crontab', 'warn'), ('', None)):
            with self.subTest(reason=reason), tempfile.TemporaryDirectory() as folder:
                selfhost, environment = launcher.install(Path(folder).resolve(), [])
                environment['FAKE_RECONCILE_HOST'] = reason
                result = launcher.harness(selfhost, environment, 'doctor_reconcile_host')
                plain = re.sub(r'\x1b\[[0-9;]*m', '', result.stdout)
                rows = [line for line in plain.splitlines() if 'reconciliation-host' in line]
                if expected is None:
                    self.assertEqual([], rows, plain)
                else:
                    self.assertEqual(1, len(rows), plain + result.stderr)
                    self.assertIn('warn', rows[0])
                    self.assertIn('Linux operator crontab', plain)
                self.assertEqual(0, result.returncode, plain + result.stderr)

    def test_up_installs_a_missing_schedule_once_cron_is_available(self):
        from chronicle_ops.__main__ import main
        from chronicle_ops.reconcile import STOP_MARKER
        for system, installed in (('Linux', True), ('Darwin', False)):
            with self.subTest(system=system), tempfile.TemporaryDirectory() as folder:
                state = Path(folder).resolve()
                (state / STOP_MARKER).write_text('')
                with patch.dict(os.environ, {'CHRONICLE_RECONCILE_ENABLED': 'true', 'CHRONICLE_OPS_STATE': str(state),
                                             'CHRONICLE_OPS_PROJECT': 'fixture'}), \
                     patch('chronicle_ops.reconcile.platform.system', return_value=system), \
                     patch('chronicle_ops.reconcile.shutil.which', return_value='/usr/bin/tool'), \
                     patch('chronicle_ops.reconcile.run', return_value=subprocess.CompletedProcess([], 0, '', '')), \
                     patch('chronicle_ops.reconcile.install') as install, \
                     patch('sys.argv', ['chronicle_ops', 'reconcile', 'resume']):
                    self.assertEqual(0, main())
                self.assertFalse((state / STOP_MARKER).exists())
                self.assertEqual(installed, install.called)

class SubnetOverlapTests(unittest.TestCase):
    """Only our own network may share CHRONICLE_SUBNET silently; every other overlap is a warning."""

    def module(self, networks, routes=()):
        import importlib.util
        from types import SimpleNamespace
        spec = importlib.util.spec_from_file_location('breaker_subnet', ROOT / 'selfhost/network-subnet.py')
        subnet = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(subnet)
        def host(args, **_):
            if args[:3] == ['docker', 'network', 'ls']:
                return SimpleNamespace(stdout=''.join(network['Id'] + '\n' for network in networks))
            if args[:3] == ['docker', 'network', 'inspect']:
                return SimpleNamespace(stdout=json.dumps(networks))
            return SimpleNamespace(stdout=json.dumps([route for route in routes if (':' in route['dst']) == (args[1] == '-6')]))
        for item in (patch.object(subnet.subprocess, 'run', side_effect=host),
                     patch.object(subnet.shutil, 'which', return_value='/usr/sbin/ip')):
            item.start()
            self.addCleanup(item.stop)
        return subnet

    def check(self, subnet, wanted='10.40.0.0/24'):
        config = {'name': 'fixture', 'networks': {'default': {'ipam': {'config': [{'subnet': wanted}]}}}}
        with patch('sys.stdin', io.StringIO(json.dumps(config))), patch('sys.stderr', new_callable=io.StringIO) as errors:
            self.assertIsNone(subnet.check())
        return errors.getvalue()

    def test_our_own_network_under_a_custom_name_passes_silently(self):
        own = {'Id': 'a' * 12, 'Name': 'chronicle-net', 'Options': {},
               'Labels': {'com.docker.compose.project': 'fixture', 'com.docker.compose.network': 'default'},
               'IPAM': {'Config': [{'Subnet': '10.40.0.0/24'}]}}
        self.assertEqual('', self.check(self.module([own], [{'dst': '10.40.0.0/24', 'dev': 'br-' + 'a' * 12}])))

    def test_another_network_or_route_overlapping_only_warns(self):
        lab = {'Id': 'b' * 12, 'Name': 'lab_net', 'IPAM': {'Config': [{'Subnet': '10.40.0.0/16'}]}}
        errors = self.check(self.module([lab], [{'dst': '10.40.0.0/20', 'dev': 'tun0'}]))
        self.assertIn('warning: CHRONICLE_SUBNET 10.40.0.0/24 overlaps Docker network lab_net (10.40.0.0/16)', errors)
        self.assertIn('host route tun0 (10.40.0.0/20)', errors)

    def test_an_unreadable_docker_or_route_table_only_warns(self):
        config = json.dumps({'name': 'fixture', 'networks': {'default': {'ipam': {'config': [{'subnet': '10.40.0.0/24'}]}}}})
        result = subprocess.run([sys.executable, str(ROOT / 'selfhost/network-subnet.py'), 'check'], input=config,
                                env={'PATH': '/nonexistent'}, capture_output=True, text=True, timeout=30)
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn('warning: could not check CHRONICLE_SUBNET against Docker networks', result.stderr)

class DiskReserveTests(unittest.TestCase):
    """Startup's reserve stays a refusal; the larger update reserve is announced before an update needs it."""
    GIB = 1024 ** 3

    def reports(self, startup_enough, update_enough):
        def report(state, project, floor_gib=5, peak_bytes=0, **_):
            enough = update_enough if peak_bytes else startup_enough
            return [('state', enough, 6 * self.GIB, 10 ** 6, int(floor_gib) * self.GIB + peak_bytes)]
        return report

    def test_doctor_warns_when_startup_fits_but_an_update_would_not(self):
        from types import SimpleNamespace
        from chronicle_ops import verify
        disk = SimpleNamespace(f_frsize=4096, f_blocks=1024 * self.GIB // 4096, f_bfree=500 * self.GIB // 4096,
                               f_bavail=500 * self.GIB // 4096)
        for startup, update, expected in ((True, False, {'state-reserve': 'ok', 'state-update-reserve': 'warn'}),
                                          (True, True, {'state-reserve': 'ok'}),
                                          (False, False, {'state-reserve': 'fail'})):
            with self.subTest(startup=startup, update=update), \
                 patch('chronicle_ops.verify.storage_report', side_effect=self.reports(startup, update)), \
                 patch('chronicle_ops.verify.os.statvfs', return_value=disk):
                rows = {row[0]: row for row in verify.disk_rows({}, '/state')}
            self.assertEqual(expected, {name: row[1] for name, row in rows.items() if name != 'disk'})
            if 'state-update-reserve' in rows:
                self.assertIn('an update needs', rows['state-update-reserve'][2])
                self.assertIn('./chronicle update', rows['state-update-reserve'][3])

    def test_update_reserve_command_reports_a_shortfall_for_the_daily_job(self):
        from chronicle_ops.__main__ import main
        for update, status in ((False, 1), (True, 0)):
            with self.subTest(update=update), tempfile.TemporaryDirectory() as folder, \
                 patch.dict(os.environ, {'CHRONICLE_OPS_STATE': folder, 'CHRONICLE_OPS_PROJECT': 'fixture'}), \
                 patch('chronicle_ops.verify.storage_report', side_effect=self.reports(True, update)), \
                 patch('sys.argv', ['chronicle_ops', 'update-reserve']), \
                 patch('sys.stderr', new_callable=io.StringIO) as errors:
                self.assertEqual(status, main())
            self.assertEqual(not update, 'an update needs' in errors.getvalue())

    def test_daily_update_check_logs_a_reserve_shortfall(self):
        from chronicle_ops import reconcile
        with tempfile.TemporaryDirectory() as folder:
            state = Path(folder).resolve()
            active = state / 'release/selfhost'
            active.mkdir(parents=True)
            (active.parent / 'release-manifest.json').write_text('{}')
            with patch.dict(os.environ, {reconcile.ENABLED_ENV: 'true', 'HOME': folder}), \
                 patch('chronicle_ops.reconcile.platform.system', return_value='Linux'), \
                 patch('chronicle_ops.reconcile.shutil.which', return_value='/usr/bin/tool'), \
                 patch('chronicle_ops.reconcile.run', return_value=subprocess.CompletedProcess([], 0, '', '')):
                reconcile.install(active / 'chronicle', state, 'fixture')
            script = (state / 'reconcile.sh').read_text()
            daily = script[script.index('--check-updates'):script.index('exec python3')]
            self.assertIn('python3 -m chronicle_ops update-reserve', daily)
            self.assertIn("logger -p user.warning -t chronicle 'Free disk is below what the next update needs", daily)

class PostureBaselineTests(unittest.TestCase):
    def test_verify_reports_a_failure_from_before_the_update_as_a_warning(self):
        from chronicle_ops.verify import reporter
        known = 'Database volume storage encryption check'
        with patch('sys.stdout', new_callable=io.StringIO) as output:
            report, failed = reporter([known])
            report(False, known)
            self.assertFalse(failed())
            report(False, '3 table(s) still on plain heap')
            self.assertTrue(failed())
        lines = re.sub(r'\x1b\[[0-9;]*m', '', output.getvalue()).splitlines()
        self.assertTrue(lines[0].strip().startswith('warn'), lines)
        self.assertIn('already failing before this update', lines[0])
        self.assertTrue(lines[1].strip().startswith('FAIL'), lines)

    def test_a_check_that_got_worse_is_a_regression_not_the_old_failure(self):
        """Numbers in a message are measurements: more plain-heap tables or unwritable
        directories, or a backup mode that gained a permission bit, is a failure the update caused."""
        from chronicle_ops.verify import reporter
        backups = '/srv/backups is {} — every local account can read the full database (want 0700)'
        for before, after, worse in (('1 table(s) still on plain heap', '100 table(s) still on plain heap', True),
                                     ('100 table(s) still on plain heap', '1 table(s) still on plain heap', False),
                                     ('2 director(y/ies) under /srv/b are not writable by this account — x',
                                      '5 director(y/ies) under /srv/b are not writable by this account — x', True),
                                     (backups.format(755), backups.format(777), True),
                                     (backups.format(775), backups.format(755), False),
                                     ('404 /chronicle/ (expected 200) ', '502 /chronicle/ (expected 200) ', False)):
            with self.subTest(after=after), patch('sys.stdout', new_callable=io.StringIO):
                report, failed = reporter([before])
                report(False, after)
                self.assertEqual(worse, failed())

    def test_failed_checks_reads_any_release_transcript(self):
        from chronicle_ops.verify import failed_checks, regressions
        transcript = '  \x1b[32mok\x1b[0m   fine\n  \x1b[31mFAIL\x1b[0m   a 2  b\n'
        self.assertEqual(['a 2  b'], failed_checks(transcript))
        self.assertEqual([], regressions(1, transcript, ['a 7 b']))
        self.assertEqual(['./chronicle verify exited 2 without naming a failed check'], regressions(2, 'Traceback\n', ['a 7 b']))
        self.assertEqual([], regressions(0, '', []))

class DownloadPathTests(unittest.TestCase):
    """Discovery and download go through the operator's HTTPS proxy, retry, and fall back to a mirror."""

    def test_release_downloads_honour_the_proxy_and_retry_with_backoff(self):
        attempts, sleeps = [], []
        def flaky(args, **_):
            attempts.append(args)
            if len(attempts) < 3:
                raise subprocess.CalledProcessError(7, args)  # could not connect
            return subprocess.CompletedProcess(args, 0, b'[]')
        with patch('chronicle_ops.update.run', side_effect=flaky), \
             patch('chronicle_ops.update.time.sleep', side_effect=sleeps.append), \
             patch('sys.stderr', new_callable=io.StringIO) as errors:
            self.assertEqual(b'[]', updater.curl('https://api.github.com/repos/x/y/releases'))
        self.assertEqual(3, len(attempts))
        self.assertTrue(all('--noproxy' not in args for args in attempts))
        self.assertEqual([1, 2], sleeps)
        self.assertIn('retrying in 1 s', errors.getvalue())

    def test_retries_stop_at_the_overall_deadline(self):
        clock = iter(range(0, 10_000, 40))
        with patch('chronicle_ops.update.run', side_effect=subprocess.CalledProcessError(28, 'curl')) as run, \
             patch('chronicle_ops.update.time.monotonic', side_effect=lambda: next(clock)), \
             patch('chronicle_ops.update.time.sleep'), \
             patch('chronicle_ops.update.transfer_timeout', return_value=100), \
             patch('sys.stderr', new_callable=io.StringIO):
            with self.assertRaises(subprocess.CalledProcessError):
                updater.curl('https://example.org/x')
        self.assertLessEqual(run.call_count, 3)
        self.assertTrue(all(int(call.args[0][call.args[0].index('--max-time') + 1]) <= 100 for call in run.call_args_list))

    def test_discovery_falls_back_from_the_api_to_the_release_feed(self):
        feed = (b'<feed><entry><link rel="alternate" type="text/html" '
                b'href="https://github.com/uzaira0/methodic/releases/tag/2026.11.5"/></entry>'
                b'<entry><link rel="alternate" type="text/html" '
                b'href="https://github.com/uzaira0/methodic/releases/tag/2026.11.6-rc.1"/></entry></feed>')
        asked = []
        def fetch(url, *_, **__):
            asked.append(url)
            if 'api.github.com' in url or 'mirror.example' in url:
                raise subprocess.CalledProcessError(22, 'curl')  # 403 rate limit, mirror down
            return feed
        with patch.dict(os.environ, {'CHRONICLE_RELEASES_URL': 'https://mirror.example/releases.json'}), \
             patch('chronicle_ops.update.curl', side_effect=fetch), \
             patch('sys.stderr', new_callable=io.StringIO) as errors:
            releases = updater.fetch_published_releases()
        self.assertEqual('https://mirror.example/releases.json', asked[0])
        self.assertTrue(asked[-1].endswith('/releases.atom'))
        chosen = updater.select_release(releases)
        self.assertEqual('2026.11.5', chosen['tag_name'])
        assets = updater.release_assets(chosen, 'chronicle-selfhost-2026.11.5.tar.gz')
        self.assertEqual('https://github.com/uzaira0/methodic/releases/download/2026.11.5/chronicle-selfhost-2026.11.5.tar.gz.sha256.sig',
                         assets.signature.url)
        self.assertIn('trying the next release source', errors.getvalue())

    def test_discovery_skips_malformed_and_incomplete_releases(self):
        def complete(tag):
            name = f'chronicle-selfhost-{tag}.tar.gz'
            return dict(tag_name=tag, draft=False, prerelease=False, assets=[
                dict(name=item, browser_download_url='https://example.org/' + item) for item in (name, name + '.sha256', name + '.sha256.sig')])
        partial = complete('2026.11.7')
        partial['assets'] = partial['assets'][:2]  # signature not uploaded yet
        catalog = [complete('2026.11.5'), dict(tag_name='2026.11.8'), dict(tag_name='latest', draft=False, prerelease=False),
                   partial, 'not a release']
        with patch('sys.stderr', new_callable=io.StringIO) as errors:
            self.assertEqual('2026.11.5', updater.select_release(catalog)['tag_name'])
        for skipped in ('2026.11.8', 'latest', '2026.11.7'):
            self.assertIn(skipped, errors.getvalue())

    def test_a_malformed_asset_row_skips_that_release_instead_of_stopping_discovery(self):
        def complete(tag):
            name = f'chronicle-selfhost-{tag}.tar.gz'
            return dict(tag_name=tag, draft=False, prerelease=False, assets=[
                dict(name=item, browser_download_url='https://example.org/' + item) for item in (name, name + '.sha256', name + '.sha256.sig')])
        broken = complete('2026.11.9')
        broken['assets'] = [None, *broken['assets']]
        odd = complete('2026.11.8')
        odd['assets'] = 'not a list'
        with patch('sys.stderr', new_callable=io.StringIO) as errors:
            self.assertEqual('2026.11.5', updater.select_release([complete('2026.11.5'), broken, odd])['tag_name'])
        self.assertIn("skipping published release '2026.11.9': malformed release asset list", errors.getvalue())
        self.assertIn("'2026.11.8'", errors.getvalue())

    def test_the_api_and_the_feed_offer_the_same_releases(self):
        """One eligibility rule: the stable tag (carried by the signed manifest), whichever source
        answers. A hand-set GitHub pre-release flag the feed cannot see changes nothing."""
        def row(tag, flag):
            name = f'chronicle-selfhost-{tag}.tar.gz'
            return dict(tag_name=tag, draft=False, prerelease=flag, assets=[
                dict(name=item, browser_download_url='https://example.org/' + item) for item in (name, name + '.sha256', name + '.sha256.sig')])
        api = [row('2026.11.5', False), row('2026.11.6', True), row('2026.11.7-rc.1', False)]
        feed = ''.join(f'<link href="https://github.com/{updater.RELEASES_REPOSITORY}/releases/tag/{tag}"/>'
                       for tag in ('2026.11.5', '2026.11.6', '2026.11.7-rc.1')).encode()
        with patch('chronicle_ops.update.curl', return_value=feed):
            from_feed = updater.feed_releases(updater.FEED_RELEASES_URL)
        self.assertEqual([release['tag_name'] for release in api if updater.offered(release)],
                         [release['tag_name'] for release in from_feed if updater.offered(release)])
        self.assertEqual(updater.select_release(api)['tag_name'], updater.select_release(from_feed)['tag_name'])
        self.assertEqual('2026.11.6', updater.select_release(api)['tag_name'])

    def test_a_non_http_release_url_is_never_fetched_and_discovery_falls_back(self):
        asked = []
        with patch.dict(os.environ, {'CHRONICLE_RELEASES_URL': 'file:///etc/passwd'}), \
             patch('chronicle_ops.update.run', side_effect=lambda args, **_: asked.append(args[-1])
                   or subprocess.CompletedProcess(args, 0, b'[]')), \
             patch('sys.stderr', new_callable=io.StringIO) as errors:
            self.assertEqual([], updater.fetch_published_releases())
        self.assertEqual([updater.API_RELEASES_URL], asked)
        self.assertIn('release URL must use http or https', errors.getvalue())

if __name__ == '__main__':
    unittest.main()
