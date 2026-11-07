"""Operator regressions using synthetic installations and host probes."""

import gzip
import html
import json
import os
import re
from pathlib import Path
import io
import shlex
import shutil
import subprocess
import sys
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from test_secret_generation import ROOT, SelfhostSetupFixture
from chronicle_ops.common import GIB, MIN_FREE_INODES, storage_report
from chronicle_ops.envfile import parse_env_text, quote_env, set_env_values, value
from chronicle_ops.verify import disk_rows
from chronicle_ops.restore import Restore
from chronicle_ops.dump import RESTORE_MUTATION_MARKER
# At import, before any test patches common.run: update binds run by name on first import.
from chronicle_ops import common, update


def read_env_text(line):
    """One printed KEY=value line read with the operator settings grammar (export prefix, quotes, comments)."""
    settings = parse_env_text(line)
    (key,) = settings
    return key, value(settings, key)


class OpsDocsTests(SelfhostSetupFixture):
    def test_transfer_deadline_covers_downloads_and_image_pulls(self):
        elapsed = common.PREPARATION_TIMEOUT_SECONDS + 1
        pull = ['docker', 'compose', 'pull']
        for override in (None, '900', '', '0', '-1', '1.5'):
            for transport in ('archive', 'pull'):
                with self.subTest(override=override, transport=transport):
                    def finish(args, deadline):
                        if deadline < elapsed:
                            raise subprocess.TimeoutExpired(args, deadline)
                        return subprocess.CompletedProcess(args, 0, stdout=b'archive')
                    def download(args, **kwargs):
                        return finish(args, int(args[args.index('--max-time') + 1]))
                    process = MagicMock(pid=123456789, returncode=0)
                    def communicate(data=None, timeout=None):
                        if timeout is not None and timeout > 1:
                            return finish(pull, timeout).stdout, ''
                        return '', ''
                    process.communicate.side_effect = communicate
                    environment = {} if override is None else {common.TRANSFER_TIMEOUT_ENV: override}
                    with patch.dict(os.environ, environment, clear=True), \
                         patch('chronicle_ops.common.subprocess.run', side_effect=download) as downloaded, \
                         patch('chronicle_ops.common.spawn') as spawned, patch('chronicle_ops.common.os.killpg'):
                        spawned.return_value.__enter__.return_value = process
                        transfer = (lambda: update.curl('https://updates.invalid/archive.tar.gz')) if transport == 'archive' else (
                            lambda: common.run(pull, check=True))
                        if override == '900':
                            transfer()
                        elif override is None:
                            with self.assertRaises(subprocess.TimeoutExpired):
                                transfer()
                        else:
                            with self.assertRaisesRegex(ValueError, 'must be a positive integer'):
                                transfer()
                            downloaded.assert_not_called()
                            spawned.assert_not_called()

    def interrupted_restore(self, state, phase, no_start=False):
        state.mkdir(exist_ok=True)
        backups = state / 'backups'; backups.mkdir(exist_ok=True)
        operation = Restore(state, backups, '', '', '17', no_start, True)
        operation.lock.mkdir()
        (operation.lock / 'owner-pid').write_text(str(os.getpid()) + '\n')
        (operation.lock / 'phase').write_text(phase + '\n')
        (operation.lock / 'restore-file').write_text('/backups/reviewed.sql.gz\n')
        return operation

    def test_interrupted_committed_restore_can_recover_without_replaying_the_dump(self):
        for phase in ('database-restored', 'starting-services', 'verified'):
            for blocked in ('', 'active-container', 'mutation', 'database', 'startup'):
                with self.subTest(phase=phase, blocked=blocked):
                    state = self.host.parent / (phase + '-' + (blocked or 'success'))
                    operation = self.interrupted_restore(state, phase)
                    lock, backups = operation.lock, Path(operation.backups)
                    if blocked == 'mutation':
                        # Restore records database-restored before it removes the marker.
                        (backups / RESTORE_MUTATION_MARKER).touch()
                        blocked = ''
                    calls = []
                    def compose(*args, **kwargs):
                        calls.append(args)
                        output = ''
                        status = 0
                        if 'config' in args or 'ps' in args:
                            output = 'postgres\nbackend\nweb\nrestore' if 'config' in args else 'postgres'
                        if 'ps' in args and blocked == 'active-container':
                            output += '\nrestore'
                        if 'up' in args and blocked == 'startup':
                            status = 1
                        return SimpleNamespace(returncode=status, stdout=output)
                    with patch('chronicle_ops.restore.compose', side_effect=compose), \
                         patch('chronicle_ops.release.postgres_sql', side_effect=ValueError('database unavailable') if blocked == 'database' else None), \
                         patch('chronicle_ops.restore.finish_operation'), \
                         patch.dict(os.environ, CHRONICLE_OPS_PROJECT='fixture'), \
                         patch('sys.stdout', io.StringIO()), patch('sys.stderr', io.StringIO()):
                        result = operation.execute(recover=True)
                    self.assertEqual(int(bool(blocked)), result)
                    self.assertEqual(bool(blocked), lock.exists())
                    self.assertFalse(any('run' in call and 'restore' in call for call in calls))
                    if not blocked:
                        self.assertFalse((backups / RESTORE_MUTATION_MARKER).exists())

    def test_recovery_of_a_live_or_reused_owner_pid_acts_only_under_the_exclusive_operation_lock(self):
        import fcntl
        from chronicle_ops.common import OPERATION_LOCK
        operation = self.interrupted_restore(self.host, 'database-restored')  # owner-pid is this live process
        held = []
        def compose(*args, **kwargs):
            with open(self.host / OPERATION_LOCK, 'a') as probe:
                try:
                    fcntl.flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    held.append(False)
                except BlockingIOError:
                    held.append(True)
            return SimpleNamespace(returncode=0, stdout='postgres\nbackend\nweb\nrestore' if 'config' in args else 'postgres')
        with patch('chronicle_ops.restore.compose', side_effect=compose), patch('chronicle_ops.release.postgres_sql'), \
             patch('chronicle_ops.restore.finish_operation'), patch('sys.stdout', io.StringIO()), patch('sys.stderr', io.StringIO()):
            self.assertEqual(0, operation.execute(recover=True))
        self.assertFalse(operation.lock.exists())
        self.assertTrue(held)
        self.assertTrue(all(held), 'restore recovery ran a Compose step without holding the operation lock')

    def test_ambiguous_restore_outcome_keeps_its_evidence(self):
        operation = self.interrupted_restore(self.host, 'restoring')
        lock, marker = operation.lock, operation.mutation_marker
        marker.touch()
        with patch('chronicle_ops.restore.compose', return_value=SimpleNamespace(returncode=0, stdout='postgres')), \
             patch('chronicle_ops.restore.finish_operation'), \
             patch('sys.stdout', io.StringIO()), patch('sys.stderr', io.StringIO()) as errors:
            self.assertEqual(1, operation.execute(recover=True))
        self.assertIn('database outcome is uncertain', errors.getvalue())
        self.assertTrue(lock.exists())
        self.assertTrue(marker.exists())

    def test_interrupted_restore_before_mutation_releases_its_lock_and_restarts_services(self):
        # SIGHUP/SIGTERM after the services stopped keeps the lock; without the mutation marker the
        # database was provably never touched, so recovery must not strand the installation.
        from chronicle_ops.reconcile import STOP_MARKER
        for phase in ('prepared', 'stopping-services', 'restoring'):
            for no_start in (False, True):
                with self.subTest(phase=phase, no_start=no_start):
                    state = self.host.parent / f'{phase}-{no_start}'
                    operation = self.interrupted_restore(state, phase, no_start)
                    calls = []
                    def compose(*args, **kwargs):
                        calls.append(args)
                        return SimpleNamespace(returncode=0, stdout='postgres\nbackend\nweb\nrestore' if 'config' in args else 'postgres')
                    with patch('chronicle_ops.restore.compose', side_effect=compose), \
                         patch('chronicle_ops.release.postgres_sql') as query, \
                         patch('chronicle_ops.restore.finish_operation'), \
                         patch('sys.stdout', io.StringIO()) as output, patch('sys.stderr', io.StringIO()):
                        self.assertEqual(0, operation.execute(recover=True))
                    self.assertFalse(operation.lock.exists())
                    query.assert_not_called()
                    self.assertFalse(any('run' in call and 'restore' in call for call in calls))
                    restarted = [call for call in calls if call[:1] == ('up',)]
                    self.assertEqual([] if no_start else [('up', '-d', '--wait', '--wait-timeout', '17', '--no-deps', 'backend', 'web')],
                                     restarted)
                    self.assertEqual(no_start, (state / STOP_MARKER).exists())
                    self.assertIn('database was not replaced', output.getvalue())
                    self.assertNotIn('Restore complete', output.getvalue())

    def test_rollback_and_recover_share_the_restore_phase_rule(self):
        from chronicle_ops.restore import Rollback
        for phase, replays in (('prepared', True), ('restoring', True), ('database-restored', False),
                               ('starting-services', False), ('verified', False)):
            with self.subTest(phase=phase):
                state = self.host.parent / ('rollback-' + phase)
                self.interrupted_restore(state, phase)
                rollback = Rollback.__new__(Rollback)
                rollback.state, rollback.assume_yes, rollback.current, rollback.previous = state, True, state, state
                rollback.record = dict(dump='/backups/reviewed.sql.gz', sha256='a' * 64)
                with patch('chronicle_ops.restore.compose', return_value=SimpleNamespace(returncode=0, stdout='postgres')), \
                     patch('chronicle_ops.restore.Restore.execute', return_value=0) as replay:
                    rollback.restore_database()
                self.assertEqual(replays, replay.called)
                self.assertFalse((state / '.chronicle-restore.lock').exists())

    def test_recovered_no_start_remains_stopped_until_explicit_up(self):
        from chronicle_ops.reconcile import STOP_MARKER
        operation = self.interrupted_restore(self.host, 'database-restored', no_start=True)
        running = {'backend', 'web'}
        def compose(*args, **kwargs):
            if 'stop' in args:
                running.difference_update(args[1:])
            output = 'postgres\nbackend\nweb\nrestore' if 'config' in args else 'postgres\n' + '\n'.join(sorted(running))
            return SimpleNamespace(returncode=0, stdout=output)
        with patch('chronicle_ops.restore.compose', side_effect=compose) as calls, \
             patch('chronicle_ops.release.postgres_sql') as query, \
             patch('chronicle_ops.restore.finish_operation'), \
             patch('sys.stdout', io.StringIO()):
            self.assertEqual(0, operation.execute(recover=True))
        query.assert_called_once()
        self.assertFalse(any('up' in call.args for call in calls.call_args_list))
        self.assertTrue((self.host / STOP_MARKER).exists())
        self.assertFalse(operation.lock.exists())
        self.assertFalse(running, 'no-start recovery left application writers running')

    def test_incident_recipe_collects_receipts_from_relocated_state(self):
        self.run_setup()
        state = self.host.parent / 'relocated state'; state.mkdir()
        receipts = state / 'operator-receipts'; receipts.mkdir()
        (receipts / 'operation.json').write_text('{"synthetic":true}\n')
        (state / 'backups/last').mkdir(parents=True)
        (state / 'backups/last/reviewed.sql.gz').write_bytes(b'synthetic')
        settings = self.host / '.env'
        settings.write_text(set_env_values(settings.read_text(), {'CHRONICLE_STATE_DIR': str(state)}, require_existing=True))
        case = self.host.parent / 'case'; case.mkdir()
        guide = (ROOT / 'selfhost/docs/INCIDENT-RESPONSE.md').read_text()
        recipe = guide[guide.index('# Operator receipts:'):].split('```', 1)[0].rstrip().removesuffix(')')
        result = subprocess.run(['bash', '-eu', '-c', 'case_dir="$CASE_DIR"\n' + recipe],
            cwd=self.host, env=dict(self.environment, CASE_DIR=str(case)), capture_output=True, text=True, timeout=10)
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertEqual((receipts / 'operation.json').read_bytes(), (case / 'operator-receipts/operation.json').read_bytes())
        self.assertIn('reviewed.sql.gz', (case / 'file-listing.txt').read_text())

    def test_ca_replacement_recipe_moves_only_the_mounted_certificates(self):
        self.run_setup()
        names = ('internal-ca.crt', 'internal-ca.key', 'internal-cert.pem', 'internal-key.pem')
        docker = self.host.parent / 'bin/docker'
        docker.write_text('#!/bin/sh\nprintf "%s\\n" "$*" >>"$COMMAND_RECORD"\n')
        # `up` runs the launcher's real bundle-readability preflight (other host probes ignored) before the fixture regenerates certificates.
        script = '''#!/usr/bin/env bash
set -eu
printf '%s\\n' "$*" >>"$COMMAND_RECORD"
if [ "$1" = up ]; then
  (source ./chronicle
   dc() { :; }; foreign_project() { :; }; ok() { :; }; warn() { :; }
   bad() { [[ -z "${permission_repair:-}" ]] || { printf '%s\\n' "$1" >&2; exit 1; }; }
   preflight_environment)
  for name in $CERTIFICATE_NAMES; do
    test ! -e "$TLS_FIXTURE/$name"
    echo regenerated >"$TLS_FIXTURE/$name"
  done
fi
'''
        (self.host / 'service-fixture').write_text(script)
        (self.host / 'service-fixture').chmod(0o755)
        guide = (ROOT / 'selfhost/docs/SECRET-ROTATION.md').read_text().split('## Internal dashboard CA\n', 1)[1].split('\n## ', 1)[0]
        self.assertIn('```bash\n', guide, 'CA replacement needs a runnable recipe')
        recipe = guide.split('```bash\n', 1)[1].split('```', 1)[0]
        recipe = recipe.replace('./chronicle up', './service-fixture up')
        # The fixture copies these two privately; a signed bundle extracts them readable.
        self.host.chmod(0o755); (self.host / 'release-signing.pub').chmod(0o644)
        settings = self.host / '.env'
        original = settings.read_text()
        for relocated in (True, False):
            with self.subTest(relocated=relocated):
                state = self.host.parent / 'relocated state' if relocated else self.host
                tls = state / 'tls'; tls.mkdir(parents=True, exist_ok=True)
                (self.host / 'tls').mkdir(exist_ok=True)
                for name in names:
                    (tls / name).write_text('mounted ' + name)
                    if relocated:
                        (self.host / 'tls' / name).write_text('release ' + name)
                settings.write_text(set_env_values(original, {'CHRONICLE_STATE_DIR': str(state)}, require_existing=True)
                                    if relocated else original)
                record = self.host.parent / f'commands-{relocated}'
                result = subprocess.run(['bash', '-eu', '-c', recipe], cwd=self.host,
                    env=dict(self.environment, COMMAND_RECORD=str(record), TLS_FIXTURE=str(tls), CERTIFICATE_NAMES=' '.join(names)),
                    capture_output=True, text=True, timeout=10)
                self.assertEqual(0, result.returncode, result.stdout + result.stderr)
                for name in names:
                    self.assertEqual('regenerated\n', (tls / name).read_text())
                    if relocated:
                        self.assertEqual('release ' + name, (self.host / 'tls' / name).read_text())
                    archived = [path for path in state.rglob(name) if path.parent != tls]
                    self.assertEqual(1, len(archived))
                    self.assertEqual('mounted ' + name, archived[0].read_text())
                    self.assertEqual(0o700, archived[0].parent.stat().st_mode & 0o777)
                self.assertEqual(['compose stop web', 'up'], record.read_text().splitlines())

    def test_tls_renewal_recipe_resolves_supported_state_assignments(self):
        self.run_setup()
        original = (self.host / '.env').read_text()
        pair = self.host.parent / 'replacement'; pair.mkdir()
        for name in ('cert.pem', 'key.pem'):
            (pair / name).write_text('replacement ' + name)
        guide = (ROOT / 'selfhost/docs/MONITORING-RUNBOOK.md').read_text()
        recipe = guide.split('```bash\n', 1)[1].split('```', 1)[0]
        recipe = recipe.replace('/path/to/new-cert.pem', str(pair / 'cert.pem')).replace('/path/to/new-key.pem', str(pair / 'key.pem'))
        recipe = recipe.replace('./chronicle verify', 'true')
        (self.host.parent / 'bin/openssl').write_text('#!/bin/sh\ncat >/dev/null\n')
        for exported in (False, True):
            for relative in (False, True):
                with self.subTest(exported=exported, relative=relative):
                    state = self.host.parent / f'renewal-{exported}-{relative}'; (state / 'tls').mkdir(parents=True)
                    path = os.path.relpath(state, self.host) if relative else str(state)
                    updated = set_env_values(original, {'CHRONICLE_STATE_DIR': path}, require_existing=True)
                    assignment = 'CHRONICLE_STATE_DIR=' + quote_env(path)
                    (self.host / '.env').write_text(updated.replace(assignment,
                        ('export ' if exported else '') + assignment + ' # mounted state'))
                    result = subprocess.run(['bash', '-eu', '-c', recipe], cwd=self.host,
                        env=self.environment, capture_output=True, text=True, timeout=10)
                    self.assertEqual(0, result.returncode, result.stdout + result.stderr)
                    for name in ('cert.pem', 'key.pem'):
                        self.assertEqual((pair / name).read_bytes(), (state / 'tls' / name).read_bytes())

    @staticmethod
    def runbook_backup_commands():
        """Each operator command that names backups/ in the Markdown runbook and in the served HTML runbook."""
        markdown = (ROOT / 'selfhost/docs/MONITORING-RUNBOOK.md').read_text()
        fences = re.findall(r'```bash\n(.*?)```', markdown, re.S)
        spans = [span.replace('\\|', '|') for span in re.findall(r'`([^`\n]+)`', re.sub(r'```.*?```', '', markdown, flags=re.S))]
        page = (ROOT / 'selfhost/monitoring/runbooks.html').read_text()
        codes = [html.unescape(code) for code in re.findall(r'<code>(.*?)</code>', page, re.S)]
        def naming(commands):
            return sorted({command for command in commands if 'backups/' in command})
        return naming(fences + spans), naming(codes)

    def test_runbook_backup_checks_read_the_resolved_state_directory(self):
        self.run_setup()
        markdown, page = self.runbook_backup_commands()
        self.assertTrue(markdown, 'the runbook gives an operator backup check')
        self.assertEqual(markdown, page, 'both runbook representations give one wording')
        original = (self.host / '.env').read_text()
        release_dumps = self.host / 'backups/last'
        release_dumps.mkdir(parents=True, exist_ok=True)
        previous = self.host.parent / 'previous-release/selfhost'
        relocated = self.host.parent / 'relocated state'
        for mode, state, path in (
            ('default', self.host, '.'),
            ('updated-default', previous, str(previous)),
            ('relocated-absolute', relocated, str(relocated)),
            ('relocated-relative', relocated, os.path.relpath(relocated, self.host)),
        ):
            # An updated release has its own backups/ directory; nothing in it may decide the check.
            (release_dumps / 'chronicle-latest.sql.gz').write_bytes(b'not the mounted backup')
            dumps = state / 'backups/last'
            dumps.mkdir(parents=True, exist_ok=True)
            (self.host / '.env').write_text(set_env_values(original, {'CHRONICLE_STATE_DIR': path}, require_existing=True))
            for valid in (True, False):
                (dumps / 'chronicle-latest.sql.gz').write_bytes(gzip.compress(b'-- dump\n') if valid else b'corrupt dump')
                for command in markdown:
                    with self.subTest(mode=mode, valid=valid, command=command):
                        result = subprocess.run(['bash', '-eu', '-c', command], cwd=self.host,
                            env=self.environment, capture_output=True, text=True, timeout=10)
                        self.assertEqual(valid, result.returncode == 0, result.stdout + result.stderr)

    def test_readme_boundary_check_probes_the_public_https_origin(self):
        guide = (ROOT / 'selfhost/README.md').read_text()
        recipe = guide.split('Verify the boundary after starting', 1)[1].split('```bash\n', 1)[1].split('```', 1)[0]
        tools = self.host.parent / 'boundary-bin'
        tools.mkdir()
        (tools / 'curl').write_text('#!/bin/sh\nfor arg; do url=$arg; done\nprintf "%s\\n" "$url" >>"$CURL_RECORD"\nprintf 404\n')
        (tools / 'curl').chmod(0o755)
        record = self.host.parent / 'boundary-urls'
        origin = 'https://chronicle.example.test:8443'
        result = subprocess.run(['bash', '-eu', '-c', recipe.replace('https://<public-host>', origin)], cwd=self.host,
            env=dict(self.environment, PATH=str(tools) + os.pathsep + self.environment['PATH'], CURL_RECORD=str(record)),
            capture_output=True, text=True, timeout=10)
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        urls = record.read_text().splitlines() if record.exists() else []
        self.assertEqual(5, len(urls), f'the recipe must probe five routes: {urls} {result.stdout}')
        for url in urls:
            self.assertTrue(url.startswith(origin + '/'), f'{url} must go through the public HTTPS origin')
        self.assertEqual(['404'] * 5, [line.split()[0] for line in result.stdout.splitlines()])
        # A plain-HTTP probe of the pool port is only valid in the labelled plaintext-waiver mode.
        flattened = re.sub(r'```.*?```', lambda fence: fence.group(0).replace('\n\n', '\n'), guide, flags=re.S)
        paragraphs = re.split(r'\n\s*\n', flattened)
        for previous, paragraph in zip([''] + paragraphs, paragraphs):
            if re.search(r'http://\S*:8080', paragraph):
                self.assertIn('POOL_PLAINTEXT_WAIVER', previous + paragraph, paragraph)

    def test_pilot_export_guide_describes_attribution_and_optional_bounds(self):
        guide = (ROOT / 'docs/PILOT-DATA.md').read_text()
        for contract in ('no server-side export jobs', 'explicit participant IDs', 'date bounds are independently optional',
                         'positive range', 'UsageStats events',
                         'Supplemental Device Lifecycle events always have an empty `username`'):
            with self.subTest(contract=contract):
                self.assertIn(contract, guide)

    def test_fresh_host_recipe_restores_before_the_first_migration(self):
        guide = (ROOT / 'selfhost/docs/BACKUP-RESTORE.md').read_text()
        recipe = guide.split('## Recover onto a fresh host\n', 1)[1].split('```bash\n', 1)[1].split('```', 1)[0]
        launcher = self.host / 'chronicle'
        launcher.write_text('''#!/usr/bin/env bash
set -eu
case "$1" in
  setup) touch configured ;;
  restore) [[ -f configured && ! -f migrated ]]; touch restored ;;
  up) [[ -f restored ]]; touch migrated ;;
  verify|doctor) [[ -f restored && -f migrated ]] ;;
  *) exit 2 ;;
esac
''')
        result = subprocess.run(['bash', '-eu', '-c', recipe], cwd=self.host,
            env=dict(self.environment, TRUSTED_SHA256='a' * 64), capture_output=True, text=True, timeout=10)
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertTrue((self.host / 'migrated').exists())

    def test_configuration_verifier_does_not_require_yq(self):
        tools = self.host.parent / 'host-tools'
        tools.mkdir()
        for directory in ('/usr/bin', '/bin'):
            for command in Path(directory).iterdir():
                target = tools / command.name
                if command.is_file() and command.name != 'yq' and not target.exists():
                    target.symlink_to(command)
        (tools / 'python3').unlink()
        (tools / 'python3').symlink_to(sys.executable)
        docker = shutil.which('docker')
        self.assertIsNotNone(docker, 'Docker Compose CLI is required to render the configuration')
        (tools / 'docker').unlink(missing_ok=True)
        (tools / 'docker').symlink_to(docker)
        result = subprocess.run(['bash', str(ROOT / 'selfhost/verify-config.sh')],
            env=dict(self.environment, PATH=str(tools)), capture_output=True, text=True, timeout=30)
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)

    def test_backup_uses_the_sidecar_after_ownership_and_mutation_checks(self):
        script = '''source "$1"
need_env() { COMPOSE_FILE=overlays/backups.yml; }
lock_operation() { echo lock; }
ops_python() { echo "$*"; [[ "${REJECT_OWNER:-false}" != true ]]; }
assert_no_incomplete_mutation() { echo mutation-check; [[ "${REJECT_MUTATION:-false}" != true ]] || exit 1; }
begin_operation() { :; }
operation_succeeded() { echo success; }
dc() { echo "compose $*"; return "${BACKUP_STATUS:-0}"; }
validate_command_arguments backup
cmd_backup backup
'''
        for overrides, expected in (({}, 0), ({'REJECT_OWNER': 'true'}, 1),
                ({'REJECT_MUTATION': 'true'}, 1), ({'BACKUP_STATUS': '1'}, 1)):
            with self.subTest(overrides=overrides):
                result = subprocess.run(['bash', '-c', script, 'fixture', str(ROOT / 'selfhost/chronicle')],
                    env=dict(os.environ, **overrides), capture_output=True, text=True, timeout=10)
                self.assertEqual(expected, result.returncode, result.stdout + result.stderr)
                if expected == 0:
                    lines = result.stdout.splitlines()
                    self.assertLess(lines.index('lock'), lines.index('owner-check'))
                    self.assertLess(lines.index('owner-check'), lines.index('mutation-check'))
                    self.assertIn('--force-recreate', result.stdout)
                    self.assertIn('--wait', result.stdout)
                    self.assertIn('db-backup', result.stdout)
                    self.assertIn('success', lines)
                elif 'BACKUP_STATUS' not in overrides:
                    self.assertNotIn('compose ', result.stdout)

    def test_doctor_enforces_startup_byte_and_inode_reserves(self):
        for free, inodes, expected in ((3 * GIB, MIN_FREE_INODES, 'fail'),
                (6 * GIB, MIN_FREE_INODES - 1, 'fail'), (6 * GIB, MIN_FREE_INODES, 'ok')):
            disk = SimpleNamespace(f_bavail=free, f_bfree=free, f_blocks=2 * free, f_frsize=1, f_favail=inodes, f_files=1)
            with self.subTest(free=free, inodes=inodes), \
                 patch('chronicle_ops.common.run', return_value=SimpleNamespace(stdout='/docker')), \
                 patch('chronicle_ops.common.database_volume_path', return_value=Path('/db')), \
                 patch('chronicle_ops.common.os.statvfs', return_value=disk), \
                 patch.dict(os.environ, CHRONICLE_OPS_STATE='/state', CHRONICLE_OPS_PROJECT='fixture'):
                startup = storage_report('/state', 'fixture')
                rows = disk_rows({}, '/state')
            self.assertEqual(expected == 'ok', all(row[1] for row in startup))
            reserve = next((row for row in rows if row[0] == 'database-volume-reserve'), None)
            self.assertIsNotNone(reserve, rows)
            self.assertEqual(expected, reserve[1])

    UNINSTALL_DOCKER = r'''#!/usr/bin/env python3
"""Stateful Docker for the uninstall recipe: label inventories of two projects, nothing else."""
import json, os, sys
from pathlib import Path
state = Path(os.environ['DOCKER_INVENTORY'])
inventory = json.loads(state.read_text())
args = sys.argv[1:]
with open(os.environ['DOCKER_RECORD'], 'a') as record:
    record.write(' '.join(args) + '\n')
    if args[:2] == ['compose', 'down'] and '--volumes' in args:
        crontab = Path(os.environ['CRONTAB_STORE'])
        scheduled = [line for line in (crontab.read_text().splitlines() if crontab.exists() else [])
                     if line.endswith('# chronicle-reconcile:' + os.environ['FIXTURE_ACTIVE_PROJECT'])]
        record.write('schedule-at-storage-removal ' + json.dumps(scheduled) + '\n')

def labelled(kind):
    selector = next((value for value in args if value.startswith('label=com.docker.compose.project=')), None)
    project = selector.split('=', 2)[2] if selector else None
    return [row['name'] for row in inventory[kind] if project is None or row['project'] == project]

def project_of_cwd():
    for line in Path('.env').read_text().splitlines():
        if line.startswith('COMPOSE_PROJECT_NAME='):
            return line.split('=', 1)[1].strip("'\"")
    sys.exit('fixture: no project')

if args[:4] == ['compose', 'ls', '--all', '--format']:
    print(json.dumps([dict(Name=name, ConfigFiles=config) for name, config in inventory['projects'].items()]))
elif args[:1] == ['compose'] and 'down' in args:
    project = args[args.index('-p') + 1] if '-p' in args else project_of_cwd()
    inventory['containers'] = [row for row in inventory['containers'] if row['project'] != project]
    if '--volumes' in args:  # Compose removes only the volumes the current COMPOSE_FILE declares.
        inventory['volumes'] = [row for row in inventory['volumes'] if row['project'] != project or row['obsolete']]
elif args[:2] == ['volume', 'ls']:
    print('\n'.join(labelled('volumes')))
elif args[:2] == ['ps', '-a']:
    print('\n'.join(labelled('containers')))
elif args[:2] == ['volume', 'inspect']:
    row = next((row for row in inventory['volumes'] if row['name'] == args[2]), None)
    if row is None:
        sys.exit('Error: No such volume: ' + args[2])
    print(json.dumps([dict(Name=row['name'], Labels={'com.docker.compose.project': row['project']})]))
elif args[:2] == ['volume', 'rm']:
    if not any(row['name'] == args[2] for row in inventory['volumes']):
        sys.exit('Error: No such volume: ' + args[2])
    inventory['volumes'] = [row for row in inventory['volumes'] if row['name'] != args[2]]
state.write_text(json.dumps(inventory))
'''

    def test_uninstall_recipe_removes_only_the_recorded_project(self):
        from chronicle_ops.reconcile import STOP_MARKER
        from test_operator_runtime_guards import crontab_fixture
        guide = (ROOT / 'selfhost/docs/UNINSTALL-DATA-DELETION.md').read_text()
        section = guide.split('## Remove the application and all installation storage\n', 1)[1].split('\n## ', 1)[0]
        blocks = [block.split('```', 1)[0] for block in section.split('```bash\n')[1:]]
        self.assertEqual(8, len(blocks), 'the uninstall recipe changed shape; update this walk-through')
        schedule, boundary, inventory_volumes, compose_down, remove_volume, inspect_state, delete_state, verify = blocks
        for exported, confirmation in ((False, None), (True, None), (False, 'a mistyped path')):
            with self.subTest(exported=exported, confirmation=confirmation):
                root = Path(self.folder.name) / f'case-{exported}-{bool(confirmation)}'; root.mkdir()
                host = root / 'selfhost'
                import shutil
                shutil.copytree(self.host, host, symlinks=True)
                state = root / 'operator state'; (state / 'backups/last').mkdir(parents=True); (state / 'tls').mkdir()
                (state / 'backups/last/chronicle-reviewed.sql.gz').write_bytes(b'synthetic')
                other_state = root / 'other state'; other_state.mkdir()
                settings = host / '.env'
                if not settings.exists():
                    self.run_setup(); shutil.copy2(self.host / '.env', settings)
                text = set_env_values(settings.read_text(), {'COMPOSE_PROJECT_NAME': 'pilot-study', 'CHRONICLE_STATE_DIR': str(state)},
                                      require_existing=True)
                if exported:
                    text = text.replace('CHRONICLE_STATE_DIR=', '  export CHRONICLE_STATE_DIR=', 1)
                settings.write_text(text)
                store, environment = crontab_fixture(root)
                other_jobs = ['0 1 * * * /usr/local/bin/nightly-report',
                              f"@reboot '{other_state}/reconcile.sh' # chronicle-reconcile:other-study"]
                store.write_text('\n'.join(other_jobs + [f"@reboot '{state}/reconcile.sh' # chronicle-reconcile:pilot-study"]) + '\n')
                inventory = root / 'docker.json'
                inventory.write_text(json.dumps(dict(
                    projects={'pilot-study': str(host / 'docker-compose.yml'), 'other-study': str(root / 'other/docker-compose.yml')},
                    containers=[dict(name=f'{project}-{service}-1', project=project)
                                for project in ('pilot-study', 'other-study') for service in ('postgres', 'backend')],
                    volumes=[dict(name=f'{project}_{volume}', project=project, obsolete=volume == 'grafana_data')
                             for project in ('pilot-study', 'other-study') for volume in ('postgres_data', 'grafana_data')])))
                record = root / 'docker-record'
                (root / 'bin/docker').write_text(self.UNINSTALL_DOCKER); (root / 'bin/docker').chmod(0o755)
                environment = dict(self.environment, HOME=environment['HOME'], CRONTAB_STORE=str(store),
                                   CRONTAB_BARRIER=environment['CRONTAB_BARRIER'], CRONTAB_READERS='1',
                                   DOCKER_INVENTORY=str(inventory), DOCKER_RECORD=str(record), FIXTURE_ACTIVE_PROJECT='pilot-study')
                environment['PATH'] = str(root / 'bin') + os.pathsep + self.environment['PATH']

                def step(script, cwd=host, stdin=''):
                    return subprocess.run(['bash', '-eu', '-o', 'pipefail', '-c', script], cwd=cwd, env=environment,
                                          input=stdin, capture_output=True, text=True, timeout=60)

                done = step(schedule)
                self.assertEqual(0, done.returncode, done.stdout + done.stderr)
                self.assertTrue((state / STOP_MARKER).exists())
                self.assertEqual(other_jobs, store.read_text().splitlines())
                recorded = step(boundary)
                self.assertEqual(0, recorded.returncode, recorded.stderr)
                # The operator records exactly what the recipe printed; nothing else tells them the boundary.
                printed = dict(read_env_text(line) for line in recorded.stdout.splitlines() if '=' in line)
                self.assertEqual('pilot-study', printed.get('COMPOSE_PROJECT_NAME'), recorded.stdout)
                self.assertEqual(str(state), printed.get('CHRONICLE_STATE_DIR'), recorded.stdout)
                self.assertEqual(str(host), recorded.stdout.splitlines()[-1])
                project, state_path = printed['COMPOSE_PROJECT_NAME'], printed['CHRONICLE_STATE_DIR']
                self.assertEqual(0, step(compose_down).returncode)
                remaining = step(inventory_volumes.replace('EXACT_PROJECT_NAME', project)).stdout.split()
                self.assertEqual(['pilot-study_grafana_data'], remaining, 'the obsolete overlay volume must be listed')
                for name in remaining:
                    self.assertEqual(0, step(remove_volume.replace('EXACT_VOLUME_NAME', name)).returncode)
                self.assertIn('schedule-at-storage-removal []', record.read_text())
                # The placeholder stands for one shell word; a path with a space is typed quoted.
                self.assertEqual(0, step(inspect_state.replace('/ABSOLUTE/CHRONICLE_STATE_DIR', shlex.quote(state_path))).returncode)
                deletion = step(delete_state.replace('/ABSOLUTE/CHRONICLE_STATE_DIR', shlex.quote(state_path)), cwd=root,
                                stdin=(confirmation or state_path) + '\n')
                if confirmation:
                    self.assertNotEqual(0, deletion.returncode)
                    self.assertTrue((state / 'backups/last/chronicle-reviewed.sql.gz').exists())
                    continue
                self.assertEqual(0, deletion.returncode, deletion.stdout + deletion.stderr)
                self.assertFalse(state.exists())
                self.assertTrue(other_state.exists() and host.exists())
                self.assertEqual('', step(verify.replace('EXACT_PROJECT_NAME', project)).stdout.strip())
                left = json.loads(inventory.read_text())
                self.assertEqual(['other-study-postgres-1', 'other-study-backend-1'], [row['name'] for row in left['containers']])
                self.assertEqual(['other-study_postgres_data', 'other-study_grafana_data'], [row['name'] for row in left['volumes']])
                self.assertEqual(other_jobs, store.read_text().splitlines())
