"""Class regressions for release startup, bounded logging and operator recovery."""
import configparser
import fcntl
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import unittest
from unittest.mock import patch

import yaml

from chronicle_ops import reconcile
from chronicle_ops.__main__ import argument_parser
from chronicle_ops.dump import publish_backup
from test_restore import DUMP

ROOT = Path(__file__).resolve().parents[2]


class UpstreamRuntimeTests(unittest.TestCase):
    def test_smoke_cleanup_stops_an_interrupted_startup_process_group(self):
        source = (ROOT / 'tests/smoke/selfhost-release-smoke.sh').read_text()
        cleanup = 'cleanup() {\n' + source.split('cleanup() {\n', 1)[1].split('\n}\ntrap cleanup EXIT', 1)[0] + '\n}\n'
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / 'crontab-before').touch()
            # A parent with a persistent child, like ./chronicle up and its Compose process.
            startup = subprocess.Popen(['bash', '-c', 'sleep 60 & echo $!; wait'], start_new_session=True,
                                       stdout=subprocess.PIPE, text=True)
            child = int(startup.stdout.readline())
            try:
                script = ('set -eu\noperator_crontab() { :; }\n' + cleanup + '\ncleanup\n')
                result = subprocess.run(['bash', '-c', script], capture_output=True, text=True, timeout=10,
                    env=dict(os.environ, RUN_DIR=folder, BUNDLE='', PROJECT='', TLS_PROXY_CONTAINER='',
                             REDIRECT_SERVER_PID='', DOCKER_EVENT_PIDS='', SMOKE_PASSED='true', interrupted_up=str(startup.pid)))
                self.assertEqual(0, result.returncode, result.stderr)
                try:
                    startup.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    self.fail('smoke cleanup left the startup process running')
                for _ in range(50):
                    if not Path(f'/proc/{child}').exists() or Path(f'/proc/{child}/stat').read_text().split()[2] == 'Z':
                        break
                    time.sleep(0.1)
                else:
                    self.fail('smoke cleanup left the startup child (Compose) running')
            finally:
                startup.kill()
                startup.wait(timeout=10)
                startup.stdout.close()
                try:
                    os.kill(child, 9)
                except ProcessLookupError:
                    pass

    def test_empty_argv_is_help(self):
        result = subprocess.run(['bash', str(ROOT / 'selfhost/chronicle')], capture_output=True, timeout=10)
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn(b'./chronicle setup', result.stdout)

    def test_reset_release_refuses_all_in_place_handoffs_before_reading_old_state(self):
        for command in ('upgrade', 'adopt'):
            result = subprocess.run(['bash', str(ROOT / 'selfhost/chronicle'), command, '--from', '/nonexistent'],
                                    capture_output=True, text=True, timeout=10)
            self.assertNotEqual(0, result.returncode)
            self.assertIn("unknown command", result.stderr)

    def test_digest_spellings_have_one_canonical_cli_value(self):
        import hashlib
        digest = hashlib.sha256(DUMP).hexdigest()
        for command, arguments in [('restore', []), ('rollback', ['--from', '/fixture', 'fixture.sql.gz'])]:
            for spelling in (digest, digest.upper(), ''.join(c.upper() if i % 2 else c for i, c in enumerate(digest))):
                with self.subTest(command=command, spelling=spelling):
                    parsed = argument_parser().parse_args([command, '--trusted-sha256', spelling, *arguments])
                    self.assertEqual(digest, parsed.trusted_sha256)

    def test_proxy_defaults_follow_every_mode_and_listener_shape(self):
        import ipaddress
        from chronicle_ops.common import compose_gateway
        from chronicle_ops.envfile import read_env, value
        host = ROOT / 'selfhost'
        gateway = compose_gateway(value(read_env(host / '.env.example'), 'CHRONICLE_SUBNET'))
        overlays = host / 'overlays'
        proxy_mode = yaml.safe_load((overlays / 'mode-behind-proxy-internal.yml').read_text())['services']['config-guard']['environment']['TLS_MODE']
        for overlay in overlays.glob('mode-*.yml'):
            mode = yaml.safe_load(overlay.read_text())['services']['config-guard']['environment']['TLS_MODE']
            for bind in ('0.0.0.0', '::', '127.0.0.1', '::1'):
                with self.subTest(mode=mode, bind=bind):
                    result = subprocess.run(['bash', '-c', 'source "$1"; trusted_proxy_sources "$2" "$3" "$4" ""',
                        'fixture', str(host / 'network-policy.sh'), mode, bind, gateway], capture_output=True, text=True)
                    if mode == proxy_mode and not ipaddress.ip_address(bind).is_loopback:
                        self.assertNotEqual(0, result.returncode)
                    else:
                        self.assertEqual(0, result.returncode, result.stderr)
                        networks = [ipaddress.ip_network(cidr) for cidr in result.stdout.split()]
                        if mode == proxy_mode:
                            self.assertTrue(any(ipaddress.ip_address(gateway) in network for network in networks))
                        else:
                            self.assertTrue(all(network.network_address.is_loopback for network in networks))

    def test_disabling_reconciliation_removes_only_this_projects_jobs(self):
        with tempfile.TemporaryDirectory() as folder:
            state = Path(folder)
            (state / 'reconcile.sh').write_text('old launcher')
            existing = '0 1 * * * unrelated\n@reboot old # chronicle-reconcile:fixture\n'
            def run(argv, **kwargs):
                return subprocess.CompletedProcess(argv, 0, existing if '-l' in argv else '', '')
            with patch.dict(os.environ, HOME=folder, CHRONICLE_RECONCILE_ENABLED='false'), \
                 patch('chronicle_ops.reconcile.run', side_effect=run) as calls, \
                 patch('chronicle_ops.reconcile.shutil.which', return_value='/bin/crontab'):
                reconcile.install(state / 'chronicle', state, 'fixture')
            writes = [call.kwargs['input'] for call in calls.call_args_list if call.args[0] == ['crontab', '-']]
            self.assertEqual(['0 1 * * * unrelated\n'], writes)
            self.assertFalse((state / 'reconcile.sh').exists())

    def test_generated_certificates_are_mounted_as_directories(self):
        services = yaml.safe_load((ROOT / 'selfhost/overlays/monitoring.yml').read_text())['services']
        for name, service in services.items():
            for mount in service.get('volumes', []):
                source = mount.split(':')[0] if isinstance(mount, str) else mount.get('source', '')
                if '${CHRONICLE_STATE_DIR' in source:
                    with self.subTest(service=name, source=source):
                        self.assertNotIn(Path(source).suffix, ('.crt', '.key', '.pem', '.p12'))

    def test_no_service_installs_plugins_at_startup(self):
        for path in (ROOT / 'selfhost').rglob('*.yml'):
            config = yaml.safe_load(path.read_text()) or {}
            for name, service in config.get('services', {}).items():
                for key, value in service.get('environment', {}).items():
                    with self.subTest(path=path, service=name, key=key):
                        if key == 'GF_PLUGINS_PREINSTALL_DISABLED':  # the switch that turns preinstall off
                            self.assertEqual('true', str(value).lower())
                            continue
                        self.assertFalse(key.startswith(('GF_INSTALL_PLUGINS', 'GF_PLUGINS_PREINSTALL'))
                                         and str(value).lower() not in ('false', '', 'none'))

    def test_every_log_input_and_unlimited_output_has_a_bound(self):
        from chronicle_ops.host_memory import FLUENT_BIT_CHUNK_SOFT_LIMIT_BYTES, memory_bytes
        from chronicle_ops.images import bundle_config
        # Fluent Bit permits repeated sections; ConfigParser parses one section at a time.
        text = (ROOT / 'selfhost/monitoring/fluent-bit.conf').read_text()
        memory = 0
        for chunk in text.split('\n['):
            parser = configparser.ConfigParser(delimiters=(' ',), comment_prefixes=('#',), strict=True)
            lines = [line.strip() for line in chunk.splitlines() if line.strip() and not line.startswith('#')]
            if not lines:
                continue
            section = lines[0].strip('[]')
            parser.read_string('[' + section + ']\n' + '\n'.join(lines[1:]))
            options = parser[section]
            if section == 'SERVICE':
                memory += int(options['storage.max_chunks_up']) * FLUENT_BIT_CHUNK_SOFT_LIMIT_BYTES
            if section == 'INPUT':
                self.assertTrue('mem_buf_limit' in options or options.get('storage.type') == 'filesystem', chunk)
                memory += memory_bytes(options.get('mem_buf_limit', '0'))
            if section == 'OUTPUT' and options.get('retry_limit', '').lower() == 'false':
                self.assertIn('storage.total_limit_size', options)
        limit = bundle_config(ROOT / 'selfhost')['services']['fluent-bit']['mem_limit']
        self.assertLess(memory, memory_bytes(limit))

    def test_backup_retention_refuses_non_numeric_ages(self):
        with tempfile.TemporaryDirectory() as folder:
            environment = dict(os.environ, POSTGRES_DB='chronicle', POSTGRES_DB_FILE='**None**', POSTGRES_HOST='db',
                               POSTGRES_USER='u', POSTGRES_USER_FILE='**None**', POSTGRES_PASSWORD='p',
                               POSTGRES_PASSWORD_FILE='**None**', POSTGRES_PASSFILE_STORE='**None**',
                               BACKUP_DIR=folder, BACKUP_KEEP_MINS='1440', BACKUP_KEEP_DAYS='14',
                               BACKUP_KEEP_WEEKS='8', BACKUP_KEEP_MONTHS='6')
            script = ['bash', '-c', 'source "$1"; echo "$KEEP_WEEKS"', 'env', str(ROOT / 'selfhost/backup-image/env.sh')]
            accepted = subprocess.run(script, env=environment, capture_output=True, text=True, timeout=10)
            self.assertEqual((0, '57'), (accepted.returncode, accepted.stdout.strip().splitlines()[-1]), accepted.stderr)
            kept = subprocess.run(script, env=dict(environment, BACKUP_KEEP_WEEKS='all'), capture_output=True, text=True, timeout=10)
            self.assertEqual((0, 'all'), (kept.returncode, kept.stdout.strip().splitlines()[-1]), kept.stderr)
            for invalid in ('weeks', '-1', '08', '1e3'):
                with self.subTest(invalid=invalid):
                    refused = subprocess.run(script, env=dict(environment, BACKUP_KEEP_WEEKS=invalid),
                                             capture_output=True, text=True, timeout=10)
                    self.assertNotEqual(0, refused.returncode)
                    self.assertIn('BACKUP_KEEP_WEEKS must be', refused.stdout)

    def test_backup_prunes_expired_history_even_when_new_dump_fails(self):
        import gzip
        for keep in ('1', 'all'):
            with self.subTest(keep=keep), tempfile.TemporaryDirectory() as folder:
                root = Path(folder); image = root / 'image'; image.mkdir(); backups = root / 'backups'; backups.mkdir()
                shutil.copy2(ROOT / 'selfhost/backup-image/backup.sh', image)
                (image / 'env.sh').write_text(f'POSTGRES_DBS=chronicle\nKEEP_MINS=1\nKEEP_DAYS={keep}\nKEEP_WEEKS={keep}\nKEEP_MONTHS={keep}\n')
                (image / 'selfcheck.sh').write_text('#!/bin/sh\nexit 1\n'); (image / 'selfcheck.sh').chmod(0o700)
                expired = []
                for bucket in ('last', 'daily', 'weekly', 'monthly'):
                    directory = backups / bucket; directory.mkdir()
                    old = directory / 'chronicle-expired.sql.gz'; old.write_bytes(gzip.compress(DUMP))
                    os.utime(old, (0, 0)); expired.append(old)
                verified = backups / 'last/chronicle-verified.sql.gz'; verified.write_bytes(gzip.compress(DUMP))
                publish_backup(verified, 'chronicle', {})
                os.utime(verified, (0, 0))
                result = subprocess.run(['bash', str(image / 'backup.sh')], capture_output=True, timeout=10,
                    env=dict(os.environ, BACKUP_DIR=str(backups), BACKUP_SUFFIX='.sql.gz', POSTGRES_HOST='fixture',
                             POSTGRES_CLUSTER='FALSE', POSTGRES_EXTRA_OPTS='', BACKUP_SUCCESS_MARKER=str(root / 'success')))
                self.assertNotEqual(0, result.returncode)
                self.assertIn(b'Creating dump', result.stdout, result.stderr)  # pruning finished; the dump failed
                # "all" keeps a tier forever; the last/ tier still follows KEEP_MINS.
                survivors = [path.parent.name for path in expired if path.exists()]
                self.assertEqual([] if keep == '1' else ['daily', 'weekly', 'monthly'], survivors, result.stderr)
                self.assertTrue(verified.exists(), 'last verified recovery point was pruned')

    def test_low_disk_rejection_follows_pruning_and_preserves_verified_backup(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); image = root / 'image'; image.mkdir(); backups = root / 'backups'; backups.mkdir()
            shutil.copy2(ROOT / 'selfhost/backup-image/backup.sh', image)
            (image / 'env.sh').write_text('POSTGRES_DBS=chronicle\nKEEP_MINS=1\nKEEP_DAYS=1\nKEEP_WEEKS=1\nKEEP_MONTHS=1\n')
            for bucket in ('last', 'daily', 'weekly', 'monthly'):
                (backups / bucket).mkdir()
            verified = backups / 'last/chronicle-verified.sql.gz'
            import gzip
            verified.write_bytes(gzip.compress(DUMP)); publish_backup(verified, 'chronicle', {})
            expired = backups / 'daily/chronicle-expired.sql.gz'; expired.touch(); os.utime(expired, (0, 0))
            second_expired = backups / 'daily/second-expired.sql.gz'; second_expired.touch(); os.utime(second_expired, (0, 0))
            (image / 'env.sh').write_text('POSTGRES_DBS="chronicle second"\nKEEP_MINS=1\nKEEP_DAYS=1\nKEEP_WEEKS=1\nKEEP_MONTHS=1\n')
            result = subprocess.run(['bash', str(image / 'backup.sh')], capture_output=True, text=True,
                env=dict(os.environ, BACKUP_DIR=str(backups), BACKUP_SUFFIX='.sql.gz', POSTGRES_HOST='fixture',
                         MIN_FREE_DISK_GIB='999999', BACKUP_SUCCESS_MARKER=str(root / 'success')))
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('MIN_FREE_DISK_GIB', result.stderr)
            self.assertFalse(expired.exists())
            self.assertFalse(second_expired.exists(), 'every database must prune before the disk guard')
            self.assertTrue(verified.exists())

    def test_successful_runs_roll_tiers_over_midnight_iso_year_and_month_end(self):
        """Seven verified runs on the sidecar's UTC clock (no TZ, no /etc/localtime in its image). 2026-12-31 and
        2027-01-01 are both ISO week 2026-W53; 2027-01-31 is 2027-W04 and 2027-02-01 is 2027-W05. Survivors are
        written out from find's whole-day ages (-mtime +N), KEEP_WEEKS*7+1 and KEEP_MONTHS*31+1 days."""
        import datetime
        runs = dict(A='2026-12-01T03:00:00', B='2026-12-24T03:00:00', C='2026-12-31T23:59:30', D='2027-01-01T00:00:30',
                    E='2027-01-31T23:59:00', F='2027-02-01T00:01:00', G='2027-02-02T03:00:00')
        last_name = {run: 'chronicle-' + moment.replace('-', '').replace(':', '').replace('T', '-') + '.sql.gz'
                     for run, moment in runs.items()}
        expected = {
            ('1', '2', '1'): dict(daily={'20270131': 'E', '20270201': 'F', '20270202': 'G'},
                                  weekly={'202704': 'E', '202705': 'G'},
                                  monthly={'202612': 'C', '202701': 'E', '202702': 'G'}),
            ('0', '0', '0'): dict(daily={'20270201': 'F', '20270202': 'G'}, weekly={'202704': 'E', '202705': 'G'},
                                  monthly={'202701': 'E', '202702': 'G'}),
            ('all', 'all', 'all'): dict(
                daily={'20261201': 'A', '20261224': 'B', '20261231': 'C', '20270101': 'D', '20270131': 'E',
                       '20270201': 'F', '20270202': 'G'},
                weekly={'202649': 'A', '202652': 'B', '202653': 'D', '202704': 'E', '202705': 'G'},
                monthly={'202612': 'C', '202701': 'E', '202702': 'G'})}
        for (weeks, days, months), tiers in expected.items():
            with self.subTest(days=days, weeks=weeks, months=months), tempfile.TemporaryDirectory() as folder:
                root = Path(folder); image = root / 'image'; image.mkdir(); backups = root / 'backups'; backups.mkdir()
                commands = root / 'bin'; commands.mkdir()
                shutil.copy2(ROOT / 'selfhost/backup-image/backup.sh', image)
                (image / 'env.sh').write_text(f'POSTGRES_DBS=chronicle\nKEEP_MINS=1440\nKEEP_DAYS={days}\n'
                                              f'KEEP_WEEKS={weeks if weeks == "all" else int(weeks) * 7 + 1}\n'
                                              f'KEEP_MONTHS={months if months == "all" else int(months) * 31 + 1}\n')
                (image / 'selfcheck.sh').write_text(
                    '#!/usr/bin/env python3\nimport gzip, sys\nfrom chronicle_ops.dump import publish_backup\n'
                    f'open(sys.argv[3], "xb").write(gzip.compress({DUMP!r}))\npublish_backup(sys.argv[3], sys.argv[2], {{}})\n')
                (image / 'selfcheck.sh').chmod(0o700)
                import shlex
                date_program = shutil.which('gdate') or shutil.which('date')
                self.assertIsNotNone(date_program)
                (commands / 'date').write_text('#!/bin/sh\nexec ' + shlex.quote(date_program) + ' -u -d "@$FIXTURE_EPOCH" "$@"\n')
                (commands / 'date').chmod(0o700)
                created = {}  # inode -> fixture time it was written, so every age follows the simulated clock
                inode = {}
                for run, moment in runs.items():
                    now = datetime.datetime.fromisoformat(moment).replace(tzinfo=datetime.timezone.utc).timestamp()
                    real = time.time()
                    for path in backups.rglob('chronicle-*.sql.gz'):
                        if not path.is_symlink():
                            age = now - created[path.stat().st_ino]
                            os.utime(path, (real - age, real - age))
                    result = subprocess.run(['bash', str(image / 'backup.sh')], capture_output=True, text=True, timeout=30,
                        env=dict(os.environ, PATH=str(commands) + os.pathsep + os.environ['PATH'], FIXTURE_EPOCH=str(int(now)),
                                 BACKUP_DIR=str(backups), BACKUP_SUFFIX='.sql.gz', POSTGRES_HOST='fixture', POSTGRES_CLUSTER='FALSE',
                                 POSTGRES_EXTRA_OPTS='', BACKUP_LATEST_TYPE='symlink', BACKUP_SUCCESS_MARKER=str(root / 'success')))
                    self.assertEqual(0, result.returncode, result.stdout + result.stderr)
                    inode[run] = (backups / 'last' / last_name[run]).stat().st_ino
                    created[inode[run]] = now
                for tier, survivors in tiers.items():
                    files = {path.name[len('chronicle-'):-len('.sql.gz')]: path for path in (backups / tier).iterdir()
                             if path.name.endswith('.sql.gz') and not path.is_symlink()}
                    self.assertEqual(set(survivors), set(files), tier)
                    for stamp, run in survivors.items():
                        self.assertEqual(inode[run], files[stamp].stat().st_ino, (tier, stamp, run))
                    newest = backups / tier / 'chronicle-latest.sql.gz'
                    self.assertTrue(newest.is_symlink())
                    self.assertEqual(inode['G'], newest.stat().st_ino, (tier, os.readlink(newest)))
                self.assertEqual({last_name['F'], last_name['G']},
                                 {path.name for path in (backups / 'last').glob('chronicle-2*.sql.gz')})
                self.assertEqual(last_name['G'], json.loads((backups / 'last/chronicle-verified.json').read_text())['file'])
                self.assertEqual([str(backups / 'daily/chronicle-20270202.sql.gz')], (root / 'success').read_text().splitlines())
                # A tier link that cannot be published fails the run and withdraws the success marker; the new dump
                # stays the verified recovery point and the earlier weekly link is left as it was.
                (commands / 'ln').write_text('#!/bin/sh\ncase "$*" in */weekly/*) exit 1 ;; esac\nexec /usr/bin/ln "$@"\n')
                (commands / 'ln').chmod(0o700)
                failed = subprocess.run(['bash', str(image / 'backup.sh')], capture_output=True, text=True, timeout=30,
                    env=dict(os.environ, PATH=str(commands) + os.pathsep + os.environ['PATH'], FIXTURE_EPOCH=str(int(now) + 3600),
                             BACKUP_DIR=str(backups), BACKUP_SUFFIX='.sql.gz', POSTGRES_HOST='fixture', POSTGRES_CLUSTER='FALSE',
                             POSTGRES_EXTRA_OPTS='', BACKUP_LATEST_TYPE='symlink', BACKUP_SUCCESS_MARKER=str(root / 'success')))
                self.assertNotEqual(0, failed.returncode)
                self.assertFalse((root / 'success').exists(), 'a failed tier publication left the success marker')
                self.assertEqual(inode['G'], (backups / 'weekly/chronicle-202705.sql.gz').stat().st_ino)
                marker = json.loads((backups / 'last/chronicle-verified.json').read_text())
                self.assertEqual('chronicle-20270202-040000.sql.gz', marker['file'])
                self.assertTrue((backups / 'last' / marker['file']).is_file())
                # A competing run steps aside: exit 0 (go-cron serves 503 after any failed run), health and links intact.
                success = root / 'success'
                success.write_text(str(backups / 'weekly/chronicle-202705.sql.gz') + '\n')
                previous_success = success.read_bytes()
                with (backups / '.backup.lock').open('w') as lock:
                    fcntl.flock(lock, fcntl.LOCK_EX)
                    busy = subprocess.run(['bash', str(image / 'backup.sh')], capture_output=True, text=True, timeout=10,
                        env=dict(os.environ, PATH=str(commands) + os.pathsep + os.environ['PATH'], FIXTURE_EPOCH=str(int(now) + 7200),
                                 BACKUP_DIR=str(backups), BACKUP_SUFFIX='.sql.gz', POSTGRES_HOST='fixture', POSTGRES_CLUSTER='FALSE',
                                 POSTGRES_EXTRA_OPTS='', BACKUP_LATEST_TYPE='symlink', BACKUP_SUCCESS_MARKER=str(success)))
                self.assertEqual(0, busy.returncode, busy.stderr)
                self.assertIn('Backup skipped: another backup run is still publishing', busy.stderr)
                self.assertEqual(previous_success, success.read_bytes())
                self.assertEqual(inode['G'], (backups / 'weekly/chronicle-202705.sql.gz').stat().st_ino)

    def test_pre_backup_prunes_expired_safety_dumps_before_space_admission(self):
        with tempfile.TemporaryDirectory() as folder:
            expired = Path(folder) / 'pre-upgrade-expired.sql.gz'; expired.touch(); os.utime(expired, (0, 0))
            result = subprocess.run(['bash', str(ROOT / 'selfhost/backup-prune-hook.sh'), 'pre-backup'],
                capture_output=True, text=True, env=dict(os.environ, BACKUP_DIR=folder,
                    PRE_OP_BACKUP_KEEP_DAYS='1', MIN_FREE_DISK_GIB='999999'))
            self.assertFalse(expired.exists(), result.stderr)

    def test_css_names_follow_final_bytes_after_font_rewriting(self):
        import hashlib
        files = list((ROOT / 'chronicle-web/dist').glob('*.css'))
        self.assertTrue(files, 'run bun run build before this regression')
        for path in files:
            digest = hashlib.sha256(path.read_bytes()).hexdigest()[:8]
            self.assertIn(digest, path.stem)

    def test_web_serves_its_own_image_without_a_mutable_asset_mount(self):
        services = yaml.safe_load((ROOT / 'selfhost/docker-compose.yml').read_text())['services']
        for mount in services['web'].get('volumes', []):
            target = mount.split(':')[1] if isinstance(mount, str) else mount.get('target')
            self.assertNotEqual('/srv', target)

    def test_first_party_sidecars_request_source_builds_in_source_checkouts(self):
        from chronicle_ops.images import SOURCE_IMAGES
        from chronicle_ops.envfile import read_env, value
        settings = read_env(ROOT / 'selfhost/.env.example')
        for image in SOURCE_IMAGES:
            with self.subTest(component=image.component):
                self.assertEqual(image.placeholder, value(settings, image.variable))
        dockerfiles = {path.resolve() for path in (ROOT / 'selfhost').glob('Dockerfile.*')}
        self.assertTrue(dockerfiles <= {(ROOT / 'selfhost' / image.dockerfile).resolve() for image in SOURCE_IMAGES})

    def test_build_context_comes_from_revision_objects(self):
        from chronicle_ops.images import archive_source, source_inputs_tree
        import io
        import tarfile
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            subprocess.run(['git', 'init', '-q', str(root)], check=True)
            def git(*args, data=None, repo=root):
                return subprocess.check_output(['git', '-C', str(repo), *args], input=data).decode().strip()
            blob = git('hash-object', '-w', '--stdin', data=b'committed bytes')
            nested = root / 'nested'; nested.mkdir()
            subprocess.run(['git', 'init', '-q', str(nested)], check=True)
            nested_blob = git('hash-object', '-w', '--stdin', data=b'pinned gitlink bytes', repo=nested)
            nested_tree = git('mktree', data=f'100644 blob {nested_blob}\tinput.txt\n'.encode(), repo=nested)
            tree = git('mktree', '--missing', data=(f'100644 blob {blob}\tinput.txt\n'
                                                   f'160000 commit {nested_tree}\tnested\n').encode())
            self.assertEqual(tree, source_inputs_tree(root, tree))
            (root / 'input.txt').write_text('transient working-tree bytes')
            (nested / 'input.txt').write_text('uncommitted submodule bytes')
            commit = subprocess.check_output(['git', '-C', str(root), 'commit-tree', tree, '-m', 'fixture'],
                                             env=dict(os.environ, GIT_AUTHOR_NAME='f', GIT_AUTHOR_EMAIL='f@f',
                                                      GIT_COMMITTER_NAME='f', GIT_COMMITTER_EMAIL='f@f')).decode().strip()
            for revision in (tree, commit):
                output = io.BytesIO()
                archive_source(root, revision, '.', output)
                # `docker build -` sniffs the first header; a PAX header there makes it read stdin as a Dockerfile.
                self.assertNotIn(output.getvalue()[156:157], (b'x', b'g'))
                with tarfile.open(fileobj=io.BytesIO(output.getvalue())) as archive:
                    self.assertEqual({}, archive.pax_headers)
                    self.assertEqual([], [member.name for member in archive if member.pax_headers])
                    self.assertEqual(b'committed bytes', archive.extractfile('input.txt').read())
                    self.assertEqual(b'pinned gitlink bytes', archive.extractfile('nested/input.txt').read())
            # A build reads only the gitlinks it names; an unrelated one need not be checked out.
            absent = git('mktree', '--missing', data=(f'100644 blob {blob}\tinput.txt\n'
                                                     f'160000 commit {nested_tree}\tnested\n'
                                                     f'160000 commit {"1" * 40}\tios\n').encode())
            output = io.BytesIO()
            archive_source(root, absent, '.', output, submodules=('nested',))
            with tarfile.open(fileobj=io.BytesIO(output.getvalue())) as archive:
                self.assertEqual({'input.txt', 'nested/input.txt'}, {member.name for member in archive if member.isfile()})
            # A context below the root ships only its own files, relative to it (the backup and Grafana builds read selfhost/).
            output = io.BytesIO()
            archive_source(root, absent, 'nested', output, submodules=('nested',))
            with tarfile.open(fileobj=io.BytesIO(output.getvalue())) as archive:
                self.assertEqual(['input.txt'], [member.name for member in archive if member.isfile()])
                self.assertEqual(b'pinned gitlink bytes', archive.extractfile('input.txt').read())
            # An image's context is relative to selfhost/: the default '..' is the repository root; one that leaves
            # the revision (or names a host path) is refused before git reads anything.
            from chronicle_ops.images import SourceImage
            root_image = SourceImage('fixture', 'FIXTURE_IMAGE', 'Dockerfile.fixture', '__FIXTURE__', submodules=('nested',))
            output = io.BytesIO()
            root_image.archive(root, absent, output)
            with tarfile.open(fileobj=io.BytesIO(output.getvalue())) as archive:
                self.assertEqual({'input.txt', 'nested/input.txt'}, {member.name for member in archive if member.isfile()})
            for escaping in (lambda out: SourceImage('fixture', 'FIXTURE_IMAGE', 'Dockerfile.fixture', '__FIXTURE__',
                                                     context='../..').archive(root, absent, out),
                             lambda out: archive_source(root, absent, str(root), out)):
                output = io.BytesIO()
                with self.assertRaisesRegex(ValueError, 'build context must be within the revision'):
                    escaping(output)
                self.assertEqual(b'', output.getvalue())

    def test_source_checkout_up_rebuilds_only_images_whose_inputs_changed(self):
        # `./chronicle up` in a source clone: an image labelled with the current inputs tree is reused, a stale or
        # missing one is rebuilt from the revision, Caddy is built on the frontend just built, and a pinned image is kept.
        from chronicle_ops import images
        from types import SimpleNamespace
        revision, tree = 'c' * 40, 'a' * 40
        tags = {image.component: image.tag(revision) for image in images.SOURCE_IMAGES}
        labels = {tags['backend']: tree, tags['frontend']: 'stale-tree'}
        for failing in (None, 'caddy'):
            with self.subTest(failing=failing), tempfile.TemporaryDirectory() as folder:
                builds, archived = [], []
                def docker(args, **kwargs):
                    if args[:2] == ['git', '-C']:
                        return SimpleNamespace(returncode=0, stdout=tree + '\n')
                    if args[:3] == ['docker', 'image', 'inspect']:
                        return SimpleNamespace(returncode=0 if args[-1] in labels else 1, stdout=labels.get(args[-1], '') + '\n')
                    builds.append((args, kwargs['stdin'].read()))
                    if failing and failing in args[args.index('-t') + 1]:
                        raise subprocess.CalledProcessError(1, args)
                    return SimpleNamespace(returncode=0)
                def archive(image, repository, revision_, output):
                    archived.append((image.component, Path(repository), revision_))
                    output.write(image.component.encode())
                selfhost = Path(folder) / 'selfhost'; selfhost.mkdir()
                settings = selfhost / '.env'
                backup = 'registry.example/backup@sha256:' + 'b' * 64
                original = ''.join(f'{image.variable}={backup if image.component == "backup" else image.placeholder}\n'
                                   for image in images.SOURCE_IMAGES)
                settings.write_text(original)
                origin = Path.cwd()
                os.chdir(selfhost)
                try:
                    with patch.object(images, 'run', side_effect=docker), patch.object(images.SourceImage, 'archive', archive), \
                         patch.dict(os.environ, BACKUP_IMAGE=backup, CADDY_IMAGE='__CHRONICLE_SELFHOST_CADDY_IMAGE__'):
                        for name in ('BACKEND_IMAGE', 'SELFHOST_FRONTEND_IMAGE', 'GRAFANA_IMAGE', 'POSTGRES_IMAGE', 'FLUENT_BIT_IMAGE'):
                            os.environ.pop(name, None)
                        if failing:
                            with self.assertRaises(subprocess.CalledProcessError):
                                images.build_source_images(revision, 'docker-compose.yml:overlays/backups.yml')
                            self.assertEqual(original, settings.read_text())  # no pin names an image that was not built
                            continue
                        images.build_source_images(revision, 'docker-compose.yml:overlays/backups.yml')
                finally:
                    os.chdir(origin)
                from chronicle_ops.envfile import read_env, value
                saved = read_env(settings)
                self.assertEqual({image.variable: tags[image.component] for image in images.SOURCE_IMAGES if not image.overlay},
                                 {image.variable: value(saved, image.variable) for image in images.SOURCE_IMAGES if not image.overlay})
                self.assertEqual(0o600, settings.stat().st_mode & 0o777)
                self.assertEqual(backup, value(saved, 'BACKUP_IMAGE'))
                # build_source_images archives Path.cwd().parent, which the OS reports resolved (/private/var on macOS).
                checkout = Path(folder).resolve()
                self.assertEqual([('frontend', checkout, revision), ('caddy', checkout, revision),
                                  ('postgres', checkout, revision)], archived)
                (frontend, frontend_input), (caddy, caddy_input), (postgres, postgres_input) = builds
                self.assertEqual((b'frontend', b'caddy', b'postgres'), (frontend_input, caddy_input, postgres_input))
                self.assertIn('Dockerfile.postgres', postgres)
                self.assertEqual(['docker', 'build', '-q', '-f', 'selfhost/Dockerfile.frontend', '-t', tags['frontend'],
                                  '--build-arg', 'GIT_SHA=' + revision, '--label', 'org.opencontainers.image.revision=' + revision,
                                  '--label', images.INPUTS_TREE_LABEL + '=' + tree, '-'], frontend)
                self.assertIn('chronicle-selfhost-frontend:release=docker-image://' + tags['frontend'], caddy)
                self.assertIn('selfhost/Dockerfile.caddy', caddy)

    def test_capacity_verifies_each_dump_once(self):
        import gzip
        from chronicle_ops import dump, verify
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'last/chronicle-good.sql.gz'; path.parent.mkdir()
            path.write_bytes(gzip.compress(DUMP)); publish_backup(path, 'chronicle', {})
            stats = json.dumps(dict(database_bytes=4096, wal_bytes=0, max_wal_bytes=4096))
            result = subprocess.CompletedProcess([], 0, 'disk 100000 0 100000 0% /data\n' + stats)
            with patch('chronicle_ops.verify.compose', return_value=result), \
                 patch('chronicle_ops.verify.storage_report', return_value=[]), \
                 patch('chronicle_ops.dump.validate_dump', wraps=dump.validate_dump) as validate, \
                 patch('chronicle_ops.verify.validate_dump', wraps=dump.validate_dump) as capacity_validate:
                verify.capacity_checks({'COMPOSE_FILE': 'overlays/backups.yml'}, folder)
                verify.capacity_checks({'COMPOSE_FILE': 'overlays/backups.yml'}, folder)
            self.assertEqual(1, validate.call_count + capacity_validate.call_count)

    def test_update_discovers_highest_published_stable_release(self):
        from chronicle_ops import update
        from chronicle_ops.release import UPDATE_AVAILABLE_EXIT
        def assets(version):  # discovery offers only a release whose three assets are published
            name = f'chronicle-selfhost-{version}.tar.gz'
            return [{'name': item, 'browser_download_url': 'https://example.org/' + item}
                    for item in (name, name + '.sha256', name + '.sha256.sig')]
        releases = [{'tag_name': version, 'draft': draft, 'prerelease': prerelease, 'assets': assets(version)}
                    for version, draft, prerelease in [('1.1.0', False, False), ('1.2.0', False, False),
                                                       ('2.0.0', True, False), ('3.0.0-rc.1', False, True)]]
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); host = root / 'selfhost'; host.mkdir()
            (root / 'release-manifest.json').write_text(json.dumps({'release_version': '1.1.0'}))
            settings = host / '.env'; settings.write_text('COMPOSE_PROJECT_NAME=fixture\n'); settings.chmod(0o600)
            with patch.object(Path, 'cwd', return_value=host), \
                 patch('chronicle_ops.update.require_current_owner'), \
                 patch('chronicle_ops.egress.first_unreachable', return_value=None), \
                 patch('chronicle_ops.update.curl', return_value=json.dumps(releases)):
                self.assertEqual(UPDATE_AVAILABLE_EXIT, update.update(check=True))
                with self.assertRaisesRegex(ValueError, 'fresh install'):
                    update.update(check=False)

    def test_scheduled_outcomes_reach_operator_receipts(self):
        from chronicle_ops.common import DEFAULT_COMPOSE_PROJECT
        from selfhost_fixture import copy_selfhost_fixture
        from chronicle_ops.release import UPDATE_AVAILABLE_EXIT
        for arguments, status, category, saved_project in [
                (arguments, status, category, project)
                for arguments, status, category in [(['--check-updates'], UPDATE_AVAILABLE_EXIT, 'update_available'),
                    (['--check-updates'], 42, 'update_check_failed'), ([], 42, 'reconcile_failed')]
                for project in ('fixture', '', None)]:
            with self.subTest(arguments=arguments, status=status, project=saved_project), tempfile.TemporaryDirectory() as folder:
                root = Path(folder); host = root / 'selfhost'; host.mkdir(); state = root / 'state'; state.mkdir()
                copy_selfhost_fixture(host)
                (host / '.env').write_text('CHRONICLE_RECONCILE_ENABLED=true\nCOMPOSE_FILE=overlays/monitoring.yml\n'
                    + (f'COMPOSE_PROJECT_NAME={saved_project}\n' if saved_project is not None else ''))
                (host / 'chronicle').write_text('#!/bin/sh\n[ "$1" = doctor ] && exit 0\nexit "$FIXTURE_STATUS"\n')
                (host / 'chronicle').chmod(0o700)
                commands = root / 'bin'; commands.mkdir()
                for name, script in {
                        'logger': '#!/bin/sh\nprintf "%s\\n" "$*" >>"$LOGGER_RECORD"\n',
                        'crontab': '#!/bin/sh\nexit 0\n',
                        'docker': '#!/bin/sh\nprintf "%s\\n" "$*" >>"$DOCKER_RECORD"\n'
                                  'case "$*" in *" ps "*) echo operational-probe ;; esac\n'}.items():
                    command = commands / name; command.write_text(script); command.chmod(0o700)
                environment = dict(HOME=folder, CHRONICLE_RECONCILE_ENABLED='true', FIXTURE_STATUS=str(status),
                    PATH=str(commands) + os.pathsep + os.environ['PATH'],
                    DOCKER_RECORD=str(root / 'docker-record'), LOGGER_RECORD=str(root / 'logger-record'))
                with patch.dict(os.environ, environment, clear=True), \
                     patch('chronicle_ops.reconcile.platform.system', return_value='Linux'), \
                     patch('chronicle_ops.reconcile.run', return_value=subprocess.CompletedProcess([], 0, '', '')):
                    reconcile.install(host / 'chronicle', state, 'fixture')
                result = subprocess.run([str(state / 'reconcile.sh'), *arguments], env=environment,
                                        capture_output=True, timeout=15)
                self.assertEqual(0 if status == UPDATE_AVAILABLE_EXIT else 1, result.returncode, result.stderr)
                receipts = list((state / 'operator-receipts/operations').glob('*.json'))
                self.assertTrue(receipts, 'scheduled outcome bypassed operator monitoring')
                self.assertEqual(category, json.loads(receipts[-1].read_text())['failureCategory'])
                operation = reconcile.SCHEDULED_UPDATE if arguments else reconcile.SCHEDULED_RECONCILE
                outcome = 'success' if status == UPDATE_AVAILABLE_EXIT else 'failure'
                project = saved_project or DEFAULT_COMPOSE_PROJECT
                calls = (root / 'docker-record').read_text().splitlines()
                self.assertEqual([
                    f'compose -p {project} ps --status running --services',
                    f'compose -p {project} exec -T operational-probe /monitoring/record-operation.sh {operation} {outcome} {category}'
                ], [call for call in calls if call.startswith('compose ')])
                # The daily update check also measures free disk against the next update's reserve.
                self.assertEqual(bool(arguments), 'info --format {{.DockerRootDir}}' in calls)
                self.assertIn('Chronicle update available' if status == UPDATE_AVAILABLE_EXIT else 'failed',
                              (root / 'logger-record').read_text())

    def test_release_canary_fails_when_every_mobile_post_is_blocked(self):
        from chronicle_ops.mobile_canary import verify_canary
        from chronicle_ops.verify import send_canary
        from selfhost_fixture import mobile_canary_fixture
        public = 'https://fixture.example'
        with tempfile.TemporaryDirectory() as folder:
            canary = mobile_canary_fixture(folder, public)
            with patch('chronicle_ops.verify.curl', return_value=(0, '\n403')):
                with self.assertRaisesRegex(ValueError, 'synthetic mobile POST failed'):
                    verify_canary(canary.path, public, send_canary)

    def test_release_canary_posts_through_curl_config_and_reads_the_json_reply(self):
        from chronicle_ops.mobile_canary import CanaryRequest
        from chronicle_ops.verify import send_canary
        request = CanaryRequest('https://fixture.example/chronicle/v4/study/x/participant/smoke-1/enroll', {'device': 'smoke'},
                                {'X-Api-Key': 'synthetic-key'})
        for reply, decoded in (('{"apiKey": "synthetic-key"}\n201', {'apiKey': 'synthetic-key'}), ('\n204', None)):
            with self.subTest(reply=reply), patch('chronicle_ops.verify.curl', return_value=(0, reply)) as curl:
                self.assertEqual(decoded, send_canary(request))
            config = curl.call_args.kwargs['config']
            self.assertIn('synthetic-key', config)  # the device key travels in curl's config, never in argv
            self.assertNotIn('synthetic-key', ' '.join(curl.call_args.args))
            self.assertIn('{"device": "smoke"}', config.replace('\\"', '"'))
        for status, reply in ((7, '\n000'), (18, '{"apiKey"\n200')):  # refused; reply cut off mid-body
            with self.subTest(status=status), patch('chronicle_ops.verify.curl', return_value=(status, reply)), \
                 self.assertRaisesRegex(ValueError, 'synthetic mobile POST failed'):
                send_canary(request)

    def test_mobile_canary_must_be_a_private_synthetic_file_and_complete_its_round_trip(self):
        from chronicle_ops.mobile_canary import verify_canary
        from chronicle_ops.receipts import write_json
        from selfhost_fixture import mobile_canary_fixture
        public = 'https://fixture.example'
        with tempfile.TemporaryDirectory() as folder:
            canary = mobile_canary_fixture(folder, public)
            document = json.loads(canary.path.read_text())
            sent = []
            def replay(enrolled_key=canary.credential, acknowledged=None):
                def send(request):
                    sent.append(request.url.rsplit('/', 1)[-1])
                    if request.url.endswith('/enroll'):
                        return enrolled_key if not isinstance(enrolled_key, str) else {'apiKey': enrolled_key}
                    return len(request.body) if acknowledged is None else acknowledged
                return send
            verify_canary(canary.path, public, replay())
            self.assertEqual(['enroll', 'collection-ack', 'sensors'], sent)
            for case, send, message in (('rotated device key', replay('another-key'), 'did not replay its device credential'),
                                        ('enrollment error body', replay(['error']), 'did not replay its device credential'),
                                        ('partial upload', replay(acknowledged=0), 'did not acknowledge its batch')):
                with self.subTest(case), self.assertRaisesRegex(ValueError, message):
                    verify_canary(canary.path, public, send)
            base = document['upload']['url'].rsplit('/participant/', 1)[0]
            for case, change, message in (
                    ('foreign origin', {'enrollment': dict(document['enrollment'], url=document['enrollment']['url'].replace(public, 'https://other.example'))}, 'synthetic mobile identities'),
                    ('real participant', {'upload': dict(document['upload'], url=base + '/participant/P-0042/android/sensors')}, 'synthetic mobile identities'),
                    ('query string', {'upload': dict(document['upload'], url=document['upload']['url'] + '?debug=1')}, 'synthetic mobile identities'),
                    ('numeric header', {'upload': dict(document['upload'], headers={'X-Api-Key': 7})}, 'invalid synthetic request'),
                    ('empty batch', {'upload': dict(document['upload'], body=[])}, 'did not acknowledge its batch')):
                with self.subTest(case):
                    write_json(canary.path, dict(document, **change))
                    with self.assertRaisesRegex(ValueError, message):
                        verify_canary(canary.path, public, replay())
            write_json(canary.path, document)
            canary.path.chmod(0o644)
            with self.assertRaisesRegex(ValueError, 'must be a regular private file'):
                verify_canary(canary.path, public, replay())
            canary.path.chmod(0o600)
            link = Path(folder) / 'linked-canary.json'
            link.symlink_to(canary.path)
            with self.assertRaisesRegex(ValueError, 'must be a regular private file'):
                verify_canary(link, public, replay())

    def test_every_scheduled_outcome_reaches_an_alert_selector(self):
        import re
        rules = json.loads((ROOT / 'selfhost/monitoring/grafana-alerting/rules.yml').read_text())
        selectors = [re.findall(r'([a-z_]+)(!?=)"([^"]*)"', datum['model'].get('expr', ''))
                     for group in rules['groups'] for rule in group['rules'] for datum in rule['data']
                     if 'chronicle_operator_operation_timestamp_seconds{' in datum['model'].get('expr', '')]
        from chronicle_ops.release import UPDATE_AVAILABLE_EXIT
        for operation in reconcile.SCHEDULED_OPERATIONS:
            for status in (1, UPDATE_AVAILABLE_EXIT if operation == reconcile.SCHEDULED_UPDATE else 1):
                with self.subTest(operation=operation, status=status), tempfile.TemporaryDirectory() as folder:
                    root = Path(folder); (root / '.env').write_text('')
                    with patch.object(Path, 'cwd', return_value=root), patch.dict(os.environ, CHRONICLE_OPS_STATE=folder), \
                         patch('chronicle_ops.receipts.write_operation_receipt') as receipt, patch('chronicle_ops.receipts.record_operation'):
                        reconcile.record_scheduled(operation, status)
                    op, outcome, category = receipt.call_args.args
                    labels = dict(operation=op, outcome=outcome, failure_category=category)
                    self.assertTrue(any(selector and all((labels.get(key) == val) == (comparison == '=')
                                                         for key, comparison, val in selector) for selector in selectors))

    def test_all_fluentd_queues_fit_the_host_memory_budget(self):
        from chronicle_ops.host_memory import require_logging_budget
        from chronicle_ops.images import bundle_config
        require_logging_budget(bundle_config(ROOT / 'selfhost')['services'])

    def test_logging_budget_covers_new_service_names_and_configuration_shapes(self):
        from chronicle_ops.host_memory import LOG_EVENT_ESTIMATE_BYTES, MEMORY_HEADROOM_BYTES, require_logging_budget
        safe = MEMORY_HEADROOM_BYTES // LOG_EVENT_ESTIMATE_BYTES
        for name in ('postgres-east', 'renamed_worker', 'arbitrary'):
            for count in (safe, str(safe)):
                services = {name: {'logging': {'driver': 'fluentd', 'options': {
                    'fluentd-async': 'true', 'fluentd-buffer-limit': count}}}}
                self.assertEqual(MEMORY_HEADROOM_BYTES, require_logging_budget(services))
                services[name]['logging']['options']['fluentd-buffer-limit'] = safe + 1
                with self.assertRaises(ValueError):
                    require_logging_budget(services)
