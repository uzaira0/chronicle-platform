import gzip
import importlib.util
import io
import json
import os
import re
import shutil
import shlex
from pathlib import Path
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'selfhost'))
from chronicle_ops import common, dump, envfile, env_migration, host_memory, receipts, reconcile, release, verify
from test_restore import DUMP
from test_secret_generation import SelfhostSetupFixture

client_spec = importlib.util.spec_from_file_location('topology_client', ROOT / 'tests/deployment/selfhost-client.py')
client = importlib.util.module_from_spec(client_spec)
client_spec.loader.exec_module(client)
POSTGRES_INSPECTION = {'Config': {'Env': ['PGDATA=/data/db']},
                       'Mounts': [{'Destination': '/data/db', 'Source': '/database'},
                                  {'Destination': '/var/lib/postgresql/tde-keyring', 'Source': '/keyring'}]}


class TopologyTests(unittest.TestCase):
    def test_webhook_runbook_describes_the_authenticated_api_and_enrollment_fence(self):
        section = (ROOT / 'selfhost/docs/CONFIGURATION.md').read_text().split('## Study webhook recipients', 1)[1].split('\n## ', 1)[0]
        api = (ROOT / 'chronicle-api/src/main/kotlin/com/openlattice/chronicle/webhooks/WebhookApi.kt').read_text()
        webhook_path = re.search(r'WEBHOOKS_PATH: String = "([^"]+)"', api)[1]
        self.assertRegex(section, r'GET /[^`\s]+' + re.escape(webhook_path) + r'`')
        for policy in ('authenticated API', 'before enrollment', 'active or pending', 'are audited', 'recipient-side deletion'):
            self.assertIn(policy, section)

    def test_update_forces_internal_login_settings_and_refuses_missing_hash(self):
        with tempfile.TemporaryDirectory() as folder:
            host = Path(folder)
            overlay = 'overlays/mode-behind-proxy-internal.yml'
            settings = {'COMPOSE_FILE': f'docker-compose.yml:{overlay}', 'TESTING_LOGIN_ENABLED': 'true', 'REQUIRE_MFA': 'false'}
            template = 'TESTING_LOGIN_ENABLED=true\nREQUIRE_MFA=true\n'
            with self.assertRaisesRegex(ValueError, 'run ./chronicle setup'):
                env_migration.merge_env(settings, template, None, host, [overlay])
            settings['DASHBOARD_PASSWORD_HASH'] = "'$2b$synthetic'"
            merged = env_migration.merge_env(settings, template, None, host, [overlay])
            self.assertIn('TESTING_LOGIN_ENABLED=false\n', merged)
            self.assertIn('REQUIRE_MFA=false\n', merged)
        snippets = (ROOT / 'selfhost/caddy/snippets.caddy').read_text()
        self.assertNotIn('basic_auth', snippets)
        self.assertIn('remote_ip', snippets)

    def test_container_structure_configs_cover_the_three_shipped_selfhost_images(self):
        import yaml
        for component in ('frontend', 'caddy', 'backup'):
            config = yaml.safe_load((ROOT / f'tests/container/selfhost-{component}.yaml').read_text())
            self.assertEqual(config['schemaVersion'], '2.0.0')
            self.assertTrue(config['commandTests'])
            self.assertTrue(config['fileExistenceTests'])

    def test_shipped_mapstores_persist_and_api_study_is_read_after_restart(self):
        import yaml
        for name in ('selfhost/config/rhizome.yaml.template', 'chronicle-server/src/main/resources/rhizome.yaml'):
            self.assertIs(yaml.safe_load((ROOT / name).read_text())['enable-persistence'], True, name)
        study = '00000000-0000-0000-0000-000000000001'
        with patch.object(client, 'dashboard_client', return_value=(object(), {})), \
             patch.object(client, 'request', return_value={'id': study}) as request:
            client.assert_study({'study': study}, 'https://management.example', None, 'synthetic')
            self.assertTrue(request.call_args.args[1].endswith('/chronicle/api/web/study/' + study))
            request.return_value = {'id': 'wrong'}
            with self.assertRaises(RuntimeError):
                client.assert_study({'study': study}, 'https://management.example', None, 'synthetic')

    def test_release_smoke_honors_explicit_reconciliation_override(self):
        source = (ROOT / 'tests/smoke/selfhost-release-smoke.sh').read_text()
        setting = next(line for line in source.splitlines() if line.startswith('export CHRONICLE_RECONCILE_ENABLED='))
        for value in ('true', 'false', None):
            env = dict(os.environ)
            env.pop('CHRONICLE_RECONCILE_ENABLED', None)
            if value is not None:
                env['CHRONICLE_RECONCILE_ENABLED'] = value
            result = shell_probe(setting + '\nprintf "%s" "$CHRONICLE_RECONCILE_ENABLED"', strict=True,
                                    env=env)
            self.assertEqual(result.stdout, value or 'false')

    def test_load_smoke_uses_enrolled_identity_current_payloads_and_requires_acknowledgment(self):
        source = (ROOT / 'tests/load/smoke-test.sh').read_text().split("<<'PY_SMOKE'\n", 1)[1].split('\nPY_SMOKE', 1)[0]
        requests = []
        result_count = 1
        def upload(_phone, path, method, rows, headers):
            self.assertEqual(method, 'POST')
            requests.append((path, headers, rows))
            # Usage answers with an UploadReceipt naming the accepted events; the other routes with a row count.
            if path.endswith('/android'):
                return {'acceptedIds': [row['clientEventId'] for row in rows][:result_count], 'discardedIds': []}
            return result_count
        fixture = {'batches': client.batches, 'client': lambda _ca: object(), 'request': upload,
                   'configure_fixture_address': client.configure_fixture_address,
                   'API_KEY_HEADER': client.API_KEY_HEADER, 'DEVICE_HEADER': client.DEVICE_HEADER}
        env = dict(BASE_URL='https://fixture.example', API_KEY='synthetic-enrolled-key',
                   UPLOAD_CONNECT_TO='fixture.example:443:127.0.0.1:9443',
                   TEST_STUDY_ID='00000000-0000-0000-0000-000000000001', TEST_PARTICIPANT_ID='enrolled-participant', TEST_RANDOM_DEVICE_ID='registered-device')
        for accepted in (1, 0):
            result_count = accepted
            requests.clear()
            with patch.dict(os.environ, env), patch('sys.argv', ['smoke', str(ROOT)]), \
                 patch('runpy.run_path', return_value=fixture), patch('sys.stdout', io.StringIO()), \
                 patch.object(client.socket, 'getaddrinfo', return_value=[]) as resolve:
                if accepted: exec(compile(source, 'smoke-test.sh', 'exec'), {})
                else:
                    with self.assertRaisesRegex(SystemExit, 'did not acknowledge'):
                        exec(compile(source, 'smoke-test.sh', 'exec'), {})
                client.socket.getaddrinfo('fixture.example', 443)
                resolve.assert_called_once_with('127.0.0.1', 9443)
                client.socket.getaddrinfo('management.example', 443)
                self.assertEqual(resolve.call_args.args, ('management.example', 443))
            self.assertTrue(requests)
            for path, headers, rows in requests:
                self.assertNotIn('Authorization', headers)
                self.assertEqual(headers['X-Api-Key'], env['API_KEY'])
                self.assertEqual(headers['X-Chronicle-Random-Device-Id'], env['TEST_RANDOM_DEVICE_ID'])
                self.assertIn('/participant/enrolled-participant/android', path)
                if path.endswith('/sensors'):
                    self.assertEqual(rows[0]['sensor'], 'accelerometer')
                else:
                    self.assertEqual(rows[0]['@class'], 'com.openlattice.chronicle.android.ChronicleUsageEvent')
                    self.assertEqual(rows[0]['studyId'], env['TEST_STUDY_ID'])
                    self.assertEqual(rows[0]['participantId'], env['TEST_PARTICIPANT_ID'])
            if accepted: self.assertEqual(len(requests), 2)

    def test_strict_hmac_needs_credentials_and_a_valid_signed_positive_control(self):
        source = (ROOT / 'tests/security/test-hmac-enforcement.sh').read_text().split("<<'PY_HMAC'\n", 1)[1].split('\nPY_HMAC', 1)[0]
        with patch.dict(os.environ, {'STRICT': '1'}, clear=True), patch('urllib.request.urlopen') as transport:
            with self.assertRaisesRegex(SystemExit, 'Strict mode requires'):
                exec(compile(source, 'test-hmac-enforcement.sh', 'exec'), {})
            transport.assert_not_called()
        import urllib.error
        attempts = []
        class Response:
            status = 200
            def __enter__(self): return self
            def __exit__(self, *_): pass
            def read(self): return b'{}'
        def transport(request, **_):
            attempts.append(request)
            if len(attempts) == 1: return Response()
            message = 'Missing required signature headers' if len(attempts) == 2 else 'Request replay detected'
            raise urllib.error.HTTPError(request.full_url, 401, 'fixture', {}, io.BytesIO(json.dumps({'error': message}).encode()))
        env = {'STRICT': '1', 'MOBILE_SIGNING_SECRET': 'synthetic-signing-secret', 'TEST_RANDOM_DEVICE_ID': 'fixture-device',
               'HMAC_TEST_PATH': '/chronicle/v4/study/fixture/participant/fixture/enroll', 'MOBILE_ENROLLMENT_BODY': '{}'}
        with patch.dict(os.environ, env, clear=True), patch('urllib.request.urlopen', side_effect=transport), patch('sys.stdout', io.StringIO()):
            exec(compile(source, 'test-hmac-enforcement.sh', 'exec'), {})
        self.assertEqual(len(attempts), 3)
        self.assertEqual(attempts[0].data, attempts[2].data)
        self.assertEqual(attempts[0].headers, attempts[2].headers)
        self.assertNotIn('X-chronicle-signature', attempts[1].headers)
        with patch.dict(os.environ, env, clear=True), patch('urllib.request.urlopen', side_effect=urllib.error.HTTPError('fixture', 500, 'fixture', {}, io.BytesIO(b'{}'))), patch('sys.stdout', io.StringIO()):
            with self.assertRaises(SystemExit) as rejected:
                exec(compile(source, 'test-hmac-enforcement.sh', 'exec'), {})
            self.assertEqual(rejected.exception.code, 1)

    def test_monitoring_siblings_cannot_reach_backend_or_hazelcast(self):
        import yaml
        base = yaml.safe_load((ROOT / 'selfhost/docker-compose.yml').read_text())
        overlay = yaml.safe_load((ROOT / 'selfhost/overlays/monitoring.yml').read_text())
        backend = set(base['services']['backend'].get('networks', ['default']))
        for service in ('grafana', 'cadvisor', 'fluent-bit', 'victoriametrics', 'victorialogs',
                        'metrics-exporter', 'operational-probe', 'monitoring-config', 'docker-socket-proxy'):
            self.assertFalse(backend.intersection(overlay['services'][service].get('networks', ['default'])), service)
        self.assertEqual(set(base['services']['postgres']['networks']) &
                         set(overlay['services']['operational-probe']['networks']), {'database-probe'})
        self.assertIn('monitoring', overlay['networks'])
        proxy = (ROOT / 'selfhost/monitoring/backend-metrics.caddy').read_text()
        self.assertIn('@metrics path /prometheus/', proxy)
        self.assertIn('reverse_proxy @metrics https://backend:8443', proxy)
        self.assertIn('respond 404', proxy)
        config = yaml.safe_load((ROOT / 'selfhost/config/rhizome.yaml.template').read_text())
        self.assertEqual(config['hazelcast']['interfaces'], ['127.0.0.1'])

    def test_monitoring_renderer_scrapes_the_backend_through_web(self):
        import yaml
        from chronicle_ops.images import bundle_config
        with tempfile.TemporaryDirectory() as folder:
            work = Path(folder)
            rendered = work / 'monitoring-config'; rendered.mkdir()
            backend_tls = work / 'backend-tls'; backend_tls.mkdir()
            (backend_tls / 'backend.crt').write_text('synthetic-backend-certificate')
            image = bundle_config(ROOT / 'selfhost')['services']['postgres']['image']
            result = subprocess.run(['docker', 'run', '--rm', '--name', 'chronicle-sat-r1-render-' + work.name,
                '--network', 'none', '--memory', '256m', '--memory-swap', '256m',
                '--read-only', '--user', '0', '--entrypoint', 'bash',
                *[argument for directory in ('monitoring-secrets', 'metrics', 'vmdata', 'vldata', 'fluent-bit/state')
                  for argument in ('--tmpfs', '/' + directory)],
                '-v', f'{ROOT / "selfhost"}:/selfhost:ro', '-v', f'{backend_tls}:/backend-tls:ro',
                '-v', f'{rendered}:/monitoring-config', '-e', 'METRICS_PASSWORD=' + 'm' * 32,
                '-e', 'GRAFANA_ADMIN_PASSWORD=' + 'g' * 32, '-e', 'CHRONICLE_HOST_UID=501',
                '-e', 'CHRONICLE_HOST_GID=501', image, '/selfhost/monitoring/render-config.sh'],
                check=False, capture_output=True, text=True, timeout=60)
            self.assertEqual(0, result.returncode, result.stderr)
            scrape = yaml.safe_load((rendered / 'scrape.yml').read_text())
            backend_scrape = next(job for job in scrape['scrape_configs'] if job['job_name'] == 'chronicle-backend')
            self.assertEqual([{'targets': ['web:9091']}], backend_scrape['static_configs'])

    def test_backend_jvm_binds_only_configured_hazelcast_interfaces(self):
        # The member binds only these interfaces: rhizome HazelcastNetworkInterfacesTest builds the network config.
        with tempfile.TemporaryDirectory() as folder:
            work = Path(folder)
            for directory in ('capture', 'rendered', 'audit'):
                (work / directory).mkdir(mode=0o777)
                (work / directory).chmod(0o777)
            java = work / 'capture/java'
            # shortcut: fixed fixture arguments contain no newlines, use JSON if arbitrary arguments are exercised.
            java.write_text('#!/bin/sh\nprintf "%s\\n" "$@" > /capture/argv\n')
            java.chmod(0o755)
            result = subprocess.run(['docker', 'run', '--rm', '--name', 'chronicle-sat-r1-backend-args-' + work.name,
                '--network', 'none', '--memory', '256m', '--memory-swap', '256m',
                '--read-only', '--entrypoint', '/bin/sh', '-v', f'{work / "capture"}:/capture',
                '-v', f'{work / "rendered"}:/server/rendered-config', '-v', f'{work / "audit"}:/var/log/chronicle',
                '-v', f'{ROOT / "selfhost/config"}:/server/config:ro',
                '-v', f'{ROOT / "selfhost/backend-entrypoint.sh"}:/server/backend-entrypoint.sh:ro',
                '-e', 'PATH=/capture:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
                '-e', 'POSTGRES_APP_PASSWORD=synthetic-app-password', '-e', 'JWT_SECRET=synthetic-jwt-secret',
                '-e', 'CHRONICLE_INTERNAL_WEB_SECRET=synthetic-internal-web-secret',
                'chronicle-backend:test', '/server/backend-entrypoint.sh'],
                check=False, capture_output=True, text=True, timeout=60)
            self.assertEqual(0, result.returncode, result.stderr)
            arguments = (work / 'capture/argv').read_text().splitlines()
            self.assertEqual(['-Dhazelcast.socket.bind.any=false'],
                             [argument for argument in arguments if argument.startswith('-Dhazelcast.socket.bind.any=')])
            self.assertLess(arguments.index('-Dhazelcast.socket.bind.any=false'),
                            arguments.index('com.openlattice.chronicle.ChronicleServer'))

    def test_monitoring_start_refuses_unpinned_release_images(self):
        pinned = 'registry.example/chronicle@sha256:' + 'a' * 64
        environment = dict(os.environ, METRICS_PASSWORD='m' * 32, GRAFANA_ADMIN_PASSWORD='g' * 32,
                           RELEASE_VERSION='2026.10.21', POSTGRES_IMAGE=pinned, CADDY_IMAGE=pinned, GRAFANA_IMAGE=pinned)
        script = ['bash', str(ROOT / 'selfhost/monitoring/render-config.sh')]
        for overrides, refused in ((dict(CADDY_IMAGE='caddy:latest'), True),
                                   (dict(GRAFANA_IMAGE=''), True),
                                   (dict(CADDY_IMAGE='caddy:latest', RELEASE_VERSION='development'), False),
                                   ({}, False)):
            with self.subTest(**overrides):
                result = subprocess.run(script, env=dict(environment, **overrides), capture_output=True, text=True,
                                        timeout=10)
                self.assertEqual(refused, 'must be digest-pinned' in result.stderr, result.stderr)
                if refused:
                    self.assertNotEqual(0, result.returncode)

    def test_enrollment_credentials_are_private_and_upload_layer_uses_them(self):
        study = '00000000-0000-0000-0000-000000000001'
        public = 'https://fixture.example'
        def response(_opener, url, _method='GET', _body=None, _headers=None, response_headers=None, **_kwargs):
            if response_headers is not None: response_headers['etag'] = '"1"'
            # request() adds the create key itself; edits must pass the revision they read.
            if _method == 'PATCH': self.assertEqual(_headers['If-Match'], '"1"')
            if url.endswith('/dashboard-login'): return {'authenticated': True, 'csrfToken': 'login-csrf'}
            # Session bootstrap reissues the CSRF cookie, as the server does.
            if url.endswith('/auth/session'): return {'authenticated': True, 'csrfToken': 'session-csrf'}
            if url.endswith('/web/study'):
                self.assertEqual(_headers['X-CSRF-Token'], 'session-csrf')
                return study
            if url.endswith('/form-access-codes'): return {'accessCode': 'synthetic-invitation'}
            if url.endswith('/enrollment-preview'):
                return {'manifest': {'serverOrigin': public, 'settingsVersion': 1}, 'manifestDigest': 'synthetic-digest'}
            if url.endswith('/enroll'): return {'apiKey': 'synthetic-device-credential'}
            return None
        with tempfile.TemporaryDirectory() as folder:
            credentials = Path(folder) / 'credentials.json'
            with patch.object(client, 'client'), patch.object(client, 'request', side_effect=response), \
                 patch.object(client, 'upload_batches'), patch.object(client, 'export_download'), patch.object(client, 'assert_oversize_rejected'):
                records = client.exercise(public, 'https://management.example', None, 'synthetic-password',
                                          enrollment_credentials=credentials)
            self.assertEqual(credentials.stat().st_mode & 0o777, 0o600)
            fixture = json.loads(credentials.read_text())
            self.assertEqual(fixture['TEST_STUDY_ID'], records['study'])
            self.assertEqual(fixture['TEST_PARTICIPANT_ID'], records['participant'])
            self.assertNotIn('API_KEY', records)
            token = "synthetic-session-jwt'$(false)"
            browser = SimpleNamespace(handlers=[client.urllib.request.HTTPCookieProcessor([
                SimpleNamespace(name='chronicle_auth', value=token)])])
            environment_file = Path(folder) / 'upload.env.sh'
            with patch.object(client, 'dashboard_client', return_value=(browser, {})) as login:
                client.write_upload_security_environment(public, 'https://management.example', 'synthetic-password',
                                                         credentials, 'fixture-ca.crt', '127.0.0.1:9443', environment_file)
            login.assert_called_once_with('https://management.example', 'fixture-ca.crt', 'synthetic-password')
            self.assertEqual(environment_file.stat().st_mode & 0o777, 0o600)
            result = subprocess.run(['bash', '-eu', '-c', 'source "$1"; python3 -c "import os,json; print(json.dumps(dict(os.environ)))"',
                                     '--', str(environment_file)], capture_output=True, text=True, check=True,
                                    env={'PATH': os.environ['PATH']})
            environment = json.loads(result.stdout)
            self.assertEqual(environment['API_KEY'], fixture['API_KEY'])
            self.assertEqual(environment['UPLOAD_CONNECT_TO'], 'fixture.example:443:127.0.0.1:9443')
            expected = dict(AUTH_TOKEN=token, MANAGEMENT_URL='https://management.example',
                            CA_CERT='fixture-ca.crt', SSL_CERT_FILE='fixture-ca.crt')
            self.assertEqual({key: environment[key] for key in expected}, expected)
        saved = dict(records, counts=dict.fromkeys(records['tables'], 3))
        client.assert_persisted(saved, lambda _sql: '3')
        with self.assertRaises(RuntimeError): client.assert_persisted(saved, lambda _sql: '2')
        smoke = (ROOT / 'tests/smoke/selfhost-release-smoke.sh').read_text()
        self.assertIn('--enrollment-credentials', smoke)
        self.assertIn('--capture-db', smoke)
        restore = smoke[smoke.index('CLEAN_RESTORE_SHA256='):smoke.index('clean_restore_seconds=')]
        self.assertEqual(restore.count('assert_upload_rows'), 2)
        self.assertIn('after-clean-backup', restore)
        self.assertIn('"$post_backup_marker" == 0', restore)

    def test_environment_contract_matches_shell_and_preserves_settings(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'settings'
            path.write_text("export POSTGRES_DB='custom db' # saved\nJWT_SECRET='literal$secret'\nEMPTY= # blank\n")
            settings = envfile.read_env(path)
            self.assertEqual(envfile.value(settings, 'POSTGRES_DB'), 'custom db')
            self.assertEqual(envfile.value(settings, 'JWT_SECRET'), 'literal$secret')
            self.assertEqual(envfile.value(settings, 'EMPTY'), '')
            shell = shell_probe('source "$1"; printf "%s" "$POSTGRES_DB"', str(path))
            self.assertEqual(shell.stdout, envfile.value(settings, 'POSTGRES_DB'))
            text = env_migration.merge_env(settings, 'POSTGRES_DB=default\nJWT_SECRET=new\n', None, folder, ['docker-compose.yml'], preserve_images=True)
            path.write_text(text)
            self.assertEqual(envfile.value(envfile.read_env(path), 'POSTGRES_DB'), 'custom db')
            for invalid in ('POSTGRES_DB=$(id)', 'POSTGRES_DB=x\nPOSTGRES_DB=y', 'source other',
                            'POSTGRES_DB=x;touch /tmp/unwanted', 'POSTGRES_DB=x|cat',
                            'POSTGRES_DB="literal\\$value"', 'POSTGRES_DB="literal\\nvalue"'):
                path.write_text(invalid)
                with self.assertRaises(ValueError): envfile.read_env(path)
            for text in ('literal$secret', "operator's state", 'spaces and # punctuation'):
                path.write_text('POSTGRES_DB=' + envfile.quote_env(text) + ' # ignored " quote\n')
                decoded = envfile.value(envfile.read_env(path), 'POSTGRES_DB')
                shell = shell_probe('source "$1"; printf "%s" "$POSTGRES_DB"', str(path))
                self.assertEqual(decoded, text)
                self.assertEqual(shell.stdout, text)

    def test_shared_lock_inherits_and_excludes_other_processes(self):
        with tempfile.TemporaryDirectory() as folder:
            descriptor = common.acquire_operation_lock(folder)
            try:
                self.assertIsNone(common.acquire_operation_lock(folder))
                child = common.run(['python3', '-c', 'from chronicle_ops.common import acquire_operation_lock;import sys;assert acquire_operation_lock(sys.argv[1]) is None', folder],
                                   capture=True, env=dict(os.environ, PYTHONPATH=str(ROOT / 'selfhost')), timeout=5)
                self.assertEqual(child.returncode, 0, child.stderr)
                competing = subprocess.run(['flock', '-n', str(Path(folder) / common.OPERATION_LOCK), 'true'], timeout=5)
                self.assertNotEqual(competing.returncode, 0)
            finally:
                common.release_operation_lock(descriptor)
            self.assertEqual(subprocess.run(['flock', '-n', str(Path(folder) / common.OPERATION_LOCK), 'true'], timeout=5).returncode, 0)

    def test_checkpoint_allows_only_explicit_forward_owner(self):
        with tempfile.TemporaryDirectory() as folder:
            state = Path(folder)
            marker = state / '.chronicle-upgrade.lock'
            marker.mkdir()
            receipts.write_json(marker / 'recovery.json', {'owner': str(state / 'new'), 'phase': 'migration-started'})
            for owner, scheduled, allowed in (('old', 'false', False), ('new', 'true', False), ('new', 'false', True)):
                with self.subTest(owner=owner, scheduled=scheduled), patch.dict(os.environ, CHRONICLE_RECONCILE_RUN=scheduled):
                    if allowed: reconcile.check_mutations(state, state / owner, True)
                    else:
                        with self.assertRaises(ValueError): reconcile.check_mutations(state, state / owner, True)
            (marker / 'recovery.json').write_text('invalid')
            with self.assertRaises(ValueError): reconcile.check_mutations(state, state / 'new', True)

    def test_empty_crontab_forces_locale_and_preserves_docker_environment(self):
        with tempfile.TemporaryDirectory() as folder, patch.dict(os.environ, HOME=folder, CHRONICLE_RECONCILE_ENABLED='true', DOCKER_HOST='unix:///run/operator/docker.sock', LC_ALL='es_CL.UTF-8'), \
             patch('chronicle_ops.reconcile.platform.system', return_value='Linux'), patch('chronicle_ops.reconcile.shutil.which', return_value='/bin/tool'), \
             patch('chronicle_ops.reconcile.run', side_effect=lambda args, **_: SimpleNamespace(
                 returncode=int(args == ['crontab', '-l']), stdout='', stderr='no crontab for fixture')) as run:
            reconcile.install(Path(folder) / 'chronicle', folder, 'fixture')
            self.assertEqual(run.call_args_list[0].kwargs['env']['LC_ALL'], 'C')
            self.assertIn('unix:///run/operator/docker.sock', (Path(folder) / 'reconcile.sh').read_text())

    def test_storage_checks_docker_and_volume_inodes_before_mutation(self):
        results = [SimpleNamespace(stdout='/docker'), SimpleNamespace(stdout='pg'),
                   SimpleNamespace(stdout=json.dumps([POSTGRES_INSPECTION]))]
        disks = {'/state': SimpleNamespace(f_bavail=20, f_frsize=common.GIB, f_files=100000, f_favail=20000),
                 '/docker': SimpleNamespace(f_bavail=2, f_frsize=common.GIB, f_files=100000, f_favail=20000),
                 '/database': SimpleNamespace(f_bavail=20, f_frsize=common.GIB, f_files=100000, f_favail=2)}
        with patch('chronicle_ops.common.run', side_effect=results) as run, patch('chronicle_ops.common.os.statvfs', side_effect=lambda path: disks[str(path)]):
            rows = common.storage_report('/state', 'fixture')
        self.assertEqual([row[1] for row in rows], [True, False, False])
        self.assertIn('-a', run.call_args_list[1].args[0])

    def test_update_peak_is_reserved_on_image_and_state_devices(self):
        results = [SimpleNamespace(stdout='/docker'), SimpleNamespace(stdout='pg'),
                   SimpleNamespace(stdout=json.dumps([POSTGRES_INSPECTION]))]
        disk = SimpleNamespace(f_bavail=20, f_frsize=common.GIB, f_files=100000, f_favail=20000)
        with patch('chronicle_ops.common.run', side_effect=results), patch('chronicle_ops.common.os.statvfs', return_value=disk):
            rows = common.storage_report('/state', 'fixture', peak_bytes=common.UPDATE_PEAK_BYTES)
        self.assertEqual([row[4] for row in rows], [8 * common.GIB, 8 * common.GIB, 5 * common.GIB])

    def test_storage_probe_uses_read_only_daemon_mount_when_operator_cannot_traverse(self):
        results = [SimpleNamespace(stdout='/docker'), SimpleNamespace(stdout=''), SimpleNamespace(stdout=''),
                   SimpleNamespace(stdout='Filesystem 1024-blocks Used Available Capacity Mounted\ndisk 20000000 1 10000000 1% /storage\nFilesystem Inodes IUsed IFree IUse% Mounted\ndisk 100000 1 99999 1% /storage\n')]
        disk = SimpleNamespace(f_bavail=20, f_frsize=common.GIB, f_files=100000, f_favail=20000)
        with patch('chronicle_ops.common.run', side_effect=results) as run, \
             patch('chronicle_ops.common.os.statvfs', side_effect=[disk, PermissionError(), PermissionError()]), \
             patch.dict(os.environ, POSTGRES_IMAGE='fixture@sha256:'+'a'*64):
            rows = common.storage_report('/state', 'fixture')
        self.assertTrue(all(row[1] for row in rows))
        self.assertIn('type=bind,src=/docker,dst=/storage,readonly', run.call_args.args[0])
        self.assertIn('--read-only', run.call_args.args[0])

    def test_missing_daemon_paths_use_daemon_measurement(self):
        results = [SimpleNamespace(stdout='/docker'), SimpleNamespace(stdout='pg'),
                   SimpleNamespace(stdout=json.dumps([POSTGRES_INSPECTION]))]
        measured = SimpleNamespace(stdout='Filesystem blocks used available percent mount\ndisk 20000000 1 10000000 1% /storage\nFilesystem inodes used available percent mount\ndisk 100000 1 99999 1% /storage\n')
        disk = SimpleNamespace(f_bavail=20, f_frsize=common.GIB, f_files=100000, f_favail=20000)
        with patch.object(common, 'run', side_effect=results + [measured, measured]) as run, \
             patch.object(common.os, 'statvfs', side_effect=[disk, FileNotFoundError(), FileNotFoundError()]), \
             patch.dict(os.environ, POSTGRES_IMAGE='fixture-image'):
            self.assertTrue(all(row[1] for row in common.storage_report('/state', 'fixture')))
        self.assertEqual([call.args[0][call.args[0].index('--mount') + 1] for call in run.call_args_list[-2:]],
                         ['type=bind,src=/docker,dst=/storage,readonly', 'type=bind,src=/database,dst=/storage,readonly'])

    def test_a_postgres_container_without_pgdata_stops_the_storage_check(self):
        # An image override that declares no PGDATA: guessing a mount would measure the wrong disk.
        inspection = dict(POSTGRES_INSPECTION, Config={'Env': ['POSTGRES_DB=chronicle']})
        results = [SimpleNamespace(stdout='/docker'), SimpleNamespace(stdout='pg'), SimpleNamespace(stdout=json.dumps([inspection]))]
        disk = SimpleNamespace(f_bavail=20, f_frsize=common.GIB, f_files=100000, f_favail=20000)
        with patch.object(common, 'run', side_effect=results), patch.object(common.os, 'statvfs', return_value=disk), \
             self.assertRaisesRegex(ValueError, "cannot identify PostgreSQL's actual PGDATA mount"):
            common.require_storage('/state', 'fixture')

    def test_a_missing_state_directory_fails_instead_of_being_measured_through_docker(self):
        roomy = SimpleNamespace(stdout='h\nd 20000000 1 10000000 1% /storage\nh\nd 100000 1 99999 1% /storage\n')
        results = [SimpleNamespace(stdout='/docker'), SimpleNamespace(stdout=''), SimpleNamespace(stdout=''), roomy, roomy]
        with patch.object(common, 'run', side_effect=results) as run, patch.dict(os.environ, POSTGRES_IMAGE='fixture-image'), \
             patch.object(common.os, 'statvfs', side_effect=FileNotFoundError(2, 'No such file or directory', '/state')), \
             self.assertRaises(FileNotFoundError):
            common.storage_report('/state', 'fixture')
        self.assertFalse([call for call in run.call_args_list if call.args[0][:2] == ['docker', 'run']])

    def test_a_lock_descriptor_inherited_from_another_deployment_is_not_this_deployments_lock(self):
        with tempfile.TemporaryDirectory() as first, tempfile.TemporaryDirectory() as second, patch.dict(os.environ):
            os.environ.pop(common.LOCK_FD_ENV, None)
            (Path(second) / common.OPERATION_LOCK).touch()
            descriptor = common.acquire_operation_lock(first)
            try:
                self.assertEqual((True, False, False), (common.holds_operation_lock(first), common.holds_operation_lock(second),
                                                        common.holds_operation_lock(Path(second) / 'never-set-up')))
            finally:
                common.release_operation_lock(descriptor)
            self.assertFalse(common.holds_operation_lock(first))

    def test_a_failed_bounded_command_reports_its_status_and_output(self):
        # e.g. `docker info` while the daemon is stopped: the caller gets the failure, not empty output.
        with self.assertRaises(subprocess.CalledProcessError) as failure:
            common.run(['sh', '-c', 'echo partial; echo daemon down >&2; exit 3'], capture=True, stderr=subprocess.PIPE,
                       timeout=10, check=True)
        self.assertEqual((3, 'partial\n', 'daemon down\n'), (failure.exception.returncode, failure.exception.output,
                                                             failure.exception.stderr))
        self.assertEqual(3, common.run(['sh', '-c', 'exit 3'], timeout=10).returncode)

    def test_up_after_an_interrupted_recreation_removes_only_never_started_placeholders(self):
        never = '0001-01-01T00:00:00Z'
        containers = {
            'aaaaaaaaaaaa': ('aaaaaaaaaaaa_fixture-backend-1', 'fixture', 'created', never),           # removed
            'bbbbbbbbbbbb': ('bbbbbbbbbbbb_fixture-web-1', 'fixture', 'created', '2026-10-30T02:00:00Z'),  # once started: data
            'cccccccccccc': ('cccccccccccc_fixture-db-init-1', 'other', 'created', never),             # another project
            'dddddddddddd': ('fixture-postgres-1', 'fixture', 'created', never),                       # not a placeholder
            'eeeeeeeeeeee': ('eeeeeeeeeeee_fixture-migrate-1', 'fixture', 'created', never),           # inspect fails
            'ffffffffffff': ('ffffffffffff_fixture-web-1', 'fixture', 'created', never),               # renamed meanwhile
        }
        def docker(args, **kwargs):
            if args[:3] == ['docker', 'ps', '-a']:
                return SimpleNamespace(returncode=0, stdout=''.join(f'{key} {name}\n' for key, (name, *_) in containers.items()))
            if args[:2] == ['docker', 'inspect']:
                name, project, status, started = containers[args[2]]
                if args[2] == 'eeeeeeeeeeee':
                    return SimpleNamespace(returncode=1, stdout='')
                if args[2] == 'ffffffffffff':
                    name = 'fixture-web-1'  # Compose finished the rename after the listing
                return SimpleNamespace(returncode=0, stdout=json.dumps([{
                    'Id': args[2] * 4, 'Name': '/' + name, 'Config': {'Labels': {'com.docker.compose.project': project}},
                    'State': {'Status': status, 'StartedAt': started}}]))
            removed.append(args)
            return SimpleNamespace(returncode=0)
        for args, expected in ((['--progress', 'plain', 'up', '-d'], [['docker', 'rm', 'aaaaaaaaaaaa' * 4]]),
                               (['up', '-d', 'backend'], [['docker', 'rm', 'aaaaaaaaaaaa' * 4]]),
                               (['--progress', 'plain', 'ps'], [])):
            with self.subTest(args=args):
                removed = []
                with patch.object(common, 'run', side_effect=docker):
                    common.before_compose('fixture', args)
                self.assertEqual(expected, removed)

    def test_rotation_waits_for_startup_lock_before_loading_configuration(self):
        with tempfile.TemporaryDirectory() as folder:
            state = Path(folder)
            for name in ('rotate-secret.sh', 'network-policy.sh'):
                shutil.copy2(ROOT / 'selfhost' / name, state / name)
            (state / 'chronicle_ops').symlink_to(ROOT / 'selfhost/chronicle_ops', target_is_directory=True)
            settings = state / '.env'; settings.write_text('CHRONICLE_STATE_DIR=.\n'); settings.chmod(0o600)
            tools = state / 'bin'; tools.mkdir()
            (tools / 'docker').write_text('#!/bin/sh\nprintf called >"$DOCKER_LOCK_PROBE"\nexit 17\n')
            (tools / 'docker').chmod(0o700)
            descriptor = common.acquire_operation_lock(state)
            environment = dict(os.environ, PATH=str(tools) + ':' + os.environ['PATH'], DOCKER_LOCK_PROBE=str(state / 'called'))
            environment.pop(common.LOCK_FD_ENV, None)
            try:
                with subprocess.Popen(['bash', str(state / 'rotate-secret.sh'), '--yes', 'jwt'], env=environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE) as child:
                    try:
                        with self.assertRaises(subprocess.TimeoutExpired): child.communicate(timeout=0.3)
                        self.assertFalse((state / 'called').exists())
                        common.release_operation_lock(descriptor); descriptor = None
                        child.communicate(timeout=10)
                        self.assertNotEqual(child.returncode, 0)
                        self.assertTrue((state / 'called').exists())
                    finally:
                        if child.poll() is None: child.kill(); child.communicate()
            finally:
                common.release_operation_lock(descriptor)

    def test_startup_lock_works_without_shell_flock(self):
        source = (ROOT / 'selfhost/chronicle').read_text()
        function = re.search(r'^lock_operation\(\) \{\n.*?^\}', source, re.M | re.S).group(0)
        with tempfile.TemporaryDirectory() as folder:
            state = Path(folder)
            script = state / 'operation.sh'
            script.write_text('''#!/usr/bin/env bash
set -eu
SCRIPT_PATH="$0"
STATE_ROOT="$1"
ops_python() { case "$1" in -c) python3 "$@" ;; *) python3 -m chronicle_ops "$@" ;; esac; }
die() { exit 1; }
flock() { exit 99; }
''' + function + '''
lock_operation
python3 -c 'from chronicle_ops.common import acquire_operation_lock; import sys; assert acquire_operation_lock(sys.argv[1]) is None' "$STATE_ROOT"
# The shell itself holds the lock after the helper exits: an unrelated process is refused.
env -u CHRONICLE_OPERATION_LOCK_FD python3 -c 'from chronicle_ops.common import acquire_operation_lock; import sys
try: acquire_operation_lock(sys.argv[1], blocking=False)
except BlockingIOError: sys.exit(0)
sys.exit(3)' "$STATE_ROOT" 9<&-
''')
            script.chmod(0o700)
            result = subprocess.run(['bash', str(script), folder], env=dict(os.environ, PYTHONPATH=str(ROOT / 'selfhost'),
                                    CHRONICLE_OPS_STATE=folder), capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_recovery_verification_and_completion_hold_the_same_lock(self):
        from chronicle_ops.__main__ import main
        with tempfile.TemporaryDirectory() as folder, patch.dict(os.environ, CHRONICLE_OPS_STATE=folder):
            def check(*args):
                self.assertIsNone(common.acquire_operation_lock(folder))
                result = subprocess.run([sys.executable, '-c',
                    'from chronicle_ops.common import acquire_operation_lock; import sys; acquire_operation_lock(sys.argv[1], blocking=False)', folder],
                    env={key: value for key, value in dict(os.environ, PYTHONPATH=str(ROOT / 'selfhost')).items() if key != common.LOCK_FD_ENV},
                    capture_output=True, timeout=5)
                self.assertNotEqual(result.returncode, 0)
                return 0
            with patch('chronicle_ops.verify.verify', side_effect=check), \
                 patch('chronicle_ops.reconcile.complete_recovery', side_effect=check) as complete, \
                 patch('chronicle_ops.__main__.finish_operation'):
                self.assertEqual(main(['verify']), 0)
                complete.assert_called_once()
            self.assertNotIn(common.LOCK_FD_ENV, os.environ)

    def test_dashboard_trust_tracks_the_certificate_issuer_for_both_probes(self):
        with tempfile.TemporaryDirectory() as folder:
            tls = Path(folder) / 'tls'; tls.mkdir()
            (tls / 'internal-ca.crt').write_text('fixture anchor')
            settings = {'DASHBOARD_BASE_URL': 'https://dashboard.example.org'}
            for verifies, expected in ((0, 'internal-ca.crt'), (1, 'internal-cert.pem')):
                with patch.object(common, 'run', return_value=SimpleNamespace(returncode=verifies)) as openssl, \
                     patch.object(verify, 'run', return_value=SimpleNamespace(returncode=0, stdout='204')) as curl, \
                     patch.object(verify, 'read_env', return_value=settings), \
                     patch.object(Path, 'is_file', return_value=True), \
                     patch.dict(os.environ, CHRONICLE_OPS_STATE=folder):
                    verify.curl(settings['DASHBOARD_BASE_URL'] + '/health')
                    self.assertIn(str(tls / expected), curl.call_args.args[0])
                    self.assertIn(str(tls / 'internal-cert.pem'), openssl.call_args.args[0])
            self.assertIn('dashboard_ca("/tls")', (ROOT / 'selfhost/monitoring/probe.sh').read_text())

    def test_monitoring_healthcheck_uses_its_mounted_certificate(self):
        import yaml
        grafana = yaml.safe_load((ROOT / 'selfhost/overlays/monitoring.yml').read_text())['services']['grafana']
        certificate = grafana['environment']['GF_SERVER_CERT_FILE']
        # The image's wget is BusyBox, which has no CA option; curl verifies against the mount.
        self.assertIn('curl -fsS -o /dev/null --cacert ' + certificate, grafana['healthcheck']['test'][1])
        self.assertTrue(any(mount.endswith(':' + certificate + ':ro') or
                            mount.endswith(':' + str(Path(certificate).parent) + ':ro') for mount in grafana['volumes']))
        # On a read-only root Grafana must keep its bundled datasources rather than replace them.
        self.assertTrue(grafana['read_only'])
        self.assertEqual(grafana['environment']['GF_PLUGINS_PREINSTALL_AUTO_UPDATE'], 'false')

    def test_protected_docker_descendant_uses_actual_mount_without_pulling_an_image(self):
        protected = Path('/mounted docker/private')
        disk = SimpleNamespace(f_bavail=20, f_frsize=common.GIB, f_favail=common.MIN_FREE_INODES, f_files=50_000)
        def statvfs(path):
            if Path(path) == protected:
                raise PermissionError('protected descendant')
            return disk
        with patch.object(common, 'run', side_effect=[SimpleNamespace(stdout=str(protected)), SimpleNamespace(stdout=''), SimpleNamespace(stdout='')]) as run, \
             patch.object(common.os, 'statvfs', side_effect=statvfs) as measured, \
             patch.object(Path, 'read_text', return_value='1 0 8:0 / / rw\n2 1 8:1 / /mounted\\040docker rw\n'):
            rows = common.storage_report('/state', 'fixture')
        self.assertTrue(all(row[1] for row in rows))
        self.assertEqual(run.call_count, 3)
        self.assertEqual(measured.call_args.args[0], Path('/mounted docker'))

    def test_existing_database_bind_volume_is_checked_after_containers_are_removed(self):
        results = [SimpleNamespace(stdout='/docker'), SimpleNamespace(stdout=''), SimpleNamespace(stdout='fixture-db'),
                   SimpleNamespace(stdout=json.dumps([{'Mountpoint': '/docker/volumes/fixture-db/_data',
                                                       'Options': {'type': 'none', 'o': 'bind', 'device': '/database'}}]))]
        disk = SimpleNamespace(f_bavail=20, f_frsize=common.GIB, f_files=100000, f_favail=20000)
        with patch.object(common, 'run', side_effect=results), patch.object(common.os, 'statvfs', return_value=disk) as measured:
            rows = common.storage_report('/state', 'fixture')
        self.assertEqual(rows[-1][0], 'database-volume')
        self.assertEqual(measured.call_args.args[0], Path('/database'))

    def test_standalone_verification_preserves_the_transaction_checkpoint(self):
        with tempfile.TemporaryDirectory() as folder, patch.dict(os.environ, clear=True):
            state = Path(folder); owner = state/'new'; owner.mkdir()
            marker = state/'.chronicle-upgrade.lock'; marker.mkdir()
            receipts.write_json(marker/reconcile.RECOVERY_FILE, {'owner':str(owner), 'phase':reconcile.RECOVERY_PHASE})
            os.environ.update(CHRONICLE_OPS_STATE=folder, CHRONICLE_OPS_PROJECT='fixture')
            with patch.object(Path, 'cwd', return_value=owner), patch('chronicle_ops.reconcile.preflight'), patch('chronicle_ops.reconcile.install') as install:
                reconcile.complete_recovery()
                install.assert_not_called()
            self.assertTrue(marker.exists())
            self.assertNotIn(common.LOCK_FD_ENV, os.environ)

    def test_release_cleanup_retains_active_state_recovery_and_rollback_window(self):
        with tempfile.TemporaryDirectory() as folder:
            parent = Path(folder); bundles=[]
            for version in range(1,7):
                path=parent/f'chronicle-selfhost-1.0.{version}'; (path/'selfhost').mkdir(parents=True)
                (path/'release-manifest.json').write_text(json.dumps({'release_version':f'1.0.{version}',
                    'images':{'backend':f'fixture:{version}@sha256:'+'a'*64}}))
                path.with_name(path.name+'.tar.gz').touch(); bundles.append(path)
            state=bundles[0]/'selfhost'; marker=state/'.chronicle-upgrade.lock'; marker.mkdir()
            receipts.write_json(marker/reconcile.RECOVERY_FILE, {'owner':str(bundles[1]/'selfhost')})
            with patch.object(Path,'cwd',return_value=bundles[-1]/'selfhost'), patch('chronicle_ops.release.run', return_value=SimpleNamespace(stdout='[]')) as run, patch('sys.stdout',io.StringIO()):
                release.cleanup_releases(parent,state)
                self.assertTrue(all(path.exists() for path in bundles))
                self.assertTrue(all('rm' not in call.args[0] for call in run.call_args_list))
                release.cleanup_releases(parent,state,True)
            self.assertEqual([path.exists() for path in bundles], [True,True,False,True,True,True])
            self.assertFalse(bundles[2].with_name(bundles[2].name+'.tar.gz').exists())
            self.assertIn('--',run.call_args.args[0])
            # Cleanup after an update keeps the images of every release it keeps: the state holder,
            # the recovery owner and the retention window, not only the active and rollback releases.
            with patch.object(Path, 'cwd', return_value=bundles[-1] / 'selfhost'), \
                 patch('chronicle_ops.release.run', return_value=SimpleNamespace(stdout='[]')) as automatic, patch('sys.stdout', io.StringIO()):
                release.cleanup_releases(parent, state, True, rollback_target=bundles[-2])
            removed = {call.args[0][-1] for call in automatic.call_args_list if call.args[0][:3] == ['docker', 'image', 'rm']}
            self.assertEqual(removed, set())
            self.assertTrue(bundles[-2].exists())


    def test_ipv6_host_sockets_and_backend_origin_use_native_shell_syntax(self):
        source=(ROOT/'selfhost/chronicle').read_text()
        start=source.index('host_listening() {'); end=source.index('\n}\n',start)+2
        shell=source[start:end]+'\nss() { printf "Header\\nLISTEN 0 0 [fd42::1]:8081 [::]:*\\n"; }; host_listening'
        result=shell_probe(shell)
        self.assertEqual(result.stdout,'fd42::1:8081\n')
        source=(ROOT/'selfhost/backend-entrypoint.sh').read_text()
        start=source.index('case "$INTERNAL_BIND" in'); end=source.index('\nesac',start)+len('\nesac')
        for address in ('fd42::1','[fd42::1]','127.0.0.1'):
            result=shell_probe(source[start:end]+'\nprintf "%s" "$INTERNAL_BIND"', shell='sh',
                                  env=dict(os.environ,INTERNAL_BIND=address))
            self.assertEqual(result.stdout,'127.0.0.1' if address=='127.0.0.1' else '[fd42::1]')

    def test_backend_refuses_a_public_base_url_that_is_not_an_https_root_origin(self):
        base = {key: value for key, value in os.environ.items() if not key.startswith(('CHRONICLE_', 'POSTGRES_', 'JWT_'))}
        for origin, accepted in (('https://study.example.org', True), ('https://[fd42::1]:8443', True),
                                 ('http://study.example.org', False), ('https://study.example.org/path', False),
                                 ('https://study.example.org:70000', False), ('https://a b', False)):
            with self.subTest(origin=origin):
                result = subprocess.run(['sh', str(ROOT / 'selfhost/backend-entrypoint.sh')], capture_output=True, text=True,
                                        env=dict(base, DOMAIN='study.example.org', CHRONICLE_PUBLIC_BASE_URL=origin), timeout=10)
                self.assertEqual(1, result.returncode)
                self.assertEqual(accepted, 'must be an exact HTTPS root origin' not in result.stderr, result.stderr)
                if accepted:
                    self.assertIn('POSTGRES_APP_PASSWORD is not set', result.stderr)

    def test_cleanup_preserves_another_deployments_configuration_state_and_live_owner(self):
        for kind in ('configuration', 'backup', 'tls', 'live'):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as folder:
                parent = Path(folder); state = parent / 'state'; state.mkdir()
                bundles = []
                for version in range(7):
                    path = parent / f'chronicle-selfhost-1.0.{version}'
                    (path / 'selfhost').mkdir(parents=True)
                    (path / 'release-manifest.json').write_text(json.dumps({'release_version': f'1.0.{version}',
                        'images': {'backend': f'fixture:{version}@sha256:' + 'a' * 64}}))
                    path.with_name(path.name + '.tar.gz').touch(); bundles.append(path)
                other = bundles[0] / 'selfhost'
                rows = []
                if kind == 'configuration':
                    (other / '.env').write_text('JWT_SECRET=synthetic-private-configuration\n')
                elif kind in ('backup', 'tls'):
                    directory = other / ('backups' if kind == 'backup' else 'tls'); directory.mkdir()
                    (directory / 'private-fixture').write_text('must survive')
                else:
                    rows = [{'Name': 'other-deployment', 'ConfigFiles': str(other / 'docker-compose.yml')}]
                with patch.object(Path, 'cwd', return_value=bundles[-1] / 'selfhost'), \
                     patch('chronicle_ops.release.run', return_value=SimpleNamespace(stdout=json.dumps(rows))), \
                     patch('sys.stdout', io.StringIO()):
                    release.cleanup_releases(parent, state, True)
                self.assertTrue(bundles[0].exists())
                self.assertTrue(bundles[0].with_name(bundles[0].name + '.tar.gz').exists())
                self.assertFalse(bundles[1].exists())

    def test_unset_pool_allowlist_admits_any_source(self):
        # A 2026.10.3 .env has no POOL_ALLOWED_IPS; a loopback default would 403 every phone.
        compose=(ROOT/'selfhost/docker-compose.yml').read_text()
        self.assertEqual(compose.count('POOL_ALLOWED_IPS: ${POOL_ALLOWED_IPS:-0.0.0.0/0 ::/0}'),
                         compose.count('      POOL_ALLOWED_IPS:'))
        self.assertIn('{$POOL_ALLOWED_IPS:0.0.0.0/0 ::/0}',(ROOT/'selfhost/caddy/snippets.caddy').read_text())
        self.assertIn('\nPOOL_ALLOWED_IPS=\n',(ROOT/'selfhost/.env.example').read_text())

    def test_backup_marker_requires_active_fresh_verified_dump(self):
        with tempfile.TemporaryDirectory() as folder:
            last = Path(folder) / 'last'; last.mkdir()
            path = last / 'custom-1.sql.gz'; path.write_bytes(gzip.compress(DUMP))
            dump.publish_backup(path, 'custom', {'database_bytes': 4096})
            self.assertEqual(dump.verified_backup(folder, 'custom', '@daily').path, path)
            with self.assertRaises(OSError): dump.verified_backup(folder, 'chronicle', '@daily')
            with patch('chronicle_ops.dump.time.time', return_value=time.time() + dump.backup_max_age_seconds('@daily') + 1):
                with self.assertRaises(dump.DumpError): dump.verified_backup(folder, 'custom', '@daily')
            path.write_bytes(b'failed dump')
            with self.assertRaises(dump.DumpError): dump.verified_backup(folder, 'custom', '@daily')

    def test_backup_overdue_window_follows_the_configured_schedule(self):
        hour, day = 60 * 60, 24 * 60 * 60
        margin = 36 * hour - day  # today's 36 h window for the default daily schedule
        self.assertEqual(36 * hour, dump.backup_max_age_seconds('@daily'))
        self.assertEqual(36 * hour, dump.backup_max_age_seconds(''))
        for schedule, interval in (('@hourly', hour), ('@midnight', day), ('@weekly', 7 * day),
                                   ('@monthly', 31 * day), ('@yearly', 366 * day), ('@annually', 366 * day),
                                   ('@every 6h', 6 * hour), ('@every 1h30m', 90 * 60)):
            with self.subTest(schedule=schedule):
                self.assertEqual(interval + margin, dump.backup_max_age_seconds(schedule))
        for schedule in ('0 3 * *', '@every', '@every 1d', '@fortnightly', '@DAILY'):
            with self.subTest(schedule=schedule), self.assertRaisesRegex(ValueError, 'BACKUP_SCHEDULE'):
                dump.backup_max_age_seconds(schedule)
        with tempfile.TemporaryDirectory() as folder:
            last = Path(folder) / 'last'; last.mkdir()
            path = last / 'custom-1.sql.gz'; path.write_bytes(gzip.compress(DUMP))
            dump.publish_backup(path, 'custom', {'database_bytes': 4096})
            cache = Path(folder) / dump.BACKUP_VERIFICATION_CACHE
            self.assertEqual(path, dump.cached_verified_backup(folder, 'custom', cache, '@weekly').path)
            # Two days after a weekly run the backup is current; a daily schedule has missed a run.
            with patch('chronicle_ops.dump.time.time', return_value=time.time() + 2 * day):
                self.assertEqual(path, dump.verified_backup(folder, 'custom', '@weekly').path)
                self.assertEqual(path, dump.cached_verified_backup(folder, 'custom', cache, '@weekly').path)
                for check in (lambda: dump.verified_backup(folder, 'custom', '@daily'),
                              lambda: dump.cached_verified_backup(folder, 'custom', cache, '@daily')):
                    with self.assertRaises(dump.DumpError): check()
                with patch.dict(os.environ, CHRONICLE_OPS_BACKUPS=folder):
                    for schedule, status in (('@weekly', 0), ('@daily', 1)):
                        with self.subTest(schedule=schedule), patch('sys.stdout', io.StringIO()):
                            self.assertEqual(status, verify.verify_backup(folder, 'custom', schedule))

    def test_failed_scratch_restore_never_publishes_or_accumulates_dumps(self):
        spec = importlib.util.spec_from_file_location('topology_selfcheck', ROOT / 'selfhost/backup-image/selfcheck.py')
        check = importlib.util.module_from_spec(spec); spec.loader.exec_module(check)
        with tempfile.TemporaryDirectory() as folder:
            last = Path(folder) / 'last'; last.mkdir()
            def snapshot(database, path, options):
                path.write_bytes(gzip.compress(DUMP)); return {'database_bytes': 4096}
            with patch.object(check, 'dump_snapshot', side_effect=snapshot), patch.object(check, 'drop_scratch'), patch('sys.stderr', io.StringIO()), patch('sys.stdout', io.StringIO()):
                for i in range(3):
                    with patch.object(check, 'check_dump', side_effect=RuntimeError('scratch failed')):
                        self.assertEqual(check.main(['dump', 'custom', str(last / f'custom-{i}.sql.gz')]), 1)
                    self.assertEqual(list(last.glob('*.sql.gz*')), [])
                    self.assertFalse(dump.backup_marker(folder, 'custom').exists())
                with patch.object(check, 'check_dump'):
                    self.assertEqual(check.main(['dump', 'custom', str(last / 'custom-good.sql.gz')]), 0)
                self.assertEqual(dump.verified_backup(folder, 'custom', '@daily').path.name, 'custom-good.sql.gz')

    def test_doctor_projects_scratch_retention_and_wal_independently_of_tde(self):
        with tempfile.TemporaryDirectory() as folder:
            data = {'database_bytes': 10000, 'wal_bytes': 5000, 'max_wal_bytes': 2000}
            result = SimpleNamespace(stdout='Filesystem blocks used available percent mount\ndisk 100 90 1 90% /db\n'+json.dumps(data))
            settings = {'POSTGRES_DB': 'custom', 'COMPOSE_FILE': 'docker-compose.yml:overlays/backups.yml', 'ENABLE_ENCRYPTION': 'false'}
            with patch('chronicle_ops.verify.compose', return_value=result), \
                 patch('chronicle_ops.verify.storage_report', return_value=[('database-volume', False, 1024, common.MIN_FREE_INODES, 5 * common.GIB)]), \
                 patch('chronicle_ops.verify.os.statvfs', return_value=SimpleNamespace(f_bavail=1, f_frsize=1024)):
                rows = verify.capacity_checks(settings, folder)
                self.assertEqual([(row[0], row[1]) for row in rows], [('database-disk', 'warn'), ('backup', 'fail'), ('backup-reserve', 'fail'), ('backup-footprint', 'warn'), ('postgres-wal', 'warn')])
                settings['COMPOSE_FILE']='docker-compose.yml'
                self.assertEqual([row[0] for row in verify.capacity_checks(settings, folder)], ['database-disk', 'postgres-wal'])

    def test_metrics_require_every_target_and_fresh_samples(self):
        from datetime import datetime, timezone
        now = int(time.time())
        targets = [{'labels': {'job': job}, 'health': 'up', 'lastScrape': datetime.fromtimestamp(now, timezone.utc).isoformat()} for job in verify.MONITORING_JOBS]
        payload = {'data': {'activeTargets': targets}}
        self.assertTrue(verify.healthy_targets(payload, now))
        self.assertFalse(verify.healthy_targets({'data': {'activeTargets': targets[:-1]}}, now))
        self.assertFalse(verify.healthy_targets(payload, now + verify.METRICS_MAX_AGE_SECONDS + 1))
        targets[0]['health']='down'
        self.assertFalse(verify.healthy_targets(payload, now))

    def test_metrics_accept_victoriametrics_fraction_widths(self):
        # VictoriaMetrics trims trailing zeros (`:09.41Z`); Python 3.9 on RHEL 9 parses only 3 or 6 digits.
        from datetime import datetime

        class Python39Datetime(datetime):
            @classmethod
            def fromisoformat(cls, text):
                if 'Z' in text or re.search(r'\.(?!\d{3}(?:\d{3})?(?:[+-]|$))\d', text):
                    raise ValueError('Invalid isoformat string: %r' % text)
                return super().fromisoformat(text)

        scraped = datetime.fromisoformat('2026-10-06T16:47:09+00:00').timestamp()
        with patch('chronicle_ops.credentials.datetime', Python39Datetime):
            with self.assertRaises(ValueError):
                Python39Datetime.fromisoformat('2026-10-06T16:47:09.41+00:00')
            for stamp in ('2026-10-06T16:47:09.41Z', '2026-10-06T16:47:09.4Z', '2026-10-06T16:47:09.123456789Z',
                          '2026-10-06T16:47:09Z'):
                with self.subTest(stamp=stamp):
                    targets = [{'labels': {'job': job}, 'health': 'up', 'lastScrape': stamp} for job in verify.MONITORING_JOBS]
                    self.assertTrue(verify.healthy_targets({'data': {'activeTargets': targets}}, scraped + 5))
                    self.assertFalse(verify.healthy_targets({'data': {'activeTargets': targets}},
                                                            scraped + verify.METRICS_MAX_AGE_SECONDS + 1))

    def test_routine_receipts_are_bounded_and_incidents_retained(self):
        with tempfile.TemporaryDirectory() as folder, patch.dict(os.environ, CHRONICLE_OPS_STATE=folder), patch.object(receipts, 'ROUTINE_RECEIPT_KEEP', 3):
            receipts.write_operation_receipt('up', 'failure', 'startup_failed')
            receipts.write_operation_receipt('upgrade', 'success')
            for _ in range(6): receipts.write_operation_receipt('up', 'success')
            files = list((Path(folder) / 'operator-receipts/operations').glob('*.json'))
            self.assertEqual(len(files), 5)
            self.assertEqual(sum(json.loads(path.read_text())['outcome'] == 'failure' for path in files), 1)

    def test_a_receipt_truncated_by_a_full_disk_is_kept_and_does_not_stop_pruning(self):
        with tempfile.TemporaryDirectory() as folder, patch.dict(os.environ, CHRONICLE_OPS_STATE=folder), patch.object(receipts, 'ROUTINE_RECEIPT_KEEP', 3):
            root = Path(folder) / 'operator-receipts/operations'
            receipts.write_operation_receipt('up', 'success')
            truncated = root / '20261031T020000Z-up-1-1.json'
            truncated.write_text('{"operation": "up", "outc')
            for _ in range(5): receipts.write_operation_receipt('up', 'success')
            self.assertTrue(truncated.exists())  # evidence of the incident; never parsed as a success
            self.assertEqual(3, sum(path != truncated for path in root.glob('*.json')))

    def test_repeated_reconciliation_failures_are_bounded_per_operation(self):
        with tempfile.TemporaryDirectory() as folder, \
             patch.dict(os.environ, CHRONICLE_OPS_STATE=folder), patch.object(receipts, 'ROUTINE_RECEIPT_KEEP', 3):
            receipts.write_operation_receipt('upgrade', 'failure', 'upgrade_failed')
            for _ in range(6):
                receipts.write_operation_receipt('up', 'failure', 'startup_failed')
                receipts.write_operation_receipt('doctor', 'failure', 'diagnosis_failed')
            files = list((Path(folder) / 'operator-receipts/operations').glob('*.json'))
            self.assertEqual(len(files), 7)
            self.assertEqual(sum(json.loads(path.read_text())['operation'] == 'up' for path in files), 3)

    def test_session_rejects_html_and_requires_cookie_follow_up(self):
        for response in ('<html>success</html>\n200', '{"authenticated": false}\n200'):
            with patch('chronicle_ops.verify.curl', return_value=(0, response)) as curl:
                self.assertFalse(verify.dashboard_session('https://management.example.org', 'synthetic')[0])
                self.assertEqual(curl.call_count, 1)
        with patch('chronicle_ops.verify.curl', side_effect=[(0, '{"authenticated":true,"csrfToken":"fixture"}\n200'), (0, '{"authenticated":false}\n200')]) as curl:
            self.assertFalse(verify.dashboard_session('https://management.example.org', 'synthetic')[0])
            self.assertIn('--cookie', curl.call_args.args)

    def test_session_token_must_match_the_csrf_cookie_session_set(self):
        def server(issued, returned):
            def fake(url, *args, **_):
                jar = args[args.index('--cookie-jar') + 1]
                token = 'login-token' if url.endswith('/dashboard-login') else issued
                Path(jar).write_text('# Netscape HTTP Cookie File\n'
                                     f'127.0.0.1\tFALSE\t/chronicle\tTRUE\t0\tol_csrf_token\t{token}\n')
                csrf = 'login-token' if url.endswith('/dashboard-login') else returned
                return 0, json.dumps({'authenticated': True, 'csrfToken': csrf}) + '\n200'
            return fake
        for issued, returned, expected in (('rotated', 'rotated', True), ('rotated', 'login-token', False), ('', '', False)):
            with patch('chronicle_ops.verify.curl', side_effect=server(issued, returned)):
                self.assertEqual(verify.dashboard_session('https://management.example.org', 'synthetic'), (expected, '200'))

    def test_monitoring_budget_includes_core_and_host_headroom(self):
        settings = envfile.read_env(ROOT / 'selfhost/.env.example')
        with self.assertRaises(ValueError): host_memory.require_memory(settings, 4 * 1024 ** 2, True)
        self.assertLess(host_memory.require_memory(settings, 10 * 1024 ** 2, True), 10 * common.GIB)

    def test_rollback_transfers_schedule_and_only_resumes_after_acceptance(self):
        from chronicle_ops.restore import rollback
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder); old=root/'old'; current=root/'new'; state=root/'state'
            for path in (old,current,state): path.mkdir()
            settings=f"COMPOSE_PROJECT_NAME=fixture\nCHRONICLE_STATE_DIR='{state}'\nCOMPOSE_FILE=docker-compose.yml:overlays/mode-behind-proxy-internal.yml\n"
            for path in (old,current):
                (path/'.env').write_text(settings); (path/'.env').chmod(0o600); (path/'.env.example').write_text(settings)
            (old/'chronicle_ops').mkdir(); (old/'chronicle_ops/__main__.py').touch()
            marker=state/'.chronicle-upgrade.lock'; marker.mkdir()
            receipts.write_json(marker/reconcile.RECOVERY_FILE, {'previous':str(old), 'owner':str(current),'phase':reconcile.RECOVERY_PHASE})
            events=[]
            def startup(*_args):
                events.append('up')
                self.assertTrue((state/reconcile.STOP_MARKER).exists())
            def start(args, **kwargs):
                events.append(args[-1])
                self.assertTrue((state/reconcile.STOP_MARKER).exists())
                return SimpleNamespace(returncode=0)
            with patch.object(Path,'cwd',return_value=current), patch('chronicle_ops.restore.Restore.execute',return_value=0), \
                 patch('chronicle_ops.restore.compose'), patch('chronicle_ops.common.run',side_effect=start), \
                 patch('chronicle_ops.upgrade.start_release', side_effect=startup), \
                 patch('chronicle_ops.reconcile.install') as install, patch.dict(os.environ, clear=True):
                self.assertEqual(rollback(old,'/backups/reviewed.sql.gz','a'*64,True),0)
                install.assert_called_once_with(old/'chronicle',state,'fixture',update_only=True)
            self.assertEqual(events,['up','verify'])
            self.assertFalse((current / '.env').exists())
            archives = list((state / receipts.OPERATOR_RECEIPTS_DIR).glob('.env.rollback-*'))
            self.assertEqual(len(archives), 1)
            self.assertEqual(archives[0].stat().st_mode & 0o777, 0o600)
            self.assertEqual(envfile.read_env(archives[0])['COMPOSE_PROJECT_NAME'], 'fixture')
            self.assertFalse((state/reconcile.STOP_MARKER).exists())
            self.assertFalse(marker.exists())

    def test_rollback_preserves_rotated_credentials_and_previous_image_pins(self):
        from chronicle_ops.restore import rollback
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); old = root / 'old'; current = root / 'new'; state = root / 'state'
            for path in (old, current, state): path.mkdir()
            credentials = {'POSTGRES_PASSWORD', 'JWT_SECRET', 'DASHBOARD_PASSWORD_HASH',
                           'CHRONICLE_INTERNAL_WEB_SECRET', 'METRICS_PASSWORD', 'GRAFANA_ADMIN_PASSWORD',
                           'CHRONICLE_REVIEWER_ACCESS_SECRET', 'CHRONICLE_REVIEWER_ACCESS_ENABLED'}
            containment = {'HTTP_BIND': ('10.20.0.5', '127.0.0.1'),
                           'INTERNAL_BIND': ('10.20.0.5', '127.0.0.1'),
                           'GRAFANA_BIND': ('10.20.0.5', '127.0.0.1'),
                           'DASHBOARD_ALLOWED_IPS': ('10.0.0.0/8', '127.0.0.1/32'),
                           'POOL_ALLOWED_IPS': ('0.0.0.0/0 ::/0', '127.0.0.1/32'),
                           'CADDY_TRUSTED_PROXIES': ('10.0.0.0/8', '127.0.0.1/32'),
                           'POOL_LISTENER_TLS': ('true', 'false'),
                           'POOL_PLAINTEXT_WAIVER': ('RISK-2026-07 LB VLAN', '')}
            settings = f"COMPOSE_PROJECT_NAME=fixture\nCHRONICLE_STATE_DIR='{state}'\nCOMPOSE_FILE=docker-compose.yml:overlays/mode-behind-proxy-internal.yml\n"
            for path, version in ((old, 'previous'), (current, 'current')):
                text = settings + f'BACKEND_IMAGE={version}-image\nRELEASE_VERSION={version}\n'
                text += ''.join(f"{key}='{version}-{key}'\n" for key in sorted(credentials))
                text += ''.join(f"{key}='{values[version == 'current']}'\n" for key, values in containment.items())
                (path / '.env').write_text(text); (path / '.env').chmod(0o600); (path / '.env.example').write_text(text)
            (old / 'chronicle_ops').mkdir(); (old / 'chronicle_ops/__main__.py').touch()
            with patch.object(Path, 'cwd', return_value=current), \
                 patch('chronicle_ops.restore.Restore.execute', return_value=0), \
                 patch('chronicle_ops.restore.compose'), patch('chronicle_ops.common.run', return_value=SimpleNamespace(returncode=0)), \
                 patch('chronicle_ops.upgrade.start_release'), \
                 patch('chronicle_ops.release.compose_projects', return_value=[{'Name': 'fixture', 'ConfigFiles': str(current / 'docker-compose.yml')}]), \
                 patch('chronicle_ops.reconcile.install'), patch.dict(os.environ, clear=True):
                self.assertEqual(rollback(old, '/backups/reviewed.sql.gz', 'a' * 64, True), 0)
            actual = envfile.read_env(old / '.env')
            for key in credentials:
                self.assertEqual(envfile.value(actual, key), f'current-{key}')
            for key, (_, tightened) in containment.items():
                self.assertEqual(envfile.value(actual, key), tightened, key)
            self.assertEqual(envfile.value(actual, 'BACKEND_IMAGE'), 'previous-image')
            self.assertEqual(envfile.value(actual, 'RELEASE_VERSION'), 'previous')

    def test_superseded_rollback_cannot_restore_retired_credentials_or_pause_active_release(self):
        from chronicle_ops.restore import rollback
        with tempfile.TemporaryDirectory() as folder, patch.dict(os.environ):
            root = Path(folder); state = root / 'state'; state.mkdir()
            old, superseded, active = (root / name for name in ('A', 'B', 'C'))
            for path in (old, superseded, active):
                path.mkdir()
                (path / '.env').write_text(f"COMPOSE_PROJECT_NAME=fixture\nCHRONICLE_STATE_DIR='{state}'\nJWT_SECRET={path.name}-secret\n")
                (path / '.env').chmod(0o600)
            (state / 'reconcile.sh').write_text('cd ' + str(active) + '\n')
            (old / 'chronicle_ops').mkdir(); (old / 'chronicle_ops/__main__.py').touch()
            snapshot = (old / '.env').read_text()
            for inventory in ([], [{'Name': 'fixture', 'ConfigFiles': str(active / 'docker-compose.yml')}]):
                with patch.object(Path, 'cwd', return_value=superseded), \
                     patch('chronicle_ops.release.compose_projects', return_value=inventory), \
                     patch('chronicle_ops.restore.Restore.execute') as restore, \
                     patch('chronicle_ops.reconcile.install') as install, \
                     self.assertRaisesRegex(ValueError, 'superseded|does not own'):
                    rollback(old, '/backups/reviewed.sql.gz', 'a' * 64, True)
                restore.assert_not_called(); install.assert_not_called()
                self.assertEqual((old / '.env').read_text(), snapshot)
                self.assertFalse((state / reconcile.STOP_MARKER).exists())
            with patch.object(Path, 'cwd', return_value=active), \
                 patch('chronicle_ops.release.compose_projects', return_value=[]), \
                 patch('chronicle_ops.restore.Restore.execute', return_value=1), \
                 self.assertRaisesRegex(ValueError, 'automatic rollback restore failed'):
                rollback(old, '/backups/reviewed.sql.gz', 'a' * 64, True)
            self.assertTrue((active / '.env').exists())
            self.assertEqual(list((state / receipts.OPERATOR_RECEIPTS_DIR).glob('.env.rollback-*')), [])
            self.assertTrue((state / reconcile.STOP_MARKER).exists())

    def test_host_routes_force_safe_subnet_selection_without_docker_conflicts(self):
        spec=importlib.util.spec_from_file_location('topology_subnet',ROOT/'selfhost/network-subnet.py')
        subnet=importlib.util.module_from_spec(spec);spec.loader.exec_module(subnet)
        networks=[{'Name':'VPN','IPAM':{'Config':[{'Subnet':'172.28.0.0/16'},{'Subnet':'10.253.0.0/24'}]}}]
        with patch.object(subnet,'docker_networks',return_value=[]), patch.object(subnet,'host_networks',return_value=networks), patch('sys.stdout',io.StringIO()) as output:
            subnet.select('172.28.0.0/16','fixture')
            self.assertEqual(output.getvalue(),'10.253.1.0/24\n')

    def subnet_module(self, networks=(), routes=(), ip=True):
        spec = importlib.util.spec_from_file_location('topology_subnet', ROOT / 'selfhost/network-subnet.py')
        subnet = importlib.util.module_from_spec(spec); spec.loader.exec_module(subnet)
        self.commands = []
        def host(args, **kwargs):
            self.commands.append(args)
            if args[:3] == ['docker', 'network', 'ls']:
                return SimpleNamespace(stdout=''.join(network['Id'] + '\n' for network in networks))
            if args[:3] == ['docker', 'network', 'inspect']:
                return SimpleNamespace(stdout=json.dumps([network for network in networks if network['Id'] in args[3:]]))
            if args[0] == 'ip':
                return SimpleNamespace(stdout=json.dumps([route for route in routes if (':' in route.get('dst', '')) == (args[1] == '-6')]))
            raise AssertionError(args)
        for item in (patch.object(subnet.subprocess, 'run', side_effect=host),
                     patch.object(subnet.shutil, 'which', return_value='/usr/sbin/ip' if ip else None)):
            item.start(); self.addCleanup(item.stop)
        return subnet

    def test_up_refuses_a_subnet_another_network_or_vpn_route_already_uses(self):
        own_labels = {'com.docker.compose.project': 'fixture', 'com.docker.compose.network': 'default'}
        own = {'Id': 'aaaaaaaaaaaa1', 'Name': 'fixture_default', 'Labels': own_labels, 'Options': {},
               'IPAM': {'Config': [{'Subnet': '10.40.0.0/24'}]}}
        lab = {'Id': 'bbbbbbbbbbbb2', 'Name': 'lab_net', 'IPAM': {'Config': [{'Subnet': '10.40.0.0/16'}]}}
        # Same name, owned by another Compose project (a second install with `name: fixture_default`): never adopted.
        impostor = dict(own, Id='cccccccccccc3', Labels=dict(own_labels, **{'com.docker.compose.project': 'fixture-old'}))
        empty = {'Id': 'dddddddddddd4', 'Name': 'none', 'IPAM': {'Config': [{'Gateway': ''}, {}]}}
        v6 = {'Id': 'eeeeeeeeeeee5', 'Name': 'v6', 'IPAM': {'Config': [{'Subnet': 'fd00:40::/64'}]}}
        vpn = {'dst': '10.40.0.0/20', 'dev': 'tun0'}
        own_bridge = {'dst': '10.40.0.0/24', 'dev': 'br-aaaaaaaaaaaa'}
        for case, networks, routes, conflict in (
                ('running stack re-up', [own, empty, v6], [own_bridge, {'dst': 'default', 'dev': 'eth0'}], None),
                ('docker network', [own, empty, lab], [], 'overlaps Docker network lab_net (10.40.0.0/16)'),
                ('hand-made default', [impostor], [], 'overlaps Docker network fixture_default (10.40.0.0/24)'),
                ('institutional VPN route', [own], [own_bridge, vpn], 'overlaps Docker network host route tun0 (10.40.0.0/20)')):
            with self.subTest(case):
                subnet = self.subnet_module(networks, routes)
                config = {'name': 'fixture', 'networks': {'default': {'ipam': {'config': [{'subnet': '10.40.0.0/24'}]}}}}
                with patch('sys.stdin', io.StringIO(json.dumps(config))):
                    if conflict is None:
                        self.assertIsNone(subnet.check())
                    else:
                        with self.assertRaises(SystemExit) as refused:
                            subnet.check()
                        self.assertEqual('CHRONICLE_SUBNET 10.40.0.0/24 ' + conflict
                                         + '; set CHRONICLE_SUBNET in .env to a free private range', str(refused.exception))
        subnet = self.subnet_module([lab])
        with patch('sys.stdin', io.StringIO(json.dumps({'name': 'fixture', 'networks': {'default': {}}}))):
            self.assertIsNone(subnet.check())  # Compose chooses the subnet; nothing to compare
        self.assertEqual([], self.commands)

    def test_setup_picks_a_free_subnet_even_without_a_reachable_docker_daemon(self):
        taken = [{'dst': f'10.253.{index}.0/24', 'dev': 'tun0'} for index in range(256)]
        for case, routes, chosen in (('default free', [], '172.28.0.0/16\n'),
                                     ('default routed', [{'dst': '172.28.0.0/14', 'dev': 'tun0'}], '10.253.0.0/24\n')):
            with self.subTest(case):
                subnet = self.subnet_module(routes=routes)
                subnet.subprocess.run.side_effect = lambda args, _host=subnet.subprocess.run.side_effect, **kwargs: (
                    _host(args, **kwargs) if args[0] == 'ip' else (_ for _ in ()).throw(FileNotFoundError('docker')))
                with patch('sys.stdout', io.StringIO()) as output:
                    subnet.select('172.28.0.0/16', 'fixture')
                self.assertEqual(chosen, output.getvalue())
        subnet = self.subnet_module(routes=taken + [{'dst': '172.28.0.0/16', 'dev': 'tun0'}])
        with self.assertRaisesRegex(SystemExit, r'no free subnet in 10\.253\.0\.0/16; set CHRONICLE_SUBNET in \.env'):
            subnet.select('172.28.0.0/16', 'fixture')

    def test_route_checks_need_iproute2_on_linux_and_read_netstat_on_macos(self):
        subnet = self.subnet_module(ip=False)
        with patch.object(subnet.sys, 'platform', 'linux'), self.assertRaisesRegex(ValueError, 'iproute2 is required'):
            subnet.host_networks([], 'fixture')
        netstat = ('Routing tables\n\nInternet:\nDestination        Gateway            Flags\ndefault            192.168.1.1        UGScg\n'
                   '10                 link#17            UCS\n172.16             link#18            UC\n'
                   '192.168.1          link#6             UCS\n192.168.1.0/25     link#6             UCS\n'
                   'fe80::%lo0/64      fe80::1%lo0        UcI\n')
        subnet.subprocess.run.side_effect = lambda args, **kwargs: SimpleNamespace(stdout=netstat)
        with patch.object(subnet.sys, 'platform', 'darwin'):
            routes = subnet.host_networks([], 'fixture')
        self.assertEqual(['10.0.0.0/8', '172.16.0.0/16', '192.168.1.0/24', '192.168.1.0/25', 'fe80::%lo0/64'],
                         [route['IPAM']['Config'][0]['Subnet'] for route in routes])

    def test_subnet_helper_command_line_fails_with_one_operator_message(self):
        with tempfile.TemporaryDirectory() as folder:
            (Path(folder) / 'docker').write_text('#!/bin/sh\necho "Cannot connect to the Docker daemon" >&2\nexit 1\n')
            (Path(folder) / 'docker').chmod(0o755)
            environment = dict(os.environ, PATH=folder + os.pathsep + os.environ['PATH'], PYTHONDONTWRITEBYTECODE='1')
            config = json.dumps({'networks': {'default': {'ipam': {'config': [{'subnet': '10.40.0.0/24'}]}}}})
            for args, stdin, message in ((['check'], config, 'could not check CHRONICLE_SUBNET against Docker networks: Command '),
                                         (['select', '172.28.0.0/16'], '', 'usage: network-subnet.py check | select DEFAULT PROJECT')):
                with self.subTest(args=args):
                    result = subprocess.run([sys.executable, '-s', str(ROOT / 'selfhost/network-subnet.py'), *args], input=stdin,
                                            env=environment, capture_output=True, text=True, timeout=30)
                    self.assertEqual((1, ''), (result.returncode, result.stdout))
                    self.assertTrue(result.stderr.startswith(message), result.stderr)

    def test_remote_tls_does_not_disable_trust_and_ipv6_authority_is_valid(self):
        with patch('chronicle_ops.verify.run', return_value=SimpleNamespace(returncode=0, stdout='204')) as run:
            verify.curl('https://public.example.org:8443/health')
            args = run.call_args.args[0]
            self.assertNotIn('-k', args); self.assertNotIn('--insecure', args)
        self.assertEqual(common.authority('fd42::1', '8443'), '[fd42::1]:8443')

    def test_persisted_upload_receipts_reject_missing_and_duplicate_rows(self):
        records={'study': '00000000-0000-0000-0000-000000000001', 'participant': 'smoke-fixture', 'tables': list(client.TABLES.values())}
        client.assert_persisted(records, lambda sql: '1')
        for count in ('0', '2'):
            with self.assertRaises(RuntimeError): client.assert_persisted(records, lambda sql: count)

    def test_paced_upload_preserves_content_length_and_json(self):
        captured = {}
        def open_request(request, timeout):
            captured['length'] = request.get_header('Content-length')
            captured['payload'] = b''.join(request.data)
            response = io.BytesIO(b'1'); response.status = 200
            response.headers = {'Content-Type': 'application/json'}
            return response
        body = [{'sample': 1}]
        with patch.object(client, 'TRANSFER_CHUNK_BYTES', 3), patch.object(client.time, 'sleep') as sleep:
            self.assertEqual(client.request(SimpleNamespace(open=open_request), 'https://fixture.example/upload', 'POST',
                                            body, padding_bytes=30, body_interval=0.1), 1)
            self.assertEqual(sleep.call_count, 10)
        self.assertEqual(captured['length'], '30')
        self.assertEqual(json.loads(captured['payload']), body)

    def test_transfer_contract_rejects_truncation_changed_content_and_accepted_idle_gap(self):
        recipe = {'upload': {'url': 'https://fixture.example/upload', 'headers': {}, 'body': [{}]},
                  'download': {'url': 'https://fixture.example/export', 'headers': {}}}
        def response(payload):
            result = io.BytesIO(payload); result.status = 200
            return result
        for second, succeeds in ((b'abcdef', True), (b'abcdez', False), (b'abcde', False)):
            opener = SimpleNamespace(open=lambda *args, **kwargs: next(downloads))
            downloads = iter((response(b'abcdef'), response(second)))
            with patch.object(client, 'LARGE_EXPORT_BYTES', 6), patch.object(client, 'TRANSFER_CHUNK_BYTES', 2), \
                 patch.object(client, 'client', return_value=opener), patch.object(client, 'request', return_value=1), \
                 patch.object(client.time, 'sleep'):
                if succeeds:
                    client.transport_replay(recipe, None)
                else:
                    with self.assertRaises(RuntimeError): client.transport_replay(recipe, None)
        with patch.object(client, 'request', return_value=1):
            with self.assertRaisesRegex(RuntimeError, 'accepted a stalled upload'):
                client.transport_replay(recipe, None, idle_failure=True)

    def test_short_idle_requires_control_and_body_progress_before_timeout_or_reset(self):
        import ssl
        import urllib.error
        recipe = {'upload': {'url': 'https://fixture.example/upload', 'headers': {}, 'body': [{}]}}
        tls_write_reset = ssl.SSLError(5, '[SYS] unknown error')
        tls_write_reset.library = 'SYS'
        errors = ((client.socket.gaierror('DNS failed'), False),
                  (ConnectionRefusedError('listener absent'), False),
                  (ssl.SSLCertVerificationError('untrusted certificate'), False),
                  (TimeoutError('timed out'), True), (ConnectionResetError('reset'), True),
                  (BrokenPipeError('closed'), True), (ssl.SSLEOFError('EOF'), True), (tls_write_reset, True))
        errors += tuple((urllib.error.HTTPError(recipe['upload']['url'], status, 'fixture', {}, io.BytesIO()), status in (408, 504))
                        for status in (408, 504, 502, 401))
        for error, _ in errors:
            if isinstance(error, urllib.error.HTTPError):
                self.addCleanup(error.close)
        for error, allowed in errors:
            for sent in (False, True):
                with self.subTest(error=type(error).__name__, sent=sent):
                    calls = []
                    def open_request(request, timeout):
                        calls.append(request)
                        if isinstance(request.data, bytes):
                            response = io.BytesIO(b'1'); response.status = 200
                            response.headers = {'Content-Type': 'application/json'}
                            return response
                        if sent:
                            next(request.data)
                            next(request.data)
                        raise error if isinstance(error, urllib.error.HTTPError) else urllib.error.URLError(error)
                    with patch.object(client, 'client', return_value=SimpleNamespace(open=open_request)), \
                         patch.object(client.time, 'sleep'):
                        if allowed and sent:
                            client.transport_replay(recipe, None, idle_failure=True)
                        else:
                            with self.assertRaises((urllib.error.URLError, OSError)):
                                client.transport_replay(recipe, None, idle_failure=True)
                    self.assertEqual(len(calls), 2)
        for error, _ in errors[:3]:
            with patch.object(client, 'request', side_effect=urllib.error.URLError(error)) as request:
                with self.assertRaises(urllib.error.URLError):
                    client.transport_replay(recipe, None, idle_failure=True)
                self.assertEqual(request.call_count, 1)
        with patch.object(client, 'request', return_value=0) as request:
            with self.assertRaisesRegex(RuntimeError, 'control upload was not acknowledged'):
                client.transport_replay(recipe, None, idle_failure=True)
            self.assertEqual(request.call_count, 1)

    def test_transparent_fixture_restores_host_filtering_after_route_cleanup_failure(self):
        source=(ROOT/'tests/deployment/selfhost-topology.sh').read_text()
        cleanup=source[source.index('cleanup() {'):source.index('\ntrap cleanup EXIT')]
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder); (root/'selfhost').mkdir(); (root/'routes-installed').touch()
            for directory in ('all','pool'):
                (root/directory).mkdir(); (root/directory/'rp_filter').write_text('0')
            shell='''
RUN="$1"; STACK="$RUN/selfhost"; TOPOLOGY_POOL_BRIDGE=pool
route_priority=20000; route_table=120; rpf_all=1; rpf_pool=2
clients() { return 0; }; docker() { return 0; }
ip() { [[ "$*" != '-4 route flush table 120' ]]; }; export -f ip
host_routes() { bash -ceu "${1//\\/host-ipv4-conf/$RUN}"; }
'''+cleanup+'\ntrue; cleanup'
            result=shell_probe(shell, folder, allowed=(1,))
            self.assertEqual(result.returncode,1,result.stderr)
            self.assertEqual((root/'all/rp_filter').read_text(),'1')
            self.assertEqual((root/'pool/rp_filter').read_text(),'2')
            self.assertEqual((root/'result.txt').read_text(),'status=1\n')


# The mode overlay in COMPOSE_FILE sets these on the guard service; rollback keeps the previous release's shape.
OVERLAY_OWNED_GUARD_INPUTS = {'TLS_MODE', 'DASHBOARD_EXPOSURE'}


def guard_settings_coupled_to(setting):
    """Parse shell statements and nested if chains, including settings named in their diagnostics."""
    settings = {match[1] for line in (ROOT / 'selfhost/.env.example').read_text().splitlines()
                if (match := envfile.assignment.match(line.lstrip('#')))} | OVERLAY_OWNED_GUARD_INPUTS
    lexer = shlex.shlex((ROOT / 'selfhost/guard-config.sh').read_text().replace('\\\n', ' '),
                        posix=True, punctuation_chars=';()|&\n')
    lexer.whitespace = ' \t\r'
    lexer.whitespace_split = True
    coupled, chains, statement = set(), [], []
    # Track decisions separately from the rest of a chain, so a diagnostic alone cannot create a dependency.
    deciding = False
    for token in [*lexer, '\n']:
        if token in ('if', 'elif', 'then', 'else', 'fi') or token.strip(';()|&\n') == '':
            text = ' '.join(statement)
            decision = statement and statement[0] not in (':', 'ok', 'warn', 'bad', 'printf', 'echo', 'for')
            names = set(re.findall(r'\b[A-Z][A-Z0-9_]*\b', text)) & settings
            if decision:
                names.update(re.findall(r'\$\{?([A-Z][A-Z0-9_]*)', text))
            for decisions, mentions in chains:
                mentions.update(names)
            if deciding:
                chains[-1][0].update(names)
            elif setting in names and decision:
                coupled |= names
            statement = []
            if token == 'if':
                chains.append((set(), set()))
                deciding = True
            elif token == 'elif':
                deciding = True
            elif token in ('then', 'else'):
                deciding = False
            elif token == 'fi':
                deciding = False
                decisions, mentions = chains.pop()
                if setting in decisions:
                    coupled |= mentions
        else:
            statement.append(token)
    assert not chains, 'unclosed shell conditional'
    return coupled - {setting}


class RollbackPoolListenerTests(SelfhostSetupFixture):
    def test_every_setting_the_guard_couples_to_the_pool_bind_travels_with_it(self):
        from chronicle_ops.restore import POOL_LISTENER_SETTINGS
        coupled = {'HTTP_BIND', 'POOL_LISTENER_TLS'} | guard_settings_coupled_to('HTTP_BIND') | guard_settings_coupled_to('POOL_LISTENER_TLS')
        self.assertTrue({'POOL_LISTENER_TLS', 'POOL_PLAINTEXT_WAIVER', 'POOL_ALLOWED_IPS', 'CADDY_TRUSTED_PROXIES'} <= coupled, coupled)
        self.assertIn('HTTP_BIND', POOL_LISTENER_SETTINGS)
        self.assertEqual(set(), coupled - OVERLAY_OWNED_GUARD_INPUTS - POOL_LISTENER_SETTINGS)

    def test_guard_dependency_parser_handles_multiline_and_nested_decisions(self):
        guard = """# INTERNAL_BIND is not part of this decision.
for flag in POOL_LISTENER_TLS TESTING_LOGIN_ENABLED; do :; done
if [[
  "$HTTP_BIND" == 127.*
]]; then
  if [[ "$POOL_LISTENER_TLS" == true && "$POOL_SITE_POLICY" == true ]]; then :; fi
elif pool_plaintext_waived "$POOL_PLAINTEXT_WAIVER"; then
  warn "POOL_ALLOWED_IPS and CADDY_TRUSTED_PROXIES must match"
fi
"""
        read_text = Path.read_text
        with patch.object(Path, 'read_text', autospec=True,
                          side_effect=lambda path: guard if path.name == 'guard-config.sh' else read_text(path)):
            self.assertEqual({'POOL_LISTENER_TLS', 'POOL_PLAINTEXT_WAIVER', 'POOL_ALLOWED_IPS', 'CADDY_TRUSTED_PROXIES',
                              'POOL_SITE_POLICY'},
                             guard_settings_coupled_to('HTTP_BIND'))

    def test_rollback_keeps_the_candidate_pool_tls_and_the_previous_release_guard_accepts_it(self):
        from chronicle_ops.restore import rollback
        self.run_setup()
        old, current = self.host, self.host.parent / 'candidate'
        current.mkdir()
        # Previous release: a same-host load balancer, plain HTTP on loopback, no waiver.
        previous = envfile.set_env_values((old / '.env').read_text(), dict(
            HTTP_BIND='127.0.0.1', POOL_LISTENER_TLS='false', POOL_PLAINTEXT_WAIVER=''), require_existing=False)
        (old / '.env').write_text(previous)
        # Candidate: setup moved the pool to a private address for a remote load balancer and turned on TLS.
        (current / '.env').write_text(envfile.set_env_values(previous, dict(
            HTTP_BIND='10.20.0.5', POOL_LISTENER_TLS='true', CADDY_TRUSTED_PROXIES='10.20.0.0/24',
            CHRONICLE_STATE_DIR=str(old)), require_existing=False).replace('POOL_PLAINTEXT_WAIVER=\n', ''))
        (current / '.env').chmod(0o600)
        marker = old / '.chronicle-upgrade.lock'; marker.mkdir()
        receipts.write_json(marker / reconcile.RECOVERY_FILE,
                            {'previous': str(old), 'owner': str(current), 'phase': reconcile.RECOVERY_PHASE})
        with patch.object(Path, 'cwd', return_value=current), patch('chronicle_ops.restore.Restore.execute', return_value=0), \
             patch('chronicle_ops.restore.compose'), patch('chronicle_ops.common.run', return_value=SimpleNamespace(returncode=0)), \
             patch('chronicle_ops.upgrade.start_release'), patch('chronicle_ops.reconcile.install'), \
             patch.dict(os.environ, clear=True):
            self.assertEqual(rollback(old, '/backups/reviewed.sql.gz', 'a' * 64, True), 0)
        settings = envfile.read_env(old / '.env')
        self.assertEqual(('10.20.0.5', 'true'), (envfile.value(settings, 'HTTP_BIND'), envfile.value(settings, 'POOL_LISTENER_TLS')))
        environment = dict(self.environment, **{key: envfile.value(settings, key) for key in settings})
        environment.update(TLS_MODE='behind-proxy', DASHBOARD_EXPOSURE='internal', BACKUPS_ENABLED='true',
                           COMPOSE_FILE_SELECTION=envfile.value(settings, 'COMPOSE_FILE'),
                           CHRONICLE_GUARD_TLS_DIR=str(old / 'tls'))
        guard = subprocess.run(['bash', str(old / 'guard-config.sh')], cwd=old, env=environment,
                               capture_output=True, text=True, timeout=20)
        self.assertEqual(0, guard.returncode, guard.stdout + guard.stderr)
        self.assertIn('pool listener 10.20.0.5 serves TLS', guard.stdout)


def shell_probe(text, *arguments, shell='bash', strict=False, allowed=(0,), **kwargs):
    result = subprocess.run([shell, *(['-eu'] if strict else []), '-c', text, 'fixture', *arguments],
                            capture_output=True, text=True, timeout=10, **kwargs)
    if result.returncode not in allowed:
        raise subprocess.CalledProcessError(result.returncode, result.args, result.stdout, result.stderr)
    return result
