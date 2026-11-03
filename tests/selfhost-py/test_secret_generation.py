"""Run setup against fake host/Compose commands; never contact a deployment."""

import datetime
import json
import os
import shutil
import subprocess
from pathlib import Path
import tempfile
import unittest

from chronicle_ops.common import run
from chronicle_ops.env_migration import merge_env
from chronicle_ops.envfile import quote_env, read_env, set_env_values, value
from chronicle_ops.credentials import GENERATION_DATES_KEY as DATES, JWT, SETUP_SECRETS, valid_generation_dates

ROOT = Path(__file__).resolve().parents[2]


class SelfhostSetupFixture(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        fixture = Path(self.folder.name)
        result = run(['bash', str(ROOT / 'tests/security/lib/selfhost-fixtures.sh'), 'setup-fixture', str(fixture)],
                     env=os.environ.copy(), capture=True, stderr=subprocess.PIPE, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.host = fixture / 'selfhost'
        self.environment = dict(os.environ, HOME=str(fixture), PATH=str(fixture / 'bin') + os.pathsep + os.environ['PATH'],
                                CHRONICLE_HOST_UID=str(os.getuid()), CHRONICLE_HOST_GID=str(os.getgid()),
                                CHRONICLE_RECONCILE_ENABLED='false')
        compose_plugin = shutil.which('docker-compose') or str(Path.home() / '.docker/cli-plugins/docker-compose')
        if Path(compose_plugin).is_file():
            config = fixture / 'docker-config'
            (config / 'cli-plugins').mkdir(parents=True)
            (config / 'cli-plugins/docker-compose').symlink_to(compose_plugin)
            self.environment['DOCKER_CONFIG'] = str(config)

    def run_setup(self, rerun=False):
        result = run(['bash', str(ROOT / 'tests/security/lib/selfhost-fixtures.sh'), 'run-setup',
                      str(self.host), str(rerun).lower()],
                     env=self.environment,
                     capture=True, stderr=subprocess.PIPE, timeout=20)
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        return result

    def write_dates(self, dates):
        content = (self.host / '.env').read_text()
        (self.host / '.env').write_text(set_env_values(content, {DATES: json.dumps(dates)}, require_existing=False))


class SecretGenerationTests(SelfhostSetupFixture):
    def test_root_deploy_uses_the_same_retired_mobile_policy(self):
        self.run_setup()
        scripts = self.host.parent / 'scripts'
        scripts.mkdir()
        shutil.copy2(ROOT / 'scripts/deploy.sh', scripts / 'deploy.sh')
        flyway = scripts / 'flyway-migrate.sh'
        flyway.write_text('#!/bin/sh\nexit 0\n')
        flyway.chmod(0o755)
        settings = self.host / '.env'
        password = value(read_env(settings), 'POSTGRES_PASSWORD')
        for enabled in ('false', 'true'):
            settings.write_text(set_env_values(settings.read_text(), dict(
                HAZELCAST_SERVER_PASSWORD=password, HAZELCAST_CLIENT_PASSWORD=password,
                MOBILE_SIGNING_ENABLED=enabled, MOBILE_SIGNING_REQUIRED=enabled), require_existing=False))
            result = run(['bash', str(scripts / 'deploy.sh'), '--environment', 'staging', '--tag', 'v1.2.3',
                          '--env-file', str(settings), '--dry-run'], env=self.environment,
                         capture=True, stderr=subprocess.PIPE, timeout=10)
            self.assertEqual(enabled == 'false', result.returncode == 0, result.stdout + result.stderr)
            if enabled == 'true':
                self.assertIn('MOBILE_SIGNING_ENABLED is unsupported', result.stderr)

    def test_root_rotation_preview_refuses_retired_mobile_credentials(self):
        self.run_setup()
        settings = self.host / '.env'
        before = settings.read_bytes()
        for credential in ('MOBILE_SIGNING_SECRET', 'MOBILE_APP_KEY'):
            with self.subTest(credential=credential):
                result = run(['bash', str(ROOT / 'scripts/rotate-secrets.sh'), '--dry-run', '--only', credential],
                             env=dict(self.environment, CHRONICLE_ENV_FILE=str(settings)),
                             capture=True, stderr=subprocess.PIPE, timeout=10)
                self.assertNotEqual(0, result.returncode, result.stdout + result.stderr)
                self.assertEqual(before, settings.read_bytes())

    def test_setup_omits_deployment_wide_mobile_keys_and_rotation_is_not_a_command(self):
        self.run_setup()
        self.assertFalse(any(key.startswith('MOBILE_SIGNING_') for key in read_env(self.host / '.env')))
        result = run(['bash', str(self.host / 'chronicle'), 'rotate-secret', 'mobile', 'begin'],
                     env=self.environment, capture=True, stderr=subprocess.PIPE, timeout=10)
        self.assertEqual(2, result.returncode, result.stderr)

    def test_setup_uses_private_umask_and_writes_a_free_grafana_port(self):
        docker = self.host.parent / 'bin/docker'
        record = self.host.parent / 'setup-umask'
        docker.write_text(docker.read_text().replace('set -euo pipefail',
                          'set -euo pipefail\numask >"$SETUP_UMASK_RECORD"'))
        self.environment['SETUP_UMASK_RECORD'] = str(record)
        ss = self.host.parent / 'bin/ss'
        ss.write_text('''#!/bin/sh
printf 'State Recv-Q Send-Q Local-Address Peer-Address\n'
printf 'LISTEN 0 0 127.0.0.1:%s 0.0.0.0:*\n' "$OCCUPIED_PORT"
''')
        port = 43000
        self.environment.update(GRAFANA_PORT=str(port), OCCUPIED_PORT=str(port), SELFHOST_SETUP_MONITORING='y')
        previous = os.umask(0)
        try:
            self.run_setup()
        finally:
            os.umask(previous)
        self.assertEqual(record.read_text().strip(), '0077')
        settings = read_env(self.host / '.env')
        self.assertEqual(int(value(settings, 'GRAFANA_PORT')), port + 1)
        self.assertEqual((self.host / '.env').stat().st_mode & 0o777, 0o600)

    def test_setup_records_generated_dates_and_preserves_them_on_resetup_and_upgrade(self):
        before = datetime.datetime.now(datetime.timezone.utc)
        self.run_setup()
        settings = read_env(self.host / '.env')
        recorded = json.loads(value(settings, DATES, '{}'))
        self.assertEqual(set(recorded), {secret.name for secret in SETUP_SECRETS})
        self.assertTrue(valid_generation_dates(recorded))
        for date in recorded.values():
            self.assertGreaterEqual(datetime.datetime.fromisoformat(date), before)
        self.assertEqual((self.host / '.env').stat().st_mode & 0o777, 0o600)

        # An older receipt makes a timestamp reset observable even within the same second.
        recorded = dict.fromkeys(recorded, '2026-01-01T00:00:00+00:00')
        self.write_dates(recorded)
        self.run_setup(rerun=True)
        settings = read_env(self.host / '.env')
        self.assertEqual(json.loads(value(settings, DATES)), recorded)
        upgraded = Path(self.folder.name) / 'upgraded-settings'
        merge_env(settings, 'CHRONICLE_STATE_DIR=.\nCOMPOSE_FILE=docker-compose.yml\n',
                  upgraded, str(self.host), ['docker-compose.yml'])
        self.assertEqual(json.loads(value(read_env(upgraded), DATES)), recorded)

        # Re-setup must not invent an age for credentials it only preserved.
        self.write_dates({})
        self.run_setup(rerun=True)
        self.assertEqual(json.loads(value(read_env(self.host / '.env'), DATES) or '{}'), {})

    def test_missing_credential_gets_a_new_receipt_without_resetting_preserved_credentials(self):
        self.run_setup()
        settings = read_env(self.host / '.env')
        recorded = dict.fromkeys(json.loads(value(settings, DATES)), '2026-01-01T00:00:00+00:00')
        self.write_dates(recorded)
        (self.host / '.env').write_text(set_env_values((self.host / '.env').read_text(), {JWT.env_key: ''}, require_existing=True))
        generated_after = datetime.datetime.now(datetime.timezone.utc)
        self.run_setup(rerun=True)
        regenerated = json.loads(value(read_env(self.host / '.env'), DATES))
        self.assertGreaterEqual(datetime.datetime.fromisoformat(regenerated[JWT.name]), generated_after)
        self.assertEqual({key: date for key, date in regenerated.items() if key != JWT.name},
                         {key: date for key, date in recorded.items() if key != JWT.name})

    def test_preflight_rejects_invalid_rotation_configuration(self):
        self.run_setup()
        settings = read_env(self.host / '.env')
        for key, invalid in [('ENABLE_ENCRYPTION', 'yes'), ('ENABLE_ENCRYPTION', 'TRUE'),
                             (DATES, '[]'), (DATES, json.dumps({JWT.name: 'private-date-sentinel'})),
                             (DATES, json.dumps({JWT.name: '20261001T120000+0000'}))]:
            with self.subTest(key=key, invalid=invalid):
                changed = dict(settings, **{key: quote_env(invalid)})
                (self.host / '.env').write_text('\n'.join(f'{k}={v}' for k, v in changed.items()) + '\n')
                result = run(['bash', str(self.host / 'chronicle'), 'up'],
                             env=self.environment, capture=True, stderr=subprocess.PIPE, timeout=20)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(key, result.stderr)
                self.assertNotIn('private-date-sentinel', result.stderr)
        for enabled in ('true', 'false'):
            changed = dict(settings, ENABLE_ENCRYPTION=enabled)
            (self.host / '.env').write_text('\n'.join(f'{k}={v}' for k, v in changed.items()) + '\n')
            result = run(['bash', str(self.host / 'chronicle'), 'doctor', '--json'],
                         env=self.environment, capture=True, stderr=subprocess.PIPE, timeout=10)
            self.assertNotIn('invalid installation configuration', result.stderr)
            self.assertIn('checks', json.loads(result.stdout), result.stderr)


class HandEditedSettingsTests(unittest.TestCase):
    """The launcher validates a hand-edited .env in process before sourcing it (selfhost/chronicle, rotation preflight)."""

    def test_rotation_preflight_accepts_only_exact_encryption_flags_and_zoned_dates(self):
        from chronicle_ops.credentials import validate_rotation_configuration
        for key, invalid, error in (('ENABLE_ENCRYPTION', 'TRUE', 'ENABLE_ENCRYPTION must be exactly true or false'),
                                    (DATES, '{not json', DATES), (DATES, '[]', DATES),
                                    (DATES, json.dumps({JWT.name: '2026-10-01T12:00:00'}), DATES)):
            with self.subTest(key=key, invalid=invalid), self.assertRaisesRegex(ValueError, error):
                validate_rotation_configuration({key: quote_env(invalid)})
        for settings in ({}, {'ENABLE_ENCRYPTION': 'false', DATES: quote_env(json.dumps({JWT.name: '2026-10-01T12:00:00Z'}))}):
            validate_rotation_configuration(settings)

    def test_a_pre_reset_installation_with_deployment_wide_mobile_signing_is_refused(self):
        from chronicle_ops.credentials import validate_mobile_signing_configuration
        for key, legacy in (('MOBILE_SIGNING_ENABLED', 'true'), ('MOBILE_SIGNING_REQUIRED', 'true'),
                            ('MOBILE_SIGNING_SECRET', 'old-shared-secret'), ('MOBILE_SIGNING_SECRET_PREVIOUS', 'older')):
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, f'^{key} is unsupported; use per-device enrollment'):
                validate_mobile_signing_configuration({key: legacy})
        validate_mobile_signing_configuration({'MOBILE_SIGNING_ENABLED': 'false', 'MOBILE_SIGNING_SECRET': ''})

    def test_setup_refuses_generation_dates_that_are_not_an_object(self):
        from chronicle_ops.credentials import setup_credentials
        preserved = dict.fromkeys((secret.env_key for secret in SETUP_SECRETS), 'kept')
        with self.assertRaisesRegex(ValueError, 'secret generation dates must be a JSON object'):
            setup_credentials({DATES: quote_env('["2026-10-01T12:00:00Z"]')}, preserved)
        self.assertEqual({JWT.name: '2026-10-01T12:00:00Z'},
                         setup_credentials({DATES: quote_env(json.dumps({JWT.name: '2026-10-01T12:00:00Z'}))}, preserved).generated_at)


class SecretAgeTests(unittest.TestCase):
    def test_doctor_reports_each_secret_from_its_newest_setup_or_completed_rotation(self):
        from chronicle_ops.credentials import ROTATION_RECEIPTS_DIR
        from chronicle_ops.verify import secret_age_rows
        utc = datetime.timezone.utc
        now = datetime.datetime(2026, 10, 22, 12, tzinfo=utc)
        # metrics was regenerated by a retried setup after its last rotation: the newer generation date wins.
        settings = {DATES: quote_env(json.dumps({JWT.name: '2026-10-01T12:00:00.123456+00:00',
                                                 'postgres': '2026-09-22T12:00:00Z',
                                                 'metrics': '2026-10-21T12:00:00Z'}))}
        with tempfile.TemporaryDirectory() as folder:
            receipts = Path(folder) / ROTATION_RECEIPTS_DIR
            receipts.mkdir(parents=True)
            for name, secret, action, completed in (('a', JWT.name, 'rotate', '20261020T120000Z'),
                                                    ('b', 'postgres', 'recover-rollback', '20261021T120000Z'),
                                                    ('c', 'tde', 'recover-forward', '20261012T120000Z'),
                                                    ('d', 'metrics', 'rotate', '20261002T120000Z')):
                (receipts / f'{name}.json').write_text(json.dumps(dict(status='completed', secret=secret, action=action,
                                                                       completed_at_utc=completed)))
            rows = secret_age_rows(settings, folder, datetime.datetime(2026, 9, 1, tzinfo=utc), now)
        self.assertEqual([('secret-ages', 'ok', 'Days since each secret was generated or rotated: '
                           'jwt 2 d, metrics 1 d, postgres 30 d, tde 10 d', 'none')], rows)
