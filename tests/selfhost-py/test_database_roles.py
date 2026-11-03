"""Runtime database credentials are independent of the migration owner."""

import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import yaml

from chronicle_ops import credentials
from chronicle_ops.envfile import read_env, value
from selfhost_fixture import FIXTURE_POSTGRES_APP_PASSWORD, FIXTURE_POSTGRES_PASSWORD, rotation_fixture
from test_restore_schemas import PgTdeFixture


ROOT = Path(__file__).resolve().parents[2]


class DatabasePoolConfigurationTests(unittest.TestCase):
    def test_setup_generates_and_preserves_a_separate_application_password(self):
        secrets = {secret.name: secret for secret in credentials.SETUP_SECRETS}
        self.assertIn('postgres-app', secrets)
        app = secrets['postgres-app']
        preserved = dict.fromkeys((secret.env_key for secret in secrets.values()), '')
        generated = credentials.setup_credentials({}, preserved)
        self.assertNotEqual(generated.values[app.env_key], generated.values[credentials.POSTGRES.env_key])
        self.assertTrue(generated.values[app.env_key])
        again = credentials.setup_credentials({}, generated.values)
        self.assertEqual(generated.values[app.env_key], again.values[app.env_key])

    def test_shipped_jdbc_templates_keep_owner_credentials_out_of_runtime(self):
        environment = dict(POSTGRES_USER='fixture_owner', POSTGRES_PASSWORD='fixture-owner-password',
                           POSTGRES_APP_PASSWORD='fixture-app-password')
        for template in ('selfhost/config/rhizome.yaml.template',):
            with self.subTest(template=template), patch.dict(os.environ, environment):
                config = yaml.safe_load(os.path.expandvars((ROOT / template).read_text()))
                self.assertEqual({'chronicle'}, set(config['datasources']))
                self.assertNotIn(environment['POSTGRES_PASSWORD'], json.dumps(config))
                self.assertNotIn(environment['POSTGRES_USER'], json.dumps(config))
                runtime = (config['postgres'], config['datasources']['chronicle'])
                for pool in runtime:
                    self.assertEqual(pool['hikari']['username'], 'chronicle_app')
                    self.assertEqual(pool['hikari']['password'], environment['POSTGRES_APP_PASSWORD'])
                    self.assertFalse(pool['initialize-tables'])
                    self.assertFalse(pool['initialize-indices'])
                    self.assertEqual(pool['hikari']['maximumPoolSize'], 20)
                    self.assertEqual(pool['hikari']['minimumIdle'], 5)

    def test_application_password_rotation_commits_or_rolls_back_independently(self):
        for failure in ('success', 'lost-ack', 'startup-failure'):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as directory:
                fixture = rotation_fixture(Path(directory))
                if failure == 'lost-ack':
                    fixture.environment['SELFHOST_ROTATION_TEST_LOSE_ALTER_ACK'] = 'true'
                elif failure == 'startup-failure':
                    fixture.environment['SELFHOST_ROTATION_TEST_FAIL_FIRST_UP_FILE'] = str(Path(directory) / 'fail-up')
                result = subprocess.run(['bash', str(fixture.host / 'rotate-secret.sh'), '--yes', 'postgres-app'],
                                        cwd=fixture.host, env=fixture.environment, capture_output=True, text=True, timeout=30)
                self.assertEqual(result.returncode == 0, failure == 'success', result.stdout + result.stderr)
                settings = read_env(fixture.host / '.env')
                expected = 'a' * 64 if failure == 'success' else FIXTURE_POSTGRES_APP_PASSWORD
                self.assertEqual(value(settings, credentials.POSTGRES_APP.env_key), expected)
                self.assertEqual(value(settings, credentials.POSTGRES.env_key), FIXTURE_POSTGRES_PASSWORD)
                self.assertEqual(Path(fixture.environment['SELFHOST_ROTATION_TEST_DB_APP_PASSWORD_FILE']).read_text(), expected)
                self.assertFalse((fixture.host / '.chronicle-secret-rotation').exists())
                for secret in (FIXTURE_POSTGRES_APP_PASSWORD, FIXTURE_POSTGRES_PASSWORD, expected):
                    self.assertNotIn(secret, result.stdout + result.stderr)


class ApplicationDatabaseRoleTests(PgTdeFixture):
    def test_shipped_provisioning_creates_a_restricted_physical_login(self):
        hba = self.sql('SHOW hba_file;')
        self.docker('exec', '--user', '0', self.container, 'sed', '-i',
                    '1i host all chronicle_app 127.0.0.1/32 scram-sha-256', hba)
        self.sql('SELECT pg_reload_conf();')
        self.sql("CREATE ROLE chronicle_app NOLOGIN; "
                 "CREATE TABLE runtime_owner_probe (value text); INSERT INTO runtime_owner_probe VALUES ('private'); "
                 "ALTER TABLE runtime_owner_probe ENABLE ROW LEVEL SECURITY; "
                 "ALTER TABLE runtime_owner_probe FORCE ROW LEVEL SECURITY; "
                 "GRANT SELECT ON runtime_owner_probe TO chronicle_app; "
                 "CREATE POLICY deny_probe ON runtime_owner_probe USING (false);")
        self.docker('exec', '-e', 'POSTGRES_APP_PASSWORD=' + FIXTURE_POSTGRES_APP_PASSWORD, self.container,
                    'psql', '-Xq', '-v', 'ON_ERROR_STOP=1', '-U', self.database_user, '-d', 'chronicle',
                    '-f', '/selfhost/database-app-role.sql')
        self.assertEqual('t', self.sql("SELECT rolcanlogin AND NOT rolsuper AND NOT rolbypassrls "
                                      "AND NOT rolcreatedb AND NOT rolcreaterole AND NOT rolreplication "
                                      "AND rolpassword IS NOT NULL FROM pg_authid WHERE rolname = 'chronicle_app';"))
        rows = self.docker('exec', '-e', 'PGPASSWORD=' + FIXTURE_POSTGRES_APP_PASSWORD, self.container,
                           'psql', '-XqAt', '-v', 'ON_ERROR_STOP=1', '-h', '127.0.0.1', '-U', 'chronicle_app',
                           '-d', 'chronicle', '-c', 'SELECT session_user; SELECT count(*) FROM runtime_owner_probe;')
        self.assertEqual('chronicle_app\n0', rows.decode().strip())
        with self.assertRaisesRegex(AssertionError, 'password authentication failed'):
            self.docker('exec', '-e', 'PGPASSWORD=wrong-fixture-password', self.container,
                        'psql', '-XqAt', '-h', '127.0.0.1', '-U', 'chronicle_app', '-d', 'chronicle', '-c', 'SELECT 1;')
        with self.assertRaisesRegex(AssertionError, 'permission denied to set role'):
            self.docker('exec', '-e', 'PGPASSWORD=' + FIXTURE_POSTGRES_APP_PASSWORD, self.container,
                        'psql', '-XqAt', '-v', 'ON_ERROR_STOP=1', '-h', '127.0.0.1', '-U', 'chronicle_app',
                        '-d', 'chronicle', '-c', 'SET ROLE ' + self.database_user)
