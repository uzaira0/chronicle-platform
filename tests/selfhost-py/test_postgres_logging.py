"""Use the real producer and shipped Fluent Bit parser, never a fabricated log line."""
import json
import os
from pathlib import Path
import re
import subprocess
import time

import yaml

from test_restore_schemas import PgTdeFixture, ROOT


class PostgresLoggingTests(PgTdeFixture):
    @classmethod
    def setUpClass(cls):
        command = yaml.safe_load((ROOT / 'selfhost/docker-compose.yml').read_text())['services']['postgres']['command']
        logging = ('log_line_prefix=', 'logging_collector=', 'log_error_verbosity=', 'log_min_error_statement=')
        cls.postgres_options = tuple(argument for option in command if option.startswith(logging)
                                     for argument in ('-c', option))
        super().setUpClass()

    def test_real_postgres_error_keeps_timestamp_severity_and_sqlstate(self):
        self.assertEqual("off", self.sql("SHOW logging_collector;"), "Docker logging requires PostgreSQL stderr")
        services = yaml.safe_load((ROOT / 'selfhost/docker-compose.yml').read_text())['services']
        prefix = next(arg.split('=', 1)[1] for arg in services['postgres']['command'] if arg.startswith('log_line_prefix='))
        self.sql("ALTER SYSTEM SET log_line_prefix = '" + prefix.replace("'", "''") + "';")
        self.sql('SELECT pg_reload_conf();')
        for _ in range(150):
            if self.sql('SHOW log_line_prefix;') == prefix.strip():
                break
            time.sleep(0.1)
        self.assertEqual(prefix.strip(), self.sql('SHOW log_line_prefix;'))
        error = subprocess.run(['docker', 'exec', self.container, 'psql', '-U', self.database_user,
                                '-d', 'chronicle', '-v', 'VERBOSITY=sqlstate', '-c',
                                "SELECT 1/0 WHERE 'participant-literal' IS NOT NULL;"],
                               capture_output=True, text=True, timeout=10)
        self.assertNotEqual(0, error.returncode)
        expected_state = re.search(r'ERROR:\s+([A-Z0-9]{5})', error.stderr).group(1)
        line = None
        for _ in range(150):
            log = subprocess.run(['docker', 'logs', self.container], check=True, capture_output=True, text=True, timeout=10)
            line = next((line for line in reversed((log.stdout + log.stderr).splitlines())
                         if 'sqlstate=' + expected_state in line and 'ERROR:' in line), None)
            if line is not None:
                break
            time.sleep(0.1)
        self.assertIsNotNone(line, "PostgreSQL did not emit its configured error envelope")
        self.assertNotIn('participant-literal', log.stdout + log.stderr, "statement text reached docker logs")
        event = self.parse_log(line)
        self.assertEqual('ERROR', event['severity'])
        self.assertEqual(expected_state, event['sqlstate'])
        self.assertLess(abs(float(event['timestamp']) - time.time()), 60)
        self.assertNotIn('SELECT', json.dumps(event))

    def parse_log(self, line):
        overlay = yaml.safe_load((ROOT / 'selfhost/overlays/monitoring.yml').read_text())['services']
        image = overlay['fluent-bit']['image']
        config_root = Path(os.environ.get('SELFHOST_MONITORING_TEST_DIR', ROOT / 'selfhost/monitoring'))
        config = self.work / 'fluent-bit.conf'
        config.write_text('''[SERVICE]
    Flush 0.1
    Parsers_File /parsers.conf
[INPUT]
    Name dummy
    Tag chronicle.postgres
    Samples 1
    Dummy ''' + json.dumps({'log': line}) + '''
[FILTER]
    Name parser
    Match chronicle.postgres
    Key_Name log
    Parser chronicle_postgres
    Reserve_Data On
    Preserve_Key Off
[FILTER]
    Name lua
    Match chronicle.*
    script /sanitize.lua
    call sanitize
[OUTPUT]
    Name stdout
    Match *
    Format json_lines
''')
        container = self.container + '-fluent'
        self.docker('run', '-d', '--name', container, '--network', 'none',
                    '-v', f'{config}:/fixture.conf:ro', '-v', f'{config_root / "parsers.conf"}:/parsers.conf:ro',
                    '-v', f'{config_root / "sanitize.lua"}:/sanitize.lua:ro', image,
                    '/fluent-bit/bin/fluent-bit', '-c', '/fixture.conf')
        self.addCleanup(self.docker, 'rm', '-f', container)
        for _ in range(150):
            logs = self.docker('logs', container).decode()
            rows = [json.loads(row) for row in logs.splitlines() if row.startswith('{')]
            if rows:
                break
            time.sleep(0.1)
        self.assertTrue(rows, logs)
        return rows[0]

