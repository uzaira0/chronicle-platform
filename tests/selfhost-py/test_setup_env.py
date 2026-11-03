"""Named setup input and the shared environment writer's public contracts."""

import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from chronicle_ops.envfile import set_env_values
from chronicle_ops.setup_env import SETUP_FIELDS, parse_setup_fields


class SetupEnvironmentTests(unittest.TestCase):
    def test_setup_refreshes_the_selected_project_before_storage_checks(self):
        launcher = Path(__file__).resolve().parents[2] / 'selfhost/chronicle'
        script = f'''source "{launcher}"
setup_existing_settings() {{ setup_outcome=new; }}
for phase in setup_mode_and_domain setup_network_policy setup_dashboard_access setup_monitoring \
  setup_backup_retention setup_project setup_network_and_credentials setup_ports setup_lock_settings \
  setup_guidance; do eval "$phase() {{ :; }}"; done
setup_write_environment() {{ :; }}
need_env() {{ export CHRONICLE_OPS_PROJECT=chronicle-selfhost-2; }}
ops_python() {{ [[ "$CHRONICLE_OPS_PROJECT" == chronicle-selfhost-2 ]]; }}
chmod() {{ :; }}
export CHRONICLE_OPS_PROJECT=chronicle-selfhost
cmd_setup setup
'''
        result = subprocess.run(['bash', '-eu', '-c', script], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_setup_publication_is_private_atomic_and_preserves_existing_file_on_failure(self):
        from chronicle_ops.setup_env import write_setup_environment
        from chronicle_ops.receipts import durable_replace
        import io
        values = dict.fromkeys(SETUP_FIELDS, '')
        values.update(COMPOSE_FILE='docker-compose.yml', CHRONICLE_STATE_DIR='.')
        records = b''.join(f'{key}={value}\0'.encode() for key, value in values.items())
        with tempfile.TemporaryDirectory() as folder:
            directory = Path(folder)
            target = directory / '.env'
            target.write_text('DOMAIN=preserved\n')
            (directory / '.env.example').write_text('DOMAIN=\n')
            original_directory = Path.cwd()
            try:
                os.chdir(directory)
                for fail in (True, False):
                    def publish(temporary, destination):
                        self.assertEqual(target.read_text(), 'DOMAIN=preserved\n')
                        self.assertEqual(temporary.stat().st_mode & 0o777, 0o600)
                        self.assertIn('GRAFANA_PORT=', temporary.read_text())
                        if fail:
                            raise OSError('synthetic publication failure')
                        durable_replace(temporary, destination)
                    with patch('sys.stdin', io.TextIOWrapper(io.BytesIO(records))), \
                         patch('chronicle_ops.setup_env.apply_setup_memory', side_effect=lambda text, *_: text), \
                         patch('chronicle_ops.receipts.durable_replace', side_effect=publish):
                        if fail:
                            with self.assertRaises(OSError):
                                write_setup_environment()
                            self.assertEqual(target.read_text(), 'DOMAIN=preserved\n')
                        else:
                            write_setup_environment()
                            self.assertEqual(target.stat().st_mode & 0o777, 0o600)
                    self.assertFalse(list(directory.glob('..env-*')))
            finally:
                os.chdir(original_directory)

    def test_generation_dates_predicate_rejects_malformed_or_timezone_free_values(self):
        from chronicle_ops.credentials import valid_generation_dates
        for dates, expected in (({}, True), ({'fixture': '2024-02-29T12:00:00Z'}, True),
                                ({'fixture': '2026-10-15T12:00:00.123456789-05:00'}, True),
                                ({'fixture': '2026-10-15T12:00:00.1+00:00'}, True),
                                ({'fixture': '2026-10-15T12:00:00.1234567890Z'}, False),
                                ({'fixture': '2026-10-15T12:00:00+00:60'}, False),
                                ([], False), (None, False), ({'fixture': None}, False),
                                ({'fixture': '2026-02-29T12:00:00Z'}, False),
                                ({'fixture': '2026-10-15T12:00:00'}, False),
                                ({'fixture': '20261015T120000+0000'}, False)):
            with self.subTest(dates=dates):
                self.assertIs(valid_generation_dates(dates), expected)

    def test_invalid_urls_raise_library_errors(self):
        from chronicle_ops.setup_env import add_management_origin, validate_alert_webhook
        for operation, message in (
            (lambda: validate_alert_webhook('http://private-sentinel'),
             'alert webhook must be an HTTPS URL without credentials, quotes or line breaks'),
            (lambda: add_management_origin('', {}, 'https://private-sentinel/path'),
             'researcher URL must be an HTTPS origin'),
        ):
            with self.subTest(message=message):
                with self.assertRaises(ValueError) as failure:
                    operation()
                self.assertEqual(str(failure.exception), message)

    def test_setup_cli_preserves_the_validation_message_and_exit_status(self):
        values = dict.fromkeys(SETUP_FIELDS, '')
        values['CHRONICLE_ALERT_WEBHOOK_URL'] = 'http://private-sentinel'
        records = ''.join(f'{key}={value}\0' for key, value in values.items())
        self.assertEqual(self.cli(['setup-env'], stdin=records),
                         (1, '', 'error: alert webhook must be an HTTPS URL without credentials, quotes or line breaks\n'))
        # The launcher's `setup` reads the answers' exit status: success writes the private settings file.
        values.update(CHRONICLE_ALERT_WEBHOOK_URL='', COMPOSE_FILE='docker-compose.yml', CHRONICLE_STATE_DIR='.')
        records = ''.join(f'{key}={value}\0' for key, value in values.items())
        with tempfile.TemporaryDirectory() as folder, \
             patch('chronicle_ops.setup_env.apply_setup_memory', side_effect=lambda text, *_: text):
            (Path(folder) / '.env.example').write_text('DOMAIN=\n')
            self.assertEqual((0, '', ''), self.cli(['setup-env'], cwd=folder, stdin=records))
            settings = Path(folder) / '.env'
            self.assertEqual(0o600, settings.stat().st_mode & 0o777)
            self.assertIn('COMPOSE_FILE=docker-compose.yml', settings.read_text().splitlines())

    def cli(self, args, cwd=None, stdin=''):
        import io
        from chronicle_ops.__main__ import run_cli
        origin = Path.cwd()
        try:
            os.chdir(cwd or origin)
            with patch('chronicle_ops.__main__.signal.signal'), patch('sys.stdin', io.TextIOWrapper(io.BytesIO(stdin.encode()))), \
                 patch('sys.stdout', new_callable=io.StringIO) as output, patch('sys.stderr', new_callable=io.StringIO) as errors:
                status = run_cli(args)
        finally:
            os.chdir(origin)
        return status, output.getvalue(), errors.getvalue()

    def test_setup_sizes_a_new_small_host_and_refuses_ceilings_it_cannot_hold(self):
        import io
        from contextlib import redirect_stdout
        from chronicle_ops.envfile import parse_env_text, value
        from chronicle_ops.host_memory import SMALL_HOST_LIMITS
        from chronicle_ops.setup_env import apply_setup_memory
        shipped = ''.join(f'{service}_MEM_LIMIT={limit}\n' for service, limit in (
            ('POSTGRES', '2g'), ('BACKEND', '3g'), ('WEB', '256m'), ('BACKUP', '512m'))) + 'BACKEND_XMX=-Xmx2g\n'
        with tempfile.TemporaryDirectory() as folder:
            meminfo = Path(folder) / 'meminfo'
            with patch.dict(os.environ, CHRONICLE_MEMINFO=str(meminfo)):
                meminfo.write_text('MemTotal: 4026500 kB\n')
                with redirect_stdout(io.StringIO()) as output:
                    sized = apply_setup_memory(shipped, {}, 'docker-compose.yml:overlays/backups.yml')
                self.assertEqual('Host has 3932 MiB of memory; sized backend/Postgres limits for a 4 GB host (see README Sizing).\n',
                                 output.getvalue())
                self.assertEqual(SMALL_HOST_LIMITS, {key: value(parse_env_text(sized), key) for key in SMALL_HOST_LIMITS})
                with self.assertRaisesRegex(ValueError, 'selected service ceilings plus host headroom need .* MiB; host has 3932'):
                    apply_setup_memory(shipped, {'DOMAIN': 'estudio.example.cl'}, 'docker-compose.yml')
                meminfo.write_text('MemTotal: 16000000 kB\n')
                self.assertEqual(shipped, apply_setup_memory(shipped, {}, 'docker-compose.yml'))
                meminfo.unlink()
                self.assertEqual(shipped, apply_setup_memory(shipped, {}, 'docker-compose.yml:overlays/monitoring.yml'))

    def test_setup_storage_skips_the_waiver_prompt_on_encrypted_disks(self):
        import json
        from types import SimpleNamespace
        tree = {'blockdevices': [{'type': 'part', 'children': [{'type': 'crypt', 'children': [{'type': 'disk'}]}]}]}
        def storage(args, **_kwargs):
            if args[0] == 'findmnt':
                return SimpleNamespace(returncode=0, stdout='/dev/mapper/luks-data[/docker]\n')
            if args[0] == 'lsblk':
                return SimpleNamespace(returncode=0, stdout=json.dumps(tree))
            return SimpleNamespace(returncode=0, stdout='/var/lib/docker\n')
        with tempfile.TemporaryDirectory() as folder:
            (Path(folder) / '.env').write_text('COMPOSE_PROJECT_NAME=fixture\n')
            with patch('chronicle_ops.verify.sys.platform', 'linux'), \
                 patch('chronicle_ops.verify.run', side_effect=storage) as probe, \
                 patch('chronicle_ops.verify.database_volume_path', return_value=Path(folder)), \
                 patch('builtins.input', side_effect=AssertionError('prompted for a waiver')):
                status, output, _ = self.cli(['setup-storage'], folder)
            self.assertEqual(0, status)
            self.assertIn('database volume backing device is encrypted', output)
            self.assertIn('backup backing device is encrypted', output)
            self.assertEqual('COMPOSE_PROJECT_NAME=fixture\n', (Path(folder) / '.env').read_text())
            self.assertEqual(['lsblk', '--inverse', '--tree', '--json', '--output', 'TYPE', '/dev/mapper/luks-data'],
                             probe.call_args_list[1].args[0])

    def test_management_origin_preserves_order_and_deduplicates_each_list(self):
        from chronicle_ops.setup_env import add_management_origin
        existing = {'INTERNAL_CERT_SANS': "'DNS:first.example,,DNS:research.example'",
                    'DASHBOARD_ORIGINS': "'https://first.example https://research.example'"}
        original = "# Settings\nINTERNAL_CERT_SANS=\nDASHBOARD_ORIGINS=\n"
        self.assertEqual(add_management_origin(original, existing, 'https://research.example'),
                         '# Settings\nINTERNAL_CERT_SANS=DNS:first.example,DNS:research.example\n'
                         "DASHBOARD_ORIGINS='https://first.example https://research.example'\n")
        self.assertEqual(add_management_origin('', {}, 'https://192.0.2.1'),
                         'INTERNAL_CERT_SANS=IP:192.0.2.1\nDASHBOARD_ORIGINS=https://192.0.2.1\n')

    def test_source_image_entry_writes_all_images_or_leaves_settings_unchanged(self):
        images = {'BACKEND_IMAGE': 'fixture/backend:new', 'SELFHOST_FRONTEND_IMAGE': 'fixture/frontend:new',
                  'CADDY_IMAGE': 'fixture/caddy:new'}
        command = ['record-source-images', '--backend-image', images['BACKEND_IMAGE'],
                   '--frontend-image', images['SELFHOST_FRONTEND_IMAGE'], '--caddy-image', images['CADDY_IMAGE']]
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / '.env'
            original = '\n'.join(f'export {key}=fixture/old' for key in images) + '\n'
            path.write_text(original)
            self.assertEqual(self.cli(command, folder), (0, '', ''))
            self.assertEqual(path.read_text(), '\n'.join(f'{key}={image}' for key, image in images.items()) + '\n')
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            incomplete = original.split('\n', 1)[1]
            path.write_text(incomplete)
            self.assertEqual(self.cli(command, folder), (1, '', 'error: missing environment keys: BACKEND_IMAGE\n'))
            self.assertEqual(path.read_text(), incomplete)

    def test_named_fields_are_order_independent_and_preserve_empty_and_equals(self):
        values = dict.fromkeys(SETUP_FIELDS, '')
        values['DOMAIN'] = 'host.example'
        values['POSTGRES_PASSWORD'] = 'synthetic=value'
        records = b''.join(f'{key}={value}\0'.encode() for key, value in reversed(values.items()))
        self.assertEqual(parse_setup_fields(records), values)

    def test_invalid_field_sets_fail_without_disclosing_values(self):
        records = [f'{key}=\0'.encode() for key in SETUP_FIELDS]
        for invalid in (records[:-1], records + [records[0]], records + [b'UNKNOWN=private-sentinel\0'],
                        records + [b'private-sentinel\0'], [b'DOMAIN=private-sentinel']):
            with self.subTest(records=len(invalid)), self.assertRaises(ValueError) as failure:
                parse_setup_fields(b''.join(invalid))
            self.assertNotIn('private-sentinel', str(failure.exception))

    def test_env_writer_replaces_assignments_and_quotes_literal_values(self):
        original = '# Settings\nexport DOMAIN=old\nUNRELATED=preserved\n'
        self.assertEqual(set_env_values(original, {'DOMAIN': 'host example', 'NEW_KEY': 'a=b'},
                                        require_existing=False),
                         '# Settings\nDOMAIN=\'host example\'\nUNRELATED=preserved\nNEW_KEY=a=b\n')
        self.assertEqual(set_env_values(original, {'DOMAIN': ''}, require_existing=True),
                         '# Settings\nDOMAIN=\nUNRELATED=preserved\n')
        for text, updates in ((original, {'MISSING': 'private-sentinel'}),
                              ('DOMAIN=one\nexport DOMAIN=two\n', {'DOMAIN': 'private-sentinel'})):
            with self.subTest(text=text), self.assertRaises(ValueError) as failure:
                set_env_values(text, updates, require_existing=True)
            self.assertNotIn('private-sentinel', str(failure.exception))
