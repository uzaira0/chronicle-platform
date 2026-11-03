"""The release smoke uses the operator wizard for each deployment's network policy."""

import ipaddress
from pathlib import Path
import runpy
import subprocess
from unittest.mock import patch

from chronicle_ops.common import compose_gateway
from chronicle_ops.envfile import read_env, set_env_values, value
from test_secret_generation import ROOT, SelfhostSetupFixture


class SmokeSetupTests(SelfhostSetupFixture):
    def test_backup_waiver_is_explicit_and_persisted_only_when_requested(self):
        driver = runpy.run_path(str(ROOT / 'tests/smoke/selfhost_release_setup.py'))
        for requested in (False, True):
            with self.subTest(requested=requested):
                if requested:
                    (self.host / '.env').unlink()
                    probe = Path(self.folder.name) / 'bin/lsblk'
                    probe.write_text("#!/usr/bin/env bash\nprintf '%s\\n' '{\"blockdevices\":[{\"type\":\"disk\"}]}'\n")
                waiver = 'synthetic-fixture-without-study-data'
                with patch('subprocess.run', wraps=subprocess.run) as setup:
                    driver['setup_release'](
                        self.host, mode=driver['SetupMode'].BEHIND_PROXY,
                        public_host='chronicle.study-host.org', password='synthetic-dashboard-password',
                        monitoring=False, environment=dict(self.environment, BACKUP_STORAGE_ENCRYPTION_WAIVER=waiver),
                        backup_storage_encryption_waiver=waiver if requested else None)
                self.assertNotIn(driver['BACKUP_WAIVER_KEY'], setup.call_args.kwargs['env'].keys())
                settings = read_env(self.host / '.env')
                self.assertEqual(value(settings, driver['BACKUP_WAIVER_KEY']), waiver if requested else '')

    def test_setup_requires_a_reviewed_waiver_when_storage_cannot_be_confirmed(self):
        from chronicle_ops.setup_env import confirm_storage_encryption
        self.run_setup()
        for waiver, succeeds in ((None, False), ('', False), ('CHANGE_ME', False), ('OPS-reviewed-fixture', True)):
            with self.subTest(waiver=waiver), patch.object(Path, 'cwd', return_value=self.host), \
                 patch('chronicle_ops.verify.verify_database_storage', return_value=1), \
                 patch('chronicle_ops.verify.verify_backup_storage', return_value=1), \
                 patch('builtins.input', return_value=waiver, side_effect=EOFError if waiver is None else None) as prompt:
                if succeeds:
                    confirm_storage_encryption()
                    self.assertEqual(waiver, value(read_env(self.host / '.env'), 'BACKUP_STORAGE_ENCRYPTION_WAIVER'))
                else:
                    with self.assertRaisesRegex(ValueError, 'reviewed storage-encryption waiver'):
                        confirm_storage_encryption()
                prompt.assert_called_once()
        with patch.object(Path, 'cwd', return_value=self.host), \
             patch('chronicle_ops.verify.verify_database_storage') as probe, patch('builtins.input') as prompt:
            confirm_storage_encryption()
            probe.assert_not_called()
            prompt.assert_not_called()

    def test_setup_derives_acl_from_selected_subnet_and_ignores_ambient_policy(self):
        template = self.host / '.env.example'
        subnet = '10.253.72.0/24'
        template.write_text(set_env_values(template.read_text(), {'CHRONICLE_SUBNET': subnet}, require_existing=True))
        environment = dict(self.environment, COMPOSE_PROJECT_NAME='smoke-setup-fixture',
                           HTTP_PORT='43100', INTERNAL_PORT='43101', GRAFANA_PORT='43102',
                           DASHBOARD_ALLOWED_IPS='192.0.2.1/32', CADDY_TRUSTED_PROXIES='192.0.2.2/32')
        driver = runpy.run_path(str(ROOT / 'tests/smoke/selfhost_release_setup.py'))
        driver['setup_release'](self.host, mode=driver['SetupMode'].BEHIND_PROXY,
              public_host='chronicle.study-host.org', password='synthetic-dashboard-password',
              monitoring=True, environment=environment)
        settings = read_env(self.host / '.env')
        self.assertEqual(value(settings, 'CHRONICLE_SUBNET'), subnet)
        gateway = ipaddress.ip_address(compose_gateway(subnet))
        allowed = [ipaddress.ip_network(cidr) for cidr in value(settings, 'DASHBOARD_ALLOWED_IPS').split()]
        self.assertTrue(any(gateway in network for network in allowed), 'host gateway cannot reach the dashboard')
        self.assertEqual(value(settings, 'CADDY_TRUSTED_PROXIES'), f'{gateway}/32')
        self.assertEqual(value(settings, 'POOL_ALLOWED_IPS'), f'{gateway}/32')
        self.assertEqual(value(settings, 'TESTING_LOGIN_ENABLED'), 'false')
        self.assertEqual(value(settings, 'REQUIRE_MFA'), 'false')
        self.assertEqual(value(settings, 'COMPOSE_PROJECT_NAME'), environment['COMPOSE_PROJECT_NAME'])
        self.assertEqual(value(settings, 'INTERNAL_PORT'), environment['INTERNAL_PORT'])
        self.assertIn('overlays/monitoring.yml', value(settings, 'COMPOSE_FILE'))
        self.assertTrue(value(settings, 'DASHBOARD_PASSWORD_HASH').startswith('$2'))
        self.assertEqual((self.host / '.env').stat().st_mode & 0o777, 0o600)
