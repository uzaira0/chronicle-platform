"""Operator audit regressions, using synthetic state and the shipped configuration."""

import subprocess
import time
import unittest

from chronicle_ops.common import acquire_operation_lock, release_operation_lock
from host_tools import modern_bash
from test_secret_generation import ROOT, SelfhostSetupFixture


class OpsAuditRegressions(SelfhostSetupFixture):
    def test_edited_guard_inputs_fail_with_the_setting_name(self):
        from chronicle_ops.envfile import read_env, value
        self.run_setup()
        settings = read_env(self.host / '.env')
        base = dict(self.environment, **{key: value(settings, key) for key in settings})
        base.update(TLS_MODE='behind-proxy', DASHBOARD_EXPOSURE='internal', BACKUPS_ENABLED='true',
                    COMPOSE_FILE_SELECTION=value(settings, 'COMPOSE_FILE'), POOL_LISTENER_TLS='true')
        for key, invalid in (
            ('CHRONICLE_RECORD_STAFF_IP', 'no'), ('RATE_LIMIT_GUARD_EVENTS', '0'),
            ('RATE_LIMIT_MOBILE_ABUSE_EVENTS', '1000001'), ('RATE_LIMIT_WEB_ABUSE_EVENTS', 'no'),
            ('RATE_LIMIT_GUARD_WINDOW', 'forever'), ('RATE_LIMIT_WEB_WINDOW', '0s'),
            ('RATE_LIMIT_MOBILE_WINDOW', '999999999999999s'),
            ('RATE_LIMIT_WEB_WINDOW', '999999h999999h999999h'),
            ('RATE_LIMIT_GUARD_WINDOW', '0.0000000001ns'),
            ('JWT_SECRET_PREVIOUS', 'too-short'), ('JWT_SECRET_PREVIOUS', value(settings, 'JWT_SECRET')),
        ):
            with self.subTest(key=key):
                result = subprocess.run(['bash', str(self.host / 'guard-config.sh')], cwd=self.host,
                    env=dict(base, **{key: invalid}), capture_output=True, text=True, timeout=20)
                self.assertNotEqual(0, result.returncode)
                self.assertRegex(result.stdout, 'FAIL.*' + key)

    def test_loopback_pool_setup_keeps_participant_credentials_under_tls(self):
        from chronicle_ops.envfile import read_env, value
        self.run_setup()
        settings = read_env(self.host / '.env')
        self.assertEqual('127.0.0.1', value(settings, 'HTTP_BIND'))
        self.assertEqual('true', value(settings, 'POOL_LISTENER_TLS'))

    def test_rollback_moves_previous_jwt_expiry_with_its_secret(self):
        from chronicle_ops.envfile import read_env, set_env_values, value
        from chronicle_ops.restore import Rollback
        self.run_setup()
        current, state = self.host.parent / 'candidate', self.host.parent / 'state'
        current.mkdir()
        state.mkdir()
        original = (self.host / '.env').read_text()
        for expiry in (int(time.time()) + 600, 0):
            with self.subTest(expiry=expiry):
                (self.host / '.env').write_text(set_env_values(original,
                    {'JWT_SECRET_PREVIOUS_EXPIRES_AT': '1'}, require_existing=False))
                (current / '.env').write_text(set_env_values(original,
                    {'JWT_SECRET_PREVIOUS': 'previous-rollback-fixture-key-0123456789' if expiry else '',
                     'JWT_SECRET_PREVIOUS_EXPIRES_AT': str(expiry)}, require_existing=False))
                (current / '.env').chmod(0o600)
                operation = Rollback.__new__(Rollback)
                operation.previous, operation.current, operation.state = self.host, current, state
                operation.settings, operation.current_settings = read_env(self.host / '.env'), read_env(current / '.env')
                operation.record = {'settings_archive': str(state / f'saved-{expiry}'), 'phase': 'rollback-settings'}
                operation.transfer_settings()
                self.assertEqual(str(expiry), value(read_env(self.host / '.env'), 'JWT_SECRET_PREVIOUS_EXPIRES_AT'))

    def test_previous_jwt_key_preserves_apostrophes_accepted_by_the_settings_reader(self):
        from chronicle_ops.envfile import read_env, value
        script = self.host / 'preserve-previous.sh'
        script.write_text('source ./rotate-secret.sh\nIFS= read -r previous\nenv_update JWT_SECRET_PREVIOUS "$previous"\n')
        (self.host / '.env').write_text("JWT_SECRET_PREVIOUS=''\n")
        previous = "synthetic-old-key-with-apostrophe'0123456789"
        result = subprocess.run(['bash', str(script)], cwd=self.host, env=self.environment,
                                input=previous + '\n', capture_output=True, text=True, timeout=10)
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertTrue(previous == value(read_env(self.host / '.env'), 'JWT_SECRET_PREVIOUS'), 'previous signing bytes changed')

    def test_setup_refuses_unsafe_network_answers_before_the_next_prompt(self):
        script = self.host / 'prompt-probe.sh'
        script.write_text('''#!/usr/bin/env bash
set -euo pipefail
source ./chronicle
source ./network-policy.sh
read() { printf '%s\\n' "$*" >>"$PROMPT_LOG"; builtin read "$@"; }
tls_mode=behind-proxy http_bind=127.0.0.1 internal_bind=127.0.0.1
domain=chronicle.study-host.org keep_subnet='' keep_public_base_url=''
setup_network_policy
''')
        for answers, next_prompt, message in (
            (['http://10.0.0.5'], 'Public HTTP redirect', 'public HTTPS origin is required'),
            (['', '', '', '0.0.0.0/0'], 'LB destination port', 'invalid pool ingress CIDRs'),
            ([''] * 8 + ['0.0.0.0/0'], 'Researcher HTTPS origin', 'invalid researcher source CIDRs'),
            ([''] * 9 + ['http://10.0.0.5'], 'reconciliation', 'researcher URL must be an HTTPS origin'),
        ):
            with self.subTest(next_prompt=next_prompt):
                log = self.host / 'prompts'
                log.write_text('')
                result = subprocess.run(['bash', str(script)], cwd=self.host,
                    env=dict(self.environment, PROMPT_LOG=str(log)), input='\n'.join(answers) + '\n',
                    capture_output=True, text=True, timeout=10)
                self.assertNotEqual(0, result.returncode)
                self.assertIn(message, result.stderr)
                self.assertNotIn(next_prompt, log.read_text())
                self.assertFalse((self.host / '.env').exists())

    def test_inherited_operation_lock_reaches_rotation_without_reexecution(self):
        self.run_setup()
        shell = modern_bash()
        (self.host.parent / 'bin/bash').symlink_to(shell)
        descriptor = acquire_operation_lock(self.host)
        try:
            environment = dict(self.environment, CHRONICLE_OPS_STATE=str(self.host),
                               CHRONICLE_OPERATION_LOCK_FD=str(descriptor))
            result = subprocess.run([shell, str(self.host / 'rotate-secret.sh'), '--yes', 'jwt'],
                                    env=environment, pass_fds=(descriptor,), capture_output=True, text=True, timeout=8)
            self.assertNotEqual(0, result.returncode)
            self.assertIn("Compose service 'backend' is not running", result.stderr)
        finally:
            release_operation_lock(descriptor)

    def test_monitoring_probe_uses_operator_identity_and_no_read_override(self):
        import yaml
        services = yaml.safe_load((ROOT / 'selfhost/overlays/monitoring.yml').read_text())['services']
        probe = services['operational-probe']
        self.assertEqual('${CHRONICLE_HOST_UID}:${CHRONICLE_HOST_GID}', probe['user'])
        self.assertFalse(probe.get('cap_add'))
        for name, service in services.items():
            if service.get('restart') not in (None, 'no') and service.get('user') == '0:0':
                self.assertIn(name, ('docker-socket-proxy', 'cadvisor'))
            for mount in service.get('volumes', []):
                if 'docker.sock' in str(mount):
                    self.assertEqual('docker-socket-proxy', name)

    def test_loopback_pool_certificate_covers_the_actual_listener_address(self):
        from selfhost_fixture import run_cert_init
        tls = self.host.parent / 'loopback-tls'
        tls.mkdir()
        result = run_cert_init(tls, base=self.environment, HTTP_BIND='127.0.0.2', POOL_LISTENER_TLS='true')
        self.assertEqual(0, result.returncode, result.stderr)
        checked = subprocess.run(['openssl', 'x509', '-checkip', '127.0.0.2', '-noout', '-in', str(tls / 'internal-cert.pem')],
                                 capture_output=True, text=True, timeout=10)
        self.assertEqual(0, checked.returncode, checked.stderr)

    def test_documented_monitoring_root_exceptions_cannot_gain_host_write_access(self):
        import copy
        import yaml
        from chronicle_ops.verify import service_contract_violations
        original = yaml.safe_load((ROOT / 'selfhost/overlays/monitoring.yml').read_text())
        for name, field, changed, message in (
            ('operational-probe', 'user', '0:0', 'long-running as root'),
            ('operational-probe', 'user', '00:0', 'long-running as root'),
            ('docker-socket-proxy', 'cap_add', ['SYS_ADMIN'], 'socket-proxy root exception'),
            ('cadvisor', 'volumes', ['/:/rootfs:rw', '/sys:/sys:ro', '/var/lib/docker/:/var/lib/docker:ro'], 'cAdvisor root exception'),
        ):
            with self.subTest(service=name, field=field):
                config = copy.deepcopy(original)
                config['services'][name][field] = changed
                path = self.host.parent / 'monitoring-policy.yml'
                path.write_text(yaml.safe_dump(config))
                self.assertIn(message, service_contract_violations([str(path)]))

    def test_external_webhook_secret_is_in_both_rotation_and_incident_recipes(self):
        for name in ('SECRET-ROTATION.md', 'INCIDENT-RESPONSE.md'):
            self.assertIn('CHRONICLE_ALERT_WEBHOOK_URL', (ROOT / 'selfhost/docs' / name).read_text())

    def test_secret_catalog_is_covered_by_the_rotation_docs_and_release_smoke(self):
        from chronicle_ops.credentials import SETUP_SECRETS
        guide = (ROOT / 'selfhost/docs/SECRET-ROTATION.md').read_text()
        smoke = (ROOT / 'tests/smoke/selfhost-release-smoke.sh').read_text()
        for secret in SETUP_SECRETS:
            self.assertTrue('rotate-secret ' + secret.name in guide, secret.name)
            self.assertTrue('rotate-secret --yes ' + secret.name in smoke, secret.name)

    def test_reset_compatibility_has_a_numeric_minimum_and_matches_release_metadata(self):
        from chronicle_ops.release import ANDROID_COMPATIBILITY
        guide = (ROOT / 'selfhost/docs/DEPLOYMENT-COMPATIBILITY.md').read_text()
        self.assertIn('versionCode **' + str(ANDROID_COMPATIBILITY['minimum_version_code']) + '**', guide)
        self.assertIn(ANDROID_COMPATIBILITY['version_name'], guide)
        self.assertIn(ANDROID_COMPATIBILITY['play_track'], guide)

    def test_compose_guard_receives_every_security_input_it_validates(self):
        import yaml
        guard = yaml.safe_load((ROOT / 'selfhost/docker-compose.yml').read_text())['services']['config-guard']['environment']
        for name in ('CHRONICLE_RECORD_STAFF_IP', 'JWT_SECRET_PREVIOUS', 'JWT_SECRET_PREVIOUS_EXPIRES_AT',
                     'RATE_LIMIT_MOBILE_ABUSE_EVENTS', 'RATE_LIMIT_MOBILE_WINDOW',
                     'RATE_LIMIT_WEB_ABUSE_EVENTS', 'RATE_LIMIT_WEB_WINDOW',
                     'RATE_LIMIT_GUARD_EVENTS', 'RATE_LIMIT_GUARD_WINDOW'):
            self.assertIn(name, guard)

    def test_staff_ip_recording_defaults_off_everywhere(self):
        # Staff IP fingerprints are opt-in.
        import yaml
        services = yaml.safe_load((ROOT / 'selfhost/docker-compose.yml').read_text())['services']
        defaults = {service: environment['CHRONICLE_RECORD_STAFF_IP'] for service, body in services.items()
                    if 'CHRONICLE_RECORD_STAFF_IP' in (environment := body.get('environment') or {})}
        self.assertEqual({'config-guard', 'backend'}, set(defaults))
        self.assertEqual({'${CHRONICLE_RECORD_STAFF_IP:-false}'}, set(defaults.values()))
        self.assertIn(': "${CHRONICLE_RECORD_STAFF_IP:=false}"', (ROOT / 'selfhost/guard-config.sh').read_text().splitlines())
        self.assertIn('CHRONICLE_RECORD_STAFF_IP=false', (ROOT / 'selfhost/.env.example').read_text().splitlines())


if __name__ == '__main__':
    unittest.main()
