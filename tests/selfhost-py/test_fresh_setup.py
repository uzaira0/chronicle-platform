"""Fresh published bundles must pass startup's configuration checks without containers."""

import json
import os
import runpy
import shlex
import shutil
import signal
import subprocess
import sys
import time
from types import SimpleNamespace
from unittest.mock import patch

from chronicle_ops.common import run
from test_secret_generation import ROOT, SelfhostSetupFixture
from selfhost_fixture import bundle_fixture_files, run_cert_init


class FreshBundleSetupTests(SelfhostSetupFixture):
    def install_ip_stub(self, extra=''):
        """An `ip` that reports loopback and one LAN IPv4 address (plus `extra` printf lines) and no policy routes."""
        (self.host.parent / 'bin/ip').write_text('''#!/bin/sh
case "$*" in
  '-o addr show'|'-4 -o addr show') printf '1: lo inet 127.0.0.1/8 scope host lo\n2: lan inet 192.168.50.10/24 scope global lan\n%s' ;;
  *'route show table all') printf '[]\\n' ;;
esac
''' % extra)

    def test_trial_setup_rejects_ipv6_before_publishing_settings(self):
        driver = runpy.run_path(str(ROOT / 'tests/smoke/selfhost_release_setup.py'))
        self.install_ip_stub(r'3: lan inet6 fd12:3456::5/64 scope global lan\n')
        for address, accepted in (('fd12:3456::5', False), ('192.168.50.10', True)):
            with self.subTest(address=address):
                (self.host / '.env').unlink(missing_ok=True)
                answers = driver['setup_answers'](mode=driver['SetupMode'].LOCAL_HTTPS,
                    public_host=address, password='synthetic-dashboard-password', monitoring=False)
                result = run(['bash', str(self.host / 'chronicle'), 'setup'], input=answers,
                    env=self.environment, capture=True, stderr=subprocess.PIPE, timeout=20)
                self.assertEqual(accepted, result.returncode == 0, result.stdout + result.stderr)
                self.assertEqual(accepted, (self.host / '.env').exists())
                if accepted:
                    from chronicle_ops.envfile import read_env, value
                    self.assertEqual('https://' + address,
                                     value(read_env(self.host / '.env'), 'CHRONICLE_PUBLIC_BASE_URL'))
                else:
                    self.assertIn('IPv4', result.stderr)

    def test_leaving_the_local_trial_drops_its_private_origin_and_passes_the_production_guard(self):
        from chronicle_ops.envfile import read_env, value
        driver = runpy.run_path(str(ROOT / 'tests/smoke/selfhost_release_setup.py'))
        self.install_ip_stub()
        for mode, public_host, origin, rerun in ((driver['SetupMode'].LOCAL_HTTPS, '192.168.50.10', 'https://192.168.50.10', False),
                                                 (driver['SetupMode'].BEHIND_PROXY, 'chronicle.study-host.org', 'https://chronicle.study-host.org', True)):
            answers = driver['setup_answers'](mode=mode, public_host=public_host, password='synthetic-dashboard-password',
                                              monitoring=False, overwrite=rerun, reuse_hash=rerun)
            result = run(['bash', str(self.host / 'chronicle'), 'setup'], input=answers,
                         env=self.environment, capture=True, stderr=subprocess.PIPE, timeout=20)
            self.assertEqual(0, result.returncode, result.stdout + result.stderr)
            self.assertEqual(origin, value(read_env(self.host / '.env'), 'CHRONICLE_PUBLIC_BASE_URL'))
        result = self.guard()
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)

    def test_every_fresh_setup_mode_initializes_an_internal_certificate_without_an_empty_san(self):
        from chronicle_ops.envfile import read_env, value
        driver = runpy.run_path(str(ROOT / 'tests/smoke/selfhost_release_setup.py'))
        self.install_ip_stub()
        for mode in driver['SetupMode']:
            with self.subTest(mode=mode):
                (self.host / '.env').unlink(missing_ok=True)
                public_host = '192.168.50.10' if mode == driver['SetupMode'].LOCAL_HTTPS else 'chronicle.study-host.org'
                answers = driver['setup_answers'](mode=mode, public_host=public_host,
                                                  password='synthetic-dashboard-password', monitoring=False)
                result = run(['bash', str(self.host / 'chronicle'), 'setup'], input=answers,
                             env=self.environment, capture=True, stderr=subprocess.PIPE, timeout=20)
                self.assertEqual(0, result.returncode, result.stdout + result.stderr)
                settings = read_env(self.host / '.env')
                sans = value(settings, 'INTERNAL_CERT_SANS')
                tls = self.host.parent / f'tls-{mode.value}'
                tls.mkdir()
                initialized = run_cert_init(tls, script=self.host / 'cert-init.sh', base=self.environment,
                                            **{key: value(settings, key) for key in ('DOMAIN', 'INTERNAL_BIND', 'INTERNAL_CERT_SANS',
                                                                                     'HTTP_BIND', 'POOL_LISTENER_TLS', 'DASHBOARD_BASE_URL')})
                self.assertEqual(0, initialized.returncode, initialized.stdout + initialized.stderr)
                names = run(['openssl', 'x509', '-noout', '-ext', 'subjectAltName', '-in', str(tls / 'internal-cert.pem')],
                            capture=True, timeout=10).stdout
                for san in filter(None, sans.split(',')):
                    self.assertIn(san.replace('IP:', 'IP Address:'), names)
                self.assertNotIn('', sans.split(',') if sans else [])

    def test_published_pins_reach_the_image_inventory_without_a_source_checkout(self):
        from chronicle_ops.envfile import set_env_values
        from chronicle_ops.images import SOURCE_IMAGES
        self.run_setup()
        settings = self.host / '.env'
        for optional in (False, True):
            pins = {image.variable: 'fixture/' + image.component + '@sha256:' + 'a' * 64
                    if optional or not image.overlay else image.placeholder for image in SOURCE_IMAGES}
            pins['COMPOSE_FILE'] = ':'.join(['docker-compose.yml', 'overlays/mode-behind-proxy-internal.yml',
                *dict.fromkeys(image.overlay for image in SOURCE_IMAGES if optional and image.overlay)])
            settings.write_text(set_env_values(settings.read_text(), pins, require_existing=False))
            result = run(['bash', '-c', 'source "$1"; need_env; ensure_images; printf pinned',
                          'fixture', str(self.host / 'chronicle')], cwd=self.host,
                         env=self.environment, capture=True, stderr=subprocess.PIPE, timeout=10)
            self.assertEqual(0, result.returncode, result.stdout + result.stderr)
            self.assertEqual('pinned', result.stdout)

    def test_release_guard_checks_enabled_optional_images(self):
        from chronicle_ops.envfile import read_env, set_env_values, value
        from chronicle_ops.images import SOURCE_IMAGES
        self.run_setup()
        settings = self.host / '.env'
        settings.write_text(set_env_values(settings.read_text(),
            dict(RELEASE_VERSION='1.0.0', **{image.variable: 'fixture/' + image.component + '@sha256:' + 'a' * 64
                                           for image in SOURCE_IMAGES}), require_existing=False))
        environment = dict(self.environment, **{key: value(read_env(settings), key) for key in read_env(settings)})
        environment.update(TLS_MODE='behind-proxy', DASHBOARD_EXPOSURE='internal', BACKUPS_ENABLED='true',
                           MONITORING_ENABLED='false', COMPOSE_FILE_SELECTION=value(read_env(settings), 'COMPOSE_FILE'))
        for image in SOURCE_IMAGES:
            if not image.overlay:
                continue
            selected = ':'.join(dict.fromkeys((environment['COMPOSE_FILE_SELECTION'] + ':' + image.overlay).split(':')))
            for reference, valid in (('mutable:latest', False), ('fixture/' + image.component + '@sha256:' + 'a' * 64, True)):
                with self.subTest(image=image.component, valid=valid):
                    result = run(['bash', str(self.host / 'guard-config.sh')], cwd=self.host,
                        env=dict(environment, COMPOSE_FILE_SELECTION=selected, **{image.variable: reference}),
                        capture=True, stderr=subprocess.PIPE, timeout=10)
                    self.assertEqual(valid, result.returncode == 0, result.stdout + result.stderr)
                    if not valid:
                        self.assertIn(image.variable + ' must be digest-pinned', result.stdout)

    def test_every_first_party_pin_must_match_the_inputs_tree(self):
        from chronicle_ops.images import SOURCE_IMAGES, source_inputs_tree
        builder = runpy.run_path(str(ROOT / 'scripts/build-selfhost-release.py'))
        revision = subprocess.check_output(['git', '-C', str(ROOT), 'rev-parse', 'HEAD'], text=True).strip()
        tree = source_inputs_tree(ROOT, revision)
        args = SimpleNamespace(version='2026.10.17', source_revision=revision, public_revision=None,
                               source_date_epoch=1700000000, **{image.component + '_image':
                               f'fixture/{image.component}@sha256:' + 'a' * 64 for image in SOURCE_IMAGES})
        validate = builder['validate_inputs']
        for stale in (None, *SOURCE_IMAGES):
            def inspect(command, **kwargs):
                bad = stale is not None and command[-1] == getattr(args, stale.component + '_image')
                return subprocess.CompletedProcess(command, 0, stdout=('0' * 40 if bad else tree) + '\n')
            with self.subTest(stale=stale), patch.dict(validate.__globals__, subprocess=SimpleNamespace(run=inspect)):
                if stale is None:
                    self.assertEqual(len(SOURCE_IMAGES), len(validate(args)))
                else:
                    with self.assertRaises(SystemExit):
                        validate(args)

    def test_every_setup_mode_passes_shipped_preflight(self):
        from chronicle_ops.migrations import migration_hashes
        docker = shutil.which('docker')
        if docker is None:
            self.skipTest('Docker Compose CLI unavailable (no daemon needed)')
        builder = runpy.run_path(str(ROOT / 'scripts/build-selfhost-release.py'))
        driver = runpy.run_path(str(ROOT / 'tests/smoke/selfhost_release_setup.py'))
        bundle = self.host.parent / 'bundle'
        tree = subprocess.check_output(['git', '-C', str(ROOT), 'rev-parse', 'HEAD^{tree}'], text=True).strip()
        args = SimpleNamespace(backup_image=None, source_revision='a' * 40, inputs_tree=tree,
                               public_revision=None, source_date_epoch=1700000000,
                               migrations=migration_hashes(ROOT))
        builder['copy_bundle_inputs'](bundle, args, builder['tracked_source_paths'](ROOT) |
                                      {'selfhost/' + name for name in bundle_fixture_files(builder)})
        builder['render_bundle'](bundle, args,
                                 {kind: f'fixture/{kind}@sha256:' + 'b' * 64
                                  for kind in builder['PLACEHOLDERS'].values()}, '2026.10.9')
        builder['require_offline_links'](bundle)
        from chronicle_ops.images import IMAGE_INPUTS_KEY, bundle_images
        manifest = json.loads((bundle / 'release-manifest.json').read_text())
        from chronicle_ops.release import ANDROID_COMPATIBILITY
        self.assertEqual(ANDROID_COMPATIBILITY, manifest['android_compatibility'])
        self.assertLessEqual(bundle_images(bundle / 'selfhost'), set(manifest['images'].values()))
        self.assertEqual({kind: tree for kind in builder['PLACEHOLDERS'].values()}, manifest[IMAGE_INPUTS_KEY])
        self.install_ip_stub()
        # Include both monitoring choices; each case starts from an untouched bundle.
        for mode in driver['SetupMode']:
            domain = '192.168.50.10' if mode == driver['SetupMode'].LOCAL_HTTPS else 'chronicle.study-host.org'
            for monitoring in (False, True):
                with self.subTest(mode=mode, monitoring=monitoring):
                    host = self.host.parent / f'mode-{mode.value}-{monitoring}'
                    shutil.copytree(bundle / 'selfhost', host)
                    self.assertFalse((host / '.env').exists())
                    environment = self.environment.copy()
                    result = driver['setup_release'](
                        host, mode=mode, public_host=domain, password='synthetic-dashboard-password',
                        monitoring=monitoring, environment=environment, capture=True)
                    self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
                    self.assertEqual((host / '.env').stat().st_mode & 0o777, 0o600)
                    if mode == driver['SetupMode'].OWN_TLS:
                        # Operators supply their TLS material before startup in this mode.
                        for name in ('cert.pem', 'key.pem'):
                            (host / 'tls' / name).write_text('synthetic TLS fixture\n')
                    rendered = run([docker, 'compose', 'config', '--format', 'json'], cwd=host,
                                   env=environment, capture=True, stderr=subprocess.PIPE, timeout=20)
                    self.assertEqual(rendered.returncode, 0, rendered.stderr)
                    guard = json.loads(rendered.stdout)['services']['config-guard']['environment']
                    # Compose escapes dollars when serializing a reusable Compose document.
                    guard = {key: text.replace('$$', '$') for key, text in guard.items()}
                    # Setup fakes Docker's bcrypt helper; verification needs the real Compose parser.
                    environment.update(guard, CHRONICLE_GUARD_TLS_DIR=str(host / 'tls'), PATH=os.environ['PATH'])
                    for script in ('verify-config.sh', 'guard-config.sh'):
                        checked = run(['bash', str(host / script)], cwd=host, env=environment,
                                      capture=True, stderr=subprocess.PIPE, timeout=20)
                        self.assertEqual(checked.returncode, 0, checked.stderr + checked.stdout)
                    rejected = run(['bash', str(host / 'guard-config.sh')], cwd=host,
                                   env=dict(environment, TESTING_LOGIN_ENABLED='true'),
                                   capture=True, stderr=subprocess.PIPE, timeout=20)
                    self.assertNotEqual(rejected.returncode, 0)
                    self.assertIn('TESTING_LOGIN_ENABLED must be false', rejected.stdout)

    def guard(self, **overrides):
        from chronicle_ops.envfile import read_env, value
        settings = read_env(self.host / '.env')
        environment = dict(self.environment, **{key: value(settings, key) for key in settings})
        environment.update(TLS_MODE='behind-proxy', DASHBOARD_EXPOSURE='internal', BACKUPS_ENABLED='true',
                           COMPOSE_FILE_SELECTION=value(settings, 'COMPOSE_FILE'),
                           CHRONICLE_GUARD_TLS_DIR=str(self.host / 'tls'), **overrides)
        return run(['bash', str(self.host / 'guard-config.sh')], cwd=self.host, env=environment,
                   capture=True, stderr=subprocess.PIPE, timeout=20)

    def test_pool_listener_off_loopback_needs_tls_or_a_recorded_waiver(self):
        self.run_setup()
        for overrides, accepted in (
                (dict(HTTP_BIND='127.0.0.1', POOL_LISTENER_TLS='false'), False),
                (dict(HTTP_BIND='127.0.0.1', POOL_LISTENER_TLS='false', POOL_PLAINTEXT_WAIVER='RISK-2026-07 local LB'), True),
                (dict(HTTP_BIND='10.20.0.5', POOL_LISTENER_TLS='true'), True),
                (dict(HTTP_BIND='10.20.0.5', POOL_LISTENER_TLS='false'), False),
                (dict(HTTP_BIND='0.0.0.0', POOL_LISTENER_TLS='false'), False),
                (dict(HTTP_BIND='10.20.0.5', POOL_LISTENER_TLS='false', POOL_PLAINTEXT_WAIVER='CHANGE_ME'), False),
                (dict(HTTP_BIND='10.20.0.5', POOL_LISTENER_TLS='false', POOL_PLAINTEXT_WAIVER='RISK-2026-07 LB VLAN'), True),
                (dict(HTTP_BIND='10.20.0.5', POOL_LISTENER_TLS='yes'), False)):
            with self.subTest(**overrides):
                # A remote load balancer also needs its own source range trusted.
                result = self.guard(CADDY_TRUSTED_PROXIES='10.20.0.0/24', **overrides)
                self.assertEqual(accepted, result.returncode == 0, result.stdout + result.stderr)
                if not accepted:
                    self.assertIn('POOL_', result.stdout)

    def test_resetup_reaches_the_fresh_setup_pool_tls_answer(self):
        from chronicle_ops.envfile import read_env, set_env_values, value
        self.environment.update(HTTP_BIND='0.0.0.0', CADDY_TRUSTED_PROXIES='10.20.0.0/24')
        self.run_setup()
        settings = self.host / '.env'
        self.assertEqual('true', value(read_env(settings), 'POOL_LISTENER_TLS'))
        for saved, waiver, expected in (('false', '', 'true'), ('', '', 'true'), ('false', 'CHANGE_ME', 'true'),
                                        ('false', 'RISK-2026-07 LB VLAN', 'false'), ('true', 'RISK-2026-07 LB VLAN', 'true')):
            with self.subTest(saved=saved, waiver=waiver):
                settings.write_text(set_env_values(settings.read_text(), dict(POOL_LISTENER_TLS=saved, POOL_PLAINTEXT_WAIVER=waiver),
                                                   require_existing=False))
                self.run_setup(rerun=True)
                self.assertEqual(expected, value(read_env(settings), 'POOL_LISTENER_TLS'))
                result = self.guard(CADDY_TRUSTED_PROXIES='10.20.0.0/24')
                self.assertEqual(0, result.returncode, result.stdout + result.stderr)

    def test_mfa_with_internal_password_login_is_refused(self):
        self.run_setup()
        for setting in ('false', ''):  # unset defaults to the internal password login's false
            accepted = self.guard(REQUIRE_MFA=setting)
            self.assertEqual(0, accepted.returncode, accepted.stdout + accepted.stderr)
        refused = self.guard(REQUIRE_MFA='true')
        self.assertNotEqual(0, refused.returncode, refused.stdout)
        self.assertIn('REQUIRE_MFA=true', refused.stdout)

    def test_numeric_settings_are_validated_by_name(self):
        self.run_setup()
        for name, invalid, valid in (
                ('MIN_FREE_DISK_GIB', 'lots', '20'), ('BACKUP_KEEP_DAYS', '7d', '7'),
                ('BACKUP_KEEP_WEEKS', '-1', '4'), ('BACKUP_KEEP_MONTHS', 'six', '6'),
                ('BACKEND_XMX', '2 gigs', '-Xmx2g'),
                ('BACKUP_SCHEDULE', '0 3 30 2 *', '0 3 * * 1-5')):
            with self.subTest(name=name):
                result = self.guard(**{name: valid})
                self.assertEqual(0, result.returncode, result.stdout + result.stderr)
                result = self.guard(**{name: invalid})
                self.assertNotEqual(0, result.returncode, result.stdout)
                self.assertIn(name, result.stdout)


class BackupRetentionSetupTests(SelfhostSetupFixture):
    def answers(self, retention):
        driver = runpy.run_path(str(ROOT / 'tests/smoke/selfhost_release_setup.py'))
        text = driver['setup_answers'](mode=driver['SetupMode'].BEHIND_PROXY, public_host='chronicle.study-host.org',
                                       password='synthetic-dashboard-password', monitoring=False)
        chosen = '\n'.join(driver['BACKUP_RETENTION']) + '\n'
        self.assertTrue(text.endswith(chosen))
        return text[:-len(chosen)] + '\n'.join(retention) + '\n'

    def setup(self, retention):
        return run(['bash', str(self.host / 'chronicle'), 'setup'], input=self.answers(retention), env=self.environment,
                   capture=True, stderr=subprocess.PIPE, timeout=20)

    def test_piped_setup_records_the_chosen_retention_and_never_supplies_one(self):
        from chronicle_ops.envfile import read_env, value
        refused = self.setup(('', '', '', ''))
        self.assertNotEqual(0, refused.returncode, refused.stdout)
        self.assertIn('BACKUP_KEEP_DAYS needs an answer', refused.stderr + refused.stdout)
        self.assertFalse((self.host / '.env').exists())
        refused = self.setup(('7', 'weekly', '6', 'all'))
        self.assertNotEqual(0, refused.returncode)
        self.assertIn('BACKUP_KEEP_WEEKS must be all or a whole number', refused.stderr + refused.stdout)
        accepted = self.setup(('3', 'all', '12', 'all'))
        self.assertEqual(0, accepted.returncode, accepted.stderr + accepted.stdout)
        settings = read_env(self.host / '.env')
        self.assertEqual(('3', 'all', '12', 'all'), tuple(value(settings, key) for key in (
            'BACKUP_KEEP_DAYS', 'BACKUP_KEEP_WEEKS', 'BACKUP_KEEP_MONTHS', 'PRE_OP_BACKUP_KEEP_DAYS')))

    def test_retention_prompt_says_what_zero_keeps(self):
        # find -mtime +0 (days) and +1 (weeks/months) leave only the newest dump of a tier.
        accepted = self.setup(('0', '0', '0', 'all'))
        self.assertEqual(0, accepted.returncode, accepted.stderr + accepted.stdout)
        self.assertIn('0 keeps only the newest backup of that kind', accepted.stdout)


class InterruptedSetupTests(SelfhostSetupFixture):
    def test_setup_killed_at_the_storage_check_leaves_nothing_to_delete_by_hand(self):
        bin_dir = self.host.parent / 'bin'
        reached = self.host.parent / 'storage-check-reached'
        storage_probe = bin_dir / ('df' if sys.platform == 'darwin' else 'findmnt')
        encrypted = storage_probe.read_text()
        # The storage-encryption check is the last wait before setup finishes publishing settings.
        storage_probe.write_text(f'#!/usr/bin/env bash\n: >{shlex.quote(str(reached))}\nexec sleep 60\n')
        process = subprocess.Popen(['bash', str(ROOT / 'tests/security/lib/selfhost-fixtures.sh'), 'run-setup',
                                    str(self.host), 'false'], env=self.environment, stdout=subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL, start_new_session=True)
        try:
            deadline = time.monotonic() + 20
            while not reached.exists():
                self.assertIsNone(process.poll(), 'setup finished before its storage check')
                self.assertLess(time.monotonic(), deadline, 'setup never reached its storage check')
                time.sleep(0.05)
            self.assertTrue((self.host / '.env').exists())
        finally:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()
        storage_probe.write_text(encrypted)
        self.assertEqual([], [path.name for path in self.host.glob('.chronicle-*') if path.name != '.chronicle-stopped'])
        self.run_setup(rerun=True)
