"""Container runtime policy and the operator documents that describe it (launch audit 2026-11-06, Lane C).

Each test renders the shipped Compose files or runs the shipped script it names; the documents are
checked against what the rendered configuration actually does.
"""
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest

from test_egress import MODES, SELFHOST, SYNTHETIC, render

ROOT = SELFHOST.parent
DOCS = SELFHOST / 'docs'


def sections(text):
    """{heading: body} of a Markdown document's level-2 sections."""
    parts = re.split(r'^## ', text, flags=re.M)
    return {part.split('\n', 1)[0].strip(): part for part in parts[1:]}


class DocumentedDefaultsTests(unittest.TestCase):
    def test_a_comment_that_names_a_default_agrees_with_the_interpolated_default(self):
        """AF-S6c: 'Secure default true' sat above CHRONICLE_SECURITY_REQUIRE_MFA: ${REQUIRE_MFA:-false}."""
        for name in ('docker-compose.yml', *sorted(p.name for p in (SELFHOST / 'overlays').glob('*.yml'))):
            path = SELFHOST / name if name == 'docker-compose.yml' else SELFHOST / 'overlays' / name
            comments = []
            for number, line in enumerate(path.read_text().splitlines(), 1):
                stripped = line.strip()
                if stripped.startswith('#'):
                    comments.append(stripped)
                    continue
                entry = re.match(r'[A-Z_][A-Z0-9_]*: \$\{[A-Z_][A-Z0-9_]*:-(true|false)\}$', stripped)
                if entry:
                    claimed = set(re.findall(r'\bdefault (?:is )?(true|false)\b', ' '.join(comments), re.I))
                    with self.subTest(file=name, line=number):
                        self.assertLessEqual({value.lower() for value in claimed}, {entry.group(1)},
                                             f'{name}:{number} comment names a default the value does not have')
                comments = []


class SocketProxyTests(unittest.TestCase):
    def test_the_socket_proxy_carries_no_setting_its_haproxy_never_reads(self):
        """AF-S7: CONTAINERS/INFO/VERSION/POST belong to the image's own entrypoint, which is replaced."""
        config = render(MODES[0], 'overlays/backups.yml', 'overlays/monitoring.yml')
        proxy = config['services']['docker-socket-proxy']
        self.assertEqual(['haproxy'], proxy['entrypoint'])
        self.assertFalse(proxy.get('environment'), proxy.get('environment'))


class StudyWebhookDocumentTests(unittest.TestCase):
    def test_every_section_about_study_webhooks_says_self_host_refuses_them(self):
        """SO-X1: CONFIGURATION.md and UNINSTALL-DATA-DELETION.md described registering and delivering them."""
        for path in [SELFHOST / 'README.md', *sorted(DOCS.glob('*.md'))]:
            for heading, body in sections(path.read_text()).items():
                if re.search(r'study webhook', body, re.I):
                    with self.subTest(document=path.name, section=heading):
                        self.assertRegex(body, r'(?i)study webhooks are off', f'{path.name} "{heading}" describes '
                                         'study webhooks without saying self-host has them off')


class PublishedPortFirewallDocumentTests(unittest.TestCase):
    def test_no_document_tells_the_operator_a_host_firewall_filters_published_ports(self):
        """CI-N3: Docker's published-port rules bypass UFW/firewalld input rules; DOCKER-USER is the place."""
        example = (SELFHOST / '.env.example').read_text()
        block = example[:example.index('\nPOOL_ALLOWED_IPS=')].rsplit('\n\n', 1)[-1]
        self.assertNotRegex(block, r'(?i)host\s+firewall\s+governs')
        readme = (SELFHOST / 'README.md').read_text()
        self.assertIn('DOCKER-USER', readme)
        self.assertRegex(readme, r'(?is)ufw.{0,200}firewalld|firewalld.{0,200}ufw')


class AlertWebhookValidationTests(unittest.TestCase):
    def guard(self, url):
        return subprocess.run(['bash', str(SELFHOST / 'guard-config.sh'), '--validate-alert-webhook', url],
                              capture_output=True, text=True, timeout=10, check=False).returncode

    def test_the_guard_accepts_https_off_the_host_and_plain_http_only_on_loopback(self):
        """SO-I3: an alert webhook carries alert text; off the host it must be HTTPS."""
        for url, accepted in (('https://alerts.example.org/hook/abc', True),
                              ('https://alerts.example.org:8443/hook', True),
                              ('http://127.0.0.1:9/dashboard-only', True),
                              ('http://localhost:9093/relay', True),
                              ('http://alerts.example.org/hook', False),
                              ('http://10.0.0.5/hook', False),
                              ('http://127.evil.example/hook', False),
                              ('http://[::1]:9/x', True),
                              ('https://user:secret@alerts.example.org/hook', False),
                              ("https://alerts.example.org/'x", False),
                              ('ftp://alerts.example.org/hook', False),
                              ('alerts.example.org/hook', False),
                              ('https:///hook', False)):
            with self.subTest(url=url):
                self.assertEqual(0 if accepted else 1, self.guard(url))


class AlertWebhookPromptTests(unittest.TestCase):
    def test_setup_asks_again_after_a_plain_http_webhook_and_keeps_the_https_one(self):
        """SO-I3: the prompt says HTTPS; a plain-http off-host answer is refused there, not later."""
        from test_secret_generation import SelfhostSetupFixture
        from chronicle_ops.envfile import read_env, value

        class Fixture(SelfhostSetupFixture):
            def runTest(self):
                pass
        fixture = Fixture()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        answers = subprocess.run(
            [sys.executable, '-s', str(ROOT / 'tests/smoke/selfhost_release_setup.py'), '--answers-only',
             '--public-host', 'chronicle.study-host.org', '--monitoring',
             '--alert-webhook', 'http://alerts.example.org/hook\nhttps://alerts.example.org/hook'],
            env=dict(fixture.environment, SMOKE_PASSWORD='synthetic-dashboard-password', ENABLE_MONITORING='false'),
            capture_output=True, text=True, timeout=30, check=True).stdout
        result = subprocess.run(['bash', str(fixture.host / 'chronicle'), 'setup'], input=answers,
                                env=fixture.environment, capture_output=True, text=True, timeout=60)
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertIn('alert webhook must be HTTPS', result.stdout + result.stderr)
        self.assertEqual('https://alerts.example.org/hook',
                         value(read_env(fixture.host / '.env'), 'CHRONICLE_ALERT_WEBHOOK_URL'))


class IncidentRecipeTests(unittest.TestCase):
    """SO-I9, SO-S3, SO-S6: the collect step's audit export runs as written inside the postgres container."""

    def collect_block(self):
        guide = (DOCS / 'INCIDENT-RESPONSE.md').read_text()
        collect = sections(guide)['1. Collect']
        return collect.split('```bash\n', 1)[1].split('```', 1)[0]

    def test_the_audit_export_authenticates_with_what_the_postgres_container_holds(self):
        block = self.collect_block()
        start = block.index('docker compose exec -T postgres')
        command = block[start:block.index('\n#', start)]
        postgres = render(MODES[0], 'overlays/backups.yml')['services']['postgres']['environment']
        with tempfile.TemporaryDirectory() as folder:
            folder = Path(folder)
            bin_dir = folder / 'bin'
            bin_dir.mkdir()
            password_file = folder / 'postgres-password'
            password_file.write_text(SYNTHETIC['POSTGRES_PASSWORD'])
            container = {key: value for key, value in postgres.items()}
            container['POSTGRES_PASSWORD_FILE'] = str(password_file)
            # docker compose exec -T postgres sh -c SCRIPT: run SCRIPT with the container's environment only.
            (bin_dir / 'docker').write_text(
                '#!/usr/bin/env python3\n'
                'import json, os, subprocess, sys\n'
                'args = sys.argv[1:]\n'
                'assert args[:4] == ["compose", "exec", "-T", "postgres"], args\n'
                f'env = json.loads({repr(__import__("json").dumps(container))})\n'
                f'env["PATH"] = {repr(str(bin_dir))} + ":/usr/bin:/bin"\n'
                'sys.exit(subprocess.run(args[4:], env=env).returncode)\n')
            # psql succeeds only with the password the server was initialised with.
            (bin_dir / 'psql').write_text(
                '#!/bin/sh\n'
                f'[ "$PGPASSWORD" = "{SYNTHETIC["POSTGRES_PASSWORD"]}" ] || {{ echo "psql: password authentication failed" >&2; exit 2; }}\n'
                'echo "id,event"\n')
            for tool in ('docker', 'psql'):
                (bin_dir / tool).chmod(0o755)
            case = folder / 'case'
            case.mkdir()
            result = subprocess.run(['bash', '-euo', 'pipefail', '-c', command],
                                    env=dict(os.environ, PATH=f'{bin_dir}:{os.environ["PATH"]}', case_dir=str(case)),
                                    capture_output=True, text=True, timeout=30)
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertEqual('id,event\n', (case / 'audit.csv').read_text())


class RunbookPrivilegeTests(unittest.TestCase):
    def test_the_runbook_privilege_table_matches_the_rendered_monitoring_services(self):
        """AF-S6a: the runbook gave the operational probe root and DAC_READ_SEARCH; compose gives neither."""
        config = render(MODES[0], 'overlays/backups.yml', 'overlays/monitoring.yml')
        without = render(MODES[0], 'overlays/backups.yml')
        monitoring = {name: service for name, service in config['services'].items()
                      if name not in without['services'] and service.get('restart') != 'no'}
        text = sections((DOCS / 'MONITORING-RUNBOOK.md').read_text())['Service privileges']
        rows = {}
        for line in text.splitlines():
            cells = [cell.strip(' `') for cell in line.strip().strip('|').split('|')]
            if len(cells) == 3 and cells[0] in monitoring:
                rows[cells[0]] = (cells[1], cells[2])
        self.assertEqual(set(monitoring), set(rows))
        for name, service in monitoring.items():
            user = service.get('user', '')
            capabilities = ', '.join(sorted(service.get('cap_add') or [])) or 'none'
            documented_user, documented_capabilities = rows[name]
            with self.subTest(service=name):
                self.assertEqual(capabilities, documented_capabilities)
                if user.startswith('0:'):
                    self.assertEqual('root', documented_user)
                elif user.startswith('${CHRONICLE_HOST_UID') or user == f'{SYNTHETIC["CHRONICLE_HOST_UID"]}:{SYNTHETIC["CHRONICLE_HOST_GID"]}':
                    self.assertEqual('operator', documented_user)
                else:
                    self.assertEqual(user, documented_user)


# Services whose thread count Go's runtime sets from GOMAXPROCS. Each sets it explicitly to its CPU
# ceiling, so a Go older than 1.25 (which ignores the cgroup CPU limit) still cannot scale with the host.
GO_SERVICES = {'web', 'web-forward', 'monitoring-forward', 'metrics-exporter', 'db-backup', 'grafana', 'cadvisor',
               'victoriametrics', 'victorialogs'}
ALL_OVERLAYS = ('overlays/backups.yml', 'overlays/monitoring.yml')


def cpu_ceiling(service):
    return service['cpu_quota'] / service['cpu_period']


def limits_table():
    """{service: (cpus, memory, pids, measured pids)} from README "Container limits"."""
    text = (SELFHOST / 'README.md').read_text()
    block = text[text.index('### Container limits'):].split('\n### ', 1)[0]
    rows = {}
    for line in block.splitlines():
        cells = [cell.strip(' `') for cell in line.strip().strip('|').split('|')]
        if len(cells) == 5 and re.fullmatch(r'[a-z][a-z-]*', cells[0]):
            rows[cells[0]] = tuple(cells[1:])
    return rows


class ResourceLimitTests(unittest.TestCase):
    """CI-R5, CI-R6, AF-S9, AF-S10: CPU ceilings, thread knobs that do not scale with host CPUs, and pid
    limits measured against both."""

    @classmethod
    def setUpClass(cls):
        cls.rendered = {mode: render(mode, *ALL_OVERLAYS) for mode in MODES}

    def test_every_service_has_a_cpu_ceiling_docker_accepts_on_any_host(self):
        # `cpus` above the host's CPU count is refused at container create ("range of CPUs is from
        # 0.01 to N"), which would stop a pilot host with 2 vCPUs; a CFS quota is accepted on any host.
        for mode, config in self.rendered.items():
            for name, service in config['services'].items():
                with self.subTest(mode=mode, service=name):
                    self.assertNotIn('cpus', service)
                    self.assertEqual(100000, service.get('cpu_period'))
                    self.assertGreaterEqual(service.get('cpu_quota', 0), 100000)
                    self.assertLessEqual(cpu_ceiling(service), 4)

    def test_go_services_run_no_more_threads_than_their_cpu_ceiling(self):
        config = self.rendered[MODES[0]]
        for name in GO_SERVICES:
            service = config['services'][name]
            with self.subTest(service=name):
                self.assertEqual(str(int(cpu_ceiling(service))), (service.get('environment') or {}).get('GOMAXPROCS'))

    def test_haproxy_runs_a_fixed_number_of_threads(self):
        config = (SELFHOST / 'monitoring/docker-api.cfg').read_text()
        threads = re.search(r'^\s*nbthread\s+(\d+)\s*$', config, re.M)
        self.assertIsNotNone(threads, 'without nbthread HAProxy starts one thread per host CPU')
        proxy = self.rendered[MODES[0]]['services']['docker-socket-proxy']
        self.assertLessEqual(int(threads.group(1)), 2)
        self.assertGreaterEqual(proxy['pids_limit'], 8 * int(threads.group(1)))

    def test_the_documented_limits_are_the_rendered_ones_and_the_measured_peak_fits(self):
        table = limits_table()
        config = self.rendered[MODES[0]]
        long_running = {name for name, service in config['services'].items() if service.get('restart') != 'no'}
        self.assertEqual(long_running, set(table))
        for name in long_running:
            service = config['services'][name]
            cpus, memory, pids, measured = table[name]
            with self.subTest(service=name):
                self.assertEqual(f'{cpu_ceiling(service):g}', cpus)
                self.assertEqual(str(service['pids_limit']), pids)
                self.assertLessEqual(int(measured) * 2, service['pids_limit'],
                                     'the pid limit keeps at least twice the measured peak')


ONE_SHOT_SCRIPTS = {'config-guard': 'guard-config.sh', 'cert-init': 'cert-init.sh', 'db-init': 'db-init.sh',
                    'restore': 'restore.sh', 'ca-export': 'ca-export.sh'}


def bundle_references(script):
    """Bundle files a one-shot script reads at /selfhost: its own name, what it sources beside itself,
    /selfhost/X paths and $RESTORE_SQL_DIR/X, following the scripts it sources."""
    seen, pending = set(), [script]
    while pending:
        name = pending.pop()
        if name in seen:
            continue
        seen.add(name)
        path = SELFHOST / name
        if not name.endswith('.sh') or not path.is_file():
            continue
        text = path.read_text()
        found = set(re.findall(r'\$\(dirname "\$\{BASH_SOURCE\[0\]\}"\)/([\w.-]+)', text))
        found |= set(re.findall(r'(?<![\w.])/selfhost/([\w.-]+)', text))
        found |= set(re.findall(r'\$RESTORE_SQL_DIR/([\w.-]+)', text))
        found |= set(re.findall(r'^\s*\. ([\w.-]+\.sh)\b', text, re.M))
        if 'PYTHONPATH=/selfhost' in text or 'PYTHONPATH="$(dirname "${BASH_SOURCE[0]}")"' in text:
            # chronicle_ops.dump falls back to .env.example for the release it stamps.
            found |= {'chronicle_ops', '.env.example'}
        pending.extend(found - seen)
    return seen


class OneShotMountTests(unittest.TestCase):
    """The one-shot jobs mount the bundle files they run, read-only, and never the directory that
    holds .env (or, with the default state directory, ./tls and ./backups)."""

    @classmethod
    def setUpClass(cls):
        cls.rendered = {mode: render(mode, *ALL_OVERLAYS) for mode in MODES}

    def binds(self, service):
        return [mount for mount in service.get('volumes') or [] if mount.get('type') == 'bind']

    def test_no_service_mounts_the_bundle_directory_that_holds_env(self):
        for mode, config in self.rendered.items():
            for name, service in config['services'].items():
                for mount in self.binds(service):
                    source = Path(mount['source'])
                    with self.subTest(mode=mode, service=name, source=str(source)):
                        self.assertNotEqual(SELFHOST, source, f'{name} mounts the bundle directory, and with it .env')
                        self.assertNotEqual('.env', source.name)

    def test_each_job_mounts_every_bundle_file_it_reads_read_only(self):
        for mode, config in self.rendered.items():
            for name, script in ONE_SHOT_SCRIPTS.items():
                if name not in config['services']:
                    continue  # ca-export exists in local-https mode only
                service = config['services'][name]
                mounted = {mount['target'].removeprefix('/selfhost/'): mount for mount in self.binds(service)
                           if mount['target'].startswith('/selfhost/')}
                for reference in sorted(bundle_references(script)):
                    with self.subTest(mode=mode, service=name, file=reference):
                        self.assertIn(reference, mounted)
                        self.assertTrue(mounted[reference].get('read_only'))
                        self.assertEqual(SELFHOST / reference, Path(mounted[reference]['source']))


class UnprivilegedRuntimeTests(unittest.TestCase):
    """CI-R1: cAdvisor ran as root with the host's / and /var/lib/docker mounted, so it could read every
    container's config.v2.json (the credential writers' environment included) and every volume."""

    @classmethod
    def setUpClass(cls):
        cls.rendered = {mode: render(mode, *ALL_OVERLAYS) for mode in MODES}

    def test_only_the_socket_proxy_runs_long_lived_as_root(self):
        for mode, config in self.rendered.items():
            root = {name for name, service in config['services'].items()
                    if service.get('restart') != 'no' and str(service.get('user', '')).split(':')[0] in ('0', 'root')}
            with self.subTest(mode=mode):
                self.assertEqual({'docker-socket-proxy'}, root)

    def test_cadvisor_mounts_no_container_configuration_volume_or_host_root(self):
        allowed = {('/sys', '/sys'), ('/proc', '/rootfs/proc'),
                   ('/var/lib/docker/image/overlay2/layerdb/mounts', '/rootfs/var/lib/docker/image/overlay2/layerdb/mounts'),
                   (str(SELFHOST / 'backups'), '/rootfs/chronicle-backups')}
        for mode, config in self.rendered.items():
            cadvisor = config['services']['cadvisor']
            mounts = {(mount['source'], mount['target']) for mount in cadvisor['volumes']}
            with self.subTest(mode=mode):
                self.assertEqual(allowed, mounts)
                self.assertTrue(all(mount.get('read_only') for mount in cadvisor['volumes']))
                self.assertNotIn(str(cadvisor.get('user', '0')).split(':')[0], ('0', 'root', ''))
                self.assertFalse(cadvisor.get('cap_add'))


class EgressAllowlistTests(unittest.TestCase):
    """CI-N2: egress-proxy's allowlist holds host:port of the public URLs and of an off-host HTTPS
    alert webhook, and nothing of a URL's path (which often carries the receiver's token)."""

    def allowlist(self, **settings):
        environment = {'PATH': os.environ['PATH'], **settings}
        result = subprocess.run(['bash', str(SELFHOST / 'monitoring/egress-allowlist.sh')], env=environment,
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(0, result.returncode, result.stderr)
        return result.stdout.split(), result.stderr

    def test_hosts_come_from_the_public_urls_and_an_off_host_webhook(self):
        for settings, expected in (
                ({'PUBLIC_TLS_URL': 'https://Chronicle.Example.org',
                  'CHRONICLE_ALERT_WEBHOOK_URL': 'https://hooks.example.net/services/T0/B0/token-value'},
                 ['chronicle.example.org:443', 'hooks.example.net:443']),
                ({'PUBLIC_TLS_URL': 'https://192.168.1.20:8443', 'PUBLIC_HEALTH_URL': 'https://192.168.1.20:8443/health',
                  'CHRONICLE_ALERT_WEBHOOK_URL': 'http://127.0.0.1:9/dashboard-only'}, ['192.168.1.20:8443']),
                ({'PUBLIC_TLS_URL': 'https://[2001:DB8::5]', 'PUBLIC_HEALTH_URL': 'https://status.example.org:9443/x'},
                 ['[2001:db8::5]:443', 'status.example.org:9443']),
                ({'PUBLIC_TLS_URL': 'https://chronicle.example.org',
                  'CHRONICLE_ALERT_WEBHOOK_URL': 'https://localhost:9093/relay'}, ['chronicle.example.org:443'])):
            with self.subTest(settings=settings):
                hosts, _ = self.allowlist(**settings)
                self.assertEqual(expected, hosts)
                self.assertFalse([host for host in hosts if '/' in host or 'token' in host])

    def test_a_plain_http_off_host_webhook_is_left_out_and_reported_without_its_url(self):
        hosts, warning = self.allowlist(PUBLIC_TLS_URL='https://chronicle.example.org',
                                        CHRONICLE_ALERT_WEBHOOK_URL='http://alerts.example.org/hook/secret-token')
        self.assertEqual(['chronicle.example.org:443'], hosts)
        self.assertIn('alert webhook is not HTTPS', warning)
        self.assertNotIn('secret-token', warning)
        hosts, warning = self.allowlist(CHRONICLE_ALERT_WEBHOOK_URL='https://user:pw@alerts.example.org/hook')
        self.assertEqual([], hosts)
        self.assertNotIn('pw@', warning)


if __name__ == '__main__':
    unittest.main()
