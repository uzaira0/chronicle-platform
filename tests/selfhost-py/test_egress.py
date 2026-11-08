"""Containers cannot send data out: the rendered Compose networks, and the settings that choose them."""
import importlib.util
import ipaddress
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SELFHOST = ROOT / 'selfhost'
sys.path.insert(0, str(SELFHOST))

from chronicle_ops import egress  # noqa: E402
from chronicle_ops.services import EDGE_SERVICES, INTERNAL_NETWORKS, SECRET_WRITERS  # noqa: E402

MODES = ('overlays/mode-behind-proxy-internal.yml', 'overlays/mode-own-tls-internal.yml', 'overlays/mode-local-https.yml')
PIN = '@sha256:' + 'a' * 64
SYNTHETIC = {
    'POSTGRES_IMAGE': 'fixture/postgres' + PIN, 'BACKEND_IMAGE': 'fixture/backend' + PIN,
    'CADDY_IMAGE': 'fixture/caddy' + PIN, 'SELFHOST_FRONTEND_IMAGE': 'fixture/frontend' + PIN,
    'BACKUP_IMAGE': 'fixture/backup' + PIN, 'GRAFANA_IMAGE': 'fixture/grafana' + PIN,
    'FLUENT_BIT_IMAGE': 'fixture/fluent-bit' + PIN,
    'POSTGRES_PASSWORD': 'p' * 32, 'POSTGRES_APP_PASSWORD': 'q' * 32, 'JWT_SECRET': 'j' * 32,
    'METRICS_PASSWORD': 'm' * 32, 'CHRONICLE_INTERNAL_WEB_SECRET': 'w' * 32, 'GRAFANA_ADMIN_PASSWORD': 'g' * 32,
    'CHRONICLE_REVIEWER_ACCESS_SECRET': 'r' * 32, 'JWT_SECRET_PREVIOUS': 'k' * 32,
    'DOMAIN': 'chronicle.example.org', 'CHRONICLE_HOST_UID': '1000', 'CHRONICLE_HOST_GID': '1000',
    'BACKUP_KEEP_DAYS': '7', 'BACKUP_KEEP_WEEKS': '4', 'BACKUP_KEEP_MONTHS': '6', 'PRE_OP_BACKUP_KEEP_DAYS': '7',
    'CHRONICLE_CORE_PREFIX': '10.252.9',
}
# The only services that may sit on a network Docker connects to the host (chronicle_ops/services.py).
EDGE = set(EDGE_SERVICES)


def render(mode, *overlays, **settings):
    """`docker compose config` of the shipped files with synthetic settings, as JSON."""
    files = ['docker-compose.yml', mode, *overlays]
    environment = {key: value for key, value in os.environ.items() if not key.startswith('COMPOSE_')}
    environment.update(SYNTHETIC, **settings)
    with tempfile.TemporaryDirectory() as folder:
        empty = Path(folder) / 'empty.env'
        empty.write_text('')
        result = subprocess.run(['docker', 'compose', '--env-file', str(empty), '--project-directory', str(SELFHOST),
                                 '-p', 'egress-fixture', '--profile', 'restore',
                                 *[part for name in files for part in ('-f', str(SELFHOST / name))],
                                 'config', '--format', 'json'], env=environment, capture_output=True, text=True, timeout=60)
    if result.returncode:
        raise AssertionError(result.stderr)
    return json.loads(result.stdout)


def members(config, network):
    return {name for name, service in config['services'].items() if network in (service.get('networks') or {})}


def outside(config):
    """Networks a container on which can reach beyond the host's bridges."""
    return {name for name, network in config['networks'].items() if not network.get('internal')}


def masquerading(config, network):
    options = config['networks'][network].get('driver_opts') or {}
    return options.get('com.docker.network.bridge.enable_ip_masquerade', 'true') != 'false'


class NetworkDesignTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rendered = {mode: render(mode, 'overlays/backups.yml', 'overlays/monitoring.yml') for mode in MODES}
        cls.alerting = render(MODES[0], 'overlays/backups.yml', 'overlays/monitoring.yml',
                              CHRONICLE_ALERT_EGRESS=egress.OPEN)

    def test_default_network_carries_only_the_port_forwarder(self):
        for mode, config in self.rendered.items():
            with self.subTest(mode=mode):
                self.assertEqual({'web-forward'}, members(config, 'default'))
                self.assertEqual({'monitoring-forward'}, members(config, 'monitoring-ports'))
                self.assertFalse(masquerading(config, 'default'), 'web-forward publishes ports but must not reach out')
                self.assertEqual('${CHRONICLE_SUBNET:-172.28.0.0/16}'.split(':-')[1].rstrip('}'),
                                 config['networks']['default']['ipam']['config'][0]['subnet'])

    def test_data_path_runs_on_the_internal_core_network(self):
        for mode, config in self.rendered.items():
            with self.subTest(mode=mode):
                self.assertTrue(config['networks']['core'].get('internal'))
                for service in ('backend', 'postgres', 'migrate', 'db-init', 'restore', 'db-backup'):
                    self.assertIn('database', config['services'][service]['networks'], service)
                    self.assertFalse(set(config['services'][service]['networks']) & outside(config), service)
                for service in ('config-guard', 'cert-init', 'caddy-storage-init', 'monitoring-cert-init'):
                    self.assertEqual('none', config['services'][service].get('network_mode'), service)

    def test_backend_trusts_forwarded_addresses_only_from_web(self):
        for mode, config in self.rendered.items():
            with self.subTest(mode=mode):
                [ipam] = config['networks']['core']['ipam']['config']
                web = config['services']['web']['networks']['core']['ipv4_address']
                self.assertEqual('10.252.9.0/25', ipam['subnet'])
                self.assertIn(ipaddress.ip_address(web), ipaddress.ip_network(ipam['subnet']))
                # Docker hands out dynamic addresses only from ip_range, so nothing else can take web's.
                self.assertNotIn(ipaddress.ip_address(web), ipaddress.ip_network(ipam['ip_range']))
                self.assertEqual(web + '/32', config['services']['backend']['environment']['CHRONICLE_TRUSTED_PROXY_CIDRS'])
                guard = config['services']['config-guard']['environment']
                self.assertNotIn('CHRONICLE_TRUSTED_PROXY_CIDRS', guard)  # the guard checks the prefix only
                self.assertEqual('10.252.9', guard['CHRONICLE_CORE_PREFIX'])

    def test_compose_renders_exactly_the_layout_network_subnet_derives(self):
        # network-subnet.py owns every range and fixed address derived from CHRONICLE_CORE_PREFIX;
        # docker-compose.yml interpolates the prefix because Compose cannot run it.
        from chronicle_ops.common import network_subnet
        module = network_subnet(SELFHOST)
        layout = module.core_layout(SYNTHETIC['CHRONICLE_CORE_PREFIX'])
        selected = ipaddress.ip_network(SYNTHETIC['CHRONICLE_CORE_PREFIX'] + '.0/24')
        for mode, config in self.rendered.items():
            with self.subTest(mode=mode):
                for name, wanted in layout['networks'].items():
                    [ipam] = config['networks'][name]['ipam']['config']
                    self.assertEqual(wanted, {'subnet': ipam['subnet'], 'ip_range': ipam['ip_range']})
                    # select-core's overlap check and the update's fallback both cover the /24.
                    self.assertTrue(ipaddress.ip_network(ipam['subnet']).subnet_of(selected))
                for service, (network, address) in layout['addresses'].items():
                    self.assertEqual(address, config['services'][service]['networks'][network]['ipv4_address'])
                    self.assertNotIn(ipaddress.ip_address(address),
                                     ipaddress.ip_network(layout['networks'][network]['ip_range']))
                derived = module.derived_subnets(SYNTHETIC['CHRONICLE_CORE_PREFIX'])
                self.assertLessEqual(set(layout['networks']), set(derived))
                for name, (subnet, ip_range) in derived.items():
                    [ipam] = config['networks'][name]['ipam']['config']
                    self.assertEqual((subnet, ip_range), (ipam['subnet'], ipam['ip_range']))
                    self.assertTrue(ipaddress.ip_network(subnet).subnet_of(selected))
                self.assertEqual(set(derived) | {'default'}, set(module.OWN_NETWORKS))
                self.assertEqual({name: 'CHRONICLE_CORE_PREFIX' for name in layout['networks']},
                                 {name: module.SUBNET_SETTINGS[name] for name in layout['networks']})

    def test_caddy_takes_proxy_headers_only_from_the_forwarders_fixed_address(self):
        for mode, config in self.rendered.items():
            with self.subTest(mode=mode):
                [ingress] = config['networks']['ingress']['ipam']['config']
                [core] = config['networks']['core']['ipam']['config']
                forwarder = config['services']['web-forward']['networks']['ingress']['ipv4_address']
                self.assertEqual('10.252.9.128/26', ingress['subnet'])
                self.assertFalse(ipaddress.ip_network(ingress['subnet']).overlaps(ipaddress.ip_network(core['subnet'])))
                self.assertIn(ipaddress.ip_address(forwarder), ipaddress.ip_network(ingress['subnet']))
                self.assertNotIn(ipaddress.ip_address(forwarder), ipaddress.ip_network(ingress['ip_range']))
                self.assertEqual(forwarder, config['services']['web']['environment']['CHRONICLE_INGRESS_FORWARDER'])
                self.assertEqual({'web', 'web-forward'}, members(config, 'ingress'))
        for name in ('Caddyfile.split', 'Caddyfile.split.tls', 'Caddyfile.split.local'):
            self.assertIn('allow {$CHRONICLE_INGRESS_FORWARDER}/32', (SELFHOST / name).read_text(), name)

    def test_only_the_forwarders_publish_ports_and_they_hold_nothing(self):
        for mode, config in self.rendered.items():
            with self.subTest(mode=mode):
                publishing = {name for name, service in config['services'].items() if service.get('ports')}
                self.assertEqual({'web-forward', 'monitoring-forward'}, publishing)
                for name in publishing:
                    service = config['services'][name]
                    self.assertEqual(['/usr/bin/chronicle-forward'], service['entrypoint'])
                    self.assertEqual(config['services']['web']['image'], service['image'])  # CADDY_IMAGE
                    self.assertFalse(service.get('volumes'), name)
                    self.assertEqual({'GOMAXPROCS': '2'}, service.get('environment'))
                    self.assertEqual([egress.BLACKHOLE_RESOLVER], service.get('dns'))
                    self.assertEqual(['ALL'], service['cap_drop'])
                    self.assertNotIn('cap_add', service)
                    self.assertTrue(service['read_only'])
                    for route in service['command']:
                        self.assertNotIn(':', route.split('=')[0], route)

    def test_only_edge_services_join_a_network_that_reaches_the_host(self):
        for config in (*self.rendered.values(), self.alerting):
            for name, service in config['services'].items():
                if set(service.get('networks') or {}) & outside(config):
                    self.assertIn(name, EDGE, name)

    def test_no_container_with_data_or_credentials_can_reach_out(self):
        for mode, config in (*self.rendered.items(), ('alerts-open', self.alerting)):
            with self.subTest(mode=mode):
                # Only the allowlisting proxy reaches the internet; it holds nothing but its allowlist.
                self.assertEqual({'egress-proxy'}, members(config, 'egress'))
                for name in ('web', 'grafana', 'fluent-bit', 'public-probe'):
                    networks = set(config['services'][name]['networks'])
                    self.assertFalse(networks - set(INTERNAL_NETWORKS), (mode, name))
                for network in outside(config) - {'egress'}:
                    self.assertFalse(masquerading(config, network), network)
                    for name in members(config, network):
                        # The embedded resolver would otherwise forward external names: DNS is a channel too.
                        self.assertEqual([egress.BLACKHOLE_RESOLVER], config['services'][name].get('dns'), name)
                probe = config['services']['public-probe']
                self.assertEqual({'egress-clients'}, set(probe['networks']))
                self.assertEqual([egress.BLACKHOLE_RESOLVER], probe.get('dns'))
                self.assertEqual('http://egress-proxy:3128', probe['environment']['HTTPS_PROXY'])
                self.assertFalse([key for key in probe.get('environment') or {} if 'PASSWORD' in key or 'SECRET' in key])
                sources = {volume.get('source', '') for volume in probe.get('volumes') or []}
                self.assertFalse([source for source in sources if source.endswith('/tls') or 'postgres' in source], sources)

    def test_the_egress_proxy_holds_only_its_allowlist(self):
        for mode, config in self.rendered.items():
            proxy = config['services']['egress-proxy']
            with self.subTest(mode=mode):
                self.assertEqual({'egress', 'egress-clients'}, set(proxy['networks']))
                self.assertEqual(['/usr/bin/chronicle-forward'], proxy['entrypoint'])
                self.assertEqual(config['services']['web']['image'], proxy['image'])  # CADDY_IMAGE
                self.assertIn('-connect', proxy['command'])
                self.assertEqual([('egress_allowlist', '/egress', True)],
                                 [(mount['source'], mount['target'], mount.get('read_only', False))
                                  for mount in proxy['volumes']])
                self.assertFalse([key for key in proxy.get('environment') or {} if key != 'GOMAXPROCS'])
                self.assertEqual(['ALL'], proxy['cap_drop'])
                self.assertNotIn('cap_add', proxy)
                self.assertTrue(proxy['read_only'])
                self.assertNotIn(str(proxy.get('user', '0')).split(':')[0], ('0', 'root', ''))
                self.assertTrue(config['networks']['egress-clients'].get('internal'))
                self.assertEqual({'egress-proxy', 'public-probe'}, members(config, 'egress-clients'))

    def test_monitoring_is_internal_and_the_database_probe_has_no_way_out(self):
        for config in self.rendered.values():
            self.assertTrue(config['networks']['monitoring'].get('internal'))
            self.assertTrue(config['networks']['docker-api'].get('internal'))
            operational = set(config['services']['operational-probe']['networks'])
            self.assertEqual({'monitoring', 'database-probe'}, operational)

    def test_grafana_reaches_out_only_when_the_alert_webhook_is_outside_the_host(self):
        closed = self.rendered[MODES[0]]['services']['grafana']
        self.assertNotIn('egress-clients', closed['networks'])
        self.assertNotIn('HTTPS_PROXY', closed['environment'])
        self.assertEqual([egress.BLACKHOLE_RESOLVER], closed.get('dns'))
        opened = self.alerting['services']['grafana']
        self.assertIn('egress-clients', opened['networks'])
        self.assertNotIn('egress', opened['networks'])
        self.assertEqual([egress.BLACKHOLE_RESOLVER], opened.get('dns'))
        self.assertEqual('http://egress-proxy:3128', opened['environment']['HTTPS_PROXY'])
        # Its own healthcheck (curl to https://127.0.0.1:3000) and data sources never use the proxy.
        for local in ('127.0.0.1', 'localhost', 'victoriametrics', 'victorialogs'):
            self.assertIn(local, opened['environment']['NO_PROXY'].split(','))
            self.assertIn(local, opened['environment']['no_proxy'].split(','))
        self.assertEqual({'egress-proxy', 'public-probe', 'grafana'}, members(self.alerting, 'egress-clients'))
        for config in (self.rendered[MODES[0]], self.alerting):
            self.assertFalse(config['services']['grafana'].get('ports'))
            ports = config['services']['monitoring-forward']['ports']
            self.assertIn(('127.0.0.1', '3000', 3000), [(port['host_ip'], port['published'], port['target']) for port in ports])
            self.assertIn('3000=grafana:3000', config['services']['monitoring-forward']['command'])

    def test_grafana_does_not_call_grafana_com(self):
        environment = self.rendered[MODES[0]]['services']['grafana']['environment']
        self.assertEqual('true', environment['GF_PLUGINS_PREINSTALL_DISABLED'])
        self.assertEqual('false', environment['GF_NEWS_NEWS_FEED_ENABLED'])

    def test_the_log_port_stays_on_loopback_through_the_monitoring_forwarder(self):
        config = self.rendered[MODES[0]]
        forward = config['services']['monitoring-forward']
        self.assertIn(('127.0.0.1', '24224', 24224),
                      [(port['host_ip'], port['published'], port['target']) for port in forward['ports']])
        self.assertIn('24224=fluent-bit:24224', forward['command'])
        self.assertFalse(config['services']['fluent-bit'].get('ports'))
        self.assertEqual({'monitoring', 'monitoring-ingress'}, set(config['services']['fluent-bit']['networks']))

    def test_web_has_no_route_out_in_any_mode_and_staples_no_ocsp(self):
        """web holds the participant TLS key and sees decrypted traffic, so no mode gives it a route
        out; with none, Caddy could not fetch an OCSP response. The real Caddy parser:
        test_egress_runtime.py."""
        for mode, name in zip(MODES, ('Caddyfile.split', 'Caddyfile.split.tls', 'Caddyfile.split.local')):
            text = (SELFHOST / name).read_text()
            start = text.index('\n{\n')
            options = text[start:text.index('\n}\n', start)]
            web = self.rendered[mode]['services']['web']
            with self.subTest(mode=mode):
                self.assertIn('\tocsp_stapling off', options)
                self.assertFalse(set(web['networks']) - set(INTERNAL_NETWORKS))
                self.assertEqual([egress.BLACKHOLE_RESOLVER], web.get('dns'))

    def test_the_database_is_reachable_only_from_its_users(self):
        """CI-N5: web (Caddy, the TLS edge) shared core with PostgreSQL and could open postgres:5432."""
        users = {'postgres', 'backend', 'db-backup', 'db-init', 'migrate', 'restore'}
        for mode, config in self.rendered.items():
            with self.subTest(mode=mode):
                self.assertTrue(config['networks']['database'].get('internal'))
                self.assertEqual(users, members(config, 'database'))
                [ipam] = config['networks']['database']['ipam']['config']
                subnet, ip_range = load_subnet_helper().derived_subnets(SYNTHETIC['CHRONICLE_CORE_PREFIX'])['database']
                self.assertEqual((subnet, ip_range), (ipam['subnet'], ipam['ip_range']))
                self.assertEqual({'database', 'database-probe'}, set(config['services']['postgres']['networks']))
                self.assertEqual({'web', 'backend'}, members(config, 'core'))
                self.assertEqual({'postgres', 'operational-probe'}, members(config, 'database-probe'))
                shared = {network for network in config['services']['web']['networks']
                          if 'postgres' in members(config, network)}
                self.assertFalse(shared, 'web shares a network with PostgreSQL')


class StaticContractTests(unittest.TestCase):
    def test_verify_config_refuses_core_or_monitoring_networks_with_a_way_out(self):
        from chronicle_ops.verify import service_contract_violations
        self.assertEqual('', service_contract_violations([str(SELFHOST / 'docker-compose.yml'),
                                                         str(SELFHOST / 'overlays/monitoring.yml')]))
        with tempfile.TemporaryDirectory() as folder:
            for network in INTERNAL_NETWORKS:
                path = Path(folder) / f'{network}.yml'
                path.write_text(f'services: {{}}\nnetworks:\n  {network}: {{}}\n')
                self.assertIn(f'the {network} network is not internal', service_contract_violations([str(path)]))

    def test_verify_refuses_a_non_edge_service_that_can_resolve_external_names(self):
        """Internal networks stop forwarding DNS only from Engine 25.0.5; the blackhole resolver
        closes the channel on every engine, so verify requires it on every non-edge service."""
        from chronicle_ops.verify import service_contract_violations
        import yaml
        service = {'image': 'fixture', 'networks': ['core'], 'logging': {}, 'read_only': True, 'cap_drop': ['ALL'],
                   'security_opt': ['no-new-privileges:true'], 'pids_limit': 64, 'mem_limit': '64m'}
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'docker-compose.yml'
            for dns, accepted in ((None, False), (['1.1.1.1'], False), ([egress.BLACKHOLE_RESOLVER, '1.1.1.1'], False),
                                  ([egress.BLACKHOLE_RESOLVER], True)):
                with self.subTest(dns=dns):
                    definition = dict(service, **({'dns': dns} if dns is not None else {}))
                    path.write_text(yaml.safe_dump({'services': {'queue': definition},
                                                    'networks': {'core': {'internal': True}}}))
                    violations = service_contract_violations([str(path)])
                    self.assertEqual(accepted, 'queue has a network but not dns' not in violations, violations)
            # An edge service resolves names normally (egress-proxy resolves the allowlisted hosts).
            path.write_text(yaml.safe_dump({'services': {'egress-proxy': dict(service, networks=['egress'])}}))
            self.assertNotIn('dns', service_contract_violations([str(path)]))

    def test_verify_refuses_a_service_outside_the_edge_list_on_an_outbound_network(self):
        from chronicle_ops.verify import service_contract_violations
        import yaml
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'monitoring.yml'
            path.write_text(yaml.safe_dump({'services': {'victorialogs': {'networks': ['monitoring', 'egress']}}}))
            self.assertIn('victorialogs joins egress, which can reach beyond the host', service_contract_violations([str(path)]))

    def test_the_conftest_policy_reads_the_lists_generated_from_services_py(self):
        generator = ROOT / 'scripts/generate-egress-rego.py'
        result = subprocess.run([sys.executable, str(generator), '--check'], capture_output=True, text=True, timeout=60)
        self.assertEqual(0, result.returncode, result.stderr)
        policy = (ROOT / 'tests/security/policies/docker_compose.rego').read_text()
        self.assertNotIn('internal_network_names :=', policy)
        self.assertNotIn('edge_service_reasons := {', policy)
        from chronicle_ops.services import rego_module
        with patch.dict(EDGE_SERVICES, {'smtp-relay': 'fixture'}):
            self.assertIn('"smtp-relay": "fixture"', rego_module())


class RenderedNetworkContractTests(unittest.TestCase):
    """The contract on what Compose actually runs, in every mode, with and without alert egress."""

    @classmethod
    def setUpClass(cls):
        cls.rendered = {(mode, alerts): render(mode, 'overlays/backups.yml', 'overlays/monitoring.yml',
                                               CHRONICLE_ALERT_EGRESS=alerts)
                        for mode in MODES for alerts in (egress.CLOSED, egress.OPEN)}

    def test_every_service_with_only_internal_networks_resolves_no_external_name(self):
        for (mode, alerts), config in self.rendered.items():
            for name, service in config['services'].items():
                networks = set(service.get('networks') or {})
                if service.get('network_mode') == 'none' or (networks - set(INTERNAL_NETWORKS)):
                    continue
                with self.subTest(mode=mode, alerts=alerts, service=name):
                    self.assertTrue(networks, name)
                    self.assertEqual([egress.BLACKHOLE_RESOLVER], service.get('dns'))

    def test_internal_networks_are_internal_and_outbound_ones_hold_only_edges(self):
        for (mode, alerts), config in self.rendered.items():
            with self.subTest(mode=mode, alerts=alerts):
                for name in INTERNAL_NETWORKS:
                    self.assertTrue(config['networks'][name].get('internal'), name)
                for name, service in config['services'].items():
                    if set(service.get('networks') or {}) & outside(config):
                        self.assertIn(name, EDGE_SERVICES)


class ProxyRuleTests(unittest.TestCase):
    def test_the_ast_grep_proxy_rule_exempts_exactly_the_files_verify_config_lets_use_the_proxy(self):
        """config_inventory.PROXY_USERS (verify-config.sh) and the ast-grep rule must agree: the
        destination probe in egress.py honours HTTPS_PROXY like the release fetcher, and the rule
        flagged it, so the engineering gate was red on a correct file."""
        import re

        from chronicle_ops.config_inventory import PROXY_USERS
        rule = (ROOT / 'tests/security/ast-grep/selfhost-curl-ignores-proxy-environment.yml').read_text()
        ignores = set(re.findall(r'^  - selfhost/(\S+)$', rule.split('ignores:', 1)[1].split('rule:', 1)[0], re.MULTILINE))
        self.assertEqual(set(PROXY_USERS), ignores)


class AlertEgressTests(unittest.TestCase):
    def test_a_webhook_off_this_host_opens_grafana_egress(self):
        for url, wanted in (('', egress.CLOSED), ('http://127.0.0.1:9/dashboard-only', egress.CLOSED),
                            ('http://localhost:9000/hook', egress.CLOSED), ('http://[::1]:9/x', egress.CLOSED),
                            ('https://hooks.slack.com/services/T/B/x', egress.OPEN),
                            ('http://192.168.1.20:8065/hooks/x', egress.OPEN), ('http://alerts:8080/x', egress.OPEN),
                            ("'not a url'", egress.CLOSED)):
            with self.subTest(url=url):
                self.assertEqual(wanted, egress.alert_egress({'CHRONICLE_ALERT_WEBHOOK_URL': url}))
        self.assertEqual(egress.CLOSED, egress.alert_egress({}))
        self.assertEqual(egress.OPEN, egress.alert_egress({'CHRONICLE_ALERT_WEBHOOK_URL': "'https://example.org/h'"}))

    def test_release_compose_commands_carry_the_choice(self):
        from chronicle_ops.release import release_command
        with tempfile.TemporaryDirectory() as folder:
            directory = Path(folder)
            (directory / 'docker-compose.yml').write_text('services: {}\n')
            for url, wanted in (('https://hooks.example.org/x', egress.OPEN), ('', egress.CLOSED)):
                (directory / '.env').write_text(f'CHRONICLE_ALERT_WEBHOOK_URL={url}\n')
                with patch.dict(os.environ, {egress.ALERT_EGRESS_ENV: 'stale'}):
                    _, environment = release_command(directory, 'fixture', ['docker-compose.yml'])
                self.assertEqual(wanted, environment[egress.ALERT_EGRESS_ENV])

    def test_the_launcher_exports_the_choice_for_every_compose_call(self):
        launcher = (SELFHOST / 'chronicle').read_text()
        need_env = launcher[launcher.index('need_env() {'):launcher.index('\nderive_mode() {')]
        self.assertIn('export ' + egress.ALERT_EGRESS_ENV, need_env)
        # After the credentials leave the environment; Python reads the URL (it may hold a token)
        # from .env itself and brings .env's derived copy in line.
        self.assertLess(need_env.index('export -n'), need_env.index('sync_env_file'))
        self.assertIn('sync_env_file(".env")', need_env)
        self.assertNotIn('CHRONICLE_ALERT_WEBHOOK_URL:-}" |', need_env)

    def test_an_unreadable_env_file_leaves_grafana_closed_with_a_warning(self):
        with tempfile.TemporaryDirectory() as folder:
            env = Path(folder) / '.env'
            env.write_text('CHRONICLE_ALERT_WEBHOOK_URL=https://hooks.example.org/x\nnot an assignment\n')
            errors = io.StringIO()
            with patch('sys.stderr', errors):
                self.assertEqual(egress.CLOSED, egress.environment_alert_egress(env))
            self.assertIn('alerts stay in the dashboard', errors.getvalue())
        self.assertEqual(egress.OPEN, egress.alert_egress_for_url('https://hooks.example.org/x'))
        self.assertEqual(egress.CLOSED, egress.alert_egress_for_url(''))


def load_subnet_helper():
    spec = importlib.util.spec_from_file_location('egress_subnet', SELFHOST / 'network-subnet.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class CoreSubnetTests(unittest.TestCase):
    def setUp(self):
        self.helper = load_subnet_helper()

    def select(self, existing, routes=(), subnet='172.28.0.0/16'):
        with patch.object(self.helper, 'docker_networks', return_value=list(existing)), \
             patch.object(self.helper, 'host_networks', return_value=list(routes)), \
             patch('sys.stdout', new_callable=io.StringIO) as output:
            self.helper.select_core(subnet, 'fixture')
        return output.getvalue().strip()

    def test_core_prefix_avoids_docker_networks_routes_and_the_edge_subnet(self):
        taken = [{'Name': 'lab', 'IPAM': {'Config': [{'Subnet': '10.252.0.0/24'}]}}]
        self.assertEqual('10.252.1', self.select(taken))
        self.assertEqual('10.252.2', self.select(taken, [{'Name': 'vpn', 'IPAM': {'Config': [{'Subnet': '10.252.1.0/24'}]}}]))
        self.assertEqual('10.252.1', self.select(taken, subnet='10.252.0.0/24'))
        own = {'Name': 'fixture_core', 'Labels': {'com.docker.compose.project': 'fixture', 'com.docker.compose.network': 'core'},
               'IPAM': {'Config': [{'Subnet': '10.252.0.0/24'}]}}
        self.assertEqual('10.252.0', self.select([own]))

    def test_subnet_check_covers_every_ipam_network_of_the_project(self):
        config = {'name': 'fixture', 'networks': {
            'default': {'ipam': {'config': [{'subnet': '10.40.0.0/24'}]}},
            'core': {'internal': True, 'ipam': {'config': [{'subnet': '10.252.5.0/24', 'ip_range': '10.252.5.128/25'}]}}}}
        existing = [{'Name': 'lab', 'IPAM': {'Config': [{'Subnet': '10.252.5.0/24'}]}},
                    {'Name': 'fixture_core', 'Labels': {'com.docker.compose.project': 'fixture', 'com.docker.compose.network': 'core'},
                     'IPAM': {'Config': [{'Subnet': '10.252.5.0/24'}]}}]
        with patch.object(self.helper, 'docker_networks', return_value=existing), \
             patch.object(self.helper, 'host_networks', return_value=[]), \
             patch('sys.stdin', io.StringIO(json.dumps(config))), patch('sys.stderr', new_callable=io.StringIO) as errors:
            self.helper.check()
        self.assertIn('10.252.5.0/24 overlaps Docker network lab', errors.getvalue())
        self.assertNotIn('fixture_core', errors.getvalue())


class CorePrefixMigrationTests(unittest.TestCase):
    def test_update_selects_a_core_prefix_for_a_release_that_had_none(self):
        from chronicle_ops.env_migration import migrate_settings
        old = {'POSTGRES_PASSWORD': 'p', 'POSTGRES_APP_PASSWORD': 'q', 'JWT_SECRET': 'j' * 32, 'METRICS_PASSWORD': 'm' * 32,
               'CHRONICLE_INTERNAL_WEB_SECRET': 'w' * 32, 'GRAFANA_ADMIN_PASSWORD': 'g' * 32, 'CHRONICLE_SUBNET': '10.40.0.0/24'}
        asked = []
        settings, notes = migrate_settings(old, lambda password: password,
                                           select_core=lambda subnet: asked.append(subnet) or '10.252.3')
        self.assertEqual('10.252.3', settings['CHRONICLE_CORE_PREFIX'])
        self.assertEqual(['10.40.0.0/24'], asked)
        self.assertTrue(any('CHRONICLE_CORE_PREFIX' in note for note in notes))
        kept, _ = migrate_settings(dict(old, CHRONICLE_CORE_PREFIX='10.252.7'), lambda password: password,
                                   select_core=lambda subnet: self.fail('an existing prefix is never moved'))
        self.assertEqual('10.252.7', kept['CHRONICLE_CORE_PREFIX'])

    def test_guard_accepts_only_a_private_core_prefix(self):
        # web's address and the trusted CIDR are derived from the prefix by Compose; ./chronicle
        # verify compares them with the live network (test_verify.CoreNetworkTests).
        guard = SELFHOST / 'guard-config.sh'
        for prefix, accepted in (('10.252.9', True), ('192.168.40', True), ('172.20.1', True), ('8.8.8', False),
                                 ('10.252', False), ('10.252.09', False), ('', False)):
            with self.subTest(prefix=prefix):
                result = subprocess.run(['bash', str(guard), '--validate-core-prefix', prefix],
                                        capture_output=True, timeout=10, check=False)
                self.assertEqual(0 if accepted else 1, result.returncode, result.stderr)


SECRET_SETTINGS = ('POSTGRES_PASSWORD', 'POSTGRES_APP_PASSWORD', 'JWT_SECRET', 'JWT_SECRET_PREVIOUS', 'METRICS_PASSWORD',
                   'CHRONICLE_INTERNAL_WEB_SECRET', 'CHRONICLE_REVIEWER_ACCESS_SECRET', 'GRAFANA_ADMIN_PASSWORD')
# No long-running service: web's entrypoint reads its one value from secrets-init's file into
# Caddy's process environment, which `docker inspect` does not show.
SECRET_IN_ENVIRONMENT = set()
CREDENTIAL_VOLUMES = {
    'postgres_secrets': {'secrets-init', 'postgres'},
    'backend_secrets': {'secrets-init', 'backend'},
    'operator_secrets': {'secrets-init', 'db-backup', 'operational-probe', 'restore'},
    'database_init_secrets': {'secrets-init', 'db-init'},
    'migrate_secrets': {'secrets-init', 'migrate'},
    'guard_secrets': {'secrets-init', 'config-guard'},
    'grafana_secrets': {'monitoring-config', 'grafana'},
    'web_secrets': {'secrets-init', 'web'},
}


def secrets_init_writes(text):
    """{(directory, file name)} that secrets-init.sh writes."""
    import re
    return set(re.findall(r'^write /out/([\w-]+) \S+ ([a-z-]+) ', text, re.M))


class SecretFileTests(unittest.TestCase):
    """Long-running containers read credentials from files; `docker inspect` of them shows none."""

    @classmethod
    def setUpClass(cls):
        cls.rendered = {mode: render(mode, 'overlays/backups.yml', 'overlays/monitoring.yml') for mode in MODES}

    def test_long_running_services_carry_no_secret_in_their_configuration(self):
        values = {SYNTHETIC[key]: key for key in SECRET_SETTINGS}
        for mode, config in self.rendered.items():
            for name, service in config['services'].items():
                if service.get('restart') == 'no':
                    continue  # one-shot jobs exit; the socket proxy hides their Env (docker-api.cfg)
                leaked = {(name, key) for key, value in (service.get('environment') or {}).items() if value in values}
                with self.subTest(mode=mode, service=name):
                    self.assertLessEqual(leaked, SECRET_IN_ENVIRONMENT)

    def test_only_the_secret_writers_hold_a_secret_in_their_configuration(self):
        # One-shot jobs included: config-guard, db-init, migrate and restore read files too, so
        # `docker inspect` of any container but these two (and web's one Caddy value) shows none.
        values = {SYNTHETIC[key]: key for key in SECRET_SETTINGS}
        for mode, config in self.rendered.items():
            for name, service in config['services'].items():
                environment = service.get('environment') or {}
                leaked = {(name, key) for key, value in environment.items() if value in values}
                with self.subTest(mode=mode, service=name):
                    if name in SECRET_WRITERS:
                        self.assertEqual('none', service.get('network_mode'))
                    else:
                        self.assertLessEqual(leaked, SECRET_IN_ENVIRONMENT)
        self.assertEqual({'secrets-init', 'monitoring-config'}, set(SECRET_WRITERS))

    def test_the_guard_checks_what_secrets_init_wrote(self):
        config = self.rendered[MODES[0]]
        self.assertEqual('service_completed_successfully',
                         config['services']['config-guard']['depends_on']['secrets-init']['condition'])
        self.assertNotIn('config-guard', config['services']['secrets-init'].get('depends_on') or {})
        writes = secrets_init_writes((SELFHOST / 'secrets-init.sh').read_text())
        import re
        for script, directory in (('guard-config.sh', 'guard'), ('db-init.sh', 'database-init'), ('restore.sh', 'operator')):
            text = (SELFHOST / script).read_text()
            loaded = set(re.findall(r'[A-Z_][A-Z0-9_]*:([a-z][a-z-]*)', text[text.index('load_secret_files "'):].split('\n\n', 1)[0]))
            with self.subTest(script=script):
                self.assertTrue(loaded)
                self.assertLessEqual({(directory, name) for name in loaded}, writes)

    def test_each_credential_volume_reaches_only_its_consumers(self):
        for mode, config in self.rendered.items():
            for volume, consumers in CREDENTIAL_VOLUMES.items():
                users = {name for name, service in config['services'].items()
                         if any(mount.get('source') == volume for mount in service.get('volumes') or [])}
                writers = {name for name, service in config['services'].items()
                           if any(mount.get('source') == volume and not mount.get('read_only')
                                  for mount in service.get('volumes') or [])}
                with self.subTest(mode=mode, volume=volume):
                    self.assertEqual(consumers, users)
                    self.assertEqual(1, len(writers), writers)

    def test_consumers_restart_when_their_credentials_change(self):
        config = self.rendered[MODES[0]]
        for name, writer in (('backend', 'secrets-init'), ('web', 'secrets-init'), ('db-backup', 'secrets-init'),
                             ('operational-probe', 'secrets-init'), ('grafana', 'monitoring-config')):
            with self.subTest(service=name):
                self.assertIs(True, config['services'][name]['depends_on'][writer].get('restart'))
        # PostgreSQL reads the password only at initdb; a restart would only interrupt service.
        self.assertFalse(config['services']['postgres']['depends_on']['secrets-init'].get('restart'))

    def test_file_paths_match_what_secrets_init_writes(self):
        writes = secrets_init_writes((SELFHOST / 'secrets-init.sh').read_text())
        config = self.rendered[MODES[0]]
        for name, directory in (('postgres', 'postgres'), ('db-backup', 'operator'), ('operational-probe', 'operator')):
            path = config['services'][name]['environment']['POSTGRES_PASSWORD_FILE']
            self.assertEqual('/run/secrets/chronicle/postgres-password', path)
            self.assertIn((directory, 'postgres-password'), writes)
        entrypoint = (SELFHOST / 'backend-entrypoint.sh').read_text()
        import re
        loaded = set(re.findall(r'[A-Z_][A-Z0-9_]*:([a-z-]+)', entrypoint[entrypoint.index('for pair in'):]
                                .split('; do', 1)[0]))
        self.assertEqual({file for directory, file in writes if directory == 'backend'}, loaded)

    def test_migrate_reads_only_the_schema_owner_password(self):
        entrypoint = (SELFHOST / 'backend-entrypoint.sh').read_text()
        loader = entrypoint[entrypoint.index('if [ -n "${CHRONICLE_SECRETS_DIR:-}" ]'):entrypoint.index('if [ "${1:-}" = --migrate ]')]
        with tempfile.TemporaryDirectory() as folder:
            (Path(folder) / 'postgres-password').write_text('own' * 11)
            script = Path(folder) / 'load.sh'
            script.write_text('set -eu\n' + loader + 'env\n')
            environment = {'PATH': os.environ['PATH'], 'CHRONICLE_SECRETS_DIR': folder}
            result = subprocess.run(['sh', str(script), '--migrate'], env=environment, capture_output=True, text=True, timeout=10)
            self.assertEqual(0, result.returncode, result.stderr)
            loaded = dict(line.split('=', 1) for line in result.stdout.splitlines() if '=' in line)
            self.assertEqual('own' * 11, loaded['POSTGRES_PASSWORD'])
            self.assertNotIn('POSTGRES_APP_PASSWORD', loaded)
            (Path(folder) / 'postgres-password').unlink()
            result = subprocess.run(['sh', str(script), '--migrate'], env=environment, capture_output=True, text=True, timeout=10)
            self.assertEqual(1, result.returncode)
            self.assertIn('postgres-password is missing', result.stderr)

    def test_the_job_loader_keeps_a_set_variable_and_refuses_a_missing_file(self):
        with tempfile.TemporaryDirectory() as folder:
            (Path(folder) / 'postgres-password').write_text('from-file')
            script = Path(folder) / 'job.sh'
            script.write_text(f'set -euo pipefail\nsource {SELFHOST / "secret-files.sh"}\n'
                              'load_secret_files "$1" POSTGRES_PASSWORD:postgres-password\n'
                              'printf "%s" "$POSTGRES_PASSWORD"\n')
            def run(**extra):
                return subprocess.run(['bash', str(script), folder], capture_output=True, text=True, timeout=10,
                                      env={'PATH': os.environ['PATH'], **extra})
            self.assertEqual('from-file', run().stdout)
            self.assertEqual('from-env', run(POSTGRES_PASSWORD='from-env').stdout)
            (Path(folder) / 'postgres-password').unlink()
            missing = run()
            self.assertEqual(1, missing.returncode)
            self.assertIn('secrets-init writes it', missing.stderr)

    def test_backend_entrypoint_loads_each_file_into_the_variable_the_templates_read(self):
        entrypoint = (SELFHOST / 'backend-entrypoint.sh').read_text()
        loader = entrypoint[entrypoint.index('if [ -n "${CHRONICLE_SECRETS_DIR:-}" ]'):entrypoint.index('if [ "${1:-}" = --migrate ]')]
        with tempfile.TemporaryDirectory() as folder:
            files = {'postgres-app-password': 'app' * 11, 'jwt-secret': 'jwt' * 11, 'jwt-secret-previous': '',
                     'metrics-password': 'met' * 11, 'internal-web-secret': 'web' * 11, 'reviewer-access-secret': ''}
            for name, value in files.items():
                (Path(folder) / name).write_text(value)
            script = Path(folder) / 'load.sh'
            script.write_text('set -eu\n' + loader + 'env\n')
            environment = {'PATH': os.environ['PATH'], 'CHRONICLE_SECRETS_DIR': folder, 'JWT_SECRET': 'kept-from-env'}
            result = subprocess.run(['sh', str(script)], env=environment, capture_output=True, text=True, timeout=10)
            self.assertEqual(0, result.returncode, result.stderr)
            loaded = dict(line.split('=', 1) for line in result.stdout.splitlines() if '=' in line)
            self.assertEqual('app' * 11, loaded['POSTGRES_APP_PASSWORD'])
            self.assertEqual('met' * 11, loaded['CHRONICLE_SECURITY_METRICS_PASSWORD'])
            self.assertEqual('web' * 11, loaded['CHRONICLE_INTERNAL_WEB_SECRET'])
            self.assertEqual('kept-from-env', loaded['JWT_SECRET'])  # an older Compose file's value wins
            (Path(folder) / 'metrics-password').unlink()
            result = subprocess.run(['sh', str(script)], env=environment, capture_output=True, text=True, timeout=10)
            self.assertNotEqual(0, result.returncode)
            self.assertIn('metrics-password is missing', result.stderr)

    def test_postgres_exec_callers_read_the_file_when_the_variable_is_absent(self):
        from chronicle_ops import release, verify
        import inspect
        sources = {'release.postgres_sql': inspect.getsource(release.postgres_sql), 'release.ROLLBACK_DUMP': release.ROLLBACK_DUMP,
                   'verify.capacity_checks': inspect.getsource(verify.capacity_checks)}
        for path in ('chronicle', 'doctor.sh', 'rotate-secret.sh'):
            sources[path] = (SELFHOST / path).read_text()
        # The release smoke and its client exec into 2026.11.6+ containers that have only the password file.
        for path in ('tests/smoke/selfhost-release-smoke.sh', 'tests/deployment/selfhost-client.py'):
            sources[path] = (SELFHOST.parent / path).read_text()
        for label, source in sources.items():
            with self.subTest(caller=label):
                self.assertNotIn('PGPASSWORD="$POSTGRES_PASSWORD"', source.replace('export PGPASSWORD="$POSTGRES_PASSWORD"\n', ''))
        with tempfile.TemporaryDirectory() as folder:
            secret = Path(folder) / 'postgres-password'
            secret.write_text('from-file')
            command = 'PGPASSWORD="${POSTGRES_PASSWORD:-$(cat "$POSTGRES_PASSWORD_FILE")}"; printf %s "$PGPASSWORD"'
            self.assertIn(command.split(';')[0], release.ROLLBACK_DUMP)
            for environment, expected in (({'POSTGRES_PASSWORD_FILE': str(secret)}, 'from-file'),
                                          ({'POSTGRES_PASSWORD': 'from-env'}, 'from-env')):
                result = subprocess.run(['bash', '-ceu', command], env=dict(environment, PATH=os.environ['PATH']),
                                        capture_output=True, text=True, timeout=10)
                self.assertEqual(expected, result.stdout)

    def test_harnesses_never_read_a_file_delivered_secret_from_a_container_environment(self):
        # The release smoke read CHRONICLE_INTERNAL_WEB_SECRET from the backend's configured environment;
        # 2026.11.6 delivers every secret secrets-init writes as a file, so that lookup raised KeyError.
        import re
        names = set(re.findall(r'^write /out/\S+ \S+ \S+ "\$\{?([A-Z_]+)', (SELFHOST / 'secrets-init.sh').read_text(), re.M))
        self.assertIn('CHRONICLE_INTERNAL_WEB_SECRET', names)
        for path in ('tests/smoke/selfhost-release-smoke.sh', 'tests/deployment/selfhost-client.py'):
            source = (SELFHOST.parent / path).read_text()
            with self.subTest(harness=path):
                self.assertEqual([], sorted(name for name in names if f"['{name}']" in source))

    def test_rotation_rewrites_the_files_before_recreating_services_without_dependencies(self):
        text = (SELFHOST / 'rotate-secret.sh').read_text()
        body = text[text.index('apply_configuration() {'):]
        self.assertLess(body.index('dc run --rm --no-deps secrets-init'), body.index('--no-deps --force-recreate'))

    def test_socket_proxy_blanks_container_environments_and_fails_closed(self):
        """Behaviour against the real proxy is in tests/security/selfhost-egress.sh; this pins the wiring."""
        config = (SELFHOST / 'monitoring/docker-api.cfg').read_text()
        rules = [line.strip() for line in config.splitlines() if line.strip().startswith('http-response')]
        self.assertEqual(['wait-for-body', 'lua.chronicle_strip_env', 'return'], [rule.split()[1] for rule in rules])
        self.assertIn('status 502', rules[2])
        self.assertTrue(all('var(txn.inspect)' in rule for rule in rules))
        self.assertIn('lua-load /etc/haproxy/strip-env.lua', config)
        mounts = self.rendered[MODES[0]]['services']['docker-socket-proxy']['volumes']
        self.assertIn('/etc/haproxy/strip-env.lua', {mount['target'] for mount in mounts})
        lua = (SELFHOST / 'monitoring/docker-api-strip-env.lua').read_text()
        self.assertIn('txn:done(reply)', lua)

    def test_verify_config_refuses_a_backend_file_secrets_init_does_not_write(self):
        import shutil
        with tempfile.TemporaryDirectory() as folder:
            copy = Path(folder) / 'selfhost'
            shutil.copytree(SELFHOST, copy, ignore=shutil.ignore_patterns('__pycache__', '.env'))
            script = copy / 'secrets-init.sh'
            script.write_text(script.read_text().replace(' jwt-secret "$JWT_SECRET"', ' jwt-token "$JWT_SECRET"'))
            result = subprocess.run(['bash', str(copy / 'verify-config.sh')], capture_output=True, text=True, timeout=120)
            self.assertNotEqual(0, result.returncode)
            self.assertIn('backend credential files that secrets-init.sh does not write: jwt-secret', result.stdout)


class BackupProvenanceTests(unittest.TestCase):
    def test_db_backup_knows_the_release_it_stamps_into_each_dump(self):
        """The backup image has no bundle beside its chronicle_ops; without RELEASE_VERSION the
        restore self-check after every dump failed reading /.env.example (seen in the egress drill)."""
        config = render(MODES[0], 'overlays/backups.yml', RELEASE_VERSION='2026.11.6')
        self.assertEqual('2026.11.6', config['services']['db-backup']['environment']['RELEASE_VERSION'])
        from chronicle_ops.dump import installed_backup_version
        with patch.dict(os.environ, {'RELEASE_VERSION': '2026.11.6'}):
            self.assertEqual('2026.11.6', installed_backup_version('/'))

    def test_a_release_pins_its_version_in_place_of_the_source_default(self):
        """The release builder used to insert a second RELEASE_VERSION key, which Compose refuses
        ("mapping key already defined") once the source overlay carries its own."""
        import runpy
        import yaml
        builder = runpy.run_path(str(ROOT / 'scripts/build-selfhost-release.py'))
        pinned = builder['pin_backup_release']((SELFHOST / 'overlays/backups.yml').read_text(), '2026.11.6')
        self.assertEqual(1, pinned.count('RELEASE_VERSION:'))
        environment = yaml.safe_load(pinned)['services']['db-backup']['environment']
        self.assertEqual('2026.11.6', environment['RELEASE_VERSION'])
        with self.assertRaises(SystemExit):
            builder['pin_backup_release'](pinned, '2026.11.6')

    def test_a_release_pins_its_version_wherever_compose_reads_it(self):
        """RELEASE_VERSION=development in a release .env turned off the guard's digest-pin rule
        (guard-config.sh) and the monitoring image check, because config-guard and monitoring-config
        read ${RELEASE_VERSION:-development} from .env (audit AF-S3, SO-S7). The builder now writes the
        release version into every file that reads it, so .env can no longer reach those checks."""
        import re
        import runpy
        import yaml
        builder = runpy.run_path(str(ROOT / 'scripts/build-selfhost-release.py'))
        files = builder['RELEASE_VERSION_FILES']
        default = re.compile(r'\$\{RELEASE_VERSION:-development\}')
        reading = {path.relative_to(SELFHOST).as_posix() for path in SELFHOST.rglob('*.yml')
                   if default.search(path.read_text())}
        self.assertEqual(reading, set(files))
        for name, count in files.items():
            with self.subTest(file=name):
                pinned = builder['pin_release_version']((SELFHOST / name).read_text(), '2026.11.6', count)
                self.assertNotRegex(pinned, default)
                self.assertEqual(count, pinned.count('RELEASE_VERSION: "2026.11.6"'))
                yaml.safe_load(pinned)
        guard = yaml.safe_load(builder['pin_release_version'](
            (SELFHOST / 'docker-compose.yml').read_text(), '2026.11.6', files['docker-compose.yml']))
        self.assertEqual('2026.11.6', guard['services']['config-guard']['environment']['RELEASE_VERSION'])


class BundleInventoryTests(unittest.TestCase):
    def test_every_file_compose_mounts_from_the_bundle_is_shipped(self):
        """secrets-init.sh was mounted by docker-compose.yml but missing from operator_files, so a
        release bundle would start secrets-init without its script and nothing would come up."""
        import runpy
        import yaml
        builder = runpy.run_path(str(ROOT / 'scripts/build-selfhost-release.py'))
        shipped = set(builder['operator_files']())
        directories = builder['BUNDLE_DIRECTORIES']
        files = [SELFHOST / 'docker-compose.yml', *sorted((SELFHOST / 'overlays').glob('*.yml')),
                 *sorted((SELFHOST / 'monitoring').glob('docker-compose.*.yml'))]
        missing = set()
        for path in files:
            for name, service in (yaml.safe_load(path.read_text()).get('services') or {}).items():
                for volume in service.get('volumes') or []:
                    source = volume.split(':', 1)[0] if isinstance(volume, str) else volume.get('source', '')
                    if not source.startswith('./'):
                        continue
                    relative = source[2:].rstrip('/')
                    if relative.split('/', 1)[0] in directories or relative == 'chronicle_ops':
                        continue
                    if relative not in shipped:
                        missing.add(f'{path.name} {name}: {relative}')
        self.assertEqual(set(), missing)


class WebhookSettingTests(unittest.TestCase):
    """Webhooks are refused on self-host through ChronicleConfiguration (chronicle.yaml), not a new flag."""

    def test_self_host_renders_chronicle_yaml_with_webhooks_off(self):
        import yaml
        template = yaml.safe_load((SELFHOST / 'config/chronicle.yaml.template').read_text())
        self.assertIs(False, template['webhooks']['enabled'])
        # The classpath chronicle.yaml is shadowed by the rendered one, so it must carry every key the
        # classpath copy has.
        classpath = yaml.safe_load((ROOT / 'chronicle-server/src/main/resources/chronicle.yaml').read_text())
        self.assertLessEqual(set(classpath), set(template))
        entrypoint = (SELFHOST / 'backend-entrypoint.sh').read_text()
        loop = next(line for line in entrypoint.splitlines() if line.startswith('for name in '))
        self.assertIn(' chronicle ', loop + ' ')
        self.assertIn('/server/rendered-config', entrypoint)



class EgressStackImageTests(unittest.TestCase):
    """The runtime proof must run the images this checkout builds, not a stale tag (a reused
    :egress-test Caddy image would lack chronicle-forward)."""

    def test_an_image_tag_changes_with_its_inputs_only(self):
        import shutil
        sys.path.insert(0, str(ROOT / 'tests/selfhost-py'))
        import egress_stack
        from chronicle_ops.images import SOURCE_IMAGES
        self.assertEqual({image.component for image in SOURCE_IMAGES}, set(egress_stack.IMAGE_INPUTS))
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            for component in ('caddy', 'postgres'):
                for relative in egress_stack.IMAGE_INPUTS[component][0]:
                    source = ROOT / relative
                    target = root / relative
                    target.parent.mkdir(parents=True, exist_ok=True)
                    (shutil.copytree if source.is_dir() else shutil.copy2)(source, target)
            shutil.copy2(ROOT / 'toolchain-manifest.yaml', root / 'toolchain-manifest.yaml')  # release_platform
            before = {component: egress_stack.inputs_digest(root, component) for component in ('caddy', 'postgres')}
            forwarder = root / 'selfhost/caddy/forward/main.go'
            forwarder.write_text(forwarder.read_text() + '\n// changed\n')
            self.assertNotEqual(before['caddy'], egress_stack.inputs_digest(root, 'caddy'))
            self.assertEqual(before['postgres'], egress_stack.inputs_digest(root, 'postgres'))
            self.assertNotEqual(egress_stack.inputs_digest(root, 'caddy', 'frontend-a'),
                                egress_stack.inputs_digest(root, 'caddy', 'frontend-b'))
            manifest = root / 'toolchain-manifest.yaml'
            platform = egress_stack.release_platform(root)
            manifest.write_text(manifest.read_text().replace(f'release_platform: "{platform}"',
                                                             'release_platform: "linux/s390x"'))
            self.assertNotEqual(before['postgres'], egress_stack.inputs_digest(root, 'postgres'))


def render_from_env_file(mode, *overlays, **settings):
    """`docker compose config` reading every setting from an .env file, none from the environment:
    what a plain `docker compose` in the bundle directory renders."""
    files = ['docker-compose.yml', mode, *overlays]
    environment = {key: value for key, value in os.environ.items()
                   if not key.startswith('COMPOSE_') and key not in SYNTHETIC and key != egress.ALERT_EGRESS_ENV}
    with tempfile.TemporaryDirectory() as folder:
        env_file = Path(folder) / '.env'
        env_file.write_text(''.join(f'{key}={value}\n' for key, value in dict(SYNTHETIC, **settings).items()))
        result = subprocess.run(['docker', 'compose', '--env-file', str(env_file), '--project-directory', str(SELFHOST),
                                 '-p', 'egress-fixture', *[part for name in files for part in ('-f', str(SELFHOST / name))],
                                 'config', '--format', 'json'], env=environment, capture_output=True, text=True, timeout=60)
    if result.returncode:
        raise AssertionError(result.stderr)
    return json.loads(result.stdout)


class DerivedAlertEgressTests(unittest.TestCase):
    """CHRONICLE_ALERT_EGRESS lives in .env as a derived copy, so plain Compose agrees with ./chronicle."""

    def env(self, folder, text):
        path = Path(folder) / '.env'
        path.write_text(text)
        path.chmod(0o600)
        return path

    def test_a_stale_copy_is_rewritten_and_reported(self):
        with tempfile.TemporaryDirectory() as folder:
            path = self.env(folder, 'CHRONICLE_ALERT_WEBHOOK_URL=https://hooks.example.org/x\n'
                                    'CHRONICLE_ALERT_EGRESS=closed\nKEPT=1\n')
            errors = io.StringIO()
            with patch('sys.stderr', errors):
                self.assertEqual(egress.OPEN, egress.sync_env_file(path))
            self.assertEqual('CHRONICLE_ALERT_WEBHOOK_URL=https://hooks.example.org/x\nCHRONICLE_ALERT_EGRESS=open\nKEPT=1\n',
                             path.read_text())
            self.assertEqual(0o600, path.stat().st_mode & 0o777)
            self.assertIn('had CHRONICLE_ALERT_EGRESS=closed', errors.getvalue())
            self.assertNotIn('hooks.example.org', errors.getvalue())  # the URL may carry a token

    def test_a_missing_copy_is_written_and_a_matching_one_is_left_alone(self):
        with tempfile.TemporaryDirectory() as folder:
            path = self.env(folder, 'COMPOSE_PROJECT_NAME=fixture\n')
            with patch('sys.stderr', io.StringIO()):
                self.assertEqual(egress.CLOSED, egress.sync_env_file(path))
            self.assertIn('CHRONICLE_ALERT_EGRESS=closed\n', path.read_text())
            before = path.stat()
            errors = io.StringIO()
            with patch('sys.stderr', errors):
                self.assertEqual(egress.CLOSED, egress.sync_env_file(path))
            self.assertEqual('', errors.getvalue())
            self.assertEqual((before.st_ino, before.st_mtime_ns), (path.stat().st_ino, path.stat().st_mtime_ns))

    def test_plain_compose_reads_the_derived_value_from_env(self):
        for alerts, joins in ((egress.OPEN, True), (egress.CLOSED, False)):
            with self.subTest(alerts=alerts):
                config = render_from_env_file(MODES[0], 'overlays/backups.yml', 'overlays/monitoring.yml',
                                              CHRONICLE_ALERT_EGRESS=alerts)
                self.assertEqual(joins, 'grafana' in members(config, 'egress-clients'))
                self.assertNotIn('grafana', members(config, 'egress'))

    def test_setup_and_the_update_migration_write_it(self):
        from chronicle_ops.env_migration import migrate_settings
        old = {'POSTGRES_PASSWORD': 'p', 'POSTGRES_APP_PASSWORD': 'q', 'JWT_SECRET': 'j' * 32, 'METRICS_PASSWORD': 'm' * 32,
               'CHRONICLE_INTERNAL_WEB_SECRET': 'w' * 32, 'GRAFANA_ADMIN_PASSWORD': 'g' * 32, 'CHRONICLE_CORE_PREFIX': '10.252.7',
               'CHRONICLE_ALERT_WEBHOOK_URL': 'https://hooks.example.org/x'}
        settings, notes = migrate_settings(old, lambda password: password)
        self.assertEqual(egress.OPEN, settings[egress.ALERT_EGRESS_ENV])
        self.assertTrue(any(egress.ALERT_EGRESS_ENV in note for note in notes))
        unchanged, notes = migrate_settings(dict(old, CHRONICLE_ALERT_EGRESS='open'), lambda password: password)
        self.assertFalse(any(egress.ALERT_EGRESS_ENV in note for note in notes))
        setup = (SELFHOST / 'chronicle_ops/setup_env.py').read_text()
        body = setup[setup.index('def write_setup_environment'):setup.index('def default_reconciliation')]
        self.assertIn("fields[ALERT_EGRESS_ENV] = alert_egress_for_url(fields['CHRONICLE_ALERT_WEBHOOK_URL'])", body)


class HostDestinationTests(unittest.TestCase):
    """update --check names the first host the deployment needs and cannot reach."""

    def fake_curl(self, folder, unreachable):
        log = Path(folder) / 'curl.log'
        curl = Path(folder) / 'curl'
        curl.write_text('#!/usr/bin/env bash\n'
                        f'printf "%s\\n" "$*" >>{log}\n'
                        f'[[ "${{@: -1}}" != "https://{unreachable}/" ]] || exit 6\n')
        curl.chmod(0o755)
        return log

    def test_the_first_unreachable_host_is_named_after_one_bounded_attempt_each(self):
        with tempfile.TemporaryDirectory() as folder:
            log = self.fake_curl(folder, 'ghcr.io')
            environment = dict(os.environ, PATH=folder + os.pathsep + os.environ['PATH'])
            environment.pop('CHRONICLE_RELEASES_URL', None)
            with patch.dict(os.environ, environment, clear=True):
                host, purpose, code = egress.first_unreachable()
            self.assertEqual(('ghcr.io', 6), (host, code))
            calls = log.read_text().splitlines()
            hosts = [name for name, _ in egress.HOST_DESTINATIONS]
            self.assertEqual(hosts[:hosts.index('ghcr.io') + 1], [call.split('https://')[-1].rstrip('/') for call in calls])
            self.assertTrue(all('--connect-timeout' in call and '--max-time' in call for call in calls))

    def test_every_destination_is_in_the_operator_document(self):
        document = (SELFHOST / 'docs/NETWORK-EGRESS.md').read_text()
        table = document[document.index('## Host destinations'):]
        for host, _ in egress.HOST_DESTINATIONS:
            with self.subTest(host=host):
                self.assertIn(f'`{host}`', table)

    def test_update_check_reports_before_it_waits_on_the_release_catalog(self):
        from chronicle_ops import update
        order = []
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); host = root / 'selfhost'; host.mkdir()
            (root / 'release-manifest.json').write_text(json.dumps({'release_version': '1.1.0'}))
            settings = host / '.env'; settings.write_text('COMPOSE_PROJECT_NAME=fixture\n'); settings.chmod(0o600)
            errors = io.StringIO()
            with patch.object(Path, 'cwd', return_value=host), \
                 patch('chronicle_ops.update.require_current_owner'), \
                 patch('chronicle_ops.egress.first_unreachable',
                       side_effect=lambda: order.append('probe') or ('ghcr.io', 'images', 6)), \
                 patch('chronicle_ops.update.fetch_published_releases',
                       side_effect=lambda: order.append('catalog') or []), \
                 patch('sys.stderr', errors):
                with self.assertRaises(ValueError):
                    update.update(check=True)
            self.assertEqual(['probe', 'catalog'], order)
            self.assertIn('cannot reach https://ghcr.io/', errors.getvalue())


if __name__ == '__main__':
    unittest.main()
