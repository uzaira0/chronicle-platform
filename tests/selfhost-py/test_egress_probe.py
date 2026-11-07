"""tests/security/selfhost-egress.sh judges what its probes saw, not whether they ran.

A fake `docker` on PATH plays a project whose containers, networks and probe outcomes each test
chooses. The probe protocol is the script's: the probe container prints PROBE:yes or PROBE:no,
and anything else (a container that could not start) is "could not run".
"""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / 'tests/security/selfhost-egress.sh'

FAKE_DOCKER = r'''#!/usr/bin/env python3
import json, os, sys
scenario = json.load(open(os.environ['FAKE_DOCKER_SCENARIO']))
args = sys.argv[1:]
services = scenario['services']
by_id = {spec['id']: name for name, spec in services.items()}

def value(flag):
    return [args[i + 1] for i, arg in enumerate(args) if arg == flag]

if args[:1] == ['version']:
    print('29.8.2'); sys.exit()
if args[:1] == ['info']:
    print('6.12.95 (fake)'); sys.exit()
if args[:1] == ['ps']:
    filters = value('--filter')
    wanted = [f.rsplit('=', 1)[1] for f in filters if f.startswith('label=com.docker.compose.service=')]
    names = [name for name in services if not wanted or name in wanted]
    if '--format' in args:
        print('\n'.join(names))
    else:
        print('\n'.join(services[name]['id'] for name in names))
    sys.exit()
if args[:2] == ['network', 'inspect']:
    print('true' if args[-1] in scenario['internal'] else 'false'); sys.exit()
if args[:1] == ['inspect']:
    template, target = args[2], args[3]
    name = by_id.get(target, 'postgres')
    if 'Config.Image' in template:
        print('fixture/postgres@sha256:' + 'a' * 64)
    elif 'NetworkSettings.Networks' in template:
        print('\n'.join(services[name]['networks']))
    elif 'Config.Labels' in template:
        print(name)
    sys.exit()
if args[:1] == ['run']:
    if scenario.get('launch_error'):
        print('docker: Error response from daemon: fixture', file=sys.stderr); sys.exit(125)
    network = value('--network')[0]
    command = args[-1]
    if 'curl' in value('--entrypoint'):
        sys.exit(22)
    if network == 'none' and command == '/egress/allow':
        print('\n'.join(scenario.get('allowlist', []))); sys.exit()
    if network == 'bridge':
        kind = 'dns' if 'getent' in command else 'tcp'
        print('PROBE:' + ('yes' if scenario['control'][kind] else 'no')); sys.exit()
    name = by_id[network.split(':', 1)[1]]
    spec = services[name]
    if 'CONNECT' in command:
        outcome = services.get('egress-proxy', {}).get('refuses', True)
    elif '/proc/net/route' in command:
        outcome = spec.get('route', False)
    elif '1.1.1.1' in command:
        outcome = spec.get('egress', False)
    elif 'example.com' in command:
        outcome = spec.get('resolves', False)
    else:
        outcome = True  # an internal path
    print('PROBE:' + ('yes' if outcome else 'no')); sys.exit()
sys.exit('fake docker: unhandled ' + ' '.join(args))
'''


def project(**changes):
    scenario = {
        'internal': ['fixture_core', 'fixture_database-probe'],
        'control': {'tcp': True, 'dns': True},
        'services': {
            'postgres': {'id': 'c1', 'networks': ['fixture_core', 'fixture_database-probe']},
            'backend': {'id': 'c2', 'networks': ['fixture_core']},
        },
    }
    for key, value in changes.items():
        if key == 'services':
            for name, spec in value.items():
                scenario['services'][name] = dict(scenario['services'].get(name, {}), **spec)
        else:
            scenario[key] = value
    return scenario


def run(scenario):
    with tempfile.TemporaryDirectory() as folder:
        bin_dir = Path(folder) / 'bin'
        bin_dir.mkdir()
        docker = bin_dir / 'docker'
        docker.write_text(FAKE_DOCKER.replace('/usr/bin/env python3', sys.executable, 1))
        docker.chmod(0o755)
        path = Path(folder) / 'scenario.json'
        path.write_text(json.dumps(scenario))
        environment = dict(os.environ, PATH=f'{bin_dir}{os.pathsep}{os.environ["PATH"]}', FAKE_DOCKER_SCENARIO=str(path))
        return subprocess.run(['bash', str(SCRIPT), 'fixture'], env=environment, capture_output=True, text=True,
                              timeout=120)


class EgressProbeTests(unittest.TestCase):
    def test_an_isolated_project_with_working_controls_passes(self):
        result = run(project())
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertIn('ok    backend: no default route', result.stdout)
        self.assertIn('Docker Engine 29.8.2, kernel 6.12.95', result.stdout)
        self.assertIn('egress proof: PASS', result.stdout)

    def test_a_probe_that_cannot_start_fails_instead_of_passing(self):
        result = run(project(launch_error=True))
        self.assertNotEqual(0, result.returncode, result.stdout)
        self.assertIn('FAIL  backend: TCP to 1.1.1.1:443 does not connect: the probe could not run', result.stdout)
        self.assertNotIn('ok    backend: TCP', result.stdout)
        self.assertNotIn('ok    backend: example.com', result.stdout)

    def test_without_a_working_control_nothing_is_proved(self):
        for control in ({'tcp': False, 'dns': True}, {'tcp': True, 'dns': False}):
            with self.subTest(control=control):
                result = run(project(control=control))
                self.assertNotEqual(0, result.returncode, result.stdout)
                self.assertIn("FAIL  control on Docker's bridge network", result.stdout)

    def test_a_default_route_fails_even_when_no_connection_got_out(self):
        result = run(project(services={'backend': {'route': True}}))
        self.assertNotEqual(0, result.returncode)
        self.assertIn('FAIL  backend: no default route', result.stdout)

    def test_a_connection_or_lookup_that_gets_out_fails(self):
        for change, message in (({'egress': True}, 'FAIL  backend: TCP to 1.1.1.1:443 does not connect'),
                                ({'resolves': True}, 'FAIL  backend: example.com does not resolve')):
            with self.subTest(change=change):
                result = run(project(services={'backend': change}))
                self.assertNotEqual(0, result.returncode)
                self.assertIn(message, result.stdout)

    def test_only_listed_edge_services_may_join_an_outbound_network(self):
        outbound = {'networks': ['fixture_core', 'fixture_egress']}
        result = run(project(services={'backend': outbound}))
        self.assertNotEqual(0, result.returncode)
        self.assertIn('FAIL  backend: joins egress, which can reach beyond the host, and is not an edge service',
                      result.stdout)
        # public-probe goes out only through egress-proxy; on the routed network itself it is refused.
        result = run(project(services={'public-probe': {'id': 'c3', 'networks': ['fixture_egress'], 'egress': True}}))
        self.assertNotEqual(0, result.returncode)
        self.assertIn('FAIL  public-probe: joins egress, which can reach beyond the host, and is not an edge service',
                      result.stdout)
        proxied = dict(internal=['fixture_core', 'fixture_database-probe', 'fixture_egress-clients'],
                       allowlist=['chronicle.example.org:443'],
                       services={'egress-proxy': {'id': 'c3', 'networks': ['fixture_egress', 'fixture_egress-clients'], 'egress': True},
                                 'public-probe': {'id': 'c4', 'networks': ['fixture_egress-clients']}})
        result = run(project(**proxied))
        self.assertEqual(0, result.returncode, result.stdout)
        self.assertIn('ok    egress-proxy: edge on egress', result.stdout)
        self.assertIn('ok    egress-proxy reaches 1.1.1.1:443', result.stdout)
        self.assertIn('ok    egress-proxy refuses CONNECT example.com:443', result.stdout)
        self.assertIn('ok    egress-proxy allowlist: chronicle.example.org:443', result.stdout)
        # A proxy that tunnels to a host outside its list fails the check.
        proxied['services']['egress-proxy']['refuses'] = False
        result = run(project(**proxied))
        self.assertNotEqual(0, result.returncode)
        self.assertIn('FAIL  egress-proxy refuses CONNECT example.com:443', result.stdout)


if __name__ == '__main__':
    unittest.main()
