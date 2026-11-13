"""The topology fixture's Compose project takes no network from Docker's default address pools.

tests/deployment/selfhost-topology.sh starts a second Compose project beside the release smoke's own
stack. That stack, with monitoring, holds seven networks from the daemon's default address pools, and
the fixture's `database-probe` asked for an eighth. On 2026-11-12 the release Mac had seven free and the
smoke failed 42 minutes in: "failed to create network chronicle-topology-78768_database-probe: Error
response from daemon: all predefined address pools have been fully subnetted".

The fixture cannot add a file to COMPOSE_FILE (guard-config.sh refuses a file it does not know), so it
creates that one network itself, on a subnet selfhost/network-subnet.py chooses, under the name and the
two labels Compose would give it. Compose uses a network that exists under its project's name and
labels; the Docker test below shows that, and that removing the project removes the network."""
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
import uuid
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
TOPOLOGY = ROOT / 'tests/deployment/selfhost-topology.sh'
# The audit helper image docker/restore-chronicle.sh already pins; any running process will do.
IMAGE = re.search(r'AUDIT_HELPER_IMAGE="([^"]+)"', (ROOT / 'docker/restore-chronicle.sh').read_text()).group(1)


def fixture_helper():
    """anonymous_volumes_removed of tests/selfhost-py/selfhost_fixture.py, which every harness that removes
    its own Compose project wraps the removal in (rule compose-down-leaves-anonymous-volumes-python).
    Its directory and selfhost/ are on the path only for the import, so no other quality test resolves
    a module name there."""
    paths = [str(ROOT / 'selfhost'), str(ROOT / 'tests/selfhost-py')]
    sys.path[:0] = paths
    try:
        import chronicle_ops.common  # noqa: F401  anonymous_volumes_removed imports it when it is called
        from selfhost_fixture import anonymous_volumes_removed
    finally:
        for entry in paths:
            sys.path.remove(entry)
    return anonymous_volumes_removed


def compose_files(text):
    """The files in the COMPOSE_FILE the topology script writes to its .env."""
    return re.search(r"COMPOSE_FILE='([^']+)'", text).group(1).split(':')


def networks_without_a_subnet(files):
    networks = {}
    for name in files:
        networks.update(yaml.safe_load((ROOT / 'selfhost' / name).read_text()).get('networks') or {})
    return sorted(name for name, network in networks.items()
                  if not any(config.get('subnet') for config in ((network or {}).get('ipam') or {}).get('config') or []))


class TopologyProbeNetworkTests(unittest.TestCase):
    def test_database_probe_is_the_one_network_of_the_fixture_project_without_a_subnet(self):
        self.assertEqual(['database-probe'], networks_without_a_subnet(compose_files(TOPOLOGY.read_text())))

    def test_the_fixture_creates_it_on_a_chosen_subnet_before_the_stack_starts(self):
        text = TOPOLOGY.read_text()
        choose = text.index('probe_subnet=$(python3 network-subnet.py select ')
        create = text.index('docker network create --internal --subnet "$probe_subnet"')
        start = text.index('docker compose up -d --wait')
        self.assertLess(choose, create)
        self.assertLess(create, start)
        command = text[create:text.index('>/dev/null', create)]
        self.assertIn('--label "com.docker.compose.project=$PROJECT"', command)
        self.assertIn('--label com.docker.compose.network=database-probe', command)
        self.assertIn('"${PROJECT}_database-probe"', command)

    @unittest.skipUnless(shutil.which('docker'), 'needs Docker')
    def test_compose_uses_a_network_that_exists_under_its_name_and_labels(self):
        anonymous_volumes_removed = fixture_helper()
        project = 'chronicle-quality-adopt-' + uuid.uuid4().hex[:10]
        network = project + '_probe'
        def docker(*arguments, check=True):
            return subprocess.run(['docker', *arguments], capture_output=True, text=True, timeout=180, check=check)
        def seen():
            return docker('network', 'inspect', network, '--format', '{{.Id}} {{range .IPAM.Config}}{{.Subnet}}{{end}}').stdout.strip()
        with tempfile.TemporaryDirectory(dir=ROOT / 'build') as folder:
            compose = Path(folder) / 'docker-compose.yml'
            compose.write_text(yaml.safe_dump({
                'services': {'a': {'image': IMAGE, 'entrypoint': ['sleep', '120'], 'networks': ['probe']}},
                'networks': {'probe': {'internal': True}}}))
            subnet = subprocess.run([sys.executable, str(ROOT / 'selfhost/network-subnet.py'), 'select', '10.251.12.0/24', project],
                                    check=True, capture_output=True, text=True, timeout=60).stdout.strip()
            try:
                docker('network', 'create', '--internal', '--subnet', subnet, '--label', 'com.docker.compose.project=' + project,
                       '--label', 'com.docker.compose.network=probe', network)
                created = seen()
                self.assertTrue(created.endswith(' ' + subnet), created)
                docker('compose', '-p', project, '-f', str(compose), 'up', '-d')
                self.assertEqual(created, seen())
                docker('compose', '-p', project, '-f', str(compose), 'run', '--rm', '--entrypoint', 'true', 'a')
                self.assertEqual(created, seen())
                with anonymous_volumes_removed(project):
                    docker('compose', '-p', project, '-f', str(compose), 'down', '--volumes')
                self.assertNotEqual(0, docker('network', 'inspect', network, check=False).returncode)
            finally:
                with anonymous_volumes_removed(project):
                    docker('compose', '-p', project, '-f', str(compose), 'down', '--volumes', check=False)
                docker('network', 'rm', network, check=False)


if __name__ == '__main__':
    unittest.main()
