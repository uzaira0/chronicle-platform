"""The release smoke's benchmark listener publishes its port from a routed network.

The backend/web network has been internal since b335e2d2, and Docker publishes no port for a container
whose only network is internal. The 2026.11.12 smoke started the listener on that network alone and
failed with "no public port '8080/tcp' published". The listener is now created on a fixture bridge that
carries the published port, joined to the backend network, then started. The Docker test below shows
both behaviours; the static test holds the smoke to that order."""
import re
import shutil
import subprocess
import unittest
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SMOKE = ROOT / 'tests/smoke/selfhost-release-smoke.sh'
# The audit helper image docker/restore-chronicle.sh already pins; any running process will do.
IMAGE = re.search(r'AUDIT_HELPER_IMAGE="([^"]+)"', (ROOT / 'docker/restore-chronicle.sh').read_text()).group(1)


def published_networks(text):
    """The --network of every docker run/create command in text that also publishes a port."""
    commands = re.findall(r'docker (?:run|create)\b(?:[^\n]*\\\n)*[^\n]*', text)
    return [re.search(r'--network\s+("\$\([^)]*\)"|"[^"]*"|\S+)', command).group(1)
            for command in commands if '--publish' in command and '--network' in command]


class BenchmarkListenerTests(unittest.TestCase):
    def test_the_listener_publishes_from_its_own_bridge_and_joins_the_backend_network_after(self):
        text = SMOKE.read_text()
        self.assertIn('"$BENCHMARK_EDGE_NETWORK"', published_networks(text))
        self.assertNotIn('"$(jq -er .network "$RUN_DIR/benchmark-listener.json")"', published_networks(text))
        create = text.index('docker network create --label "chronicle.sat-r1.fixture=$PROJECT" "$BENCHMARK_EDGE_NETWORK"')
        connect = text.index('docker network connect "$(jq -er .network "$RUN_DIR/benchmark-listener.json")"')
        start = text.index('docker start "$BENCHMARK_LISTENER_CONTAINER"')
        self.assertLess(create, connect)
        self.assertLess(connect, start)
        self.assertIn('docker network rm "$BENCHMARK_EDGE_NETWORK"', text)

    def test_the_check_catches_the_2026_11_6_command(self):
        old = ('X="$(docker run -d --name n \\\n'
               '  --network "$(jq -er .network "$RUN_DIR/benchmark-listener.json")" --publish 127.0.0.1::8080 \\\n'
               '  "$CADDY_IMAGE")"\n')
        self.assertEqual(['"$(jq -er .network "$RUN_DIR/benchmark-listener.json")"'], published_networks(old))

    @unittest.skipUnless(shutil.which('docker'), 'needs Docker')
    def test_docker_publishes_no_port_on_an_internal_network_but_does_after_create_connect_start(self):
        tag = 'chronicle-quality-publish-' + uuid.uuid4().hex[:10]
        def docker(*arguments, check=True):
            return subprocess.run(['docker', *arguments], capture_output=True, text=True, timeout=180, check=check)
        try:
            docker('network', 'create', '--internal', tag + '-internal')
            docker('network', 'create', tag + '-edge')
            docker('run', '-d', '--name', tag + '-a', '--network', tag + '-internal', '--publish', '127.0.0.1::8080',
                   IMAGE, 'sleep', '120')
            refused = docker('port', tag + '-a', '8080/tcp', check=False)
            self.assertNotEqual(0, refused.returncode)
            self.assertIn('no public port', refused.stderr)
            docker('create', '--name', tag + '-b', '--network', tag + '-edge', '--publish', '127.0.0.1::8080',
                   IMAGE, 'sleep', '120')
            docker('network', 'connect', tag + '-internal', tag + '-b')
            docker('start', tag + '-b')
            self.assertRegex(docker('port', tag + '-b', '8080/tcp').stdout.strip(), r'^127\.0\.0\.1:[0-9]+$')
        finally:
            docker('rm', '-fv', tag + '-a', tag + '-b', check=False)
            docker('network', 'rm', tag + '-internal', tag + '-edge', check=False)


if __name__ == '__main__':
    unittest.main()
