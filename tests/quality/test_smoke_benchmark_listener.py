"""The release smoke's benchmark listener publishes its port from a routed network.

The backend/web network has been internal since b335e2d2, and Docker publishes no port for a container
whose only network is internal. The 2026.11.12 smoke started the listener on that network alone and
failed with "no public port '8080/tcp' published". The listener is now created on a fixture bridge that
carries the published port, joined to the backend network, then started. The Docker test below shows
both behaviours; the static test holds the smoke to that order.

The listener also sends a GET again when its round trip to the backend failed without an answer. The
load script's oversized-URI probe makes Jetty answer 414 and close while caddy is still sending the
request line; when caddy sees its failed write first, it answers 502 itself. Measured on 2026-11-16
against the 2026.11.16 backend through a caddy configured like the listener: 10 of 3,000 such requests
came back 502 ("write: broken pipe" or EOF in caddy's log), and 0 of 6,000 with lb_retries 2. One such
502 among 38 answers failed a smoke of 2026.11.16."""
import re
import shutil
import subprocess
import sys
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


def listener_proxy_block(text):
    """The reverse_proxy block of the Caddyfile that text writes for the benchmark listener."""
    caddyfile = re.search(r"\(folder / 'benchmark\.Caddyfile'\)\.write_text\('''(.*?)'''\)", text, re.S).group(1)
    return re.search(r'\n    reverse_proxy https://backend:8443 \{\n(.*?)\n    \}\n', caddyfile, re.S).group(1)


def retries_a_failed_round_trip_only(block):
    """True when the block retries, and no matcher lets an answer from the backend be retried away."""
    directives = [line.split('#', 1)[0].split() for line in block.splitlines()]
    retries = [words for words in directives if words[:1] == ['lb_retries']]
    return (len(retries) == 1 and len(retries[0]) == 2 and retries[0][1].isdigit() and int(retries[0][1]) >= 1
            and not any(words[:1] == ['lb_retry_match'] for words in directives))


class BenchmarkListenerTests(unittest.TestCase):
    def test_the_listener_sends_a_get_again_when_its_round_trip_failed_without_an_answer(self):
        self.assertTrue(retries_a_failed_round_trip_only(listener_proxy_block(SMOKE.read_text())))

    def test_the_retry_check_catches_the_listener_of_2026_11_16_and_a_status_matcher(self):
        listener = ("(folder / 'benchmark.Caddyfile').write_text('''{\n    admin off\n}\n:8080 {\n"
                    "    reverse_proxy https://backend:8443 {\nRETRY        transport http {\n"
                    "            versions 1.1\n        }\n    }\n}\n''')\n")
        self.assertFalse(retries_a_failed_round_trip_only(listener_proxy_block(listener.replace('RETRY', ''))))
        self.assertFalse(retries_a_failed_round_trip_only(listener_proxy_block(
            listener.replace('RETRY', '        # lb_retries 2\n'))))
        self.assertTrue(retries_a_failed_round_trip_only(listener_proxy_block(
            listener.replace('RETRY', '        lb_retries 2\n'))))
        self.assertFalse(retries_a_failed_round_trip_only(listener_proxy_block(listener.replace(
            'RETRY', '        lb_retries 2\n        lb_retry_match expression `{rp.status_code} in [502]`\n'))))

    def test_the_listener_publishes_from_its_own_bridge_and_joins_the_backend_network_after(self):
        text = SMOKE.read_text()
        self.assertIn('"$BENCHMARK_EDGE_NETWORK"', published_networks(text))
        self.assertNotIn('"$(jq -er .network "$RUN_DIR/benchmark-listener.json")"', published_networks(text))
        create = text.index('docker network create --subnet "$benchmark_edge_subnet" '
                            '--label "chronicle.sat-r1.fixture=$PROJECT" "$BENCHMARK_EDGE_NETWORK"')
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
        def subnet(default, name):
            # Chosen, not taken from Docker's default address pools (test_created_networks_name_a_subnet).
            return subprocess.run([sys.executable, str(ROOT / 'selfhost/network-subnet.py'), 'select', default, name],
                                  check=True, capture_output=True, text=True, timeout=60).stdout.strip()
        try:
            docker('network', 'create', '--subnet', subnet('10.251.6.0/24', tag + '-internal'), '--internal', tag + '-internal')
            docker('network', 'create', '--subnet', subnet('10.251.7.0/24', tag + '-edge'), tag + '-edge')
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
