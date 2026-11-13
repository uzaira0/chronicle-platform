"""Every Docker network the tests and build scripts create names its own subnet.

A network created without --subnet takes one from the daemon's default address pools, and a host
that runs many Compose projects has few of those left. On 2026-11-12 this Mac had 7 of OrbStack's 30
free; the release smoke with monitoring needed 8 (seven for the stack, one for its benchmark
listener), and the listener's network was the one this repository could place itself. Six commands
in four files drew from the pools. Each now asks selfhost/network-subnet.py select for a subnet that
overlaps no Docker network and no host route, as the route-surface, monitoring, forward-drill and
log-sanitizer fixtures already did.

The stack's own Compose networks are not commands and are outside this rule: `default`, `core`,
`ingress` and `database` carry subnets from .env, the others take what the operator's daemon gives."""
import re
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SHELL = re.compile(r'\bdocker network create\b(?:[^\n]*\\\n)*[^\n]*')
PYTHON = re.compile(r'''(?:\bdocker\(|["']docker["'],)\s*["']network["'],\s*["']create["'][^\n]*''')


def from_the_pools(text):
    """The network-create commands in text that name no subnet."""
    return [command for pattern in (SHELL, PYTHON) for command in pattern.findall(text) if '--subnet' not in command]


class CreatedNetworksNameASubnetTests(unittest.TestCase):
    def test_no_tracked_script_or_test_creates_a_network_from_the_default_pools(self):
        tracked = subprocess.run(['git', '-C', str(ROOT), 'ls-files', '-z', '--', '*.sh', '*.py'],
                                 capture_output=True, text=True, check=True).stdout.split('\0')
        found = [f'{name}: {command.strip()}' for name in tracked if name and ROOT / name != Path(__file__).resolve()
                 for command in from_the_pools((ROOT / name).read_text(errors='replace'))]
        self.assertEqual([], found)

    def test_the_check_catches_the_commands_it_replaced(self):
        for old in ('docker network create --label "chronicle.sat-r1.fixture=$PROJECT" "$BENCHMARK_EDGE_NETWORK" >/dev/null ||',
                    '  docker network create --internal "$id-internal" >/dev/null',
                    '  docker network create "$id-egress" >/dev/null',
                    "        cls.docker('network', 'create', cls.name)",
                    "            docker('network', 'create', '--internal', tag + '-internal')",
                    'subprocess.run(["docker", "network", "create", name], check=True)',
                    'docker network create \\\n  --label a=b "$name"\n'):
            self.assertEqual(1, len(from_the_pools(old)), old)

    def test_the_check_accepts_a_named_subnet_and_ignores_other_text(self):
        for kept in ('docker network create --subnet "$subnet" "$outage" >/dev/null',
                     'docker network create \\\n  --subnet "$subnet" "$name"\n',
                     'docker("network", "create", "--subnet", self.subnet, self.network)',
                     'subprocess.run(["docker", "network", "create", "--subnet", subnet, network], check=True)',
                     "[call for call in calls if call.startswith(('run', 'network', 'create'))]",
                     'docker network rm "$BENCHMARK_EDGE_NETWORK"'):
            self.assertEqual([], from_the_pools(kept), kept)


if __name__ == '__main__':
    unittest.main()
