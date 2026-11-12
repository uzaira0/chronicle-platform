"""The launcher's address checks read the whole address list before they answer.

Under `set -o pipefail` a pipeline whose consumer leaves at the first match reports a failure for
a correct answer: the producer is killed by SIGPIPE while it writes the rest, and its status (141)
becomes the pipeline's. `./chronicle check` and `up` refused a healthy host that way on 2026-11-11
("INTERNAL_BIND=127.0.0.1 is not an address on this host"): `host_addrs | grep -qx` had matched
127.0.0.1 and left while awk was still writing the other addresses.

These tests give the launcher an `ip` whose output starts with the addresses asked about and goes
on for longer than a pipe can hold, so a consumer that leaves early always kills the producer.
No Docker and no network: the launcher is sourced (it returns before dispatch) and its own
functions are called.
"""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

import chronicle_ops

# The package under test may be a built bundle (run_suite.py selects it through PYTHONPATH).
SELFHOST = Path(chronicle_ops.__file__).resolve().parents[1]
# `ip -o addr show` of a host with 60,002 addresses: loopback and one LAN address first, then about
# 780 kB of link-local ones. A pipe holds 64 kB at most on Linux and macOS, so whoever writes this
# list is still writing when a consumer that stops at the first match has gone.
LONG_ADDRESS_LIST = r'''#!/usr/bin/env bash
printf '1: lo    inet 127.0.0.1/8 scope host lo\n2: eth0    inet 10.20.0.5/24 brd 10.20.0.255 scope global eth0\n'
exec awk 'BEGIN { for (i = 0; i < 60000; i++) printf "%d: veth%d    inet6 fe80::%x:%x/64 scope link\n", i + 3, i, int(i / 65536), i % 65536 }'
'''


class AddressChecksReadTheWholeListTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.tools = Path(folder.name)
        (self.tools / 'ip').write_text(LONG_ADDRESS_LIST)
        (self.tools / 'ip').chmod(0o755)

    def launcher(self, script, *arguments, stdin=''):
        """Run `script` in a shell that has sourced the launcher, with the long address list first on PATH."""
        return subprocess.run(['bash', '-c', f'source {SELFHOST / "chronicle"}\n{script}', 'fixture', *arguments],
                              cwd=SELFHOST, env=dict(os.environ, PATH=f'{self.tools}{os.pathsep}{os.environ["PATH"]}'),
                              input=stdin, capture_output=True, text=True, timeout=120)

    def test_the_fixture_kills_the_writer_of_a_consumer_that_leaves_at_the_first_match(self):
        # What the checks did before: this is the false failure, and the reason for the two tests below.
        result = self.launcher('host_addrs | grep -qx 127.0.0.1; printf "%s\\n" "${PIPESTATUS[*]}"')
        self.assertEqual('141 0', result.stdout.strip(), result.stderr)
        result = self.launcher('host_addrs | grep -x 127.0.0.1 >/dev/null; printf "%s\\n" "${PIPESTATUS[*]}"')
        self.assertEqual('0 0', result.stdout.strip(), result.stderr)

    def test_startup_accepts_the_addresses_the_host_has(self):
        script = '''
HTTP_BIND=10.20.0.5 INTERNAL_BIND=127.0.0.1 TLS_MODE=behind-proxy DASHBOARD_EXPOSURE=internal COMPOSE_FILE=
PREFLIGHT_FAILED=0
preflight_addresses
printf 'failed=%s\\n' "$PREFLIGHT_FAILED"
'''
        result = self.launcher(script)
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertNotIn('is not an address on this host', result.stdout + result.stderr)
        self.assertIn('HTTP_BIND=10.20.0.5 is an address on this host', result.stdout)
        self.assertEqual('failed=0', result.stdout.strip().splitlines()[-1])

    def test_startup_still_refuses_an_address_the_host_does_not_have(self):
        script = '''
HTTP_BIND=10.20.0.6 INTERNAL_BIND=127.0.0.1 TLS_MODE=behind-proxy DASHBOARD_EXPOSURE=internal COMPOSE_FILE=
PREFLIGHT_FAILED=0
preflight_addresses >/dev/null
printf 'failed=%s\\n' "$PREFLIGHT_FAILED"
'''
        result = self.launcher(script)
        self.assertEqual('failed=1', result.stdout.strip().splitlines()[-1], result.stderr)

    def test_setup_accepts_an_address_the_host_has_at_the_first_answer(self):
        result = self.launcher('ask_bind_addr "$1"', '127.0.0.1', stdin='10.20.0.5\n')
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual('10.20.0.5\n', result.stdout)
        self.assertNotIn('is not an address on this host', result.stderr)


if __name__ == '__main__':
    unittest.main()
