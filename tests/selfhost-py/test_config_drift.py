"""PR-O13: running containers whose configuration differs from what Compose renders now.

Reconcile starts the stack with --no-recreate (selfhost/chronicle cmd_up), so an edited .env or
Compose file that was never applied with ./chronicle up stays silent. Compose records each
container's configuration hash in the com.docker.compose.config-hash label and prints the
current one with `config --hash`; doctor and status compare the two."""

import io
import os
import subprocess
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

from chronicle_ops import services
from chronicle_ops.__main__ import run_cli

RENDERED = 'backend aaaa\npostgres bbbb\nweb cccc\nmigrate dddd\n'


def fake_compose(running):
    """docker compose: `config --hash *` renders; `ps` lists containers with their recorded hash."""
    def compose(*args, **_kwargs):
        if args[:2] == ('config', '--hash'):
            return subprocess.CompletedProcess(args, 0, RENDERED, '')
        if args[0] == 'ps':
            return subprocess.CompletedProcess(args, 0, ''.join(f'{name}\t{digest}\n' for name, digest in running), '')
        raise AssertionError(f'unexpected compose call {args}')
    return compose


class ConfigDriftTests(unittest.TestCase):
    def setUp(self):
        active = patch.dict(os.environ, CHRONICLE_OPS_PROJECT='fixture')
        active.start()
        self.addCleanup(active.stop)

    def drift(self, running):
        with patch('chronicle_ops.services.compose', side_effect=fake_compose(running)):
            return services.config_drift()

    def test_a_running_service_with_an_older_configuration_is_named(self):
        self.assertEqual(['web'], self.drift([('backend', 'aaaa'), ('postgres', 'bbbb'), ('web', 'old')]))

    def test_matching_hashes_and_stopped_one_shots_are_not_drift(self):
        # migrate is not running; ps --status running never lists it.
        self.assertEqual([], self.drift([('backend', 'aaaa'), ('postgres', 'bbbb'), ('web', 'cccc')]))

    def test_a_running_service_no_longer_in_the_configuration_is_drift(self):
        self.assertEqual(['retired'], self.drift([('backend', 'aaaa'), ('retired', 'eeee')]))

    def test_cli_prints_doctor_rows(self):
        for running, status, text in (([('web', 'old')], 'warn', 'web'), ([('web', 'cccc')], 'ok', 'match')):
            with self.subTest(status=status), patch('chronicle_ops.services.compose', side_effect=fake_compose(running)), \
                 patch('chronicle_ops.__main__.signal.signal'), redirect_stdout(io.StringIO()) as output:
                self.assertEqual(0, run_cli(['config-drift']))
                ident, row_status, summary, action = output.getvalue().rstrip('\n').split('\x1f')
                self.assertEqual(('config-drift', status), (ident, row_status))
                self.assertIn(text, summary)
                self.assertTrue(action == 'none' if status == 'ok' else action.startswith('./chronicle up '), action)

    def test_an_unreadable_configuration_is_a_warning_not_a_crash(self):
        def broken(*args, **_kwargs):
            return subprocess.CompletedProcess(args, 1, '', 'boom')
        with patch('chronicle_ops.services.compose', side_effect=broken), \
             patch('chronicle_ops.__main__.signal.signal'), redirect_stdout(io.StringIO()) as output:
            self.assertEqual(0, run_cli(['config-drift']))
        self.assertTrue(output.getvalue().startswith('config-drift\x1fwarn\x1f'), output.getvalue())


if __name__ == '__main__':
    unittest.main()
