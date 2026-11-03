"""Host memory probes and the setup/check command contract."""

import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from chronicle_ops.common import run
from test_secret_generation import SelfhostSetupFixture


class HostMemoryTests(unittest.TestCase):
    def test_cli_honors_meminfo_and_threshold_boundaries(self):
        import io
        from chronicle_ops.__main__ import run_cli
        from chronicle_ops.host_memory import MIN_MEMORY_KIB, MONITORING_MIN_MEMORY_KIB
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'meminfo'
            for memory, warning, default in ((MIN_MEMORY_KIB - 1, True, 'N\n'),
                                             (MIN_MEMORY_KIB, False, 'N\n'),
                                             (MONITORING_MIN_MEMORY_KIB - 1, False, 'N\n'),
                                             (MONITORING_MIN_MEMORY_KIB, False, 'Y\n')):
                path.write_text(f'MemTotal: {memory} kB\n')
                for action in ('check', 'monitoring-default'):
                    with self.subTest(memory=memory, action=action), patch.dict(os.environ, CHRONICLE_MEMINFO=str(path)), \
                         patch('chronicle_ops.__main__.signal.signal'), patch('sys.stdout', new_callable=io.StringIO) as stdout, \
                         patch('sys.stderr', new_callable=io.StringIO) as stderr:
                        self.assertEqual(run_cli(['host-memory', action]), 0)
                        result = subprocess.CompletedProcess([], 0, stdout.getvalue(), stderr.getvalue())
                        expected = default if action == 'monitoring-default' else (
                            f'{memory // 1048576} GiB of memory; below the 4 GB minimum the stack is sized for '
                            '(README Sizing), so containers may be OOM-killed. Use a host with 4 GB or more\n'
                            if warning else '')
                        self.assertEqual(result.stdout, expected)
                        self.assertEqual(result.stderr, '')

    def test_unreadable_or_malformed_meminfo_is_unknown(self):
        from chronicle_ops.host_memory import total_memory_kib
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'meminfo'
            with patch.dict(os.environ, CHRONICLE_MEMINFO=str(path)):
                self.assertIsNone(total_memory_kib())
                for content in ('', 'MemTotal:', 'MemTotal: unknown kB\n'):
                    path.write_text(content)
                    self.assertIsNone(total_memory_kib())

    def test_native_probe_is_used_only_for_check_without_override(self):
        from chronicle_ops.host_memory import total_memory_kib
        with patch.dict(os.environ, {}, clear=True), patch.object(Path, 'read_text', side_effect=OSError), \
             patch('chronicle_ops.host_memory.subprocess.run', return_value=subprocess.CompletedProcess([], 0, '4294967296\n')) as probe:
            self.assertIsNone(total_memory_kib())
            probe.assert_not_called()
            self.assertEqual(total_memory_kib(native_fallback=True), 4194304)
            probe.assert_called_once_with(['sysctl', '-n', 'hw.memsize'], check=True, capture_output=True, text=True)
            # A Linux host without /proc/meminfo has no sysctl hw.memsize either: memory stays unknown.
            for failure in (FileNotFoundError('sysctl'), subprocess.CalledProcessError(1, 'sysctl')):
                probe.side_effect = failure
                self.assertIsNone(total_memory_kib(native_fallback=True))

    def test_logging_action_reports_the_selected_stacks_log_queue_budget(self):
        import io, json
        from contextlib import redirect_stdout
        from chronicle_ops.host_memory import LOG_EVENT_ESTIMATE_BYTES, MEMORY_HEADROOM_BYTES, host_memory
        for events, warned in ((MEMORY_HEADROOM_BYTES // LOG_EVENT_ESTIMATE_BYTES, False), (1048576, True)):
            # Synchronous fluentd logging queues nothing in Docker, so it never counts against the headroom.
            config = {'services': {'backend': {'logging': {'driver': 'fluentd', 'options': {
                'fluentd-async': 'true', 'fluentd-buffer-limit': str(events)}}},
                'web': {'logging': {'driver': 'fluentd', 'options': {'fluentd-buffer-limit': '1048576'}}}}}
            rendered = subprocess.CompletedProcess([], 0, json.dumps(config))
            with self.subTest(events=events), patch('chronicle_ops.common.compose', return_value=rendered), \
                 redirect_stdout(io.StringIO()) as output:
                self.assertEqual(0, host_memory('logging'))
                self.assertEqual(warned, 'Docker pending log messages need' in output.getvalue())


class LauncherMemoryTests(SelfhostSetupFixture):
    def install_host_tools(self, meminfo):
        self.environment.update(CHRONICLE_MEMINFO=str(meminfo), DOCKER_FIXTURE_ROOT=str(self.host.parent))
        self.run_setup()
        tools = self.host.parent / 'bin'
        (tools / 'docker').write_text('''#!/usr/bin/env python3
import os
import sys
args = sys.argv[1:]
if args == ['compose', 'ls', '--all', '--format', 'json']:
    print('[]')
elif args[:2] == ['compose', 'version']:
    print('2.39.1')
elif args[:1] == ['info'] and '--format' in args:
    print(os.environ['DOCKER_FIXTURE_ROOT'])
elif args[-3:] == ['config', '--format', 'json']:
    print(os.environ.get('DOCKER_FIXTURE_CONFIG', '{}'))
elif args[-1:] == ['config-guard']:
    print('config-guard fixture')
''')
        (tools / 'ip').write_text('#!/bin/sh\nprintf "1: lo inet 127.0.0.1/8 scope host lo\\n"\n')
        (tools / 'timedatectl').write_text('#!/bin/sh\necho yes\n')
        (self.host / 'verify-config.sh').write_text('#!/bin/sh\nexit 0\n')
        for path in (self.host.parent, self.host, *self.host.rglob('*')):
            if path.name != '.env':
                path.chmod(0o755 if path.is_dir() or path.stat().st_mode & 0o111 else 0o644)
        (tools / 'timedatectl').chmod(0o755)

    def check(self):
        result = run(['bash', str(self.host / 'chronicle'), 'check'], env=self.environment,
                     capture=True, stderr=subprocess.PIPE, timeout=20)
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        return result

    def test_check_keeps_host_checks_before_config_guard_and_warns_only_below_minimum(self):
        from chronicle_ops.host_memory import MIN_MEMORY_KIB
        meminfo = self.host.parent / 'meminfo'
        meminfo.write_text('MemTotal: 3900000 kB\n')
        self.install_host_tools(meminfo)
        for memory, warning in ((MIN_MEMORY_KIB - 1, True), (MIN_MEMORY_KIB, False)):
            meminfo.write_text(f'MemTotal: {memory} kB\n')
            result = self.check()
            self.assertEqual('below the 4 GB minimum' in result.stderr, warning)
            self.assertLess(result.stdout.index('state, Docker data and database filesystems'),
                            result.stdout.index('internal config contract intact'))
            self.assertLess(result.stdout.index('internal config contract intact'),
                            result.stdout.index('config-guard fixture'))

    def test_check_validates_the_log_queue_budget_whenever_monitoring_is_enabled(self):
        # `up` runs the same preflight before starting anything (selfhost/chronicle cmd_up).
        import json
        from chronicle_ops.envfile import set_env_values
        meminfo = self.host.parent / 'meminfo'
        meminfo.write_text('MemTotal: 16000000 kB\n')
        self.install_host_tools(meminfo)
        self.environment['DOCKER_FIXTURE_CONFIG'] = json.dumps({'services': {'backend': {'logging': {
            'driver': 'fluentd', 'options': {'fluentd-async': 'true', 'fluentd-buffer-limit': '1048576'}}}}})
        settings = self.host / '.env'
        compose_file = next(line.split('=', 1)[1] for line in settings.read_text().splitlines() if line.startswith('COMPOSE_FILE='))
        for monitoring in (False, True):
            names = [name for name in compose_file.strip("'\"").split(':') if name != 'overlays/monitoring.yml']
            names += ['overlays/monitoring.yml'] if monitoring else []
            settings.write_text(set_env_values(settings.read_text(), {'COMPOSE_FILE': ':'.join(names)}, require_existing=True))
            with self.subTest(monitoring=monitoring):
                self.assertEqual(monitoring, 'Docker pending log messages need' in self.check().stderr)

    def test_setup_on_a_4_gib_host_writes_the_shipped_small_host_limits(self):
        from chronicle_ops.envfile import read_env, value
        from chronicle_ops.host_memory import SMALL_HOST_LIMITS
        meminfo = self.host.parent / 'meminfo'
        meminfo.write_text('MemTotal: 4194304 kB\n')
        self.environment['CHRONICLE_MEMINFO'] = str(meminfo)
        self.assertIn('sized backend/Postgres limits for a 4 GB host', self.run_setup().stdout)
        settings = read_env(self.host / '.env')
        self.assertEqual(SMALL_HOST_LIMITS, {key: value(settings, key) for key in SMALL_HOST_LIMITS})
