"""One default per setting across the shipped self-host files (AF-P7).

A setting's fallback is restated wherever it is read: `${NAME:-default}` in Compose files and
scripts, `: "${NAME:=default}"` in guard-config.sh, and `NAME=value` in .env.example, which is
what setup writes. When two of them disagree, the stack behaves differently depending on whether
the key is present in .env, and guard-config validates a value the services never use."""

import re
import unittest
from collections import defaultdict
from pathlib import Path
from typing import ClassVar

ROOT = Path(__file__).resolve().parents[2]
SELFHOST = ROOT / 'selfhost'
FALLBACK = re.compile(r'\$\{([A-Z][A-Z0-9_]*):?[-=]([^}]*)\}')
ASSIGNMENT = re.compile(r'([A-Z][A-Z0-9_]*)=(.*)$')

# Names whose differing literals are not alternative defaults of one setting. Each says why.
DIFFERENT_MEANINGS = {
    'DOMAIN': 'DOMAIN is required (docker-compose.yml ${DOMAIN:?}); chronicle.example.org is the placeholder '
              'setup replaces, localhost the in-container fallback, unknown a monitoring label',
    'RELEASE_VERSION': 'development marks a source checkout (guard-config); unknown is the label receipts and '
                       'probes print when no release is recorded',
    'COMPOSE_FILE': 'the launcher prints ${COMPOSE_FILE:-docker-compose.yml} as a label only',
    'CADDY_TRUSTED_PROXIES': '.env.example holds the answer setup gives a same-host proxy on the default subnet '
                             '(its gateway); unset falls back to loopback only, which trusts no Docker peer (W52)',
}


def shipped_files():
    for path in sorted(SELFHOST.rglob('*')):
        if not path.is_file() or 'docs' in path.relative_to(SELFHOST).parts:
            continue
        if path.suffix in ('.yml', '.yaml', '.sh', '.caddy') or path.name in ('chronicle', '.env.example') \
                or path.name.startswith('Caddyfile'):
            yield path


def literal(default):
    """A fixed value, or None for no default, a derived one, or a placeholder setup must replace."""
    default = default.strip().strip('\'"')
    if not default or '$' in default or default.startswith(('__CHRONICLE_', 'CHANGE_ME')) or default == '<empty>':
        return None
    return default


def defaults():
    found = defaultdict(lambda: defaultdict(list))
    for path in shipped_files():
        lines = path.read_text(encoding='utf-8', errors='replace').splitlines()
        for number, line in enumerate(lines, 1):
            where = f'{path.relative_to(SELFHOST)}:{number}'
            for match in FALLBACK.finditer(line):
                if (value := literal(match[2])) is not None:
                    found[match[1]][value].append(where)
            if (path.name == '.env.example' and (match := ASSIGNMENT.match(line))
                    and (value := literal(match[2])) is not None):
                found[match[1]][value].append(where)
    return found


class ConfigDefaultTests(unittest.TestCase):
    def test_every_setting_has_one_default_wherever_it_is_restated(self):
        conflicts = {name: dict(values) for name, values in defaults().items()
                     if len(values) > 1 and name not in DIFFERENT_MEANINGS}
        self.assertEqual({}, conflicts)

    def test_the_monitoring_defaults_the_audit_named_are_seen_in_every_place(self):
        found = defaults()
        self.assertEqual({'30d'}, set(found['METRICS_RETENTION']))
        self.assertGreaterEqual(len(found['METRICS_RETENTION']['30d']), 4)

    def test_every_exception_still_differs(self):
        found = defaults()
        for name in DIFFERENT_MEANINGS:
            with self.subTest(name=name):
                self.assertGreater(len(found[name]), 1, f'{name} no longer needs an exception')


if __name__ == '__main__':
    unittest.main()


class MonitoringStorageTests(unittest.TestCase):
    """AF-P3 and AF-P10: VictoriaMetrics has no byte cap of its own, so its free-space floor is
    what bounds it; and the metrics 'max' setting is an alert budget, so it is named one."""

    OLD: ClassVar[dict] = {'POSTGRES_PASSWORD': 'p', 'POSTGRES_APP_PASSWORD': 'q', 'JWT_SECRET': 'j' * 32, 'METRICS_PASSWORD': 'm' * 32,
           'CHRONICLE_INTERNAL_WEB_SECRET': 'w' * 32, 'GRAFANA_ADMIN_PASSWORD': 'g' * 32}

    def test_victoriametrics_stops_writing_before_an_update_would_be_refused(self):
        from chronicle_ops.common import (
            DEFAULT_MIN_FREE_DISK_GIB,
            GIB,
            UPDATE_PEAK_BYTES,
        )
        reserve = DEFAULT_MIN_FREE_DISK_GIB * GIB + UPDATE_PEAK_BYTES
        found = defaults()
        self.assertEqual({str(reserve)}, set(found['METRICS_MIN_FREE_DISK_BYTES']))
        monitoring = (SELFHOST / 'overlays/monitoring.yml').read_text()
        self.assertIn(f'--storage.minFreeDiskSpaceBytes=${{METRICS_MIN_FREE_DISK_BYTES:-{reserve}}}', monitoring)

    def test_the_metrics_budget_is_named_a_budget(self):
        found = defaults()
        self.assertNotIn('METRICS_MAX_DISK_BYTES', found)
        self.assertEqual({'5368709120'}, set(found['METRICS_DISK_BUDGET_BYTES']))
        self.assertNotIn('METADATA_REVISION', (ROOT / 'scripts/check-detekt-waiver-source.py').read_text())

    def test_update_moves_the_old_name_and_the_old_shipped_reserve(self):
        from chronicle_ops.common import (
            DEFAULT_MIN_FREE_DISK_GIB,
            GIB,
            UPDATE_PEAK_BYTES,
        )
        from chronicle_ops.env_migration import migrate_settings
        reserve = str(DEFAULT_MIN_FREE_DISK_GIB * GIB + UPDATE_PEAK_BYTES)
        old = dict(self.OLD, METRICS_MAX_DISK_BYTES='6442450944', METRICS_MIN_FREE_DISK_BYTES='2147483648')
        settings, notes = migrate_settings(old, lambda password: password)
        self.assertEqual('6442450944', settings['METRICS_DISK_BUDGET_BYTES'])
        self.assertNotIn('METRICS_MAX_DISK_BYTES', settings)
        self.assertEqual(reserve, settings['METRICS_MIN_FREE_DISK_BYTES'])
        self.assertTrue(any('METRICS_MIN_FREE_DISK_BYTES' in note for note in notes), notes)
        # An operator's own choice is never changed.
        kept, _ = migrate_settings(dict(self.OLD, METRICS_MIN_FREE_DISK_BYTES='12884901888'), lambda password: password)
        self.assertEqual('12884901888', kept['METRICS_MIN_FREE_DISK_BYTES'])

    def test_guard_warns_when_the_metrics_reserve_is_below_the_update_floor(self):
        import os
        import subprocess
        base = dict(os.environ, MONITORING_ENABLED='true', GRAFANA_ADMIN_PASSWORD='g' * 40)
        for floor_gib, reserve, warned in (('', '8589934592', False), ('', '2147483648', True), ('10', '8589934592', True),
                                           ('10', '13958643712', False)):
            with self.subTest(floor=floor_gib, reserve=reserve):
                result = subprocess.run(['bash', str(SELFHOST / 'guard-config.sh'), '--metrics-reserve'], capture_output=True,
                                        text=True, timeout=20, check=False, env=dict(base, MIN_FREE_DISK_GIB=floor_gib,
                                                                         METRICS_MIN_FREE_DISK_BYTES=reserve))
                self.assertEqual(0, result.returncode, result.stderr)
                self.assertEqual(warned, 'METRICS_MIN_FREE_DISK_BYTES' in result.stdout + result.stderr, result.stdout)
