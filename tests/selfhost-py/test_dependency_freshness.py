"""Exercise complete package revisions through the shipped dependency reporter."""
import datetime
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[2]


class DependencyFreshnessTests(unittest.TestCase):
    def test_package_revision_changes_and_failed_lookups_cannot_report_current(self):
        pin = yaml.safe_load((ROOT / 'toolchain-manifest.yaml').read_text())['postgres']['image'].rsplit(':', 1)[1]
        version, revision = pin.rsplit('-', 1)
        latest = version + '-' + str(int(revision) + 1)
        with tempfile.TemporaryDirectory() as folder:
            commands = Path(folder)
            for mode in ('revision', 'ahead', 'missing'):
                observed = latest if mode == 'revision' else version + '-' + str(int(revision) - 1)
                scripts = {
                    'gh': '#!/bin/sh\nprintf v1.0.0\\n\n',
                    'curl': '#!/bin/sh\ncase "$*" in *percona/percona-distribution-postgresql*) '
                            + ('printf \'{"results":[{"name":"' + observed + '"}]}\'' if mode != 'missing' else 'exit 7')
                            + ';; *) printf "<version>1.0.0</version>";; esac\n',
                }
                for name, script in scripts.items():
                    path = commands / name
                    path.write_text(script)
                    path.chmod(0o755)
                result = subprocess.run(['bash', str(ROOT / 'scripts/deps-freshness.sh'), '--json'],
                    env=dict(os.environ, PATH=str(commands) + os.pathsep + os.environ['PATH']),
                    capture_output=True, text=True, timeout=30)
                rows, _ = json.JSONDecoder().raw_decode(result.stdout)
                postgres = next(row for row in rows if row['name'] == 'postgres-percona')
                self.assertEqual(mode == 'ahead', postgres['status'] == 'current')
                if mode == 'missing':
                    self.assertNotEqual(0, result.returncode)

    def test_a_newer_postgres_major_is_reported_major_behind(self):
        pin = yaml.safe_load((ROOT / 'toolchain-manifest.yaml').read_text())['postgres']['image'].rsplit(':', 1)[1]
        newer = str(int(pin.split('.', 1)[0]) + 1) + '.0.1-1'
        with tempfile.TemporaryDirectory() as folder:
            commands = Path(folder)
            # Docker Hub's name filter is a substring match; answer each query with the tags it would return.
            scripts = {
                'gh': '#!/bin/sh\nprintf v1.0.0\\n\n',
                'curl': '#!/bin/sh\ncase "$*" in *percona/percona-distribution-postgresql*name=' + newer.split('.')[0]
                        + '.*) printf \'{"results":[{"name":"' + newer + '"}]}\';; '
                        + '*percona/percona-distribution-postgresql*) printf \'{"results":[{"name":"' + pin + '"}]}\';; '
                        + '*) printf "<version>1.0.0</version>";; esac\n',
            }
            for name, script in scripts.items():
                path = commands / name
                path.write_text(script)
                path.chmod(0o755)
            result = subprocess.run(['bash', str(ROOT / 'scripts/deps-freshness.sh'), '--json'],
                env=dict(os.environ, PATH=str(commands) + os.pathsep + os.environ['PATH']),
                capture_output=True, text=True, timeout=30)
            rows, _ = json.JSONDecoder().raw_decode(result.stdout)
            postgres = next(row for row in rows if row['name'] == 'postgres-percona')
            self.assertEqual((newer, 'MAJOR-BEHIND'), (postgres['latest'], postgres['status']))

    def test_the_database_image_may_trail_a_newer_build_only_for_the_limit(self):
        # 2026-11-13: 18.6.1-4 against 18.7.1-1 was "minor-behind" and nothing else; the image scan has no
        # advisories for Percona's packages, so the report was the only place the lag showed.
        manifest = yaml.safe_load((ROOT / 'toolchain-manifest.yaml').read_text())
        pin = manifest['postgres']['image'].rsplit(':', 1)[1]
        limit = int(manifest['freshness']['database_max_lag_days'])
        version, revision = pin.rsplit('-', 1)
        newer = version + '-' + str(int(revision) + 1)
        with tempfile.TemporaryDirectory() as folder:
            commands = Path(folder)
            for days, fails in ((limit - 2, False), (limit + 5, True)):
                pushed = (datetime.datetime.now(datetime.UTC) - datetime.timedelta(days=days)).strftime('%Y-%m-%dT%H:%M:%SZ')
                answer = json.dumps({'results': [{'name': newer, 'tag_last_pushed': pushed}, {'name': pin}]})
                scripts = {
                    'gh': '#!/bin/sh\nprintf v1.0.0\\n\n',
                    'curl': '#!/bin/sh\ncase "$*" in *percona/percona-distribution-postgresql*) printf %s \''
                            + answer + '\';; *) printf "<version>1.0.0</version>";; esac\n',
                }
                for name, script in scripts.items():
                    path = commands / name
                    path.write_text(script)
                    path.chmod(0o755)
                with self.subTest(days=days):
                    result = subprocess.run(['bash', str(ROOT / 'scripts/deps-freshness.sh'), '--json'],
                        env=dict(os.environ, PATH=str(commands) + os.pathsep + os.environ['PATH']),
                        capture_output=True, text=True, timeout=60, check=False)
                    self.assertEqual(fails, '[fail] database image: ' + pin + ' has been behind ' + newer in result.stderr,
                                     result.stderr[-1500:])
                    self.assertIn('database image: ' + pin + ' is behind ' + newer, result.stderr)
                    if fails:
                        self.assertNotEqual(0, result.returncode)
