#!/usr/bin/env python3
"""gradle-depcheck says how old its NVD database is and refuses a stale or undated one.

With SKIP_NVD_UPDATE=1 (the dependency gate runner's security step, which has no NVD key and gets a
copy of the workstation's database) the job used to scan with whatever database it found: one last
updated weeks ago passed exactly like a fresh one. Dependency-Check keeps its last update time inside
its H2 database, which nothing outside the JVM reads, so a successful update now records the time in
chronicle-nvd-updated-utc next to the database, and a cache-only run prints that time and its age and
exits 2 when the record is missing or older than CHRONICLE_DEPCHECK_MAX_AGE_HOURS (default 168).
"""
import datetime as dt
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
STAMP = 'chronicle-nvd-updated-utc'
# The gate runner's security step sets these for local-ci (dependency-gate-runner.py job_env); a test
# that inherited them ran its update case as a cache-only run (renovate/eclipse-temurin-25-jdk, 2026-11-08).
JOB_INPUTS = ('SKIP_NVD_UPDATE', 'CHRONICLE_DEPCHECK_MAX_AGE_HOURS', 'CHRONICLE_DEPCHECK_DATA_DIR')
# The job with the JVM, the Gradle runs and the report copy replaced: only the database checks run.
DRIVER = '''source "$1"
require_jdk21() { :; }
gradle() { printf 'gradle %s\\n' "$*"; }
run_with_timeout_logged() { printf 'update %s\\n' "${*:3}"; }
copy_dependency_check_reports() { :; }
job_gradle_depcheck
'''


class DepcheckFreshnessTests(unittest.TestCase):
    def run_job(self, data: Path, **env):
        inherited = {name: value for name, value in os.environ.items() if name not in JOB_INPUTS}
        environment = dict(inherited, CHRONICLE_DEPCHECK_DATA_DIR=str(data), NVD_API_KEY='placeholder-not-a-key',
                           CHRONICLE_LOCAL_CI_REPORT_DIR=str(data.parent / 'reports'), **env)
        return subprocess.run(['bash', '-s', str(ROOT / 'scripts/local-ci.sh')], input=DRIVER, capture_output=True,
                              text=True, timeout=120, check=False, env=environment)

    def database(self, folder: str, updated: dt.datetime | None) -> Path:
        data = Path(folder) / 'nvd'
        data.mkdir()
        (data / 'odc.mv.db').write_bytes(b'h2' * 64)
        if updated is not None:
            (data / STAMP).write_text(updated.strftime('%Y-%m-%dT%H:%M:%SZ') + '\n')
        return data

    def test_a_cache_only_run_without_an_update_record_fails_and_says_why(self):
        with tempfile.TemporaryDirectory() as folder:
            result = self.run_job(self.database(folder, None), SKIP_NVD_UPDATE='1')
            self.assertEqual(2, result.returncode, result.stdout + result.stderr)
            self.assertIn('no record of when the NVD database', result.stderr)
            self.assertNotIn('gradle dependencyCheckAll', result.stdout)

    def test_a_stale_database_fails_with_its_age(self):
        with tempfile.TemporaryDirectory() as folder:
            old = dt.datetime.now(dt.UTC) - dt.timedelta(days=9)
            result = self.run_job(self.database(folder, old), SKIP_NVD_UPDATE='1')
            self.assertEqual(2, result.returncode, result.stdout + result.stderr)
            self.assertRegex(result.stderr, r'NVD database is stale: last updated \S+ \(21[56] hours ago; limit 168\)')
            self.assertNotIn('gradle dependencyCheckAll', result.stdout)

    def test_the_limit_is_configurable(self):
        with tempfile.TemporaryDirectory() as folder:
            old = dt.datetime.now(dt.UTC) - dt.timedelta(hours=30)
            result = self.run_job(self.database(folder, old), SKIP_NVD_UPDATE='1', CHRONICLE_DEPCHECK_MAX_AGE_HOURS='24')
            self.assertEqual(2, result.returncode, result.stdout + result.stderr)
            self.assertIn('limit 24', result.stderr)

    def test_a_fresh_database_scans_and_reports_its_age(self):
        with tempfile.TemporaryDirectory() as folder:
            recent = dt.datetime.now(dt.UTC) - dt.timedelta(hours=3)
            result = self.run_job(self.database(folder, recent), SKIP_NVD_UPDATE='1')
            self.assertEqual(0, result.returncode, result.stdout + result.stderr)
            self.assertRegex(result.stdout, r'NVD database last updated \S+ \([23] hours ago; limit 168\)')
            self.assertIn('gradle dependencyCheckAll', result.stdout)

    def test_a_successful_update_records_its_time(self):
        # As in the gate sandbox: the environment around the test is a cache-only run.
        with tempfile.TemporaryDirectory() as folder, mock.patch.dict(os.environ, SKIP_NVD_UPDATE='1',
                                                                       CHRONICLE_DEPCHECK_MAX_AGE_HOURS='1'):
            data = self.database(folder, None)
            before = dt.datetime.now(dt.UTC).replace(microsecond=0)
            result = self.run_job(data)
            self.assertEqual(0, result.returncode, result.stdout + result.stderr)
            self.assertIn('update', result.stdout)
            recorded = dt.datetime.strptime((data / STAMP).read_text().strip(), '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=dt.UTC)
            self.assertLessEqual(before, recorded)
            self.assertIn('gradle dependencyCheckAll', result.stdout)


if __name__ == '__main__':
    unittest.main()
