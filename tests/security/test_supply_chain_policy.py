"""Parse temporary XML against the shipped suppression policy."""

import datetime
from pathlib import Path
import runpy
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
CHECKER = ROOT / "tests/security/check-dependency-check-suppressions.py"
MAX_DAYS = runpy.run_path(str(CHECKER))['MAX_DAYS']


class SuppressionPolicyTests(unittest.TestCase):
    def check(self, rules, expected, problem=None):
        with tempfile.TemporaryDirectory() as directory:
            fixture = Path(directory)
            for module, coordinate in (('server', 'org.resolved:library:4.2.0'),
                                       ('android/app', 'org.resolved:nested:5.0.0'),
                                       ('another/module', 'org.resolved:transitive:6.0.0')):
                lock = fixture / module / 'gradle.lockfile'
                lock.parent.mkdir(parents=True)
                lock.write_text('# Gradle generated dependency lock\n\n' + coordinate
                                + '=runtimeClasspath,testRuntimeClasspath\nempty=compileClasspath\n')
            xml = fixture / "waivers.xml"
            xml.write_text('<suppressions xmlns="https://jeremylong.github.io/DependencyCheck/dependency-suppression.1.3.xsd">'
                           + rules + '</suppressions>')
            result = subprocess.run([sys.executable, '-s', str(CHECKER), str(xml), str(fixture)],
                                    text=True, capture_output=True, timeout=10)
            self.assertEqual(expected, result.returncode, result.stdout + result.stderr)
            if problem:
                self.assertIn(problem, result.stdout + result.stderr)

    def rule(self, *, until=None, package="pkg:maven/org.bundled/library@1.0.0", advisory='<vulnerabilityName regex="true">.*</vulnerabilityName>'):
        expiry = '' if until is None else f' until="{until}"'
        return f'<suppress{expiry}><packageUrl regex="true">{package}</packageUrl>{advisory}</suppress>'

    def test_removed_and_other_reviewed_bundled_waivers_pass(self):
        self.check('', 0)
        self.check(self.rule(until=self.soon), 0)
        self.check(self.rule(until=self.soon, advisory=''), 0)
        self.check(self.rule(until=(self.today + datetime.timedelta(days=MAX_DAYS)).isoformat()), 0)
        self.check(self.rule(until=self.soon, package='pkg:maven/org.resolved/library@1.0.0'), 0)

    def test_missing_invalid_expired_and_distant_dates_fail(self):
        for until in (None, 'not-a-date', self.today.isoformat(),
                      (self.today - datetime.timedelta(days=1)).isoformat(),
                      (self.today + datetime.timedelta(days=MAX_DAYS + 1)).isoformat()):
            with self.subTest(until=until):
                self.check(self.rule(until=until), 1, 'until')

    def test_resolved_nested_and_transitive_coordinates_fail(self):
        for package in ('pkg:maven/org.resolved/nested@5.0.0',
                        'pkg:maven/org.resolved/library@4.2.0',
                        'pkg:maven/org.resolved/transitive@6.0.0', '.*'):
            for advisory in ('', '<vulnerabilityName regex="true">^.*$</vulnerabilityName>'):
                with self.subTest(package=package, advisory=advisory):
                    self.check(self.rule(until=self.soon, package=package, advisory=advisory), 1,
                               'matches resolved dependency')

    def test_wide_gav_and_unrestricted_package_selectors_fail(self):
        self.check(self.rule(until=self.soon).replace('<packageUrl regex="true">pkg:maven/org.bundled/library@1.0.0</packageUrl>',
                                                     '<gav regex="true">org.resolved:.*</gav>'), 1,
                   'matches resolved dependency')
        self.check(f'<suppress until="{self.soon}"><vulnerabilityName regex="true">.*</vulnerabilityName></suppress>',
                   1, 'matches resolved dependency')

    def test_specific_advisory_needs_no_package_wide_expiry(self):
        self.check(self.rule(package='pkg:maven/org.resolved/library@4.2.0',
                             advisory='<cve>CVE-2099-12345</cve>'), 0)

    def setUp(self):
        self.today = datetime.datetime.now(datetime.timezone.utc).date()
        self.soon = (self.today + datetime.timedelta(days=22)).isoformat() + 'Z'


if __name__ == '__main__':
    unittest.main()
