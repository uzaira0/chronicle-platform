#!/usr/bin/env python3
"""scripts/web_dependency_age.py: an unmaintained direct web dependency fails deps-freshness."""
import datetime as dt
import importlib.util
import json
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('web_dependency_age', ROOT / 'scripts/web_dependency_age.py')
age = importlib.util.module_from_spec(spec)
spec.loader.exec_module(age)

TODAY = dt.date(2026, 11, 1)
POLICY = {'web_max_release_age_days': 1095, 'web_stale_accepted': []}
# license-checker's newest release (and only current one) is 25.0.1, published 2019-01-10.
RELEASES = {'license-checker': ('25.0.1', dt.date(2019, 1, 10)), 'clsx': ('2.1.1', dt.date(2024, 4, 23)),
            'react': ('19.3.1', dt.date(2026, 10, 14))}


class AgeRuleTests(unittest.TestCase):
    def test_a_dependency_over_the_age_limit_fails_and_fresh_ones_pass(self):
        found = age.problems(RELEASES, POLICY, TODAY)
        self.assertEqual(1, len(found))
        self.assertTrue(found[0].startswith('license-checker: newest release 25.0.1 is 2852 days old'))

    def test_the_limit_is_inclusive_of_its_last_day(self):
        releases = {'edge': ('1.0.0', TODAY - dt.timedelta(days=1095))}
        self.assertEqual([], age.problems(releases, POLICY, TODAY))
        releases = {'edge': ('1.0.0', TODAY - dt.timedelta(days=1096))}
        self.assertEqual(1, len(age.problems(releases, POLICY, TODAY)))

    def test_an_acceptance_with_a_reason_and_a_future_expiry_passes(self):
        policy = dict(POLICY, web_stale_accepted=[{'name': 'license-checker', 'reason': 'replacement in review',
                                                    'expires': '2026-12-01'}])
        self.assertEqual([], age.problems(RELEASES, policy, TODAY))

    def test_an_acceptance_cannot_rot(self):
        cases = {
            'expired': ({'name': 'license-checker', 'reason': 'r', 'expires': '2026-10-31'}, 'expired on 2026-10-31'),
            'no reason': ({'name': 'license-checker', 'reason': ' ', 'expires': '2026-12-01'}, 'has no reason'),
            'no expiry': ({'name': 'license-checker', 'reason': 'r'}, 'no valid expires date'),
            'not stale': ({'name': 'react', 'reason': 'r', 'expires': '2026-12-01'}, 'names no stale direct dependency'),
        }
        for label, (entry, message) in cases.items():
            with self.subTest(label):
                found = age.problems(RELEASES, dict(POLICY, web_stale_accepted=[entry]), TODAY)
                self.assertTrue(any(message in line for line in found), found)


class SourceParsingTests(unittest.TestCase):
    def test_deps_dev_default_version_is_the_latest(self):
        document = {'versions': [
            {'versionKey': {'version': '3.0.0-beta'}, 'publishedAt': '2026-10-01T00:00:00Z', 'isDefault': False},
            {'versionKey': {'version': '2.1.1'}, 'publishedAt': '2024-04-23T12:00:00Z', 'isDefault': True}]}
        self.assertEqual(('2.1.1', dt.date(2024, 4, 23)), age.latest_from_deps_dev(document))
        with self.assertRaises(age.ReleaseLookupError):
            age.latest_from_deps_dev({'versions': []})

    def test_npm_dist_tag_latest_is_the_latest(self):
        document = {'dist-tags': {'latest': '25.0.1'}, 'time': {'25.0.1': '2019-01-10T18:56:33.000Z',
                                                                '26.0.0-rc': '2026-01-01T00:00:00.000Z'}}
        self.assertEqual(('25.0.1', dt.date(2019, 1, 10)), age.latest_from_npm(document))
        with self.assertRaises(age.ReleaseLookupError):
            age.latest_from_npm({'dist-tags': {}})

    def test_local_packages_are_not_registry_dependencies(self):
        package = {'dependencies': {'react': '19.3.1', '@eqds/css': 'file:vendor/equal/packages/css'},
                   'devDependencies': {'eslint': '^10.8.0'}}
        self.assertEqual(['eslint', 'react'], age.direct_dependencies(package))


class WiringTests(unittest.TestCase):
    def test_deps_freshness_runs_the_rule_against_the_manifest_policy(self):
        script = (ROOT / 'scripts/deps-freshness.sh').read_text()
        self.assertTrue('web_dependency_age.py' in script, 'scripts/deps-freshness.sh does not run web_dependency_age.py')
        policy = json.loads(subprocess.run(['yq', '-o=json', '.freshness', str(ROOT / 'toolchain-manifest.yaml')],
                                           capture_output=True, text=True, check=True).stdout)
        self.assertGreater(int(policy['web_max_release_age_days']), 0)
        self.assertIsInstance(policy.get('web_stale_accepted'), list)


if __name__ == '__main__':
    unittest.main()
