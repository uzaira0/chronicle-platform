#!/usr/bin/env python3
"""scripts/frontend_license_policy.py: the frontend license gate refuses what the allowlist does not name."""
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('frontend_license_policy', ROOT / 'scripts/frontend_license_policy.py')
policy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(policy)

ALLOWED = frozenset({'MIT', 'ISC', 'Apache-2.0', 'BSD-3-Clause'})
PACKAGE = {'dependencies': {'react': '19.3.1', 'clsx': '2.1.1'}, 'devDependencies': {'eslint': '10.14.0'}}


def npm(name, *licenses, version='1.0.0'):
    return {'type': 'npm', 'name': name, 'version': version,
            'licenses': [{'value': value, 'spdxExpression': value} for value in licenses]}


class LicenseExpressionTests(unittest.TestCase):
    def test_a_single_identifier_must_be_listed(self):
        self.assertTrue(policy.permitted('MIT', ALLOWED))
        self.assertFalse(policy.permitted('MPL-2.0', ALLOWED))

    def test_or_needs_one_listed_operand_and_and_needs_all(self):
        self.assertTrue(policy.permitted('MPL-2.0 OR MIT', ALLOWED))
        self.assertTrue(policy.permitted('(MIT OR GPL-2.0-only) AND ISC', ALLOWED))
        self.assertFalse(policy.permitted('MIT AND SSPL-1.0', ALLOWED))
        self.assertFalse(policy.permitted('(MIT AND SSPL-1.0) OR BUSL-1.1', ALLOWED))

    def test_an_exception_is_allowed_only_as_the_listed_whole(self):
        self.assertFalse(policy.permitted('GPL-2.0-only WITH Classpath-exception-2.0', ALLOWED))
        self.assertTrue(policy.permitted('GPL-2.0-only WITH Classpath-exception-2.0',
                                         ALLOWED | {'GPL-2.0-only WITH Classpath-exception-2.0'}))

    def test_a_malformed_expression_is_an_error_not_a_pass(self):
        for expression in ('', 'MIT OR', '(MIT', 'MIT)', 'AND MIT',
                           'MIT OR ISC WITH )', 'MIT OR ISC WITH AND', 'MIT OR ISC WITH OR'):
            with self.subTest(expression=expression), self.assertRaises(policy.LicenseExpressionError):
                policy.permitted(expression, ALLOWED)


class CatalogTests(unittest.TestCase):
    def test_a_clean_production_catalog_passes(self):
        catalog = {'artifacts': [npm('react', 'MIT'), npm('clsx', 'MIT'), npm('scheduler', 'MIT')]}
        self.assertEqual([], policy.violations(catalog, PACKAGE, ALLOWED))

    def test_an_unlisted_license_is_refused_with_its_package(self):
        catalog = {'artifacts': [npm('react', 'MIT'), npm('clsx', 'MIT'), npm('axe-core', 'MPL-2.0', version='4.11.2')]}
        self.assertEqual(['axe-core@4.11.2: MPL-2.0'], policy.violations(catalog, PACKAGE, ALLOWED))

    def test_a_package_that_declares_no_license_is_refused(self):
        catalog = {'artifacts': [npm('react', 'MIT'), npm('clsx')]}
        self.assertEqual(['clsx@1.0.0: declares no license'], policy.violations(catalog, PACKAGE, ALLOWED))

    def test_a_production_dependency_the_scan_missed_is_refused(self):
        catalog = {'artifacts': [npm('react', 'MIT')]}
        self.assertEqual(['clsx: production dependency missing from the catalog'],
                         policy.violations(catalog, PACKAGE, ALLOWED))

    def test_an_empty_catalog_is_refused(self):
        self.assertEqual(1, len(policy.violations({'artifacts': []}, PACKAGE, ALLOWED)))

    def test_the_cli_exits_non_zero_on_a_violation(self):
        with tempfile.TemporaryDirectory() as work:
            catalog, package = Path(work) / 'catalog.json', Path(work) / 'package.json'
            catalog.write_text(json.dumps({'artifacts': [npm('react', 'MIT'), npm('clsx', 'BUSL-1.1')]}))
            package.write_text(json.dumps(PACKAGE))
            self.assertEqual(1, policy.main(['x', str(catalog), str(package), 'MIT;ISC']))
            catalog.write_text(json.dumps({'artifacts': [npm('react', 'MIT'), npm('clsx', 'ISC')]}))
            self.assertEqual(0, policy.main(['x', str(catalog), str(package), 'MIT;ISC']))


class GateWiringTests(unittest.TestCase):
    def test_production_install_uses_an_explicit_workspace_temporary_directory(self):
        work_root = ROOT / 'build' / 'frontend-license-tests'
        work_root.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=work_root) as directory:
            fixture = Path(directory)
            scripts = fixture / 'scripts'
            web = fixture / 'chronicle-web'
            tools = fixture / 'bin'
            for path in (scripts, web / 'vendor', tools):
                path.mkdir(parents=True)
            for name in ('check-frontend-licenses.sh', 'frontend_license_policy.py'):
                shutil.copyfile(ROOT / 'scripts' / name, scripts / name)
            (web / 'package.json').write_text(json.dumps(PACKAGE))
            for name in ('bun.lock', 'bunfig.toml'):
                (web / name).write_text('')
            (web / 'LICENSE').write_text('GNU GENERAL PUBLIC LICENSE')
            (tools / 'bun').write_text('#!/bin/sh\nif [ "$1" = -e ]; then echo GPL-3.0-or-later; fi\n')
            (tools / 'mktemp').write_text('#!/bin/sh\n[ "$#" -eq 2 ] && [ "$1" = -d ] && [ "$2" = "$FRONTEND_LICENSE_FIXTURE/build/frontend-licenses.XXXXXX" ] || { echo "explicit workspace template required" >&2; exit 91; }\nexec /usr/bin/mktemp "$@"\n')
            catalog = {'artifacts': [npm('react', 'MIT'), npm('clsx', 'MIT')]}
            (tools / 'syft').write_text(f'#!{sys.executable}\nimport pathlib, sys\noutput = next(arg.split("=", 1)[1] for arg in sys.argv if arg.startswith("syft-json="))\npathlib.Path(output).write_text({json.dumps(catalog)!r})\n')
            for path in tools.iterdir():
                path.chmod(0o755)
            environment = dict(os.environ, PATH=str(tools) + os.pathsep + os.environ['PATH'],
                               FRONTEND_LICENSE_FIXTURE=str(fixture))
            result = subprocess.run(['bash', str(scripts / 'check-frontend-licenses.sh')],
                                    env=environment, capture_output=True, text=True, timeout=20)
            self.assertEqual(0, result.returncode, result.stderr + result.stdout)

    def test_the_gate_no_longer_runs_the_unmaintained_license_checker(self):
        # license-checker 25.0.1 (2019-01-10) is the latest and only current release: unmaintained.
        package = json.loads((ROOT / 'chronicle-web/package.json').read_text())
        self.assertNotIn('license-checker', package.get('devDependencies', {}))
        self.assertNotIn('license-checker', package.get('dependencies', {}))
        script = (ROOT / 'scripts/check-frontend-licenses.sh').read_text()
        self.assertNotIn('license-checker', script)
        self.assertIn('frontend_license_policy.py', script)
        self.assertIn('--production', script)


if __name__ == '__main__':
    unittest.main()
