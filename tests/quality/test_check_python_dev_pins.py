#!/usr/bin/env python3
"""scripts/check-python-dev-pins.py: the PyYAML/openpyxl a host runs must be the hashed versions in
requirements-dev.txt, and no repo Python may import a third-party module the lock does not pin."""

import importlib.util
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('check_python_dev_pins', ROOT / 'scripts/check-python-dev-pins.py')
pins = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pins)

LOCK = """\
pyyaml==6.0.3 \\
    --hash=sha256:aaaa \\
    --hash=sha256:bbbb
    # direct
openpyxl==3.1.5 \\
    --hash=sha256:cccc
"""


class PinnedVersionTests(unittest.TestCase):
    def test_lock_entries_are_read_with_their_hashes(self):
        self.assertEqual(pins.parse_lock(LOCK), {'pyyaml': ('6.0.3', 2), 'openpyxl': ('3.1.5', 1)})

    def test_an_entry_without_a_hash_is_refused(self):
        with self.assertRaisesRegex(ValueError, 'openpyxl.*--hash'):
            pins.parse_lock('openpyxl==3.1.5\n')

    def test_an_unpinned_entry_is_refused(self):
        with self.assertRaisesRegex(ValueError, 'pyyaml>=6'):
            pins.parse_lock('pyyaml>=6 \\\n    --hash=sha256:aaaa\n')

    def test_matching_versions_pass(self):
        installed = {'pyyaml': '6.0.3', 'openpyxl': '3.1.5'}.get
        self.assertEqual(pins.version_problems(pins.parse_lock(LOCK), installed), [])

    def test_a_different_installed_version_fails_and_names_the_install_command(self):
        installed = {'pyyaml': '5.4.1', 'openpyxl': '3.1.5'}.get
        problems = pins.version_problems(pins.parse_lock(LOCK), installed)
        self.assertEqual(len(problems), 1)
        self.assertIn('pyyaml 5.4.1 is installed, requirements-dev.txt pins 6.0.3', problems[0])
        self.assertIn('--require-hashes -r requirements-dev.txt', problems[0])

    def test_a_missing_package_fails(self):
        installed = {'pyyaml': '6.0.3'}.get
        self.assertEqual(pins.version_problems(pins.parse_lock(LOCK), installed),
                         [f'openpyxl is not installed; requirements-dev.txt pins 3.1.5 ({pins.INSTALL_HINT})'])


class UnpinnedImportTests(unittest.TestCase):
    def tree(self, files):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        root = Path(folder.name)
        for name, text in files.items():
            (root / name).parent.mkdir(parents=True, exist_ok=True)
            (root / name).write_text(text)
        return root, sorted(files)

    def test_stdlib_local_and_pinned_imports_pass(self):
        root, files = self.tree({
            'scripts/a.py': 'import json\nimport yaml\nfrom openpyxl import Workbook\nimport helper\n',
            'scripts/helper.py': 'import os\n',
            'tests/pkg/__init__.py': '', 'tests/b.py': 'from pkg import thing\nfrom . import sibling\n',
        })
        self.assertEqual(pins.unpinned_imports(root, files, {'pyyaml', 'openpyxl'}), {})

    def test_a_third_party_import_missing_from_the_lock_is_reported_with_its_files(self):
        root, files = self.tree({'scripts/a.py': 'import requests\nimport yaml\n', 'tests/c.py': 'import requests.adapters\n'})
        self.assertEqual(pins.unpinned_imports(root, files, {'pyyaml'}), {'requests': ['scripts/a.py', 'tests/c.py']})

    def test_python39_discovers_stdlib_without_accepting_installed_third_party_modules(self):
        root, files = self.tree({'scripts/a.py': 'import sys, json, _ssl, openpyxl, requests\n'})
        with mock.patch.object(pins.sys, 'stdlib_module_names', None, create=True):
            self.assertEqual(pins.unpinned_imports(root, files, {'openpyxl'}), {'requests': ['scripts/a.py']})

    def test_the_shipped_lock_pins_every_third_party_import_in_the_repo(self):
        lock = pins.parse_lock((ROOT / 'requirements-dev.txt').read_text())
        self.assertEqual(pins.unpinned_imports(ROOT, pins.tracked_python_files(ROOT), set(lock)), {})


if __name__ == '__main__':
    unittest.main()
