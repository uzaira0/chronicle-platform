#!/usr/bin/env python3
"""A test that loads a script by file location must put the module in sys.modules before running it.

On Python 3.12 and 3.13 (the floor is 3.12) a @dataclass with string annotations looks its module up in
sys.modules and fails with AttributeError when it is not there; 3.14 and later do not. The dependency
gate runs tests/quality on the gate image's Python 3.13, where three suites failed to import."""
from __future__ import annotations

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
# spec = importlib.util.spec_from_file_location('name', ROOT / 'scripts/x.py')
# module = importlib.util.module_from_spec(spec)
# <the next line>
LOAD = re.compile(r"^(\w+) = importlib\.util\.spec_from_file_location\([^,]+,\s*ROOT\s*/\s*'([^']+)'\)\n"
                  r"(\w+) = importlib\.util\.module_from_spec\(\1\)\n(?P<next>.*)$", re.MULTILINE)
DATACLASS = re.compile(r'^@(?:dataclasses\.)?dataclass\b', re.MULTILINE)


class SpecLoadedModuleTests(unittest.TestCase):
    def test_a_spec_loaded_module_with_dataclasses_is_registered_before_it_runs(self):
        unregistered, checked = [], 0
        for path in sorted((ROOT / 'tests').rglob('*.py')):
            text = path.read_text(encoding='utf-8', errors='replace')
            for match in LOAD.finditer(text):
                spec, target, module = match.group(1), ROOT / match.group(2), match.group(3)
                if not target.is_file() or not DATACLASS.search(target.read_text(encoding='utf-8')):
                    continue
                checked += 1
                if match.group('next').split('#', 1)[0].strip() != f'sys.modules[{spec}.name] = {module}':
                    unregistered.append(f'{path.relative_to(ROOT)}: {module} ({match.group(2)})')
        self.assertGreaterEqual(checked, 3)
        self.assertEqual([], unregistered)


if __name__ == '__main__':
    unittest.main()
