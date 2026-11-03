#!/usr/bin/env python3
"""scripts/check-duplication.py: new and stale clone groups both fail; updating only shrinks."""

from collections import Counter
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('check_duplication', ROOT / 'scripts/check-duplication.py')
duplication = importlib.util.module_from_spec(spec)
spec.loader.exec_module(duplication)

KEPT = ('kotlin', 80, ('a.kt', 'b.kt'))
GONE = ('kotlin', 90, ('c.kt', 'd.kt'))
NEW = ('python', 75, ('e.py', 'f.py'))


class CheckDuplicationTests(unittest.TestCase):
    def run_gate(self, baseline, current, *arguments):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'baseline.jsonl'
            path.write_text(''.join(json.dumps(key) + '\n' for key in baseline))
            locations = {key: ['x:1'] for key in current}
            with patch.object(duplication, 'BASELINE', path), \
                 patch.object(duplication, 'ROOT', Path(folder)), \
                 patch.object(duplication, 'scan', return_value=(Counter(current), locations)), \
                 patch('sys.argv', ['check-duplication.py', *arguments]), \
                 contextlib.redirect_stdout(io.StringIO()) as output:
                status = duplication.main()
            written = [tuple(entry[:2]) + (tuple(entry[2]),) for entry in map(json.loads, path.read_text().splitlines())]
        return status, output.getvalue(), written

    def test_matching_baseline_passes(self):
        self.assertEqual(0, self.run_gate([KEPT], [KEPT])[0])

    def test_new_clone_fails(self):
        status, output, _ = self.run_gate([KEPT], [KEPT, NEW])
        self.assertEqual(1, status)
        self.assertIn('NEW clone (python', output)

    def test_stale_entry_fails(self):
        status, output, _ = self.run_gate([KEPT, GONE], [KEPT])
        self.assertEqual(1, status)
        self.assertIn('STALE baseline entry (kotlin, 90 tokens', output)

    def test_update_drops_stale_entries_and_never_adds_new_clones(self):
        status, _, written = self.run_gate([KEPT, GONE], [KEPT, NEW], '--update-baseline')
        self.assertEqual(0, status)
        self.assertEqual([KEPT], written)


if __name__ == '__main__':
    unittest.main()
