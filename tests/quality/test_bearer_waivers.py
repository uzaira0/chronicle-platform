#!/usr/bin/env python3
"""scripts/check-bearer-waivers.py: a waiver passes only for the statement that was recorded for it."""

import contextlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('check_bearer_waivers', ROOT / 'scripts/check-bearer-waivers.py')
waivers = importlib.util.module_from_spec(spec)
spec.loader.exec_module(waivers)

FILE = 'forward/main.go'
RULE = 'go_lang_logger_leak'
NAME = 'ccd0f053ee9a598e6a8dba5924410a98'
FORWARD = '''package main

func main() {
	route, err := parseMapping(argument)
	if err != nil {
		log.Fatal(err)
	}
	address, err := net.ResolveTCPAddr("tcp", ":"+route.listen)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("listening on :%s for %s",
		route.listen, route.upstream)
}
'''
CHECK_ONLY = '''	if err := check(routes); err != nil {
		log.Fatal(err)
	}
'''


def scan(root):
    """A Bearer JSON report of the fixture with no waiver applied: every log call is a finding, named as
    Bearer names it, by its position among the findings of the file."""
    items = []
    for number, line in enumerate((root / FILE).read_text().splitlines(), 1):
        if line.strip().startswith('log.'):
            extent = {'start': number, 'end': number + line.rstrip().endswith(',')}
            items.append({'id': RULE, 'filename': FILE, 'line_number': number, 'fingerprint': f'{NAME}_{len(items)}',
                          'source': extent, 'sink': extent})
    report = root / 'report.json'
    report.write_text(json.dumps({'critical': [], 'low': items}))
    return report


class BearerWaiverTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.root = Path(folder.name)
        (self.root / FILE).parent.mkdir()
        (self.root / 'tests/security').mkdir(parents=True)
        (self.root / FILE).write_text(FORWARD)
        self.waive(0, 1, 2)
        self.assertEqual((True, 3), (self.check('--write')[0], len(self.recorded())))

    def waive(self, *positions):
        (self.root / 'bearer.ignore').write_text(json.dumps(
            {f'{NAME}_{position}': {'comment': 'reviewed', 'false_positive': True} for position in positions}))

    def recorded(self):
        return json.loads((self.root / 'tests/security/bearer-waiver-sources.json').read_text())

    def check(self, *arguments):
        output = io.StringIO()
        with patch('sys.argv', ['check-bearer-waivers.py', '--root', str(self.root), '--findings', str(scan(self.root)),
                                *arguments]), contextlib.redirect_stdout(output):
            try:
                waivers.main()
            except ValueError as error:
                return False, output.getvalue() + str(error)
        return True, output.getvalue()

    def edit(self, old, new):
        source = (self.root / FILE).read_text()
        self.assertEqual(1, source.count(old))
        (self.root / FILE).write_text(source.replace(old, new))

    def test_the_record_holds_the_statement_and_the_lines_that_tell_it_from_an_identical_one(self):
        recorded = self.recorded()
        self.assertEqual({'rule': RULE, 'file': FILE, 'above': ['route, err := parseMapping(argument)', 'if err != nil {'],
                          'statement': ['log.Fatal(err)']}, recorded[NAME + '_0'])
        self.assertEqual(recorded[NAME + '_0']['statement'], recorded[NAME + '_1']['statement'])
        self.assertNotEqual(recorded[NAME + '_0'], recorded[NAME + '_1'])
        self.assertEqual(['log.Printf("listening on :%s for %s",', 'route.listen, route.upstream)'],
                         recorded[NAME + '_2']['statement'])
        passed, output = self.check()
        self.assertTrue(passed, output)
        self.assertIn('3 waivers, each covers the statement recorded for it', output)

    def test_a_statement_that_only_moved_still_passes(self):
        self.edit('package main\n', 'package main\n\n// Forward TCP.\n// One listener per mapping.\n')
        self.assertTrue(*self.check())

    def test_a_flagged_statement_added_above_fails_every_waiver_it_moved(self):
        self.edit('func main() {\n', 'func main() {\n' + CHECK_ONLY)
        passed, output = self.check()
        self.assertFalse(passed)
        # Bearer alone reports only the last statement, which was reviewed, as the new finding.
        self.assertIn(f'{NAME}_3: {FILE}:15 ({RULE}) has no waiver', output)
        self.assertIn(f'{NAME}_0: the waiver now covers {FILE}:5 ({RULE})\n'
                      '      func main() {\n      if err := check(routes); err != nil {\n    > log.Fatal(err)\n'
                      f'  and was reviewed for {FILE} ({RULE})\n'
                      '      route, err := parseMapping(argument)\n      if err != nil {\n    > log.Fatal(err)\n'
                      f'  which is now {NAME}_1 at {FILE}:9', output)
        self.assertIn(f'  which is now {NAME}_2 at {FILE}:13', output)
        self.assertIn(f'  which is now {NAME}_3 at {FILE}:15', output)
        self.assertIn('4 Bearer waiver(s) do not match the scan', output)
        # Waiving the reported finding, as was done on 2026-11-06, leaves the three moved waivers failing.
        self.waive(0, 1, 2, 3)
        passed, output = self.check()
        self.assertFalse(passed)
        self.assertIn(f'{NAME}_3: the waiver of {FILE}:15 has no recorded statement', output)
        self.assertEqual(3, output.count(': the waiver now covers '))
        before = self.recorded()
        passed, output = self.check('--write')
        self.assertTrue(passed, output)
        self.assertEqual([f'recorded {NAME}_{position} {FILE}:{line}' for position, line in enumerate((5, 9, 13, 15))],
                         [line for line in output.splitlines() if line.startswith('recorded ')])
        self.assertEqual(before[NAME + '_2'], self.recorded()[NAME + '_3'])
        self.assertTrue(*self.check())

    def test_an_edited_statement_or_edited_lines_above_it_fail(self):
        self.edit('route.listen, route.upstream)', 'route.listen, route.password)')
        passed, output = self.check()
        self.assertFalse(passed)
        self.assertIn(f'{NAME}_2: the waiver now covers {FILE}:12', output)
        self.assertIn('    > route.listen, route.password)', output)
        self.assertIn('    > route.listen, route.upstream)\n  which the scan no longer reports', output)
        self.assertIn('1 Bearer waiver(s) do not match the scan', output)
        (self.root / FILE).write_text(FORWARD)
        self.edit('route, err := parseMapping(argument)', 'route, err := parseSecret(argument)')
        passed, output = self.check()
        self.assertFalse(passed)
        self.assertIn(f'{NAME}_0: the waiver now covers {FILE}:6', output)
        self.assertIn('1 Bearer waiver(s) do not match the scan', output)

    def test_a_waiver_without_a_finding_and_a_record_without_a_waiver_fail(self):
        self.edit('\tlog.Printf("listening on :%s for %s",\n\t\troute.listen, route.upstream)\n', '')
        passed, output = self.check()
        self.assertFalse(passed)
        self.assertIn(f'{NAME}_2: stale waiver, the scan has no finding with this name', output)
        # --write cannot record a statement that is gone, and does not pass over the stale waiver.
        passed, output = self.check('--write')
        self.assertFalse(passed)
        self.assertEqual([NAME + '_0', NAME + '_1'], list(self.recorded()))
        (self.root / FILE).write_text(FORWARD)
        self.assertEqual((True, 3), (self.check('--write')[0], len(self.recorded())))
        self.waive(0, 1)
        passed, output = self.check()
        self.assertFalse(passed)
        self.assertIn(f'{NAME}_2: {FILE}:12 ({RULE}) has no waiver', output)
        self.assertIn(f'{NAME}_2: a recorded statement without a waiver in bearer.ignore', output)

    def test_a_report_of_another_tree_or_another_format_is_refused(self):
        report = scan(self.root)
        (self.root / FILE).write_text('package main\n')
        other = self.root / 'other.json'
        for content, message in ((report.read_text(), f'{FILE}:6: the report does not belong to this tree'),
                                 ('{"runs": [{"results": []}], "version": "2.1.0"}', 'not a Bearer JSON report')):
            other.write_text(content)
            with patch('sys.argv', ['check-bearer-waivers.py', '--root', str(self.root), '--findings', str(other)]), \
                 self.assertRaisesRegex(ValueError, message):
                waivers.main()

    def test_every_waiver_of_this_repository_has_its_reviewed_statement_in_the_tree(self):
        ignored = json.loads((ROOT / waivers.IGNORE).read_text())
        sources = json.loads((ROOT / waivers.SOURCES).read_text())
        self.assertEqual(sorted(ignored), sorted(sources))
        for name, entry in sources.items():
            lines = [line.strip() for line in (ROOT / entry['file']).read_text().splitlines()]
            size = len(entry['statement'])
            places = [at for at in range(len(lines)) if lines[at:at + size] == entry['statement']
                      and [line for line in lines[:at] if line][-waivers.LINES_ABOVE:] == entry['above']]
            self.assertTrue(places, f'{name}: {entry["file"]} no longer holds the statement recorded for this waiver; '
                                    'read the new statement, then scripts/check-bearer-waivers.py --write')


if __name__ == '__main__':
    unittest.main()
