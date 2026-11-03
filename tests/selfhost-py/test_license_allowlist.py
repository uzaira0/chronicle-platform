"""config/allowed-licenses.json admits no license the FSF lists as GPL-incompatible.

The allowlist is what checkLicense (chronicle-server and chronicle/app) enforces for a GPL-3.0
project. It allowlisted single-license EPL-1.0, EPL-2.0 and CDDL, which the FSF license list
(gnu.org/licenses/license-list) calls incompatible with the GNU GPL; an EPL-2.0 library
(aspectjweaver) then passed into the shipped server. A dependency that is dual-licensed still
passes through its GPL-compatible option, which stays listed (GPL2 w/ CPE, MPL 2.0, Apache, EDL).
"""
from __future__ import annotations

import json
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ALLOWLIST = ROOT / 'config/allowed-licenses.json'

# Single licenses the FSF list names as incompatible with the GNU GPL. EPL-2.0 is compatible only
# with the "Secondary License" designation, which a bare license name does not carry.
INCOMPATIBLE = (
    ('EPL-1.0/2.0', re.compile(r'eclipse public licen[cs]e|\bepl\b', re.IGNORECASE)),
    ('CDDL-1.0/1.1', re.compile(r'common development and distribution licen[cs]e|\bcddl\b', re.IGNORECASE)),
    ('Apache-1.1', re.compile(r'apache(?: software)? licen[cs]e,? (?:version )?1\.1|\bapache-1\.1\b', re.IGNORECASE)),
)
# A name that also offers the GPL (dual licensing) is not a single incompatible license.
DUAL_WITH_GPL = re.compile(r'\bGPL', re.IGNORECASE)


def incompatible(license_name: str) -> str | None:
    if DUAL_WITH_GPL.search(license_name):
        return None
    for label, pattern in INCOMPATIBLE:
        if pattern.search(license_name):
            return label
    return None


class LicenseAllowlistTests(unittest.TestCase):
    def test_the_classifier_recognizes_the_incompatible_spellings(self):
        for name in ('Eclipse Public License 1.0', 'Eclipse Public License - v 2.0', 'Eclipse Public License v. 2.0',
                     'EPL 2.0', 'Common Development and Distribution License 1.1', 'CDDL 1.0',
                     'The Apache Software License, Version 1.1', 'Apache-1.1'):
            with self.subTest(name=name):
                self.assertIsNotNone(incompatible(name))
        for name in ('CDDL+GPL License', 'CDDL/GPLv2+CE', 'Dual license consisting of the CDDL v1.1 and GPL v2',
                     'Eclipse Distribution License - v 1.0', 'EDL 1.0', 'Apache License, Version 2.0',
                     'GNU General Public License, version 2 with the GNU Classpath Exception', 'MPL 2.0'):
            with self.subTest(name=name):
                self.assertIsNone(incompatible(name))

    def test_the_allowlist_admits_no_gpl_incompatible_single_license(self):
        allowlist = json.loads(ALLOWLIST.read_text())
        self.assertIn('GPL-3.0', allowlist['$schema'])
        refused = [(entry['moduleLicense'], incompatible(entry['moduleLicense']))
                   for entry in allowlist['allowedLicenses']
                   if 'moduleLicense' in entry and incompatible(entry['moduleLicense'])]
        self.assertEqual([], refused)


if __name__ == '__main__':
    unittest.main()
