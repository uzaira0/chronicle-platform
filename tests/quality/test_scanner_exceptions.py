"""The fix round removes dormant scanner waivers without allowing new ones."""

import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]


class ScannerExceptionsTest(unittest.TestCase):
    def test_grype_has_no_dormant_ignore_rules(self):
        config = yaml.safe_load((ROOT / ".grype.yaml").read_text())
        self.assertEqual([], config.get("ignore", []), "Remove scanner waivers; fix resolved vulnerable packages")


if __name__ == "__main__":
    unittest.main()
