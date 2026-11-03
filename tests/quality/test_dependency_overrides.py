"""The stale forces found in the release audit must not return."""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[2]


class DependencyOverrideTests(unittest.TestCase):
    def test_removed_dependencies_cannot_hold_the_framework_back(self):
        source = (ROOT / "gradles/chronicle.gradle").read_text()
        for coordinate in ("com.google.protobuf:protobuf-java", "io.micrometer:micrometer-"):
            self.assertIsNone(re.search(r"\bforce\s+['\"]" + re.escape(coordinate), source), coordinate)


if __name__ == "__main__":
    unittest.main()
