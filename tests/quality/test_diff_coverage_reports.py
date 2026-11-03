import contextlib
import importlib.util
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("diff_coverage", ROOT / "scripts/diff-coverage.py")
COVERAGE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(COVERAGE)


class CoverageReportTests(unittest.TestCase):
    def test_child_repository_reports_are_checked_in_the_child(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            child = root / "child"
            (child / ".git").mkdir(parents=True)
            report = child / "build/reports/jacoco/test/report.xml"
            report.parent.mkdir(parents=True)
            report.write_text("<report/>")
            self.assertEqual([], COVERAGE.reports_and_roots(root)[0])
            self.assertEqual([str(report)], COVERAGE.reports_and_roots(child)[0])

    def test_agp_reports_and_distribution_source_sets_are_discovered(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report = root / "app/build/reports/coverage/test/openDebug/report.xml"
            report.parent.mkdir(parents=True)
            report.write_text("<report/>")
            (root / "app/src/open/java/com/example").mkdir(parents=True)
            xml, _, sources = COVERAGE.reports_and_roots(root)
            self.assertEqual([str(report)], xml)
            self.assertIn("app/src/open/java", sources)
            self.assertNotIn("app/src/open/java/com", sources)
            self.assertNotIn("app/src/open/java/com/example", sources)
        for source_set in ("main", "open", "research", "amazon", "googleServices"):
            self.assertTrue(COVERAGE.production_jvm(f"app/src/{source_set}/java/Worker.kt"))
        for source_set in ("test", "testOpen", "androidTest", "androidTestOpen"):
            self.assertFalse(COVERAGE.production_jvm(f"app/src/{source_set}/java/Worker.kt"))

    def test_changed_selfhost_python_requires_its_own_report(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "selfhost/chronicle_ops/restore.py"
            source.parent.mkdir(parents=True)
            source.write_text("value = 1\n")
            with patch.object(COVERAGE, "root", root, create=True), \
                 patch.object(COVERAGE, "children", return_value=[]), \
                 patch.object(COVERAGE, "changed_files", return_value={"selfhost/chronicle_ops/restore.py"}), \
                 contextlib.redirect_stderr(io.StringIO()) as errors:
                self.assertTrue(COVERAGE.check(root, "base", {".": {"cobertura"}}))
                self.assertIn("changed selfhost Python sources require coverage.xml", errors.getvalue())


if __name__ == "__main__":
    unittest.main()
