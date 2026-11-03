import importlib
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tests/security'))
inventory = importlib.import_module('check-suite-inventory')


class ParserCorpusInventoryTests(unittest.TestCase):
    def test_a_present_parser_requires_its_mutated_corpus(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for source, corpus, declaration in (
                ('chronicle-web/src/modern/lib/study-config-file.ts',
                 'chronicle-web/src/modern/lib/study-config-file.property.test.ts', 'fc.property('),
                ('selfhost/chronicle_ops/restore.py', 'tests/selfhost-py/test_restore.py',
                 'def test_mutated_archive_metadata_is_refused_before_any_service_or_database_change('),
            ):
                parser = root / source
                parser.parent.mkdir(parents=True, exist_ok=True)
                parser.write_text('parser')
                self.assertIn(parser, inventory.parser_corpora(root, []))
                test = root / corpus
                test.parent.mkdir(parents=True, exist_ok=True)
                test.write_text(declaration)
                self.assertNotIn(parser, inventory.parser_corpora(root, []))
                test.write_text('')
                self.assertIn(parser, inventory.parser_corpora(root, []))

    def test_fuzz_targets_require_an_executable_mutating_gate(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / 'chronicle-server/src/test/kotlin/com/openlattice/chronicle/fuzz/JsonFuzzTest.kt'
            target.parent.mkdir(parents=True)
            target.write_text('@FuzzTest(maxDuration = "5s") fun json() {}')
            self.assertEqual({target}, inventory.parser_corpora(root, []))
            self.assertEqual(set(), inventory.parser_corpora(root, ['JAZZER_FUZZ=1 gradle :chronicle-server:test']))


if __name__ == '__main__':
    unittest.main()
