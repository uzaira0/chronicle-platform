"""SARIF-derived metadata pins existing detekt waivers without granting new ones."""

import copy
import hashlib
import importlib.util
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("waiver_source", ROOT / "scripts/check-detekt-waiver-source.py")
CHECK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECK)


def report(rule, path, line, column, end_line, end_column):
    return {"version": "2.1.0", "runs": [{"results": [{
        "ruleId": "detekt.complexity." + rule,
        "locations": [{"physicalLocation": {"artifactLocation": {"uri": path}, "region": {
            "startLine": line, "startColumn": column, "endLine": end_line, "endColumn": end_column,
        }}}],
    }]}]}


class DetektWaiverSourceTest(unittest.TestCase):
    def setUp(self):
        self.assertTrue(hasattr(CHECK, "waived_findings"), "SARIF-derived waiver metadata is missing")
        scratch = ROOT / "build/operator-test-runs"
        scratch.mkdir(parents=True, exist_ok=True)
        self.directory = tempfile.TemporaryDirectory(dir=scratch)
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.path = self.root / "src/Example.kt"
        self.path.parent.mkdir()
        self.source = 'class Example {\n    fun kept() {\n        old()\n    }\n    fun sibling() = 1\n}\n'
        self.path.write_text(self.source)
        self.all = report("LongMethod", "src/Example.kt", 2, 9, 2, 13)
        self.filtered = {"version": "2.1.0", "runs": [{"results": []}]}
        self.ids = {"LongMethod:Example.kt$Example$fun kept()"}

    def metadata(self):
        return {"baselineBase": "fixture-base", "baselineIds": sorted(self.ids), "findings": CHECK.waived_findings(self.root, self.all, self.filtered),
                "suppressions": CHECK.suppression_inventory(self.root)}

    def test_sarif_baseline_difference_pins_the_full_affected_method(self):
        pin = self.metadata()
        self.assertEqual(1, len(pin["findings"]))
        entry = pin["findings"][0]
        self.assertEqual(("LongMethod", "src/Example.kt", 2, 9),
                         (entry["rule"], entry["path"], entry["line"], entry["column"]))
        self.assertEqual(hashlib.sha256('fun kept() {\n        old()\n    }'.encode()).hexdigest(), entry["sha256"])
        self.assertEqual([], CHECK.verify_metadata(self.root, pin, self.ids))
        self.path.write_text(self.source.replace("= 1", "= 2"))
        self.assertEqual([], CHECK.verify_metadata(self.root, pin, self.ids))
        self.path.write_text(self.source.replace("old()", "edited()"))
        self.assertTrue(any("edited" in error for error in CHECK.verify_metadata(self.root, pin, self.ids)))

    def test_no_xml_id_or_unknown_or_moved_finding_is_allowed(self):
        pin = self.metadata()
        self.assertTrue(CHECK.verify_metadata(self.root, pin, self.ids | {"LongMethod:New.kt$new"}))
        self.assertEqual([], CHECK.verify_metadata(self.root, pin, self.ids, self.all, self.filtered))
        moved = copy.deepcopy(self.all)
        moved["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]["startColumn"] = 10
        self.assertTrue(any("unknown" in error for error in CHECK.verify_metadata(self.root, pin, self.ids, moved, self.filtered)))
        self.assertEqual([], CHECK.waived_findings(self.root, self.all, self.all))

    def test_renaming_a_waived_file_cannot_refresh_the_accepted_pin(self):
        accepted = self.metadata()
        moved = self.root / "src/Renamed.kt"
        self.path.rename(moved)
        renamed_report = report("LongMethod", "src/Renamed.kt", 2, 9, 2, 13)
        failures = CHECK.verify_metadata(self.root, accepted, self.ids, renamed_report, self.filtered)
        self.assertTrue(any("unavailable" in error for error in failures))
        self.assertTrue(any("unknown or moved" in error for error in failures))
        refreshed = {**accepted, "findings": CHECK.waived_findings(self.root, renamed_report, self.filtered)}
        self.assertTrue(CHECK.metadata_policy(refreshed, accepted, self.ids))

    def test_a_second_same_basename_cannot_reuse_the_signature_allowance(self):
        accepted = self.metadata()
        added = self.root / "other/src/Example.kt"
        added.parent.mkdir(parents=True)
        added.write_text(self.source)
        combined = copy.deepcopy(self.all)
        combined["runs"][0]["results"] += report("LongMethod", "other/src/Example.kt", 2, 9, 2, 13)["runs"][0]["results"]
        failures = CHECK.verify_metadata(self.root, accepted, self.ids, combined, self.filtered)
        self.assertTrue(any("other/src/Example.kt" in error and "unknown" in error for error in failures))

    def test_refreshing_a_hash_cannot_bless_an_edited_method(self):
        accepted = self.metadata()
        self.path.write_text(self.source.replace("old()", "edited()"))
        pin = self.metadata()
        self.assertEqual([], CHECK.verify_metadata(self.root, pin, self.ids))
        self.assertTrue(any("refresh" in error for error in CHECK.metadata_policy(pin, accepted, self.ids)))

    def test_suppression_inventory_pins_path_line_and_full_directive_only(self):
        source = '@Suppress("LargeClass", "TooManyFunctions")\nclass Example { fun run() = 1 }\n'
        self.path.write_text(source)
        pin = {"baselineIds": [], "findings": [], "suppressions": CHECK.suppression_inventory(self.root)}
        self.assertEqual([{"path": "src/Example.kt", "line": 1,
                           "text": '@Suppress("LargeClass", "TooManyFunctions")'}], pin["suppressions"])
        self.path.write_text(source.replace("= 1", "= 2"))
        self.assertEqual([], CHECK.verify_metadata(self.root, pin, set()))
        for changed in ("\n" + source, source.replace('"LargeClass"', '"LongMethod"')):
            self.path.write_text(changed)
            self.assertTrue(CHECK.verify_metadata(self.root, pin, set()))
        self.path.write_text("class Example { fun run() = 1 }\n")
        pin["suppressions"] = []
        self.assertEqual([], CHECK.verify_metadata(self.root, pin, set()))

    def test_localized_catch_parameter_uses_the_sarif_region(self):
        source = 'class Example { fun run() { try { call() } catch (e: Exception) { old() } } }\n'
        self.path.write_text(source)
        column = source.index("e: Exception") + 1
        self.all = report("TooGenericExceptionCaught", "src/Example.kt", 1, column, 1, column + len("e: Exception"))
        self.ids = {"TooGenericExceptionCaught:Example.kt$Example$e: Exception"}
        pin = self.metadata()
        self.assertEqual(hashlib.sha256(b"e: Exception").hexdigest(), pin["findings"][0]["sha256"])
        self.path.write_text(source.replace("old()", "edited()"))
        self.assertEqual([], CHECK.verify_metadata(self.root, pin, self.ids))

    def test_non_size_suppressions_are_in_the_full_directive_inventory(self):
        self.path.write_text('@Suppress("TooGenericExceptionCaught")\nfun example() {}\n')
        self.assertEqual(1, len(CHECK.suppression_inventory(self.root)))

    def test_pinned_parser_preserves_arguments_of_split_annotation_nodes(self):
        # Existing Kotlin interface context makes ast-grep 0.42.1 split the annotation name from its arguments.
        source = (
            'public interface ParticipantStatsCache {\n'
            '    public fun get(studyId: UUID, participantId: String): ParticipantStats?\n'
            '\n'
            '    public fun merge(stats: ParticipantStats)\n'
            '\n'
            '    public fun <T> quarantineParticipant(\n'
            '        studyId: UUID,\n'
            '        participantId: String,\n'
            '        transaction: () -> T,\n'
            '    ): T\n'
            '\n'
            '    public fun <T> quarantineStudy(\n'
            '        studyId: UUID,\n'
            '        transaction: () -> T,\n'
            '    ): T\n'
            '}\n'
            '\n'
            '// reason: quarantine commits are authoritative; broad boundary catches keep\n'
            '// best-effort cache cleanup from changing or masking the transaction outcome\n'
            '@Suppress("TooGenericExceptionCaught")\n'
            'public open class Example {}\n'
        )
        for prefix in ("@Suppress", "@kotlin.Suppress"):
            with self.subTest(prefix=prefix):
                self.path.write_text(source.replace("@Suppress", prefix))
                self.assertEqual([{"path": "src/Example.kt", "line": 20,
                                   "text": prefix + '("TooGenericExceptionCaught")'}], CHECK.suppression_inventory(self.root))
        self.path.write_text(source.replace('@Suppress(', '@Suppress /* comment */ ('))
        with self.assertRaisesRegex(ValueError, "complete suppression"):
            CHECK.suppression_inventory(self.root)

    def test_local_cast_keeps_the_complete_suppression_directive(self):
        self.path.write_text(
            'class Example {\n'
            '    private fun adapt(returnType: Type, response: Response<Any>): Any {\n'
            '        @Suppress("UNCHECKED_CAST")\n'
            '        val adapter = ChronicleCallAdapterFactory().get(returnType, emptyArray(), retrofitStub())\n'
            '            as retrofit2.CallAdapter<Any, Any>\n'
            '        return adapter.adapt(FixedCall(response))\n'
            '    }\n'
            '}\n')
        self.assertEqual([{"path": "src/Example.kt", "line": 3,
                           "text": '@Suppress("UNCHECKED_CAST")'}], CHECK.suppression_inventory(self.root))
        original = self.path.read_text()
        for rule in ("UNCHECKED_CAST", "LongMethod"):
            self.path.write_text(original.replace("UNCHECKED_CAST", rule).replace('@Suppress(', '@Suppress /* comment */ ('))
            with self.subTest(rule=rule), self.assertRaisesRegex(ValueError, "complete suppression"):
                CHECK.suppression_inventory(self.root)

    def test_directive_capture_preserves_file_targets_and_same_line_multiplicity(self):
        for prefix in ("@file:Suppress", "@file:kotlin.Suppress", "@kotlin.Suppress"):
            with self.subTest(prefix=prefix):
                self.path.write_text(prefix + '("LongMethod")\nclass Example {}\n')
                self.assertEqual([{"path": "src/Example.kt", "line": 1,
                                   "text": prefix + '("LongMethod")'}], CHECK.suppression_inventory(self.root))
        self.path.write_text('@Suppress("LongMethod") fun one() {} ; @Suppress("LongMethod") fun two() {}\n')
        records = CHECK.suppression_inventory(self.root)
        self.assertEqual(2, len(records))
        self.assertEqual(records[0], records[1])

    def test_use_site_suppression_uses_the_native_annotation_span(self):
        for prefix in ('@get:Suppress', '@get: kotlin.Suppress', '@get:/* comment */Suppress'):
            with self.subTest(prefix=prefix):
                self.path.write_text('class Example {\n' + prefix + '("TooGenericExceptionCaught")\nval value: Int get() = 1\n}\n')
                self.assertEqual([{"path": "src/Example.kt", "line": 2,
                                   "text": prefix + '("TooGenericExceptionCaught")'}], CHECK.suppression_inventory(self.root))

    def test_grouped_file_suppression_fails_closed_without_confusing_string_values(self):
        for directive in ('@file:[Suppress("LongMethod")]',
                          '@file:[JvmName("Other") Suppress("LongMethod")]',
                          '@file:[kotlin.Suppress("LongMethod")]'):
            with self.subTest(directive=directive):
                self.path.write_text(directive + '\npackage fixture\nfun example() {}\n')
                with self.assertRaisesRegex(ValueError, "grouped.*suppression"):
                    CHECK.suppression_inventory(self.root)
        self.path.write_text('@file:[JvmName("Suppress")]\npackage fixture\nfun example() {}\n')
        self.assertEqual([], CHECK.suppression_inventory(self.root))

    def test_ast_ignore_comments_cannot_hide_suppression_inventory(self):
        self.path.write_text('// ast-grep-ignore\n@Suppress("LongMethod")\nfun example() {}\n')
        self.assertEqual(1, len(CHECK.suppression_inventory(self.root)))

    def test_initial_metadata_fingerprints_current_existing_waivers_and_allows_old_directive_relocation(self):
        self.path.write_text('@Suppress("LongMethod")\n' + self.source)
        historical = CHECK.suppression_inventory(self.root)
        # Bootstrap pins the final candidate, rather than forcing unrelated historical bodies to return.
        self.path.write_text('\n' + '@Suppress("LongMethod")\n' + self.source.replace("old()", "edited()"))
        self.all = report("LongMethod", "src/Example.kt", 4, 9, 4, 13)
        pin = self.metadata()
        self.assertEqual([], CHECK.metadata_policy(pin, None, self.ids, historical))
        self.assertEqual([], CHECK.verify_metadata(self.root, pin, self.ids, self.all, self.filtered))
        added = copy.deepcopy(pin)
        added["suppressions"].append({**added["suppressions"][0], "path": "src/New.kt"})
        self.assertTrue(CHECK.metadata_policy(added, None, self.ids, historical), "bootstrap cannot duplicate a directive")
        self.assertTrue(CHECK.metadata_policy(pin, None, set(), historical), "bootstrap cannot grant a new XML ID")
        moved = copy.deepcopy(pin)
        moved["suppressions"][0]["line"] += 1
        self.assertTrue(CHECK.metadata_policy(moved, pin, self.ids), "committed pins cannot relocate")

    def test_bootstrap_accepts_strictly_narrowed_directives_without_new_rules_or_splits(self):
        def inventory(*texts):
            return [{"path": "src/Example.kt", "line": index + 1, "text": text} for index, text in enumerate(texts)]
        dated = inventory('@Suppress("ReturnCount", "TooGenericExceptionCaught")')
        pin = {"baselineIds": [], "findings": [], "suppressions": inventory('@Suppress("ReturnCount")')}
        self.assertEqual([], CHECK.metadata_policy(pin, None, set(), dated))
        for texts in (('@Suppress("ReturnCount", "NewRule")',),
                      ('@Suppress("ReturnCount")', '@Suppress("ReturnCount")'),
                      ('@Suppress("ReturnCount")', '@Suppress("TooGenericExceptionCaught")')):
            with self.subTest(texts=texts):
                self.assertTrue(CHECK.metadata_policy({**pin, "suppressions": inventory(*texts)}, None, set(), dated))
        # Each old directive can be consumed at most once; find a full matching rather than greedy pairing.
        dated = inventory('@Suppress("A", "B")', '@Suppress("A", "C")')
        pin["suppressions"] = inventory('@Suppress("A")', '@Suppress("B")')
        self.assertEqual([], CHECK.metadata_policy(pin, None, set(), dated))
        pin["suppressions"] = inventory('@Suppress("B", "C")')
        self.assertTrue(CHECK.metadata_policy(pin, None, set(), dated), "two old directives cannot be merged into one broader allowance")

    def test_deleting_active_metadata_rows_cannot_hide_an_existing_waiver(self):
        accepted = self.metadata()
        removed = {**accepted, "findings": []}
        self.assertEqual([], CHECK.metadata_policy(removed, accepted, self.ids))
        self.assertTrue(any("unknown" in error for error in CHECK.verify_metadata(
            self.root, removed, self.ids, self.all, self.filtered)))
        # A row may retire only when the actual paired scan no longer reports a masked finding.
        self.assertEqual([], CHECK.verify_metadata(self.root, removed, self.ids, self.all, self.all))

    def test_reviewed_metadata_is_tracked_so_a_clean_checkout_can_run_the_gate(self):
        tracked = subprocess.run(["git", "-C", str(ROOT), "ls-files", "--error-unmatch", CHECK.METADATA.name],
                                 capture_output=True, text=True)
        self.assertEqual(0, tracked.returncode, tracked.stderr)
        base = subprocess.run(["git", "-C", str(ROOT), "rev-parse", CHECK.BASELINE_BASE],
                              capture_output=True, text=True, check=True).stdout.strip()
        self.assertEqual(base, json.loads(CHECK.METADATA.read_text())["baselineBase"])
        self.assertEqual(base, CHECK.accepted_metadata(ROOT, CHECK.METADATA_REVISION)["baselineBase"])

    def test_accepted_pins_come_from_the_reviewed_revision_not_head(self):
        def store(document):
            return subprocess.run(["git", "-C", str(self.root), "hash-object", "-w", "--stdin"],
                                  input=json.dumps(document),
                                  capture_output=True, text=True, check=True).stdout.strip()
        subprocess.run(["git", "init", "--quiet", str(self.root)], capture_output=True, check=True)
        reviewed = self.metadata()
        revision = store(reviewed)
        # Later metadata edits the waived span and refreshes its own pin.
        self.path.write_text(self.source.replace("old()", "edited()"))
        refreshed = self.metadata()
        store(refreshed)
        self.assertNotEqual("HEAD", CHECK.METADATA_REVISION)
        accepted = CHECK.accepted_metadata(self.root, revision)
        self.assertEqual(reviewed, accepted)
        self.assertTrue(any("refresh" in error for error in CHECK.metadata_policy(refreshed, accepted, self.ids)))

    def test_write_rejects_refreshed_pins_without_overwriting_the_metadata(self):
        accepted = self.metadata()
        metadata_path = self.root / CHECK.METADATA.name
        original = json.dumps(accepted)
        metadata_path.write_text(original)
        all_path, filtered_path = self.root / "all.json", self.root / "filtered.json"
        all_path.write_text(json.dumps(self.all))
        filtered_path.write_text(json.dumps(self.filtered))
        baseline = '<SmellBaseline><ID>' + next(iter(self.ids)) + '</ID></SmellBaseline>'
        (self.root / "detekt-baseline.xml").write_text(baseline)
        self.path.write_text(self.source.replace("old()", "edited()"))
        coverage = Mock()
        coverage.git.side_effect = [accepted["baselineBase"], baseline]
        with patch.object(CHECK, "ROOT", self.root), patch.object(CHECK, "diff_coverage", return_value=coverage), \
                patch.object(CHECK, "accepted_metadata", return_value=accepted), \
                patch("sys.argv", ["check-detekt-waiver-source.py", "--write", "--metadata", str(metadata_path),
                                   "--all-sarif", str(all_path), "--filtered-sarif", str(filtered_path)]):
            with self.assertRaisesRegex(ValueError, "refresh"):
                CHECK.main()
        self.assertEqual(original, metadata_path.read_text())

    def test_multiline_suppression_cannot_be_blessed_by_changing_only_its_pin(self):
        original = '@Suppress(\n    "LargeClass"\n)\nclass Example {}\n'
        self.path.write_text(original)
        historical = CHECK.suppression_inventory(self.root)
        self.path.write_text(original.replace('"LargeClass"', '"LargeClass", "TooManyFunctions"'))
        pin = {"baselineIds": [], "findings": [], "suppressions": CHECK.suppression_inventory(self.root)}
        errors = CHECK.metadata_policy(pin, None, set(), historical)
        self.assertTrue(any("new suppression" in error for error in errors))


if __name__ == "__main__":
    unittest.main()
