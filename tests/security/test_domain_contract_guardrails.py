"""Exercise the domain guard's real web checks against isolated current sources."""
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
GUARD = ROOT / "tests/security/domain-contract-guardrails.sh"
WEB_CHECK_MARKER = (
    'python3 - "$ROOT_DIR" "$MODELS_DIR" "$LINKML_CONTRACT" "$IOS_AVAILABLE" <<\'PY\'\n'
)
OPERATIONS = Path("chronicle-web/src/modern/state/study-operations-api.ts")
CONTRACT = Path("generated/domain-contracts/chronicle-domain-contracts.json")
INPUTS = (
    OPERATIONS,
    CONTRACT,
    Path("chronicle-web/src/modern/lib/study-constants.ts"),
    Path("chronicle/settings.gradle"),
    Path("chronicle/app/build.gradle"),
    Path("chronicle-server/settings.gradle"),
    Path("chronicle-server/build.gradle"),
)


class DomainContractGuardrailsTest(unittest.TestCase):
    def setUp(self):
        directory = ROOT / "build/operator-test-runs"
        directory.mkdir(parents=True, exist_ok=True)
        temporary = tempfile.TemporaryDirectory(prefix="domain-guard-", dir=directory)
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        for relative in INPUTS:
            destination = self.root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / relative, destination)
        source = GUARD.read_text(encoding="utf-8")
        self.assertEqual(1, source.count(WEB_CHECK_MARKER))
        self.check = source.split(WEB_CHECK_MARKER, 1)[1].split("\nPY\n", 1)[0]

    def run_guard(self):
        return subprocess.run(
            [sys.executable, "-", str(self.root), str(self.root / "chronicle-models"),
             str(self.root / CONTRACT), "0"],
            input=self.check, capture_output=True, text=True, check=False, timeout=20,
        )

    def mutate_operations(self, old, new):
        path = self.root / OPERATIONS
        source = path.read_text(encoding="utf-8")
        self.assertIn(old, source)
        path.write_text(source.replace(old, new), encoding="utf-8")

    def assert_rejected(self, message):
        result = self.run_guard()
        self.assertEqual(1, result.returncode, result.stdout + result.stderr)
        self.assertIn(message, result.stderr)
        self.assertNotIn("Traceback", result.stderr)

    def test_current_production_validation_needs_no_deleted_zod_file(self):
        result = self.run_guard()
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertIn("participation-status guard", result.stdout)
        self.assertIn("downstream Android/server build files are present", result.stdout)

    def test_import_without_runtime_membership_is_rejected(self):
        self.mutate_operations(
            "return typeof value === 'string' && (PARTICIPATION_STATUSES as readonly string[]).includes(value);",
            "const unusedMembership = (PARTICIPATION_STATUSES as readonly string[]).includes(value as string);\n"
            "  // PARTICIPATION_STATUSES.includes(value)\n  return typeof value === 'string';",
        )
        self.assert_rejected("isParticipationStatus must test membership")

    def test_unused_status_guard_does_not_validate_the_response(self):
        self.mutate_operations(
            "isParticipationStatus(participant.participationStatus)",
            "true /* isParticipationStatus(participant.participationStatus) */",
        )
        self.assert_rejected("normalizeParticipantList must use isParticipationStatus")

    def test_consent_entry_must_use_the_generated_wire_schema(self):
        self.mutate_operations(
            "export type CollectionAcknowledgmentEntry = components['schemas']['CollectionAcknowledgmentEntry']",
            "// CollectionAcknowledgmentEntry = components['schemas']['CollectionAcknowledgmentEntry']\n"
            "export type CollectionAcknowledgmentEntry = Record<string, unknown>",
        )
        self.assert_rejected("CollectionAcknowledgmentEntry must use its generated wire schema")

    def test_unused_generated_consent_alias_does_not_type_the_request(self):
        self.mutate_operations(
            "readAllRows<CollectionAcknowledgmentEntry[]>(",
            "readAllRows<unknown[]>( /* readAllRows<CollectionAcknowledgmentEntry[]>( */",
        )
        self.assert_rejected("getStudyCollectionAcknowledgments must consume CollectionAcknowledgmentEntry")

    def test_copied_canonical_union_is_rejected(self):
        path = self.root / OPERATIONS
        with path.open("a", encoding="utf-8") as output:
            output.write("\nexport type ParticipationStatus = 'ENROLLED' | 'UNKNOWN';\n")
        self.assert_rejected("re-declares canonical union ParticipationStatus")

    def test_copied_contract_import_is_rejected(self):
        self.mutate_operations("from '@/generated/chronicle-contracts'", "from '@/lib/copied-contracts'")
        self.assert_rejected("must import from the generated chronicle-contracts module")


if __name__ == "__main__":
    unittest.main()
