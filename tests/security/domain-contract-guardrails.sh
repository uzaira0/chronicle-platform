#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
MODELS_DIR="${CHRONICLE_MODELS_DIR:-$ROOT_DIR/chronicle-models}"
IOS_DIR_EXPLICIT=0
if [[ -n "${CHRONICLE_IOS_DIR:-}" ]]; then
  IOS_DIR="$CHRONICLE_IOS_DIR"
  IOS_DIR_EXPLICIT=1
else
  IOS_DIR="$ROOT_DIR/chronicle-ios"
fi
CHECK_IOS_CONTRACTS="${CHRONICLE_CHECK_IOS_CONTRACTS:-$IOS_DIR_EXPLICIT}"
API_SPEC="${CHRONICLE_API_SPEC:-$ROOT_DIR/chronicle-api/chronicle.yaml}"
LINKML_CONTRACT="$ROOT_DIR/generated/domain-contracts/chronicle-domain-contracts.json"

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

case "$CHECK_IOS_CONTRACTS" in
  0|1) ;;
  *) fail "CHRONICLE_CHECK_IOS_CONTRACTS must be 0 or 1" ;;
esac

pass() {
  echo "PASS: $*"
}

skip() {
  echo "SKIP: $*"
}

require_file() {
  local file="$1"
  [[ -f "$file" ]] || fail "required file missing: $file"
}

require_file_contains() {
  local file="$1"
  local pattern="$2"
  local description="$3"
  require_file "$file"
  if ! grep -Eq "$pattern" "$file"; then
    fail "$description"
  fi
  pass "$description"
}

echo "=== Chronicle domain contract guardrails ==="

require_file "$LINKML_CONTRACT"
require_file "$ROOT_DIR/scripts/generate-chronicle-contracts.py"

"$ROOT_DIR/scripts/generate-chronicle-contracts.py" --check
pass "LinkML-generated Chronicle contract artifacts are fresh"
python3 "$ROOT_DIR/tests/security/endpoint-consumer-coverage.py"
python3 "$ROOT_DIR/tests/security/endpoint-consumer-coverage.py" --self-test

python3 -s - "$ROOT_DIR" <<'PY'
import importlib.util
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

root = Path(sys.argv[1])
generator = Path("scripts/generate-chronicle-contracts.py")
spec = importlib.util.spec_from_file_location("chronicle_contracts", root / generator)
contracts = importlib.util.module_from_spec(spec)
spec.loader.exec_module(contracts)
schema = contracts.load_schema()
outputs = contracts.all_outputs(schema)
source = contracts.SCHEMA_PATH.relative_to(root)
upload_outputs = contracts.upload_limit_outputs(schema)
constant = next(path.relative_to(root) for path in upload_outputs if path.suffix == ".kt")
adapters = tuple(path.relative_to(root) for path in contracts.UPLOAD_LIMIT_ADAPTERS)
limit = contracts.upload_limit_bytes(schema)
with tempfile.TemporaryDirectory(prefix="chronicle-contract-") as directory:
    scratch = Path(directory)
    for path in sorted({root / generator, *contracts.INPUTS, *outputs}):
        target = scratch / path.relative_to(root)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, target)

    def check(expected_status, path=None):
        result = subprocess.run([sys.executable, "-s", str(scratch / generator), "--check"],
                                cwd=scratch, capture_output=True, text=True, check=False)
        assert result.returncode == expected_status, (
            f"{path}: expected exit {expected_status}, got {result.returncode}\n" + result.stdout + result.stderr)
        if path is not None:
            assert f"{path} is stale" in result.stderr, result.stderr
            print(f"PASS contract --check: {path} drift rejected (exit {result.returncode})")
        else:
            print("PASS contract --check: clean scratch copy accepted (exit 0)")

    check(0)
    path = contracts.FRESH_SCHEMA_PATH.relative_to(root)
    target = scratch / path
    original = target.read_text()
    prefix = contracts.RESTORE_RECEIPT_VERSION_PREFIX
    target.write_text(original.replace(prefix, prefix + "0 + "))
    check(1, path)
    target.write_text(original)
    check(0)
    for path in (*adapters, source):
        target = scratch / path
        original = target.read_text()
        target.write_text(original.replace(str(limit), str(limit + 1)))
        check(1, constant if path == source else path)
        target.write_text(original)
        check(0)

    for output in sorted(outputs.keys() - contracts.UPLOAD_LIMIT_ADAPTERS.keys()):
        path = output.relative_to(root)
        target = scratch / path
        original = target.read_text()
        target.write_text(original + "\n")
        check(1, path)
        target.write_text(original)
        check(0)
PY
pass "Default contract check rejects drift in every generated output, upload adapter and ontology constant"

python3 "$ROOT_DIR/tests/security/play-store-module-registry-check.py"
python3 "$ROOT_DIR/tests/security/play-store-module-registry-check.py" --self-test

python3 "$ROOT_DIR/tests/security/contract-drift-diff.py" "$ROOT_DIR" ||
  fail "shared value sets drift across LinkML, chronicle-models, web, OpenAPI or the ast-grep rule"
pass "Shared value sets agree across LinkML, chronicle-models, web, OpenAPI and Android"

# iOS is intentionally pinned with `submodule.<name>.update=none` in chronicle-platform. An
# incidental developer checkout must not silently broaden root CI. Run this section
# only when CHRONICLE_CHECK_IOS_CONTRACTS=1 or CHRONICLE_IOS_DIR is explicitly supplied;
# otherwise the chronicle-ios repository owns its generated-artifact gate.
IOS_AVAILABLE=0
if [[ "$CHECK_IOS_CONTRACTS" -eq 1 ]]; then
  require_file "$IOS_DIR/scripts/generate-ios-contracts.py"
  IOS_AVAILABLE=1
fi
require_file "$API_SPEC"
if [[ "$IOS_AVAILABLE" -eq 1 ]]; then
  (
    cd "$IOS_DIR"
    CHRONICLE_MODELS_DIR="$MODELS_DIR" CHRONICLE_API_SPEC="$API_SPEC" \
      python3 scripts/generate-ios-contracts.py --check
  )
  pass "chronicle-ios generated Swift contracts, routes, and fixtures are fresh"
else
  skip "chronicle-ios is update=none; its repository CI owns generated artifacts unless root checking is explicitly enabled"
fi

python3 - "$ROOT_DIR" "$MODELS_DIR" "$LINKML_CONTRACT" "$IOS_AVAILABLE" <<'PY'
import json
import re
import sys
from pathlib import Path

root = Path(sys.argv[1])
models_dir = Path(sys.argv[2])
linkml_contract_path = Path(sys.argv[3])
ios_available = sys.argv[4] == "1"
contract = json.loads(linkml_contract_path.read_text(encoding="utf-8"))
contracts = contract["contracts"]


def fail(message: str) -> None:
    print(f"FAIL: {message}", file=sys.stderr)
    raise SystemExit(1)


def pass_msg(message: str) -> None:
    print(f"PASS: {message}")


# chronicle-web consumes the GENERATED contract module. The guardrail no
# longer parses hand-maintained literal unions (they must not exist); it asserts the
# new invariants: generated imports present, no re-declared canonical unions, defaults
# and sensor mappings joined (not hand-written), and web-owned presentation covering
# exactly the active generated module ids. Descriptor label/description coverage is
# additionally enforced by chronicle-web's own test suite (study-constants.test.ts).
web_dir = root / "chronicle-web"
web_constants_path = web_dir / "src/modern/lib/study-constants.ts"
if not web_constants_path.exists():
    # An uninitialized chronicle-web submodule must fail the gate, not skip it:
    # every web invariant below would otherwise pass vacuously.
    fail("chronicle-web checkout missing or empty — init the submodule before running the guardrails")
web = web_constants_path.read_text(encoding="utf-8")
ops = (web_dir / "src/modern/state/study-operations-api.ts").read_text(encoding="utf-8")

generated_import = re.compile(r"from '(?:\.\./|@/)generated/chronicle-contracts'")
for name, text in (
    ("study-constants.ts", web),
    ("study-operations-api.ts", ops),
):
    if not generated_import.search(text):
        fail(f"chronicle-web {name} must import from the generated chronicle-contracts module")
pass_msg("chronicle-web migrated files consume the generated chronicle-contracts module")

canonical_unions = [
    ("study-constants.ts", web, "CollectionModuleId"),
    ("study-operations-api.ts", ops, "ParticipationStatus"),
    ("study-operations-api.ts", ops, "StudyLifecycleStatus"),
    ("study-operations-api.ts", ops, "ParticipantDataType"),
]
for name, text, symbol in canonical_unions:
    match = re.search(rf"export\s+type\s+{re.escape(symbol)}\s*=\s*([^;]+);", text)
    # Catch single- AND double-quoted literal unions; a re-declaration must not
    # slip through on quote style.
    if match and ("'" in match.group(1) or '"' in match.group(1)):
        fail(f"chronicle-web {name} re-declares canonical union {symbol} as string literals")
    # The canonical symbol must still be present (re-exported from or aliased to
    # the generated module) — a silently deleted re-export is drift too.
    if not re.search(rf"\b{re.escape(symbol)}\b", text):
        fail(f"chronicle-web {name} no longer exposes canonical symbol {symbol}")
pass_msg("chronicle-web declares no hand-maintained canonical value-set unions")

# Production response validation lives in the API normalizer; Zod schemas under
# modern/test are test fixtures. Require the predicate's returned expression, not
# a tuple name in an import, comment or unused declaration.
status_guard = re.search(r"^function isParticipationStatus\([^\n]+\{\n(.*?)^\}", ops, re.M | re.S)
if not status_guard or not re.fullmatch(
    r"\s*return typeof value === 'string' && "
    r"\(PARTICIPATION_STATUSES as readonly string\[\]\)\.includes\(value\);\s*",
    status_guard.group(1),
):
    fail("chronicle-web isParticipationStatus must test membership against the generated PARTICIPATION_STATUSES array")
normalizer = re.search(r"^export function normalizeParticipantList\([^\n]+\{\n(.*?)^\}", ops, re.M | re.S)
if not normalizer or not re.search(
    r"^\s+participationStatus:\s*isParticipationStatus\(participant\.participationStatus\)\s*"
    r"\?\s*participant\.participationStatus\s*:\s*PARTICIPATION_STATUS\.UNKNOWN,",
    normalizer.group(1), re.M,
):
    fail("chronicle-web normalizeParticipantList must use isParticipationStatus for the returned status")
pass_msg("chronicle-web participation-status guard is driven by the generated array")

# Consent entries now use the generated OpenAPI wire type, whose trigger enum is
# compared with LinkML by contract-drift-diff.py. Require the actual query's alias
# and use; the removed private CollectionConsentTrigger alias had no caller.
if not re.search(
    r"^import type \{ components \} from '@/types/chronicle-api\.generated';", ops, re.M,
) or not re.search(
    r"^export type CollectionAcknowledgmentEntry = "
    r"components\['schemas'\]\['CollectionAcknowledgmentEntry'\]", ops, re.M,
):
    fail("chronicle-web CollectionAcknowledgmentEntry must use its generated wire schema")
acknowledgments_query = re.search(
    r"^    getStudyCollectionAcknowledgments: builder\.query<CollectionAcknowledgmentEntry\[\],[\s\S]*?^    \}\),",
    ops, re.M,
)
if not acknowledgments_query or not re.search(
    r"^\s+readAllRows<CollectionAcknowledgmentEntry\[\]>\(", acknowledgments_query.group(0), re.M,
):
    fail("chronicle-web getStudyCollectionAcknowledgments must consume CollectionAcknowledgmentEntry")
pass_msg("chronicle-web consent query consumes the generated wire schema")

if re.search(r"defaultEnabled\s*:\s*(?:true|false)\b", web):
    fail("chronicle-web study-constants.ts hand-writes defaultEnabled; join it from COLLECTION_MODULE_CONTRACTS")
if re.search(r"sensorType\s*:\s*'", web):
    fail("chronicle-web study-constants.ts hand-writes sensorType; join it from ANDROID_SENSOR_MAPPINGS")
pass_msg("chronicle-web module defaults and sensor mappings are joined from generated contract data")

presentation_match = re.search(
    r"const\s+COLLECTION_MODULE_PRESENTATION\s*=\s*\[(.*?)\]\s*as const",
    web,
    flags=re.S,
)
if not presentation_match:
    fail("Unable to find chronicle-web COLLECTION_MODULE_PRESENTATION")
presented = re.findall(r"value:\s*COLLECTION_MODULE_ID\.(\w+)", presentation_match.group(1))
active_id_set = set(contracts["activeCollectionModuleIds"])
if len(presented) != len(set(presented)) or set(presented) != active_id_set:
    fail(
        "chronicle-web COLLECTION_MODULE_PRESENTATION coverage drift: "
        f"missing={sorted(active_id_set - set(presented))}, "
        f"stale={sorted(set(presented) - active_id_set)}"
    )
pass_msg("chronicle-web module presentation covers exactly the active generated module ids")

if ios_available:
    ios_dir = root / "chronicle-ios"
    forbidden = re.compile(r"\b(CollectionModuleId|ConsentTrigger|StudyFeature|StudyLifecycleStatus)\b")
    hits = []
    swift_files_scanned = 0
    for path in ios_dir.rglob("*.swift"):
        if ".build" in path.parts or "DerivedData" in path.parts:
            continue
        swift_files_scanned += 1
        text = path.read_text(encoding="utf-8", errors="ignore")
        if forbidden.search(text):
            hits.append(str(path.relative_to(root)))
    if swift_files_scanned == 0:
        fail("chronicle-ios checkout was supplied but contains no Swift sources")
    if hits:
        fail("iOS must not reintroduce local shared-domain enum definitions/usages before generated contracts: " + ", ".join(hits[:20]))
    pass_msg(f"iOS has no local shared-domain enum duplicates covered by the contract artifact ({swift_files_scanned} Swift files scanned)")
else:
    pass_msg("iOS duplicate scan delegated to chronicle-ios repository CI (update=none)")

android_settings = root / "chronicle/settings.gradle"
android_build = root / "chronicle/app/build.gradle"
server_settings = root / "chronicle-server/settings.gradle"
server_build = root / "chronicle-server/build.gradle"
for path in [android_settings, android_build, server_settings, server_build]:
    if not path.exists():
        fail(f"required downstream build file missing: {path.relative_to(root)}")
pass_msg("downstream Android/server build files are present")
PY

python3 "$ROOT_DIR/tests/security/test_domain_contract_guardrails.py"
pass "Domain guard rejects isolated copied-value and detached-validation fixtures"

# Web descriptor label/description coverage lives in chronicle-web's own test suite.
# Run it when bun and the web dependencies are available; the textual invariants above
# already cover the structural checks when they are not.
WEB_DIR="$ROOT_DIR/chronicle-web"
if [[ -f "$WEB_DIR/src/modern/lib/study-constants.test.ts" ]]; then
  if command -v bun >/dev/null 2>&1 && [[ -d "$WEB_DIR/node_modules" ]]; then
    # Do not swallow the test output: on failure the diagnostics are the point.
    (cd "$WEB_DIR" && bun test src/modern/lib/study-constants.test.ts) ||
      fail "chronicle-web study-constants coverage test suite failed"
    pass "chronicle-web descriptor coverage test suite passes"
    (cd "$WEB_DIR" && bun test ./src/modern/state/normalizers.property.test.ts \
      -t 'counts unknown statuses without dropping their participants') ||
      fail "chronicle-web participation-status response validation test failed"
    pass "chronicle-web production participation-status response validation passes"
  else
    skip "bun/web dependencies unavailable here; descriptor coverage test runs in chronicle-web CI (build.yml bun test)"
  fi
fi

# Which modules honor a collection interval lives once, in
# chronicle-models CollectionCadenceModules (web reads it via the generated contracts;
# contract-drift-diff.py compares the lists). Fail if either side goes back to a hand copy.
ANDROID_PULL_SCHEDULE="${CHRONICLE_ANDROID_DIR:-$ROOT_DIR/chronicle}/app/src/main/java/com/openlattice/chronicle/collection/device/ExpansionPullSchedule.kt"
WEB_STUDY_CONSTANTS="$WEB_DIR/src/modern/lib/study-constants.ts"
if [[ -f "$ANDROID_PULL_SCHEDULE" && -f "$WEB_STUDY_CONSTANTS" ]]; then
  grep -Eq 'INTERVAL_GATED_MODULES[^=]*=[[:space:]]*CollectionCadenceModules\.intervalGated' "$ANDROID_PULL_SCHEDULE" ||
    fail "Android INTERVAL_GATED_MODULES no longer reads CollectionCadenceModules.intervalGated"
  tr -d '[:space:]' < "$WEB_STUDY_CONSTANTS" |
    grep -E 'INTERVAL_CONFIGURABLE_MODULES[^=]*=newSet<[^>]*>\(INTERVAL_GATED_COLLECTION_MODULE_IDS,?\)' >/dev/null ||
    fail "web INTERVAL_CONFIGURABLE_MODULES no longer reads INTERVAL_GATED_COLLECTION_MODULE_IDS"
  pass "Android and web interval-gated modules both read the chronicle-models list"
else
  skip "Android or web checkout missing; interval module source not checked"
fi

require_file_contains "$ROOT_DIR/chronicle/settings.gradle" \
  "includeBuild\\((chronicleModelsDir|'\\.\\./chronicle-models')\\)" \
  "Android build includes local chronicle-models composite source"
require_file_contains "$ROOT_DIR/chronicle/settings.gradle" \
  "CHRONICLE_MODELS_DIR|chronicleModelsDir" \
  "Android build documents configurable chronicle-models source path"
require_file_contains "$ROOT_DIR/chronicle/app/build.gradle" \
  "com\\.openlattice:chronicle-models:0\\.1\\.0-SNAPSHOT" \
  "Android app depends on chronicle-models artifact"
require_file_contains "$ROOT_DIR/chronicle-server/settings.gradle" \
  "include ':chronicle-models'" \
  "Server settings include chronicle-models project"
require_file_contains "$ROOT_DIR/chronicle-server/build.gradle" \
  "implementation\\(project\\(\":chronicle-models\"\\)\\)" \
  "Server depends on chronicle-models project"

pass "Domain contract guardrails passed"
