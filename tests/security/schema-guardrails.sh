#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCHEMA="$ROOT_DIR/ontology/chronicle.linkml.yaml"
CHRONICLE_MODELS_DIR="${CHRONICLE_MODELS_DIR:-$ROOT_DIR/chronicle-models}"

python3 - "$ROOT_DIR" "$SCHEMA" "$CHRONICLE_MODELS_DIR" <<'PY'
import re
import sys
from pathlib import Path

import yaml

root = Path(sys.argv[1])
schema_path = Path(sys.argv[2])
models_dir = Path(sys.argv[3])

schema = yaml.safe_load(schema_path.read_text(encoding="utf-8"))
enums = schema.get("enums", {})

def schema_values(name):
    values = enums[name]["permissible_values"]
    return set(values.keys())

def enum_constants(path):
    text = path.read_text(encoding="utf-8")
    if "enum class" in text:
        body = text.split("enum class", 1)[1]
    else:
        body = text.split("enum", 1)[1]
    body = body.split("{", 1)[1].rsplit("}", 1)[0]
    out = []
    for line in body.splitlines():
        line = re.sub(r"//.*", "", line).strip()
        if not line or line.startswith(("public ", "private ", "internal ", "companion ", "@")):
            continue
        match = re.match(r"([A-Za-z][A-Za-z0-9_]*)\s*(?:\(|,|;|$)", line)
        if match:
            out.append(match.group(1))
    return set(out)

def collection_module_ids(path):
    text = path.read_text(encoding="utf-8")
    return set(re.findall(r'^[ \t]*[A-Z][A-Z0-9_]*\("([a-z0-9_]+)"', text, flags=re.MULTILINE))

def string_wire_ids(path):
    text = path.read_text(encoding="utf-8")
    return set(re.findall(r'^[ \t]*[A-Z][A-Z0-9_]*\("([a-z0-9_]+)"', text, flags=re.MULTILINE))

checks = [
    (
        "SourceDeviceType",
        schema_values("SourceDeviceType"),
        enum_constants(models_dir / "src/main/kotlin/com/openlattice/chronicle/sources/SourceDeviceType.kt"),
    ),
    (
        "ParticipantDataType",
        schema_values("ParticipantDataType"),
        enum_constants(models_dir / "src/main/kotlin/com/openlattice/chronicle/study/ParticipantDataType.kt"),
    ),
    (
        "StudyFeature",
        schema_values("StudyFeature"),
        enum_constants(models_dir / "src/main/kotlin/com/openlattice/chronicle/study/StudyFeature.kt"),
    ),
    (
        "AndroidSensorType",
        schema_values("AndroidSensorType"),
        enum_constants(models_dir / "src/main/kotlin/com/openlattice/chronicle/android/AndroidSensorType.kt"),
    ),
    (
        "ParticipationStatus",
        schema_values("ParticipationStatus"),
        enum_constants(models_dir / "src/main/java/com/openlattice/chronicle/data/ParticipationStatus.java"),
    ),
    (
        "StudyLifecycleStatus",
        schema_values("StudyLifecycleStatus"),
        enum_constants(models_dir / "src/main/kotlin/com/openlattice/chronicle/study/StudyLifecycleStatus.kt"),
    ),
    (
        "ConsentTrigger",
        schema_values("ConsentTrigger"),
        enum_constants(models_dir / "src/main/kotlin/com/openlattice/chronicle/collection/ConsentTrigger.kt"),
    ),
    (
        "CollectionPrivacyClass",
        schema_values("CollectionPrivacyClass"),
        enum_constants(models_dir / "src/main/kotlin/com/openlattice/chronicle/collection/CollectionPrivacyClass.kt"),
    ),
    (
        "CollectionModuleId",
        schema_values("CollectionModuleId"),
        collection_module_ids(models_dir / "src/main/kotlin/com/openlattice/chronicle/collection/CollectionModuleId.kt"),
    ),
]

failed = False
for name, expected, actual in checks:
    missing = sorted(actual - expected)
    stale = sorted(expected - actual)
    if missing or stale:
        failed = True
        print(f"{name} drift:")
        if missing:
            print(f"  missing from LinkML: {', '.join(missing)}")
        if stale:
            print(f"  stale in LinkML: {', '.join(stale)}")

if failed:
    raise SystemExit(1)

print("Chronicle LinkML schema parses and selected enum mirrors are in sync")
PY

"$ROOT_DIR/scripts/generate-chronicle-contracts.py" --check

python3 - "$ROOT_DIR" "$SCHEMA" <<'PY'
import json
import re
import sys
from pathlib import Path

root = Path(sys.argv[1])
schema_path = Path(sys.argv[2])
expected = __import__("hashlib").sha256(schema_path.read_bytes()).hexdigest()

checks = [
    (
        root / "docs/generated/chronicle-contracts.md",
        re.compile(rf"Source SHA-256: `{re.escape(expected)}`\."),
    ),
    (
        root / "chronicle-web/src/modern/generated/chronicle-contracts.ts",
        re.compile(rf"// Source-SHA256: {re.escape(expected)}"),
    ),
    (
        root / "deploy/cue/chronicle_contracts.gen.cue",
        re.compile(rf"// Source-SHA256: {re.escape(expected)}"),
    ),
]
for path, pattern in checks:
    if not path.exists():
        raise SystemExit(f"Generated artifact missing: {path.relative_to(root)}")
    if pattern.search(path.read_text(encoding="utf-8")) is None:
        raise SystemExit(f"Generated artifact lacks current LinkML source SHA-256: {path.relative_to(root)}")

domain_json = root / "generated/domain-contracts/chronicle-domain-contracts.json"
payload = json.loads(domain_json.read_text(encoding="utf-8"))
actual = payload.get("sourceFiles", {}).get("linkml", {}).get("sha256")
if actual != expected:
    raise SystemExit(
        "Generated domain contract has stale LinkML source SHA-256: "
        f"expected {expected}, got {actual!r}"
    )

print("Generated contract artifacts carry the current LinkML source SHA-256")
PY

python3 - "$ROOT_DIR" <<'PY'
import re
import sys
from pathlib import Path

root = Path(sys.argv[1])
runtime_root = root / "chronicle-server/src/main/kotlin"
# chronicle_restore_continuity is restore-time checkpoint state owned by restore.sh and the
# reconciler's contract upgrades, not Flyway-managed application schema.
permanent_table_sql = re.compile(
    r"\bCREATE\s+(?!(?:TEMP|TEMPORARY)\s+)TABLE\b(?!\s+(?:IF\s+NOT\s+EXISTS\s+)?chronicle_restore_continuity\.)",
    flags=re.IGNORECASE,
)
table_definition_execution = re.compile(r"\.createTableQuery\s*\(")

violations = []
for path in sorted(runtime_root.rglob("*.kt")):
    text = path.read_text(encoding="utf-8")
    for label, pattern in (
        ("literal permanent CREATE TABLE", permanent_table_sql),
        ("PostgresTableDefinition.createTableQuery()", table_definition_execution),
    ):
        for match in pattern.finditer(text):
            line = text.count("\n", 0, match.start()) + 1
            violations.append((path.relative_to(root), line, label))

if violations:
    for path, line, label in violations:
        print(f"Runtime schema DDL is forbidden outside Flyway: {path}:{line}: {label}")
    raise SystemExit(1)

print("Permanent Chronicle server tables are owned by Flyway rather than service startup")
PY
