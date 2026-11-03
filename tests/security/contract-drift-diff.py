#!/usr/bin/env python3
"""Diff Chronicle's shared value sets across every consumer.

Surfaces compared:
  0. OpenAPI -> chronicle-api/chronicle.yaml component enums
  1. LinkML  -> generated/domain-contracts/chronicle-domain-contracts.json (root)
  3. Web     -> chronicle-web/src/modern/generated/chronicle-contracts.ts (tuples)
  4. Android -> no local redefinition of the canonical enums; every module id
                referenced as a CollectionModuleId constant, not a raw literal
  5. The tests/security/ast-grep raw-module-id rule must cover every module id

Exit 1 on any drift. Called from tests/security/domain-contract-guardrails.sh.
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parents[2]

LINKML = ROOT / "generated/domain-contracts/chronicle-domain-contracts.json"
WEB_TS = ROOT / "chronicle-web/src/modern/generated/chronicle-contracts.ts"
ASTG_RULE = ROOT / "tests/security/ast-grep/collection-module-id-no-raw-string.yml"
ANDROID = ROOT / "chronicle"

# canonical json key -> web tuple export name
TUPLES = {
    "activeCollectionModuleIds": None,  # derived below, compared against COLLECTION_MODULE_IDS
    "studyFeatures": "STUDY_FEATURES",
    "participantDataTypes": "PARTICIPANT_DATA_TYPES",
    "participationStatuses": "PARTICIPATION_STATUSES",
    "studyLifecycleStatuses": "STUDY_LIFECYCLE_STATUSES",
    "consentTriggers": "CONSENT_TRIGGERS",
    "apiKeyScopes": "API_KEY_SCOPES",
    "androidUploadIssueCodes": "ANDROID_UPLOAD_ISSUE_CODES",
    "participantFormKinds": "PARTICIPANT_FORM_KINDS",
    "uploadTypes": "UPLOAD_TYPES",
    "androidSensorTypes": "ANDROID_SENSOR_TYPES",
    "intervalGatedCollectionModuleIds": "INTERVAL_GATED_COLLECTION_MODULE_IDS",
    "consentGatedCollectionModuleIds": "CONSENT_GATED_COLLECTION_MODULE_IDS",
    "playStoreBuildCollectionModuleIds": "PLAY_STORE_BUILD_COLLECTION_MODULE_IDS",
}

failures: list[str] = []


def ts_tuple(text: str, name: str) -> list[str]:
    m = re.search(rf"export const {name} = \[(.*?)\] as const;", text, re.DOTALL)
    if not m:
        failures.append(f"chronicle-web generated contracts export no {name}")
        return []
    return re.findall(r"'([^']+)'", m.group(1))


def server_assigned_issue_codes(root):
    """Issue codes the LinkML ontology marks serverAssigned: the server stores them, a phone never sends them."""
    import yaml
    values = yaml.safe_load((root / "ontology/chronicle.linkml.yaml").read_text())["enums"]["AndroidUploadIssueCode"]["permissible_values"]
    return {code for code, body in values.items()
            if (((body or {}).get("annotations") or {}).get("serverAssigned") or {}).get("value") is True}


def check_upload_diagnostics(root, spec):
    properties = spec["AndroidUploadDiagnosticEvent"]["properties"]
    server_assigned = server_assigned_issue_codes(root)
    model = (root / "chronicle-models/src/main/kotlin/com/openlattice/chronicle/collection/AndroidUploadDiagnosticEvent.kt").read_text()
    issue_codes = (root / "chronicle-models/src/main/kotlin/com/openlattice/chronicle/collection/AndroidUploadIssueCode.kt").read_text()
    android = (root / "chronicle/app/src/main/java/com/openlattice/chronicle/services/upload/LocalUploadDiagnosticsStore.kt").read_text()
    destination = (root / "chronicle/app/src/main/java/com/openlattice/chronicle/services/upload/UploadPolicy.kt").read_text()
    web = (root / "chronicle-web/src/modern/types/chronicle-api.generated.ts").read_text()
    block = re.search(r"\n        AndroidUploadDiagnosticEvent: \{(.*?)\n        \};", web, re.DOTALL)
    if not block:
        raise ValueError("web has no AndroidUploadDiagnosticEvent schema")
    sql = {}
    migrations = root / "chronicle-server/src/main/resources/db/migration"
    for migration in sorted(migrations.glob("V*__*.sql"), key=lambda path: int(path.name.split("__")[0][1:])):
        for column, values in re.findall(r"CHECK\s*\(\s*(?:\(\s*)*(module_family|issue_code)\s+IN\s*\((.*?)\)\s*\)", migration.read_text(), re.DOTALL | re.IGNORECASE):
            sql[column] = set(re.findall(r"'([^']+)'", values))
    for field, constant, column, enum in (
        ("moduleFamily", "MODULE_FAMILIES", "module_family", "LocalUploadModuleFamily"),
        ("issueCode", "ISSUE_CODES", "issue_code", "LocalOperationalIssue"),
    ):
        canonical = set(properties[field]["x-extensible-enum" if field == "issueCode" else "enum"])
        kotlin = re.search(rf"val {constant} = setOf\((.*?)\)", model, re.DOTALL)
        if field == "issueCode":
            # The model derives its codes from the generated AndroidUploadIssueCode enum.
            kotlin = re.search(r"enum class AndroidUploadIssueCode \{(.*?)\}", issue_codes, re.DOTALL)
        generated = re.search(rf"\b{field}: ([^;]+);", block.group(1))
        if not canonical or not kotlin or not generated or column not in sql:
            raise ValueError(f"incomplete upload diagnostic catalog: {field}")
        mobile_catalogs = {enum: android}
        if field == "issueCode":
            mobile_catalogs.update(UploadDestinationIssue=destination, UploadFailureIssue=android)
        mobile = set()
        for name, source in mobile_catalogs.items():
            local = re.search(rf"enum class {name}\s*\{{(.*?)\}}", source, re.DOTALL)
            if not local:
                raise ValueError(f"incomplete Android diagnostic catalog: {name}")
            mobile.update(re.findall(r"\b[A-Z][A-Z_]+\b", local.group(1)))
        model_values = (re.findall(r"\b([A-Z][A-Z_]+),", kotlin.group(1)) if field == "issueCode"
                        else re.findall(r'"([^"]+)"', kotlin.group(1)))
        consumers = {"model": set(model_values), "SQL": sql[column], "Android": mobile}
        if field == "issueCode":
            if properties[field].get("type") != "string" or "enum" in properties[field] or generated.group(1) != "string":
                failures.append("upload diagnostics issueCode must accept unknown bounded strings")
            consumers["web"] = set(ts_tuple((root / "chronicle-web/src/modern/generated/chronicle-contracts.ts").read_text(),
                                            "ANDROID_UPLOAD_ISSUE_CODES"))
        else:
            consumers["web"] = set(re.findall(r'"([^"]+)"', generated.group(1)))
        for consumer, values in consumers.items():
            # The phone's catalog is what it can send, so it compares against the codes the server does not assign.
            expected = canonical - server_assigned if consumer == "Android" and field == "issueCode" else canonical
            if values != expected:
                failures.append(f"upload diagnostics {consumer} {field}: missing {sorted(expected - values)}, extra {sorted(values - expected)}")


def check_mirrors(linkml, web, module_ids):
    # 1 vs 3 -- canonical sets against the web's generated tuples.
    if ts_tuple(web, "COLLECTION_MODULE_IDS") != module_ids:
        failures.append("web COLLECTION_MODULE_IDS != contract collectionModules")
    for key, export in TUPLES.items():
        if export and ts_tuple(web, export) != linkml[key]:
            failures.append(f"web {export} != contract {key}")



def check_openapi(linkml, spec, module_ids):
    # 1 vs OpenAPI -- the published spec (source of chronicle-api.generated.ts and the
    #      payload contracts) must carry the same enum members.
    for schema, canon in (
        ("CollectionModuleId", module_ids),
        ("CollectionConsentTrigger", linkml["consentTriggers"]),
        ("ParticipationStatus", linkml["participationStatuses"]),
        ("ApiKeyScope", linkml["apiKeyScopes"]),
        ("ParticipantFormKind", linkml["participantFormKinds"]),
        ("ParticipantDataType", linkml["participantDataTypes"]),
    ):
        got = spec.get(schema, {}).get("enum")
        if got is None:
            failures.append(f"OpenAPI has no enum schema {schema}")
        elif set(got) != set(canon):
            failures.append(
                f"OpenAPI {schema} drift: missing {sorted(set(canon) - set(got))}, extra {sorted(set(got) - set(canon))}"
            )

    check_upload_diagnostics(ROOT, spec)

    # OpenAPI AndroidSensorSetting must carry the Kotlin model's fields (named units, so
    # no bare samplingRate) and the canonical sensor-type enum.
    kt = (ROOT / "chronicle-models/src/main/kotlin/com/openlattice/chronicle/android/AndroidSensorSetting.kt").read_text()
    kt_fields = set(re.findall(r"(?m)^\s+val (\w+):", kt))  # constructor params, not the companion
    sensor_setting = spec.get("AndroidSensorSetting", {})
    spec_fields = set(sensor_setting.get("properties", {})) - {"@class"}
    if spec_fields != kt_fields:
        failures.append(
            f"OpenAPI AndroidSensorSetting drift: missing {sorted(kt_fields - spec_fields)}, extra {sorted(spec_fields - kt_fields)}"
        )
    sensor_enum = spec.get("AndroidSensorType", {}).get("enum")
    if sensor_enum != linkml["androidSensorTypes"]:
        failures.append("OpenAPI AndroidSensorType enum != contract androidSensorTypes")
    items = sensor_setting.get("properties", {}).get("sensors", {}).get("items", {})
    if items.get("$ref") != "#/components/schemas/AndroidSensorType":
        failures.append("OpenAPI AndroidSensorSetting.sensors items must $ref AndroidSensorType")



def check_android(module_ids):
    # 4 -- Android must not redefine a canonical enum.
    canonical = ("CollectionModuleId", "StudyFeature",
                 "CollectionPrivacyClass", "ConsentTrigger", "StudyLifecycleStatus",
                 "ApiKeyScope", "ParticipantFormKind", "UploadType")
    for kt in ANDROID.rglob("*.kt"):
        if "/build/" in str(kt):
            continue
        text = kt.read_text(errors="ignore")
        for sym in canonical:
            if re.search(rf"\benum class {sym}\b", text):
                failures.append(f"Android redefines canonical enum {sym}: {kt.relative_to(ROOT)}")

    # 5 -- the raw-literal guardrail must name every module id, and no production
    #      Android collection source may carry a module id as a bare string.
    rule = ASTG_RULE.read_text()
    covered = set(re.findall(r"pattern: '\"([a-z_]+)\"'", rule))
    uncovered = sorted(set(module_ids) - covered)
    if uncovered:
        failures.append(f"ast-grep raw-module-id rule does not cover: {', '.join(uncovered)}")
    literal = re.compile('"(' + "|".join(re.escape(i) for i in module_ids) + ')"')
    for kt in ANDROID.rglob("*.kt"):
        parts = str(kt)
        if "/build/" in parts or "/test/" in parts or "/androidTest" in parts:
            continue
        if "/collection/" not in parts:
            continue
        for n, line in enumerate(kt.read_text(errors="ignore").splitlines(), 1):
            stripped = line.lstrip()
            if stripped.startswith(("//", "*", "/*")):
                continue
            code = line.split("//", 1)[0]
            # log labels and WorkManager unique names are not wire ids
            if re.search(r"\blabel\s*=|WORK_NAME\s*=", code):
                continue
            m = literal.search(code)
            if m:
                failures.append(
                    f"raw module-id literal {m.group(0)} at {kt.relative_to(ROOT)}:{n}"
                    " -- use CollectionModuleId.<CONST>.id"
                )



def edge_routes():
    """Exact paths the selfhost Caddy edge answers itself (`handle /path {`), outside the backend API."""
    return {match for caddyfile in (ROOT / "selfhost").glob("Caddyfile*")
            for match in re.findall(r"^\s*handle (/[^\s*{]+) \{", caddyfile.read_text(), re.MULTILINE)}


def check_numeric_units(schemas):
    """Numeric measurements carry a unit in their wire name or description."""
    for model, schema in schemas.items():
        for name, field in schema.get("properties", {}).items():
            values = field.get("additionalProperties")
            numeric = field.get("type") in {"integer", "number"} or isinstance(values, dict) and values.get("type") in {"integer", "number"}
            measurement = re.search(r"time|duration|usage|size|rate|interval|timeout", name, re.IGNORECASE)
            named_unit = re.search(r"Seconds|Millis(?:econds)?|Minutes|Hours|Days|Bytes|Pixels|Dpi|Hz|Count|Revision|Version$", name)
            described_unit = re.search(r"\b(seconds?|milliseconds?|minutes?|hours?|days?|bytes?|hertz|hz|pixels?|count)\b", field.get("description", ""), re.IGNORECASE)
            if numeric and measurement and not named_unit and not described_unit:
                failures.append(f"OpenAPI numeric measurement has no unit: {model}.{name}")


def check_typed_bodies(paths, schemas=None):
    visited = set()
    def visit(node, location):
        if not isinstance(node, dict):
            return
        reference = node.get("$ref", "").removeprefix("#/components/schemas/")
        if schemas and reference in schemas and reference not in visited:
            visited.add(reference)
            visit(schemas[reference], f"{location} -> {reference}")
        if node.get("type") == "object" and not any(key in node for key in ("properties", "additionalProperties", "$ref", "allOf", "oneOf", "anyOf")):
            failures.append(f"OpenAPI body has an opaque object: {location}")
        for key, child in node.items():
            if isinstance(child, dict):
                visit(child, f"{location}/{key}")
            elif isinstance(child, list):
                for index, item in enumerate(child):
                    visit(item, f"{location}/{key}/{index}")
    for path, operations in paths.items():
        for method, operation in operations.items():
            if isinstance(operation, dict):
                for key in ("requestBody", "responses"):
                    visit(operation.get(key), f"{method.upper()} {path}/{key}")


def check_api_literal_unions(source):
    for name in re.findall(r"^export type (\w+)\s*=\s*(?:\|\s*)?['\"][^'\"]+['\"](?:\s*\|\s*['\"][^'\"]+['\"])+\s*;", source, re.MULTILINE):
        failures.append(f"web API enum must use a generated contract: {name}")


def check_request_operations(paths, extracted, edge):
    documented = [(method.upper(), re.compile(re.sub(r"\\\{[^}]*\\\}", "[^/]+", re.escape(path))))
                  for path, operations in paths.items() for method in operations
                  if method in {"get", "post", "put", "patch", "delete", "head", "options"}]
    requests = set()
    for request in extracted:
        path = request["path"].split("?", 1)[0].rstrip("/")
        if not path.startswith("/") and "/chronicle/" in path:
            path = path[path.index("/chronicle/"):]
        if not path.startswith("/"):
            continue
        if request["callee"] == "fetch" and not path.startswith("/chronicle/"):
            if path not in edge:
                failures.append(f"web same-origin fetch has no selfhost edge route: {path}")
            continue
        path = re.sub(r"^/chronicle/api/web(?=/|$)", "/chronicle/v3", path)
        if not path.startswith("/chronicle/"):
            path = "/chronicle/v3" + path
        requests.add((request["method"], path))
    for method, path in sorted(requests):
        if not any(method == declared and pattern.fullmatch(path) for declared, pattern in documented):
            failures.append(f"web request operation is absent from OpenAPI: {method} {path}")


def check_web_request_paths(paths):
    """Structural lint: executable web request sites must have an OpenAPI path, or, for a raw
    same-origin fetch outside /chronicle/, a route the selfhost edge serves."""
    edge = edge_routes()
    sources = sorted(path for path in (ROOT / "chronicle-web/src/modern").rglob("*.ts*")
                     if ".test." not in path.name and ".generated." not in path.name
                     and "generated" not in path.parts and "test" not in path.parts)
    extracted = subprocess.run(["bun", str(ROOT / "tests/security/endpoint-consumers.ts"),
                                *map(str, sources)], check=True, capture_output=True, text=True)
    check_request_operations(paths, json.loads(extracted.stdout), edge)


def main() -> int:
    import yaml
    linkml = json.loads(LINKML.read_text())["contracts"]
    web = WEB_TS.read_text()
    module_ids = [module["id"] for module in linkml["collectionModules"]]
    check_mirrors(linkml, web, module_ids)
    document = yaml.safe_load((ROOT / "chronicle-api/chronicle.yaml").read_text())
    spec = document["components"]["schemas"]
    check_openapi(linkml, spec, module_ids)
    check_numeric_units(spec)
    check_typed_bodies(document["paths"], spec)
    check_api_literal_unions((ROOT / "chronicle-web/src/modern/state/study-operations-api.ts").read_text())
    check_android(module_ids)
    check_web_request_paths(document["paths"])

    for f in failures:
        print(f"FAIL: {f}")
    if failures:
        print(f"\n{len(failures)} contract-drift failure(s)")
        return 1
    print("PASS: all Chronicle value sets agree across LinkML, chronicle-models, web, Android")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
