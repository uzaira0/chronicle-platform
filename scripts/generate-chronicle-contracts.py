#!/usr/bin/env python3
"""Generate checked Chronicle contract artifacts from the LinkML schema."""

from __future__ import annotations

import argparse
import difflib
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "ontology" / "chronicle.linkml.yaml"
OPENAPI_PATH = ROOT / "chronicle-api" / "chronicle.yaml"
OPEN_MODULE_REGISTRY = ROOT / "chronicle/app/src/open/assets/approved-module-registry.json"
FORM_WINDOW_FIXTURE = ROOT / "ontology" / "participant-form-windows.json"
PAYLOAD_FIXTURE_REGISTRY = ROOT / "chronicle-models/fixtures/payloads/registry.json"
WEB_BACKEND_GOLDENS = tuple(sorted((ROOT / "chronicle-web/src/modern/test/golden").glob("backend-*.json")))
WEB_DAY_FIXTURE = ROOT / "chronicle-web/src/modern/test/golden/exact-day-study-limits.json"
STRING_LENGTH_CASES = ROOT / "tests/security/fixtures/string-length-cases.json"
RESTORE_CHECKPOINT_TEMPLATES = tuple(sorted((ROOT / "selfhost").glob("restore-checkpoint-*.sql.template")))
RESTORE_CHECKPOINT_PARTS = {
    "CHECKPOINT_DIGEST_SQL": ROOT / "selfhost/restore-continuity-digest.sql",
    "AUTHORITIES_SCHEMA_SQL": ROOT / "selfhost/restore-authorities-schema.sql",
    "RESTRICTIONS_SCHEMA_SQL": ROOT / "selfhost/restore-restrictions-schema.sql",
    "RESTRICTIONS_VERIFICATION_SQL": ROOT / "selfhost/restore-restrictions-verify.sql",
    "RESTORE_CONTINUITY_CONTRACT_VERSION": ROOT / "selfhost/restore-continuity.version",
}
FRESH_SCHEMA_PATH = ROOT / "chronicle-server/src/main/resources/db/migration/V1__fresh_schema.sql"
RESTORE_RECEIPT_VERSION_PREFIX = "    CONSTRAINT restore_continuity_reconciliations_contract_version_check CHECK ((contract_version = "
OUTPUTS = {
    ROOT / "docs" / "generated" / "chronicle-contracts.md": "markdown",
    ROOT / "chronicle-web" / "src" / "modern" / "generated" / "chronicle-contracts.ts": "typescript",
    ROOT / "deploy" / "cue" / "chronicle_contracts.gen.cue": "cue",
    ROOT / "generated" / "domain-contracts" / "chronicle-domain-contracts.json": "domain-json",
}
UPLOAD_LIMIT_FIELD = "MAX_REQUEST_SIZE_BYTES"
UPLOAD_HEADROOM_FIELD = "REQUEST_HEADER_HEADROOM_BYTES"
UPLOAD_LIMIT_ADAPTERS = {
    ROOT / "selfhost/caddy/snippets.caddy": (
        "\timport chronicle_body_limit {limit}\n", "        read_body {body_timeout}s\n"),
    ROOT / "selfhost/chronicle": (
        "LB_MIN_BODY_BYTES={limit}\n", "LB_MIN_HEADER_BYTES={header_headroom}\n",
        "LB_MIN_IDLE_SECONDS={body_timeout}\n"),
    ROOT / "selfhost/.env.example": (
        "LB_MAX_BODY_BYTES={limit}\n", "LB_IDLE_TIMEOUT_SECONDS={body_timeout}\n",
        "LB_MAX_HEADER_BYTES={header_headroom}\n"),
    ROOT / "tests/deployment/selfhost-topology.compose.yml":
        "      TOPOLOGY_BODY_LIMIT: ${{TOPOLOGY_BODY_LIMIT:-{limit}}}\n",
}
RHIZOME_TEMPLATE = ROOT / "selfhost/config/rhizome.yaml.template"
JETTY_TEMPLATE = ROOT / "selfhost/config/jetty.yaml.template"
INPUTS = (SCHEMA_PATH, RHIZOME_TEMPLATE, JETTY_TEMPLATE, OPEN_MODULE_REGISTRY, OPENAPI_PATH, FORM_WINDOW_FIXTURE, PAYLOAD_FIXTURE_REGISTRY, WEB_DAY_FIXTURE, STRING_LENGTH_CASES, *WEB_BACKEND_GOLDENS,
          *RESTORE_CHECKPOINT_TEMPLATES, *RESTORE_CHECKPOINT_PARTS.values(), *UPLOAD_LIMIT_ADAPTERS, FRESH_SCHEMA_PATH)


TS_EXPORT_NAMES = {
    "AndroidUploadIssueCode": "ANDROID_UPLOAD_ISSUE_CODES",
    "ApiKeyScope": "API_KEY_SCOPES",
    "ParticipantFormKind": "PARTICIPANT_FORM_KINDS",
    "UploadType": "UPLOAD_TYPES",
    "BrowserErrorKind": "BROWSER_ERROR_KINDS",
    "StudySettingType": "STUDY_SETTING_TYPES",
    "AppUsageFrequency": "APP_USAGE_FREQUENCIES",
    "AppUsageDayState": "APP_USAGE_DAY_STATES",
    "AppUsageDayConflict": "APP_USAGE_DAY_CONFLICTS",
    "DeploymentProfile": "DEPLOYMENT_PROFILES",
    "ObservabilityBackend": "OBSERVABILITY_BACKENDS",
    "SourceDeviceType": "SOURCE_DEVICE_TYPES",
    "ParticipantDataType": "PARTICIPANT_DATA_TYPES",
    "ParticipationStatus": "PARTICIPATION_STATUSES",
    "StudyLifecycleStatus": "STUDY_LIFECYCLE_STATUSES",
    "ConsentTrigger": "CONSENT_TRIGGERS",
    "CollectionPrivacyClass": "COLLECTION_PRIVACY_CLASSES",
    "WithdrawalMode": "WITHDRAWAL_MODE_VALUES",
    "CollectionModuleId": "COLLECTION_MODULE_IDS",
    "AndroidSensorType": "ANDROID_SENSOR_TYPES",
    "StudyFeature": "STUDY_FEATURES",
}


def upload_limit_bytes(schema: dict) -> int:
    limit = schema["constants"][UPLOAD_LIMIT_FIELD]["value"]
    if type(limit) is not int or not 0 < limit <= 2**31 - 1:
        raise ValueError("The upload limit must be a positive Kotlin Int-sized byte count")
    headroom = schema["constants"][UPLOAD_HEADROOM_FIELD]["value"]
    if type(headroom) is not int or not 0 < headroom < limit:
        raise ValueError("Upload header headroom must be positive and smaller than the body limit")
    return limit


def render_kotlin_constants(schema: dict) -> str:
    return "\n".join(generated_header("//") + [
        "", "package com.openlattice.chronicle.generated", "",
        "public object UploadLimits {",
        f"    public const val {UPLOAD_LIMIT_FIELD}: Long = {upload_limit_bytes(schema)}L",
        f"    public const val {UPLOAD_HEADROOM_FIELD}: Int = {schema['constants'][UPLOAD_HEADROOM_FIELD]['value']}",
        f"    public const val UPLOAD_ROW_REJECTED_CODE: String = \"{schema['constants']['UPLOAD_ROW_REJECTED_CODE']['value']}\"",
        "}", "",
    ])


def enrollment_locked_fields(schema: dict) -> dict[str, str]:
    fields = {}
    for name, body in enum_value_bodies(schema, "StudySettingType"):
        if annotation(body, "lockedAfterEnrollment") is None or not annotation_bool(body, "lockedAfterEnrollment"):
            continue
        field = annotation(body, "formField")
        if not field:
            raise ValueError(f"Enrollment-locked setting {name} needs its form field")
        fields[name] = field
    return fields


def synchronous_export_limits(schema: dict) -> dict[str, int]:
    limits = {name: body["value"] for name, body in schema["constants"].items() if name.startswith("SYNC_EXPORT_")}
    if any(type(value) is not int or not 0 < value <= 2**31 - 1 for value in limits.values()):
        raise ValueError("Synchronous export limits must be positive Kotlin Int values")
    return limits


def browser_download_fields(schema: dict) -> dict[str, str]:
    fields = {name: body["value"] for name, body in schema["constants"].items() if name.startswith("BROWSER_DOWNLOAD_")}
    if any(not isinstance(value, str) or not value for value in fields.values()):
        raise ValueError("Browser download fields must be nonempty strings")
    return fields


COLLECTION_DEFAULT_INTS = ("COLLECTION_DEFAULT_SENSOR_RATE_HZ", "COLLECTION_DEFAULT_SENSOR_DUTY_ACTIVE_SECONDS",
                           "COLLECTION_DEFAULT_SENSOR_DUTY_PERIOD_SECONDS", "COLLECTION_DEFAULT_INTERVAL_SECONDS")


def collection_defaults(schema: dict) -> dict[str, Any]:
    """The defaults a study inherits when it names none; one owner for Kotlin, the web and the spec."""
    values = {name: schema["constants"][name]["value"] for name in
              (*COLLECTION_DEFAULT_INTS, "STUDY_DEFAULT_WITHDRAWAL_MODE")}
    if any(type(values[name]) is not int or values[name] <= 0 for name in COLLECTION_DEFAULT_INTS):
        raise ValueError("Collection defaults must be positive integers")
    if values["STUDY_DEFAULT_WITHDRAWAL_MODE"] not in dict(enum_values(schema, "WithdrawalMode")):
        raise ValueError("STUDY_DEFAULT_WITHDRAWAL_MODE must be a WithdrawalMode")
    spec = yaml.safe_load(OPENAPI_PATH.read_text(encoding="utf-8"))["components"]["schemas"]["AndroidSensorSetting"]["properties"]
    for field, name in (("samplingRateHz", "COLLECTION_DEFAULT_SENSOR_RATE_HZ"),
                        ("dutyCycleActiveSeconds", "COLLECTION_DEFAULT_SENSOR_DUTY_ACTIVE_SECONDS"),
                        ("dutyCyclePeriodSeconds", "COLLECTION_DEFAULT_SENSOR_DUTY_PERIOD_SECONDS")):
        if spec[field].get("default") != values[name]:
            raise ValueError(f"OpenAPI AndroidSensorSetting.{field} default must match {name}")
    return values


def collection_default_outputs(schema: dict) -> dict[Path, str]:
    values = collection_defaults(schema)
    lines = generated_header("//") + ["", "package com.openlattice.chronicle.generated", "",
        "import com.openlattice.chronicle.study.WithdrawalMode", "",
        "public object CollectionDefaultValues {",
        f"    public const val SENSOR_RATE_HZ: Int = {values['COLLECTION_DEFAULT_SENSOR_RATE_HZ']}",
        f"    public const val SENSOR_DUTY_ACTIVE_SECONDS: Int = {values['COLLECTION_DEFAULT_SENSOR_DUTY_ACTIVE_SECONDS']}",
        f"    public const val SENSOR_DUTY_PERIOD_SECONDS: Int = {values['COLLECTION_DEFAULT_SENSOR_DUTY_PERIOD_SECONDS']}",
        f"    public const val INTERVAL_SECONDS: Long = {values['COLLECTION_DEFAULT_INTERVAL_SECONDS']}L",
        f"    public val WITHDRAWAL_MODE: WithdrawalMode = WithdrawalMode.{values['STUDY_DEFAULT_WITHDRAWAL_MODE']}",
        "}", ""]
    return {ROOT / "chronicle-models/src/main/kotlin/com/openlattice/chronicle/generated/CollectionDefaultValues.kt": "\n".join(lines)}


def header_fields(schema: dict) -> dict[str, str]:
    fields = {name: body["value"] for name, body in schema["constants"].items()
              if name.endswith(("_HEADER", "_HEADER_VALUE"))}
    if any(not isinstance(value, str) or not value for value in fields.values()):
        raise ValueError("Header names and values must be nonempty strings")
    return fields


def web_policy_outputs(schema: dict) -> dict[Path, str]:
    values = schema["constants"]
    api = yaml.safe_load(OPENAPI_PATH.read_text(encoding="utf-8"))
    lines = generated_header("//") + ["", "package com.openlattice.chronicle.generated", "", "public object SynchronousExportBounds {"]
    for name in synchronous_export_limits(schema):
        lines.append(f"    public const val {name}: Int = {values[name]['value']}")
    lines += ["}", ""]
    browser = generated_header("//") + ["", "package com.openlattice.chronicle.generated", "", "public object BrowserDownloadContracts {"]
    browser += [f"    public const val {name}: String = {json.dumps(value)}" for name, value in browser_download_fields(schema).items()]
    browser += ["}", ""]
    error_path = values["BROWSER_ERROR_REPORT_PATH"]["value"]
    report = api["paths"][error_path]["post"]["requestBody"]["content"]["application/json"]["schema"]
    if report["properties"]["kind"]["enum"] != [value for value, _ in enum_values(schema, "BrowserErrorKind")]:
        raise ValueError("Browser error kinds must match their LinkML owner")
    errors = generated_header("//") + ["", "package com.openlattice.chronicle.generated", "",
        "public object BrowserErrorContracts {",
        f"    public const val BROWSER_ERROR_REPORT_PATH: String = {json.dumps(error_path)}", "}", ""]
    processing = generated_header("//") + ["", "package com.openlattice.chronicle.generated", "",
        "public object ParticipantProcessingContracts {",
        f"    public const val PARTICIPANT_PROCESSING_BLOCKED_CODE: String = {json.dumps(values['PARTICIPANT_PROCESSING_BLOCKED_CODE']['value'])}",
        f"    public const val PARTICIPANT_ID_PATTERN: String = {json.dumps(values['PARTICIPANT_ID_PATTERN']['value'])}", "}", ""]
    return {ROOT / "chronicle-models/src/main/kotlin/com/openlattice/chronicle/generated/SynchronousExportBounds.kt": "\n".join(lines),
            ROOT / "chronicle-models/src/main/kotlin/com/openlattice/chronicle/generated/BrowserDownloadContracts.kt": "\n".join(browser),
            ROOT / "chronicle-models/src/main/kotlin/com/openlattice/chronicle/generated/BrowserErrorContracts.kt": "\n".join(errors),
            ROOT / "chronicle-models/src/main/kotlin/com/openlattice/chronicle/generated/ParticipantProcessingContracts.kt": "\n".join(processing)}


def study_enum_outputs(schema: dict) -> dict[Path, str]:
    api = yaml.safe_load(OPENAPI_PATH.read_text(encoding="utf-8"))
    if api["components"]["schemas"]["WithdrawalMode"]["enum"] != [value for value, _ in enum_values(schema, "WithdrawalMode")]:
        raise ValueError("OpenAPI WithdrawalMode must match its LinkML owner")
    api_frequency = api["components"]["schemas"]["AppUsageFrequency"]["enum"]
    if api_frequency != [value for value, _ in enum_values(schema, "AppUsageFrequency")]:
        raise ValueError("OpenAPI AppUsageFrequency must match its LinkML owner")
    if api["components"]["schemas"]["AppUsageDayState"]["enum"] != [value for value, _ in enum_values(schema, "AppUsageDayState")]:
        raise ValueError("OpenAPI AppUsageDayState must match its LinkML owner")
    api_issue_codes = api["components"]["schemas"]["AndroidUploadDiagnosticEvent"]["properties"]["issueCode"]["x-extensible-enum"]
    if api_issue_codes != [value for value, _ in enum_values(schema, "AndroidUploadIssueCode")]:
        raise ValueError("OpenAPI AndroidUploadDiagnosticEvent.issueCode must match its LinkML owner")
    outputs = {}
    for name, package in (("StudySettingType", "study"), ("AppUsageFrequency", "settings"), ("BrowserErrorKind", "observability"),
                          ("AndroidUploadIssueCode", "collection"), ("WithdrawalMode", "study"),
                          ("AppUsageDayState", "survey"), ("AppUsageDayConflict", "survey")):
        lines = generated_header("//") + ["", f"package com.openlattice.chronicle.{package}", "",
            f"public enum class {name}" + ("(public val lockedAfterEnrollment: Boolean)" if name == "StudySettingType" else "") + " {"]
        for value, body in enum_value_bodies(schema, name):
            argument = f"({str(value in enrollment_locked_fields(schema)).lower()})" if name == "StudySettingType" else ""
            lines.append(f"    {value}{argument},")
        lines.extend(["}", ""])
        outputs[ROOT / f"chronicle-models/src/main/kotlin/com/openlattice/chronicle/{package}/{name}.kt"] = "\n".join(lines)
    for name, target in (
        ("ApiKeyScope", "chronicle-api/src/main/kotlin/com/openlattice/chronicle/apikey/ApiKeyScope.kt"),
        ("UploadType", "chronicle-server/src/main/kotlin/com/openlattice/chronicle/services/upload/UploadType.kt"),
        ("ParticipantFormKind", "chronicle-models/src/main/kotlin/com/openlattice/chronicle/participantaccess/ParticipantFormKind.kt"),
    ):
        package = target.split("/com/openlattice/chronicle/", 1)[1].rsplit("/", 1)[0].replace("/", ".")
        parameters = "(public val countsAsResearchReceipt: Boolean)" if name == "UploadType" else ""
        lines = generated_header("//") + ["", f"package com.openlattice.chronicle.{package}", "",
            f"public enum class {name}{parameters} {{"]
        lines += [f"    {value}" + (f"({str(annotation_bool(body, 'countsAsResearchReceipt')).lower()})" if name == "UploadType" else "") + ","
                  for value, body in enum_value_bodies(schema, name)]
        if name == "ParticipantFormKind":
            lines[-1] = lines[-1].removesuffix(",") + ";"
            lines += ["", "    public val requiresSubmissionDate: Boolean",
                "        get() = this == TIME_USE_DIARY || this == QUESTIONNAIRE", "",
                "    public fun dailySubmissionResourceKey(date: java.time.LocalDate): String {",
                '        require(this == TIME_USE_DIARY) { "This form has no daily submission resource" }',
                '        return "time-use-diary:$date"', "    }"]
        lines += ["}", ""]
        outputs[ROOT / target] = "\n".join(lines)
    return outputs


def upload_limit_outputs(schema: dict) -> dict[Path, str]:
    limit = upload_limit_bytes(schema)
    outputs = {ROOT / "chronicle-models/src/main/kotlin/com/openlattice/chronicle/generated/UploadLimits.kt":
               render_kotlin_constants(schema),
               ROOT / "generated/upload-limits.json": json.dumps({name: schema['constants'][name]['value']
                   for name in (UPLOAD_LIMIT_FIELD, UPLOAD_HEADROOM_FIELD)}, indent=2) + "\n"}
    for path, templates in UPLOAD_LIMIT_ADAPTERS.items():
        lines = path.read_text().splitlines(keepends=True)
        for template in (templates,) if isinstance(templates, str) else templates:
            prefix = template.partition("{")[0]
            if sum(line.startswith(prefix) for line in lines) != 1:
                raise ValueError(f"Expected one upload-limit adapter in {path}: {prefix}")
            generated = template.format(limit=limit, body_timeout=schema["constants"]["UPLOAD_BODY_TIMEOUT_SECONDS"]["value"],
                                        header_headroom=schema["constants"][UPLOAD_HEADROOM_FIELD]["value"])
            lines = [generated if line.startswith(prefix) else line for line in lines]
        outputs[path] = "".join(lines)
    return outputs


def load_schema() -> dict:
    return yaml.safe_load(SCHEMA_PATH.read_text(encoding="utf-8"))


def source_sha256() -> str:
    return hashlib.sha256(SCHEMA_PATH.read_bytes()).hexdigest()


def generated_header(comment_prefix: str, source: Path = SCHEMA_PATH) -> list[str]:
    return [
        f"{comment_prefix} Generated by scripts/generate-chronicle-contracts.py from {source.relative_to(ROOT)}.",
        f"{comment_prefix} Source-SHA256: {hashlib.sha256(source.read_bytes()).hexdigest()}",
        f"{comment_prefix} Do not edit by hand.",
    ]


def enum_values(schema: dict, enum_name: str) -> list[tuple[str, str]]:
    values = schema["enums"][enum_name]["permissible_values"]
    out = []
    for value, body in values.items():
        description = ""
        if isinstance(body, dict):
            description = str(body.get("description") or "")
        out.append((str(value), description))
    return out


def enum_value_bodies(schema: dict, enum_name: str) -> list[tuple[str, dict[str, Any]]]:
    values = schema["enums"][enum_name]["permissible_values"]
    out = []
    for value, body in values.items():
        out.append((str(value), body if isinstance(body, dict) else {}))
    return out


def annotation(body: dict[str, Any], key: str) -> str | None:
    raw = (body.get("annotations") or {}).get(key)
    if isinstance(raw, dict):
        value = raw.get("value")
    else:
        value = raw
    if value is None:
        return None
    return str(value)


def annotation_bool(body: dict[str, Any], key: str) -> bool:
    value = annotation(body, key)
    if value is None:
        raise ValueError(f"Missing boolean annotation {key}")
    if value.lower() == "true":
        return True
    if value.lower() == "false":
        return False
    raise ValueError(f"Invalid boolean annotation {key}: {value}")


def annotation_int(body: dict[str, Any], key: str) -> int | None:
    value = annotation(body, key)
    return None if value is None else int(value)


def ts_string(value: str) -> str:
    return "'" + value.replace("\\", "\\\\").replace("'", "\\'") + "'"


def cue_string(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def lower_camel_from_upper_snake(value: str) -> str:
    parts = value.lower().split("_")
    return parts[0] + "".join(part.capitalize() for part in parts[1:])


def render_typescript_enums(schema: dict) -> list[str]:
    lines = []
    for enum_name, export_name in TS_EXPORT_NAMES.items():
        values = [value for value, _ in enum_values(schema, enum_name)]
        single_line = f"export const {export_name} = [{', '.join(ts_string(value) for value in values)}] as const;"
        if len(single_line) <= 120:
            lines.append(single_line)
        else:
            lines.append(f"export const {export_name} = [")
            for value in values:
                lines.append(f"  {ts_string(value)},")
            lines.append("] as const;")
        lines.append(f"export type {enum_name} = (typeof {export_name})[number];")
        lines.append("")
        object_name = {"ParticipationStatus": "PARTICIPATION_STATUS", "StudyLifecycleStatus": "STUDY_LIFECYCLE_STATUS",
                       "BrowserErrorKind": "BROWSER_ERROR_KIND", "WithdrawalMode": "WITHDRAWAL_MODE"}.get(enum_name)
        if object_name:
            lines += [f"export const {object_name} = {{", *[f"  {value}: {ts_string(value)}," for value in values], "} as const;", ""]

    return lines


def render_typescript_modules(contract: dict) -> list[str]:
    lines = []
    lines.append("export const COLLECTION_MODULE_ID = {")
    lines.extend(f"  {module['id']}: {ts_string(module['id'])}," for module in contract["collectionModules"])
    lines.extend(["} as const satisfies Record<string, CollectionModuleId>;", ""])

    lines.extend(
        [
            "export type CollectionModuleContract = {",
            "  readonly enumName: string;",
            "  readonly id: CollectionModuleId;",
            "  readonly privacyClass: CollectionPrivacyClass;",
            "  readonly active: boolean;",
            "  readonly consentGated: boolean;",
            "  readonly defaultEnabledOverride: boolean | null;",
            "  readonly defaultEnabled: boolean;",
            "  readonly androidSensorModule: boolean;",
            "  readonly activeDefaultEnabled: boolean;",
            "  readonly intervalGated: boolean;",
            "  readonly playStoreBuild: boolean;",
            "};",
            "",
            "export const COLLECTION_MODULE_CONTRACTS = [",
        ]
    )
    for module in contract["collectionModules"]:
        lines.extend(
            [
                "  {",
                f"    enumName: {ts_string(module['enumName'])},",
                f"    id: {ts_string(module['id'])},",
                f"    privacyClass: {ts_string(module['privacyClass'])},",
                f"    active: {str(module['active']).lower()},",
                f"    consentGated: {str(module['consentGated']).lower()},",
                "    defaultEnabledOverride: "
                + ("null" if module["defaultEnabledOverride"] is None else str(module["defaultEnabledOverride"]).lower())
                + ",",
                f"    defaultEnabled: {str(module['defaultEnabled']).lower()},",
                f"    androidSensorModule: {str(module['androidSensorModule']).lower()},",
                f"    activeDefaultEnabled: {str(module['activeDefaultEnabled']).lower()},",
                f"    intervalGated: {str(module['intervalGated']).lower()},",
                f"    playStoreBuild: {str(module['playStoreBuild']).lower()},",
                "  },",
            ]
        )
    lines.extend(["] as const satisfies readonly CollectionModuleContract[];", ""])
    return lines


def render_typescript_sensors(contract: dict) -> list[str]:
    lines = []
    lines.extend(
        [
            "export type AndroidSensorMapping = {",
            "  readonly androidSensorType: AndroidSensorType;",
            "  readonly collectionModuleId: CollectionModuleId;",
            "  readonly collectionModuleEnum: string;",
            "  readonly active: boolean;",
            "  readonly displayOrder: number;",
            "};",
            "",
            "export const ANDROID_SENSOR_MAPPINGS = [",
        ]
    )
    for mapping in contract["androidSensorMappings"]:
        lines.extend(
            [
                "  {",
                f"    androidSensorType: {ts_string(mapping['androidSensorType'])},",
                f"    collectionModuleId: {ts_string(mapping['collectionModuleId'])},",
                f"    collectionModuleEnum: {ts_string(mapping['collectionModuleEnum'])},",
                f"    active: {str(mapping['active']).lower()},",
                f"    displayOrder: {mapping['displayOrder']},",
                "  },",
            ]
        )
    lines.extend(
        [
            "] as const satisfies readonly AndroidSensorMapping[];",
            "",
        ]
    )
    return lines


def render_typescript_subsets(contract: dict) -> list[str]:
    lines = []
    for export_name, type_name, values in [
        ("ACTIVE_COLLECTION_MODULE_IDS", "ActiveCollectionModuleId", contract["activeCollectionModuleIds"]),
        (
            "ACTIVE_DEFAULT_ENABLED_COLLECTION_MODULE_IDS",
            "ActiveDefaultEnabledCollectionModuleId",
            contract["activeDefaultEnabledCollectionModuleIds"],
        ),
        ("INACTIVE_COLLECTION_MODULE_IDS", "InactiveCollectionModuleId", contract["inactiveCollectionModuleIds"]),
        ("ANDROID_SENSOR_MODULE_IDS", "AndroidSensorModuleId", contract["androidSensorModuleIds"]),
        ("CONSENT_GATED_COLLECTION_MODULE_IDS", "ConsentGatedCollectionModuleId", contract["consentGatedCollectionModuleIds"]),
        (
            "INTERVAL_GATED_COLLECTION_MODULE_IDS",
            "IntervalGatedCollectionModuleId",
            contract["intervalGatedCollectionModuleIds"],
        ),
        (
            "PLAY_STORE_BUILD_COLLECTION_MODULE_IDS",
            "PlayStoreBuildCollectionModuleId",
            contract["playStoreBuildCollectionModuleIds"],
        ),
    ]:
        lines.append(f"export const {export_name} = [")
        for value in values:
            lines.append(f"  {ts_string(value)},")
        lines.append("] as const;")
        lines.append(f"export type {type_name} = (typeof {export_name})[number];")
        lines.append("")

    return lines


def render_typescript(schema: dict) -> str:
    contract = domain_contract(schema)["contracts"]
    lines = ["", f"export const {UPLOAD_LIMIT_FIELD} = {upload_limit_bytes(schema)} as const;", "",
             *render_typescript_enums(schema), *render_typescript_modules(contract),
             *render_typescript_sensors(contract), *render_typescript_subsets(contract)]
    for name in synchronous_export_limits(schema):
        lines.append(f"export const {name} = {schema['constants'][name]['value']} as const;")
    lines.extend(f"export const {name} = {ts_string(value)} as const;" for name, value in browser_download_fields(schema).items())
    lines.append(f"export const BROWSER_ERROR_REPORT_PATH = {ts_string(schema['constants']['BROWSER_ERROR_REPORT_PATH']['value'])} as const;")
    lines.append(f"export const PARTICIPANT_PROCESSING_BLOCKED_CODE = {ts_string(schema['constants']['PARTICIPANT_PROCESSING_BLOCKED_CODE']['value'])} as const;")
    lines.append(f"export const PARTICIPANT_ID_PATTERN = {ts_string(schema['constants']['PARTICIPANT_ID_PATTERN']['value'])} as const;")
    for name in header_fields(schema):
        lines.append(f"export const {name} = {ts_string(schema['constants'][name]['value'])} as const;")
    categories = {code: annotation(body, "category") for code, body in enum_value_bodies(schema, "AndroidUploadIssueCode")}
    if not all(categories.values()):
        raise ValueError("Every AndroidUploadIssueCode needs a category annotation")
    lines.append("export const ANDROID_UPLOAD_ISSUE_CATEGORIES = {")
    lines += [f"  {code}: {ts_string(category)}," for code, category in categories.items()]
    lines.append("} as const;")
    for name, value in collection_defaults(schema).items():
        lines.append(f"export const {name} = {value if type(value) is int else ts_string(value)} as const;")
    lines.append(f"export const SESSION_IDLE_WINDOW_MS_FIELD = {ts_string(schema['constants']['SESSION_IDLE_WINDOW_MS_FIELD']['value'])} as const;")
    locked_fields = enrollment_locked_fields(schema)
    lines += ["export const ENROLLMENT_LOCKED_SETTING_FIELDS = {",
              *[f"  {name}: {ts_string(value)}," for name, value in locked_fields.items()], "} as const;", ""]
    # body starts with the blank separator line ("" head of `lines`), and is the
    # exact byte range chronicle-web's checker hashes: everything after the
    # "// Do not edit by hand.\n" line.
    body = "\n".join(lines)
    header = generated_header("//")
    header.insert(2, f"// Content-SHA256: {hashlib.sha256(body.encode('utf-8')).hexdigest()}")
    return "\n".join(header) + "\n" + body


def render_cue(schema: dict) -> str:
    lines = generated_header("//") + ["", "package chronicledeploy", ""]

    for enum_name, export_name in TS_EXPORT_NAMES.items():
        values = [value for value, _ in enum_values(schema, enum_name)]
        cue_values = " | ".join(cue_string(value) for value in values)
        cue_list_name = lower_camel_from_upper_snake(export_name)
        lines.append(f"#{enum_name}: {cue_values}")
        lines.append(f"{cue_list_name}: [")
        for value in values:
            lines.append(f"  {cue_string(value)},")
        lines.append("]")
        lines.append("")

    return "\n".join(lines)


def render_markdown(schema: dict) -> str:
    lines = [
        "# Chronicle generated contracts",
        "",
        "Generated by `scripts/generate-chronicle-contracts.py` from",
        "`ontology/chronicle.linkml.yaml`.",
        "",
        f"Source SHA-256: `{source_sha256()}`.",
        "",
        "Do not edit by hand.",
        "",
        f"Maximum request body: {upload_limit_bytes(schema)} bytes.",
        "",
    ]

    for enum_name in TS_EXPORT_NAMES:
        enum_body = schema["enums"][enum_name]
        lines.extend([
            f"## {enum_name}",
            "",
            str(enum_body.get("description") or "").strip(),
            "",
            "| Value | Description |",
            "|-------|-------------|",
        ])
        for value, description in enum_values(schema, enum_name):
            lines.append(f"| `{value}` | {description} |")
        lines.append("")

    return "\n".join(lines)


def privacy_classes(schema: dict) -> list[dict[str, Any]]:
    return [
        {
            "name": value,
            "defaultEnabled": annotation_bool(body, "defaultEnabled"),
        }
        for value, body in enum_value_bodies(schema, "CollectionPrivacyClass")
    ]


def collection_modules(schema: dict) -> list[dict[str, Any]]:
    approved_ids = {module["id"] for module in json.loads(OPEN_MODULE_REGISTRY.read_text())["modules"]}
    modules = []
    for value, body in enum_value_bodies(schema, "CollectionModuleId"):
        default_override = annotation(body, "defaultEnabledOverride")
        modules.append(
            {
                "enumName": annotation(body, "enumName") or value.upper(),
                "id": value,
                "privacyClass": annotation(body, "privacyClass"),
                "active": annotation_bool(body, "active"),
                "consentGated": annotation_bool(body, "consentGated"),
                "defaultEnabledOverride": None if default_override is None else default_override.lower() == "true",
                "defaultEnabled": annotation_bool(body, "defaultEnabled"),
                "androidSensorModule": annotation_bool(body, "androidSensorModule"),
                "activeDefaultEnabled": annotation_bool(body, "activeDefaultEnabled"),
                "intervalGated": annotation_bool(body, "intervalGated"),
                "playStoreBuild": value in approved_ids,
            }
        )
    return modules


def android_sensor_mappings(schema: dict) -> list[dict[str, Any]]:
    mappings = []
    for value, body in enum_value_bodies(schema, "CollectionModuleId"):
        sensor_type = annotation(body, "androidSensorType")
        display_order = annotation_int(body, "sensorDisplayOrder")
        if sensor_type is None:
            continue
        mappings.append(
            {
                "androidSensorType": sensor_type,
                "collectionModuleId": value,
                "collectionModuleEnum": annotation(body, "enumName") or value.upper(),
                "active": annotation_bool(body, "active"),
                "displayOrder": display_order if display_order is not None else len(mappings),
            }
        )
    return sorted(mappings, key=lambda entry: entry["displayOrder"])


def domain_contract(schema: dict) -> dict[str, Any]:
    modules = collection_modules(schema)
    mappings = android_sensor_mappings(schema)
    return {
        "schemaVersion": "chronicle-domain-contracts/v1",
        "generatedBy": "scripts/generate-chronicle-contracts.py",
        "manualEdit": False,
        "sourceRepo": "methodic",
        "sourceFiles": {
            "linkml": {
                "path": "ontology/chronicle.linkml.yaml",
                "sha256": source_sha256(),
            },
            "openModuleRegistry": {
                "path": OPEN_MODULE_REGISTRY.relative_to(ROOT).as_posix(),
                "sha256": hashlib.sha256(OPEN_MODULE_REGISTRY.read_bytes()).hexdigest(),
            },
            "fixtureRegistry": {
                "path": PAYLOAD_FIXTURE_REGISTRY.relative_to(ROOT).as_posix(),
                "sha256": hashlib.sha256(PAYLOAD_FIXTURE_REGISTRY.read_bytes()).hexdigest(),
            },
        },
        "contracts": {
            "synchronousExportLimits": synchronous_export_limits(schema),
            "enrollmentLockedSettings": list(enrollment_locked_fields(schema)),
            "collectionModules": modules,
            "activeCollectionModuleIds": [module["id"] for module in modules if module["active"]],
            "activeDefaultEnabledCollectionModuleIds": [
                module["id"] for module in modules if module["activeDefaultEnabled"]
            ],
            "inactiveCollectionModuleIds": [module["id"] for module in modules if not module["active"]],
            "androidSensorModuleIds": [module["id"] for module in modules if module["androidSensorModule"]],
            "consentGatedCollectionModuleIds": [module["id"] for module in modules if module["consentGated"]],
            "intervalGatedCollectionModuleIds": [module["id"] for module in modules if module["intervalGated"]],
            "playStoreBuildCollectionModuleIds": [module["id"] for module in modules if module["playStoreBuild"]],
            "privacyClasses": privacy_classes(schema),
            "androidSensorTypes": [value for value, _ in enum_values(schema, "AndroidSensorType")],
            "androidSensorMappings": mappings,
            "studyFeatures": [value for value, _ in enum_values(schema, "StudyFeature")],
            "participantDataTypes": [value for value, _ in enum_values(schema, "ParticipantDataType")],
            "participationStatuses": [value for value, _ in enum_values(schema, "ParticipationStatus")],
            "studyLifecycleStatuses": [value for value, _ in enum_values(schema, "StudyLifecycleStatus")],
            "consentTriggers": [value for value, _ in enum_values(schema, "ConsentTrigger")],
            "apiKeyScopes": [value for value, _ in enum_values(schema, "ApiKeyScope")],
            "androidUploadIssueCodes": [value for value, _ in enum_values(schema, "AndroidUploadIssueCode")],
            "participantFormKinds": [value for value, _ in enum_values(schema, "ParticipantFormKind")],
            "uploadTypes": [value for value, _ in enum_values(schema, "UploadType")],
            "fixtureRegistry": json.loads(PAYLOAD_FIXTURE_REGISTRY.read_text()),
        },
        "compatibility": {
            "unknownCollectionModuleIds": "Consumers that support tolerant settings decode should ignore unknown module ids.",
            "inactiveCollectionModuleIds": "Inactive ids are decode-compatible and must not be offered as active collection modules.",
            "generatedConsumers": "Generated consumers must preserve unknown-value handling appropriate to their platform boundary.",
        },
    }


def render_domain_json(schema: dict) -> str:
    return json.dumps(domain_contract(schema), indent=2) + "\n"


def expected_outputs(schema: dict) -> dict[Path, str]:
    return {
        path: (
            render_markdown(schema)
            if kind == "markdown"
            else render_typescript(schema)
            if kind == "typescript"
            else render_cue(schema)
            if kind == "cue"
            else render_domain_json(schema)
        )
        for path, kind in OUTPUTS.items()
    }


def consent_policy_outputs(schema: dict) -> dict[Path, str]:
    lines = generated_header("//") + ["", "package com.openlattice.chronicle.generated", "",
        "import com.openlattice.chronicle.collection.CollectionModuleId", "",
        "public object CollectionConsentContracts {",
        "    public val consentGatedModules: Set<CollectionModuleId> = setOf("]
    lines += [f"        CollectionModuleId.{module['enumName']}," for module in collection_modules(schema) if module['consentGated']]
    lines += ["    )",
              f"    public const val COLLECTION_ACK_REJECTED_CODE: String = {json.dumps(schema['constants']['COLLECTION_ACK_REJECTED_CODE']['value'])}",
              "}", ""]
    headers =generated_header("//") + ["", "package com.openlattice.chronicle.generated", "", "public object ChronicleHeaders {"]
    headers += [f"    public const val {name}: String = {json.dumps(schema['constants'][name]['value'])}"
                for name in header_fields(schema)]
    headers += ["}", ""]
    attempts = generated_header("//") + ["", "package com.openlattice.chronicle.generated", "",
        "public object EnrollmentAttemptContracts {"]
    attempts += [f"    public const val {name}: String = {json.dumps(schema['constants'][name]['value'])}"
                 for name in ("ENROLLMENT_CANCELLED_CODE", "ENROLLMENT_STUDY_CHANGED_CODE")]
    attempts += ["}", ""]
    metadata = generated_header("//") + ["", "package com.openlattice.chronicle.generated", "",
        "public object SessionMetadataFields {",
        f"    public const val IDLE_WINDOW_MS: String = {json.dumps(schema['constants']['SESSION_IDLE_WINDOW_MS_FIELD']['value'])}",
        "}", ""]
    return {ROOT / "chronicle-models/src/main/kotlin/com/openlattice/chronicle/generated/CollectionConsentContracts.kt": "\n".join(lines),
            ROOT / "chronicle-models/src/main/kotlin/com/openlattice/chronicle/generated/ChronicleHeaders.kt": "\n".join(headers),
            ROOT / "chronicle-models/src/main/kotlin/com/openlattice/chronicle/generated/EnrollmentAttemptContracts.kt": "\n".join(attempts),
            ROOT / "chronicle-models/src/main/kotlin/com/openlattice/chronicle/generated/SessionMetadataFields.kt": "\n".join(metadata)}


def restore_checkpoint_outputs() -> dict[Path, str]:
    outputs = {}
    for template in RESTORE_CHECKPOINT_TEMPLATES:
        sql = template.read_text()
        for name, path in RESTORE_CHECKPOINT_PARTS.items():
            sql = sql.replace(f"@{name}@", path.read_text().strip())
        sql = f"-- Generated from {template.relative_to(ROOT)} by scripts/generate-chronicle-contracts.py.\n" + sql
        outputs[template.with_suffix("")] = sql
        outputs[ROOT / "chronicle-server/src/test/resources" / template.stem] = sql
    return outputs


def api_constraint_outputs() -> dict[Path, str]:
    """Generate shared scalar limits from the published request schemas."""
    schemas = yaml.safe_load(OPENAPI_PATH.read_text())["components"]["schemas"]
    rule = schemas["BatterySample"]["properties"]["producerVersion"]
    if schemas["IosBatterySample"]["properties"]["producerVersion"]["allOf"] != [
        {"$ref": "#/components/schemas/BatterySample/properties/producerVersion"}
    ]:
        raise ValueError("iOS producerVersion must reuse BatterySample's constraint")
    lines = generated_header("//", OPENAPI_PATH) + ["", "package com.openlattice.chronicle.generated", "",
        "public object ProducerVersionConstraints {",
        f"    public const val MAX_LENGTH: Int = {rule['maxLength']}",
        f"    public const val PATTERN: String = {json.dumps(rule['pattern'])}", "}", ""]
    diagnostic = generated_header("//", OPENAPI_PATH) + ["", "package com.openlattice.chronicle.generated", "",
        "public object UploadDiagnosticConstraints {",
        f"    public const val MAX_ISSUE_CODE_LENGTH: Int = {schemas['AndroidUploadDiagnosticEvent']['properties']['issueCode']['maxLength']}",
        f"    public const val MAX_ERROR_TYPE_LENGTH: Int = {schemas['AndroidUploadDiagnosticEvent']['properties']['errorType']['maxLength']}",
        "}", ""]
    acknowledgment = generated_header("//", OPENAPI_PATH) + ["", "package com.openlattice.chronicle.generated", "",
        "public object CollectionAcknowledgmentConstraints {",
        f"    public const val MAX_APP_VERSION_UTF16_LENGTH: Int = {schemas['CollectionAcknowledgment']['properties']['appVersion']['x-maxLengthUtf16']}",
        "}", ""]
    return {ROOT / "chronicle-models/src/main/kotlin/com/openlattice/chronicle/generated/ProducerVersionConstraints.kt": "\n".join(lines),
            ROOT / "chronicle-models/src/main/kotlin/com/openlattice/chronicle/generated/UploadDiagnosticConstraints.kt": "\n".join(diagnostic),
            ROOT / "chronicle-models/src/main/kotlin/com/openlattice/chronicle/generated/CollectionAcknowledgmentConstraints.kt": "\n".join(acknowledgment)}


def all_outputs(schema: dict) -> dict[Path, str]:
    day_fixture = {ROOT / "chronicle-server/src/test/resources/exact-day-study-limits.json": WEB_DAY_FIXTURE.read_text()}
    day_fixture[ROOT / "chronicle-server/src/test/resources/string-length-cases.json"] = STRING_LENGTH_CASES.read_text()
    api_document = yaml.safe_load(OPENAPI_PATH.read_text())
    api_schemas = {ROOT / "chronicle-server/src/test/resources/openapi-schemas.json": json.dumps({
        "_comment": "Generated from chronicle-api/chronicle.yaml by the root contract generator.",
        "schemas": api_document["components"]["schemas"],
        "paths": api_document["paths"],
    }, indent=2) + "\n"}
    web_goldens = {ROOT / "chronicle-server/src/test/resources/web-golden" / path.name:
                   json.dumps({"_comment": f"Generated from {path.relative_to(ROOT)} by the root contract generator.",
                               **json.loads(path.read_text())}, indent=2) + "\n" for path in WEB_BACKEND_GOLDENS}
    pool = schema["bootstrap_pool"]
    bootstrap_pools = {profile: {key: value for key, value in pool.items() if key != "connectionTimeout"}
                      | {"connectionTimeout": timeout} for profile, timeout in pool["connectionTimeout"].items()}
    pool_output = {ROOT / "chronicle-server/src/main/resources/bootstrap-pools.json":
                   json.dumps(bootstrap_pools, indent=2) + "\n"}
    form_windows = {ROOT / path: FORM_WINDOW_FIXTURE.read_text() for path in (
        "chronicle-server/src/test/resources/participant-form-windows.json",
        "chronicle-web/src/modern/generated/participant-form-windows.json",
    )}
    return expected_outputs(schema) | upload_limit_outputs(schema) | study_enum_outputs(schema) | web_policy_outputs(schema) | consent_policy_outputs(schema) | collection_default_outputs(schema) | api_constraint_outputs() | form_windows | pool_output | web_goldens | api_schemas | day_fixture | restore_checkpoint_outputs()


def check_outputs(outputs: dict[Path, str]) -> int:
    failed = False
    for path, expected in outputs.items():
        actual = path.read_text(encoding="utf-8") if path.exists() else ""
        if actual != expected:
            failed = True
            print(f"{path.relative_to(ROOT)} is stale", file=sys.stderr)
            diff = difflib.unified_diff(
                actual.splitlines(),
                expected.splitlines(),
                fromfile=str(path.relative_to(ROOT)),
                tofile=f"{path.relative_to(ROOT)} (expected)",
                lineterm="",
            )
            for line in diff:
                print(line, file=sys.stderr)
    return 1 if failed else 0


def write_outputs(outputs: dict[Path, str]) -> None:
    for path, content in outputs.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        print(f"wrote {path.relative_to(ROOT)}")


def fresh_schema_output(schema: dict) -> str:
    """Rewrite only schema-owned CHECK constraints in the hand-owned migration."""
    lines = FRESH_SCHEMA_PATH.read_text().splitlines(keepends=True)
    version = RESTORE_CHECKPOINT_PARTS["RESTORE_CONTINUITY_CONTRACT_VERSION"].read_text().strip()
    pattern = "^" + schema["constants"]["PARTICIPANT_ID_PATTERN"]["value"] + "$"
    quoted_pattern = pattern.replace("'", "''")
    producer = yaml.safe_load(OPENAPI_PATH.read_text())["components"]["schemas"]["BatterySample"]["properties"]["producerVersion"]
    producer_pattern = producer["pattern"].replace("'", "''").replace("\\", "' || chr(92) || '")
    upload_types = ", ".join("'" + value.replace("'", "''") + "'" for value, _ in enum_values(schema, "UploadType"))
    constraints = {
        RESTORE_RECEIPT_VERSION_PREFIX: f"{RESTORE_RECEIPT_VERSION_PREFIX}{version})),\n",
        "ALTER TABLE public.study_participants ADD CONSTRAINT study_participants_participant_id_format ":
            "ALTER TABLE public.study_participants ADD CONSTRAINT study_participants_participant_id_format "
            f"CHECK (participant_id ~ '{quoted_pattern}');\n",
        "ALTER TABLE public.upload_buffer ADD CONSTRAINT upload_buffer_upload_type_check ":
            "ALTER TABLE public.upload_buffer ADD CONSTRAINT upload_buffer_upload_type_check "
            f"CHECK (upload_type IN ({upload_types}));\n",
        "ALTER TABLE public.battery_telemetry ADD CONSTRAINT battery_telemetry_producer_version_check ":
            "ALTER TABLE public.battery_telemetry ADD CONSTRAINT battery_telemetry_producer_version_check "
            f"CHECK (producer_version IS NULL OR (char_length(producer_version) <= {producer['maxLength']} "
            f"AND producer_version ~ ('{producer_pattern}')));\n",
    }
    for prefix, replacement in constraints.items():
        if sum(line.startswith(prefix) for line in lines) != 1:
            raise ValueError(f"Expected exactly one generated constraint: {prefix}")
        lines = [replacement if line.startswith(prefix) else line for line in lines]
    return "".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="fail if generated contract artifacts are stale")
    args = parser.parse_args()
    schema = load_schema()
    outputs = all_outputs(schema)
    outputs[FRESH_SCHEMA_PATH] = fresh_schema_output(schema)
    if args.check:
        return check_outputs(outputs)
    write_outputs(outputs)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
