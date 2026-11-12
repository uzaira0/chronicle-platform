#!/usr/bin/env bash
# Security layer runner for CI.
# Usage: run-all-security.sh <layer> <report-dir>
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
# shellcheck source=tests/security/security-runner-lib.sh
source "$SCRIPT_DIR/security-runner-lib.sh"
# shellcheck source=tests/security/lib/selfhost-python.sh
source "$SCRIPT_DIR/lib/selfhost-python.sh"
# shellcheck source=tests/security/lib/k6-fixture-trust.sh
source "$SCRIPT_DIR/lib/k6-fixture-trust.sh"

prepare_checkov_runtime() {
  if checkov --version >/dev/null 2>&1; then
    return 0
  fi

  local expat_lib="/opt/homebrew/opt/expat/lib"
  if [ -d "$expat_lib" ] &&
    DYLD_LIBRARY_PATH="$expat_lib${DYLD_LIBRARY_PATH:+:$DYLD_LIBRARY_PATH}" checkov --version >/dev/null 2>&1; then
    export DYLD_LIBRARY_PATH="$expat_lib${DYLD_LIBRARY_PATH:+:$DYLD_LIBRARY_PATH}"
    echo "Using Homebrew expat for local Checkov Python runtime"
    return 0
  fi

  echo "Checkov is installed but failed to start. Run 'checkov --version' for the local toolchain error." >&2
  return 1
}

validate_sarif() {
  local report="$1"
  [ -s "$report" ] || return 1
  python3 - "$report" <<'PY'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as handle:
    document = json.load(handle)
if document.get("version") != "2.1.0" or not isinstance(document.get("runs"), list):
    raise SystemExit("invalid SARIF document")
PY
}

run_checkov_scan() {
  local output_dir="$REPORT_DIR/checkov-output"
  local report="$output_dir/results_sarif.sarif"
  local status=0
  command -v checkov >/dev/null 2>&1 || return 127
  prepare_checkov_runtime || return 2
  mkdir -p "$output_dir"
  local -a dockerfiles=()
  mapfile -d '' -t dockerfiles < <(discover_dockerfiles)
  checkov -f "${dockerfiles[@]}" \
    --framework dockerfile \
    --output sarif --output-file-path "$output_dir" || status=$?
  validate_sarif "$report" || return 2
  return "$status"
}

run_hadolint_scan() {
  local dockerfile="$1"
  local report="$2"
  local status=0
  command -v hadolint >/dev/null 2>&1 || return 127
  # Named, because Hadolint looks for .hadolint.yaml in the working directory only: started from
  # another directory it used its default threshold and failed on note-level results.
  hadolint --config "$ROOT_DIR/.hadolint.yaml" --format sarif "$dockerfile" >"$report" || status=$?
  validate_sarif "$report" || return 2
  return "$status"
}

# docker/ and k8s/ are frozen and unscanned.
discover_dockerfiles() {
  python3 - "$ROOT_DIR/selfhost" <<'PY'
import os
import sys

root = os.path.abspath(sys.argv[1])
matches = []
for directory, _, files in os.walk(root):
    for name in files:
        if name == "Dockerfile" or name.startswith("Dockerfile.") or name.endswith(".Dockerfile"):
            matches.append(os.path.join(directory, name))
for path in sorted(matches):
    sys.stdout.buffer.write(path.encode("utf-8") + b"\0")
PY
}

dockerfile_report_name() {
  python3 - "$ROOT_DIR" "$1" <<'PY'
import os
import re
import sys

relative = os.path.relpath(os.path.abspath(sys.argv[2]), os.path.abspath(sys.argv[1]))
print("hadolint-" + re.sub(r"[^A-Za-z0-9._-]+", "__", relative) + ".sarif")
PY
}

run_auth_semgrep() {
  local report="$REPORT_DIR/auth-patterns.sarif"
  local status=0
  command -v semgrep >/dev/null 2>&1 || return 127
  semgrep scan --error --config "p/jwt" --config "p/secrets" \
    --sarif -o "$report" \
    "$ROOT_DIR/chronicle-server/src" "$ROOT_DIR/chronicle-web/src" || status=$?
  validate_sarif "$report" || return 2
  return "$status"
}

run_injection_semgrep() {
  local report="$REPORT_DIR/injection.sarif"
  local status=0
  command -v semgrep >/dev/null 2>&1 || return 127
  semgrep scan --error --config "p/sql-injection" --config "p/xss" \
    --sarif -o "$report" \
    "$ROOT_DIR/chronicle-server/src" "$ROOT_DIR/chronicle-web/src" || status=$?
  validate_sarif "$report" || return 2
  return "$status"
}

run_crypto_semgrep() {
  local report="$REPORT_DIR/crypto.sarif"
  local status=0
  command -v semgrep >/dev/null 2>&1 || return 127
  semgrep scan --error --config "p/insecure-transport" \
    --sarif -o "$report" "$ROOT_DIR/chronicle-server/src" || status=$?
  validate_sarif "$report" || return 2
  return "$status"
}

android_source_roots() {
  find "$ROOT_DIR/chronicle" -mindepth 3 -maxdepth 3 -type d -path '*/src/*' ! -iname '*test*' -print | sort
}

run_deployment_semgrep() {
  local report="$REPORT_DIR/deployment-semgrep.sarif" status=0
  command -v semgrep >/dev/null 2>&1 || return 127
  SEMGREP_SETTINGS_FILE="$REPORT_DIR/semgrep-settings.yml" SEMGREP_LOG_FILE="$REPORT_DIR/semgrep-runtime.log" \
  semgrep scan --jobs 2 --error --disable-version-check --metrics off --no-git-ignore \
    --include '*.sh' --include '*.conf' --include '*.yml' --include '*.yaml' --include 'Dockerfile*' \
    --config "$ROOT_DIR/tests/security/deployment-rules" \
    --exclude '.env*' --exclude '*.pem' \
    --sarif -o "$report" "$ROOT_DIR/selfhost" "$ROOT_DIR/scripts" || status=$?
  validate_sarif "$report" || return 2
  return "$status"
}

run_sast_semgrep() {
  local report="$REPORT_DIR/semgrep.sarif"
  local count_report="$REPORT_DIR/semgrep-actionable-count.txt"
  local status=0
  command -v semgrep >/dev/null 2>&1 || return 127
  local android_roots=()
  mapfile -t android_roots < <(android_source_roots)
  [ "${#android_roots[@]}" -gt 0 ] || return 2
  semgrep scan --quiet --config "$ROOT_DIR/tests/security/rules/" \
    --sarif -o "$report" \
    "$ROOT_DIR/chronicle-server/src" "$ROOT_DIR/chronicle-api/src" \
    "$ROOT_DIR/chronicle-models/src" "$ROOT_DIR/rhizome/src" "$ROOT_DIR/rhizome-client/src" \
    "$ROOT_DIR/chronicle-web/src" "${android_roots[@]}" || status=$?
  validate_sarif "$report" || return 2
  python3 - "$report" "$count_report" <<'PY'
import json
import sys

path, count_path = sys.argv[1:]
with open(path, "r", encoding="utf-8") as handle:
    sarif = json.load(handle)

unsuppressed_count = 0
for run in sarif.get("runs", []):
    kept = [
        result
        for result in run.get("results", [])
        if not result.get("suppressions")
    ]
    run["results"] = kept
    unsuppressed_count += len(kept)

with open(path, "w", encoding="utf-8") as handle:
    json.dump(sarif, handle)
with open(count_path, "w", encoding="utf-8") as handle:
    handle.write(str(unsuppressed_count))
print(f"Semgrep actionable findings: {unsuppressed_count}")
PY
  [ "$status" -le 1 ] || return 2
  [ "$(cat "$count_report")" -eq 0 ] || return 1
  return 0
}

run_bun_frozen_install() {
  command -v bun >/dev/null 2>&1 || return 127
  [ -f "$ROOT_DIR/chronicle-web/package.json" ] || return 2
  (cd "$ROOT_DIR/chronicle-web" && bun install --frozen-lockfile --ignore-scripts)
}

run_bun_audit() {
  local report="$REPORT_DIR/bun-audit.json"
  local status=0
  command -v bun >/dev/null 2>&1 || return 127
  [ -f "$ROOT_DIR/chronicle-web/package.json" ] || return 2
  # bun 1.3 --json ignores --audit-level (exits 1 for any advisory), so the report decides: high or critical fails.
  (cd "$ROOT_DIR/chronicle-web" && bun audit --audit-level=high --json) >"$report" || status=$?
  python3 - "$report" "$status" <<'PY'
import json
import sys
try:
    with open(sys.argv[1], "r", encoding="utf-8") as handle:
        report = json.load(handle)
except (OSError, ValueError):
    sys.exit(2)
if not isinstance(report, dict) or any(not isinstance(advisories, list) for advisories in report.values()):
    sys.exit(2)
if any(not isinstance(advisory, dict) or advisory.get("severity") not in ("info", "low", "moderate", "high", "critical")
       for advisories in report.values() for advisory in advisories):
    sys.exit(2)
blocking = []
for name, advisories in report.items():
    for advisory in advisories:
        line = f"{name}: {advisory['severity']} {advisory.get('url')}"
        if advisory["severity"] in ("high", "critical"):
            blocking.append(line)
        else:
            print(f"[info] below the high-severity bar: {line}")
if blocking:
    print("\n".join(blocking))
    sys.exit(1)
# No advisories and a failed bun run is a scanner error, not a pass.
sys.exit(2 if not any(report.values()) and sys.argv[2] != "0" else 0)
PY
}

run_gitleaks_scan() {
  local report="$REPORT_DIR/gitleaks.sarif" canary ignore
  local status=0
  command -v gitleaks >/dev/null 2>&1 || return 127
  # Positive control: a config without rules reports "no leaks" for anything, so it must find a planted token.
  canary="$(mktemp -d "$REPORT_DIR/gitleaks-canary.XXXXXX")" || return 2
  printf 'token = "%s"\n' "ghp""_Zx9Qw3Er7Ty1Ui5Op2As6Df8Gh4Jk0Lm3Nb7" > "$canary/canary.txt"
  if gitleaks dir "$canary" --config "$ROOT_DIR/tests/security/gitleaks.toml" --no-banner >/dev/null 2>&1; then
    rm -r -- "$canary"
    echo "gitleaks config found no planted GitHub token; it has no detection rules" >&2
    return 2
  fi
  rm -r -- "$canary"
  # Reviewed history findings are fingerprinted privately; the public mirror has its own history.
  ignore="$ROOT_DIR/tests/security/gitleaks-ignore/chronicle-platform-root.gitleaksignore"
  [[ -f "$ignore" ]] || ignore=/dev/null
  gitleaks detect --source "$ROOT_DIR" \
    --config "$ROOT_DIR/tests/security/gitleaks.toml" \
    --gitleaks-ignore-path "$ignore" \
    --report-format sarif --report-path "$report" \
    --no-banner || status=$?
  validate_sarif "$report" || return 2
  return "$status"
}

run_license_report() {
  (cd "$ROOT_DIR" && ./gradlew :chronicle-server:generateLicenseReport --no-daemon) || return $?
  printf '%s\n' '{"passed":true,"note":"Gradle license report generated successfully"}' \
    >"$REPORT_DIR/license.json"
}

run_compliance_scan() {
  local report="$REPORT_DIR/compliance.json"
  local status=0
  command -v conftest >/dev/null 2>&1 || return 127
  [ -d "$ROOT_DIR/tests/security/policies" ] || return 2
  conftest verify --policy "$ROOT_DIR/tests/security/policies/" \
    >"$REPORT_DIR/compliance-policy-tests.log" 2>&1 || return $?
  # selfhost/monitoring/docker-compose.*.yml are the Grafana network fragments monitoring.yml extends.
  conftest test "$ROOT_DIR/selfhost/docker-compose.yml" "$ROOT_DIR"/selfhost/overlays/*.yml \
    "$ROOT_DIR"/selfhost/monitoring/docker-compose.*.yml \
    --policy "$ROOT_DIR/tests/security/policies/" \
    --output json >"$report" 2>&1 || status=$?
  python3 - "$report" <<'PY' || return 2
import json
import sys
with open(sys.argv[1], "r", encoding="utf-8") as handle:
    json.load(handle)
PY
  return "$status"
}

sarif_actionable_count() {
  python3 - "$1" <<'PY'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as handle:
    sarif = json.load(handle)
print(
    sum(
        1
        for run in sarif.get("runs", [])
        for result in run.get("results", [])
        if not result.get("suppressions")
    )
)
PY
}

run_collection_semgrep_modularization() {
  local report="$REPORT_DIR/collection-semgrep-modularization.sarif"
  local status=0
  local count
  command -v semgrep >/dev/null 2>&1 || return 127
  local android_roots=()
  mapfile -t android_roots < <(android_source_roots)
  local collection_roots=() source_root
  for source_root in "${android_roots[@]}"; do
    source_root="$source_root/java/com/openlattice/chronicle/collection"
    [ ! -d "$source_root" ] || collection_roots+=("$source_root")
  done
  [ "${#collection_roots[@]}" -gt 0 ] || return 2
  semgrep scan --quiet \
    --config "$ROOT_DIR/tests/security/collection-rules/collection-modularization.yaml" \
    --sarif -o "$report" \
    "${collection_roots[@]}" \
    || status=$?
  validate_sarif "$report" || return 2
  [ "$status" -le 1 ] || return 2
  count="$(sarif_actionable_count "$report")" || return 2
  echo "Collection modularization findings: $count"
  [ "$count" -eq 0 ] || return 1
}

run_collection_semgrep_dto() {
  local report="$REPORT_DIR/collection-semgrep-dto.sarif"
  local status=0
  local count
  command -v semgrep >/dev/null 2>&1 || return 127
  semgrep scan --quiet \
    --config "$ROOT_DIR/tests/security/collection-rules/collection-dto.yaml" \
    --sarif -o "$report" \
    "$ROOT_DIR/chronicle-models/src/main/kotlin/com/openlattice/chronicle/collection" \
    || status=$?
  validate_sarif "$report" || return 2
  [ "$status" -le 1 ] || return 2
  count="$(sarif_actionable_count "$report")" || return 2
  echo "Collection DTO findings: $count"
  [ "$count" -eq 0 ] || return 1
}

run_collection_ast_grep() {
  local rule="$1"
  local report="$REPORT_DIR/collection-${rule}.sarif"
  local stderr_report="$REPORT_DIR/collection-${rule}.stderr"
  local status=0
  local count
  command -v ast-grep >/dev/null 2>&1 || return 127
  ast-grep scan --rule "$ROOT_DIR/tests/security/ast-grep/${rule}.yml" \
    "$ROOT_DIR/chronicle" "$ROOT_DIR/chronicle-models" "$ROOT_DIR/chronicle-server" \
    --format sarif >"$report" 2>"$stderr_report" || status=$?
  cat "$stderr_report"
  # ast-grep 0.45 writes its own version into the SARIF version field.
  jq '.version = "2.1.0"' "$report" >"$report.tmp" && mv "$report.tmp" "$report" || return 2
  validate_sarif "$report" || return 2
  [ "$status" -le 1 ] || return 2
  count="$(sarif_actionable_count "$report")" || return 2
  echo "$rule: $count finding(s)"
  [ "$count" -eq 0 ] || return 1
}

auth_api_guardrails() {
    if grep -Eiq 'blocklist check failed.*allowing request|fail[s]? open' \
      "$ROOT_DIR/chronicle-server/src/main/kotlin/com/openlattice/chronicle/filters/JwtBlocklistFilter.kt"; then
      echo "JwtBlocklistFilter must fail closed when token revocation state cannot be checked"
      auth_failures=$((auth_failures + 1))
    fi

    if ! grep -Eq '@Valid[[:space:]]+@RequestBody[[:space:]]+request:[[:space:]]+ApiKeyCreateRequest' \
      "$ROOT_DIR/chronicle-server/src/main/kotlin/com/openlattice/chronicle/controllers/ApiKeyController.kt"; then
      echo "ApiKeyController must validate ApiKeyCreateRequest request bodies"
      auth_failures=$((auth_failures + 1))
    fi

    if ! grep -Eq 'MAX_ADMIN_KEY_TTL_DAYS[[:space:]]*=[[:space:]]*30' \
      "$ROOT_DIR/chronicle-server/src/main/kotlin/com/openlattice/chronicle/services/apikeys/ApiKeyService.kt"; then
      echo "Manual ADMIN API keys must be capped at 30 days"
      auth_failures=$((auth_failures + 1))
    fi
    if ! grep -Eq 'MAX_WRITE_KEY_TTL_DAYS[[:space:]]*=[[:space:]]*90' \
      "$ROOT_DIR/chronicle-server/src/main/kotlin/com/openlattice/chronicle/services/apikeys/ApiKeyService.kt"; then
      echo "Manual WRITE API keys must be capped at 90 days"
      auth_failures=$((auth_failures + 1))
    fi

    if grep -Eq 'Invalid API key from IP|study \{\}|participant \{\}|participantId" to participantId|randomDeviceId" to randomDeviceId' \
      "$ROOT_DIR/chronicle-server/src/main/kotlin/com/openlattice/chronicle/services/apikeys/ApiKeyService.kt" \
      "$ROOT_DIR/chronicle-server/src/main/kotlin/com/openlattice/chronicle/filters/ApiKeyAuthenticationFilter.kt"; then
      echo "API key logs/audit metadata must use stable refs instead of raw identifiers"
      auth_failures=$((auth_failures + 1))
    fi

    if ! grep -Eq 'allowedProtocols[[:space:]]*=[[:space:]]*setOf\("https"\)' \
      "$ROOT_DIR/chronicle-server/src/main/kotlin/com/openlattice/chronicle/services/webhooks/WebhookService.kt"; then
      echo "Webhook delivery URLs must be HTTPS-only"
      auth_failures=$((auth_failures + 1))
    fi
    if ! grep -Eq '\.header\("X-Chronicle-Signature",[[:space:]]*computeSignature\(claim\.payload,[[:space:]]*claim\.secretHash\)\)' \
      "$ROOT_DIR/chronicle-server/src/main/kotlin/com/openlattice/chronicle/services/webhooks/WebhookService.kt"; then
      echo "Webhook deliveries must include an authenticated signature header"
      auth_failures=$((auth_failures + 1))
    fi
    if grep -Eq '\.setAllowedOrigins[[:space:]]*\([[:space:]]*"\*"' \
      "$ROOT_DIR/rhizome/src/main/java/com/geekbeast/rhizome/configuration/websockets/WebSocketConfig.java"; then
      echo "Shared WebSocket configuration must not permit arbitrary origins"
      auth_failures=$((auth_failures + 1))
    fi
    if ! grep -Eq '@field:NotBlank\(message = "Webhook secret is required"\)' \
      "$ROOT_DIR/chronicle-api/src/main/kotlin/com/openlattice/chronicle/webhooks/WebhookCreateRequest.kt"; then
      echo "Webhook registrations must require a shared secret"
      auth_failures=$((auth_failures + 1))
    fi
    if grep -Eq 'Webhook \{\} created for study \{\}|Webhook \{\} deleted for study \{\}|delivery attempt \{\} to \{\}' \
      "$ROOT_DIR/chronicle-server/src/main/kotlin/com/openlattice/chronicle/services/webhooks/WebhookService.kt"; then
      echo "Webhook logs must not expose raw study IDs or callback URLs"
      auth_failures=$((auth_failures + 1))
    fi

}

auth_export_guardrails() {
    if grep -Eq 'Database error .*Message: \{\}".*e\.message|e\.message,[[:space:]]*e' \
      "$ROOT_DIR/chronicle-server/src/main/kotlin/com/openlattice/chronicle/controllers/ChronicleServerExceptionHandler.kt"; then
      echo "SQL exception logs must sanitize database error messages"
      auth_failures=$((auth_failures + 1))
    fi

    if grep -Eq 'response\.status[[:space:]]*===[[:space:]]*401[[:space:]]*\)[[:space:]]*\{[[:space:]]*return[[:space:]]*\{[^}]*testingLoginEnabled:[[:space:]]*true' \
      "$ROOT_DIR/chronicle-web/src/modern/lib/bootstrap-auth.ts"; then
      echo "The web bootstrap must not infer testing-login availability from an auth/session 401"
      auth_failures=$((auth_failures + 1))
    fi

    if grep -Eq 'URLSearchParams\(\{[[:space:]]*token[[:space:]]*\}\)|/download\?\$\{params\.toString\(\)\}|@RequestParam\("token"\)[[:space:]]+token:[[:space:]]+String|X-Chronicle-Download-Token|RequestHeader\(.*Download|SecureCompare\.equalsNullSafe' \
      "$ROOT_DIR/chronicle-web/src/modern/state/study-operations-api.ts" \
      "$ROOT_DIR/chronicle-server/src/main/kotlin/com/openlattice/chronicle/controllers/ExportController.kt"; then
      echo "Export downloads must not use bearer download tokens in URLs, headers, or controller comparisons"
      auth_failures=$((auth_failures + 1))
    fi



}

auth_browser_guardrails() {
    local analytics_pattern='googletagmanager|google-analytics|gtag\(|G-WJ7BQMLPEK'
    if rg -i -q -e "$analytics_pattern" "$ROOT_DIR/chronicle-web/index.html" \
      "$ROOT_DIR/chronicle-web/src" "$ROOT_DIR/chronicle-web/scripts"; then
      echo "Browser-delivered Chronicle assets must not include third-party analytics beacons"
      auth_failures=$((auth_failures + 1))
    fi

    local referrer_pattern='Referrer-Policy[[:space:]]+"strict-origin-when-cross-origin"|referrerPolicy[=:][[:space:]]*strict-origin-when-cross-origin|name="referrer"[[:space:]]+content="(origin|strict-origin|strict-origin-when-cross-origin)"'
    if rg -i -q -e "$referrer_pattern" "$ROOT_DIR/chronicle-web/index.html" \
      "$ROOT_DIR/chronicle-web/src/index.html"; then
      echo "Browser surfaces with participant identifiers must not send their origin to other sites"
      auth_failures=$((auth_failures + 1))
    fi
    # same-origin, as the edge header: no referrer leaves for other sites, and native download POSTs keep
    # their real Origin (no-referrer sends Origin: null, which CorsValidationFilter rejects).
    if ! grep -Eq 'name="referrer"|name='\''referrer'\''' "$ROOT_DIR/chronicle-web/index.html" ||
      ! grep -Eq 'content="same-origin"|content='\''same-origin'\''' "$ROOT_DIR/chronicle-web/index.html" ||
      ! grep -Eq 'name="referrer"|name='\''referrer'\''' "$ROOT_DIR/chronicle-web/src/index.html" ||
      ! grep -Eq 'content="same-origin"|content='\''same-origin'\''' "$ROOT_DIR/chronicle-web/src/index.html" ||
      ! grep -Eq 'Referrer-Policy[[:space:]]+"same-origin"' "$ROOT_DIR/selfhost/caddy/snippets.caddy"; then
      echo "Chronicle HTML entrypoints and the edge must declare referrer policy same-origin"
      auth_failures=$((auth_failures + 1))
    fi

}

auth_log_guardrails() {
    if grep -Eq 'MDC\.put\("studyId",[[:space:]]*studyMatcher\.group\(1\)\)|MDC\.put\("participantId",[[:space:]]*LogSanitizer\.sanitize\(rawId|MDC\.put\("httpPath",[[:space:]]*LogSanitizer\.sanitizeUri\(path\)\)' \
      "$ROOT_DIR/chronicle-server/src/main/kotlin/com/openlattice/chronicle/configuration/ObservabilityFilter.kt"; then
      echo "ObservabilityFilter must log stable refs and route-shaped paths instead of raw request identifiers"
      auth_failures=$((auth_failures + 1))
    fi
    if ! grep -Eq 'sanitizeRequestPath\(path\)' \
      "$ROOT_DIR/chronicle-server/src/main/kotlin/com/openlattice/chronicle/configuration/ObservabilityFilter.kt"; then
      echo "ObservabilityFilter must route-shape httpPath via LogSanitizer.sanitizeRequestPath"
      auth_failures=$((auth_failures + 1))
    fi
    if grep -Eq 'UUID_PATTERN|/participant/\[\^/\]\+' \
      "$ROOT_DIR/chronicle-server/src/main/kotlin/com/openlattice/chronicle/observability/ApiMetricsFilter.kt"; then
      echo "ApiMetricsFilter must use shared request-path shaping instead of ad hoc identifier regexes"
      auth_failures=$((auth_failures + 1))
    fi
    # ApiMetricsFilterTest checks matched templates and bounded unmatched labels in jvm-smoke.
    if grep -Eq 'sanitizeUri\(request\.requestURI\)' \
      "$ROOT_DIR/chronicle-server/src/main/kotlin/com/openlattice/chronicle/filters/ApiKeyAuthenticationFilter.kt"; then
      echo "ApiKeyAuthenticationFilter path-mismatch logs must route-shape request paths"
      auth_failures=$((auth_failures + 1))
    fi
    if grep -Eq 'enrollmentTotal\.labels\(studyId\.toString\(\)\)|labelNames\("study_id"\)' \
      "$ROOT_DIR/chronicle-server/src/main/kotlin/com/openlattice/chronicle/services/enrollment/EnrollmentService.kt" \
      "$ROOT_DIR/chronicle-server/src/main/kotlin/com/openlattice/chronicle/observability/ChronicleMetrics.kt"; then
      echo "Enrollment metrics must label stable study refs instead of raw study IDs"
      auth_failures=$((auth_failures + 1))
    fi
    # The single-quoted expression intentionally matches literal Kotlin
    # interpolation syntax.
    # shellcheck disable=SC2016
    if grep -Eq 'sanitizeUri\(requestPath\)|sanitizeUri\(path\)|sanitizeUri\(request\.requestURI\)|URI: \$\{request\.requestURI\}|IP: \$\{request\.remoteAddr\}|endpoint:\$\{request\.requestURI\}|\$studyId:\$participantId|UUID_PATTERN|PARTICIPANT_PATTERN' \
      "$ROOT_DIR/chronicle-server/src/main/kotlin/com/openlattice/chronicle/configuration/RateLimitFilter.kt" \
      "$ROOT_DIR/chronicle-server/src/main/kotlin/com/openlattice/chronicle/configuration/SecurityHardeningConfig.kt" \
      "$ROOT_DIR/chronicle-server/src/main/kotlin/com/openlattice/chronicle/configuration/ParameterPollutionFilter.kt"; then
      echo "Request validation/rate-limit logs and keys must use route-shaped paths and stable refs"
      auth_failures=$((auth_failures + 1))
    fi
    if grep -Eq 'path[[:space:]]*=[[:space:]]*req\.requestURI|val path[[:space:]]*=[[:space:]]*request\.requestURI|sanitizeLogValue\((req|request)\.requestURI\)' \
      "$ROOT_DIR/chronicle-server/src/main/kotlin/com/openlattice/chronicle/controllers/ChronicleServerExceptionHandler.kt"; then
      echo "Exception handlers must not echo or log raw request paths"
      auth_failures=$((auth_failures + 1))
    fi

}
auth_static_guardrails() {
  local auth_failures=0
  auth_api_guardrails
  auth_export_guardrails
  auth_browser_guardrails
  auth_log_guardrails
  if [ "$auth_failures" -gt 0 ]; then
    echo "Auth static guardrails found $auth_failures violation(s)"
    return 1
  fi
  return 0
}

run_auth_behavior_tests() {
  local server_dir="$ROOT_DIR/chronicle-server"
  python3 -s "$ROOT_DIR/tests/security/lib/auth-test-results.py" "$server_dir/build/test-results/test" "$server_dir" \
    "$ROOT_DIR/gradles" "$ROOT_DIR/build.gradle.kts" "$ROOT_DIR/settings.gradle.kts" \
    "$ROOT_DIR/chronicle-models" "$ROOT_DIR/chronicle-api" "$ROOT_DIR/rhizome" "$ROOT_DIR/rhizome-client"
}

run_security_layer_selfhost_topology() {
    run_security_step "deploy.selfhost-topology" "Deploy: real remote TLS, enrollment and uploads" "guardrail" \
      "selfhost-topology.txt" "" -- bash "$ROOT_DIR/tests/deployment/selfhost-topology.sh" "${SELFHOST_TOPOLOGY_SOURCE:-$ROOT_DIR/selfhost}"
}

run_security_layer_sast() {
    run_security_step "sast.semgrep" "SAST: Semgrep repository rules" "scanner" \
      "semgrep.log" "semgrep.sarif" -- run_sast_semgrep
    run_security_step "sast.rls" "SAST: focused RLS guardrails" "guardrail" \
      "rls-guardrails.txt" "" -- "$ROOT_DIR/tests/security/run-rls-guardrails.sh" "$REPORT_DIR"
    for rule in room-migrations-single-owner entity-tags-single-owner notification-post-single-owner foreground-service-single-owner exact-alarm-single-owner usage-access-single-owner sensor-registration-single-owner health-connect-client-single-owner health-connect-read-single-owner notification-listener-access-single-owner media-session-single-owner accessibility-access-single-owner receiver-registration-single-owner activity-recognition-single-owner battery-exemption-single-owner work-stop-reason-single-owner package-label-single-owner network-usage-single-owner pending-intent-mutability-single-owner; do
      run_security_step "sast.ast-grep.${rule}" \
        "SAST: ast-grep $rule" "scanner" \
        "collection-${rule}.log" "collection-${rule}.sarif" -- \
        run_collection_ast_grep "$rule"
    done
    run_security_step "sast.single-owner-fixtures" "SAST: single-owner negative fixtures" "guardrail" \
      "single-owner-fixtures.log" "" -- bash "$ROOT_DIR/tests/security/single-owner-fixtures.sh"
    run_security_step "sast.semgrep-rule-fixtures" "SAST: Semgrep rule positive/negative fixtures" "guardrail" \
      "semgrep-rule-fixtures.log" "" -- \
      semgrep --test --disable-version-check --metrics off \
        --config "$ROOT_DIR/tests/security/rules/" "$ROOT_DIR/tests/security/rules/"
    echo "SAST scan complete"
}

run_security_layer_sca() {
    run_security_step "sca.supply-chain" "SCA: supply-chain reproducibility guardrails" "guardrail" \
      "supply-chain-guardrails.txt" "supply-chain" -- \
      "$ROOT_DIR/tests/security/supply-chain-guardrails.sh" "$REPORT_DIR/supply-chain"
    run_security_step "sca.bun-install" "SCA: Bun frozen-lockfile install" "build" \
      "bun-install.log" "" -- run_bun_frozen_install
    run_security_step "sca.bun-audit" "SCA: Bun high-severity audit" "scanner" \
      "bun-audit.log" "bun-audit.json" -- run_bun_audit
    echo "SCA scan complete"
}

run_security_layer_secrets() {
    run_security_step "secrets.gitleaks" "Secrets: Gitleaks" "scanner" \
      "gitleaks.log" "gitleaks.sarif" -- run_gitleaks_scan
    run_security_step "secrets.publish-gate" "Secrets: public mirror push gate fails closed" "guardrail" \
      "publish-gate.txt" "" -- python3 -s "$ROOT_DIR/tests/security/test_publish_gate.py"
    echo "Secrets scan complete"
}

run_security_layer_iac() {
    run_security_step "iac.gate-evidence" "IaC: gate jobs fail closed on scanner failures and stale evidence" "guardrail" \
      "gate-evidence.txt" "" -- python3 -s "$ROOT_DIR/tests/security/test_gate_evidence.py"
    run_security_step \
      "iac.checkov" "IaC: Checkov Dockerfile scan" "scanner" \
      "checkov.log" "checkov-output/results_sarif.sarif" -- run_checkov_scan

    dockerfile_list="$REPORT_DIR/dockerfiles.nul"
    discover_dockerfiles >"$dockerfile_list"
    dockerfile_count=0
    while IFS= read -r -d '' df; do
      dockerfile_count=$((dockerfile_count + 1))
      report_name="$(dockerfile_report_name "$df")"
      relative_df="${df#"$ROOT_DIR"/}"
      step_suffix="$(printf '%s' "$relative_df" | tr '/.' '--')"
      run_security_step \
        "iac.hadolint.${step_suffix}" "IaC: Hadolint $relative_df" "scanner" \
        "${report_name%.sarif}.log" "$report_name" -- \
        run_hadolint_scan "$df" "$REPORT_DIR/$report_name"
    done <"$dockerfile_list"
    if [ "$dockerfile_count" -eq 0 ]; then
      record_security_blocked \
        "iac.hadolint.discovery" "IaC: recursive Dockerfile discovery" \
        "No shipped Dockerfiles were discovered"
    fi
    echo "IaC scan complete"
}

run_deploy_operations() {
    run_security_step "deploy.selfhost-combination-matrix" "Deploy: declared self-host combination matrix" "guardrail" \
      "selfhost-combination-matrix.txt" "" -- "$ROOT_DIR/tests/security/selfhost-combination-matrix.sh"
    run_security_step "deploy.selfhost-release-bundle" "Deploy: source-free self-host release bundle contract" "guardrail" \
      "selfhost-release-bundle.txt" "" -- "$ROOT_DIR/tests/security/selfhost-release-bundle.sh"
    run_security_step "deploy.failure-propagation" "Deploy: failure propagation guardrails" "guardrail" \
      "failure-propagation-guardrails.txt" "" -- "$ROOT_DIR/tests/security/failure-propagation-guardrails.sh"
    echo "Deploy guardrails complete"
}

run_deploy_guardrails() {
    run_security_step "deploy.selfhost-restore-failclosed" "Deploy: self-host restore fail-closed contract" "guardrail" \
      "selfhost-restore-failclosed.txt" "" -- "$ROOT_DIR/tests/security/selfhost-restore-failclosed.sh"
    run_security_step "deploy.selfhost-restore-orchestration" "Deploy: self-host restore orchestration contract" "guardrail" \
      "selfhost-restore-orchestration.txt" "" -- "$ROOT_DIR/tests/security/selfhost-restore-orchestration.sh"
    run_security_step "deploy.selfhost-backup-readiness" "Deploy: self-host backup restart readiness contract" "guardrail" \
      "selfhost-backup-readiness.txt" "" -- "$ROOT_DIR/tests/security/selfhost-backup-readiness.sh"
    run_security_step "deploy.selfhost-setup-secrets" "Deploy: self-host setup secret-custody contract" "guardrail" \
      "selfhost-setup-secrets.txt" "" -- "$ROOT_DIR/tests/security/selfhost-setup-secrets.sh"
    run_security_step "deploy.mobile-secret-flow" "Deploy: age-sealed mobile secret custody contract" "guardrail" \
      "mobile-secret-flow.txt" "" -- "$ROOT_DIR/tests/security/mobile-secret-flow.sh"
    run_security_step "deploy.selfhost-verify-secrets" "Deploy: self-host verify secret-custody contract" "guardrail" \
      "selfhost-verify-secrets.txt" "" -- "$ROOT_DIR/tests/security/selfhost-verify-secrets.sh"
    run_security_step "deploy.selfhost-secret-rotation" "Deploy: self-host secret rotation and rollback contract" "guardrail" \
      "selfhost-secret-rotation.txt" "" -- "$ROOT_DIR/tests/security/selfhost-secret-rotation.sh"
    run_security_step "deploy.selfhost-deletion-status" "Deploy: self-host deletion status secret-custody contract" "guardrail" \
      "selfhost-deletion-status.txt" "" -- "$ROOT_DIR/tests/security/selfhost-deletion-status.sh"
    run_deploy_operations
}

run_security_layer_deploy() {
    run_security_step "deploy.gate-regressions" "Deploy: gate coverage and failure propagation regressions" "build" \
      "gate-regressions.txt" "" -- python3 "$ROOT_DIR/chronicle/scripts/test-gate-regressions.py"
    run_security_step "deploy.selfhost-python" "Deploy: complete self-host Python regression suite" "build" \
      "selfhost-python.txt" "" -- run_selfhost_python_suite discover -s "$ROOT_DIR/tests/selfhost-py"
    for suite in selfhost-cert-init selfhost-backup-selfcheck selfhost-deployment-audit selfhost-release-source \
                 selfhost-audit-regressions selfhost-web-lint gitleaks-history-regression; do
      run_security_step "deploy.$suite" "Deploy: $suite regressions" "guardrail" \
        "$suite.txt" "" -- bash "$ROOT_DIR/tests/security/$suite.sh"
    done
    for suite in "$ROOT_DIR"/tests/security/selfhost-operator-*.sh; do
      name="$(basename "$suite" .sh)"
      run_security_step "deploy.$name" "Deploy: $name regressions" "guardrail" \
        "$name.txt" "" -- bash "$suite"
    done
    run_security_step "deploy.semgrep" "Deploy: Bash/nginx/Docker/Compose Semgrep" "scanner" \
      "deployment-semgrep.log" "deployment-semgrep.sarif" -- run_deployment_semgrep
    run_security_step "deploy.public-tree-privacy" "Deploy: public-tree privacy guardrails" "guardrail" \
      "public-tree-privacy-guardrails.txt" "" -- python3 "$ROOT_DIR/tests/security/public-tree-privacy-guardrails.py"
    run_security_step "deploy.runner-self-test" "Deploy: security runner capture-all self-test" "build" \
      "security-runner-self-test.txt" "" -- "$ROOT_DIR/tests/security/security-runner-self-test.sh"
    run_security_step "deploy.production" "Deploy: production deployment guardrails" "guardrail" \
      "deploy-guardrails.txt" "" -- "$ROOT_DIR/tests/security/deploy-guardrails.sh" "$REPORT_DIR"
    run_security_step "deploy.db-secret-transport" "Deploy: database client secret-transport contract" "guardrail" \
      "db-secret-transport.txt" "" -- "$ROOT_DIR/tests/security/db-secret-transport-guardrails.sh"
    run_security_step "deploy.schema" "Deploy: schema/source-of-truth guardrails" "guardrail" \
      "schema-guardrails.txt" "" -- "$ROOT_DIR/tests/security/schema-guardrails.sh"
    run_deploy_guardrails
}

run_security_layer_auth() {
    run_security_step "auth.static" "Auth: JWT/session static guardrails" "guardrail" \
      "auth-static-guardrails.txt" "" -- auth_static_guardrails
    run_security_step "auth.behavior" "Auth: mobile identity and request privacy behavior" "build" \
      "auth-behavior.log" "" -- run_auth_behavior_tests
    # Semgrep is deliberately independent so a static guardrail finding cannot
    # suppress the scanner report.
    run_security_step "auth.semgrep" "Auth: hardcoded-secret and JWT patterns" "scanner" \
      "auth-semgrep.log" "auth-patterns.sarif" -- run_auth_semgrep
    echo "Auth scan complete"
}

run_security_layer_injection() {
    run_security_step "injection.semgrep" "Injection: Semgrep injection rules" "scanner" \
      "injection-semgrep.log" "injection.sarif" -- run_injection_semgrep
    echo "Injection scan complete"
}

run_security_layer_upload() {
    run_security_step "upload.input-validation" "Upload: enrolled-device input validation probes" "guardrail" \
      "file-upload-tests.txt" "" -- bash "$ROOT_DIR/tests/security/file-upload-tests.sh"
    run_security_step "upload.load-smoke" "Upload: load smoke test" "guardrail" \
      "load-smoke.txt" "" -- bash "$ROOT_DIR/tests/load/smoke-test.sh"
    # Exported for this layer only; the race script reads STUDY_ID.
    local STUDY_ID="${TEST_STUDY_ID:-}"
    export STUDY_ID
    run_security_step "upload.races" "Upload: enrollment, nonce, deletion and settings races" "guardrail" \
      "race-conditions.txt" "race-summary.json" -- k6_run_trusting_fixture_ca \
      "BASE_URL MANAGEMENT_URL STUDY_ID TEST_RANDOM_DEVICE_ID AUTH_TOKEN MOBILE_SIGNING_SECRET UPLOAD_CONNECT_TO" -- \
      --summary-export "$REPORT_DIR/race-summary.json" "$ROOT_DIR/tests/security/k6-race-conditions.js"
}

run_security_layer_crypto() {
    run_security_step "crypto.semgrep" "Crypto: weak crypto patterns" "scanner" \
      "crypto-semgrep.log" "crypto.sarif" -- run_crypto_semgrep
    echo "Crypto scan complete"
}

run_security_layer_license() {
    run_security_step "license.gradle" "License: Gradle license report" "build" \
      "license.log" "license.json" -- run_license_report
    echo "License scan complete"
}

run_security_layer_collection() {
    run_security_step "collection.semgrep-modularization" \
      "Collection: Semgrep modularization rules" "scanner" \
      "collection-semgrep-modularization.log" "collection-semgrep-modularization.sarif" -- \
      run_collection_semgrep_modularization
    run_security_step "collection.semgrep-dto" \
      "Collection: Semgrep DTO secret-redaction rule" "scanner" \
      "collection-semgrep-dto.log" "collection-semgrep-dto.sarif" -- \
      run_collection_semgrep_dto

    for rule in collection-module-id-no-raw-string \
                collection-queue-insert-only-in-sink \
                collection-sensor-insert-only-in-sink \
                collection-hardware-service-only-via-manager \
                collection-lifecycle-record-only-via-module \
                collection-worker-no-direct-sensor-instantiation \
                collection-settings-service-no-rls-context-call \
                collection-settings-resolver-only-via-coordinator; do
      run_security_step "collection.ast-grep.${rule}" \
        "Collection: ast-grep $rule" "scanner" \
        "collection-${rule}.log" "collection-${rule}.sarif" -- \
        run_collection_ast_grep "$rule"
    done

    run_security_step "collection.fixture-self-check" \
      "Collection: guardrail fixture self-check" "guardrail" \
      "collection-guardrail-fixtures.log" "" -- \
      "$ROOT_DIR/tests/security/collection-guardrail-fixtures.sh" "$REPORT_DIR"
    echo "Collection guardrails complete"
}

run_security_layer_compliance() {
    run_security_step "compliance.conftest" "Compliance: Conftest OPA policies" "scanner" \
      "compliance.log" "compliance.json" -- run_compliance_scan
    echo "Compliance scan complete"
}

security_runner_main() {
  if [ "$#" -ne 2 ]; then
    echo "Usage: $0 <layer> <report-dir>" >&2
    return 2
  fi
  LAYER="$1"
  REPORT_DIR="$2"
  security_runner_init "$LAYER" "$REPORT_DIR"
  trap 'security_runner_exit_trap $?' EXIT

case "$LAYER" in
  selfhost-topology) run_security_layer_selfhost_topology ;;
  sast) run_security_layer_sast ;;
  sca) run_security_layer_sca ;;
  secrets) run_security_layer_secrets ;;
  iac) run_security_layer_iac ;;
  deploy) run_security_layer_deploy ;;
  auth) run_security_layer_auth ;;
  injection) run_security_layer_injection ;;
  upload) run_security_layer_upload ;;
  crypto) run_security_layer_crypto ;;
  license) run_security_layer_license ;;
  collection) run_security_layer_collection ;;
  compliance) run_security_layer_compliance ;;
  *)
    echo "ERROR: Unknown layer: $LAYER"
    echo "Valid layers: sast, sca, secrets, iac, deploy, selfhost-topology, auth, injection, upload, crypto, license, compliance, collection"
    exit 1
    ;;
esac

echo "Layer $LAYER completed. Reports in $REPORT_DIR"
security_runner_finalize 0
trap - EXIT
return "$SECURITY_RUNNER_EXIT_CODE"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  runner_status=0
  security_runner_main "$@" || runner_status=$?
  exit "$runner_status"
fi
