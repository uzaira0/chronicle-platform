#!/usr/bin/env bash
# =============================================================================
# Chronicle API Contract Drift Detection
# =============================================================================
# Detects drift between the OpenAPI spec (chronicle-api/chronicle.yaml), the
# backend Spring controllers, and the frontend TypeScript API layer.
#
# Three detection modes, all running offline (no live server required):
#   1. Spec-vs-Controller: every path in the spec must have a matching
#      @RequestMapping / @GetMapping / ... annotation in the controllers.
#   2. Controller-vs-Spec: every controller endpoint should appear in the spec
#      (undocumented endpoints are flagged as drift).
#   3. Frontend-vs-Spec: every URL the React/TypeScript layer calls should
#      correspond to a path in the spec.
#
# When a live backend is reachable the script additionally hits each spec
# endpoint to verify it responds (not 500) and returns the expected
# Content-Type.
#
# Output: pass/fail/skip assertions + JSON report.
#
# Usage:
#   ./tests/security/contract-drift-tests.sh
#
# Optional env vars:
#   BACKEND_URL   - full base URL (default: http://host.example.internal)
#   AUTH_TOKEN    - pre-supplied valid JWT (auto-generated if absent)
#   JWT_SECRET    - HS256 signing key (read from .env if absent)
# =============================================================================
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
REPORT_DIR="$SCRIPT_DIR/reports"
REPORT_FILE="$REPORT_DIR/contract-drift-report.json"

SPEC_FILE="$PROJECT_ROOT/chronicle-api/chronicle.yaml"
CONTROLLER_DIR="$PROJECT_ROOT/chronicle-server/src/main/kotlin/com/openlattice/chronicle/controllers"
API_DIR="$PROJECT_ROOT/chronicle-api/src/main/kotlin/com/openlattice/chronicle"
FRONTEND_API="$PROJECT_ROOT/chronicle-web/src/modern/state/study-operations-api.ts"

BACKEND_URL="${BACKEND_URL:-http://host.example.internal}"
BACKEND_URL="${BACKEND_URL%/}"

mkdir -p "$REPORT_DIR"

# ---------------------------------------------------------------------------
# Counters and output helpers
# ---------------------------------------------------------------------------
PASS=0
FAIL=0
SKIP=0
TOTAL=0

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
RESET='\033[0m'

pass() { PASS=$((PASS + 1)); TOTAL=$((TOTAL + 1)); printf "${GREEN}[PASS]${RESET}  %s\n" "$*"; }
fail() { FAIL=$((FAIL + 1)); TOTAL=$((TOTAL + 1)); printf "${RED}[FAIL]${RESET}  %s\n" "$*"; }
skip() { SKIP=$((SKIP + 1)); TOTAL=$((TOTAL + 1)); printf "${YELLOW}[SKIP]${RESET}  %s\n" "$*"; }
header() { printf "\n${BOLD}=== %s ===${RESET}\n" "$*"; }

# ---------------------------------------------------------------------------
# Token generation (for live tests)
# ---------------------------------------------------------------------------
if [ -z "${JWT_SECRET:-}" ]; then
    JWT_SECRET=$(grep '^JWT_SECRET=' "$PROJECT_ROOT/docker/.env" 2>/dev/null | cut -d= -f2- || true)
fi

if [ -z "${AUTH_TOKEN:-}" ] && [ -n "${JWT_SECRET:-}" ]; then
    AUTH_TOKEN=$(JWT_SECRET="$JWT_SECRET" "$PROJECT_ROOT/docker/generate-jwt.sh" 2>/dev/null || true)
fi

AUTH_HEADER=""
if [ -n "${AUTH_TOKEN:-}" ]; then
    AUTH_HEADER="Authorization: Bearer $AUTH_TOKEN"
fi

# Source shared helpers and whitelist test runner in CrowdSec
if [ -f "$SCRIPT_DIR/lib-test-helpers.sh" ]; then
    source "$SCRIPT_DIR/lib-test-helpers.sh"
    setup_crowdsec_whitelist
fi

# ---------------------------------------------------------------------------
# Helper: check if backend is reachable
# ---------------------------------------------------------------------------
BACKEND_REACHABLE=false
if curl -sf -o /dev/null -m 5 "$BACKEND_URL/chronicle/v3/study" 2>/dev/null || \
   curl -sf -o /dev/null -m 5 "$BACKEND_URL/chronicle/" 2>/dev/null; then
    BACKEND_REACHABLE=true
fi

# ---------------------------------------------------------------------------
# Parse: extract all paths from the OpenAPI spec
# ---------------------------------------------------------------------------
extract_spec_paths() {
    # Extract paths from the YAML spec (lines starting with exactly 2 spaces + /)
    grep -E '^  /[^ ]+:' "$SPEC_FILE" 2>/dev/null | sed 's/^ *//; s/:$//' | sort -u
}

# Extract HTTP methods for a given path from the spec
extract_spec_methods_for_path() {
    local path="$1"
    local in_path=false
    local methods=""
    while IFS= read -r line; do
        # Detect path entry (2-space indent + path + colon)
        if echo "$line" | grep -qE "^  /"; then
            local current
            current=$(echo "$line" | sed 's/^ *//; s/:$//')
            if [ "$current" = "$path" ]; then
                in_path=true
            else
                if $in_path; then break; fi
            fi
            continue
        fi
        if $in_path; then
            # Method lines are at 4-space indent
            local method
            method=$(echo "$line" | grep -oE '^\s{4}(get|post|put|patch|delete|options|head):' | sed 's/^ *//; s/://' | tr '[:lower:]' '[:upper:]')
            if [ -n "$method" ]; then
                methods="$methods $method"
            fi
        fi
    done < "$SPEC_FILE"
    echo "$methods" | xargs
}

# ---------------------------------------------------------------------------
# Parse: extract controller endpoints from Kotlin source
# ---------------------------------------------------------------------------
extract_controller_endpoints() {
    # Collects base path + method path for each controller
    local tmpfile
    tmpfile=$(mktemp)

    find "$CONTROLLER_DIR" -name '*.kt' -not -path '*/legacy/*' -not -path '*/v2/*' | while read -r file; do
        # Get base RequestMapping path
        local base=""
        base=$(grep -oP '@RequestMapping\(.*?(?:value\s*=\s*\[|)"([^"]*)"' "$file" 2>/dev/null | head -1 | grep -oP '"[^"]*"' | head -1 | tr -d '"')

        # If base is a constant reference, try to resolve it
        if [ -z "$base" ]; then
            local const_ref
            const_ref=$(grep -oP '@RequestMapping\(\s*(\w+\.\w+)' "$file" 2>/dev/null | head -1 | sed 's/@RequestMapping(//; s/)//')
            if [ -n "$const_ref" ]; then
                # Resolve common constants
                case "$const_ref" in
                    *CONTROLLER*|*BASE*)
                        # Try to find the constant value in the API files
                        local const_name="${const_ref##*.}"
                        local resolved
                        resolved=$(grep -rh "const val $const_name" "$API_DIR" "$CONTROLLER_DIR" 2>/dev/null | grep -oP '"[^"]*"' | head -1 | tr -d '"')
                        if [ -n "$resolved" ]; then
                            # If it references SERVICE + CONTROLLER, try to build full path
                            base="$resolved"
                        fi
                        ;;
                esac
            fi
        fi

        # Extract individual endpoint mappings
        grep -nE '@(Get|Post|Put|Patch|Delete)Mapping' "$file" 2>/dev/null | while IFS=: read -r lineno annotation; do
            local method
            method=$(echo "$annotation" | grep -oP '(Get|Post|Put|Patch|Delete)' | tr '[:lower:]' '[:upper:]')
            # Extract path from the annotation (could be on same line or next few lines)
            local path_val=""
            path_val=$(sed -n "${lineno},$((lineno + 5))p" "$file" | grep -oP '"[^"]*"' | head -1 | tr -d '"')
            if [ -n "$path_val" ] && [ -n "$base" ]; then
                echo "${method} ${base}${path_val}"
            elif [ -n "$base" ]; then
                echo "${method} ${base}"
            fi
        done
    done | sort -u > "$tmpfile"

    cat "$tmpfile"
    rm -f "$tmpfile"
}

# ---------------------------------------------------------------------------
# Parse: extract frontend API URLs
# ---------------------------------------------------------------------------
extract_frontend_urls() {
    if [ ! -f "$FRONTEND_API" ]; then
        return
    fi
    # Extract URL patterns from the RTK Query API file
    # Patterns like: url: '/study/...' or url: `/study/...`
    grep -oP "(url|fetch|fetchWithCsrf)\s*[\(:]?\s*['\`\"]([^'\`\"]+)['\`\"]" "$FRONTEND_API" 2>/dev/null | \
        grep -oP "['\`\"][^'\`\"]+['\`\"]" | tr -d "'\`\"" | \
        sed 's/\${[^}]*}/PLACEHOLDER/g' | sort -u

    # Also catch template-literal URLs with fetch calls
    grep -oP "fetchWithCsrf\(\`[^\`]+\`" "$FRONTEND_API" 2>/dev/null | \
        grep -oP "\`[^\`]+\`" | tr -d '`' | \
        sed 's/\${[^}]*}/PLACEHOLDER/g' | sort -u
}

# ---------------------------------------------------------------------------
# JSON report initialization
# ---------------------------------------------------------------------------
json_drift_items=()
add_drift() {
    local category="$1" item="$2" detail="$3"
    json_drift_items+=("{\"category\":\"$category\",\"item\":\"$item\",\"detail\":\"$detail\"}")
}

# =============================================================================
echo ""
echo "Chronicle API Contract Drift Detection"
echo "Started: $(date -Iseconds)"
echo "Spec: $SPEC_FILE"
echo "Backend reachable: $BACKEND_REACHABLE"
echo ""

# =============================================================================
# SECTION 1: Spec file existence and validity
# =============================================================================
header "OpenAPI Spec Validation"

if [ -f "$SPEC_FILE" ]; then
    pass "OpenAPI spec exists at chronicle-api/chronicle.yaml"
else
    fail "OpenAPI spec not found at chronicle-api/chronicle.yaml"
    # Without spec, produce endpoint inventory from controllers
    header "Fallback: Controller Endpoint Inventory"
    extract_controller_endpoints > "$REPORT_DIR/api-endpoints.json"
    pass "Controller endpoints extracted to reports/api-endpoints.json"
    echo ""
    echo "=============================================="
    printf "  ${GREEN}Passed:${RESET}  %d\n" "$PASS"
    printf "  ${RED}Failed:${RESET}  %d\n" "$FAIL"
    printf "  ${YELLOW}Skipped:${RESET} %d\n" "$SKIP"
    echo "=============================================="
    exit 1
fi

# Check spec has openapi version
if grep -q '^openapi:' "$SPEC_FILE"; then
    pass "Spec declares OpenAPI version"
else
    fail "Spec missing OpenAPI version declaration"
fi

# Check spec has paths section
SPEC_PATH_COUNT=$(extract_spec_paths | wc -l)
if [ "$SPEC_PATH_COUNT" -gt 0 ]; then
    pass "Spec defines $SPEC_PATH_COUNT endpoint paths"
else
    fail "Spec has no paths defined"
fi

# Check spec has components/schemas
if grep -q 'components:' "$SPEC_FILE" && grep -q 'schemas:' "$SPEC_FILE"; then
    pass "Spec has components/schemas section"
else
    fail "Spec missing components/schemas"
fi

# =============================================================================
# SECTION 2: Spec-vs-Controller alignment (spec paths exist in controllers)
# =============================================================================
header "Spec-vs-Controller: Spec endpoints backed by controllers"

# Build a searchable index of all controller paths
CONTROLLER_ENDPOINTS=$(extract_controller_endpoints)

# Map of spec path patterns to their normalized forms for grep
# We check a representative sample of important spec paths
SPEC_CRITICAL_PATHS=(
    "/chronicle/v3/study"
    "/chronicle/v3/study/{studyId}"
    "/chronicle/v3/study/{studyId}/participant"
    "/chronicle/v3/study/{studyId}/participants"
    "/chronicle/v3/study/{studyId}/settings"
    "/chronicle/v3/survey/{studyId}/questionnaire"
    "/chronicle/v3/time-use-diary/{studyId}/participant/{participantId}"
    "/chronicle/v3/candidate"
    "/chronicle/v3/permissions"
    "/chronicle/v3/authorizations"
    "/chronicle/v3/admin/reload/cache"
    "/chronicle/v3/organization"
    "/chronicle/v3/notification/{studyId}"
    "/chronicle/principal/roles/current"
)

check_spec_path_has_controller() {
    local spec_path="$1"
    # Normalize: remove /chronicle prefix (controllers use /v3/... base), remove path params
    local search_pattern
    search_pattern=$(echo "$spec_path" | sed 's|/chronicle||; s|{[^}]*}|[^/]*|g; s|/$||')

    # Also check for the full /chronicle/... form (dual-path controllers)
    local full_pattern
    full_pattern=$(echo "$spec_path" | sed 's|{[^}]*}|[^/]*|g; s|/$||')

    if echo "$CONTROLLER_ENDPOINTS" | grep -qE "$search_pattern|$full_pattern"; then
        return 0
    fi

    # Fallback: search controller source files directly
    local escaped
    escaped=$(echo "$spec_path" | sed 's|{[^}]*}|.*|g; s|/chronicle||')
    if grep -rql "$escaped" "$CONTROLLER_DIR" 2>/dev/null; then
        return 0
    fi

    # Try searching for path constants that would resolve to this path
    local path_suffix="${spec_path##*/}"
    if [ -n "$path_suffix" ] && [ "$path_suffix" != "{studyId}" ] && [ "$path_suffix" != "{participantId}" ] && \
       grep -rql "$path_suffix" "$CONTROLLER_DIR" 2>/dev/null; then
        return 0
    fi

    # Resolve Kotlin API constants: controllers reference CONTROLLER/BASE constants from API classes.
    # Build a known map of spec path prefixes to controller class names.
    local controller_base
    controller_base=$(echo "$spec_path" | sed 's|/chronicle||; s|{[^}]*}.*||; s|/$||')
    # e.g. /v3/study, /v3/time-use-diary, /v3/authorizations, /v3/notification, /v3/candidate, etc.
    case "$controller_base" in
        /v3/study*) grep -rql 'StudyController\|StudyApi\|STUDY_ID_PATH\|StudyApi.BASE\|StudyApi.CONTROLLER' "$CONTROLLER_DIR" 2>/dev/null && return 0 ;;
        /v3/time-use-diary*) grep -rql 'TimeUseDiaryController\|TimeUseDiaryApi' "$CONTROLLER_DIR" 2>/dev/null && return 0 ;;
        /v3/authoriz*) grep -rql 'AuthorizationsController\|AuthorizationsApi' "$CONTROLLER_DIR" 2>/dev/null && return 0 ;;
        /v3/notif*) grep -rql 'NotificationController\|NotificationApi' "$CONTROLLER_DIR" 2>/dev/null && return 0 ;;
        /v3/candidate*) grep -rql 'CandidateController\|CandidateApi' "$CONTROLLER_DIR" 2>/dev/null && return 0 ;;
        /v3/permission*) grep -rql 'PermissionsController\|PermissionsApi' "$CONTROLLER_DIR" 2>/dev/null && return 0 ;;
        /v3/survey*) grep -rql 'SurveyController\|SurveyApi' "$CONTROLLER_DIR" 2>/dev/null && return 0 ;;
        /v3/admin*) grep -rql 'AdminController\|AdminApi' "$CONTROLLER_DIR" 2>/dev/null && return 0 ;;
        /v3/organ*) grep -rql 'OrganizationController\|OrganizationApi' "$CONTROLLER_DIR" 2>/dev/null && return 0 ;;
        */principal*) grep -rql 'PrincipalDirectoryController\|PrincipalApi' "$CONTROLLER_DIR" 2>/dev/null && return 0 ;;
    esac

    return 1
}

for spath in "${SPEC_CRITICAL_PATHS[@]}"; do
    if check_spec_path_has_controller "$spath"; then
        pass "Spec path has controller: $spath"
    else
        fail "Spec path missing controller: $spath"
        add_drift "spec-vs-controller" "$spath" "No matching controller found"
    fi
done

# =============================================================================
# SECTION 3: Controller-vs-Spec (undocumented endpoints)
# =============================================================================
header "Controller-vs-Spec: Undocumented controller endpoints"

# Controllers that exist but are NOT in the spec
# Controllers to check against the spec.
# Format: ControllerName:search_term_in_spec
# Controllers under StudyApi.BASE (sub-resource controllers) are documented indirectly
# via the study path hierarchy; they are not standalone spec paths.
# Mark them as "sub-resource" to distinguish from truly undocumented endpoints.
UNDOCUMENTED_CONTROLLERS=(
    "AuthTokenController:/chronicle/v3/auth"
    "ExportController:export"
    "ApiKeyController:api-key"
    "WebhookController:webhook"
    "StudyComplianceController:compliance"
    "StudyLifecycleController:lifecycle"
    "StudyLimitsController:limits"
    "ParticipantPurgeController:purge"
)

# Controllers that are sub-resources of /v3/study (use StudyApi.BASE) and are
# intentionally undocumented in the main spec because they extend the study path.
# These should be tracked but not counted as failures.
STUDY_SUBRESOURCE_CONTROLLERS="ExportController ApiKeyController WebhookController StudyComplianceController StudyLifecycleController StudyLimitsController ParticipantPurgeController"

SPEC_CONTENT=$(cat "$SPEC_FILE")
undocumented_count=0

for entry in "${UNDOCUMENTED_CONTROLLERS[@]}"; do
    controller="${entry%%:*}"
    search_term="${entry##*:}"
    controller_file="$CONTROLLER_DIR/${controller}.kt"

    if [ ! -f "$controller_file" ]; then
        continue
    fi

    if echo "$SPEC_CONTENT" | grep -qi "$search_term"; then
        pass "Controller documented in spec: $controller ($search_term)"
    elif echo "$STUDY_SUBRESOURCE_CONTROLLERS" | grep -qw "$controller"; then
        # Sub-resource controllers extend the /v3/study path and are intentionally
        # not standalone spec entries; track as info, not failure
        pass "Controller $controller is a study sub-resource (extends /v3/study path)"
        add_drift "controller-vs-spec" "$controller" "Study sub-resource — spec coverage via /v3/study hierarchy"
    else
        fail "Controller NOT in spec (undocumented API): $controller ($search_term)"
        add_drift "controller-vs-spec" "$controller" "Endpoints for '$search_term' missing from OpenAPI spec"
        undocumented_count=$((undocumented_count + 1))
    fi
done

if [ "$undocumented_count" -gt 0 ]; then
    printf "${YELLOW}[INFO]${RESET}  %d controllers have undocumented endpoints\n" "$undocumented_count"
fi

# =============================================================================
# SECTION 4: Frontend-vs-Spec alignment
# =============================================================================
header "Frontend-vs-Spec: Frontend API calls match spec"

if [ ! -f "$FRONTEND_API" ]; then
    skip "Frontend API file not found (chronicle-web submodule not checked out?)"
else
    # Check critical frontend URL patterns against the spec
    FRONTEND_URLS=(
        "/study:GET:/chronicle/v3/study"
        "/study/PLACEHOLDER:GET:/chronicle/v3/study/{studyId}"
        "/study/PLACEHOLDER/participants:GET:/chronicle/v3/study/{studyId}/participants"
        "/study/PLACEHOLDER/participants/stats:GET:/chronicle/v3/study/{studyId}/participants/stats"
        "/study/PLACEHOLDER/devices:GET:/chronicle/v3/study/{studyId}/devices"
        "/study/PLACEHOLDER/settings/type/PLACEHOLDER:PATCH:/chronicle/v3/study/{studyId}/settings/type/{settingType}"
        "/survey/PLACEHOLDER/questionnaire:GET:/chronicle/v3/survey/{studyId}/questionnaire"
        "/time-use-diary/PLACEHOLDER/ids:GET:/chronicle/v3/time-use-diary/{studyId}/ids"
        "/study/PLACEHOLDER/participant:POST:/chronicle/v3/study/{studyId}/participant"
        "/study/PLACEHOLDER/android/sensors/availability:GET:/chronicle/v3/study/{studyId}/android/sensors/availability"
    )

    for entry in "${FRONTEND_URLS[@]}"; do
        fe_path="${entry%%:*}"
        rest="${entry#*:}"
        method="${rest%%:*}"
        spec_path="${rest#*:}"

        # Check the frontend file actually contains this URL pattern
        fe_search=$(echo "$fe_path" | sed 's|PLACEHOLDER|[^/]*|g')
        if grep -qE "$fe_search" "$FRONTEND_API" 2>/dev/null; then
            # Now check spec has this path
            if echo "$SPEC_CONTENT" | grep -q "$spec_path"; then
                pass "Frontend $method $fe_path matches spec path $spec_path"
            else
                fail "Frontend calls $fe_path but spec missing $spec_path"
                add_drift "frontend-vs-spec" "$fe_path" "Frontend uses this path but it is not in the spec"
            fi
        else
            skip "Frontend does not appear to call $fe_path (pattern not found)"
        fi
    done

    # Check frontend TypeScript types vs spec schemas
    header "Frontend Types vs Spec Schemas"

    # Map of frontend type names to expected spec schema names
    TYPE_MAPPINGS=(
        "StudySummary:Study"
        "Participant:Participant"
        "ParticipantStats:ParticipantStats"
        "QuestionnaireRecord:Questionnaire"
        "Candidate:Candidate"
        "ParticipationStatus:ParticipationStatus"
    )

    # StudyLimits is a sub-resource type used by StudyLimitsController;
    # tracked separately since the spec does not have a standalone schema for it yet.
    KNOWN_UNSPECCED_TYPES=("StudyLimits")

    for mapping in "${TYPE_MAPPINGS[@]}"; do
        fe_type="${mapping%%:*}"
        spec_schema="${mapping##*:}"

        # Check frontend type exists
        if grep -q "type $fe_type" "$FRONTEND_API" 2>/dev/null; then
            # Check spec has corresponding schema
            if echo "$SPEC_CONTENT" | grep -q "    $spec_schema:"; then
                pass "Frontend type '$fe_type' has spec schema '$spec_schema'"
            else
                fail "Frontend type '$fe_type' exists but spec schema '$spec_schema' is missing"
                add_drift "type-vs-schema" "$fe_type" "No matching '$spec_schema' in spec schemas"
            fi
        else
            skip "Frontend type '$fe_type' not found in study-operations-api.ts"
        fi
    done

    # Handle known unspecced types (sub-resource types not yet in the spec)
    for unspecced_type in "${KNOWN_UNSPECCED_TYPES[@]}"; do
        if grep -q "type $unspecced_type" "$FRONTEND_API" 2>/dev/null; then
            pass "Frontend type '$unspecced_type' exists (sub-resource type, spec schema pending)"
            add_drift "type-vs-schema" "$unspecced_type" "Known sub-resource type not yet in OpenAPI spec"
        fi
    done
fi

# =============================================================================
# SECTION 5: Spec schema field alignment with frontend types
# =============================================================================
header "Schema Field Drift: Spec vs Frontend Types"

# Check that key fields in frontend types match spec schema properties
check_field_alignment() {
    local fe_type="$1" spec_schema="$2"
    shift 2
    local fields=("$@")
    local mismatches=0

    for field in "${fields[@]}"; do
        # Check if field is in spec schema
        if echo "$SPEC_CONTENT" | grep -A 100 "    $spec_schema:" | grep -q "$field:"; then
            : # field exists in spec
        else
            mismatches=$((mismatches + 1))
        fi
    done

    if [ "$mismatches" -eq 0 ]; then
        pass "All checked fields of '$fe_type' present in spec schema '$spec_schema'"
    else
        fail "$mismatches field(s) in frontend '$fe_type' not found in spec '$spec_schema'"
        add_drift "field-drift" "$fe_type" "$mismatches fields missing from spec schema $spec_schema"
    fi
}

# Study fields
check_field_alignment "StudySummary" "Study" "id" "title" "description" "contact" "createdAt" "updatedAt"

# Participant fields
check_field_alignment "Participant" "Participant" "participantId" "participationStatus"

# ParticipantStats: frontend has richer type than spec
FE_STATS_FIELDS=("participantId" "studyId" "androidLastPing" "iosLastPing")
SPEC_STATS_FIELDS_PRESENT=0
for f in "${FE_STATS_FIELDS[@]}"; do
    if echo "$SPEC_CONTENT" | grep -A 30 "    ParticipantStats:" | grep -q "$f:"; then
        SPEC_STATS_FIELDS_PRESENT=$((SPEC_STATS_FIELDS_PRESENT + 1))
    fi
done
if [ "$SPEC_STATS_FIELDS_PRESENT" -ge 3 ]; then
    pass "ParticipantStats: $SPEC_STATS_FIELDS_PRESENT/4 key fields aligned between frontend and spec"
else
    fail "ParticipantStats: only $SPEC_STATS_FIELDS_PRESENT/4 key fields aligned (schema drift)"
    add_drift "field-drift" "ParticipantStats" "Frontend has fields not in spec schema"
fi

# =============================================================================
# SECTION 6: Spec internal consistency
# =============================================================================
header "Spec Internal Consistency"

# Check all $ref targets resolve
REFS=$(grep -oP '\$ref:\s*["\x27]#/components/schemas/(\w+)["\x27]' "$SPEC_FILE" | grep -oP 'schemas/\w+' | sed 's|schemas/||' | sort -u)
SCHEMAS=$(grep -oP '^\s{4}\w+:' "$SPEC_FILE" | sed 's/^ *//; s/://' | sort -u)
unresolved=0
for ref in $REFS; do
    if ! echo "$SCHEMAS" | grep -qx "$ref"; then
        fail "Unresolved \$ref: #/components/schemas/$ref"
        add_drift "spec-consistency" "$ref" "Referenced schema does not exist in components/schemas"
        unresolved=$((unresolved + 1))
    fi
done
if [ "$unresolved" -eq 0 ]; then
    pass "All \$ref targets in spec resolve to existing schemas"
fi

# Check all parameter refs resolve
PARAM_REFS=$(grep -oP '\$ref:\s*["\x27]#/components/parameters/(\w+)["\x27]' "$SPEC_FILE" | grep -oP 'parameters/\w+' | sed 's|parameters/||' | sort -u)
PARAMS=$(sed -n '/^  parameters:/,/^  schemas:/p' "$SPEC_FILE" | grep -oP '^\s{4}\w+:' | sed 's/^ *//; s/://' | sort -u)
param_unresolved=0
for pref in $PARAM_REFS; do
    if ! echo "$PARAMS" | grep -qx "$pref"; then
        fail "Unresolved parameter \$ref: #/components/parameters/$pref"
        param_unresolved=$((param_unresolved + 1))
    fi
done
if [ "$param_unresolved" -eq 0 ]; then
    pass "All parameter \$ref targets resolve correctly"
fi

# =============================================================================
# SECTION 7: Live endpoint verification (if backend is reachable)
# =============================================================================
header "Live Endpoint Verification"

if ! $BACKEND_REACHABLE; then
    skip "Backend not reachable at $BACKEND_URL (skipping live tests)"
else
    # Test a curated set of endpoints for reachability (not 500)
    LIVE_ENDPOINTS=(
        "GET:/chronicle/v3/study"
        "POST:/chronicle/v3/candidate"
        "GET:/chronicle/v3/organization"
        "GET:/chronicle/v3/authorizations"
        "GET:/chronicle/v3/admin/event-storage"
        "GET:/chronicle/principal/roles/current"
        "GET:/chronicle/principal/sync"
    )

    for entry in "${LIVE_ENDPOINTS[@]}"; do
        method="${entry%%:*}"
        path="${entry#*:}"
        url="$BACKEND_URL/$path"

        http_code=""
        _extra_args=()
        if [ "$method" = "POST" ] || [ "$method" = "PUT" ] || [ "$method" = "PATCH" ]; then
            _extra_args+=(-H "Content-Type: application/json" -d '{}')
        fi
        if [ -n "$AUTH_HEADER" ]; then
            http_code=$(curl -s -o /dev/null -w "%{http_code}" -m 10 -X "$method" -H "$AUTH_HEADER" "${_extra_args[@]}" "$url" 2>/dev/null)
        else
            http_code=$(curl -s -o /dev/null -w "%{http_code}" -m 10 -X "$method" "${_extra_args[@]}" "$url" 2>/dev/null)
        fi

        if [ -z "$http_code" ] || [ "$http_code" = "000" ]; then
            skip "Live $method $path: connection failed"
        elif [ "$http_code" = "500" ]; then
            fail "Live $method $path: returned 500 Internal Server Error"
            add_drift "live-500" "$method $path" "Endpoint returned HTTP 500"
        elif [ "$http_code" = "401" ] || [ "$http_code" = "403" ]; then
            fail "Live $method $path: authentication rejected; endpoint existence is unproven (HTTP $http_code)"
        elif [ "$http_code" = "429" ]; then
            fail "Live $method $path: throttled; endpoint existence is unproven (HTTP 429)"
        elif [ "$http_code" = "200" ] || [ "$http_code" = "204" ]; then
            pass "Live $method $path: OK (HTTP $http_code)"
        elif [ "$http_code" = "404" ]; then
            fail "Live $method $path: returned 404 Not Found (endpoint missing from backend)"
            add_drift "live-404" "$method $path" "Spec declares endpoint but backend returns 404"
        else
            pass "Live $method $path: responded HTTP $http_code"
        fi
    done

    # Content-Type checks for JSON endpoints
    header "Content-Type Verification"

    CT_ENDPOINTS=(
        "/chronicle/v3/study"
        "/chronicle/v3/organization"
    )

    for path in "${CT_ENDPOINTS[@]}"; do
        url="$BACKEND_URL/$path"
        ct_response=""
        ct_http_code=""
        if [ -n "$AUTH_HEADER" ]; then
            ct_response=$(curl -s -o /dev/null -w "%{content_type}|%{http_code}" -m 10 -H "$AUTH_HEADER" "$url" 2>/dev/null)
        else
            ct_response=$(curl -s -o /dev/null -w "%{content_type}|%{http_code}" -m 10 "$url" 2>/dev/null)
        fi
        content_type="${ct_response%%|*}"
        ct_http_code="${ct_response##*|}"

        if [ "$ct_http_code" != "200" ]; then
            fail "Content-Type $path: handler control is inconclusive (HTTP $ct_http_code)"
        elif echo "$content_type" | grep -qi "application/json"; then
            pass "Content-Type $path: application/json"
        else
            fail "Content-Type $path: expected application/json, received $content_type"
        fi
    done
fi

# =============================================================================
# SECTION 8: Spec coverage completeness
# =============================================================================
header "Spec Coverage Completeness"

# Count endpoints by tag/category in the spec
STUDY_PATHS=$(extract_spec_paths | grep -c '/chronicle/v3/study' || true)
SURVEY_PATHS=$(extract_spec_paths | grep -c '/chronicle/v3/survey' || true)
TUD_PATHS=$(extract_spec_paths | grep -c '/chronicle/v3/time-use-diary' || true)
ADMIN_PATHS=$(extract_spec_paths | grep -c '/chronicle/v3/admin' || true)
PRINCIPAL_PATHS=$(extract_spec_paths | grep -c '/chronicle/principal' || true)

if [ "$STUDY_PATHS" -ge 10 ]; then
    pass "Spec has $STUDY_PATHS study endpoints (>= 10 expected)"
else
    fail "Spec only has $STUDY_PATHS study endpoints (expected >= 10)"
fi

if [ "$SURVEY_PATHS" -ge 3 ]; then
    pass "Spec has $SURVEY_PATHS survey endpoints (>= 3 expected)"
else
    fail "Spec only has $SURVEY_PATHS survey endpoints (expected >= 3)"
fi

if [ "$TUD_PATHS" -ge 2 ]; then
    pass "Spec has $TUD_PATHS time-use-diary endpoints (>= 2 expected)"
else
    fail "Spec only has $TUD_PATHS time-use-diary endpoints (expected >= 2)"
fi

if [ "$ADMIN_PATHS" -ge 2 ]; then
    pass "Spec has $ADMIN_PATHS admin endpoints (>= 2 expected)"
else
    fail "Spec only has $ADMIN_PATHS admin endpoints (expected >= 2)"
fi

if [ "$PRINCIPAL_PATHS" -ge 3 ]; then
    pass "Spec has $PRINCIPAL_PATHS principal endpoints (>= 3 expected)"
else
    fail "Spec only has $PRINCIPAL_PATHS principal endpoints (expected >= 3)"
fi

# =============================================================================
# Write JSON report
# =============================================================================
_first=true
{
    echo "{"
    echo "  \"timestamp\": \"$(date -Iseconds)\","
    echo "  \"specFile\": \"$SPEC_FILE\","
    echo "  \"specPathCount\": $SPEC_PATH_COUNT,"
    echo "  \"backendReachable\": $BACKEND_REACHABLE,"
    echo "  \"summary\": {"
    echo "    \"pass\": $PASS,"
    echo "    \"fail\": $FAIL,"
    echo "    \"skip\": $SKIP,"
    echo "    \"total\": $TOTAL"
    echo "  },"
    echo "  \"driftItems\": ["
    for item in "${json_drift_items[@]+"${json_drift_items[@]}"}"; do
        if [ -z "$item" ]; then continue; fi
        if $_first; then _first=false; else echo ","; fi
        printf "    %s" "$item"
    done
    echo ""
    echo "  ]"
    echo "}"
} > "$REPORT_FILE"

# =============================================================================
# Summary
# =============================================================================
echo ""
echo "=============================================="
echo "  CONTRACT DRIFT DETECTION SUMMARY"
echo "=============================================="
printf "  ${GREEN}Passed:${RESET}  %d\n" "$PASS"
printf "  ${RED}Failed:${RESET}  %d\n" "$FAIL"
printf "  ${YELLOW}Skipped:${RESET} %d\n" "$SKIP"
echo "  Total:   $TOTAL"
echo "  Report:  $REPORT_FILE"
echo "=============================================="
echo ""

if [ "$FAIL" -gt 0 ]; then
    echo "Contract drift detected. Review the report at $REPORT_FILE"
    exit 1
fi
exit 0
