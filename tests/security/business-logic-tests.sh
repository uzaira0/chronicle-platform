#!/usr/bin/env bash
set -euo pipefail

# ---------------------------------------------------------------------------
# Business Logic Security Tests for Chronicle
# ---------------------------------------------------------------------------
# Validates authorization boundaries: study isolation, privilege escalation
# guards, export downloads, and purge restrictions. A missing fixture or an
# unreachable backend fails: a skipped probe proves nothing.
#
# Required env vars:
#   AUTH_TOKEN        - JWT for a researcher-level user
#   STUDY_A           - UUID of study the researcher HAS access to
#   STUDY_B           - UUID of study the researcher does NOT have access to
#   PARTICIPANT_ID    - participant enrolled in Study B; its owner's export of them succeeds
#
# Optional:
#   BASE_URL          - backend URL (default: http://localhost:40320)
#   ADMIN_STUDY_ID    - study UUID for admin-endpoint tests (defaults to STUDY_A)
# ---------------------------------------------------------------------------

# Use explicit disposable fixtures; an administrator token cannot prove study isolation.
BASE_URL="${BASE_URL:-http://localhost:40320}"
AUTH_TOKEN="${AUTH_TOKEN:-}"
STUDY_A="${STUDY_A:-}"
STUDY_B="${STUDY_B:-}"
PARTICIPANT_ID="${PARTICIPANT_ID:-}"
ADMIN_STUDY_ID="${ADMIN_STUDY_ID:-${STUDY_A:-}}"

# -- Counters ---------------------------------------------------------------
PASS_COUNT=0
FAIL_COUNT=0

# -- Colors -----------------------------------------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
RESET='\033[0m'

# -- Helpers ----------------------------------------------------------------
log()  { printf "${CYAN}[INFO]${RESET}  %s\n" "$*"; }
pass() { PASS_COUNT=$((PASS_COUNT + 1)); printf "${GREEN}[PASS]${RESET}  %s\n" "$*"; }
fail() { FAIL_COUNT=$((FAIL_COUNT + 1)); printf "${RED}[FAIL]${RESET}  %s\n" "$*"; }

# Perform an HTTP request and return the status code.
# Usage: http_status METHOD URL [extra-curl-args...]
http_status() {
    local method="$1" url="$2"
    shift 2
    curl -q --noproxy '*' --connect-timeout 3 --max-time 30 -s -o /dev/null -w "%{http_code}" -X "$method" "$@" "$url" 2>/dev/null || echo "000"
}

# Perform an authenticated HTTP request (uses AUTH_TOKEN).
auth_http_status() {
    local method="$1" url="$2"
    shift 2
    local token_header="$AUTH_TOKEN"
    case "$token_header" in *$'\n'*|*$'\r'*) return 2 ;; esac
    token_header="${token_header//\\/\\\\}"
    token_header="${token_header//\"/\\\"}"
    printf 'header = "Authorization: Bearer %s"\n' "$token_header" |
        http_status "$method" "$url" --config - "$@"
}

# Assert that the returned status matches one of the expected codes.
# Usage: assert_status <test_label> <actual_status> <expected_code> [<expected_code>...]
assert_status() {
    local label="$1" actual="$2"
    shift 2
    for expected in "$@"; do
        if [[ "$actual" == "$expected" ]]; then
            pass "${label} (HTTP ${actual})"
            return
        fi
    done
    fail "${label} — expected HTTP $(IFS=/; echo "$*") but got ${actual}"
}

# ---------------------------------------------------------------------------
# Pre-flight: backend reachability
# ---------------------------------------------------------------------------
log "Checking backend reachability at ${BASE_URL} ..."
health_status=$(http_status GET "${BASE_URL}/chronicle/v3/" 2>/dev/null || echo "000")
if [[ "$health_status" == "000" ]]; then
    fail "Backend at ${BASE_URL} is unreachable"
    exit 1
fi
log "Backend responded with HTTP ${health_status}."

# ---------------------------------------------------------------------------
# Test 1: Study Cross-Contamination
# ---------------------------------------------------------------------------
log "--- Test 1: Study Cross-Contamination ---"
if [[ -z "$AUTH_TOKEN" || -z "$STUDY_A" || -z "$STUDY_B" || "$STUDY_A" == "$STUDY_B" ]]; then
    fail "Test 1: provide an A-only researcher token and two distinct study fixtures"
else
    status=$(auth_http_status GET "${BASE_URL}/chronicle/v3/study/${STUDY_A}/participants")
    assert_status "Test 1a: Same token can read Study A" "$status" "200"
    status=$(auth_http_status GET "${BASE_URL}/chronicle/v3/study/${STUDY_B}/participants")
    assert_status "Test 1b: Same token cannot read Study B" "$status" "403"
fi

# ---------------------------------------------------------------------------
# Test 2: Privilege Escalation
# ---------------------------------------------------------------------------
log "--- Test 2: Privilege Escalation ---"
if [[ -z "$AUTH_TOKEN" || -z "$ADMIN_STUDY_ID" ]]; then
    fail "Test 2: missing AUTH_TOKEN or ADMIN_STUDY_ID"
else
    # Admin controller is at /chronicle/v3/admin — test real endpoints
    status=$(auth_http_status GET "${BASE_URL}/chronicle/v3/admin/event-storage")
    assert_status "Test 2a: GET admin/event-storage with researcher token" "$status" "403"

    status=$(auth_http_status GET "${BASE_URL}/chronicle/v3/admin/reload/cache")
    assert_status "Test 2b: GET admin/reload/cache with researcher token" "$status" "403"
fi


# ---------------------------------------------------------------------------
# Test 4: Unauthorized Export Download
# ---------------------------------------------------------------------------
log "--- Test 4: Unauthorized Export Download ---"
if [[ -z "$AUTH_TOKEN" || -z "$STUDY_B" || -z "$PARTICIPANT_ID" ]]; then
    fail "Test 4: provide AUTH_TOKEN, STUDY_B and its PARTICIPANT_ID"
else
    download="${BASE_URL}/chronicle/v3/study/${STUDY_B}/participants/data?dataType=UsageEvents&participantId=${PARTICIPANT_ID}&responseType=csv"
    status=$(http_status GET "$download")
    assert_status "Test 4a: Export download with no auth token" "$status" "401" "403"
    status=$(printf 'header = "Authorization: Bearer invalid.token.value"\n' | http_status GET "$download" --config -)
    assert_status "Test 4b: Export download with invalid auth token" "$status" "401" "403"
    status=$(auth_http_status GET "$download")
    assert_status "Test 4c: Study B export download with a Study A researcher token" "$status" "403"
fi


# ---------------------------------------------------------------------------
# Test 5: Unauthorized Purge
# ---------------------------------------------------------------------------
log "--- Test 5: Unauthorized Purge ---"
if [[ -z "$AUTH_TOKEN" || -z "$STUDY_B" || -z "$PARTICIPANT_ID" ]]; then
    fail "Test 5: provide AUTH_TOKEN, STUDY_B and its PARTICIPANT_ID"
else
    # A valid body reaches the study permission check instead of request validation.
    status=$(auth_http_status POST \
        "${BASE_URL}/chronicle/v3/study/${STUDY_B}/participants/purge" \
        -H "Content-Type: application/json" \
        -d "{\"participantId\":\"${PARTICIPANT_ID}\",\"confirmationToken\":\"probe\"}")
    assert_status "Test 5: Purge a Study B participant with a Study A researcher token" "$status" "403"
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
printf "\n========================================\n"
printf "  Business Logic Security Test Summary\n"
printf "========================================\n"
printf "  ${GREEN}Passed${RESET}:  %d\n" "$PASS_COUNT"
printf "  ${RED}Failed${RESET}:  %d\n" "$FAIL_COUNT"
printf "========================================\n"

if [[ "$FAIL_COUNT" -gt 0 ]]; then
    exit 1
fi
exit 0
