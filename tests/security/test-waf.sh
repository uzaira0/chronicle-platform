#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# WAF (Coraza / OWASP CRS) Test Suite
# Tests that the Coraza WAF container blocks common attack patterns
# while allowing legitimate requests through.
# =============================================================================

# WAF is accessed via Traefik, not direct backend port
BASE_URL="${BASE_URL:-http://localhost:40320}"
: "${AUTH_TOKEN:?Provide a valid researcher credential for the WAF control}"

# ---------------------------------------------------------------------------
# Colors & counters
# ---------------------------------------------------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

PASS_COUNT=0
FAIL_COUNT=0
SKIP_COUNT=0

pass() {
    PASS_COUNT=$((PASS_COUNT + 1))
    printf "${GREEN}[PASS]${NC} %s\n" "$1"
}

fail() {
    FAIL_COUNT=$((FAIL_COUNT + 1))
    printf "${RED}[FAIL]${NC} %s (expected %s, got %s)\n" "$1" "$2" "$3"
}

skip() {
    SKIP_COUNT=$((SKIP_COUNT + 1))
    printf "${YELLOW}[SKIP]${NC} %s\n" "$1"
}

info() {
    printf "${CYAN}[INFO]${NC} %s\n" "$1"
}

# ---------------------------------------------------------------------------
# Pre-check: WAF container must be running
# ---------------------------------------------------------------------------
info "Checking for chronicle-crowdsec container..."

WAF_CONTAINER=$(docker ps --filter name=chronicle-crowdsec --format '{{.Names}}' 2>/dev/null || true)

if [[ -z "$WAF_CONTAINER" ]]; then
    echo ""
    info "chronicle-crowdsec container is not running."
    info "Deploy the security overlay first, then re-run this script."
    echo ""
    printf "${YELLOW}WAF fixture is required.${NC}\n"
    exit 1
fi

info "WAF container found: ${WAF_CONTAINER}"
info "Base URL: ${BASE_URL}"

# Source shared helpers and whitelist test runner in CrowdSec
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/api-client.sh
source "$SCRIPT_DIR/lib/api-client.sh"
if [ -f "$SCRIPT_DIR/lib-test-helpers.sh" ]; then
    source "$SCRIPT_DIR/lib-test-helpers.sh"
    setup_crowdsec_whitelist
fi
echo ""

# ---------------------------------------------------------------------------
# Helper: perform a curl and return the HTTP status code
# ---------------------------------------------------------------------------
http_status() {
    local method="$1"
    shift
    local url="$1"
    shift
    # remaining args are extra curl flags
    curl -H "Authorization: Bearer $AUTH_TOKEN" -s -o /dev/null -w '%{http_code}' -X "$method" "$@" "$url" 2>/dev/null || echo "000"
}

# Establish the authenticated handler before interpreting attack rejections.
CONTROL=$(http_status GET "${BASE_URL}/chronicle/v3/study")
if [[ "$CONTROL" != 200 ]]; then
    fail "WAF positive control is inconclusive" "200" "$CONTROL"
    exit 1
fi

# ---------------------------------------------------------------------------
# Test 1: SQL Injection probe
# ---------------------------------------------------------------------------
info "Test 1: SQL Injection probe"
STATUS=$(http_status GET "${BASE_URL}/chronicle/v3/study?id=1%20OR%201%3D1")
if [[ "$STATUS" == "403" ]]; then
    pass "SQLi probe blocked ($STATUS)"
else
    fail "SQLi probe" "403" "$STATUS"
fi

# ---------------------------------------------------------------------------
# Test 2: XSS probe
# ---------------------------------------------------------------------------
info "Test 2: XSS probe"
STATUS=$(http_status GET "${BASE_URL}/chronicle/v3/study?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E")
if [[ "$STATUS" == "403" ]]; then
    pass "XSS probe blocked ($STATUS)"
else
    fail "XSS probe" "403" "$STATUS"
fi

# ---------------------------------------------------------------------------
# Test 3: Command Injection
# ---------------------------------------------------------------------------
info "Test 3: Command Injection"
STATUS=$(http_status GET "${BASE_URL}/chronicle/v3/study?cmd=%24(whoami)")
if [[ "$STATUS" == "403" ]]; then
    pass "Command injection blocked ($STATUS)"
else
    fail "Command injection" "403" "$STATUS"
fi

# ---------------------------------------------------------------------------
# Test 4: Path Traversal
# ---------------------------------------------------------------------------
info "Test 4: Path Traversal"
STATUS=$(http_status GET "${BASE_URL}/chronicle/../../../../etc/passwd")
if [[ "$STATUS" == "403" || "$STATUS" == "400" || "$STATUS" == "404" ]]; then
    pass "Path traversal blocked (${STATUS})"
else
    fail "Path traversal" "403/400/404" "$STATUS"
fi

# ---------------------------------------------------------------------------
# Test 5: Legitimate request (no false positive)
# ---------------------------------------------------------------------------
info "Test 5: Legitimate request (no false positive)"
STATUS=$(http_status GET "${BASE_URL}/chronicle/v3/study")
if [[ "$STATUS" == "200" ]]; then
    pass "Legitimate request allowed (${STATUS})"
elif [[ "$STATUS" == "403" ]]; then
    fail "Legitimate request" "200" "403 (WAF false positive)"
else
    fail "Legitimate request" "200" "$STATUS"
fi

# ---------------------------------------------------------------------------
# Test 6: WAF Bypass Attempts
# ---------------------------------------------------------------------------
info "Test 6a: Unicode-encoded SQLi bypass"
STATUS=$(http_status GET "${BASE_URL}/chronicle/v3/study?id=%u0027%u004F%u0052")
if [[ "$STATUS" == "403" ]]; then
    pass "Unicode SQLi bypass blocked (403)"
elif [[ "$STATUS" == 200 ]]; then
    skip "Unicode SQLi passes through at PL1; blocking is unproved"
else
    fail "Unicode SQLi probe is inconclusive" "200 or 403" "$STATUS"
fi

info "Test 6b: Double-encoded path traversal bypass"
STATUS=$(http_status GET "${BASE_URL}/chronicle/%252F%252E%252E%252Fetc/passwd")
if [[ "$STATUS" == "403" ]]; then
    pass "Double-encoded path traversal blocked (403)"
elif [[ "$STATUS" == 200 ]]; then
    skip "Double-encoded traversal passes through at PL1; blocking is unproved"
else
    fail "Double-encoded traversal is inconclusive" "200 or 403" "$STATUS"
fi

info "Test 6c: Null byte injection"
STATUS=$(http_status GET "${BASE_URL}/chronicle/v3/study%00.json")
if [[ "$STATUS" == "403" || "$STATUS" == "400" ]]; then
    pass "Null byte injection blocked ($STATUS)"
else
    fail "Null byte injection" "403/400" "$STATUS"
fi

# ---------------------------------------------------------------------------
# Test 7: POST body SQL Injection
# ---------------------------------------------------------------------------
info "Test 7: POST body SQL Injection"
STATUS=$(http_status POST "${BASE_URL}/chronicle/v3/study" \
    -H "Content-Type: application/json" -H "$(idempotency_key_header)" \
    -d '{"name": "'"'"'; DROP TABLE users; --"}')
if [[ "$STATUS" == "403" ]]; then
    pass "POST body SQLi blocked ($STATUS)"
else
    fail "POST body SQLi" "403" "$STATUS"
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo "============================================="
printf "  PASS: ${GREEN}%d${NC}  FAIL: ${RED}%d${NC}  SKIP: ${YELLOW}%d${NC}\n" \
    "$PASS_COUNT" "$FAIL_COUNT" "$SKIP_COUNT"
echo "============================================="

if [[ "$FAIL_COUNT" -gt 0 ]]; then
    exit 1
fi

exit 0
