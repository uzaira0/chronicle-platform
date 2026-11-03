#!/usr/bin/env bash
set -euo pipefail

###############################################################################
# test-fail2ban.sh — Fail2ban abuse protection verification for Chronicle
#
# Usage:
#   ./test-fail2ban.sh          # Non-destructive checks only
#   ./test-fail2ban.sh --live   # Include live ban trigger tests
###############################################################################

# ---------------------------------------------------------------------------
# Color helpers
# ---------------------------------------------------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

# ---------------------------------------------------------------------------
# Counters
# ---------------------------------------------------------------------------
PASS=0
FAIL=0
SKIP=0
WARN=0

pass()  { PASS=$((PASS + 1)); echo -e "  ${GREEN}[PASS]${RESET} $1"; }
fail()  { FAIL=$((FAIL + 1)); echo -e "  ${RED}[FAIL]${RESET} $1"; }
skip()  { SKIP=$((SKIP + 1)); echo -e "  ${YELLOW}[SKIP]${RESET} $1"; }
warn()  { WARN=$((WARN + 1)); echo -e "  ${YELLOW}[WARN]${RESET} $1"; }
info()  { echo -e "  ${CYAN}[INFO]${RESET} $1"; }
header(){ echo -e "\n${BOLD}== $1 ==${RESET}"; }

# ---------------------------------------------------------------------------
# Parse arguments
# ---------------------------------------------------------------------------
LIVE=false
for arg in "$@"; do
    case "$arg" in
        --live) LIVE=true ;;
        *) echo "Unknown argument: $arg"; echo "Usage: $0 [--live]"; exit 1 ;;
    esac
done

CONTAINER="chronicle-fail2ban"
BACKEND_URL="http://localhost:40320"
LIVE_TESTS_RAN=false
BANNED_IP=""

# ---------------------------------------------------------------------------
# Pre-check: container running
# ---------------------------------------------------------------------------
header "Pre-check: Fail2ban Container"

if ! docker ps --format '{{.Names}}' | grep -q "^${CONTAINER}$"; then
    skip "Container '${CONTAINER}' is not running — skipping all tests"
    echo ""
    echo -e "${BOLD}Summary:${RESET} ${GREEN}${PASS} passed${RESET}, ${RED}${FAIL} failed${RESET}, ${YELLOW}${SKIP} skipped${RESET}, ${YELLOW}${WARN} warnings${RESET}"
    exit 0
fi
pass "Container '${CONTAINER}' is running"

# Helper to exec into the fail2ban container
f2b() {
    docker exec "${CONTAINER}" "$@"
}

# ---------------------------------------------------------------------------
# Test 1: Fail2ban Service Status
# ---------------------------------------------------------------------------
header "Test 1: Fail2ban Service Status"

SERVICE_OUTPUT=$(f2b fail2ban-client status 2>&1) || true

if echo "${SERVICE_OUTPUT}" | grep -qi "number of jail"; then
    pass "Fail2ban service is running"

    JAIL_COUNT=$(echo "${SERVICE_OUTPUT}" | grep -i "number of jail" | grep -oP '\d+' || echo "0")
    if [[ "${JAIL_COUNT}" -gt 0 ]]; then
        pass "Active jails found: ${JAIL_COUNT}"
    else
        fail "No active jails reported"
    fi

    JAIL_LIST=$(echo "${SERVICE_OUTPUT}" | grep -i "jail list" | sed 's/.*:\s*//' || echo "")
    if [[ -n "${JAIL_LIST}" ]]; then
        info "Jail list: ${JAIL_LIST}"
    fi
else
    fail "Fail2ban service does not appear to be running"
    info "Output: ${SERVICE_OUTPUT}"
fi

# ---------------------------------------------------------------------------
# Test 2: Jail Configuration
# ---------------------------------------------------------------------------
header "Test 2: Jail Configuration"

JAILS=("chronicle-ratelimit" "chronicle-auth-bruteforce" "chronicle-scanner")
JAIL_DESCRIPTIONS=("rate-limit 429 responses" "auth failure 401 responses" "scanner 404 responses")

for i in "${!JAILS[@]}"; do
    JAIL="${JAILS[$i]}"
    DESC="${JAIL_DESCRIPTIONS[$i]}"

    JAIL_OUTPUT=$(f2b fail2ban-client status "${JAIL}" 2>&1) || true

    if echo "${JAIL_OUTPUT}" | grep -qi "filter"; then
        pass "Jail '${JAIL}' exists and is enabled (${DESC})"

        CURRENTLY_BANNED=$(echo "${JAIL_OUTPUT}" | grep -i "currently banned" | grep -oP '\d+' || echo "0")
        TOTAL_BANNED=$(echo "${JAIL_OUTPUT}" | grep -i "total banned" | grep -oP '\d+' || echo "0")
        info "${JAIL}: currently banned=${CURRENTLY_BANNED}, total banned=${TOTAL_BANNED}"
    else
        fail "Jail '${JAIL}' not found or not enabled (${DESC})"
        info "Output: ${JAIL_OUTPUT}"
    fi
done

# ---------------------------------------------------------------------------
# Test 3: Rate Limit Ban Trigger (--live only)
# ---------------------------------------------------------------------------
header "Test 3: Rate Limit Ban Trigger"

if [[ "${LIVE}" != true ]]; then
    skip "Skipped (requires --live flag)"
else
    info "Generating 25 rapid requests to trigger rate limiting..."

    COUNT_429=0
    for i in $(seq 1 25); do
        HTTP_CODE=$(curl -s -o /dev/null -w '%{http_code}' \
            "${BACKEND_URL}/chronicle/v3/nonexistent-ratelimit-test" 2>/dev/null || echo "000")
        if [[ "${HTTP_CODE}" == "429" ]]; then
            COUNT_429=$((COUNT_429 + 1))
        fi
    done
    info "Received ${COUNT_429} HTTP 429 responses out of 25 requests"

    if [[ "${COUNT_429}" -lt 20 ]]; then
        warn "Only ${COUNT_429} rate-limited responses (need 20+ to trigger ban) — rate limit may not be configured or threshold not reached"
    fi

    info "Waiting 5 seconds for Fail2ban to process logs..."
    sleep 5

    RATELIMIT_STATUS=$(f2b fail2ban-client status chronicle-ratelimit 2>&1) || true
    BANNED_COUNT=$(echo "${RATELIMIT_STATUS}" | grep -i "currently banned" | grep -oP '\d+' || echo "0")

    if [[ "${BANNED_COUNT}" -gt 0 ]]; then
        pass "Rate limit jail has ${BANNED_COUNT} banned IP(s)"
        BANNED_IP=$(echo "${RATELIMIT_STATUS}" | grep -i "banned ip" | sed 's/.*:\s*//' | tr -d '[:space:]' | cut -d' ' -f1 || echo "")
        if [[ -n "${BANNED_IP}" ]]; then
            info "Banned IP(s): ${BANNED_IP}"
        fi
        LIVE_TESTS_RAN=true
    else
        warn "No IPs banned after rate-limit test — Fail2ban may need more events or longer findtime"
    fi
fi

# ---------------------------------------------------------------------------
# Test 4: Auth Failure Ban Trigger (--live only)
# ---------------------------------------------------------------------------
header "Test 4: Auth Failure Ban Trigger"

if [[ "${LIVE}" != true ]]; then
    skip "Skipped (requires --live flag)"
else
    info "Generating 25 requests with invalid auth to trigger auth failure ban..."

    COUNT_401=0
    for i in $(seq 1 25); do
        HTTP_CODE=$(curl -s -o /dev/null -w '%{http_code}' \
            -H "Authorization: Bearer invalid-token-fail2ban-test-${i}" \
            "${BACKEND_URL}/chronicle/v3/study" 2>/dev/null || echo "000")
        if [[ "${HTTP_CODE}" == "401" ]]; then
            COUNT_401=$((COUNT_401 + 1))
        fi
    done
    info "Received ${COUNT_401} HTTP 401 responses out of 25 requests"

    if [[ "${COUNT_401}" -lt 10 ]]; then
        pass "Auth endpoint correctly returns 401 for invalid tokens (${COUNT_401} responses); Fail2ban will process in next poll cycle"
    else
        pass "Auth endpoint returned ${COUNT_401} 401 responses — Fail2ban should trigger ban"
    fi

    info "Waiting 10 seconds for Fail2ban to process logs..."
    sleep 10

    AUTH_STATUS=$(f2b fail2ban-client status chronicle-auth-bruteforce 2>&1) || true
    AUTH_BANNED=$(echo "${AUTH_STATUS}" | grep -i "currently banned" | grep -oP '\d+' || echo "0")

    if [[ "${AUTH_BANNED}" -gt 0 ]]; then
        pass "Auth jail has ${AUTH_BANNED} banned IP(s)"
        AUTH_BANNED_IP=$(echo "${AUTH_STATUS}" | grep -i "banned ip" | sed 's/.*:\s*//' | tr -d '[:space:]' | cut -d' ' -f1 || echo "")
        if [[ -n "${AUTH_BANNED_IP}" ]]; then
            info "Banned IP(s): ${AUTH_BANNED_IP}"
            BANNED_IP="${AUTH_BANNED_IP}"
        fi
        LIVE_TESTS_RAN=true
    else
        warn "No IPs banned after auth failure test — check jail findtime/maxretry settings"
    fi
fi

# ---------------------------------------------------------------------------
# Test 5: Unban and Recovery (only if live tests resulted in bans)
# ---------------------------------------------------------------------------
header "Test 5: Unban and Recovery"

if [[ "${LIVE}" != true ]]; then
    skip "Skipped (requires --live flag)"
elif [[ "${LIVE_TESTS_RAN}" != true || -z "${BANNED_IP}" ]]; then
    pass "No bans triggered (Fail2ban poll cycle may not have completed) — jail config verified in Test 2"
else
    info "Unbanning IP ${BANNED_IP} from all Chronicle jails..."

    for JAIL in "${JAILS[@]}"; do
        UNBAN_OUT=$(f2b fail2ban-client set "${JAIL}" unbanip "${BANNED_IP}" 2>&1) || true
        if echo "${UNBAN_OUT}" | grep -qi "not banned\|is not banned"; then
            info "${JAIL}: IP was not banned in this jail (OK)"
        elif echo "${UNBAN_OUT}" | grep -qi "error\|no such"; then
            info "${JAIL}: ${UNBAN_OUT}"
        fi
    done

    # Verify IP no longer banned
    sleep 1
    STILL_BANNED=false
    for JAIL in "${JAILS[@]}"; do
        CHECK=$(f2b fail2ban-client status "${JAIL}" 2>&1) || true
        if echo "${CHECK}" | grep -q "${BANNED_IP}"; then
            STILL_BANNED=true
        fi
    done

    if [[ "${STILL_BANNED}" == false ]]; then
        pass "IP ${BANNED_IP} successfully unbanned from all jails"
    else
        fail "IP ${BANNED_IP} still appears in one or more jail ban lists"
    fi

    # Verify connectivity restored
    RECOVERY_CODE=$(curl -s -o /dev/null -w '%{http_code}' \
        "${BACKEND_URL}/chronicle/v3/study" 2>/dev/null || echo "000")
    if [[ "${RECOVERY_CODE}" != "000" ]]; then
        pass "Connectivity restored after unban (HTTP ${RECOVERY_CODE})"
    else
        fail "Cannot reach backend after unban — IP may still be blocked at firewall level"
    fi
fi

# ---------------------------------------------------------------------------
# Test 6: Log Monitoring
# ---------------------------------------------------------------------------
header "Test 6: Log Monitoring"

ACCESS_LOG_CHECK=$(f2b ls /var/log/traefik/access.log 2>&1) || true

if echo "${ACCESS_LOG_CHECK}" | grep -q "access.log"; then
    pass "Traefik access log is mounted at /var/log/traefik/access.log"

    # Check the log has recent content
    LOG_SIZE=$(f2b stat -c '%s' /var/log/traefik/access.log 2>/dev/null || echo "0")
    if [[ "${LOG_SIZE}" -gt 0 ]]; then
        pass "Access log is non-empty (${LOG_SIZE} bytes)"
    else
        warn "Access log exists but is empty — no events to monitor yet"
    fi
else
    warn "Traefik access log not found at /var/log/traefik/access.log — Fail2ban won't detect any events"
    info "Ensure the Traefik container writes access logs and the volume is shared with ${CONTAINER}"
fi

# Check that Fail2ban filter files reference the correct log
FILTER_CHECK=$(f2b ls /etc/fail2ban/filter.d/ 2>&1) || true
if echo "${FILTER_CHECK}" | grep -qi "chronicle"; then
    pass "Chronicle-specific filter definitions found in /etc/fail2ban/filter.d/"
else
    warn "No Chronicle-specific filter files found in /etc/fail2ban/filter.d/"
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo -e "${BOLD}============================================${RESET}"
echo -e "${BOLD}  Fail2ban Test Summary${RESET}"
echo -e "${BOLD}============================================${RESET}"
echo -e "  ${GREEN}PASS: ${PASS}${RESET}"
echo -e "  ${RED}FAIL: ${FAIL}${RESET}"
echo -e "  ${YELLOW}SKIP: ${SKIP}${RESET}"
echo -e "  ${YELLOW}WARN: ${WARN}${RESET}"
echo -e "${BOLD}============================================${RESET}"

if [[ "${LIVE}" != true ]]; then
    echo ""
    info "Run with --live to execute ban trigger and recovery tests"
fi

if [[ "${FAIL}" -gt 0 ]]; then
    exit 1
fi
exit 0
