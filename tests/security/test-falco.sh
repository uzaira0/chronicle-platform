#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# Falco Container Runtime Security Verification
# =============================================================================
# Tests that Falco is running, rules are loaded, and detection is working.
# Use --live flag to run active detection tests (shell exec, package install).
# =============================================================================

LIVE=false
for arg in "$@"; do
    case "$arg" in
        --live) LIVE=true ;;
    esac
done

# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

PASS_COUNT=0
FAIL_COUNT=0
SKIP_COUNT=0
WARN_COUNT=0

pass() { PASS_COUNT=$((PASS_COUNT + 1)); echo -e "  ${GREEN}[PASS]${NC} $1"; }
fail() { FAIL_COUNT=$((FAIL_COUNT + 1)); echo -e "  ${RED}[FAIL]${NC} $1"; }
skip() { SKIP_COUNT=$((SKIP_COUNT + 1)); echo -e "  ${YELLOW}[SKIP]${NC} $1"; }
warn() { WARN_COUNT=$((WARN_COUNT + 1)); echo -e "  ${YELLOW}[WARN]${NC} $1"; }
info() { echo -e "  ${CYAN}[INFO]${NC} $1"; }

header() {
    echo ""
    echo -e "${CYAN}--- $1 ---${NC}"
}

# ---------------------------------------------------------------------------
# Pre-check: Falco container must be running
# ---------------------------------------------------------------------------
header "Pre-check: Falco Container"

if ! docker ps --format '{{.Names}}' | grep '^chronicle-falco$' >/dev/null; then
    skip "chronicle-falco container is not running — skipping all tests"
    echo ""
    echo "========================================="
    echo -e " Results: ${YELLOW}SKIP=$SKIP_COUNT${NC}"
    echo "========================================="
    exit 0
fi

pass "chronicle-falco container is running"

# ---------------------------------------------------------------------------
# Test 1: Falco Health
# ---------------------------------------------------------------------------
header "Test 1: Falco Health"

if version_output=$(docker exec chronicle-falco falco --version 2>&1); then
    pass "Falco is responsive: $(echo "$version_output" | sed -n 1p)"
else
    fail "Falco did not return version info"
    info "Output: $version_output"
fi

# ---------------------------------------------------------------------------
# Test 2: Rules Loaded
# ---------------------------------------------------------------------------
header "Test 2: Rules Loaded"

# Check falco.yaml for chronicle-rules.yaml reference
if docker exec chronicle-falco cat /etc/falco/falco.yaml 2>/dev/null | grep 'chronicle-rules' >/dev/null; then
    pass "falco.yaml references chronicle-rules.yaml"
else
    warn "chronicle-rules.yaml not found in falco.yaml rules_file list"
fi

# Check Falco logs for rules loaded message
rules_log=$(docker logs chronicle-falco 2>&1 | grep -i "rules" | tail -5 || true)
if [ -n "$rules_log" ]; then
    pass "Falco logs contain rules-related messages"
    while IFS= read -r line; do
        info "$line"
    done <<< "$rules_log"
else
    warn "No rules-related messages found in Falco logs"
fi

# ---------------------------------------------------------------------------
# Test 3: Shell Exec Detection (--live only)
# ---------------------------------------------------------------------------
header "Test 3: Shell Exec Detection"

if [ "$LIVE" = true ]; then
    if ! docker ps --format '{{.Names}}' | grep '^chronicle-backend$' >/dev/null; then
        skip "chronicle-backend container is not running — cannot test shell detection"
    else
        info "Executing shell in chronicle-backend to trigger Falco alert..."
        docker exec chronicle-backend sh -c 'echo falco-test' >/dev/null 2>&1 || true

        info "Waiting 3 seconds for Falco to process event..."
        sleep 3

        # Check events.json
        shell_event=$(docker exec chronicle-falco cat /var/log/falco/events.json 2>/dev/null | tail -5 || true)
        # Check logs
        shell_log=$(docker logs chronicle-falco 2>&1 | tail -20 | grep -i "shell\|exec" || true)

        if [ -n "$shell_log" ]; then
            pass "Falco detected shell execution in container"
            info "$(echo "$shell_log" | tail -3)"
        elif [ -n "$shell_event" ]; then
            pass "Falco recorded events (check events.json for shell alert)"
            info "$(echo "$shell_event" | tail -2)"
        else
            warn "No shell exec alert detected — rule may not be configured or event not yet flushed"
        fi
    fi
else
    skip "Shell exec detection (requires --live flag)"
fi

# ---------------------------------------------------------------------------
# Test 4: Package Install Detection (--live only)
# ---------------------------------------------------------------------------
header "Test 4: Package Install Detection"

if [ "$LIVE" = true ]; then
    if ! docker ps --format '{{.Names}}' | grep '^chronicle-backend$' >/dev/null; then
        skip "chronicle-backend container is not running — cannot test package manager detection"
    else
        info "Attempting apt-get update in chronicle-backend..."
        apt_output=$(docker exec chronicle-backend apt-get update 2>&1 || true)

        if echo "$apt_output" | grep -i "permission denied\|not allowed\|root" >/dev/null; then
            pass "apt-get blocked by non-root user — security win"
        else
            info "apt-get ran (may or may not have succeeded): $(echo "$apt_output" | sed -n 1p)"
        fi

        info "Waiting 3 seconds for Falco to process event..."
        sleep 3

        pkg_log=$(docker logs chronicle-falco 2>&1 | tail -20 | grep -i "package\|apt\|dpkg\|install" || true)
        if [ -n "$pkg_log" ]; then
            pass "Falco detected package manager activity"
            info "$(echo "$pkg_log" | tail -3)"
        else
            warn "No package manager alert detected — rule may not be configured or container uses non-root user"
        fi
    fi
else
    skip "Package install detection (requires --live flag)"
fi

# ---------------------------------------------------------------------------
# Test 5: Falco JSON Output
# ---------------------------------------------------------------------------
header "Test 5: Falco JSON Output"

# Check json_output in config
if docker exec chronicle-falco cat /etc/falco/falco.yaml 2>/dev/null | grep 'json_output:\s*true' >/dev/null; then
    pass "json_output is enabled in falco.yaml"
else
    yaml_json_line=$(docker exec chronicle-falco cat /etc/falco/falco.yaml 2>/dev/null | grep 'json_output' || true)
    if [ -n "$yaml_json_line" ]; then
        warn "json_output setting found but not set to true: $yaml_json_line"
    else
        warn "json_output not found in falco.yaml"
    fi
fi

# Check events file exists
if docker exec chronicle-falco ls /var/log/falco/events.json >/dev/null 2>&1; then
    pass "Events file exists at /var/log/falco/events.json"
else
    warn "Events file /var/log/falco/events.json does not exist (may not have been created yet)"
fi

# ---------------------------------------------------------------------------
# Test 6: Alert Destination
# ---------------------------------------------------------------------------
header "Test 6: Alert Destination"

# Check that Falco produces stdout output (for Docker logging pipeline)
# --tail: docker reads the end of the log, not a long-running Falco's log from its start.
log_tail=$(docker logs --tail 10 chronicle-falco 2>&1 || true)
if [ -n "$log_tail" ]; then
    pass "Falco is producing stdout output (available via docker logs)"
    info "Latest log line: $(echo "$log_tail" | sed -n '$p')"
else
    warn "No stdout output from Falco — alerts may not reach Docker logging/Loki pipeline"
fi

# Check for configured output channels in falco.yaml
stdout_enabled=$(docker exec chronicle-falco cat /etc/falco/falco.yaml 2>/dev/null | grep -A1 'stdout_output' | grep 'enabled' || true)
if echo "$stdout_enabled" | grep 'true' >/dev/null; then
    pass "stdout_output is enabled in falco.yaml"
elif [ -n "$stdout_enabled" ]; then
    warn "stdout_output found but may not be enabled: $stdout_enabled"
else
    info "Could not determine stdout_output setting from falco.yaml"
fi

file_output=$(docker exec chronicle-falco cat /etc/falco/falco.yaml 2>/dev/null | grep -A2 'file_output' | grep 'enabled' || true)
if echo "$file_output" | grep 'true' >/dev/null; then
    pass "file_output is enabled in falco.yaml"
else
    info "file_output not explicitly enabled (events.json may be configured elsewhere)"
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo "========================================="
echo -e " Results: ${GREEN}PASS=$PASS_COUNT${NC}  ${RED}FAIL=$FAIL_COUNT${NC}  ${YELLOW}WARN=$WARN_COUNT${NC}  ${YELLOW}SKIP=$SKIP_COUNT${NC}"
if [ "$LIVE" = false ]; then
    echo -e " ${CYAN}Tip: run with --live for active detection tests${NC}"
fi
echo "========================================="

if [ "$FAIL_COUNT" -gt 0 ]; then
    exit 1
fi
exit 0
