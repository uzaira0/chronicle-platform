#!/bin/bash
# =============================================================================
# Shared helpers for Chronicle security test scripts
# =============================================================================
# Source this file at the top of test scripts:
#   source "$(dirname "${BASH_SOURCE[0]}")/lib-test-helpers.sh"
# =============================================================================

# Resolve paths
_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
_PROJECT_ROOT="$(cd "$_LIB_DIR/../.." && pwd)"

# --- ANSI colors (shared across all test scripts) ---
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[1;36m'; RESET='\033[0m'

# --- Test counters ---
PASS_COUNT=0; FAIL_COUNT=0; SKIP_COUNT=0

pass()  { PASS_COUNT=$((PASS_COUNT + 1));  echo -e "  ${GREEN}[PASS]${RESET} $*"; }
fail()  { FAIL_COUNT=$((FAIL_COUNT + 1));  echo -e "  ${RED}[FAIL]${RESET} $*"; }
skip()  { SKIP_COUNT=$((SKIP_COUNT + 1));  echo -e "  ${YELLOW}[SKIP]${RESET} $*"; }
warn()  { echo -e "  ${YELLOW}[WARN]${RESET} $*"; }
section() { echo -e "\n${CYAN}=== $* ===${RESET}"; }

print_summary() {
    local name="${1:-Test}"
    echo ""
    echo "=============================================="
    echo "  $name SUMMARY"
    echo "=============================================="
    echo -e "  ${GREEN}Passed:${RESET}  $PASS_COUNT"
    echo -e "  ${RED}Failed:${RESET}  $FAIL_COUNT"
    echo -e "  ${YELLOW}Skipped:${RESET} $SKIP_COUNT"
    echo "  ──────────────────────────────"
    echo "  Total:   $((PASS_COUNT + FAIL_COUNT + SKIP_COUNT)) assertions"
    echo "=============================================="
}

# --- Environment auto-detection ---

# Auto-detect BASE_URL from running backend or .env DOMAIN
detect_base_url() {
    if [ -n "${BASE_URL:-}" ]; then echo "$BASE_URL"; return 0; fi
    local domain
    domain=$(grep '^DOMAIN=' "$_PROJECT_ROOT/docker/.env" 2>/dev/null | cut -d= -f2-)
    if curl -sf --max-time 3 "http://localhost:40320/chronicle/internal/health/ready" &>/dev/null; then
        echo "http://${domain:-localhost}"
    elif [ -n "$domain" ] && curl -sf --max-time 3 "http://${domain}/chronicle/v3/edm/entity/type" &>/dev/null; then
        echo "http://${domain}"
    else
        echo "http://localhost"
    fi
}

# Auto-detect AUTH_TOKEN from JWT_SECRET in .env
detect_auth_token() {
    if [ -n "${AUTH_TOKEN:-}" ]; then echo "$AUTH_TOKEN"; return 0; fi
    local jwt_secret
    jwt_secret=$(grep '^JWT_SECRET=' "$_PROJECT_ROOT/docker/.env" 2>/dev/null | cut -d= -f2-)
    if [ -n "$jwt_secret" ] && [ -f "$_PROJECT_ROOT/docker/generate-jwt.sh" ]; then
        JWT_SECRET="$jwt_secret" bash "$_PROJECT_ROOT/docker/generate-jwt.sh" 2>/dev/null
    fi
}

# Auto-detect POSTGRES_PASSWORD from .env
detect_pg_password() {
    grep '^POSTGRES_PASSWORD=' "$_PROJECT_ROOT/docker/.env" 2>/dev/null | cut -d= -f2-
}

# Run SQL against chronicle database
run_sql() {
    local sql="$1"
    docker exec chronicle-postgres psql -U chronicle -d chronicle -tAc "$sql" 2>/dev/null
}

# --- CrowdSec whitelist ---

setup_crowdsec_whitelist() {
    if ! docker ps --filter name=chronicle-crowdsec --format '{{.Names}}' 2>/dev/null | grep chronicle-crowdsec >/dev/null; then
        echo "[INFO] CrowdSec not running — skipping whitelist setup"
        return 0
    fi

    local my_ip=""
    my_ip=$(docker exec edge-traefik sh -c "tail -5 /var/log/traefik/access.log 2>/dev/null | grep -oE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | tail -1" 2>/dev/null) || true

    if [ -z "$my_ip" ]; then
        my_ip=$(docker network inspect chronicle_chronicle-internal 2>/dev/null | python3 -c "import json,sys; d=json.load(sys.stdin); print(d[0]['IPAM']['Config'][0]['Gateway'])" 2>/dev/null) || true
    fi

    if [ -z "$my_ip" ]; then
        my_ip="172.30.0.1"
    fi

    if ! docker exec chronicle-crowdsec cscli decisions delete --ip "$my_ip" 2>/dev/null; then
        echo "[WARN] Failed to clear CrowdSec decisions for $my_ip — tests may get 429s" >&2
    fi

    echo "[INFO] Cleared CrowdSec decisions for test runner IP: $my_ip"
}
