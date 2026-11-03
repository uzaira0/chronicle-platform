#!/usr/bin/env bash
# =============================================================================
# Chronicle HTTP Smoke Tests
#
# Verifies that backend and frontend services are alive and responding to
# HTTP requests with expected status codes. Designed to run after containers
# are built/started (docker compose up) or against any running instance.
#
# Usage:
#   ./scripts/smoke-test.sh                         # defaults: backend=localhost:40320, frontend=localhost:8080
#   ./scripts/smoke-test.sh http://backend:40320    # custom backend URL
#   ./scripts/smoke-test.sh http://backend:40320 http://frontend:8080
#
# Exit codes:
#   0 — all checks passed
#   1 — one or more checks failed
# =============================================================================
set -euo pipefail

# Prerequisites
command -v curl >/dev/null 2>&1 || { echo "ERROR: curl is required but not installed." >&2; exit 1; }

BACKEND_URL="${1:-http://localhost:40320}"
FRONTEND_URL="${2:-http://localhost:8080}"

# Strip trailing slashes
BACKEND_URL="${BACKEND_URL%/}"
FRONTEND_URL="${FRONTEND_URL%/}"

# Keep curl's explicit wildcard and remote exclusions while always bypassing local proxies.
CURL_NO_PROXY="${no_proxy:-${NO_PROXY:-}}"
if [[ "$CURL_NO_PROXY" != '*' ]]; then
  CURL_NO_PROXY="localhost,127.0.0.1,::1,$CURL_NO_PROXY"
fi

PASS=0
FAIL=0
SKIP=0
TOTAL=0

# Colours (disabled when not a terminal)
if [ -t 1 ]; then
  GREEN='\033[0;32m'
  RED='\033[0;31m'
  NC='\033[0m'
else
  GREEN='' RED='' NC=''
fi

# ---------------------------------------------------------------------------
# check_http <label> <url> <acceptable_codes_csv> [expected_body_substring]
#
#   acceptable_codes_csv  e.g. "200" or "200,401,403"
#   expected_body_substring  optional — if set, response body must contain it
# ---------------------------------------------------------------------------
check_http() {
  local label="$1"
  local url="$2"
  local ok_codes="$3"
  local body_substr="${4:-}"
  TOTAL=$((TOTAL + 1))

  # Use --connect-timeout so a down service fails fast
  local http_code body tmp
  tmp=$(mktemp)
  http_code=$(curl -q --noproxy "$CURL_NO_PROXY" -sS --connect-timeout 5 --max-time 15 -o "$tmp" -w '%{http_code}' "$url" 2>/dev/null) || http_code="000"
  body=$(<"$tmp")
  rm -f "$tmp"

  # Check status code against acceptable list
  local code_ok=false
  IFS=',' read -ra codes <<< "$ok_codes"
  for c in "${codes[@]}"; do
    if [[ "$http_code" == "$c" ]]; then
      code_ok=true
      break
    fi
  done

  # Check body substring if provided
  local body_ok=true
  if [[ -n "$body_substr" ]] && ! echo "$body" | grep -qF "$body_substr"; then
    body_ok=false
  fi

  if $code_ok && $body_ok; then
    printf "${GREEN}[PASS]${NC} %-50s HTTP %s\n" "$label" "$http_code"
    PASS=$((PASS + 1))
  else
    if ! $code_ok; then
      printf "${RED}[FAIL]${NC} %-50s HTTP %s (expected %s)\n" "$label" "$http_code" "$ok_codes"
    else
      printf "${RED}[FAIL]${NC} %-50s body missing: %s\n" "$label" "$body_substr"
    fi
    FAIL=$((FAIL + 1))
  fi
}

# ---------------------------------------------------------------------------
# check_not_status <label> <url> <bad_codes_csv>
#
# Passes if the response code is NOT in the bad list (and not 000 / unreachable).
# Useful for "anything but 5xx" checks.
# ---------------------------------------------------------------------------
check_not_status() {
  local label="$1"
  local url="$2"
  local bad_codes="$3"
  TOTAL=$((TOTAL + 1))

  local tmp http_code
  tmp=$(mktemp)
  http_code=$(curl -q --noproxy "$CURL_NO_PROXY" -sS --connect-timeout 5 --max-time 15 -o "$tmp" -w '%{http_code}' "$url" 2>/dev/null) || http_code="000"
  rm -f "$tmp"

  if [[ "$http_code" == "000" ]]; then
    printf "${RED}[FAIL]${NC} %-50s unreachable\n" "$label"
    FAIL=$((FAIL + 1))
    return
  fi

  local is_bad=false
  IFS=',' read -ra codes <<< "$bad_codes"
  for c in "${codes[@]}"; do
    if [[ "$http_code" == "$c" ]]; then
      is_bad=true
      break
    fi
  done

  if $is_bad; then
    printf "${RED}[FAIL]${NC} %-50s HTTP %s (must not be %s)\n" "$label" "$http_code" "$bad_codes"
    FAIL=$((FAIL + 1))
  else
    printf "${GREEN}[PASS]${NC} %-50s HTTP %s\n" "$label" "$http_code"
    PASS=$((PASS + 1))
  fi
}

# =============================================================================
#  Main
# =============================================================================
printf "Chronicle HTTP Smoke Tests\n"
printf "  backend:  %s\n" "$BACKEND_URL"
printf "  frontend: %s\n\n" "$FRONTEND_URL"

# ---- Backend liveness / dependency readiness ----
check_http       "backend: /chronicle/internal/health/live"  "$BACKEND_URL/chronicle/internal/health/live"  "204"
check_http       "backend: /chronicle/internal/health/ready" "$BACKEND_URL/chronicle/internal/health/ready" "204"
check_http       "backend: /prometheus/ (no scraper auth)"   "$BACKEND_URL/prometheus/"                    "401"

# ---- Backend API endpoints ----
# Unauthenticated requests to protected endpoints should get 401/403, NOT 500/502/503.
# A 5xx here means the service is broken; 4xx means auth is enforced (correct).
check_not_status "backend: /chronicle/v3/study (no auth)"  "$BACKEND_URL/chronicle/v3/study"     "500,502,503,504"
check_not_status "backend: /chronicle/v4/study (no auth)"  "$BACKEND_URL/chronicle/v4/study"     "500,502,503,504"

# Legacy status endpoint (v2) — should not 5xx

# Auth token endpoint — exists and is not erroring
check_not_status "backend: /chronicle/auth/token"          "$BACKEND_URL/chronicle/auth/token"   "500,502,503,504"

# ---- Frontend ----
check_http       "frontend: /health"                       "$FRONTEND_URL/health"                "200"
check_http       "frontend: / serves HTML"                 "$FRONTEND_URL/"                      "200"       "<html"

# ---- Summary ----
printf "\n"
printf "Results: %d total, %d passed, %d failed, %d skipped\n" "$TOTAL" "$PASS" "$FAIL" "$SKIP"

if (( FAIL > 0 )); then
  printf "\nSmoke tests FAILED.\n"
  exit 1
fi

printf "\nAll smoke tests passed.\n"
exit 0
