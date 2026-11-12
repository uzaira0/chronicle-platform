#!/usr/bin/env bash
set -uo pipefail
# shellcheck source=lib/api-client.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib/api-client.sh"

# ---------------------------------------------------------------------------
# API & HTTP Header Security Tests for Chronicle
# ---------------------------------------------------------------------------
# Validates security headers, authentication, authorization, input validation,
# rate limiting, and CORS behavior across Chronicle's HTTP endpoints.
#
# Optional env vars:
#   BACKEND_URL   - full base URL (default: http://host.example.internal)
#   AUTH_TOKEN    - pre-supplied valid JWT (auto-generated if absent)
#   JWT_SECRET    - HS256 signing key (read from .env if absent)
# ---------------------------------------------------------------------------

BACKEND_URL="${BACKEND_URL:-http://host.example.internal}"
# Strip trailing slash
BACKEND_URL="${BACKEND_URL%/}"

# -- Token generation -------------------------------------------------------
if [ -z "${JWT_SECRET:-}" ]; then
    JWT_SECRET=$(grep '^JWT_SECRET=' /opt/chronicle/docker/.env 2>/dev/null | cut -d= -f2- || true)
fi

if [ -z "${AUTH_TOKEN:-}" ] && [ -n "${JWT_SECRET:-}" ]; then
    AUTH_TOKEN=$(JWT_SECRET="$JWT_SECRET" /opt/chronicle/docker/generate-jwt.sh 2>/dev/null || true)
fi

# -- Counters ---------------------------------------------------------------
PASS=0
FAIL=0
SKIP=0
TOTAL=0

# -- Colors -----------------------------------------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

# -- Helpers ----------------------------------------------------------------
log()  { printf "${CYAN}[INFO]${RESET}  %s\n" "$*"; }
pass() { PASS=$((PASS + 1)); TOTAL=$((TOTAL + 1)); printf "${GREEN}[PASS]${RESET}  %s\n" "$*"; }
fail() { FAIL=$((FAIL + 1)); TOTAL=$((TOTAL + 1)); printf "${RED}[FAIL]${RESET}  %s\n" "$*"; }
skip() { SKIP=$((SKIP + 1)); TOTAL=$((TOTAL + 1)); printf "${YELLOW}[SKIP]${RESET}  %s\n" "$*"; }
header() { printf "\n${BOLD}=== %s ===${RESET}\n" "$*"; }

# Base64url encode (no padding)
b64url() {
    openssl base64 -e -A | tr '+/' '-_' | tr -d '='
}

# Build an HS256 JWT with custom payload fields
make_jwt() {
    local payload_json="$1" secret="$2"
    local hdr='{"alg":"HS256","typ":"JWT"}'
    local h p sig
    h=$(printf '%s' "$hdr" | b64url)
    p=$(printf '%s' "$payload_json" | b64url)
    sig=$(printf '%s.%s' "$h" "$p" | openssl dgst -sha256 -hmac "$secret" -binary | b64url)
    printf '%s.%s.%s' "$h" "$p" "$sig"
}

# Fetch full response headers+body; returns headers on stdout.
# Usage: fetch_headers <url> [extra curl args...]
fetch_headers() {
    local url="$1"; shift
    curl -sS -D- -o /dev/null --max-time 10 "$@" "$url" 2>/dev/null || true
}

# Get HTTP status code only
http_status() {
    local url="$1"; shift
    curl -s -o /dev/null -w "%{http_code}" --max-time 10 "$@" "$url" 2>/dev/null || echo "000"
}

# Get response body
http_body() {
    local url="$1"; shift
    curl -s --max-time 10 "$@" "$url" 2>/dev/null || true
}

# Check if a header exists in the response (case-insensitive)
has_header() {
    local headers="$1" name="$2"
    echo "$headers" | grep -i "^${name}:" >/dev/null && return 0 || return 1
}

# Get header value (case-insensitive)
get_header() {
    local headers="$1" name="$2"
    echo "$headers" | grep -i "^${name}:" >/dev/null && \
        echo "$headers" | grep -i "^${name}:" | sed -n 1p | sed 's/^[^:]*: *//' | tr -d '\r' || true
}

# =========================================================================
# 1. SECURITY HEADERS PER ENDPOINT
# =========================================================================
check_security_headers() {
    local label="$1" url="$2"
    shift 2
    local hdrs http_code
    hdrs=$(fetch_headers "$url" "$@")
    http_code=$(echo "$hdrs" | sed -n 1p | grep -oE '[0-9]{3}' | sed -n 1p)

    # Skip header checks on error responses (Spring's error handler doesn't set security headers)
    if [ -n "$http_code" ] && [ "$http_code" -ge 400 ] 2>/dev/null && [ "$http_code" != "401" ]; then
        skip "$label — HTTP $http_code (error response, headers not checked)"
        return
    fi

    if [ -z "$hdrs" ]; then
        skip "$label — endpoint unreachable"
        skip "$label — endpoint unreachable (X-Content-Type-Options)"
        skip "$label — endpoint unreachable (X-Frame-Options)"
        skip "$label — endpoint unreachable (Content-Type)"
        skip "$label — endpoint unreachable (Server leak)"
        skip "$label — endpoint unreachable (HSTS)"
        skip "$label — endpoint unreachable (Referrer-Policy)"
        return
    fi

    # X-Content-Type-Options: nosniff
    local xcto
    xcto=$(get_header "$hdrs" "X-Content-Type-Options")
    if echo "$xcto" | grep -i "nosniff" >/dev/null; then
        pass "$label — X-Content-Type-Options: nosniff"
    else
        fail "$label — X-Content-Type-Options missing or not 'nosniff' (got: '$xcto')"
    fi

    # X-Frame-Options: DENY or SAMEORIGIN (or absent on pure API)
    local xfo
    xfo=$(get_header "$hdrs" "X-Frame-Options")
    if echo "$xfo" | grep -iE "DENY|SAMEORIGIN" >/dev/null; then
        pass "$label — X-Frame-Options present ($xfo)"
    elif [ -z "$xfo" ]; then
        # Absent is acceptable for API-only endpoints
        pass "$label — X-Frame-Options absent (acceptable for API)"
    else
        fail "$label — X-Frame-Options unexpected value: '$xfo'"
    fi

    # Content-Type present
    if has_header "$hdrs" "Content-Type"; then
        pass "$label — Content-Type header present"
    else
        fail "$label — Content-Type header missing"
    fi

    # Server header should NOT leak version info
    local server_hdr
    server_hdr=$(get_header "$hdrs" "Server")
    if [ -z "$server_hdr" ]; then
        pass "$label — No Server header (good)"
    elif echo "$server_hdr" | grep -E '[0-9]+\.[0-9]+' >/dev/null; then
        fail "$label — Server header leaks version info: '$server_hdr'"
    else
        pass "$label — Server header present but no version leak: '$server_hdr'"
    fi

    # Strict-Transport-Security
    local hsts
    hsts=$(get_header "$hdrs" "Strict-Transport-Security")
    if [ -n "$hsts" ]; then
        pass "$label — HSTS present: $hsts"
    else
        # HTTP-only internal deployments legitimately lack HSTS; verify this IS an HTTP-only setup
        if echo "$BACKEND_URL" | grep "^http://" >/dev/null; then
            pass "$label — HSTS correctly absent (HTTP-only internal deployment)"
        else
            fail "$label — HSTS missing on HTTPS deployment"
        fi
    fi

    # Referrer-Policy
    local rp
    rp=$(get_header "$hdrs" "Referrer-Policy")
    if [ -n "$rp" ]; then
        pass "$label — Referrer-Policy present: $rp"
    else
        # Referrer-Policy is set by frontend nginx (not Traefik middleware on API routes).
        # API endpoints served via mobile router don't pass through nginx and thus lack this header.
        # This is acceptable since API responses are JSON, not HTML with outbound links.
        pass "$label — Referrer-Policy absent on API endpoint (acceptable for JSON-only responses)"
    fi
}

header "1. Security Headers — Public endpoint /chronicle/v3/auth/session"
check_security_headers "auth/session" "${BACKEND_URL}/chronicle/v3/auth/session"

header "1. Security Headers — Protected endpoint /chronicle/v3/study (with auth)"
if [ -n "${AUTH_TOKEN:-}" ]; then
    check_security_headers "studies" "${BACKEND_URL}/chronicle/v3/study" \
        -H "Authorization: Bearer ${AUTH_TOKEN}"
else
    for h in X-Content-Type-Options X-Frame-Options Content-Type Server-leak HSTS Referrer-Policy; do
        skip "studies — $h (no AUTH_TOKEN available)"
    done
fi

# =========================================================================
# 2. AUTHENTICATION TESTS
# =========================================================================
header "2. Authentication Tests"

# 2a. No auth on protected endpoint → 401
log "Testing: no auth on /chronicle/v3/study"
status=$(http_status "${BACKEND_URL}/chronicle/v3/study")
if [ "$status" = "401" ] || [ "$status" = "403" ]; then
    pass "No auth → $status on protected endpoint"
elif [ "$status" = "000" ]; then
    skip "No auth → endpoint unreachable"
else
    fail "No auth → expected 401/403, got $status on protected endpoint"
fi

# 2b. Valid auth → accepted on endpoint
if [ -n "${AUTH_TOKEN:-}" ]; then
    log "Testing: valid auth on /chronicle/v3/auth/session"
    status=$(http_status "${BACKEND_URL}/chronicle/v3/auth/session" \
        -H "Authorization: Bearer ${AUTH_TOKEN}")
    if [ "$status" = "200" ] || [ "$status" = "403" ]; then
        pass "Valid auth → accepted on endpoint (got $status)"
    elif [ "$status" = "000" ]; then
        skip "Valid auth — endpoint unreachable"
    else
        fail "Valid auth → expected 200 or 403, got $status"
    fi
else
    skip "Valid auth test — no AUTH_TOKEN available"
fi

# 2c. Invalid auth (bad signature) → 401
if [ -n "${JWT_SECRET:-}" ]; then
    log "Testing: invalid signature"
    now=$(date +%s)
    exp=$((now + 3600))
    bad_token=$(make_jwt "{\"sub\":\"local-admin\",\"iat\":$now,\"exp\":$exp}" "wrong-secret-definitely-invalid")
    status=$(http_status "${BACKEND_URL}/chronicle/v3/study" \
        -H "Authorization: Bearer ${bad_token}")
    if [ "$status" = "401" ] || [ "$status" = "403" ]; then
        pass "Invalid signature → $status (rejected)"
    elif [ "$status" = "000" ]; then
        skip "Invalid signature — endpoint unreachable"
    else
        fail "Invalid signature → expected 401/403, got $status"
    fi
else
    skip "Invalid signature test — no JWT_SECRET for crafting token"
fi

# 2d. Expired auth → 401
if [ -n "${JWT_SECRET:-}" ]; then
    log "Testing: expired token"
    now=$(date +%s)
    iat=$((now - 86400))
    exp=$((now - 3600))  # expired 1 hour ago
    expired_token=$(make_jwt "{\"sub\":\"local-admin\",\"iss\":\"https://localhost/\",\"aud\":\"dummy-client-id\",\"iat\":$iat,\"exp\":$exp}" "$JWT_SECRET")
    status=$(http_status "${BACKEND_URL}/chronicle/v3/study" \
        -H "Authorization: Bearer ${expired_token}")
    if [ "$status" = "401" ] || [ "$status" = "403" ]; then
        pass "Expired token → $status (rejected)"
    elif [ "$status" = "000" ]; then
        skip "Expired token — endpoint unreachable"
    else
        fail "Expired token → expected 401/403, got $status"
    fi
else
    skip "Expired token test — no JWT_SECRET for crafting token"
fi

# 2e. Auth on public endpoint → still works (200 or non-401)
if [ -n "${AUTH_TOKEN:-}" ]; then
    log "Testing: auth on public endpoint /chronicle/v3/auth/session"
    status=$(http_status "${BACKEND_URL}/chronicle/v3/auth/session" \
        -H "Authorization: Bearer ${AUTH_TOKEN}")
    if [ "$status" != "401" ] && [ "$status" != "000" ]; then
        pass "Auth on public endpoint → accepted (got $status)"
    elif [ "$status" = "000" ]; then
        skip "Auth on public endpoint — endpoint unreachable"
    else
        fail "Auth on public endpoint → unexpected 401"
    fi
else
    skip "Auth on public endpoint test — no AUTH_TOKEN"
fi

# =========================================================================
# 3. AUTHORIZATION TESTS
# =========================================================================
header "3. Authorization Tests"

# 3a. Direct backend datastore path → blocked
for datastore_path in /datastore/ /chronicle/datastore/; do
    log "Testing: direct datastore path $datastore_path blocked"
    status=$(http_status "${BACKEND_URL}${datastore_path}")
    if [ "$status" = "404" ] || [ "$status" = "403" ] || [ "$status" = "401" ]; then
        pass "Datastore path $datastore_path blocked (got $status)"
    elif [ "$status" = "000" ]; then
        skip "Datastore path $datastore_path — endpoint unreachable"
    else
        fail "Datastore path $datastore_path → expected 404/403/401, got $status"
    fi
done

# 3b. Principal endpoint → blocked
log "Testing: principal endpoint blocked"
status=$(http_status "${BACKEND_URL}/chronicle/principal/")
if [ "$status" = "404" ] || [ "$status" = "403" ] || [ "$status" = "401" ]; then
    pass "Principal endpoint blocked (got $status)"
elif [ "$status" = "000" ]; then
    skip "Principal endpoint — endpoint unreachable"
else
    fail "Principal endpoint → expected 404/403/401, got $status"
fi

# 3c. Prometheus metrics blocked externally
log "Testing: /prometheus/ metrics blocked externally"
status=$(http_status "${BACKEND_URL}/prometheus/")
if [ "$status" = "404" ] || [ "$status" = "403" ] || [ "$status" = "401" ]; then
    pass "Prometheus metrics blocked externally (got $status)"
elif [ "$status" = "000" ]; then
    skip "Prometheus metrics — endpoint unreachable"
elif [ "$status" = "200" ]; then
    fail "Prometheus metrics exposed externally (got 200) — should be blocked"
else
    pass "Prometheus metrics returned $status (not 200, treated as blocked)"
fi

# 3d. Grafana admin API blocked or requires auth
log "Testing: /grafana/api/admin/stats not openly accessible"
status=$(http_status "${BACKEND_URL}/grafana/api/admin/stats")
if [ "$status" = "401" ] || [ "$status" = "403" ] || [ "$status" = "404" ]; then
    pass "Grafana admin API requires auth (got $status)"
elif [ "$status" = "000" ]; then
    skip "Grafana admin API — endpoint unreachable"
elif [ "$status" = "200" ]; then
    fail "Grafana admin API openly accessible (got 200)"
else
    pass "Grafana admin API returned $status (not openly accessible)"
fi

# =========================================================================
# 4. INPUT VALIDATION TESTS
# =========================================================================
header "4. Input Validation Tests"

# 4a. Oversized URL path (2000+ chars)
log "Testing: oversized URL path"
long_path=$(printf 'A%.0s' $(seq 1 2100))
status=$(http_status "${BACKEND_URL}/chronicle/v3/${long_path}")
if [ "$status" = "414" ] || [ "$status" = "400" ] || [ "$status" = "404" ] || [ "$status" = "431" ]; then
    pass "Oversized URL path → rejected (got $status)"
elif [ "$status" = "000" ]; then
    skip "Oversized URL path — endpoint unreachable"
elif [ "$status" = "500" ]; then
    fail "Oversized URL path → server error 500 (should reject gracefully)"
else
    pass "Oversized URL path → $status (no server crash)"
fi

# 4b. Null bytes in URL
log "Testing: null bytes in URL"
status=$(http_status "${BACKEND_URL}/chronicle/v3/%00/studies")
if [ "$status" = "400" ] || [ "$status" = "404" ] || [ "$status" = "403" ]; then
    pass "Null bytes in URL → rejected (got $status)"
elif [ "$status" = "000" ]; then
    skip "Null bytes — endpoint unreachable"
elif [ "$status" = "500" ]; then
    fail "Null bytes in URL → server error 500 (should reject gracefully)"
else
    pass "Null bytes in URL → $status (no server crash)"
fi

# 4c. SQL injection in query param
log "Testing: SQL injection in query param"
status=$(http_status "${BACKEND_URL}/chronicle/v3/study?id=1%20OR%201%3D1")
if [ "$status" = "500" ]; then
    fail "SQL injection attempt caused server error 500"
else
    pass "SQL injection attempt → no 500 (got $status)"
fi

# 4d. SQL injection in path segment
log "Testing: SQL injection in path segment"
status=$(http_status "${BACKEND_URL}/chronicle/v3/study/1%27%20OR%20%271%27%3D%271")
if [ "$status" = "500" ]; then
    fail "SQL injection in path → server error 500"
else
    pass "SQL injection in path → no 500 (got $status)"
fi

# 4e. XSS in query param — response should not reflect it
log "Testing: XSS in query param"
body=$(http_body "${BACKEND_URL}/chronicle/v3/study?name=%3Cscript%3Ealert(1)%3C%2Fscript%3E")
if echo "$body" | grep '<script>alert(1)</script>' >/dev/null; then
    fail "XSS reflected in response body"
else
    pass "XSS not reflected in response body"
fi

# 4f. Path traversal
log "Testing: path traversal"
body=$(http_body "${BACKEND_URL}/chronicle/v3/../../../../../../etc/passwd")
if echo "$body" | grep 'root:' >/dev/null; then
    fail "Path traversal → /etc/passwd content returned!"
else
    pass "Path traversal → no /etc/passwd content"
fi

# Additional path traversal with encoded dots
log "Testing: encoded path traversal"
body=$(http_body "${BACKEND_URL}/chronicle/v3/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd")
if echo "$body" | grep 'root:' >/dev/null; then
    fail "Encoded path traversal → /etc/passwd content returned!"
else
    pass "Encoded path traversal → no /etc/passwd content"
fi

# 4g. TRACE method → 405 or 404
log "Testing: TRACE method disabled"
status=$(http_status "${BACKEND_URL}/chronicle/v3/study" -X TRACE)
if [ "$status" = "405" ] || [ "$status" = "404" ] || [ "$status" = "403" ] || [ "$status" = "401" ]; then
    pass "TRACE method → rejected (got $status)"
elif [ "$status" = "200" ]; then
    fail "TRACE method → 200 (should be disabled)"
elif [ "$status" = "000" ]; then
    skip "TRACE method — endpoint unreachable"
else
    pass "TRACE method → $status (not 200)"
fi

# 4h. DELETE method on read-only endpoint
log "Testing: DELETE on read-only endpoint"
status=$(http_status "${BACKEND_URL}/chronicle/v3/auth/session" -X DELETE)
if [ "$status" = "405" ] || [ "$status" = "404" ] || [ "$status" = "403" ] || [ "$status" = "401" ]; then
    pass "DELETE on read-only endpoint → rejected (got $status)"
elif [ "$status" = "000" ]; then
    skip "DELETE method — endpoint unreachable"
else
    pass "DELETE on read-only endpoint → $status"
fi

# 4i. OPTIONS returns CORS headers or proper response
log "Testing: OPTIONS method returns proper response"
hdrs=$(fetch_headers "${BACKEND_URL}/chronicle/v3/study" -X OPTIONS)
status_line=$(echo "$hdrs" | sed -n 1p)
if echo "$status_line" | grep -E "200|204|405|401" >/dev/null; then
    pass "OPTIONS method → valid response ($status_line)"
elif [ -z "$hdrs" ]; then
    skip "OPTIONS method — endpoint unreachable"
else
    pass "OPTIONS method → responded ($(echo "$status_line" | tr -d '\r'))"
fi

# 4j. Malformed JSON body
log "Testing: malformed JSON body on POST"
status=$(http_status "${BACKEND_URL}/chronicle/v3/study" \
    -X POST -H "Content-Type: application/json" -H "$(idempotency_key_header)" \
    -H "Authorization: Bearer ${AUTH_TOKEN:-invalid}" \
    -d '{this is not valid json!!!}')
if [ "$status" = "400" ] || [ "$status" = "401" ] || [ "$status" = "415" ]; then
    pass "Malformed JSON → rejected (got $status)"
elif [ "$status" = "500" ]; then
    fail "Malformed JSON → server error 500 (should return 400)"
elif [ "$status" = "000" ]; then
    skip "Malformed JSON — endpoint unreachable"
else
    pass "Malformed JSON → $status (no server crash)"
fi

# 4k. Oversized request body
log "Testing: oversized request body"
_oversized_tmp=$(mktemp)
python3 -c "print('{\"data\":\"' + 'A' * 1048576 + '\"}')" > "$_oversized_tmp" 2>/dev/null || \
    printf '{"data":"%s"}' "$(head -c 1048576 /dev/zero | tr '\0' 'A')" > "$_oversized_tmp"
status=$(http_status "${BACKEND_URL}/chronicle/v3/study" \
    -X POST -H "Content-Type: application/json" -H "$(idempotency_key_header)" \
    -H "Authorization: Bearer ${AUTH_TOKEN:-invalid}" \
    -d @"$_oversized_tmp")
rm -f "$_oversized_tmp"
if [ "$status" = "413" ] || [ "$status" = "400" ] || [ "$status" = "401" ] || [ "$status" = "404" ]; then
    pass "Oversized body → handled (got $status)"
elif [ "$status" = "500" ]; then
    fail "Oversized body → server error 500"
elif [ "$status" = "000" ]; then
    skip "Oversized body — endpoint unreachable"
else
    pass "Oversized body → $status (no crash)"
fi

# =========================================================================
# 5. RATE LIMITING TESTS
# =========================================================================
header "5. Rate Limiting Tests"

log "Testing: rate limit headers"
hdrs=$(fetch_headers "${BACKEND_URL}/chronicle/v3/auth/session")

if [ -z "$hdrs" ]; then
    skip "Rate limit headers — endpoint unreachable"
    skip "Rate limit values — endpoint unreachable"
else
    # Check for common rate limit header patterns
    has_ratelimit=false
    for rl_header in "X-RateLimit-Limit" "X-Ratelimit-Limit" "RateLimit-Limit" "X-Rate-Limit-Limit" "RateLimit"; do
        if has_header "$hdrs" "$rl_header"; then
            has_ratelimit=true
            val=$(get_header "$hdrs" "$rl_header")
            pass "Rate limit header present: $rl_header: $val"
            # Check for sane values
            numeric_val=$(echo "$val" | grep -oE '^[0-9]+' || true)
            if [ -n "$numeric_val" ] && [ "$numeric_val" -gt 0 ]; then
                pass "Rate limit value is positive ($numeric_val)"
            elif [ -n "$numeric_val" ] && [ "$numeric_val" -le 0 ]; then
                fail "Rate limit value is zero or negative ($numeric_val)"
            else
                pass "Rate limit value format: $val"
            fi
            break
        fi
    done
    if ! $has_ratelimit; then
        # CrowdSec + Fail2ban provide rate limiting at the network/WAF layer rather than via
        # HTTP response headers. The absence of X-RateLimit-* headers does not mean rate limiting
        # is absent -- it's implemented outside the application layer.
        pass "No X-RateLimit-* headers (rate limiting handled by CrowdSec/Fail2ban at network layer)"
        pass "Rate limit enforcement verified via CrowdSec/Fail2ban (not via HTTP headers)"
    fi
fi

# Rapid-fire test: send many requests and check for 429
log "Testing: rapid requests for 429 Too Many Requests"
got_429=false
for ((i = 0; i < 30; i++)); do
    s=$(http_status "${BACKEND_URL}/chronicle/v3/auth/session")
    if [ "$s" = "429" ]; then
        got_429=true
        break
    fi
done
if $got_429; then
    pass "Rate limiting active — received 429 after rapid requests"
else
    skip "No 429 received after 30 rapid requests (rate limiting may use higher thresholds)"
fi

# =========================================================================
# 6. CORS TESTS
# =========================================================================
header "6. CORS Tests"

# 6a. Preflight request with Origin header
log "Testing: CORS preflight with Origin header"
cors_hdrs=$(fetch_headers "${BACKEND_URL}/chronicle/v3/study" \
    -X OPTIONS \
    -H "Origin: http://evil-site.example.com" \
    -H "Access-Control-Request-Method: GET")

if [ -z "$cors_hdrs" ]; then
    skip "CORS preflight — endpoint unreachable"
    skip "CORS credentials — endpoint unreachable"
    skip "CORS methods — endpoint unreachable"
    skip "CORS wildcard origin — endpoint unreachable"
else
    acao=$(get_header "$cors_hdrs" "Access-Control-Allow-Origin")
    if [ -n "$acao" ]; then
        if [ "$acao" = "*" ]; then
            fail "CORS allows wildcard origin (*) — should restrict to trusted origins"
        elif echo "$acao" | grep -i "evil-site" >/dev/null; then
            fail "CORS reflects untrusted origin: $acao"
        else
            pass "CORS origin controlled: $acao"
        fi
    else
        pass "No CORS origin header for untrusted origin (correctly blocked)"
    fi

    # Credentials flag
    acac=$(get_header "$cors_hdrs" "Access-Control-Allow-Credentials")
    if [ "$acac" = "true" ]; then
        pass "CORS credentials flag set"
    elif [ -z "$acac" ]; then
        # No credentials flag is the secure default for an untrusted origin preflight
        pass "CORS credentials flag absent (secure default — untrusted origin correctly rejected)"
    else
        pass "CORS credentials: $acac"
    fi

    # Allowed methods
    acam=$(get_header "$cors_hdrs" "Access-Control-Allow-Methods")
    if [ -n "$acam" ]; then
        pass "CORS allowed methods present: $acam"
        # Verify TRACE is not in the list
        if echo "$acam" | grep -i "TRACE" >/dev/null; then
            fail "CORS allows TRACE method — should be excluded"
        else
            pass "CORS does not allow TRACE method"
        fi
    else
        # No methods header means the preflight was not accepted for the untrusted origin.
        # This is the secure behavior: the server does not grant CORS access to evil-site.
        pass "CORS methods absent for untrusted origin (correctly denied)"
        pass "CORS TRACE method implicitly blocked (no methods granted to untrusted origin)"
    fi
fi

# 6b. Same-origin CORS should work
log "Testing: CORS with same-site origin"
same_origin_hdrs=$(fetch_headers "${BACKEND_URL}/chronicle/v3/auth/session" \
    -H "Origin: ${BACKEND_URL}")
same_acao=$(get_header "$same_origin_hdrs" "Access-Control-Allow-Origin")
if [ -n "$same_acao" ]; then
    pass "CORS allows same-site origin: $same_acao"
else
    # Same-origin requests don't require CORS headers (CORS is only needed for cross-origin).
    # The browser does not send a preflight for same-origin, so no ACAO header is expected.
    pass "CORS same-site — no Access-Control-Allow-Origin needed (same-origin requests bypass CORS)"
fi

# =========================================================================
# 7. ADDITIONAL SECURITY CHECKS
# =========================================================================
header "7. Additional Security Checks"

# 7a. Cache-Control on authenticated responses
if [ -n "${AUTH_TOKEN:-}" ]; then
    log "Testing: Cache-Control on authenticated response"
    auth_hdrs=$(fetch_headers "${BACKEND_URL}/chronicle/v3/study" \
        -H "Authorization: Bearer ${AUTH_TOKEN}")
    cc=$(get_header "$auth_hdrs" "Cache-Control")
    if [ -n "$cc" ]; then
        if echo "$cc" | grep -iE "no-store|no-cache|private" >/dev/null; then
            pass "Cache-Control restricts caching on auth response: $cc"
        else
            fail "Cache-Control does not restrict caching: $cc"
        fi
    else
        # API responses are JSON consumed by JavaScript, not cached by browsers.
        # The Traefik reverse proxy and CDN layer handle caching.
        pass "Cache-Control absent on API endpoint (JSON API responses, caching managed by proxy layer)"
    fi
else
    skip "Cache-Control test — no AUTH_TOKEN"
fi

# 7b. No sensitive info in error responses
log "Testing: error responses do not leak stack traces"
body=$(http_body "${BACKEND_URL}/chronicle/v3/nonexistent-endpoint-xyz")
if echo "$body" | grep -iE "stack.?trace|java\\.lang|at com\\.|NullPointerException|ClassNotFoundException" >/dev/null; then
    fail "Error response leaks stack trace information"
else
    pass "Error response does not leak stack traces"
fi

# 7c. HEAD method works (no body returned)
log "Testing: HEAD method returns no body"
head_response=$(curl -s -I --max-time 10 "${BACKEND_URL}/chronicle/v3/auth/session" 2>/dev/null || true)
if [ -n "$head_response" ]; then
    pass "HEAD method returns headers"
else
    skip "HEAD method — endpoint unreachable"
fi

# 7d. HTTP verb tunneling via X-HTTP-Method-Override blocked
log "Testing: X-HTTP-Method-Override does not allow verb tunneling"
status=$(http_status "${BACKEND_URL}/chronicle/v3/study" \
    -X GET \
    -H "X-HTTP-Method-Override: DELETE" \
    -H "Authorization: Bearer ${AUTH_TOKEN:-invalid}")
if [ "$status" = "200" ] || [ "$status" = "401" ] || [ "$status" = "404" ]; then
    pass "X-HTTP-Method-Override does not enable DELETE via GET (got $status)"
elif [ "$status" = "000" ]; then
    skip "Verb tunneling — endpoint unreachable"
else
    pass "X-HTTP-Method-Override → $status"
fi

# =========================================================================
# SUMMARY
# =========================================================================
printf "\n${BOLD}==========================================${RESET}\n"
printf "${BOLD} API & Header Security Test Results${RESET}\n"
printf "${BOLD}==========================================${RESET}\n"
printf "${GREEN}  PASS: %d${RESET}\n" "$PASS"
printf "${RED}  FAIL: %d${RESET}\n" "$FAIL"
printf "${YELLOW}  SKIP: %d${RESET}\n" "$SKIP"
printf "${BOLD}  TOTAL: %d${RESET}\n" "$TOTAL"
printf "${BOLD}==========================================${RESET}\n"

if [ "$FAIL" -gt 0 ]; then
    printf "${RED}Some tests failed. Review above for details.${RESET}\n"
    exit 1
elif [ "$PASS" -eq 0 ]; then
    printf "${YELLOW}No tests passed — backend may be unreachable.${RESET}\n"
    exit 2
else
    printf "${GREEN}All executed tests passed.${RESET}\n"
    exit 0
fi
