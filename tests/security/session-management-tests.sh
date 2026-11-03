#!/usr/bin/env bash
set -euo pipefail
# shellcheck source=lib/api-client.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib/api-client.sh"

# ---------------------------------------------------------------------------
# Session Management Security Tests for Chronicle
# ---------------------------------------------------------------------------
# Validates JWT lifecycle, cookie attributes, CSRF protections, and token
# handling: expired token rejection, secret rotation, cookie security flags,
# CSRF on state-changing endpoints, token-in-URL prevention, and concurrent
# session documentation.
#
# Required env vars:
#   (none — all have sensible defaults or degrade to SKIP)
#
# Optional:
#   BASE_URL          - backend URL (default: http://localhost:40320)
#   AUTH_TOKEN        - valid JWT for authenticated requests
#   JWT_SECRET        - HS256 signing key (enables crafted-token tests)
#   OLD_JWT_SECRET    - previous signing key (for secret-rotation test)
#   NEW_JWT_SECRET    - current signing key (for secret-rotation test)
# ---------------------------------------------------------------------------

SCRIPT_DIR_SM="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT_SM="$(cd "$SCRIPT_DIR_SM/../.." && pwd)"

# Credentials are explicit inputs; never infer authentication evidence from a local env file.
BASE_URL="${BASE_URL:-http://localhost:40320}"

AUTH_TOKEN="${AUTH_TOKEN:-}"
JWT_SECRET="${JWT_SECRET:-}"
OLD_JWT_SECRET="${OLD_JWT_SECRET:-}"
NEW_JWT_SECRET="${NEW_JWT_SECRET:-}"

# -- Counters ---------------------------------------------------------------
PASS_COUNT=0
FAIL_COUNT=0
SKIP_COUNT=0

# -- Colors -----------------------------------------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

# -- Helpers ----------------------------------------------------------------
log()  { printf "${CYAN}[INFO]${RESET}  %s\n" "$*"; }
pass() { PASS_COUNT=$((PASS_COUNT + 1)); printf "${GREEN}[PASS]${RESET}  %s\n" "$*"; }
fail() { FAIL_COUNT=$((FAIL_COUNT + 1)); printf "${RED}[FAIL]${RESET}  %s\n" "$*"; }
skip() { SKIP_COUNT=$((SKIP_COUNT + 1)); printf "${YELLOW}[SKIP]${RESET}  %s\n" "$*"; }

header() { printf "\n${BOLD}--- %s ---${RESET}\n" "$*"; }

# Perform an HTTP request and return the status code.
http_status() {
    local method="$1" url="$2"
    shift 2
    local status
    status=$(curl --silent --show-error --connect-timeout 3 --max-time 10 -o /dev/null -w "%{http_code}" -X "$method" "$@" "$url" 2>/dev/null) || status=000
    printf '%s' "$status"
}

# Preserve the real fixture identity, issuer, audience and custom claims.
token_payload() {
    AUTH_TOKEN="$AUTH_TOKEN" python3 - <<'PY_CLAIMS'
import base64, json, os
segment = os.environ['AUTH_TOKEN'].split('.')[1]
print(json.dumps(json.loads(base64.urlsafe_b64decode(segment + '=' * (-len(segment) % 4)))))
PY_CLAIMS
}

# A rejection counts only when the otherwise identical control succeeds.
differential_probe() {
    local label="$1" positive="$2" negative="$3"
    if [[ "$positive" == 200 && "$negative" == 401 ]]; then
        pass "$label: valid control accepted and single-variable variant rejected"
    else
        fail "$label: expected valid=200 and rejected=401; got $positive/$negative (throttling is inconclusive)"
    fi
}

# Create an HS256-signed JWT with the given payload JSON and secret.
# Usage: make_jwt <payload_json> <secret>
make_jwt() {
    local payload_json="$1" secret="$2"
    python3 -c "
import hmac, hashlib, base64, json, sys

def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

header = b64url(json.dumps({'alg': 'HS256', 'typ': 'JWT'}, separators=(',',':')).encode())
payload = b64url(json.dumps(json.loads(sys.argv[1]), separators=(',',':')).encode())
signing_input = f'{header}.{payload}'
sig = hmac.new(sys.argv[2].encode(), signing_input.encode(), hashlib.sha256).digest()
print(f'{signing_input}.{b64url(sig)}')
" "$payload_json" "$secret"
}

# ---------------------------------------------------------------------------
# Pre-flight: backend reachability
# ---------------------------------------------------------------------------
log "Checking backend reachability at ${BASE_URL} ..."
health_status=$(http_status GET "${BASE_URL}/chronicle/v3/auth/session" 2>/dev/null || echo "000")
if [[ "$health_status" != "200" ]]; then
    fail "Session endpoint is unreachable or unsuccessful (HTTP ${health_status})"
    
    printf "\n========================================\n"
    printf "  Session Management Test Summary\n"
    printf "========================================\n"
    printf "  ${GREEN}Passed${RESET}:  %d\n" "$PASS_COUNT"
    printf "  ${RED}Failed${RESET}:  %d\n" "$FAIL_COUNT"
    printf "  ${YELLOW}Skipped${RESET}: %d\n" "$SKIP_COUNT"
    printf "========================================\n"
    exit 1
fi
log "Backend responded with HTTP ${health_status}."

# ---------------------------------------------------------------------------
# Test 1: Expired JWT Rejection
# ---------------------------------------------------------------------------
header "Test 1: Expired JWT Rejection"

if [[ -z "$JWT_SECRET" || -z "$AUTH_TOKEN" ]]; then
    fail "Test 1: JWT_SECRET and a valid AUTH_TOKEN are required to isolate expiry"
else
    payloads=$(token_payload | python3 -c '
import json, sys, time
payload = json.load(sys.stdin)
now = int(time.time())
payload["iat"] = now - 180
for expiration in (now + 3600, now - 120):
    print(json.dumps(dict(payload, exp=expiration), separators=(",", ":")))
')
    valid_token=$(make_jwt "${payloads%%$'\n'*}" "$JWT_SECRET")
    expired_token=$(make_jwt "${payloads#*$'\n'}" "$JWT_SECRET")
    protected_url="${BASE_URL}/chronicle/v3/study"
    valid_status=$(http_status GET "$protected_url" -H "Authorization: Bearer ${valid_token}")
    expired_status=$(http_status GET "$protected_url" -H "Authorization: Bearer ${expired_token}")
    differential_probe "Test 1: expiration" "$valid_status" "$expired_status"
fi

# ---------------------------------------------------------------------------
# Test 2: JWT After Secret Rotation
# ---------------------------------------------------------------------------
header "Test 2: JWT After Secret Rotation"

NEW_JWT_SECRET="${NEW_JWT_SECRET:-$JWT_SECRET}"
if [[ -z "$AUTH_TOKEN" || -z "$OLD_JWT_SECRET" || -z "$NEW_JWT_SECRET" ]]; then
    fail "Test 2: a valid AUTH_TOKEN and explicit retired/current signing keys are required"
elif [[ "$OLD_JWT_SECRET" == "$NEW_JWT_SECRET" ]]; then
    fail "Test 2: retired and current signing keys must differ"
else
    rotation_payload=$(token_payload)
    current_token=$(make_jwt "$rotation_payload" "$NEW_JWT_SECRET")
    old_token=$(make_jwt "$rotation_payload" "$OLD_JWT_SECRET")
    protected_url="${BASE_URL}/chronicle/v3/study"
    current_status=$(http_status GET "$protected_url" -H "Authorization: Bearer ${current_token}")
    retired_status=$(http_status GET "$protected_url" -H "Authorization: Bearer ${old_token}")
    differential_probe "Test 2: retired signing key" "$current_status" "$retired_status"
fi

# ---------------------------------------------------------------------------
# Test 3: Cookie Attributes
# ---------------------------------------------------------------------------
header "Test 3: Cookie Attributes"

if [[ -z "$AUTH_TOKEN" ]]; then
    fail "Test 3: AUTH_TOKEN is required to observe an authenticated cookie session"
else
    session_parent="${TMPDIR:-$PROJECT_ROOT_SM/build/operator-test-runs/session-management}"
    mkdir -p "$session_parent"
    session_work=$(mktemp -d "$session_parent/session.XXXXXX")
    trap 'rm -rf -- "$session_work"' EXIT
    cookie_status=$(AUTH_TOKEN="$AUTH_TOKEN" python3 -c 'import json,os; print(json.dumps({"token":os.environ["AUTH_TOKEN"]}))' |
        curl --silent --show-error --connect-timeout 3 --max-time 10           -X POST -H 'Content-Type: application/json' --data-binary @-           -D "$session_work/headers" --cookie-jar "$session_work/cookies" -o "$session_work/body" -w '%{http_code}'           "${BASE_URL}/chronicle/v3/auth/set-cookie" 2>/dev/null) || cookie_status=000
    if [[ "$cookie_status" != 200 ]]; then
        fail "Test 3: authenticated cookie exchange failed (HTTP ${cookie_status})"
    elif python3 - "$session_work/headers" "$session_work/body" <<'PYCOOKIE'
import json,re,sys
from pathlib import Path
try:
    body=json.loads(Path(sys.argv[2]).read_text())
    assert body.get('authenticated') is True
    cookies=[line.split(':',1)[1].strip() for line in Path(sys.argv[1]).read_text().splitlines()
             if line.lower().startswith('set-cookie:')]
    auth=[cookie for cookie in cookies if cookie.startswith('chronicle_auth=')]
    assert len(auth)==1
    parts=[part.strip() for part in auth[0].split(';')]
    assert parts[0].split('=',1)[1]
    flags={part.lower() for part in parts[1:]}
    assert 'httponly' in flags and 'secure' in flags
    assert flags.intersection({'samesite=lax','samesite=strict'})
except (OSError,ValueError,AssertionError):
    raise SystemExit(1)
PYCOOKIE
    then
        pass "Test 3: observed authenticated chronicle_auth cookie has HttpOnly, Secure and SameSite"
    else
        fail "Test 3: authenticated cookie evidence is absent or insecure"
    fi
fi

# ---------------------------------------------------------------------------
# Test 4: CSRF on State-Changing Endpoints
# ---------------------------------------------------------------------------
header "Test 4: CSRF on State-Changing Endpoints"

if [[ "${cookie_status:-000}" != 200 ]]; then
    fail "Test 4: a real cookie session is required"
else
    csrf_token=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("csrfToken", ""))' "$session_work/body")
    protected_url="${BASE_URL}/chronicle/v3/study"
    positive=$(http_status GET "$protected_url" --cookie "$session_work/cookies" -H "X-CSRF-Token: $csrf_token")
    # Invalid study JSON deliberately exercises deserialization without creating data.
    valid=$(http_status POST "$protected_url" --cookie "$session_work/cookies" -H "X-CSRF-Token: $csrf_token" -H "$(idempotency_key_header)" -H 'Content-Type: application/json' --data '{}')
    missing=$(http_status POST "$protected_url" --cookie "$session_work/cookies" -H 'Content-Type: application/json' --data '{}')
    mismatch=$(http_status POST "$protected_url" --cookie "$session_work/cookies" -H 'X-CSRF-Token: mismatched-fixture' -H 'Content-Type: application/json' --data '{}')
    # The resolver rejects a missing/mismatched CSRF header by withholding the cookie JWT.
    if [[ -n "$csrf_token" && "$positive" == 200 && "$valid" == 400 && "$missing" == 401 && "$mismatch" == 401 ]]; then
        pass "Test 4: cookie session reaches validation with matching CSRF; missing and mismatched headers reject authentication"
    else
        fail "Test 4: expected GET=200, valid=400, missing=401, mismatch=401; got $positive/$valid/$missing/$mismatch"
    fi
fi

# ---------------------------------------------------------------------------
# Test 5: Token in URL Prevention
# ---------------------------------------------------------------------------
header "Test 5: Token in URL Prevention"

test_token="${AUTH_TOKEN:-dummy.jwt.token}"
log "Sending request with token as query parameter ?token=..."

url_token_status=$(http_status GET \
    "${BASE_URL}/chronicle/v3/study?token=${test_token}")

if [[ "$url_token_status" == "401" || "$url_token_status" == "403" ]]; then
    pass "Test 5: Token in URL query parameter rejected (HTTP ${url_token_status})"
elif [[ "$url_token_status" == "200" ]]; then
    # Verify it was the query param that authenticated (not a coincidence like a public endpoint)
    no_token_status=$(http_status GET "${BASE_URL}/chronicle/v3/study")
    if [[ "$no_token_status" == "200" ]]; then
        log "Endpoint returns 200 with or without token -- likely a public endpoint."
        skip "Test 5: Endpoint is publicly accessible -- cannot determine if URL token was used"
    else
        fail "Test 5: Token accepted via URL query parameter (HTTP 200) -- tokens should only be in headers or cookies"
    fi
else
    log "Received HTTP ${url_token_status} for query-parameter token."
    fail "Test 5: Cannot prove token rejection from HTTP ${url_token_status}"
fi

# ---------------------------------------------------------------------------
# Test 6: Concurrent Session Handling (Informational)
# ---------------------------------------------------------------------------
header "Test 6: Concurrent Session Handling"

log "Chronicle uses stateless HS256 JWTs for authentication."
log "Multiple valid JWTs can exist simultaneously because:"
log "  - JWTs are self-contained; the backend validates signature + expiry only."
log "  - There is no server-side session store or token revocation list."
log "  - Any token signed with the current JWT_SECRET and not expired is accepted."
log ""
log "Implications:"
log "  - Token revocation requires rotating JWT_SECRET (invalidates ALL tokens)."
log "  - Individual session termination is not possible without a revocation list."
log "  - Short token lifetimes (e.g., 30 min) reduce the window of exposure."
log ""
log "Manual diagnostic tokens generated by docker/generate-jwt.sh default to"
log "15 minutes and are capped at 1 hour unless the script is deliberately changed."
log "The backend-managed access-token default is 15 minutes, with refresh-token"
log "rotation and server-side JWT blocklisting for explicit revocation."

# This test is informational -- no pass/fail.
log "(Informational only -- no pass/fail for this test)"

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
printf "\n========================================\n"
printf "  Session Management Test Summary\n"
printf "========================================\n"
printf "  ${GREEN}Passed${RESET}:  %d\n" "$PASS_COUNT"
printf "  ${RED}Failed${RESET}:  %d\n" "$FAIL_COUNT"
printf "  ${YELLOW}Skipped${RESET}: %d\n" "$SKIP_COUNT"
printf "========================================\n"

if [[ "$FAIL_COUNT" -gt 0 ]]; then
    exit 1
fi
exit 0
