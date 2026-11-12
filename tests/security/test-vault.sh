#!/usr/bin/env bash
# =============================================================================
# Chronicle Vault Security Verification
# =============================================================================
# Tests HashiCorp Vault container (chronicle-vault) for correct configuration,
# seal status, audit logging, policy enforcement, and secret engine setup.
#
# Usage:
#   ./tests/security/test-vault.sh
#
# Environment:
#   VAULT_TOKEN  — (optional) Vault token for secret read verification
# =============================================================================
set -euo pipefail


PASS=0
FAIL=0
SKIP=0
WARN=0

# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------
log()  { echo -e "\033[1;34m[VAULT]\033[0m $*"; }
pass() { echo -e "\033[1;32m[PASS]\033[0m $*"; PASS=$((PASS + 1)); }
fail() { echo -e "\033[1;31m[FAIL]\033[0m $*"; FAIL=$((FAIL + 1)); }
skip() { echo -e "\033[1;33m[SKIP]\033[0m $*"; SKIP=$((SKIP + 1)); }
warn() { echo -e "\033[1;35m[WARN]\033[0m $*"; WARN=$((WARN + 1)); }

# =============================================================================
# Pre-check: Vault container running
# =============================================================================
log "Pre-check: verifying chronicle-vault container is running"

if ! docker ps --format '{{.Names}}' 2>/dev/null | grep '^chronicle-vault$' >/dev/null; then
  skip "chronicle-vault container is not running — skipping all Vault tests"
  echo ""
  echo "=============================================="
  echo "  VAULT SECURITY SUMMARY"
  echo "=============================================="
  echo -e "  \033[32mPassed:\033[0m  $PASS"
  echo -e "  \033[31mFailed:\033[0m  $FAIL"
  echo -e "  \033[35mWarned:\033[0m  $WARN"
  echo -e "  \033[33mSkipped:\033[0m $SKIP"
  echo "=============================================="
  exit 0
fi

log "chronicle-vault container is running"

# =============================================================================
# Test 1: Vault Status (initialized and unsealed)
# =============================================================================
log "Test 1: Vault status — initialized and unsealed"

VAULT_STATUS=$(docker exec chronicle-vault vault status -format=json 2>/dev/null) || true

if [ -z "$VAULT_STATUS" ]; then
  fail "Test 1: unable to retrieve Vault status"
else
  INITIALIZED=$(echo "$VAULT_STATUS" | python3 -c "import sys,json; print(json.load(sys.stdin).get('initialized', False))" 2>/dev/null || echo "false")
  SEALED=$(echo "$VAULT_STATUS" | python3 -c "import sys,json; print(json.load(sys.stdin).get('sealed', True))" 2>/dev/null || echo "true")

  if [ "$INITIALIZED" = "True" ]; then
    pass "Test 1a: Vault is initialized"
  else
    fail "Test 1a: Vault is NOT initialized"
  fi

  if [ "$SEALED" = "False" ]; then
    pass "Test 1b: Vault is unsealed"
  else
    warn "Test 1b: Vault is SEALED — requires unseal before secrets can be accessed"
  fi
fi

# =============================================================================
# Test 2: Health Endpoint
# =============================================================================
log "Test 2: Health endpoint — HTTP 200 with initialized=true"

HEALTH_RESPONSE=$(docker exec chronicle-vault wget -q -O- http://127.0.0.1:8200/v1/sys/health 2>/dev/null) || true

if [ -z "$HEALTH_RESPONSE" ]; then
  fail "Test 2: health endpoint returned no response"
else
  HEALTH_INIT=$(echo "$HEALTH_RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin).get('initialized', False))" 2>/dev/null || echo "false")
  if [ "$HEALTH_INIT" = "True" ]; then
    pass "Test 2: health endpoint reports initialized=true"
  else
    fail "Test 2: health endpoint reports initialized=$HEALTH_INIT"
  fi
fi

# =============================================================================
# Test 3: Secret Read Verification (requires VAULT_TOKEN)
# =============================================================================
log "Test 3: Secret read verification — chronicle/database"

if [ -n "${VAULT_TOKEN:-}" ]; then
  SECRET_OUTPUT=$(docker exec -e VAULT_TOKEN="$VAULT_TOKEN" chronicle-vault \
    vault kv get -format=json chronicle/database 2>/dev/null) || true

  if [ -z "$SECRET_OUTPUT" ]; then
    fail "Test 3: unable to read secret at chronicle/database"
  else
    HAS_PASSWORD=$(echo "$SECRET_OUTPUT" | python3 -c "
import sys, json
data = json.load(sys.stdin)
keys = list(data.get('data', {}).get('data', data.get('data', {})).keys())
print('true' if 'password' in keys else 'false')
" 2>/dev/null || echo "false")

    if [ "$HAS_PASSWORD" = "true" ]; then
      pass "Test 3: chronicle/database secret exists with 'password' key"
    else
      fail "Test 3: chronicle/database secret missing 'password' key"
    fi
  fi
else
  skip "Test 3: VAULT_TOKEN not set — provide VAULT_TOKEN env var to verify secret reads"
fi

# =============================================================================
# Test 4: Audit Log Existence
# =============================================================================
log "Test 4: Audit logging — at least one audit backend enabled"

if [ -n "${VAULT_TOKEN:-}" ]; then
  AUDIT_OUTPUT=$(docker exec -e VAULT_TOKEN="$VAULT_TOKEN" chronicle-vault \
    vault audit list -format=json 2>/dev/null) || true

  if [ -z "$AUDIT_OUTPUT" ]; then
    warn "Test 4: unable to list audit backends (may require elevated permissions)"
  else
    AUDIT_COUNT=$(echo "$AUDIT_OUTPUT" | python3 -c "
import sys, json
data = json.load(sys.stdin)
print(len(data))
" 2>/dev/null || echo "0")

    if [ "$AUDIT_COUNT" -gt 0 ] 2>/dev/null; then
      pass "Test 4: $AUDIT_COUNT audit backend(s) enabled"
    else
      warn "Test 4: no audit backends enabled — Vault operations are not being logged"
    fi
  fi
else
  skip "Test 4: VAULT_TOKEN not set — cannot check audit backends"
fi

# =============================================================================
# Test 5: Policy Enforcement (invalid token rejected)
# =============================================================================
log "Test 5: Policy enforcement — invalid token must be rejected"

INVALID_TOKEN="s.INVALID_TOKEN_FOR_TESTING_$(date +%s)"
POLICY_OUTPUT=$(docker exec -e VAULT_TOKEN="$INVALID_TOKEN" chronicle-vault \
  vault token lookup -format=json 2>&1) || true

if echo "$POLICY_OUTPUT" | grep -i "permission denied\|403\|bad token\|missing client token" >/dev/null; then
  pass "Test 5: invalid token correctly rejected (permission denied)"
else
  fail "Test 5: invalid token was NOT rejected — possible misconfiguration"
fi

# =============================================================================
# Test 6: Secret Engine Verification (chronicle/ KV path)
# =============================================================================
log "Test 6: Secret engine — chronicle/ KV path exists"

if [ -n "${VAULT_TOKEN:-}" ]; then
  SECRETS_LIST=$(docker exec -e VAULT_TOKEN="$VAULT_TOKEN" chronicle-vault \
    vault secrets list -format=json 2>/dev/null) || true

  if [ -z "$SECRETS_LIST" ]; then
    fail "Test 6: unable to list secret engines (may require elevated permissions)"
  else
    HAS_CHRONICLE=$(echo "$SECRETS_LIST" | python3 -c "
import sys, json
data = json.load(sys.stdin)
paths = list(data.keys())
print('true' if 'chronicle/' in paths else 'false')
" 2>/dev/null || echo "false")

    if [ "$HAS_CHRONICLE" = "true" ]; then
      pass "Test 6: chronicle/ KV secret engine is mounted"
    else
      fail "Test 6: chronicle/ KV secret engine NOT found in secrets list"
    fi
  fi
else
  skip "Test 6: VAULT_TOKEN not set — cannot verify secret engines"
fi

# =============================================================================
# Summary
# =============================================================================
echo ""
echo "=============================================="
echo "  VAULT SECURITY SUMMARY"
echo "=============================================="
echo -e "  \033[32mPassed:\033[0m  $PASS"
echo -e "  \033[31mFailed:\033[0m  $FAIL"
echo -e "  \033[35mWarned:\033[0m  $WARN"
echo -e "  \033[33mSkipped:\033[0m $SKIP"
TOTAL=$((PASS + FAIL + WARN + SKIP))
echo "  Total:   $TOTAL"
echo "=============================================="
echo ""

if [ "$FAIL" -gt 0 ]; then
  echo "Review failed checks above."
  exit 1
fi
