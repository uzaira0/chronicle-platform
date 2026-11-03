#!/bin/bash
# Chronicle Vault Initialization Script
# Sets up HashiCorp Vault for TDE key management in production.
#
# Usage:
#   ./init-vault.sh --vault-addr <https-url> [--tde-key-file <mode-0600-file>]
#
# Prerequisites:
#   - HashiCorp Vault server running and accessible
#   - vault CLI installed
#   - VAULT_ADDR and VAULT_TOKEN environment variables (or --vault-addr)
#   - Set CHRONICLE_ALLOW_INSECURE_VAULT=true only for local development Vault.
#
# This script:
#   1. Initializes Vault with 5 unseal keys (3 threshold)
#   2. Enables KV v2 secrets engine at the configured mount path
#   3. Stores the TDE principal key in Vault
#   4. Creates a PostgreSQL read-only policy
#   5. Generates a token with that policy

set -euo pipefail

# ── Defaults ──────────────────────────────────────────────────────────────────
VAULT_ADDR="${VAULT_ADDR:-}"
VAULT_MOUNT_PATH="${PG_TDE_VAULT_MOUNT_PATH:-secret}"
TDE_KEY=""
TDE_KEY_FILE="${CHRONICLE_TDE_KEY_FILE:-}"
VAULT_INIT_SHARES=5
VAULT_INIT_THRESHOLD=3
SKIP_INIT=false
CHRONICLE_ALLOW_INSECURE_VAULT="${CHRONICLE_ALLOW_INSECURE_VAULT:-false}"
VAULT_TDE_SERVICE_TOKEN_TTL="${VAULT_TDE_SERVICE_TOKEN_TTL:-8760h}"
VAULT_APPROLE_TOKEN_TTL="${VAULT_APPROLE_TOKEN_TTL:-1h}"
VAULT_APPROLE_TOKEN_MAX_TTL="${VAULT_APPROLE_TOKEN_MAX_TTL:-4h}"
VAULT_APPROLE_SECRET_ID_TTL="${VAULT_APPROLE_SECRET_ID_TTL:-720h}"
VAULT_APPROLE_SECRET_ID_NUM_USES="${VAULT_APPROLE_SECRET_ID_NUM_USES:-0}"

# ── Colors ────────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
NC='\033[0m'

log()      { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"; }
log_ok()   { echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] ${GREEN}OK${NC} $*"; }
log_err()  { echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] ${RED}ERROR${NC} $*" >&2; }
log_warn() { echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] ${YELLOW}WARN${NC} $*"; }
log_step() { echo -e "\n${BOLD}=== Step $1: $2 ===${NC}"; }

usage() {
    echo "Usage: $0 [options]"
    echo ""
    echo "Options:"
    echo "  --vault-addr <url>    Vault address (required, https:// unless CHRONICLE_ALLOW_INSECURE_VAULT=true)"
    echo "  --tde-key-file <path> Read the TDE principal key from a current-owner mode-0600 file"
    echo "  --mount-path <path>   KV v2 mount path (default: secret)"
    echo "  --skip-init           Skip Vault init (use if already initialized)"
    exit 1
}

# ── Parse arguments ───────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --vault-addr)   VAULT_ADDR="$2"; shift 2 ;;
        --tde-key-file) TDE_KEY_FILE="$2"; shift 2 ;;
        --tde-key)      log_err "--tde-key is unsafe because secret values appear in process arguments; use --tde-key-file"; exit 2 ;;
        --mount-path)   VAULT_MOUNT_PATH="$2"; shift 2 ;;
        --skip-init)    SKIP_INIT=true; shift ;;
        --help|-h)      usage ;;
        *)              log_err "Unknown option: $1"; usage ;;
    esac
done

export VAULT_ADDR

if [ -z "$VAULT_ADDR" ]; then
    log_err "Vault address is required. Set VAULT_ADDR or pass --vault-addr https://vault.example.com:8200"
    exit 1
fi

if [[ "$VAULT_ADDR" != https://* && "$CHRONICLE_ALLOW_INSECURE_VAULT" != "true" ]]; then
    log_err "Vault address must use https:// for production: ${VAULT_ADDR}"
    log_err "Set CHRONICLE_ALLOW_INSECURE_VAULT=true only for local development Vault."
    exit 1
fi

# ── Check prerequisites ──────────────────────────────────────────────────────
if ! command -v vault >/dev/null 2>&1; then
    log_err "vault CLI not found. Install from: https://developer.hashicorp.com/vault/install"
    exit 1
fi

log "Vault address: ${VAULT_ADDR}"

# Check Vault connectivity
if ! vault status -format=json >/dev/null 2>&1; then
    # vault status returns exit code 2 when sealed, 1 when not initialized -- both are OK
    VAULT_STATUS_CODE=$?
    if [ "$VAULT_STATUS_CODE" -gt 2 ]; then
        log_err "Cannot reach Vault at ${VAULT_ADDR}"
        exit 1
    fi
fi

# ── Output directory for secrets ──────────────────────────────────────────────
OUTPUT_DIR="./vault-init-output"
mkdir -p "$OUTPUT_DIR"
chmod 700 "$OUTPUT_DIR"

require_private_secret_file() {
    local path="$1"
    local description="$2"
    local mode
    [ -f "$path" ] && [ ! -L "$path" ] || {
        log_err "${description} must be a regular, non-symlink file"
        exit 1
    }
    [ -O "$path" ] || {
        log_err "${description} must be owned by the current operator"
        exit 1
    }
    mode=$(stat -c '%a' "$path" 2>/dev/null || stat -f '%Lp' "$path")
    [ "$mode" = "600" ] || {
        log_err "${description} must have mode 0600"
        exit 1
    }
}

# Serialize shell values to Vault through stdin. Function arguments stay inside this shell;
# child-process arguments contain only the destination path and static program text.
vault_kv_put_pairs() {
    local secret_path="$1"
    shift
    {
        while [ "$#" -gt 0 ]; do
            [ "$#" -ge 2 ] || {
                log_err "vault_kv_put_pairs requires key/value pairs"
                return 1
            }
            printf '%s\0%s\0' "$1" "$2"
            shift 2
        done
    } | python3 -c '
import json
import sys

items = sys.stdin.buffer.read().split(b"\0")
if items and items[-1] == b"":
    items.pop()
if len(items) % 2:
    raise SystemExit("vault_kv_put_pairs received incomplete input")
payload = {
    items[index].decode("utf-8"): items[index + 1].decode("utf-8")
    for index in range(0, len(items), 2)
}
json.dump(payload, sys.stdout)
' | vault kv put "$secret_path" -
}

if [ -n "$TDE_KEY_FILE" ]; then
    require_private_secret_file "$TDE_KEY_FILE" "TDE key input"
    IFS= read -r TDE_KEY < "$TDE_KEY_FILE"
    [ -n "$TDE_KEY" ] || {
        log_err "TDE key input is empty"
        exit 1
    }
fi

# ══════════════════════════════════════════════════════════════════════════════
log_step 1 "Initialize Vault"
# ══════════════════════════════════════════════════════════════════════════════

if [ "$SKIP_INIT" = true ]; then
    log "Skipping Vault initialization (--skip-init)"
else
    INIT_STATUS=$(vault status -format=json 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin).get('initialized', False))" 2>/dev/null || echo "false")

    if [ "$INIT_STATUS" = "True" ] || [ "$INIT_STATUS" = "true" ]; then
        log_warn "Vault is already initialized. Use --skip-init to proceed."
        log_warn "If you need to re-initialize, you must destroy and recreate the Vault storage."
    else
        log "Initializing Vault with ${VAULT_INIT_SHARES} unseal keys, ${VAULT_INIT_THRESHOLD} threshold..."

        INIT_OUTPUT=$(vault operator init \
            -key-shares="${VAULT_INIT_SHARES}" \
            -key-threshold="${VAULT_INIT_THRESHOLD}" \
            -format=json)

        # Extract unseal keys and root token
        for i in $(seq 0 $((VAULT_INIT_SHARES - 1))); do
            KEY=$(echo "$INIT_OUTPUT" | python3 -c "import sys,json; print(json.load(sys.stdin)['unseal_keys_b64'][$i])")
            echo "$KEY" > "${OUTPUT_DIR}/unseal-key-$((i + 1)).txt"
            chmod 600 "${OUTPUT_DIR}/unseal-key-$((i + 1)).txt"
        done

        ROOT_TOKEN=$(echo "$INIT_OUTPUT" | python3 -c "import sys,json; print(json.load(sys.stdin)['root_token'])")
        echo "$ROOT_TOKEN" > "${OUTPUT_DIR}/root-token.txt"
        chmod 600 "${OUTPUT_DIR}/root-token.txt"

        log_ok "Vault initialized"
        log "  Unseal keys written to ${OUTPUT_DIR}/unseal-key-{1..${VAULT_INIT_SHARES}}.txt"
        log "  Root token written to ${OUTPUT_DIR}/root-token.txt"

        # Unseal Vault
        log "Unsealing Vault..."
        for i in $(seq 1 "$VAULT_INIT_THRESHOLD"); do
            vault operator unseal < "${OUTPUT_DIR}/unseal-key-${i}.txt" >/dev/null 2>&1
        done
        log_ok "Vault unsealed"

        export VAULT_TOKEN="$ROOT_TOKEN"
    fi
fi

# Verify Vault is unsealed
SEALED=$(vault status -format=json 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin).get('sealed', True))" 2>/dev/null || echo "true")
if [ "$SEALED" = "True" ] || [ "$SEALED" = "true" ]; then
    log_err "Vault is sealed. Unseal it before continuing."
    exit 1
fi

# Ensure we have a token
if [ -z "${VAULT_TOKEN:-}" ]; then
    if [ -f "${OUTPUT_DIR}/root-token.txt" ]; then
        VAULT_TOKEN=$(cat "${OUTPUT_DIR}/root-token.txt")
        export VAULT_TOKEN
    else
        log_err "VAULT_TOKEN is not set. Export it or provide root-token.txt."
        exit 1
    fi
fi

# ══════════════════════════════════════════════════════════════════════════════
log_step 2 "Enable KV v2 secrets engine"
# ══════════════════════════════════════════════════════════════════════════════

# Check if already enabled
EXISTING_MOUNTS=$(vault secrets list -format=json 2>/dev/null || echo "{}")
if echo "$EXISTING_MOUNTS" | python3 -c "import sys,json; d=json.load(sys.stdin); exit(0 if '${VAULT_MOUNT_PATH}/' in d else 1)" 2>/dev/null; then
    log_warn "Secrets engine already enabled at '${VAULT_MOUNT_PATH}/'"
else
    vault secrets enable -path="${VAULT_MOUNT_PATH}" -version=2 kv
    log_ok "KV v2 secrets engine enabled at '${VAULT_MOUNT_PATH}/'"
fi

# ══════════════════════════════════════════════════════════════════════════════
log_step 3 "Store TDE principal key"
# ══════════════════════════════════════════════════════════════════════════════

if [ -z "$TDE_KEY" ]; then
    log "Generating new TDE principal key..."
    TDE_KEY=$(openssl rand -hex 32)
    log_ok "Generated 256-bit TDE key"
fi

TDE_FINGERPRINT=$(echo -n "$TDE_KEY" | sha256sum | awk '{print $1}')
TDE_CREATED_AT="$(date -Iseconds)"
TDE_DESCRIPTION="Chronicle TDE principal encryption key"
vault_kv_put_pairs "${VAULT_MOUNT_PATH}/chronicle/tde-principal-key" \
    key "$TDE_KEY" \
    fingerprint "$TDE_FINGERPRINT" \
    created_at "$TDE_CREATED_AT" \
    description "$TDE_DESCRIPTION"

log_ok "TDE key stored at ${VAULT_MOUNT_PATH}/chronicle/tde-principal-key"
log "  Key fingerprint: ${TDE_FINGERPRINT}"

# ══════════════════════════════════════════════════════════════════════════════
log_step 4 "Create PostgreSQL read policy"
# ══════════════════════════════════════════════════════════════════════════════

POLICY_NAME="chronicle-tde-read"

vault policy write "$POLICY_NAME" - <<POLICY
# Chronicle TDE Key Read Policy
# Allows the PostgreSQL service to read the TDE principal key
# but not write, delete, or list other secrets.

path "${VAULT_MOUNT_PATH}/data/chronicle/tde-principal-key" {
    capabilities = ["read"]
}

path "${VAULT_MOUNT_PATH}/metadata/chronicle/tde-principal-key" {
    capabilities = ["read"]
}
POLICY

log_ok "Policy '${POLICY_NAME}' created"

# ══════════════════════════════════════════════════════════════════════════════
log_step 5 "Generate service token"
# ══════════════════════════════════════════════════════════════════════════════

SERVICE_TOKEN_OUTPUT=$(vault token create \
    -policy="${POLICY_NAME}" \
    -display-name="chronicle-postgres-tde" \
    -ttl="${VAULT_TDE_SERVICE_TOKEN_TTL}" \
    -format=json)

SERVICE_TOKEN=$(echo "$SERVICE_TOKEN_OUTPUT" | python3 -c "import sys,json; print(json.load(sys.stdin)['auth']['client_token'])")

echo "$SERVICE_TOKEN" > "${OUTPUT_DIR}/pg-tde-service-token.txt"
chmod 600 "${OUTPUT_DIR}/pg-tde-service-token.txt"

log_ok "Service token generated with policy '${POLICY_NAME}'"
log "  Token written to ${OUTPUT_DIR}/pg-tde-service-token.txt"
log "  TTL: ${VAULT_TDE_SERVICE_TOKEN_TTL} -- rotate before expiry"

# ══════════════════════════════════════════════════════════════════════════════
log_step 6 "Seed application secrets"
# ══════════════════════════════════════════════════════════════════════════════

# Prompt for secrets interactively or use environment variables
PROMPT_SECRETS="${PROMPT_SECRETS:-true}"

read_secret() {
    local name="$1"
    local env_var="$2"
    local default="$3"
    local value="${!env_var:-}"

    if [ -n "$value" ]; then
        echo "$value"
        return
    fi

    if [ "$PROMPT_SECRETS" = "true" ] && [ -t 0 ]; then
        read -rsp "  Enter ${name} (or press Enter to generate): " value
        echo >&2
    fi

    if [ -z "$value" ] && [ -n "$default" ]; then
        value="$default"
    elif [ -z "$value" ]; then
        value=$(openssl rand -base64 32)
    fi

    echo "$value"
}

# Database credentials
DB_USER=$(read_secret "database user" "POSTGRES_USER" "chronicle")
DB_PASSWORD=$(read_secret "database password" "POSTGRES_PASSWORD" "")
vault_kv_put_pairs "${VAULT_MOUNT_PATH}/chronicle/database" user "$DB_USER" password "$DB_PASSWORD"
log_ok "Database credentials stored"

# JWT signing secret
JWT_SECRET=$(read_secret "JWT signing secret" "JWT_SECRET" "")
vault_kv_put_pairs "${VAULT_MOUNT_PATH}/chronicle/jwt" secret "$JWT_SECRET"
log_ok "JWT secret stored"

# Hazelcast passwords
HZ_SERVER=$(read_secret "Hazelcast server password" "HAZELCAST_SERVER_PASSWORD" "")
HZ_CLIENT=$(read_secret "Hazelcast client password" "HAZELCAST_CLIENT_PASSWORD" "")
vault_kv_put_pairs "${VAULT_MOUNT_PATH}/chronicle/hazelcast" \
    server-password "$HZ_SERVER" client-password "$HZ_CLIENT"
log_ok "Hazelcast passwords stored"

# SMTP credentials (optional)
if [ -n "${SMTP_HOST:-}" ] || [ "$PROMPT_SECRETS" = "true" ]; then
    SMTP_H=$(read_secret "SMTP host" "SMTP_HOST" "smtp.example.com")
    SMTP_P=$(read_secret "SMTP port" "SMTP_PORT" "587")
    SMTP_U=$(read_secret "SMTP username" "SMTP_USERNAME" "noreply@example.com")
    SMTP_PW=$(read_secret "SMTP password" "SMTP_PASSWORD" "")
    vault_kv_put_pairs "${VAULT_MOUNT_PATH}/chronicle/smtp" \
        host "$SMTP_H" port "$SMTP_P" user "$SMTP_U" password "$SMTP_PW"
    log_ok "SMTP credentials stored"
fi

# Mobile signing secret (optional)
if [ -n "${MOBILE_SIGNING_SECRET:-}" ]; then
    MOBILE_APP_KEY_VALUE="${MOBILE_APP_KEY:-}"
    vault_kv_put_pairs "${VAULT_MOUNT_PATH}/chronicle/mobile" \
        signing-secret "$MOBILE_SIGNING_SECRET" app-key "$MOBILE_APP_KEY_VALUE"
    log_ok "Mobile secrets stored"
fi

# ══════════════════════════════════════════════════════════════════════════════
log_step 7 "Create chronicle-server policy and AppRole"
# ══════════════════════════════════════════════════════════════════════════════

APP_POLICY_NAME="chronicle-server"

vault policy write "$APP_POLICY_NAME" - <<POLICY
# Chronicle Server Application Policy
# Read-only access to application secrets, deny TDE keys (separate policy)

path "${VAULT_MOUNT_PATH}/data/chronicle/database" {
    capabilities = ["read"]
}
path "${VAULT_MOUNT_PATH}/data/chronicle/jwt" {
    capabilities = ["read"]
}
path "${VAULT_MOUNT_PATH}/data/chronicle/smtp" {
    capabilities = ["read"]
}
path "${VAULT_MOUNT_PATH}/data/chronicle/hazelcast" {
    capabilities = ["read"]
}
path "${VAULT_MOUNT_PATH}/data/chronicle/mobile" {
    capabilities = ["read"]
}
path "${VAULT_MOUNT_PATH}/data/chronicle/twilio" {
    capabilities = ["read"]
}
path "${VAULT_MOUNT_PATH}/metadata/chronicle/*" {
    capabilities = ["read", "list"]
}

# Deny TDE keys — managed separately by PostgreSQL
path "${VAULT_MOUNT_PATH}/data/chronicle/tde-principal-key" {
    capabilities = ["deny"]
}
POLICY

log_ok "Policy '${APP_POLICY_NAME}' created"

# Enable AppRole auth method
vault auth enable approle 2>/dev/null || log_warn "AppRole auth already enabled"

vault write auth/approle/role/chronicle-server \
    token_policies="${APP_POLICY_NAME}" \
    token_ttl="${VAULT_APPROLE_TOKEN_TTL}" \
    token_max_ttl="${VAULT_APPROLE_TOKEN_MAX_TTL}" \
    secret_id_ttl="${VAULT_APPROLE_SECRET_ID_TTL}" \
    secret_id_num_uses="${VAULT_APPROLE_SECRET_ID_NUM_USES}"

APPROLE_ROLE_ID=$(vault read -field=role_id auth/approle/role/chronicle-server/role-id)
APPROLE_SECRET_ID=$(vault write -field=secret_id -f auth/approle/role/chronicle-server/secret-id)

echo "$APPROLE_ROLE_ID" > "${OUTPUT_DIR}/approle-role-id.txt"
echo "$APPROLE_SECRET_ID" > "${OUTPUT_DIR}/approle-secret-id.txt"
chmod 600 "${OUTPUT_DIR}/approle-role-id.txt" "${OUTPUT_DIR}/approle-secret-id.txt"

log_ok "AppRole 'chronicle-server' created"
log "  Role ID written to ${OUTPUT_DIR}/approle-role-id.txt"
log "  Secret ID written to ${OUTPUT_DIR}/approle-secret-id.txt"

# ══════════════════════════════════════════════════════════════════════════════
log_step 8 "Generate .env configuration"
# ══════════════════════════════════════════════════════════════════════════════

cat > "${OUTPUT_DIR}/vault-env-snippet.txt" <<ENVEOF
# === Vault-backed TDE (PostgreSQL encryption at rest) ===
PG_TDE_KEY_PROVIDER=vault
PG_TDE_VAULT_URL=${VAULT_ADDR}
PG_TDE_VAULT_TOKEN=${SERVICE_TOKEN}
PG_TDE_VAULT_MOUNT_PATH=${VAULT_MOUNT_PATH}
# PG_TDE_VAULT_CA_PATH=/path/to/vault-ca.pem  # Uncomment for TLS

# === Vault-backed application secrets (chronicle-server) ===
VAULT_ENABLED=true
VAULT_ADDR=${VAULT_ADDR}
VAULT_AUTH_METHOD=approle
VAULT_APP_ROLE_ID=${APPROLE_ROLE_ID}
VAULT_APP_ROLE_SECRET_ID=${APPROLE_SECRET_ID}
# Or use token auth (simpler but less secure):
# VAULT_AUTH_METHOD=token
# VAULT_TOKEN=${SERVICE_TOKEN}
ENVEOF
chmod 600 "${OUTPUT_DIR}/vault-env-snippet.txt"

log_ok "Environment snippet written to ${OUTPUT_DIR}/vault-env-snippet.txt"

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}=========================================="
echo "Vault Initialization Complete"
echo -e "==========================================${NC}"
echo ""
echo "  Vault Address:      ${VAULT_ADDR}"
echo "  Secrets Mount:      ${VAULT_MOUNT_PATH}/"
echo "  TDE Key Path:       ${VAULT_MOUNT_PATH}/chronicle/tde-principal-key"
echo "  TDE Fingerprint:    ${TDE_FINGERPRINT}"
echo ""
echo "  Policies:"
echo "    ${POLICY_NAME}       — PostgreSQL TDE read-only"
echo "    ${APP_POLICY_NAME}   — chronicle-server app secrets"
echo ""
echo "  AppRole: chronicle-server"
echo "    Role ID:   (written to ${OUTPUT_DIR}/approle-role-id.txt)"
echo "    Secret ID: (written to ${OUTPUT_DIR}/approle-secret-id.txt)"
echo ""
echo "  Output files:"
if [ "$SKIP_INIT" != true ]; then
echo "    ${OUTPUT_DIR}/unseal-key-{1..${VAULT_INIT_SHARES}}.txt  (distribute to custodians)"
echo "    ${OUTPUT_DIR}/root-token.txt                (store securely, revoke after setup)"
fi
echo "    ${OUTPUT_DIR}/pg-tde-service-token.txt      (use as PG_TDE_VAULT_TOKEN)"
echo "    ${OUTPUT_DIR}/approle-role-id.txt           (use as VAULT_APP_ROLE_ID)"
echo "    ${OUTPUT_DIR}/approle-secret-id.txt         (use as VAULT_APP_ROLE_SECRET_ID)"
echo "    ${OUTPUT_DIR}/vault-env-snippet.txt         (paste into .env)"
echo ""
echo -e "${YELLOW}IMPORTANT:${NC}"
echo "  1. Distribute unseal keys to different custodians (same as key ceremony)"
echo "  2. Revoke the root token after initial setup: vault token revoke <root-token>"
echo "  3. Set up auto-unseal for production (see docs/KEY-MANAGEMENT-RUNBOOK.md)"
echo "  4. Copy the .env snippet into your production .env file"
echo "  5. Rotate the AppRole secret ID periodically"
echo "  6. Rotate the TDE service token before ${VAULT_TDE_SERVICE_TOKEN_TTL}"
echo ""
