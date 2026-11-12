#!/bin/sh
# Chronicle Vault Development Initialization Script
# Seeds development secrets and creates AppRole for the backend service.
#
# This script runs inside the Vault container after dev-mode startup.
# It is NOT for production — production uses ../init-vault.sh with protected inputs.

set -eu
umask 077

export VAULT_ADDR="http://127.0.0.1:8200"
export VAULT_TOKEN="${VAULT_DEV_ROOT_TOKEN_ID:-chronicle-dev-token}"
BOOTSTRAP_DIR="${VAULT_BOOTSTRAP_DIR:-/vault/file/bootstrap}"
mkdir -p "$BOOTSTRAP_DIR"
chmod 700 "$BOOTSTRAP_DIR"

echo "=== Chronicle Vault Dev Init ==="
echo "  Vault address: ${VAULT_ADDR}"

# ── 1. Enable KV v2 at secret/ (dev mode enables it by default, but be explicit) ─
vault secrets list | grep "^secret/" >/dev/null && echo "KV v2 already enabled at secret/" || \
    vault secrets enable -path=secret -version=2 kv

# ── 2. Seed development secrets ─────────────────────────────────────────────

echo "Seeding chronicle/database..."
vault kv put secret/chronicle/database \
    user="chronicle" \
    password="dev-db-password-not-for-production"

echo "Seeding chronicle/jwt..."
vault kv put secret/chronicle/jwt \
    secret="dev-jwt-secret-256bit-minimum-length-for-hs256-signing-algorithm"

echo "Seeding chronicle/smtp..."
vault kv put secret/chronicle/smtp \
    host="smtp.example.com" \
    port="587" \
    user="noreply@example.com" \
    password="dev-smtp-password"

echo "Seeding chronicle/hazelcast..."
vault kv put secret/chronicle/hazelcast \
    server-password="dev-hazelcast-server-pw" \
    client-password="dev-hazelcast-client-pw"

echo "Seeding chronicle/mobile..."
vault kv put secret/chronicle/mobile \
    signing-secret="dev-mobile-signing-secret-base64" \
    app-key="dev-mobile-app-key-hex-string"

echo "Seeding chronicle/twilio..."
vault kv put secret/chronicle/twilio \
    sid="AC-dev-twilio-sid" \
    token="dev-twilio-auth-token" \
    from-phone="+15551234567"

echo "Seeding chronicle/crowdsec..."
vault kv put secret/chronicle/crowdsec \
    bouncer-api-key="dev-crowdsec-bouncer-key"

echo "Seeding chronicle/grafana..."
vault kv put secret/chronicle/grafana \
    admin-password="dev-grafana-admin-pw"

# ── 3. Create policy ─────────────────────────────────────────────────────────

echo "Creating chronicle-server policy..."
vault policy write chronicle-server /vault/policies/chronicle-server-policy.hcl

# ── 4. Enable AppRole auth and create role ────────────────────────────────────

echo "Enabling AppRole auth..."
vault auth list | grep "^approle/" >/dev/null && echo "AppRole already enabled" || \
    vault auth enable approle

echo "Creating chronicle-server AppRole..."
vault write auth/approle/role/chronicle-server \
    token_policies="chronicle-server" \
    token_ttl="1h" \
    token_max_ttl="4h" \
    secret_id_ttl="0" \
    secret_id_num_uses="0"

# Fetch the role ID and create a secret ID
ROLE_ID=$(vault read -field=role_id auth/approle/role/chronicle-server/role-id)
SECRET_ID=$(vault write -field=secret_id -f auth/approle/role/chronicle-server/secret-id)
printf '%s\n' "$ROLE_ID" > "$BOOTSTRAP_DIR/approle-role-id"
printf '%s\n' "$SECRET_ID" > "$BOOTSTRAP_DIR/approle-secret-id"
chmod 600 "$BOOTSTRAP_DIR/approle-role-id" "$BOOTSTRAP_DIR/approle-secret-id"
unset ROLE_ID SECRET_ID

echo ""
echo "=== Development Vault Ready ==="
echo "  AppRole bootstrap credentials were written to protected files in:"
echo "    ${BOOTSTRAP_DIR}"
echo ""
echo "  The development root token remains the caller-supplied container setting;"
echo "  neither it nor the generated AppRole secret is printed to logs."
echo "  Vault UI: http://localhost:8200/ui"
echo "==================================="
