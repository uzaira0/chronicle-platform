#!/usr/bin/env bash
# rotate-tde-principal-key.sh — Rotate the Chronicle TDE principal (master) key.
#
# The TDE principal key is the master key that wraps pg_tde's per-table internal
# keys. Rotating it creates a NEW key version under the active key provider and
# sets it as the principal key. pg_tde then RE-WRAPS the existing internal keys
# under the new principal key — this is a metadata-only operation: it does NOT
# re-encrypt table data and requires no downtime or full-table rewrite.
#
# Provider selection mirrors docker/init-db-encryption.sh:
#   PG_TDE_KEY_PROVIDER=vault  -> provider "chronicle-vault"      (HashiCorp Vault)
#   PG_TDE_KEY_PROVIDER=file   -> provider "chronicle-file-vault" (file keyring; dev/test)
#   (anything else defaults to the file provider)
#
# When the active provider is Vault, the rotated_at field of the Vault metadata at
# secret/chronicle/tde-principal-key is also updated.
#
# Usage:
#   ./scripts/rotate-tde-principal-key.sh            # rotate now
#   ./scripts/rotate-tde-principal-key.sh --dry-run  # print SQL/actions, change nothing
#
# Environment (read from CHRONICLE_ENV_FILE, then docker/.env.production.local
# when present, then legacy docker/.env, falling back to the process environment),
# mirroring deploy.sh / init-db-encryption.sh:
#   POSTGRES_USER, POSTGRES_DB, POSTGRES_PASSWORD  — DB connection
#   PG_TDE_KEY_PROVIDER                            — file | vault
#   PG_TDE_VAULT_URL, PG_TDE_VAULT_TOKEN, PG_TDE_VAULT_MOUNT_PATH — Vault (if vault)
#   PG_CONTAINER                                   — postgres container (default chronicle-postgres)
#
# Pre-requisites:
#   - docker (the Postgres container must be running)
#   - vault CLI (only when PG_TDE_KEY_PROVIDER=vault, for the metadata update)
#   - Run from the repository root (or the script's parent dir)

set -euo pipefail

# Preserve process-environment compatibility inputs only as unexported shell fallbacks.
# Do this before dirname, pwd, stat, grep, or any other helper can inherit the deployment
# credentials. The fallbacks are cleared as soon as their protected local copies are read.
AMBIENT_POSTGRES_PASSWORD="${POSTGRES_PASSWORD-}"
AMBIENT_PG_TDE_VAULT_TOKEN="${PG_TDE_VAULT_TOKEN-}"
export -n POSTGRES_PASSWORD PG_TDE_VAULT_TOKEN 2>/dev/null || true
unset POSTGRES_PASSWORD PG_TDE_VAULT_TOKEN

umask 077

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
ENV_FILE="$REPO_ROOT/docker/.env"
if [[ -n "${CHRONICLE_ENV_FILE:-}" ]]; then
  ENV_FILE="$CHRONICLE_ENV_FILE"
elif [[ -f "$REPO_ROOT/docker/.env.production.local" ]]; then
  ENV_FILE="$REPO_ROOT/docker/.env.production.local"
fi
CHRONICLE_ALLOW_INSECURE_VAULT="${CHRONICLE_ALLOW_INSECURE_VAULT:-false}"

DRY_RUN=false

# ── Argument parsing ────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run) DRY_RUN=true; shift ;;
    -h|--help)
      sed -n '2,/^$/{ s/^# //; s/^#$//; p }' "$0"
      exit 0
      ;;
    *) echo "Unknown option: $1" >&2; exit 1 ;;
  esac
done

# ── Helpers ─────────────────────────────────────────────────────────
log()  { printf '\033[1;34m[rotate-tde]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[warn]\033[0m %s\n'        "$*" >&2; }
err()  { printf '\033[1;31m[error]\033[0m %s\n'       "$*" >&2; exit 1; }

file_mode() {
  stat -c '%a' "$1" 2>/dev/null || stat -f '%Lp' "$1" 2>/dev/null
}

require_private_file() {
  local path="$1" description="$2" mode
  [[ -f "$path" && ! -L "$path" ]] || err "$description must be a regular, non-symlink file: $path"
  mode="$(file_mode "$path")" || err "Could not inspect permissions for $description: $path"
  [[ "$mode" == "600" ]] || err "$description must have mode 0600 (found $mode): $path"
  [[ -O "$path" ]] || err "$description must be owned by the current user: $path"
}

# Read a value from docker/.env, falling back to the current environment.
# Mirrors the env_val helper in rotate-secrets.sh but env-aware.
env_or_file() {
  local key="$1" default="${2:-}" val=""
  if [[ -f "$ENV_FILE" ]]; then
    val="$(grep -E "^${key}=" "$ENV_FILE" | head -1 | cut -d= -f2- || true)"
  fi
  if [[ -z "$val" ]]; then
    case "$key" in
      POSTGRES_PASSWORD) val="$AMBIENT_POSTGRES_PASSWORD" ;;
      PG_TDE_VAULT_TOKEN) val="$AMBIENT_PG_TDE_VAULT_TOKEN" ;;
      *) val="${!key:-}" ;;
    esac
  fi
  if [[ -z "$val" ]]; then
    val="$default"
  fi
  printf '%s' "$val"
}

# ── Resolve configuration ───────────────────────────────────────────
if [[ -f "$ENV_FILE" ]]; then
  require_private_file "$ENV_FILE" "Chronicle environment file"
fi
PG_CONTAINER="$(env_or_file PG_CONTAINER chronicle-postgres)"
POSTGRES_USER="$(env_or_file POSTGRES_USER postgres)"
POSTGRES_DB="$(env_or_file POSTGRES_DB chronicle)"
POSTGRES_PASSWORD_FILE="$(env_or_file POSTGRES_PASSWORD_FILE)"
if [[ -n "$POSTGRES_PASSWORD_FILE" ]]; then
  require_private_file "$POSTGRES_PASSWORD_FILE" "Postgres password file"
  POSTGRES_PASSWORD="$(<"$POSTGRES_PASSWORD_FILE")"
else
  POSTGRES_PASSWORD="$(env_or_file POSTGRES_PASSWORD)"
fi
unset AMBIENT_POSTGRES_PASSWORD
PG_TDE_KEY_PROVIDER="$(env_or_file PG_TDE_KEY_PROVIDER file)"
if [[ "$PG_TDE_KEY_PROVIDER" != vault ]]; then
  unset AMBIENT_PG_TDE_VAULT_TOKEN
fi

# Select the active provider exactly as init-db-encryption.sh does.
case "$PG_TDE_KEY_PROVIDER" in
  vault) KEY_PROVIDER="chronicle-vault" ;;
  *)     KEY_PROVIDER="chronicle-file-vault" ;;
esac

KEY_NAME_BASE="chronicle-principal-key"
NEW_KEY_NAME="${KEY_NAME_BASE}-$(date +%Y%m%d%H%M%S)"

log "TDE key provider: ${PG_TDE_KEY_PROVIDER} (provider name: ${KEY_PROVIDER})"
log "New principal key version: ${NEW_KEY_NAME}"

# Keep database credentials and SQL out of the host and container process argv.
# The first protected input line becomes PGPASSWORD inside the container; psql
# consumes the remaining lines as SQL from stdin.
SQL_INPUT_DIR="$REPO_ROOT/docker/.env-backups"
declare -a PRIVATE_INPUTS=()
cleanup_private_inputs() {
  local input
  for input in "${PRIVATE_INPUTS[@]}"; do
    [[ -n "$input" && -f "$input" ]] && rm -f -- "$input"
  done
  return 0
}
trap cleanup_private_inputs EXIT

new_private_input() {
  local _target_name="$1" _created_path
  mkdir -p "$SQL_INPUT_DIR"
  [[ -d "$SQL_INPUT_DIR" && ! -L "$SQL_INPUT_DIR" && -O "$SQL_INPUT_DIR" ]] \
    || err "TDE input directory must be a current-user-owned, non-symlink directory: $SQL_INPUT_DIR"
  chmod 700 "$SQL_INPUT_DIR"
  _created_path="$(mktemp "$SQL_INPUT_DIR/.tde-rotation-input.XXXXXX")"
  chmod 600 "$_created_path"
  PRIVATE_INPUTS+=("$_created_path")
  printf -v "$_target_name" '%s' "$_created_path"
}

run_sql() {
  local sql="$1" input
  new_private_input input
  {
    printf '%s\n' "$POSTGRES_PASSWORD"
    printf '%s\n' "$sql"
  } > "$input"
  docker exec -i "$PG_CONTAINER" sh -ceu '
    IFS= read -r PGPASSWORD
    export PGPASSWORD
    exec psql -v ON_ERROR_STOP=1 -h 127.0.0.1 -U "$1" -d "$2"
  ' sh "$POSTGRES_USER" "$POSTGRES_DB" < "$input"
  rm -f -- "$input"
}

# ── Rotation SQL ────────────────────────────────────────────────────
# Create a new principal-key version under the active provider, then set it as
# THE principal key. Setting the key re-wraps the existing internal keys under
# the new principal key (metadata-only; no full-table re-encryption).
ROTATE_SQL="SELECT pg_tde_create_key_using_database_key_provider('${NEW_KEY_NAME}', '${KEY_PROVIDER}');
SELECT pg_tde_set_key_using_database_key_provider('${NEW_KEY_NAME}', '${KEY_PROVIDER}');"

# ── Vault metadata update (vault provider only) ─────────────────────
update_vault_metadata() {
  local mount_path vault_addr vault_token vault_token_file kv_path
  mount_path="$(env_or_file PG_TDE_VAULT_MOUNT_PATH secret)"
  vault_addr="$(env_or_file PG_TDE_VAULT_URL)"
  vault_token_file="$(env_or_file PG_TDE_VAULT_TOKEN_FILE)"
  if [[ -n "$vault_token_file" ]]; then
    require_private_file "$vault_token_file" "Vault token file"
    vault_token="$(<"$vault_token_file")"
  else
    vault_token="$(env_or_file PG_TDE_VAULT_TOKEN)"
  fi
  unset AMBIENT_PG_TDE_VAULT_TOKEN
  kv_path="${mount_path}/chronicle/tde-principal-key"

  [[ -n "$vault_addr" ]]  || err "PG_TDE_VAULT_URL is required to update Vault metadata"
  [[ -n "$vault_token" ]] || err "PG_TDE_VAULT_TOKEN is required to update Vault metadata"
  if [[ "$vault_addr" != https://* && "$CHRONICLE_ALLOW_INSECURE_VAULT" != "true" ]]; then
    err "PG_TDE_VAULT_URL must use https:// for Vault metadata updates"
  fi

  if $DRY_RUN; then
    log "[dry-run] Would update Vault metadata at ${kv_path}:"
    log "[dry-run]   vault kv patch ${kv_path} rotated_at=<now> rotated_key=${NEW_KEY_NAME}"
    return
  fi

  if ! command -v vault >/dev/null 2>&1; then
    warn "vault CLI not found — skipping Vault metadata update at ${kv_path}"
    warn "Record the rotation manually: rotated_at + rotated_key=${NEW_KEY_NAME}"
    return
  fi

  # Mirror how init-vault.sh writes this secret (rotated_at uses date -Iseconds,
  # same format as init-vault.sh's created_at). kv patch preserves existing
  # fields (key/fingerprint/created_at) while adding the rotation marker.
  VAULT_ADDR="$vault_addr" VAULT_TOKEN="$vault_token" \
    vault kv patch "$kv_path" \
      rotated_at="$(date -Iseconds)" \
      rotated_key="$NEW_KEY_NAME" \
      >/dev/null \
    || err "Failed to update Vault metadata at ${kv_path}"

  log "Updated Vault metadata at ${kv_path} (rotated_at, rotated_key=${NEW_KEY_NAME})"
}

# ── Execute ─────────────────────────────────────────────────────────
if $DRY_RUN; then
  log "[dry-run] Would execute the following against ${PG_CONTAINER} (db: ${POSTGRES_DB}):"
  log "[dry-run] --- rotate principal key ---"
  printf '%s\n' "$ROTATE_SQL"
  if [[ "$PG_TDE_KEY_PROVIDER" == "vault" ]]; then
    update_vault_metadata
  fi
  log "[dry-run] No changes made."
  exit 0
fi

[[ -n "$POSTGRES_PASSWORD" ]] || err "POSTGRES_PASSWORD is not set (checked $ENV_FILE and environment)"

log "Rotating TDE principal key..."
run_sql "$ROTATE_SQL" || err "Failed to rotate TDE principal key — principal key UNCHANGED"
log "New principal key '${NEW_KEY_NAME}' created and set under provider '${KEY_PROVIDER}'"
log "Internal keys re-wrapped under the new principal key (no table re-encryption)"

if [[ "$PG_TDE_KEY_PROVIDER" == "vault" ]]; then
  update_vault_metadata
fi

log ""
log "=== TDE principal key rotation complete ==="
log "  Provider:        ${KEY_PROVIDER}"
log "  New key version: ${NEW_KEY_NAME}"
log "Next steps:"
log "  1. Verify the principal key:  docker exec ${PG_CONTAINER} psql -U ${POSTGRES_USER} -d ${POSTGRES_DB} -c 'SELECT * FROM pg_tde_key_info();'"
log "  2. Record the rotation in the key-management log"
