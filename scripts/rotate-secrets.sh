#!/usr/bin/env bash
# rotate-secrets.sh — Transactional secret rotation for Chronicle production
#
# Rotates selected PostgreSQL, JWT, or Hazelcast credentials and recreates their
# dependents. A failed health/credential check restores the prior authority.
#
# Usage:
#   ./scripts/rotate-secrets.sh --only JWT_SECRET
#   ./scripts/rotate-secrets.sh --auto --only POSTGRES_PASSWORD
#   ./scripts/rotate-secrets.sh --dry-run      # preview the supported inventory
#   ./scripts/rotate-secrets.sh --only <name>  # PostgreSQL, JWT or Hazelcast password
# Live batch/Grafana/CrowdSec/TDE rotations are refused before any side effect;
# use their dedicated coordinated recovery procedures.
#
# Secrets that CANNOT be auto-rotated by THIS script (require external coordination):
#   PG_TDE_VAULT_TOKEN    — Vault AUTH token, issued by the external Vault cluster
#   SMTP_PASSWORD         — managed by the email provider (Office 365 admin)
#
# The TDE principal KEY itself IS rotatable (distinct from PG_TDE_VAULT_TOKEN
# above): rotate it via scripts/rotate-tde-principal-key.sh, invoked here by the
# rotate_tde_principal_key helper. It creates a new principal-key version under
# the active pg_tde provider and re-wraps the internal keys (no table rewrite).
# This transaction script only previews that helper in --dry-run mode.
#
# Pre-requisites:
#   - openssl, docker, docker compose
#   - Run from the repository root (or the script's parent dir)
#   - The docker stack must be running for service-level rotations (Postgres, CrowdSec, Grafana)

set -euo pipefail
umask 077

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
ENV_FILE="${CHRONICLE_ENV_FILE:-$REPO_ROOT/docker/.env}"
COMPOSE_FILE="$REPO_ROOT/docker/docker-compose.traefik.yml"
BACKUP_DIR="${CHRONICLE_ROTATION_BACKUP_DIR:-$REPO_ROOT/docker/.env-backups}"
SECRET_DIR="$REPO_ROOT/docker/secrets"
TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"

DRY_RUN=false
AUTO=false
ONLY=""

# ── Argument parsing ────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run) DRY_RUN=true; shift ;;
    --auto)    AUTO=true; shift ;;
    --only)    ONLY="$2"; shift 2 ;;
    -h|--help)
      sed -n '2,/^$/{ s/^# //; s/^#$//; p }' "$0"
      exit 0
      ;;
    *) echo "Unknown option: $1" >&2; exit 1 ;;
  esac
done

# ── Helpers ─────────────────────────────────────────────────────────
log()  { printf '\033[1;34m[rotate]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[warn]\033[0m %s\n'   "$*" >&2; }
err()  { printf '\033[1;31m[error]\033[0m %s\n'   "$*" >&2; exit 1; }

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

declare -a PRIVATE_FILES=()
cleanup_private_files() {
  local path
  for path in "${PRIVATE_FILES[@]}"; do
    [[ -n "$path" && -f "$path" ]] && rm -f -- "$path"
  done
  return 0
}
rotation_committed=false
postgres_changed=false
finish_rotation() {
  local status=$?
  if ! $DRY_RUN && [[ "$rotation_committed" != true && -n "${ENV_BACKUP:-}" ]]; then
    rollback_rotation || { warn "Automatic rollback failed; retain the protected rotation backup for recovery"; status=1; }
  fi
  cleanup_private_files
  return "$status"
}
trap finish_rotation EXIT

new_private_file() {
  local _target_name="$1" _created_path
  _created_path="$(mktemp "$BACKUP_DIR/.rotation-secret.XXXXXX")"
  chmod 600 "$_created_path"
  PRIVATE_FILES+=("$_created_path")
  printf -v "$_target_name" '%s' "$_created_path"
}

generate_secret_file() {
  local target_var="$1" encoding="$2" bytes="$3" generated raw
  new_private_file generated
  case "$encoding" in
    base64)
      new_private_file raw
      openssl rand -out "$raw" "$bytes"
      openssl base64 -A -in "$raw" -out "$generated"
      rm -f -- "$raw"
      ;;
    hex)
      openssl rand -hex -out "$generated" "$bytes"
      ;;
    *) err "Unsupported secret encoding: $encoding" ;;
  esac
  require_private_file "$generated" "generated secret"
  printf -v "$target_var" '%s' "$generated"
}

prepare_secret_file() {
  local target_var="$1" encoding="$2" bytes="$3"
  if $DRY_RUN; then
    printf -v "$target_var" ''
  else
    generate_secret_file "$target_var" "$encoding" "$bytes"
  fi
}

confirm() {
  if $AUTO; then return 0; fi
  if [[ ! -t 0 ]]; then
    err "Non-interactive stdin detected. Use --auto for unattended rotation or run from a terminal."
  fi
  printf '\033[1;33m%s [y/N] \033[0m' "$1"
  read -r ans
  [[ "$ans" =~ ^[Yy] ]]
}

# Read current value of an env var from the .env file
env_val() { grep -E "^${1}=" "$ENV_FILE" | head -1 | cut -d= -f2-; }

# Replace a value in .env atomically without putting it in process arguments.
env_set() {
  local key="$1" secret_file="$2" length tmp_file
  if $DRY_RUN; then
    log "[dry-run] Would set $key=<redacted>"
    return
  fi
  require_private_file "$secret_file" "$key replacement secret"
  length="$(wc -c < "$secret_file" | tr -d '[:space:]')"
  tmp_file="$(mktemp "$ENV_FILE.tmp.XXXXXX")"
  chmod 600 "$tmp_file"
  PRIVATE_FILES+=("$tmp_file")
  if ! python3 - "$ENV_FILE" "$key" "$secret_file" "$tmp_file" <<'PY'
import pathlib
import sys

env_path, key, secret_path, output_path = map(pathlib.Path, sys.argv[1:])
secret = secret_path.read_text(encoding="utf-8").rstrip("\r\n")
if not secret or "\n" in secret or "\r" in secret:
    raise SystemExit("replacement secret must be one non-empty line")
prefix = f"{key}="
lines = env_path.read_text(encoding="utf-8").splitlines(keepends=True)
found = False
rewritten = []
for line in lines:
    if line.startswith(prefix) and not found:
        ending = "\n" if line.endswith("\n") else ""
        rewritten.append(f"{prefix}{secret}{ending}")
        found = True
    else:
        rewritten.append(line)
if not found:
    raise SystemExit(f"{key} is missing from the environment file")
pathlib.Path(output_path).write_text("".join(rewritten), encoding="utf-8")
PY
  then
    err "Failed writing $key to $ENV_FILE — original file unchanged"
  fi
  chmod 600 "$tmp_file"
  mv -- "$tmp_file" "$ENV_FILE"
  grep -qE "^${key}=" "$ENV_FILE" \
    || err "$key not found in $ENV_FILE after write"
  case "$key" in
    POSTGRES_PASSWORD|JWT_SECRET|HAZELCAST_SERVER_PASSWORD|HAZELCAST_CLIENT_PASSWORD)
      local authority="$SECRET_DIR/${key,,}" saved="$BACKUP_DIR/${key,,}.before"
      if [[ ! -e "$saved" ]]; then
        require_private_file "$authority" "$key authoritative secret"
        install -m 0600 "$authority" "$saved"
      fi
      # A bind mount keeps its old inode until recreation; install first, then recreate.
      install -m 0600 "$secret_file" "$authority"
      ;;
  esac
  log "Rotated $key ($length chars)"
}

dc() { CHRONICLE_ENV_FILE="$ENV_FILE" docker compose --env-file "$ENV_FILE" -f "$COMPOSE_FILE" "$@"; }

postgres_stdin() {
  local input="$1"
  shift
  docker exec -i chronicle-postgres sh -ceu '
    IFS= read -r PGPASSWORD || [ -n "$PGPASSWORD" ]; export PGPASSWORD
    pg_user=$1 pg_db=$2
    shift 2
    exec psql -v ON_ERROR_STOP=1 --set=role_name="$pg_user" -h 127.0.0.1 -U "$pg_user" -d "$pg_db" "$@"
  ' sh "$(env_val POSTGRES_USER)" "$(env_val POSTGRES_DB)" "$@" < "$input"
}

write_postgres_password_payload() {
  python3 - "$@" <<'PY'
import pathlib
import sys

env_arg, new_arg, output_arg, candidate = sys.argv[1:]
old = next((line.split(b"=", 1)[1] for line in pathlib.Path(env_arg).read_bytes().splitlines()
            if line.startswith(b"POSTGRES_PASSWORD=")), None)
new = pathlib.Path(new_arg).read_bytes().rstrip(b"\r\n") if candidate != "old" else old
if old is None or (candidate == "rotate" and (
        not old or not new or b"'" in new or b"\n" in new or b"\r" in new)):
    raise SystemExit("invalid Postgres password rotation input")
alter = b"ALTER ROLE :\"role_name\" WITH PASSWORD "
if candidate == "rotate":
    payload = old + b"\n\\set new_password '" + new + b"'\n" + alter + b":'new_password';\n"
else:
    quoted = old.replace(b"'", b"''")
    payload = new + b"\n" + alter + b"'" + quoted + b"';\n"
pathlib.Path(output_arg).write_bytes(payload)
PY
}

# ── Pre-flight ──────────────────────────────────────────────────────
if ! $DRY_RUN; then
  case "$ONLY" in
    POSTGRES_PASSWORD|JWT_SECRET|HAZELCAST_SERVER_PASSWORD|HAZELCAST_CLIENT_PASSWORD) ;;
    *) err "Transactional rotation requires --only POSTGRES_PASSWORD, JWT_SECRET, or HAZELCAST_*_PASSWORD. Other credentials require their dedicated coordinated recovery procedures." ;;
  esac
fi
[[ -f "$ENV_FILE" ]] || err "$ENV_FILE not found — run from the repository root"
require_private_file "$ENV_FILE" "Chronicle environment file"

if ! $DRY_RUN; then
  mkdir -p "$BACKUP_DIR"
  [[ -d "$BACKUP_DIR" && ! -L "$BACKUP_DIR" && -O "$BACKUP_DIR" ]] \
    || err "Secret backup directory must be a current-user-owned, non-symlink directory: $BACKUP_DIR"
  chmod 700 "$BACKUP_DIR"
  BACKUP_DIR="$(mktemp -d "$BACKUP_DIR/rotation.$TIMESTAMP.XXXXXX")"
  ENV_BACKUP="$BACKUP_DIR/.env.$TIMESTAMP"
  install -m 0600 "$ENV_FILE" "$ENV_BACKUP"
  log "Backed up .env → $BACKUP_DIR/.env.$TIMESTAMP"
fi

# Do not let ambient copies of old credentials propagate to docker/openssl
# children. Secret values read by this script remain unexported shell data.
export -n POSTGRES_PASSWORD JWT_SECRET GRAFANA_ADMIN_PASSWORD \
  CROWDSEC_BOUNCER_API_KEY HAZELCAST_SERVER_PASSWORD \
  HAZELCAST_CLIENT_PASSWORD MOBILE_SIGNING_SECRET MOBILE_APP_KEY 2>/dev/null || true

# Track which services need restart (keyed by docker compose SERVICE name)
declare -A RESTART_NEEDED

# Restore both authoritative inputs before recreating dependents. Database rollback uses
# protected stdin; neither the old nor the replacement credential is a process argument.
rollback_rotation() {
  local authority saved input candidate rolled_back
  if [[ "${postgres_changed:-false}" == true ]]; then
    rolled_back=false
    # A lost ALTER response is ambiguous: try the new credential, then the old
    # one. Both attempts set the role to the protected previous password.
    for candidate in new old; do
      new_private_file input
      write_postgres_password_payload "$ENV_BACKUP" "$PG_NEW_FILE" "$input" "$candidate" || return 1
      if postgres_stdin "$input"; then
        rolled_back=true
        break
      fi
    done
    [[ "$rolled_back" == true ]] || return 1
  fi
  install -m 0600 "$ENV_BACKUP" "$ENV_FILE" || return 1
  for saved in "$BACKUP_DIR"/*.before; do
    [[ -f "$saved" ]] || continue
    authority="$SECRET_DIR/$(basename "${saved%.before}")"
    install -m 0600 "$saved" "$authority" || return 1
  done
  postgres_changed=false
  if [[ -n "${RESTART_NEEDED[*]+x}" ]]; then restart_services; fi
}

# ── Individual rotation functions ───────────────────────────────────

rotate_postgres_password() {
  local new_file pg_input
  prepare_secret_file new_file base64 32
  log "Rotating POSTGRES_PASSWORD..."

  if ! $DRY_RUN; then
    new_private_file pg_input
    write_postgres_password_payload "$ENV_FILE" "$new_file" "$pg_input" rotate
    chmod 600 "$pg_input"
    PG_NEW_FILE="$new_file"
    postgres_changed=true
    RESTART_NEEDED[chronicle-backend]=1
    RESTART_NEEDED[chronicle-postgres-exporter]=1
    RESTART_NEEDED[postgres]=1
    RESTART_NEEDED[postgres-replica]=1
    if ! postgres_stdin "$pg_input" 2>/dev/null; then
      err "Postgres ALTER ROLE did not confirm success; restoring the previous credential"
    fi
    rm -f -- "$pg_input"
    log "ALTER ROLE succeeded in Postgres"
  fi

  env_set POSTGRES_PASSWORD "$new_file"
  RESTART_NEEDED[chronicle-backend]=1
  RESTART_NEEDED[chronicle-postgres-exporter]=1
  RESTART_NEEDED[postgres]=1
  RESTART_NEEDED[postgres-replica]=1
}

rotate_jwt_secret() {
  local new_file
  prepare_secret_file new_file base64 64
  log "Rotating JWT_SECRET (all active sessions will be invalidated)..."
  if ! $DRY_RUN && ! confirm "This invalidates ALL user sessions. Continue?"; then
    warn "Skipped JWT_SECRET rotation"
    return
  fi
  env_set JWT_SECRET "$new_file"
  RESTART_NEEDED[chronicle-backend]=1
}

rotate_hazelcast_passwords() {
  local new_server_file new_client_file
  prepare_secret_file new_server_file base64 32
  prepare_secret_file new_client_file base64 32
  log "Rotating HAZELCAST_SERVER_PASSWORD + HAZELCAST_CLIENT_PASSWORD..."
  env_set HAZELCAST_SERVER_PASSWORD "$new_server_file"
  env_set HAZELCAST_CLIENT_PASSWORD "$new_client_file"
  RESTART_NEEDED[chronicle-backend]=1
}

rotate_grafana_admin_password() {
  local new_file
  prepare_secret_file new_file base64 32
  log "Rotating GRAFANA_ADMIN_PASSWORD..."

  if ! $DRY_RUN; then
    if ! docker exec -i chronicle-grafana \
         grafana cli admin reset-admin-password --password-from-stdin \
         < "$new_file" >/dev/null; then
      err "Could not reset Grafana admin password — .env NOT changed. Grafana password unchanged."
    fi
    log "Grafana admin password reset via grafana-cli"
  fi

  env_set GRAFANA_ADMIN_PASSWORD "$new_file"
  RESTART_NEEDED[grafana]=1
}

rotate_crowdsec_bouncer_key() {
  local new_file container_key_file
  log "Rotating CROWDSEC_BOUNCER_API_KEY..."

  if ! $DRY_RUN; then
    if ! docker exec chronicle-crowdsec cscli bouncers delete traefik-bouncer >/dev/null 2>&1; then
      warn "Delete of old bouncer failed — may not exist yet, continuing"
    fi
    container_key_file="/var/lib/crowdsec/data/.chronicle-bouncer-key-${TIMESTAMP}-$$"
    if ! docker exec chronicle-crowdsec sh -ceu '
           umask 077
           cscli bouncers add "$1" -o raw > "$2"
         ' sh traefik-bouncer "$container_key_file" >/dev/null 2>&1; then
      docker exec chronicle-crowdsec rm -f -- "$container_key_file" >/dev/null 2>&1 || true
      err "Failed to create new CrowdSec bouncer key — .env NOT changed"
    fi
    new_private_file new_file
    if ! docker cp "chronicle-crowdsec:$container_key_file" "$new_file" >/dev/null; then
      docker exec chronicle-crowdsec rm -f -- "$container_key_file" >/dev/null 2>&1 || true
      err "Failed to copy the protected CrowdSec bouncer key — .env NOT changed"
    fi
    docker exec chronicle-crowdsec rm -f -- "$container_key_file" >/dev/null 2>&1 \
      || warn "Could not remove protected CrowdSec key handoff file from the container"
    chmod 600 "$new_file"
    [[ -s "$new_file" ]] || err "cscli bouncers add returned an empty key — .env NOT changed"
  else
    new_file=""
  fi

  env_set CROWDSEC_BOUNCER_API_KEY "$new_file"
  RESTART_NEEDED[traefik]=1
}

rotate_tde_principal_key() {
  log "Rotating TDE principal key (delegating to rotate-tde-principal-key.sh)..."
  local rotate_tde="$SCRIPT_DIR/rotate-tde-principal-key.sh"
  [[ -x "$rotate_tde" ]] || err "rotate-tde-principal-key.sh not found or not executable at $rotate_tde"

  if $DRY_RUN; then
    "$rotate_tde" --dry-run
  else
    "$rotate_tde" || err "TDE principal key rotation failed — see output above"
  fi
  # The TDE principal key lives in pg_tde/Vault, not docker/.env, so no env_set
  # and no service restart is required (re-wrap is online).
}

# ── Determine what to rotate ───────────────────────────────────────

ROTATABLE_SECRETS=(
  POSTGRES_PASSWORD
  JWT_SECRET
  HAZELCAST_SERVER_PASSWORD
  HAZELCAST_CLIENT_PASSWORD
  GRAFANA_ADMIN_PASSWORD
  CROWDSEC_BOUNCER_API_KEY
)

if [[ -n "$ONLY" ]]; then
  case "$ONLY" in
    POSTGRES_PASSWORD)          rotate_postgres_password ;;
    JWT_SECRET)                 rotate_jwt_secret ;;
    HAZELCAST_SERVER_PASSWORD)  rotate_hazelcast_passwords ;;
    HAZELCAST_CLIENT_PASSWORD)  rotate_hazelcast_passwords ;;
    GRAFANA_ADMIN_PASSWORD)     rotate_grafana_admin_password ;;
    CROWDSEC_BOUNCER_API_KEY)   rotate_crowdsec_bouncer_key ;;
    TDE_PRINCIPAL_KEY)          rotate_tde_principal_key ;;
    *)
      err "Unknown secret: $ONLY. Rotatable: ${ROTATABLE_SECRETS[*]} TDE_PRINCIPAL_KEY"
      ;;
  esac
else
  log "=== Starting full secret rotation ==="
  log "Secrets to rotate: ${ROTATABLE_SECRETS[*]} TDE_PRINCIPAL_KEY"
  log ""

  if ! $DRY_RUN && ! $AUTO && ! confirm "Proceed with rotation?"; then
    log "Aborted."
    exit 0
  fi

  rotate_postgres_password
  rotate_jwt_secret
  rotate_hazelcast_passwords
  rotate_grafana_admin_password
  rotate_crowdsec_bouncer_key
  rotate_tde_principal_key


fi

# ── Restart affected services ──────────────────────────────────────

restart_services() {
  local svc
  local -a order=(postgres postgres-replica traefik chronicle-backend chronicle-postgres-exporter grafana)
  for svc in "${order[@]}"; do
    if [[ -n "${RESTART_NEEDED[$svc]:-}" ]]; then
      log "Recreating $svc with the selected environment and mounted secrets..."
      if ! dc config --services | grep -Fxq "$svc"; then
        [[ "$svc" == chronicle-postgres-exporter || "$svc" == postgres-replica ]] && continue
        return 1
      fi
      dc up -d --force-recreate --wait --wait-timeout 120 "$svc" || return 1
    fi
  done
  if [[ "${postgres_changed:-false}" == true ]]; then
    # TCP authentication proves the new database credential, beyond container health.
    postgres_stdin "$SECRET_DIR/postgres_password" -c "SELECT 1" || return 1
  fi
}

# Guard: under `set -u`, an empty `declare -A` array errors on ${#arr[@]}.
# The +x test is set only when the array has at least one element. Some rotations
# (e.g. the TDE principal key) intentionally populate nothing.
if [[ -n "${RESTART_NEEDED[*]+x}" ]]; then
  log ""
  log "Services needing restart: ${!RESTART_NEEDED[*]}"

  if $DRY_RUN; then
    log "[dry-run] Would restart: ${!RESTART_NEEDED[*]}"
  else
    restart_services || err "New credentials failed runtime verification; rolling back"
  fi
fi

rotation_committed=true

# ── Summary ─────────────────────────────────────────────────────────

log ""
log "=== Rotation complete ==="
log "Backup: $BACKUP_DIR/.env.$TIMESTAMP"

if ! $DRY_RUN; then
  log ""
  log "Post-rotation checklist:"
  log "  1. Verify backend readiness:  curl -fsS http://localhost:40320/chronicle/internal/health/ready"
  log "  2. Verify Traefik health:  docker exec edge-traefik traefik healthcheck"
  log "  3. Verify Grafana login:   open https://\$(grep DOMAIN $ENV_FILE | cut -d= -f2)/grafana"
  log "  4. Update the secret rotation log with today's date"
fi
