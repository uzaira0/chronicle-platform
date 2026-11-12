#!/bin/bash
# Chronicle Backup Script
# Automated, encrypted backups of database, TDE keyring, config/secrets, and audit logs.
#
# Usage:
#   ./backup-chronicle.sh [--full|--verify|--list|--prune]
#     --full    (default) Create a full encrypted backup
#     --verify  Decrypt and validate the latest backup
#     --list    List all backup directories with retention tags
#     --prune   Remove old backups per retention policy
#
# Cron setup:
#   0 2 * * *   /opt/chronicle/docker/backup-chronicle.sh >> /var/log/chronicle-backup.log 2>&1
#   0 3 * * 0   /opt/chronicle/docker/backup-chronicle.sh --verify >> /var/log/chronicle-backup.log 2>&1
#
# Retention: 7 daily, 4 weekly (Sunday), 3 monthly (1st of month)

set -euo pipefail

# shellcheck source=docker/backup-format.sh
source "$(dirname "${BASH_SOURCE[0]}")/backup-format.sh"

# Cleanup temp files on exit (especially important for unencrypted dumps)
TEMP_FILES=()
TEMP_DIRS=()
cleanup() {
    rm -f "${TEMP_FILES[@]}"
    rm -rf "${TEMP_DIRS[@]}"
}
trap cleanup EXIT

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
BACKUP_ROOT="/opt/chronicle/backups"
# Store encryption key OUTSIDE the backup directory.
# Default location: /etc/chronicle/backup-encryption-key (root-only readable)
KEY_FILE="${CHRONICLE_BACKUP_KEY:-/etc/chronicle/backup-encryption-key}"
CONTAINER="chronicle-postgres"
BACKEND_CONTAINER="chronicle-backend"
DB_USER="chronicle"
DB_NAME="chronicle"
# Connect over TCP (-h 127.0.0.1), NOT the default local unix socket: the socket
# matches pg_hba "local all all peer" and docker-exec's OS user != the DB role, so
# socket connections fail with "Peer authentication failed" — which silently broke
# every pg_dump/psql here. TCP uses scram-sha-256 with the password below.
DB_HOST="127.0.0.1"
COMPOSE_PROD_FILE="${SCRIPT_DIR}/docker-compose.production.yml"
AUDIT_BACKUP_REQUIRED="${CHRONICLE_REQUIRE_AUDIT_BACKUP:-true}"

# Retention policy
KEEP_DAILY=7
KEEP_WEEKLY=4
KEEP_MONTHLY=3

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"; }
log_ok() { echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] ${GREEN}OK${NC} $*"; }
log_err() { echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] ${RED}ERROR${NC} $*" >&2; }
log_warn() { echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] ${YELLOW}WARN${NC} $*"; }

check_prereqs() {
    if [ ! -f "$KEY_FILE" ]; then
        log_err "Backup encryption key not found: $KEY_FILE"
        log_err "Generate with: openssl rand -base64 64 > $KEY_FILE && chmod 600 $KEY_FILE"
        exit 1
    fi

    if ! docker inspect "$CONTAINER" --format='{{.State.Running}}' 2>/dev/null | grep true >/dev/null; then
        log_err "PostgreSQL container '$CONTAINER' is not running"
        exit 1
    fi
}

encrypt_file() {
    local src="$1"
    local dst="$2"
    openssl enc -aes-256-cbc -salt -pbkdf2 -iter "$BACKUP_PBKDF2_ITERATIONS" \
        -in "$src" -out "$dst" -pass "file:${KEY_FILE}"
}

decrypt_file() {
    local src="$1"
    local dst="$2"
    openssl enc -aes-256-cbc -d -salt -pbkdf2 -iter "$BACKUP_PBKDF2_ITERATIONS" \
        -in "$src" -out "$dst" -pass "file:${KEY_FILE}"
}

# Consume the complete archive listing. With pipefail enabled, grep -q can exit
# early and SIGPIPE tar, incorrectly treating a valid archive as corrupt.
archive_contains_entry() {
    local archive="$1"
    local pattern="$2"
    tar -tzf "$archive" 2>/dev/null | grep -E -- "$pattern" >/dev/null
}

sha256() {
    sha256sum "$1" | awk '{print $1}'
}

postgres_exec() {
    docker exec "$CONTAINER" sh -euc \
        'export PGPASSWORD="${POSTGRES_PASSWORD:?POSTGRES_PASSWORD is unavailable}"; exec "$@"' \
        chronicle-postgres-command "$@"
}

capture_database_contract() {
    local summary
    local history_file
    local key_state
    local expected_provider_name

    if ! summary=$(postgres_exec psql -X -v ON_ERROR_STOP=1 -qAt -P pager=off \
        -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" -F '|' -c "
        SELECT
          (SELECT count(*)
             FROM pg_class
            WHERE relkind = 'r'
              AND relnamespace = (SELECT oid FROM pg_namespace WHERE nspname = 'public')),
          (SELECT count(*)
             FROM pg_class c
             JOIN pg_am am ON c.relam = am.oid
            WHERE c.relkind = 'r'
              AND am.amname = 'tde_heap'
              AND c.relnamespace = (SELECT oid FROM pg_namespace WHERE nspname = 'public')),
          COALESCE(max(version::int)
            FILTER (WHERE success AND version ~ '^[0-9]+$'), 0),
          max(version::int)
            FILTER (WHERE success AND type = 'BASELINE' AND version ~ '^[0-9]+$'),
          count(*) FILTER (WHERE success),
          count(*) FILTER (WHERE NOT success),
          count(*) FILTER (WHERE version IS NOT NULL AND version !~ '^[0-9]+$')
        FROM public.flyway_schema_history;
    " 2>/dev/null); then
        log_err "Unable to capture database/Flyway backup contract"
        return 1
    fi
    IFS='|' read -r CAPTURE_TABLE_COUNT CAPTURE_TDE_COUNT CAPTURE_FLYWAY_MAX \
        CAPTURE_FLYWAY_BASELINE CAPTURE_FLYWAY_SUCCESSFUL CAPTURE_FLYWAY_FAILED \
        CAPTURE_FLYWAY_INVALID <<< "$summary"
    if [[ ! "$CAPTURE_TABLE_COUNT" =~ ^[1-9][0-9]*$ ]] \
        || [[ ! "$CAPTURE_TDE_COUNT" =~ ^[1-9][0-9]*$ ]] \
        || [ "$CAPTURE_TDE_COUNT" -ne "$CAPTURE_TABLE_COUNT" ] \
        || [[ ! "$CAPTURE_FLYWAY_MAX" =~ ^[1-9][0-9]*$ ]] \
        || { [ -n "$CAPTURE_FLYWAY_BASELINE" ] && [[ ! "$CAPTURE_FLYWAY_BASELINE" =~ ^[0-9]+$ ]]; } \
        || [[ ! "$CAPTURE_FLYWAY_SUCCESSFUL" =~ ^[1-9][0-9]*$ ]] \
        || [ "$CAPTURE_FLYWAY_FAILED" != "0" ] \
        || [ "$CAPTURE_FLYWAY_INVALID" != "0" ]; then
        log_err "Database/Flyway backup contract is invalid: '${summary:-no result}'"
        return 1
    fi
    [ -n "$CAPTURE_FLYWAY_BASELINE" ] || CAPTURE_FLYWAY_BASELINE=null

    history_file=$(mktemp)
    TEMP_FILES+=("$history_file")
    if ! postgres_exec psql -X -v ON_ERROR_STOP=1 -qAt -P pager=off \
        -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" -c "
        SELECT jsonb_build_array(
            installed_rank,
            version,
            description,
            type,
            script,
            checksum,
            success
        )::text
        FROM public.flyway_schema_history
        ORDER BY installed_rank;
    " > "$history_file"; then
        log_err "Unable to capture Flyway history for the backup contract"
        return 1
    fi
    if [ ! -s "$history_file" ]; then
        log_err "Flyway history is empty"
        return 1
    fi
    if ! CAPTURE_FLYWAY_SHA256=$(sha256 "$history_file"); then
        log_err "Unable to fingerprint Flyway history"
        return 1
    fi

    if ! CAPTURE_TDE_PROVIDER=$(docker exec "$CONTAINER" sh -euc \
        'printf "%s\n" "${PG_TDE_KEY_PROVIDER:?PG_TDE_KEY_PROVIDER is unavailable}"' 2>/dev/null); then
        log_err "Unable to determine the configured TDE key provider"
        return 1
    fi
    case "$CAPTURE_TDE_PROVIDER" in
        file) expected_provider_name=chronicle-file-vault ;;
        vault) expected_provider_name=chronicle-vault ;;
        *)
            log_err "Unsupported TDE key provider for production backup: ${CAPTURE_TDE_PROVIDER:-unset}"
            return 1
            ;;
    esac
    if ! key_state=$(postgres_exec psql -X -v ON_ERROR_STOP=1 -qAt -P pager=off \
        -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" -F '|' \
        -c "SELECT key_name, provider_name FROM pg_tde_key_info();" 2>/dev/null); then
        log_err "Unable to query the active TDE principal key"
        return 1
    fi
    IFS='|' read -r CAPTURE_TDE_KEY_NAME CAPTURE_TDE_PROVIDER_NAME <<< "$key_state"
    if [[ ! "$CAPTURE_TDE_KEY_NAME" =~ ^[A-Za-z0-9._-]+$ ]] \
        || [ "$CAPTURE_TDE_PROVIDER_NAME" != "$expected_provider_name" ]; then
        log_err "Active TDE key/provider does not match configured ${CAPTURE_TDE_PROVIDER} custody"
        return 1
    fi
    if ! postgres_exec psql -X -v ON_ERROR_STOP=1 -qAt -P pager=off \
        -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" \
        -c "SELECT pg_tde_verify_key();" >/dev/null; then
        log_err "The active TDE principal key could not be verified"
        return 1
    fi
}

json_escape() {
    printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'
}

json_bool() {
    case "$1" in
        true|TRUE|1|yes|YES) printf 'true' ;;
        *) printf 'false' ;;
    esac
}

resolve_env_config_file() {
    if [ -n "${CHRONICLE_BACKUP_ENV_FILE:-}" ]; then
        if [[ "${CHRONICLE_BACKUP_ENV_FILE}" = /* ]]; then
            printf '%s\n' "${CHRONICLE_BACKUP_ENV_FILE}"
        else
            printf '%s\n' "${SCRIPT_DIR}/${CHRONICLE_BACKUP_ENV_FILE}"
        fi
        return
    fi

    if [ -f "${SCRIPT_DIR}/.env.production.local" ]; then
        printf '%s\n' "${SCRIPT_DIR}/.env.production.local"
        return
    fi

    if [ -f "${SCRIPT_DIR}/.env" ]; then
        printf '%s\n' "${SCRIPT_DIR}/.env"
        return
    fi

    printf '%s\n' "${SCRIPT_DIR}/.env.production.local"
}

copy_if_exists() {
    local src="$1"
    local dst_root="$2"
    local rel="${src#"${REPO_ROOT}/"}"
    if [ -e "$src" ]; then
        mkdir -p "${dst_root}/$(dirname "$rel")"
        cp -R "$src" "${dst_root}/${rel}"
    fi
}

create_deployment_manifest_archive() {
    local dst="$1"
    local env_config_file="$2"
    local stage
    stage=$(mktemp -d)
    TEMP_DIRS+=("$stage")

    for required_evidence in \
        "${SCRIPT_DIR}/docker-compose.traefik.yml" \
        "${COMPOSE_PROD_FILE}" \
        "${REPO_ROOT}/deploy/cue/profiles.cue"; do
        if [ ! -s "$required_evidence" ] || [ ! -f "$required_evidence" ]; then
            log_err "Required deployment evidence is missing or empty: ${required_evidence}"
            return 1
        fi
    done

    mkdir -p "${stage}/deployment"

    local git_commit git_branch git_dirty
    git_commit=$(git -C "$REPO_ROOT" rev-parse HEAD 2>/dev/null || echo "unknown")
    git_branch=$(git -C "$REPO_ROOT" rev-parse --abbrev-ref HEAD 2>/dev/null || echo "unknown")
    if git -C "$REPO_ROOT" diff --quiet --ignore-submodules -- 2>/dev/null \
        && git -C "$REPO_ROOT" diff --cached --quiet --ignore-submodules -- 2>/dev/null; then
        git_dirty=false
    else
        git_dirty=true
    fi

    cat > "${stage}/deployment/deployment-manifest.json" <<MANIFEST
{
    "schema_version": ${BACKUP_MANIFEST_VERSION},
    "timestamp": "$(date -Iseconds)",
    "git_commit": "$(json_escape "$git_commit")",
    "git_branch": "$(json_escape "$git_branch")",
    "git_dirty": ${git_dirty},
    "env_config_file": "$(json_escape "$(basename "$env_config_file")")",
    "compose_files": [
        "docker/docker-compose.traefik.yml",
        "docker/docker-compose.production.yml"
    ],
    "kubernetes_profile_source": "deploy/cue/profiles.cue"
}
MANIFEST

    git -C "$REPO_ROOT" status --short --branch --ignore-submodules=dirty > "${stage}/deployment/git-status.txt" 2>/dev/null || true
    git -C "$REPO_ROOT" submodule status --recursive > "${stage}/deployment/git-submodules.txt" 2>/dev/null || true

    copy_if_exists "${SCRIPT_DIR}/docker-compose.traefik.yml" "$stage"
    copy_if_exists "${COMPOSE_PROD_FILE}" "$stage"
    copy_if_exists "${SCRIPT_DIR}/.env.production" "$stage"
    copy_if_exists "${REPO_ROOT}/scripts/deploy.sh" "$stage"
    copy_if_exists "${REPO_ROOT}/scripts/server-setup.sh" "$stage"
    copy_if_exists "${REPO_ROOT}/k8s" "$stage"
    copy_if_exists "${REPO_ROOT}/deploy/cue" "$stage"
    copy_if_exists "${REPO_ROOT}/ontology/chronicle.linkml.yaml" "$stage"
    copy_if_exists "${REPO_ROOT}/docs/RHEL9-DEDICATED-SERVER-RUNBOOK.md" "$stage"
    copy_if_exists "${REPO_ROOT}/docs/RHEL9-KUBERNETES-RUNBOOK.md" "$stage"
    copy_if_exists "${REPO_ROOT}/docs/KUBERNETES-DEPLOYMENT.md" "$stage"
    copy_if_exists "${REPO_ROOT}/docs/SCHEMA-CONFIG-SOURCE-OF-TRUTH.md" "$stage"

    local deployment_tmp
    deployment_tmp=$(mktemp)
    TEMP_FILES+=("$deployment_tmp")
    tar -czf "$deployment_tmp" -C "$stage" .
    encrypt_file "$deployment_tmp" "$dst"
    rm -f "$deployment_tmp"
}

backup_database() {
    # 1. Database dump
    log "  Dumping database..."
    if ! capture_database_contract; then
        exit 1
    fi
    PRE_TABLE_COUNT="$CAPTURE_TABLE_COUNT"
    PRE_TDE_COUNT="$CAPTURE_TDE_COUNT"
    PRE_FLYWAY_MAX="$CAPTURE_FLYWAY_MAX"
    PRE_FLYWAY_BASELINE="$CAPTURE_FLYWAY_BASELINE"
    PRE_FLYWAY_SUCCESSFUL="$CAPTURE_FLYWAY_SUCCESSFUL"
    PRE_FLYWAY_FAILED="$CAPTURE_FLYWAY_FAILED"
    PRE_FLYWAY_SHA256="$CAPTURE_FLYWAY_SHA256"
    PRE_TDE_PROVIDER="$CAPTURE_TDE_PROVIDER"
    PRE_TDE_PROVIDER_NAME="$CAPTURE_TDE_PROVIDER_NAME"
    PRE_TDE_KEY_NAME="$CAPTURE_TDE_KEY_NAME"
    DUMP_TMP=$(mktemp); TEMP_FILES+=("$DUMP_TMP")
    postgres_exec pg_dump -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" -Fc -Z6 > "$DUMP_TMP"
    if ! capture_database_contract; then
        exit 1
    fi
    if [ "$CAPTURE_TABLE_COUNT" != "$PRE_TABLE_COUNT" ] \
        || [ "$CAPTURE_TDE_COUNT" != "$PRE_TDE_COUNT" ] \
        || [ "$CAPTURE_FLYWAY_MAX" != "$PRE_FLYWAY_MAX" ] \
        || [ "$CAPTURE_FLYWAY_BASELINE" != "$PRE_FLYWAY_BASELINE" ] \
        || [ "$CAPTURE_FLYWAY_SUCCESSFUL" != "$PRE_FLYWAY_SUCCESSFUL" ] \
        || [ "$CAPTURE_FLYWAY_FAILED" != "$PRE_FLYWAY_FAILED" ] \
        || [ "$CAPTURE_FLYWAY_SHA256" != "$PRE_FLYWAY_SHA256" ] \
        || [ "$CAPTURE_TDE_PROVIDER" != "$PRE_TDE_PROVIDER" ] \
        || [ "$CAPTURE_TDE_PROVIDER_NAME" != "$PRE_TDE_PROVIDER_NAME" ] \
        || [ "$CAPTURE_TDE_KEY_NAME" != "$PRE_TDE_KEY_NAME" ]; then
        log_err "Database schema/Flyway state changed during pg_dump; refusing an internally inconsistent backup"
        exit 1
    fi
    encrypt_file "$DUMP_TMP" "${BACKUP_DIR}/database.dump.enc"
    rm -f "$DUMP_TMP"
    log_ok "database.dump.enc ($(du -h "${BACKUP_DIR}/database.dump.enc" | cut -f1))"
}

backup_configuration() {
    # 3. Config/secrets
    log "  Backing up config and secrets..."
    ENV_CONFIG_FILE=$(resolve_env_config_file)
    if [ ! -f "$ENV_CONFIG_FILE" ]; then
        log_err "Required env config file missing: ${ENV_CONFIG_FILE}"
        log_err "Create docker/.env.production.local or set CHRONICLE_BACKUP_ENV_FILE to the active untracked env file."
        exit 1
    fi
    for CONF_FILE in rhizome-docker.yaml chronicle-auth.yaml; do
        if [ ! -f "${SCRIPT_DIR}/${CONF_FILE}" ]; then
            log_err "Required config file missing: ${SCRIPT_DIR}/${CONF_FILE}"
            exit 1
        fi
    done
    for TLS_FILE in \
        postgres-ssl/server/server.crt \
        postgres-ssl/ca/ca.crt \
        postgres-ssl/pg_hba-ssl.conf; do
        if [ ! -s "${SCRIPT_DIR}/${TLS_FILE}" ] || [ ! -f "${SCRIPT_DIR}/${TLS_FILE}" ]; then
            log_err "Required PostgreSQL TLS file missing or empty: ${SCRIPT_DIR}/${TLS_FILE}"
            exit 1
        fi
    done
    CONFIG_TMP=$(mktemp); TEMP_FILES+=("$CONFIG_TMP")
    # postgres-ssl/server/server.key is mode 600 owned by the postgres uid and is
    # unreadable by the backup user. Stage every readable secret, then pull
    # server.key through the container (which runs as the postgres uid) so the
    # bundle is complete instead of aborting the whole backup on a permission error.
    CONFIG_STAGE=$(mktemp -d); TEMP_DIRS+=("$CONFIG_STAGE")
    cp "$ENV_CONFIG_FILE" "${CONFIG_STAGE}/$(basename "$ENV_CONFIG_FILE")"
    cp "${SCRIPT_DIR}/rhizome-docker.yaml" "${CONFIG_STAGE}/rhizome-docker.yaml"
    cp "${SCRIPT_DIR}/chronicle-auth.yaml" "${CONFIG_STAGE}/chronicle-auth.yaml"
    if ( cd "$SCRIPT_DIR" && tar -cf - --exclude=postgres-ssl/server/server.key postgres-ssl/ ) \
        | tar -xf - -C "$CONFIG_STAGE"; then
        :
    else
        log_err "Unable to stage PostgreSQL TLS configuration"
        exit 1
    fi
    if docker exec "$CONTAINER" cat /etc/postgres-ssl-src/server.key > "$CONFIG_STAGE/postgres-ssl/server/server.key" 2>/dev/null \
        && [ -s "$CONFIG_STAGE/postgres-ssl/server/server.key" ]; then
        chmod 600 "$CONFIG_STAGE/postgres-ssl/server/server.key"
        log_ok "  captured server.key via container"
    else
        log_err "Required PostgreSQL TLS server.key could not be captured"
        exit 1
    fi
    tar -czf "$CONFIG_TMP" -C "$CONFIG_STAGE" .
    encrypt_file "$CONFIG_TMP" "${BACKUP_DIR}/config-secrets.tar.gz.enc"
    rm -f "$CONFIG_TMP"
    log_ok "config-secrets.tar.gz.enc"
}

write_backup_manifest() {
    # 6. Manifest
    log "  Creating manifest..."

    if ! DB_SIZE=$(postgres_exec psql -X -v ON_ERROR_STOP=1 -qAt -P pager=off \
        -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" \
        -c "SELECT pg_size_pretty(pg_database_size('${DB_NAME}'));" 2>/dev/null); then
        log_err "Unable to query database size for the backup manifest"
        exit 1
    fi
    TABLE_COUNT="$CAPTURE_TABLE_COUNT"
    TDE_COUNT="$CAPTURE_TDE_COUNT"

    # Build checksums
    CHECKSUMS="{"
    for F in "${BACKUP_DIR}"/*.enc; do
        [ -f "$F" ] || continue
        FNAME=$(basename "$F")
        HASH=$(sha256 "$F")
        CHECKSUMS="${CHECKSUMS}\"${FNAME}\":\"${HASH}\","
    done
    CHECKSUMS="${CHECKSUMS%,}}"

    REQUIRED_ARTIFACTS="[\"database.dump.enc\",\"tde-keyring.tar.gz.enc\",\"config-secrets.tar.gz.enc\",\"deployment-manifest.tar.gz.enc\""
    if [ "$AUDIT_BACKED_UP" = true ]; then
        REQUIRED_ARTIFACTS="${REQUIRED_ARTIFACTS},\"audit-logs.tar.gz.enc\""
    fi
    REQUIRED_ARTIFACTS="${REQUIRED_ARTIFACTS}]"

    # Retention tags
    DAY_OF_WEEK=$(date '+%u')  # 7=Sunday
    DAY_OF_MONTH=$(date '+%d')
    TAGS="[\"daily\""
    [ "$DAY_OF_WEEK" = "7" ] && TAGS="${TAGS},\"weekly\""
    [ "$DAY_OF_MONTH" = "01" ] && TAGS="${TAGS},\"monthly\""
    TAGS="${TAGS}]"

    cat > "${BACKUP_DIR}/manifest.json" <<MANIFEST
{
    "schema_version": ${BACKUP_MANIFEST_VERSION},
    "timestamp": "$(date -Iseconds)",
    "backup_dir": "${TIMESTAMP}",
    "env_config_file": "$(json_escape "$(basename "$ENV_CONFIG_FILE")")",
    "audit_logs_required": $(json_bool "$AUDIT_BACKUP_REQUIRED"),
    "database_size": "${DB_SIZE}",
    "table_count": ${TABLE_COUNT},
    "tde_encrypted_tables": ${TDE_COUNT},
    "tde": {
        "provider": "${CAPTURE_TDE_PROVIDER}",
        "provider_name": "${CAPTURE_TDE_PROVIDER_NAME}",
        "principal_key_name": "${CAPTURE_TDE_KEY_NAME}"
    },
    "flyway": {
        "history_format": "jsonb-array-lines/v1",
        "baseline_version": ${CAPTURE_FLYWAY_BASELINE},
        "max_version": ${CAPTURE_FLYWAY_MAX},
        "successful_entry_count": ${CAPTURE_FLYWAY_SUCCESSFUL},
        "failed_entry_count": ${CAPTURE_FLYWAY_FAILED},
        "history_sha256": "${CAPTURE_FLYWAY_SHA256}"
    },
    "required_artifacts": ${REQUIRED_ARTIFACTS},
    "retention_tags": ${TAGS},
    "checksums": ${CHECKSUMS}
}
MANIFEST

    log_ok "manifest.json"
}

do_full_backup() {
    check_prereqs

    TIMESTAMP=$(date '+%Y%m%d_%H%M%S')
    BACKUP_DIR="${BACKUP_ROOT}/${TIMESTAMP}"
    mkdir -p "$BACKUP_DIR"

    log "Starting full backup to ${BACKUP_DIR}"

    backup_database

    # 2. TDE keyring
    log "  Backing up TDE keyring..."
    KEYRING_TMP=$(mktemp); TEMP_FILES+=("$KEYRING_TMP")
    docker exec "$CONTAINER" tar -czf - -C /var/lib/postgresql tde-keyring > "$KEYRING_TMP"
    encrypt_file "$KEYRING_TMP" "${BACKUP_DIR}/tde-keyring.tar.gz.enc"
    rm -f "$KEYRING_TMP"
    log_ok "tde-keyring.tar.gz.enc"

    backup_configuration

    # 4. Audit logs (from backend container, if running)
    log "  Backing up audit logs..."
    AUDIT_BACKED_UP=false
    if docker inspect "$BACKEND_CONTAINER" --format='{{.State.Running}}' 2>/dev/null | grep true >/dev/null; then
        AUDIT_TMP=$(mktemp); AUDIT_ERR=$(mktemp); TEMP_FILES+=("$AUDIT_TMP" "$AUDIT_ERR")
        if docker exec "$BACKEND_CONTAINER" tar -czf - -C /var/log chronicle > "$AUDIT_TMP" 2>"$AUDIT_ERR"; then
            if [ -s "$AUDIT_TMP" ]; then
                encrypt_file "$AUDIT_TMP" "${BACKUP_DIR}/audit-logs.tar.gz.enc"
                AUDIT_BACKED_UP=true
                log_ok "audit-logs.tar.gz.enc"
            else
                log_warn "No audit logs found (empty archive)"
            fi
        else
            log_warn "Failed to backup audit logs: $(tr '\n' ' ' < "$AUDIT_ERR")"
        fi
        rm -f "$AUDIT_TMP" "$AUDIT_ERR"
    else
        log_warn "Backend container not running, skipping audit logs"
    fi
    if [ "$AUDIT_BACKED_UP" != true ] && [ "$(json_bool "$AUDIT_BACKUP_REQUIRED")" = true ]; then
        log_err "Audit log backup is required. Set CHRONICLE_REQUIRE_AUDIT_BACKUP=false only for non-production drills."
        exit 1
    fi

    # 5. Deployment evidence
    log "  Backing up deployment manifest and IaC evidence..."
    create_deployment_manifest_archive "${BACKUP_DIR}/deployment-manifest.tar.gz.enc" "$ENV_CONFIG_FILE"
    log_ok "deployment-manifest.tar.gz.enc"

    write_backup_manifest

    # Set permissions
    chmod 700 "$BACKUP_DIR"
    chmod 600 "${BACKUP_DIR}"/*

    log ""
    log "Backup complete: ${BACKUP_DIR}"
    log "  Database: ${DB_SIZE}, ${TABLE_COUNT} tables (${TDE_COUNT} encrypted)"
    log "  Env config: $(basename "$ENV_CONFIG_FILE")"
    log "  Retention: ${TAGS}"

    # Auto-prune after backup
    do_prune
}

do_verify() {
    check_prereqs

    # Find latest backup
    LATEST=$(ls -d "${BACKUP_ROOT}"/[0-9]*_[0-9]* 2>/dev/null | sort -r | sed -n 1p)
    if [ -z "$LATEST" ]; then
        log_err "No backups found in ${BACKUP_ROOT}"
        exit 1
    fi

    log "Verifying backup: $(basename "$LATEST")"
    ERRORS=0

    # Check manifest exists
    if [ ! -f "${LATEST}/manifest.json" ]; then
        log_err "manifest.json missing"
        exit 1
    fi
    log_ok "manifest.json present"

    REQUIRED_ARTIFACTS=(database.dump.enc tde-keyring.tar.gz.enc config-secrets.tar.gz.enc deployment-manifest.tar.gz.enc)
    if grep -q '"audit-logs.tar.gz.enc"' "${LATEST}/manifest.json" || [ "$(json_bool "$AUDIT_BACKUP_REQUIRED")" = true ]; then
        REQUIRED_ARTIFACTS+=(audit-logs.tar.gz.enc)
    fi

    log "  Verifying required artifact set..."
    for FNAME in "${REQUIRED_ARTIFACTS[@]}"; do
        if [ ! -f "${LATEST}/${FNAME}" ]; then
            log_err "  required artifact missing: ${FNAME}"
            ERRORS=$((ERRORS + 1))
            continue
        fi
        if ! grep -q "\"${FNAME}\"" "${LATEST}/manifest.json"; then
            log_err "  required artifact not declared in manifest: ${FNAME}"
            ERRORS=$((ERRORS + 1))
        fi
    done

    # Verify checksums
    log "  Verifying checksums..."
    for F in "${LATEST}"/*.enc; do
        [ -f "$F" ] || continue
        FNAME=$(basename "$F")
        ACTUAL_HASH=$(sha256 "$F")
        # Extract expected hash from manifest (simple grep approach)
        EXPECTED_HASH=$(grep -o "\"${FNAME}\":\"[a-f0-9]*\"" "${LATEST}/manifest.json" 2>/dev/null | cut -d'"' -f4 || true)
        if [ -n "$EXPECTED_HASH" ] && [ "$ACTUAL_HASH" = "$EXPECTED_HASH" ]; then
            log_ok "  ${FNAME} checksum matches"
        elif [ -z "$EXPECTED_HASH" ]; then
            log_err "  ${FNAME} missing from manifest checksums"
            ERRORS=$((ERRORS + 1))
        else
            log_err "  ${FNAME} checksum MISMATCH"
            ERRORS=$((ERRORS + 1))
        fi
    done

    # Decrypt and validate database dump (use pg_restore inside container)
    log "  Validating database dump..."
    DUMP_TMP=$(mktemp)
    if decrypt_file "${LATEST}/database.dump.enc" "$DUMP_TMP"; then
        docker cp "$DUMP_TMP" "${CONTAINER}:/tmp/verify.dump" 2>/dev/null
        docker exec -u root "$CONTAINER" chmod 644 /tmp/verify.dump 2>/dev/null
        TABLE_LIST=$(docker exec "$CONTAINER" pg_restore --list /tmp/verify.dump 2>/dev/null | grep -c "TABLE " || true)
        docker exec -u root "$CONTAINER" rm -f /tmp/verify.dump 2>/dev/null
        if [ "$TABLE_LIST" -gt 0 ]; then
            log_ok "  database.dump.enc decrypts OK (${TABLE_LIST} table entries)"
        else
            log_err "  database.dump.enc decrypted but pg_restore --list found no tables"
            ERRORS=$((ERRORS + 1))
        fi
    else
        log_err "  database.dump.enc decryption FAILED"
        ERRORS=$((ERRORS + 1))
    fi
    rm -f "$DUMP_TMP"

    # Decrypt and validate TDE keyring
    log "  Validating TDE keyring archive..."
    KEYRING_TMP=$(mktemp)
    if decrypt_file "${LATEST}/tde-keyring.tar.gz.enc" "$KEYRING_TMP"; then
        if tar -tzf "$KEYRING_TMP" >/dev/null 2>&1; then
            FILE_COUNT=$(tar -tzf "$KEYRING_TMP" 2>/dev/null | wc -l)
            log_ok "  tde-keyring.tar.gz.enc decrypts OK (${FILE_COUNT} entries)"
        else
            log_err "  tde-keyring.tar.gz.enc decrypted but tar is invalid"
            ERRORS=$((ERRORS + 1))
        fi
    else
        log_err "  tde-keyring.tar.gz.enc decryption FAILED"
        ERRORS=$((ERRORS + 1))
    fi
    rm -f "$KEYRING_TMP"

    # Decrypt and validate config/secrets bundle
    log "  Validating config/secrets archive..."
    CONFIG_VERIFY_TMP=$(mktemp)
    if decrypt_file "${LATEST}/config-secrets.tar.gz.enc" "$CONFIG_VERIFY_TMP"; then
        if tar -tzf "$CONFIG_VERIFY_TMP" >/dev/null 2>&1; then
            if archive_contains_entry "$CONFIG_VERIFY_TMP" '(^|/)\.env.production.local$|(^|/)\.env$'; then
                log_ok "  config-secrets.tar.gz.enc decrypts OK"
            else
                log_err "  config-secrets.tar.gz.enc lacks an env file"
                ERRORS=$((ERRORS + 1))
            fi
        else
            log_err "  config-secrets.tar.gz.enc decrypted but tar is invalid"
            ERRORS=$((ERRORS + 1))
        fi
    else
        log_err "  config-secrets.tar.gz.enc decryption FAILED"
        ERRORS=$((ERRORS + 1))
    fi
    rm -f "$CONFIG_VERIFY_TMP"

    # Decrypt and validate deployment manifest bundle
    log "  Validating deployment manifest archive..."
    DEPLOY_VERIFY_TMP=$(mktemp)
    if decrypt_file "${LATEST}/deployment-manifest.tar.gz.enc" "$DEPLOY_VERIFY_TMP"; then
        if archive_contains_entry "$DEPLOY_VERIFY_TMP" 'deployment/deployment-manifest\.json$'; then
            log_ok "  deployment-manifest.tar.gz.enc decrypts OK"
        else
            log_err "  deployment-manifest.tar.gz.enc lacks deployment/deployment-manifest.json"
            ERRORS=$((ERRORS + 1))
        fi
    else
        log_err "  deployment-manifest.tar.gz.enc decryption FAILED"
        ERRORS=$((ERRORS + 1))
    fi
    rm -f "$DEPLOY_VERIFY_TMP"

    if [ -f "${LATEST}/audit-logs.tar.gz.enc" ]; then
        log "  Validating audit log archive..."
        AUDIT_VERIFY_TMP=$(mktemp)
        if decrypt_file "${LATEST}/audit-logs.tar.gz.enc" "$AUDIT_VERIFY_TMP"; then
            if archive_contains_entry "$AUDIT_VERIFY_TMP" '^chronicle'; then
                log_ok "  audit-logs.tar.gz.enc decrypts OK"
            else
                log_err "  audit-logs.tar.gz.enc lacks chronicle log entries"
                ERRORS=$((ERRORS + 1))
            fi
        else
            log_err "  audit-logs.tar.gz.enc decryption FAILED"
            ERRORS=$((ERRORS + 1))
        fi
        rm -f "$AUDIT_VERIFY_TMP"
    fi

    # Write Prometheus-compatible metrics for monitoring
    # Override with CHRONICLE_BACKUP_METRICS_FILE when /var/log/chronicle isn't
    # writable by the backup user (avoids a redirect error spamming the log; the
    # default dir is owned by the backend container).
    VERIFY_METRICS_FILE="${CHRONICLE_BACKUP_METRICS_FILE:-/var/log/chronicle/backup-verify-metrics.prom}"
    METRICS_DIR="$(dirname "$VERIFY_METRICS_FILE")"
    if mkdir -p "$METRICS_DIR" 2>/dev/null && [ -w "$METRICS_DIR" ]; then
        cat > "$VERIFY_METRICS_FILE" <<PROM
# HELP chronicle_backup_verify_success Whether the last backup verification passed (1) or failed (0).
# TYPE chronicle_backup_verify_success gauge
chronicle_backup_verify_success $([ "$ERRORS" -eq 0 ] && echo 1 || echo 0)
# HELP chronicle_backup_verify_timestamp_seconds Unix timestamp of last backup verification.
# TYPE chronicle_backup_verify_timestamp_seconds gauge
chronicle_backup_verify_timestamp_seconds $(date +%s)
# HELP chronicle_backup_verify_errors Number of errors in last backup verification.
# TYPE chronicle_backup_verify_errors gauge
chronicle_backup_verify_errors ${ERRORS}
PROM
        chmod 644 "$VERIFY_METRICS_FILE" 2>/dev/null || true
    else
        log_warn "  metrics dir $METRICS_DIR not writable; skipping Prometheus metrics export"
    fi

    echo ""
    if [ "$ERRORS" -eq 0 ]; then
        log_ok "Backup verification PASSED"
    else
        log_err "Backup verification FAILED ($ERRORS errors)"
        exit 1
    fi
}

do_list() {
    log "Backups in ${BACKUP_ROOT}:"
    echo ""
    printf "%-20s %-10s %-8s %-8s %s\n" "DIRECTORY" "DB SIZE" "TABLES" "TDE" "TAGS"
    printf "%-20s %-10s %-8s %-8s %s\n" "---------" "-------" "------" "---" "----"

    for DIR in $(ls -d "${BACKUP_ROOT}"/[0-9]*_[0-9]* 2>/dev/null | sort -r); do
        MANIFEST="${DIR}/manifest.json"
        if [ -f "$MANIFEST" ]; then
            DIRNAME=$(basename "$DIR")
            DB_SIZE=$(grep -o '"database_size"[[:space:]]*:[[:space:]]*"[^"]*"' "$MANIFEST" | cut -d'"' -f4 || true)
            TABLES=$(grep -o '"table_count"[[:space:]]*:[[:space:]]*[0-9]*' "$MANIFEST" | grep -o '[0-9]*$' || true)
            TDE=$(grep -o '"tde_encrypted_tables"[[:space:]]*:[[:space:]]*[0-9]*' "$MANIFEST" | grep -o '[0-9]*$' || true)
            TAGS=$(grep -o '"retention_tags"[[:space:]]*:[[:space:]]*\[[^]]*\]' "$MANIFEST" | sed 's/.*\[//;s/\]//;s/"//g' || true)
            printf "%-20s %-10s %-8s %-8s %s\n" "$DIRNAME" "$DB_SIZE" "$TABLES" "$TDE" "$TAGS"
        fi
    done
    echo ""
}

do_prune() {
    log "Pruning old backups (keep: ${KEEP_DAILY}d, ${KEEP_WEEKLY}w, ${KEEP_MONTHLY}m)..."

    # Get all backup directories sorted newest first
    mapfile -t DIRS < <(ls -d "${BACKUP_ROOT}"/[0-9]*_[0-9]* 2>/dev/null | sort -r)
    TOTAL=${#DIRS[@]}

    if [ "$TOTAL" -eq 0 ]; then
        log "  No backups to prune"
        return
    fi

    DAILY_KEPT=0
    WEEKLY_KEPT=0
    MONTHLY_KEPT=0
    REMOVED=0

    for DIR in "${DIRS[@]}"; do
        MANIFEST="${DIR}/manifest.json"
        KEEP=false

        if [ -f "$MANIFEST" ]; then
            TAGS=$(grep -o '"retention_tags"[[:space:]]*:[[:space:]]*\[[^]]*\]' "$MANIFEST" 2>/dev/null || echo "")

            # Check monthly tag
            if echo "$TAGS" | grep "monthly" >/dev/null && [ "$MONTHLY_KEPT" -lt "$KEEP_MONTHLY" ]; then
                KEEP=true
                MONTHLY_KEPT=$((MONTHLY_KEPT + 1))
            fi

            # Check weekly tag
            if echo "$TAGS" | grep "weekly" >/dev/null && [ "$WEEKLY_KEPT" -lt "$KEEP_WEEKLY" ]; then
                KEEP=true
                WEEKLY_KEPT=$((WEEKLY_KEPT + 1))
            fi

            # Daily: keep N most recent
            if [ "$DAILY_KEPT" -lt "$KEEP_DAILY" ]; then
                KEEP=true
                DAILY_KEPT=$((DAILY_KEPT + 1))
            fi
        else
            # No manifest — keep if within daily limit
            if [ "$DAILY_KEPT" -lt "$KEEP_DAILY" ]; then
                KEEP=true
                DAILY_KEPT=$((DAILY_KEPT + 1))
            fi
        fi

        if [ "$KEEP" = false ]; then
            log "  Removing: $(basename "$DIR")"
            rm -rf "$DIR"
            REMOVED=$((REMOVED + 1))
        fi
    done

    log "  Pruned $REMOVED of $TOTAL backups"
}

[[ "${BASH_SOURCE[0]}" == "$0" ]] || return 0

# Main
MODE="${1:---full}"

case "$MODE" in
    --full)
        do_full_backup
        ;;
    --verify)
        do_verify
        ;;
    --list)
        do_list
        ;;
    --prune)
        do_prune
        ;;
    *)
        echo "Usage: $0 [--full|--verify|--list|--prune]"
        exit 1
        ;;
esac
