#!/bin/bash
# Chronicle Disaster Recovery Script
# Guided restoration from encrypted backups.
#
# Usage:
#   ./restore-chronicle.sh <backup-directory> [encryption-key-file]
#
# Examples:
#   ./restore-chronicle.sh /opt/chronicle/backups/20260225_020000
#   ./restore-chronicle.sh /opt/chronicle/backups/20260225_020000 /path/to/backup-key
#
# This script will:
#   1. Verify backup integrity (checksums)
#   2. Decrypt and restore config/secrets
#   3. Start postgres only
#   4. Decrypt and restore database
#   5. Restore TDE keyring
#   6. Re-enable TDE encryption
#   7. Restore audit logs when required by the manifest
#   8. Start all services
#   9. Run health checks and quiesce application writers on failure

set -euo pipefail

# shellcheck source=docker/backup-format.sh
source "$(dirname "${BASH_SOURCE[0]}")/backup-format.sh"
umask 077

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEFAULT_KEY="/etc/chronicle/backup-encryption-key"
COMPOSE_FILE="${SCRIPT_DIR}/docker-compose.traefik.yml"
COMPOSE_PROD_FILE="${SCRIPT_DIR}/docker-compose.production.yml"
CONTAINER="chronicle-postgres"
DB_USER="chronicle"
DB_NAME="chronicle"
DB_HOST="127.0.0.1"
AUDIT_VOLUME="chronicle_audit_logs"
REQUESTED_AUDIT_VOLUME="${CHRONICLE_AUDIT_VOLUME:-$AUDIT_VOLUME}"
RESTORE_STATE_PARENT="${CHRONICLE_RESTORE_STATE_DIR:-/var/lib/chronicle/restore}"
AUDIT_HELPER_IMAGE="docker.io/library/alpine:3.20.10@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc"
JQ_COMMAND="${CHRONICLE_RESTORE_JQ:-jq}"
TEMP_FILES=()
TEMP_DIRS=()
CONTAINER_DUMP_PATH="/tmp/chronicle-restore-$$-${RANDOM}.dump"
CONTAINER_DUMP_STAGED=false
CONTAINER_KEYRING_ARCHIVE="/tmp/chronicle-keyring-$$-${RANDOM}.tar.gz"
CONTAINER_KEYRING_STAGE="/tmp/chronicle-keyring-stage-$$-${RANDOM}"
CONTAINER_KEYRING_STAGED=false
CONFIG_TRANSACTION_ACTIVE=false
CONFIG_TRANSACTION_ROOT=""
CONFIG_TRANSACTION_ROLLBACK=""
CONFIG_TRANSACTION_TARGETS=()
CONFIG_TRANSACTION_BACKED_UP=()
CONFIG_TRANSACTION_INSTALLED=()
APPLICATION_START_ATTEMPTED=false
MIGRATION_CONTAINER="chronicle-restore-migrate-$$"
MIGRATION_RUN_ACTIVE=false
RESTORE_LOCK_DIR=""
RESTORE_LOCK_HELD=false
RESTORE_RUN_DIR=""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
NC='\033[0m'

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"; }
log_ok() { echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] ${GREEN}OK${NC} $*"; }
log_err() { echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] ${RED}ERROR${NC} $*" >&2; }
log_warn() { echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] ${YELLOW}WARN${NC} $*"; }
log_step() { echo -e "\n${BOLD}=== Step $1: $2 ===${NC}"; }

prepare_restore_workspace() {
    if [[ "$RESTORE_STATE_PARENT" != /* ]] \
        || [ "$RESTORE_STATE_PARENT" = / ] \
        || [ "$RESTORE_STATE_PARENT" = /tmp ] \
        || [ "$RESTORE_STATE_PARENT" = /var/tmp ] \
        || [ -L "$RESTORE_STATE_PARENT" ]; then
        log_err "Restore state directory must be an absolute, dedicated, non-temporary path"
        return 1
    fi
    if ! mkdir -p "$RESTORE_STATE_PARENT" \
        || ! chmod 700 "$RESTORE_STATE_PARENT" \
        || [ ! -d "$RESTORE_STATE_PARENT" ] \
        || [ -L "$RESTORE_STATE_PARENT" ] \
        || [ ! -O "$RESTORE_STATE_PARENT" ]; then
        log_err "Restore state directory is not a private operator-owned directory: ${RESTORE_STATE_PARENT}"
        return 1
    fi

    RESTORE_LOCK_DIR="${RESTORE_STATE_PARENT}/active.lock"
    if ! mkdir "$RESTORE_LOCK_DIR" 2>/dev/null; then
        log_err "Another restore may already be active; lock is held at ${RESTORE_LOCK_DIR}"
        return 1
    fi
    RESTORE_LOCK_HELD=true
    if ! chmod 700 "$RESTORE_LOCK_DIR"; then
        log_err "Unable to secure the restore ownership lock"
        return 1
    fi

    if ! RESTORE_RUN_DIR=$(mktemp -d "${RESTORE_STATE_PARENT}/run.XXXXXX"); then
        log_err "Unable to create a private restore workspace"
        return 1
    fi
    if [ -z "$RESTORE_RUN_DIR" ] \
        || [[ "$RESTORE_RUN_DIR" != "${RESTORE_STATE_PARENT}/run."* ]] \
        || [ ! -d "$RESTORE_RUN_DIR" ] \
        || [ -L "$RESTORE_RUN_DIR" ] \
        || [ ! -O "$RESTORE_RUN_DIR" ] \
        || ! chmod 700 "$RESTORE_RUN_DIR"; then
        log_err "Restore workspace is not a validated private directory"
        return 1
    fi
    TEMP_DIRS+=("$RESTORE_RUN_DIR")
    export TMPDIR="$RESTORE_RUN_DIR" TMP="$RESTORE_RUN_DIR" TEMP="$RESTORE_RUN_DIR"
}

resolve_jq() {
    if [[ "$JQ_COMMAND" == */* ]]; then
        if [ ! -x "$JQ_COMMAND" ]; then
            log_err "Required jq executable is unavailable: ${JQ_COMMAND}"
            return 1
        fi
        JQ_BIN="$JQ_COMMAND"
        return 0
    fi

    if ! JQ_BIN=$(command -v "$JQ_COMMAND" 2>/dev/null); then
        log_err "jq is required to validate the recovery manifest"
        return 1
    fi
}

decrypt_file() {
    local src="$1"
    local dst="$2"
    openssl enc -aes-256-cbc -d -salt -pbkdf2 -iter "$BACKUP_PBKDF2_ITERATIONS" \
        -in "$src" -out "$dst" -pass "file:${KEY_FILE}" 2>/dev/null
}

sha256() {
    sha256sum "$1" | awk '{print $1}'
}

ARCHIVE_LISTING=""
validate_archive_member_paths() {
    local archive="$1"
    local label="$2"
    local member
    local normalized_member
    local seen_member
    local verbose_listing
    local verbose_entry
    local -a seen_members=()

    ARCHIVE_LISTING=$(mktemp)
    TEMP_FILES+=("$ARCHIVE_LISTING")
    if ! tar -tzf "$archive" > "$ARCHIVE_LISTING" 2>/dev/null || [ ! -s "$ARCHIVE_LISTING" ]; then
        log_err "${label} archive is unreadable or empty"
        return 1
    fi

    verbose_listing=$(mktemp)
    TEMP_FILES+=("$verbose_listing")
    if ! tar -tvzf "$archive" > "$verbose_listing" 2>/dev/null || [ ! -s "$verbose_listing" ]; then
        log_err "${label} archive metadata is unreadable"
        return 1
    fi
    while IFS= read -r verbose_entry || [ -n "$verbose_entry" ]; do
        case "${verbose_entry:0:1}" in
            -|d) ;;
            *)
                log_err "${label} archive contains a link or unsupported member type"
                return 1
                ;;
        esac
    done < "$verbose_listing"

    while IFS= read -r member || [ -n "$member" ]; do
        [ -n "$member" ] || continue
        if [[ "$member" == /* \
            || "$member" == ".." \
            || "$member" == ../* \
            || "$member" == */../* \
            || "$member" == */.. ]]; then
            log_err "${label} archive contains an unsafe member path: ${member}"
            return 1
        fi
        if printf '%s' "$member" | LC_ALL=C grep -q '[[:cntrl:]]'; then
            log_err "${label} archive contains a control character in a member path"
            return 1
        fi
        normalized_member="${member#./}"
        normalized_member="${normalized_member%/}"
        [ -n "$normalized_member" ] || continue
        for seen_member in ${seen_members[@]+"${seen_members[@]}"}; do
            if [ "$seen_member" = "$normalized_member" ]; then
                log_err "${label} archive contains a duplicate member path: ${normalized_member}"
                return 1
            fi
        done
        seen_members+=("$normalized_member")
    done < "$ARCHIVE_LISTING"
}

extract_validated_archive() {
    local archive="$1"
    local stage="$2"
    local label="$3"
    local unsupported_entry

    if ! validate_archive_member_paths "$archive" "$label"; then
        return 1
    fi
    if ! tar -xzf "$archive" -C "$stage" --no-same-owner --no-same-permissions; then
        log_err "${label} archive extraction failed during preflight"
        return 1
    fi
    unsupported_entry=$(find "$stage" -mindepth 1 ! -type d ! -type f -print -quit)
    if [ -n "$unsupported_entry" ]; then
        log_err "${label} archive contains a link or unsupported entry: ${unsupported_entry#"$stage"/}"
        return 1
    fi
}

validate_config_stage() {
    local stage="$1"
    local env_name="$2"
    local entry
    local relative

    for required_config in \
        "$env_name" \
        rhizome-docker.yaml \
        chronicle-auth.yaml \
        postgres-ssl/server/server.crt \
        postgres-ssl/server/server.key \
        postgres-ssl/ca/ca.crt \
        postgres-ssl/pg_hba-ssl.conf; do
        if [ ! -s "${stage}/${required_config}" ] || [ ! -f "${stage}/${required_config}" ]; then
            log_err "Config archive is missing required regular file: ${required_config}"
            return 1
        fi
    done

    while IFS= read -r -d '' entry; do
        relative="${entry#"$stage"/}"
        if [ -d "$entry" ]; then
            case "$relative" in
                postgres-ssl|postgres-ssl/server|postgres-ssl/ca|postgres-ssl/client) ;;
                *)
                    log_err "Config archive contains an unexpected directory: ${relative}"
                    return 1
                    ;;
            esac
        else
            case "$relative" in
                "$env_name"|rhizome-docker.yaml|chronicle-auth.yaml \
                    |postgres-ssl/server/server.crt \
                    |postgres-ssl/server/server.key \
                    |postgres-ssl/ca/ca.crt \
                    |postgres-ssl/ca/ca.srl \
                    |postgres-ssl/client/client.crt \
                    |postgres-ssl/client/client.key \
                    |postgres-ssl/pg_hba-ssl.conf \
                    |postgres-ssl/postgresql-ssl.conf) ;;
                *)
                    log_err "Config archive contains an unexpected file: ${relative}"
                    return 1
                    ;;
            esac
        fi
    done < <(find "$stage" -mindepth 1 -print0)
}

rollback_config_transaction() {
    local rollback_failed=false
    local target
    local index

    [ "$CONFIG_TRANSACTION_ACTIVE" = true ] || return 0

    index=0
    [ -z "${CONFIG_TRANSACTION_INSTALLED+x}" ] || index=${#CONFIG_TRANSACTION_INSTALLED[@]}
    while [ "$index" -gt 0 ]; do
        index=$((index - 1))
        target="${CONFIG_TRANSACTION_INSTALLED[$index]}"
        case "$target" in
            .env.production.local|rhizome-docker.yaml|chronicle-auth.yaml)
                rm -f -- "${SCRIPT_DIR}/${target}" || rollback_failed=true
                ;;
            postgres-ssl)
                rm -rf -- "${SCRIPT_DIR}/postgres-ssl" || rollback_failed=true
                ;;
            *)
                log_err "Refusing rollback of unexpected config target: ${target}"
                rollback_failed=true
                ;;
        esac
    done

    index=0
    [ -z "${CONFIG_TRANSACTION_BACKED_UP+x}" ] || index=${#CONFIG_TRANSACTION_BACKED_UP[@]}
    while [ "$index" -gt 0 ]; do
        index=$((index - 1))
        target="${CONFIG_TRANSACTION_BACKED_UP[$index]}"
        if ! mv "${CONFIG_TRANSACTION_ROLLBACK}/${target}" "${SCRIPT_DIR}/${target}"; then
            log_err "Unable to roll back config target: ${target}"
            rollback_failed=true
        fi
    done

    if [ "$rollback_failed" = true ]; then
        log_err "Config rollback is incomplete; preserving rollback material at ${CONFIG_TRANSACTION_ROLLBACK}"
        return 1
    fi
    CONFIG_TRANSACTION_ACTIVE=false
    CONFIG_TRANSACTION_BACKED_UP=()
    CONFIG_TRANSACTION_INSTALLED=()
    return 0
}

restore_validated_config() {
    local source_stage="$1"
    local env_name="$2"
    local install_stage
    local target
    local existing_target

    if ! install_stage=$(mktemp -d "${SCRIPT_DIR}/.chronicle-config-install.XXXXXX"); then
        log_err "Unable to create a config installation stage"
        return 1
    fi
    if [ -z "$install_stage" ] \
        || [[ "$install_stage" != "${SCRIPT_DIR}/.chronicle-config-install."* ]] \
        || [ ! -d "$install_stage" ] \
        || [ -L "$install_stage" ]; then
        log_err "Config installation stage is not a validated private directory"
        return 1
    fi
    TEMP_DIRS+=("$install_stage")
    CONFIG_TRANSACTION_ROOT="$install_stage"
    CONFIG_TRANSACTION_ROLLBACK="${install_stage}/rollback"
    CONFIG_TRANSACTION_TARGETS=(.env.production.local rhizome-docker.yaml chronicle-auth.yaml postgres-ssl)
    CONFIG_TRANSACTION_BACKED_UP=()
    CONFIG_TRANSACTION_INSTALLED=()

    if ! mkdir -p "$CONFIG_TRANSACTION_ROLLBACK" \
        || ! cp "${source_stage}/${env_name}" "${install_stage}/.env.production.local" \
        || ! cp "${source_stage}/rhizome-docker.yaml" "${install_stage}/rhizome-docker.yaml" \
        || ! cp "${source_stage}/chronicle-auth.yaml" "${install_stage}/chronicle-auth.yaml" \
        || ! cp -a "${source_stage}/postgres-ssl" "${install_stage}/postgres-ssl" \
        || ! chmod 600 "${install_stage}/.env.production.local" \
            "${install_stage}/rhizome-docker.yaml" \
            "${install_stage}/chronicle-auth.yaml" \
        || ! find "${install_stage}/postgres-ssl" -type d -exec chmod 700 {} + \
        || ! find "${install_stage}/postgres-ssl" -type f -exec chmod 600 {} +; then
        log_err "Unable to prepare the validated config installation stage"
        return 1
    fi

    CONFIG_TRANSACTION_ACTIVE=true
    for target in ${CONFIG_TRANSACTION_TARGETS[@]+"${CONFIG_TRANSACTION_TARGETS[@]}"}; do
        existing_target="${SCRIPT_DIR}/${target}"
        if [ -e "$existing_target" ] || [ -L "$existing_target" ]; then
            if ! mv "$existing_target" "${CONFIG_TRANSACTION_ROLLBACK}/${target}"; then
                log_err "Unable to stage existing config for replacement: ${target}"
                if ! rollback_config_transaction; then
                    log_err "Immediate config rollback failed"
                fi
                return 1
            fi
            CONFIG_TRANSACTION_BACKED_UP+=("$target")
        fi
    done

    for target in ${CONFIG_TRANSACTION_TARGETS[@]+"${CONFIG_TRANSACTION_TARGETS[@]}"}; do
        if ! mv "${install_stage}/${target}" "${SCRIPT_DIR}/${target}"; then
            log_err "Unable to install restored config atomically: ${target}"
            if ! rollback_config_transaction; then
                log_err "Immediate config rollback failed"
            fi
            return 1
        fi
        CONFIG_TRANSACTION_INSTALLED+=("$target")
    done

    if ! rm -rf -- "$CONFIG_TRANSACTION_ROLLBACK"; then
        log_err "Unable to remove config rollback material"
        if ! rollback_config_transaction; then
            log_err "Immediate config rollback failed"
        fi
        return 1
    fi
    CONFIG_TRANSACTION_ACTIVE=false
    CONFIG_TRANSACTION_BACKED_UP=()
    CONFIG_TRANSACTION_INSTALLED=()
}

compose_cmd() {
    local args=(-p chronicle)
    if [ -n "${CHRONICLE_RESTORE_ENV_FILE:-}" ]; then
        args+=(--env-file "${CHRONICLE_RESTORE_ENV_FILE}")
    elif [ -f "${SCRIPT_DIR}/.env.production.local" ]; then
        args+=(--env-file "${SCRIPT_DIR}/.env.production.local")
    elif [ -f "${SCRIPT_DIR}/.env" ]; then
        args+=(--env-file "${SCRIPT_DIR}/.env")
    fi
    args+=(-f "$COMPOSE_FILE")
    if [ -f "$COMPOSE_PROD_FILE" ]; then
        args+=(-f "$COMPOSE_PROD_FILE")
    fi
    docker compose "${args[@]}" "$@"
}

postgres_exec() {
    docker exec "$CONTAINER" sh -euc \
        'export PGPASSWORD="${POSTGRES_PASSWORD:?POSTGRES_PASSWORD is unavailable}"; exec "$@"' \
        chronicle-postgres-command "$@"
}

preflight_migration_runner() {
    # migrate reads the superuser password from the copy backend-secrets-init stages from the
    # (now restored) secret files; --no-deps would otherwise skip that step.
    compose_cmd run --rm --no-deps backend-secrets-init >/dev/null || return 1
    compose_cmd run --rm --no-deps --entrypoint /bin/sh migrate -euc '
        test -x /opt/java/openjdk/bin/java
        test -r /app/ssl/ca.crt
        test -r "${POSTGRES_MIGRATION_PASSWORD_FILE:-/run/secrets/postgres_password}" || test -n "${POSTGRES_PASSWORD:-}"
        found=false
        for archive in /server/lib/*; do
            case "$archive" in
                *chronicle-server*) found=true; break ;;
            esac
        done
        test "$found" = true
    ' chronicle-migration-preflight >/dev/null
}

run_flyway_migrations() {
    MIGRATION_RUN_ACTIVE=true
    if ! compose_cmd run --rm --no-deps --name "$MIGRATION_CONTAINER" \
        migrate; then
        if docker rm -f "$MIGRATION_CONTAINER" >/dev/null 2>&1; then
            MIGRATION_RUN_ACTIVE=false
        fi
        return 1
    fi
    MIGRATION_RUN_ACTIVE=false
}

application_containers=(
    edge-traefik
    chronicle-backend
    chronicle-frontend
    chronicle-preprocessing-frontend
)

application_container_state() {
    local container_name="$1"
    local state

    if ! state=$(docker container ls --all \
        --filter "name=^/${container_name}$" \
        --format '{{.State}}' 2>/dev/null); then
        log_err "Unable to query application container state: ${container_name}"
        return 1
    fi
    if [[ "$state" == *$'\n'* ]]; then
        log_err "Container state query was ambiguous: ${container_name}"
        return 1
    fi
    printf '%s\n' "$state"
}

verify_application_writers_stopped() {
    local container_name
    local running_state
    for container_name in "${application_containers[@]}"; do
        if ! running_state=$(application_container_state "$container_name"); then
            return 1
        fi
        case "$running_state" in
            ""|created|exited|dead) ;;
            *)
                log_err "Application container is not safely stopped: ${container_name} (${running_state})"
                return 1
                ;;
        esac
    done
}

quiesce_application_services() {
    local compose_stop_ok=true
    local container_name
    local running_state

    if ! compose_cmd stop traefik chronicle-backend chronicle-frontend chronicle-preprocessing-frontend; then
        compose_stop_ok=false
    fi
    for container_name in "${application_containers[@]}"; do
        if ! running_state=$(application_container_state "$container_name"); then
            compose_stop_ok=false
            continue
        fi
        case "$running_state" in
          running|restarting|paused)
            docker stop "$container_name" >/dev/null 2>&1 || compose_stop_ok=false
            ;;
        esac
    done
    if verify_application_writers_stopped && [ "$compose_stop_ok" = true ]; then
        APPLICATION_START_ATTEMPTED=false
        return 0
    fi
    return 1
}

wait_for_container_health() {
    local container_name="$1"
    local health_label="$2"
    local health_state="missing"
    local attempt

    for attempt in $(seq 1 30); do
        health_state=$(docker inspect "$container_name" \
            --format='{{if .State.Health}}{{.State.Health.Status}}{{else}}missing{{end}}' \
            2>/dev/null || echo "missing")
        if [ "$health_state" = "healthy" ]; then
            log_ok "${health_label} healthcheck passed"
            return 0
        fi
        [ "$attempt" -eq 30 ] || sleep 5
    done
    log_err "${health_label} healthcheck failed: ${health_state}"
    return 1
}

verify_current_encryption() {
    local phase="$1"
    local encryption_counts
    local current_table_count
    local tde_table_count
    local plain_table_count

    if ! encryption_counts=$(postgres_exec \
        psql -v ON_ERROR_STOP=1 -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" -t -A -F '|' -c "
        SELECT COUNT(*) AS total_tables,
               COUNT(*) FILTER (WHERE am.amname = 'tde_heap') AS tde_tables,
               COUNT(*) FILTER (WHERE am.amname <> 'tde_heap') AS plain_tables
          FROM pg_class c
          JOIN pg_am am ON c.relam = am.oid
         WHERE c.relkind = 'r'
           AND c.relnamespace = (SELECT oid FROM pg_namespace WHERE nspname = 'public');
    " 2>/dev/null); then
        log_err "${phase} encryption inventory query failed"
        return 1
    fi
    IFS='|' read -r current_table_count tde_table_count plain_table_count <<< "$encryption_counts"
    if [[ ! "$current_table_count" =~ ^[1-9][0-9]*$ ]] \
        || [[ ! "$tde_table_count" =~ ^[0-9]+$ ]] \
        || [[ ! "$plain_table_count" =~ ^[0-9]+$ ]] \
        || [ "$tde_table_count" -ne "$current_table_count" ] \
        || [ "$plain_table_count" -ne 0 ]; then
        log_err "${phase} TDE postcondition failed: total='${current_table_count:-no result}', encrypted='${tde_table_count:-no result}', plain='${plain_table_count:-no result}'"
        return 1
    fi
    log_ok "${phase} encryption inventory: ${tde_table_count}/${current_table_count} public tables use tde_heap"
}

verify_tde_key_contract() {
    local phase="$1"
    local configured_provider
    local key_state
    local key_name
    local provider_name
    local provider_type
    local expected_provider_type

    if ! configured_provider=$(docker exec "$CONTAINER" sh -euc \
        'printf "%s\n" "${PG_TDE_KEY_PROVIDER:?PG_TDE_KEY_PROVIDER is unavailable}"' 2>/dev/null); then
        log_err "${phase} TDE provider environment is unavailable"
        return 1
    fi
    if [ "$configured_provider" != "$EXPECTED_TDE_PROVIDER" ]; then
        log_err "${phase} TDE provider mismatch: configured '${configured_provider}', expected '${EXPECTED_TDE_PROVIDER}'"
        return 1
    fi
    case "$EXPECTED_TDE_PROVIDER" in
        file) expected_provider_type="file" ;;
        vault) expected_provider_type="vault-v2" ;;
        *)
            log_err "${phase} TDE provider contract is unsupported: ${EXPECTED_TDE_PROVIDER}"
            return 1
            ;;
    esac
    if ! key_state=$(postgres_exec psql -X -v ON_ERROR_STOP=1 -qAt -P pager=off \
        -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" -F '|' -c "
        SELECT key_info.key_name, key_info.provider_name, provider.type
          FROM pg_tde_key_info() AS key_info
          JOIN pg_tde_list_all_database_key_providers() AS provider
            ON provider.name = key_info.provider_name;
    " 2>/dev/null); then
        log_err "${phase} TDE principal-key query failed"
        return 1
    fi
    IFS='|' read -r key_name provider_name provider_type <<< "$key_state"
    if [ "$key_name" != "$EXPECTED_TDE_KEY_NAME" ] \
        || [ "$provider_name" != "$EXPECTED_TDE_PROVIDER_NAME" ] \
        || [ "$provider_type" != "$expected_provider_type" ]; then
        log_err "${phase} TDE principal-key contract mismatch"
        return 1
    fi
    if ! postgres_exec psql -X -v ON_ERROR_STOP=1 -qAt -P pager=off \
        -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" \
        -c "SELECT pg_tde_verify_key();" >/dev/null; then
        log_err "${phase} TDE principal key could not be retrieved and verified"
        return 1
    fi
    log_ok "${phase} TDE key contract verified (${EXPECTED_TDE_PROVIDER}/${EXPECTED_TDE_PROVIDER_NAME}/${EXPECTED_TDE_KEY_NAME})"
}

verify_restored_data_readable() {
    if ! postgres_exec \
        psql -v ON_ERROR_STOP=1 -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" -t -A -c "
        SELECT (SELECT COUNT(*) FROM studies)
             + (SELECT COUNT(*) FROM study_participants)
             + (SELECT COUNT(*) FROM candidates)
             + (SELECT COUNT(*) FROM devices) AS restore_data_read_proof;
    " >/dev/null; then
        log_err "Restored-data read proof failed"
        return 1
    fi
    log_ok "Restored-data read proof passed"
}

verify_replica_streaming() {
    local primary_streams
    local replica_recovery

    if ! primary_streams=$(postgres_exec psql -X -v ON_ERROR_STOP=1 -qAt -P pager=off \
        -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" \
        -c "SELECT count(*) FROM pg_stat_replication WHERE state = 'streaming';" 2>/dev/null); then
        log_err "Primary replication-state query failed"
        return 1
    fi
    if [[ ! "$primary_streams" =~ ^[1-9][0-9]*$ ]]; then
        log_err "No streaming PostgreSQL replica is attached to the restored primary"
        return 1
    fi
    if ! replica_recovery=$(docker exec chronicle-postgres-replica sh -euc '
        export PGPASSWORD="${POSTGRES_PASSWORD:?POSTGRES_PASSWORD is unavailable}"
        exec psql -X -v ON_ERROR_STOP=1 -qAt -P pager=off \
          -h 127.0.0.1 -U "${POSTGRES_USER:-chronicle}" -d "${POSTGRES_DB:-chronicle}" \
          -c "SELECT pg_is_in_recovery() AND pg_last_wal_replay_lsn() IS NOT NULL;"
    ' 2>/dev/null); then
        log_err "Replica recovery-state query failed"
        return 1
    fi
    if [ "$replica_recovery" != t ]; then
        log_err "PostgreSQL replica is not replaying WAL as a standby"
        return 1
    fi
    log_ok "PostgreSQL replica is attached and replaying WAL"
}

capture_flyway_contract() {
    local phase="$1"
    local summary
    local history_file

    if ! summary=$(postgres_exec psql -X -v ON_ERROR_STOP=1 -qAt -P pager=off \
        -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" -F '|' -c "
        SELECT
          COALESCE(max(version::int)
            FILTER (WHERE success AND version ~ '^[0-9]+$'), 0),
          max(version::int)
            FILTER (WHERE success AND type = 'BASELINE' AND version ~ '^[0-9]+$'),
          count(*) FILTER (WHERE success),
          count(*) FILTER (WHERE NOT success),
          count(*) FILTER (WHERE version IS NOT NULL AND version !~ '^[0-9]+$')
        FROM public.flyway_schema_history;
    " 2>/dev/null); then
        log_err "${phase} Flyway summary query failed"
        return 1
    fi
    IFS='|' read -r ACTUAL_FLYWAY_MAX ACTUAL_FLYWAY_BASELINE \
        ACTUAL_FLYWAY_SUCCESSFUL ACTUAL_FLYWAY_FAILED ACTUAL_FLYWAY_INVALID <<< "$summary"
    if [[ ! "$ACTUAL_FLYWAY_MAX" =~ ^[1-9][0-9]*$ ]] \
        || [[ ! "$ACTUAL_FLYWAY_SUCCESSFUL" =~ ^[1-9][0-9]*$ ]] \
        || [[ ! "$ACTUAL_FLYWAY_FAILED" =~ ^[0-9]+$ ]] \
        || [[ ! "$ACTUAL_FLYWAY_INVALID" =~ ^[0-9]+$ ]] \
        || { [ -n "$ACTUAL_FLYWAY_BASELINE" ] && [[ ! "$ACTUAL_FLYWAY_BASELINE" =~ ^[0-9]+$ ]]; } \
        || [ "$ACTUAL_FLYWAY_FAILED" -ne 0 ] \
        || [ "$ACTUAL_FLYWAY_INVALID" -ne 0 ]; then
        log_err "${phase} Flyway summary is invalid: '${summary:-no result}'"
        return 1
    fi
    [ -n "$ACTUAL_FLYWAY_BASELINE" ] || ACTUAL_FLYWAY_BASELINE=null

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
        log_err "${phase} Flyway history query failed"
        return 1
    fi
    if [ ! -s "$history_file" ]; then
        log_err "${phase} Flyway history is empty"
        return 1
    fi
    if ! ACTUAL_FLYWAY_SHA256=$(sha256 "$history_file"); then
        log_err "${phase} Flyway history fingerprint failed"
        return 1
    fi
}

verify_restored_flyway_contract() {
    if ! capture_flyway_contract "Restored"; then
        return 1
    fi
    if { [ "$ACTUAL_FLYWAY_MAX" != "$EXPECTED_FLYWAY_MAX" ] \
            || [ "$ACTUAL_FLYWAY_BASELINE" != "$EXPECTED_FLYWAY_BASELINE" ] \
            || [ "$ACTUAL_FLYWAY_SUCCESSFUL" != "$EXPECTED_FLYWAY_SUCCESSFUL" ] \
            || [ "$ACTUAL_FLYWAY_FAILED" != "$EXPECTED_FLYWAY_FAILED" ] \
            || [ "$ACTUAL_FLYWAY_SHA256" != "$EXPECTED_FLYWAY_SHA256" ]; }; then
        log_err "Restored Flyway history does not match the backup manifest"
        return 1
    fi
    log_ok "Restored Flyway history contract verified (max V${ACTUAL_FLYWAY_MAX}, ${ACTUAL_FLYWAY_SUCCESSFUL} successful entries)"
}

cleanup_restore_artifacts() {
    local cleanup_failed=false
    local temp_file
    local temp_dir

    if ! rollback_config_transaction; then
        cleanup_failed=true
    fi

    if [ "$MIGRATION_RUN_ACTIVE" = true ]; then
        if docker rm -f "$MIGRATION_CONTAINER" >/dev/null 2>&1; then
            MIGRATION_RUN_ACTIVE=false
        else
            cleanup_failed=true
        fi
    fi

    if [ "$CONTAINER_DUMP_STAGED" = true ]; then
        if docker exec "$CONTAINER" rm -f "$CONTAINER_DUMP_PATH" >/dev/null 2>&1; then
            CONTAINER_DUMP_STAGED=false
        else
            cleanup_failed=true
        fi
    fi

    if [ "$CONTAINER_KEYRING_STAGED" = true ]; then
        if docker exec -u root "$CONTAINER" sh -euc \
            'rm -f -- "$1"; rm -rf -- "$2"' \
            chronicle-keyring-cleanup "$CONTAINER_KEYRING_ARCHIVE" "$CONTAINER_KEYRING_STAGE" \
            >/dev/null 2>&1; then
            CONTAINER_KEYRING_STAGED=false
        else
            cleanup_failed=true
        fi
    fi

    for temp_file in ${TEMP_FILES[@]+"${TEMP_FILES[@]}"}; do
        if [ -n "$temp_file" ] && [ -e "$temp_file" ] && ! rm -f -- "$temp_file"; then
            cleanup_failed=true
        fi
    done

    for temp_dir in ${TEMP_DIRS[@]+"${TEMP_DIRS[@]}"}; do
        if [ "$CONFIG_TRANSACTION_ACTIVE" = true ] && [ "$temp_dir" = "$CONFIG_TRANSACTION_ROOT" ]; then
            cleanup_failed=true
            continue
        fi
        if [ -n "$temp_dir" ] && [ -e "$temp_dir" ] && ! rm -rf -- "$temp_dir"; then
            cleanup_failed=true
        fi
    done

    if [ "$RESTORE_LOCK_HELD" = true ]; then
        if [ "$cleanup_failed" = false ] && rmdir "$RESTORE_LOCK_DIR"; then
            RESTORE_LOCK_HELD=false
        else
            cleanup_failed=true
            log_err "Preserving restore lock for operator inspection: ${RESTORE_LOCK_DIR}"
        fi
    fi

    [ "$cleanup_failed" = false ]
}

finish_restore() {
    local result_code=$?
    trap - EXIT HUP INT TERM
    if [ "$result_code" -ne 0 ] && [ "$APPLICATION_START_ATTEMPTED" = true ]; then
        if ! quiesce_application_services; then
            log_err "Failed to quiesce application services during abnormal restore exit"
        fi
    fi
    if ! cleanup_restore_artifacts; then
        log_err "Failed to clean one or more restore staging artifacts"
        if [ "$result_code" -eq 0 ]; then
            result_code=1
        fi
    fi
    exit "$result_code"
}

trap finish_restore EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

confirm() {
    local msg="$1"
    echo -e "\n${YELLOW}${msg}${NC}"
    read -rp "Continue? [y/N] " response
    case "$response" in
        [yY][eE][sS]|[yY]) return 0 ;;
        *) return 1 ;;
    esac
}

# Parse arguments
BACKUP_DIR="${1:-}"
KEY_FILE="${2:-$DEFAULT_KEY}"

if [ -z "$BACKUP_DIR" ]; then
    echo "Usage: $0 <backup-directory> [encryption-key-file]"
    echo ""
    echo "Available backups:"
    find /opt/chronicle/backups -mindepth 1 -maxdepth 1 -type d -name '[0-9]*_[0-9]*' -print \
        2>/dev/null | sort -r | while read -r d; do
        echo "  $(basename "$d")"
    done
    exit 1
fi

if [ ! -d "$BACKUP_DIR" ]; then
    log_err "Backup directory not found: $BACKUP_DIR"
    exit 1
fi

if [ ! -f "$KEY_FILE" ]; then
    log_err "Encryption key not found: $KEY_FILE"
    exit 1
fi

if ! prepare_restore_workspace; then
    exit 1
fi

echo ""
echo -e "${BOLD}=========================================="
echo "Chronicle Disaster Recovery"
echo -e "==========================================${NC}"
echo ""
echo "  Backup: $(basename "$BACKUP_DIR")"
echo "  Key:    $KEY_FILE"
echo ""

# ================================================================
log_step 1 "Verify backup integrity"
# ================================================================

MANIFEST_FILE="${BACKUP_DIR}/manifest.json"
if [ ! -f "$MANIFEST_FILE" ] || [ -L "$MANIFEST_FILE" ]; then
    log_err "manifest.json is required for a production restore"
    exit 1
fi
if [ "$REQUESTED_AUDIT_VOLUME" != "$AUDIT_VOLUME" ]; then
    log_err "Audit restore volume must match the Compose-owned volume exactly: ${AUDIT_VOLUME}"
    exit 1
fi

if ! resolve_jq; then
    exit 1
fi

if ! "$JQ_BIN" -e -s 'length == 1' "$MANIFEST_FILE" >/dev/null 2>&1; then
    log_err "Manifest must contain exactly one valid JSON document"
    exit 1
fi
if DUPLICATE_MANIFEST_PATHS=$("$JQ_BIN" --stream -r \
    'select(length == 2) | .[0] | @json' "$MANIFEST_FILE" \
    | LC_ALL=C sort | uniq -d) \
    && [ -n "$DUPLICATE_MANIFEST_PATHS" ]; then
    log_err "Manifest contains duplicate JSON paths"
    exit 1
fi

if ! "$JQ_BIN" --argjson format_version "$BACKUP_MANIFEST_VERSION" -e -s '
    def integer: (type == "number") and (. == floor);
    def common_contract:
      . as $manifest
      | ((.schema_version | integer))
      and (.schema_version == (.schema_version | floor))
      and (.schema_version == $format_version)
      and ((.audit_logs_required | type) == "boolean")
      and ((.table_count | type) == "number")
      and (.table_count == (.table_count | floor))
      and (.table_count > 0)
      and ((.tde_encrypted_tables | type) == "number")
      and (.tde_encrypted_tables == (.tde_encrypted_tables | floor))
      and (.tde_encrypted_tables == .table_count)
      and ((.env_config_file | type) == "string")
      and (.env_config_file | test("^\\.env[A-Za-z0-9._-]*$"))
      and (.env_config_file != "." and .env_config_file != "..")
      and ((.required_artifacts | type) == "array")
      and ((.required_artifacts | length) >= 4 and (.required_artifacts | length) <= 5)
      and ((.required_artifacts | unique | length) == (.required_artifacts | length))
      and all(.required_artifacts[];
          . == "database.dump.enc"
          or . == "tde-keyring.tar.gz.enc"
          or . == "config-secrets.tar.gz.enc"
          or . == "deployment-manifest.tar.gz.enc"
          or . == "audit-logs.tar.gz.enc")
      and all([
          "database.dump.enc",
          "tde-keyring.tar.gz.enc",
          "config-secrets.tar.gz.enc",
          "deployment-manifest.tar.gz.enc"
      ][]; . as $required | ($manifest.required_artifacts | index($required)) != null)
      and ($manifest.audit_logs_required == false
          or ($manifest.required_artifacts | index("audit-logs.tar.gz.enc")) != null)
      and ((.checksums | type) == "object")
      and ((.checksums | keys | sort) == (.required_artifacts | sort))
      and all(.checksums[]; (type == "string") and test("^[a-f0-9]{64}$"))
      and ((.timestamp | type) == "string" and (.timestamp | length > 0))
      and ((.backup_dir | type) == "string" and (.backup_dir | length > 0))
      and ((.database_size | type) == "string")
      and ((.retention_tags | type) == "array")
      and all(.retention_tags[]; type == "string");
    def manifest_keys: [
      "audit_logs_required", "backup_dir", "checksums", "database_size", "env_config_file",
      "required_artifacts", "retention_tags", "schema_version", "table_count", "tde_encrypted_tables",
      "timestamp", "flyway", "tde"
    ];
    length == 1
    and (.[0]
      | common_contract
      and ((keys | sort) == (manifest_keys | sort))
          and ((.flyway | type) == "object")
          and ((.flyway | keys | sort) == ([
              "baseline_version", "failed_entry_count", "history_format",
              "history_sha256", "max_version", "successful_entry_count"
          ] | sort))
          and (.flyway.history_format == "jsonb-array-lines/v1")
          and (.flyway.max_version | integer)
          and (.flyway.max_version > 0)
          and ((.flyway.baseline_version == null)
              or ((.flyway.baseline_version | integer)
                  and (.flyway.baseline_version >= 0)
                  and (.flyway.baseline_version <= .flyway.max_version)))
          and (.flyway.successful_entry_count | integer)
          and (.flyway.successful_entry_count > 0)
          and (.flyway.failed_entry_count | integer)
          and (.flyway.failed_entry_count == 0)
          and ((.flyway.history_sha256 | type) == "string")
          and (.flyway.history_sha256 | test("^[a-f0-9]{64}$"))
          and ((.tde | type) == "object")
          and ((.tde | keys | sort) == ([
              "principal_key_name", "provider", "provider_name"
          ] | sort))
          and (.tde.provider == "file" or .tde.provider == "vault")
          and ((.tde.provider == "file" and .tde.provider_name == "chronicle-file-vault")
              or (.tde.provider == "vault" and .tde.provider_name == "chronicle-vault"))
          and ((.tde.principal_key_name | type) == "string")
          and (.tde.principal_key_name | test("^[A-Za-z0-9._-]+$"))
        )
' "$MANIFEST_FILE" >/dev/null 2>&1; then
    log_err "Manifest JSON or recovery contract is invalid"
    exit 1
fi

echo "  Validated manifest:"
"$JQ_BIN" . "$MANIFEST_FILE" | sed 's/^/    /'
echo ""

EXPECTED_TABLE_COUNT=$("$JQ_BIN" -er '.table_count' "$MANIFEST_FILE")
CONFIG_ENV_NAME=$("$JQ_BIN" -er '.env_config_file' "$MANIFEST_FILE")
AUDIT_LOGS_REQUIRED=$("$JQ_BIN" -r '.audit_logs_required' "$MANIFEST_FILE")
EXPECTED_FLYWAY_SUCCESSFUL=$("$JQ_BIN" -er '.flyway.successful_entry_count' "$MANIFEST_FILE")
EXPECTED_FLYWAY_FAILED=$("$JQ_BIN" -er '.flyway.failed_entry_count' "$MANIFEST_FILE")
EXPECTED_FLYWAY_BASELINE=$("$JQ_BIN" -r '.flyway.baseline_version' "$MANIFEST_FILE")
EXPECTED_FLYWAY_MAX=$("$JQ_BIN" -er '.flyway.max_version' "$MANIFEST_FILE")
EXPECTED_FLYWAY_SHA256=$("$JQ_BIN" -er '.flyway.history_sha256' "$MANIFEST_FILE")
EXPECTED_TDE_PROVIDER=$("$JQ_BIN" -er '.tde.provider' "$MANIFEST_FILE")
EXPECTED_TDE_PROVIDER_NAME=$("$JQ_BIN" -er '.tde.provider_name' "$MANIFEST_FILE")
EXPECTED_TDE_KEY_NAME=$("$JQ_BIN" -er '.tde.principal_key_name' "$MANIFEST_FILE")

REQUIRED_ARTIFACTS=()
while IFS= read -r artifact_name; do
    [ -n "$artifact_name" ] && REQUIRED_ARTIFACTS+=("$artifact_name")
done < <("$JQ_BIN" -er '.required_artifacts[]' "$MANIFEST_FILE")

artifact_is_declared() {
    local expected_artifact="$1"
    local declared_artifact
    for declared_artifact in "${REQUIRED_ARTIFACTS[@]}"; do
        [ "$declared_artifact" = "$expected_artifact" ] && return 0
    done
    return 1
}

for required_base_artifact in \
    database.dump.enc \
    tde-keyring.tar.gz.enc \
    config-secrets.tar.gz.enc \
    deployment-manifest.tar.gz.enc; do
    if ! artifact_is_declared "$required_base_artifact"; then
        log_err "Manifest does not declare required recovery artifact: ${required_base_artifact}"
        exit 1
    fi
done
if [ "$AUDIT_LOGS_REQUIRED" = true ] && ! artifact_is_declared audit-logs.tar.gz.enc; then
    log_err "Manifest requires audit logs but does not declare audit-logs.tar.gz.enc"
    exit 1
fi

for FNAME in "${REQUIRED_ARTIFACTS[@]}"; do
    F="${BACKUP_DIR}/${FNAME}"
    if [ ! -s "$F" ]; then
        log_err "Required recovery artifact is missing or empty: ${FNAME}"
        exit 1
    fi
    EXPECTED=$("$JQ_BIN" -er --arg artifact "$FNAME" '.checksums[$artifact]' "$MANIFEST_FILE")
    if [[ ! "$EXPECTED" =~ ^[a-f0-9]{64}$ ]]; then
        log_err "Required recovery artifact has no valid manifest checksum: ${FNAME}"
        exit 1
    fi
    ACTUAL=$(sha256 "$F")
    if [ "$ACTUAL" != "$EXPECTED" ]; then
        log_err "${FNAME} checksum MISMATCH"
        exit 1
    fi
    log_ok "${FNAME} checksum OK"
done

KEYRING_TMP=$(mktemp)
TEMP_FILES+=("$KEYRING_TMP")
KEYRING_PREFLIGHT_DIR=$(mktemp -d)
TEMP_DIRS+=("$KEYRING_PREFLIGHT_DIR")
if ! decrypt_file "${BACKUP_DIR}/tde-keyring.tar.gz.enc" "$KEYRING_TMP" \
    || ! extract_validated_archive "$KEYRING_TMP" "$KEYRING_PREFLIGHT_DIR" "TDE keyring" \
    || [ ! -d "${KEYRING_PREFLIGHT_DIR}/tde-keyring" ]; then
    log_err "TDE keyring archive validation failed before database replacement"
    exit 1
fi
if [ "$EXPECTED_TDE_PROVIDER" = file ] \
    && [ -z "$(find "${KEYRING_PREFLIGHT_DIR}/tde-keyring" -type f -name '*.per' -size +0c -print -quit)" ]; then
    log_err "File-provider TDE backup lacks regular key material"
    exit 1
fi
log_ok "TDE keyring archive matches ${EXPECTED_TDE_PROVIDER} provider requirements"

CONFIG_TMP=$(mktemp)
TEMP_FILES+=("$CONFIG_TMP")
CONFIG_PREFLIGHT_DIR=$(mktemp -d)
TEMP_DIRS+=("$CONFIG_PREFLIGHT_DIR")
if ! decrypt_file "${BACKUP_DIR}/config-secrets.tar.gz.enc" "$CONFIG_TMP" \
    || ! extract_validated_archive "$CONFIG_TMP" "$CONFIG_PREFLIGHT_DIR" "Config" \
    || ! validate_config_stage "$CONFIG_PREFLIGHT_DIR" "$CONFIG_ENV_NAME"; then
    log_err "Config archive validation failed before database replacement"
    exit 1
fi
log_ok "Config archive decrypts and matches the allowlisted restore shape"

DEPLOYMENT_TMP=$(mktemp)
TEMP_FILES+=("$DEPLOYMENT_TMP")
DEPLOYMENT_PREFLIGHT_DIR=$(mktemp -d)
TEMP_DIRS+=("$DEPLOYMENT_PREFLIGHT_DIR")
if ! decrypt_file "${BACKUP_DIR}/deployment-manifest.tar.gz.enc" "$DEPLOYMENT_TMP" \
    || ! extract_validated_archive "$DEPLOYMENT_TMP" "$DEPLOYMENT_PREFLIGHT_DIR" "Deployment evidence" \
    || [ ! -s "${DEPLOYMENT_PREFLIGHT_DIR}/deployment/deployment-manifest.json" ] \
    || [ ! -f "${DEPLOYMENT_PREFLIGHT_DIR}/deployment/git-status.txt" ] \
    || [ ! -f "${DEPLOYMENT_PREFLIGHT_DIR}/deployment/git-submodules.txt" ] \
    || [ ! -s "${DEPLOYMENT_PREFLIGHT_DIR}/docker/docker-compose.traefik.yml" ] \
    || [ ! -s "${DEPLOYMENT_PREFLIGHT_DIR}/docker/docker-compose.production.yml" ] \
    || [ ! -s "${DEPLOYMENT_PREFLIGHT_DIR}/deploy/cue/profiles.cue" ]; then
    log_err "Deployment evidence validation failed before database replacement"
    exit 1
fi
DEPLOYMENT_MANIFEST_FILE="${DEPLOYMENT_PREFLIGHT_DIR}/deployment/deployment-manifest.json"
if ! "$JQ_BIN" -e -s 'length == 1' "$DEPLOYMENT_MANIFEST_FILE" >/dev/null 2>&1; then
    log_err "Deployment evidence manifest must contain exactly one JSON document"
    exit 1
fi
if DUPLICATE_DEPLOYMENT_PATHS=$("$JQ_BIN" --stream -r \
    'select(length == 2) | .[0] | @json' "$DEPLOYMENT_MANIFEST_FILE" \
    | LC_ALL=C sort | uniq -d) \
    && [ -n "$DUPLICATE_DEPLOYMENT_PATHS" ]; then
    log_err "Deployment evidence manifest contains duplicate JSON paths"
    exit 1
fi
if ! "$JQ_BIN" --argjson format_version "$BACKUP_MANIFEST_VERSION" -e -s --arg env_name "$CONFIG_ENV_NAME" '
        length == 1 and (.[0]
        | ((keys | sort) == ([
            "compose_files", "env_config_file", "git_branch", "git_commit",
            "git_dirty", "kubernetes_profile_source", "schema_version", "timestamp"
        ] | sort))
        and (.schema_version == $format_version)
        and ((.timestamp | type) == "string" and (.timestamp | length > 0))
        and ((.git_commit | type) == "string")
        and (.git_commit == "unknown" or (.git_commit | test("^[a-f0-9]{40}([a-f0-9]{24})?$")))
        and ((.git_branch | type) == "string" and (.git_branch | length > 0))
        and ((.git_dirty | type) == "boolean")
        and (.env_config_file == $env_name)
        and ((.compose_files | type) == "array")
        and ((.compose_files | unique | sort) == ([
            "docker/docker-compose.production.yml",
            "docker/docker-compose.traefik.yml"
        ] | sort))
        and all(.compose_files[]; type == "string")
        and (.kubernetes_profile_source == "deploy/cue/profiles.cue"))
    ' "$DEPLOYMENT_MANIFEST_FILE" >/dev/null 2>&1; then
    log_err "Deployment evidence validation failed before database replacement"
    exit 1
fi
log_ok "Deployment evidence decrypts and contains a valid deployment manifest"

AUDIT_TMP=""
if artifact_is_declared audit-logs.tar.gz.enc; then
    AUDIT_TMP=$(mktemp)
    TEMP_FILES+=("$AUDIT_TMP")
    if ! decrypt_file "${BACKUP_DIR}/audit-logs.tar.gz.enc" "$AUDIT_TMP" \
        || ! validate_archive_member_paths "$AUDIT_TMP" "Audit log" \
        || ! grep -Eq '^(\./)?chronicle(/|$)' "$ARCHIVE_LISTING"; then
        log_err "Audit log archive validation failed before database replacement"
        exit 1
    fi
    if ! docker image inspect "$AUDIT_HELPER_IMAGE" >/dev/null 2>&1; then
        log_err "Pinned audit restore helper image is unavailable locally: ${AUDIT_HELPER_IMAGE}"
        exit 1
    fi
    if ! docker run --rm --pull=never --network=none --read-only \
        --security-opt=no-new-privileges \
        "$AUDIT_HELPER_IMAGE" \
        sh -euc 'command -v tar >/dev/null; command -v find >/dev/null; command -v mv >/dev/null; command -v chmod >/dev/null' \
        chronicle-audit-helper-preflight >/dev/null; then
        log_err "Pinned audit restore helper image failed its executable preflight"
        exit 1
    fi
    log_ok "Audit log archive decrypts and is readable"
    log_ok "Pinned audit restore helper image is available"
fi

if [ ! -x "${SCRIPT_DIR}/migrate-tde.sh" ]; then
    log_err "migrate-tde.sh is missing or not executable; refusing recovery before database replacement"
    exit 1
fi

log_ok "All required artifacts and manifest postconditions verified"

# ================================================================
log_step 2 "Restore config and secrets"
# ================================================================

if confirm "This will replace the active env/config files and validated postgres-ssl/ content in ${SCRIPT_DIR}"; then
    if ! restore_validated_config "$CONFIG_PREFLIGHT_DIR" "$CONFIG_ENV_NAME"; then
        log_err "Validated config could not be installed; existing files were rolled back"
        exit 1
    fi
    log_ok "Config and secrets restored to ${SCRIPT_DIR}"
    log_ok "Production env restored as .env.production.local"
else
    log_warn "Skipped config restore (using existing config files)"
fi

if ! preflight_migration_runner; then
    log_err "One-shot Flyway migration runner preflight failed before database replacement"
    exit 1
fi
log_ok "One-shot Flyway migration runner is available"

# ================================================================
log_step 3 "Stop all services and start postgres only"
# ================================================================

if confirm "This will stop all Chronicle services and drop/recreate the database"; then
    log "Stopping all services..."
    if ! compose_cmd down; then
        log_err "Unable to stop all Chronicle services; refusing database replacement"
        exit 1
    fi
    if ! verify_application_writers_stopped; then
        log_err "Service shutdown could not be verified; refusing database replacement"
        exit 1
    fi

    log "Starting postgres only..."
    compose_cmd up -d postgres
    log "Waiting for postgres to be healthy..."
    for i in $(seq 1 30); do
        if docker exec "$CONTAINER" pg_isready -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" >/dev/null 2>&1; then
            log_ok "PostgreSQL is ready"
            break
        fi
        if [ "$i" -eq 30 ]; then
            log_err "PostgreSQL did not become ready in time"
            exit 1
        fi
        sleep 2
    done
else
    log_err "Recovery cancelled"
    exit 1
fi

# ================================================================
log_step 4 "Restore database"
# ================================================================

log "Decrypting database dump..."
DUMP_TMP=$(mktemp)
TEMP_FILES+=("$DUMP_TMP")
decrypt_file "${BACKUP_DIR}/database.dump.enc" "$DUMP_TMP"

log "Staging and validating database dump..."
CONTAINER_DUMP_STAGED=true
docker cp "$DUMP_TMP" "${CONTAINER}:${CONTAINER_DUMP_PATH}"
if ! docker exec "$CONTAINER" pg_restore --list "$CONTAINER_DUMP_PATH" >/dev/null; then
    log_err "Database archive validation failed before database replacement"
    exit 1
fi
log_ok "Database archive is readable"

log "Dropping and recreating database..."
if ! postgres_exec \
    psql -v ON_ERROR_STOP=1 -h "$DB_HOST" -U "$DB_USER" -d postgres \
    -c "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = '${DB_NAME}' AND pid <> pg_backend_pid();"; then
    log_err "Unable to terminate existing database sessions; refusing database replacement"
    exit 1
fi
if ! postgres_exec \
    psql -v ON_ERROR_STOP=1 -h "$DB_HOST" -U "$DB_USER" -d postgres \
    -c "DROP DATABASE IF EXISTS ${DB_NAME};"; then
    log_err "Unable to drop the existing database; refusing to continue"
    exit 1
fi
if ! postgres_exec \
    psql -v ON_ERROR_STOP=1 -h "$DB_HOST" -U "$DB_USER" -d postgres \
    -c "CREATE DATABASE ${DB_NAME} OWNER ${DB_USER};"; then
    log_err "Unable to create the replacement database; refusing to restore"
    exit 1
fi

log "Restoring database from dump..."
if ! postgres_exec \
    pg_restore -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" \
    --exit-on-error --no-owner --no-acl "$CONTAINER_DUMP_PATH" 2>&1; then
    log_err "Database restore failed; refusing to start application services"
    exit 1
fi
if ! docker exec "$CONTAINER" rm -f "$CONTAINER_DUMP_PATH" >/dev/null 2>&1; then
    log_err "Failed to remove staged database dump from the PostgreSQL container"
    exit 1
fi
CONTAINER_DUMP_STAGED=false
if ! rm -f -- "$DUMP_TMP"; then
    log_err "Failed to remove decrypted database dump from the host"
    exit 1
fi

if ! TABLE_COUNT=$(postgres_exec \
    psql -v ON_ERROR_STOP=1 -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" -t -A \
    -c "SELECT COUNT(*) FROM pg_class WHERE relkind='r' AND relnamespace=(SELECT oid FROM pg_namespace WHERE nspname='public');" 2>/dev/null); then
    log_err "Restore table-count query failed"
    exit 1
fi
if [[ ! "$TABLE_COUNT" =~ ^[0-9]+$ ]]; then
    log_err "Restore postcondition failed: table count is not numeric: '${TABLE_COUNT:-no result}'"
    exit 1
fi
if [ "$TABLE_COUNT" -eq 0 ]; then
    log_err "Restore postcondition failed: expected at least one public table"
    exit 1
fi
if [ "$TABLE_COUNT" -ne "$EXPECTED_TABLE_COUNT" ]; then
    log_err "Restore postcondition failed: restored table count ${TABLE_COUNT} does not match manifest ${EXPECTED_TABLE_COUNT}"
    exit 1
fi

if ! SCHEMA_ANCHOR_COUNT=$(postgres_exec \
    psql -v ON_ERROR_STOP=1 -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" -t -A -c "
    SELECT COUNT(*)
      FROM (VALUES ('studies'), ('study_participants'), ('candidates'), ('devices'), ('android_sensor_data'))
           AS required_table(name)
      JOIN pg_namespace n ON n.nspname = 'public'
      JOIN pg_class c ON c.relnamespace = n.oid
                     AND c.relname = required_table.name
                     AND c.relkind = 'r';
" 2>/dev/null); then
    log_err "Schema postcondition query failed"
    exit 1
fi
if [ "$SCHEMA_ANCHOR_COUNT" != "5" ]; then
    log_err "Schema postcondition failed: required Chronicle tables are missing (${SCHEMA_ANCHOR_COUNT:-no result}/5 present)"
    exit 1
fi

if ! verify_restored_flyway_contract; then
    log_err "Migration history postcondition failed"
    exit 1
fi
log_ok "Database restored (${TABLE_COUNT} tables)"

# ================================================================
log_step 5 "Restore TDE keyring"
# ================================================================

log "Restoring validated TDE keyring..."
CONTAINER_KEYRING_STAGED=true
docker cp "$KEYRING_TMP" "${CONTAINER}:${CONTAINER_KEYRING_ARCHIVE}"
if ! docker exec -u root "$CONTAINER" sh -euc '
    archive="$1"
    stage="$2"
    provider="$3"
    rm -rf -- "$stage"
    mkdir -p "$stage"
    tar -xzf "$archive" -C "$stage"
    test -d "$stage/tde-keyring"
    if [ "$provider" = file ]; then
        key_material=$(find "$stage/tde-keyring" -type f -name "*.per" -size +0c -print -quit)
        test -n "$key_material"
    else
        test "$provider" = vault
    fi
    find /var/lib/postgresql/tde-keyring -mindepth 1 -maxdepth 1 -exec rm -rf -- {} +
    cp -a "$stage/tde-keyring/." /var/lib/postgresql/tde-keyring/
    chown -R postgres:postgres /var/lib/postgresql/tde-keyring
    chmod 700 /var/lib/postgresql/tde-keyring
    rm -rf -- "$stage"
    rm -f -- "$archive"
' chronicle-keyring-restore "$CONTAINER_KEYRING_ARCHIVE" "$CONTAINER_KEYRING_STAGE" "$EXPECTED_TDE_PROVIDER"; then
    log_err "TDE keyring replacement failed before application startup"
    exit 1
fi
CONTAINER_KEYRING_STAGED=false
rm -f -- "$KEYRING_TMP"
log_ok "TDE keyring restored"

# ================================================================
log_step 6 "Apply schema migrations with a one-shot runner"
# ================================================================

log "Running the isolated Flyway migration command without starting application workers..."
if ! run_flyway_migrations; then
    log_err "One-shot Flyway migration failed"
    exit 1
fi
if ! verify_application_writers_stopped; then
    log_err "Application writers were observed after the one-shot migration"
    exit 1
fi
if ! capture_flyway_contract "Post-migration"; then
    exit 1
fi
if [ "$ACTUAL_FLYWAY_MAX" -lt "$EXPECTED_FLYWAY_MAX" ]; then
    log_err "Post-migration Flyway version V${ACTUAL_FLYWAY_MAX} is behind backup manifest V${EXPECTED_FLYWAY_MAX}"
    exit 1
fi
log_ok "One-shot Flyway migration completed at V${ACTUAL_FLYWAY_MAX}"

# ================================================================
log_step 7 "Re-enable TDE encryption"
# ================================================================

log "Running TDE migration..."
if [ ! -x "${SCRIPT_DIR}/migrate-tde.sh" ]; then
    log_err "migrate-tde.sh is missing or not executable; refusing to start application services"
    exit 1
fi
if ! env \
    CHRONICLE_TDE_EXPECTED_PROVIDER="$EXPECTED_TDE_PROVIDER" \
    CHRONICLE_TDE_EXPECTED_PROVIDER_NAME="$EXPECTED_TDE_PROVIDER_NAME" \
    CHRONICLE_TDE_EXPECTED_KEY_NAME="$EXPECTED_TDE_KEY_NAME" \
    "${SCRIPT_DIR}/migrate-tde.sh"; then
    log_err "TDE migration failed; refusing to start application services"
    exit 1
fi
log_ok "TDE migration complete"
if ! verify_tde_key_contract "Pre-ingress"; then
    exit 1
fi
if ! verify_current_encryption "Pre-ingress"; then
    exit 1
fi
if ! verify_restored_data_readable; then
    exit 1
fi

# ================================================================
log_step 8 "Restore audit logs"
# ================================================================

if artifact_is_declared audit-logs.tar.gz.enc; then
    if confirm "Restore audit logs into Docker volume ${AUDIT_VOLUME}?"; then
        if ! docker volume create "$AUDIT_VOLUME" >/dev/null; then
            log_err "Unable to create or resolve the Compose audit-log volume"
            exit 1
        fi
        if ! docker run --rm --pull=never --network=none --read-only \
            --security-opt=no-new-privileges \
            -v "${AUDIT_VOLUME}:/restore" \
            -v "${AUDIT_TMP}:/tmp/audit-logs.tar.gz:ro,Z" \
            "$AUDIT_HELPER_IMAGE" \
            sh -euc '
                stage="/restore/.chronicle-restore-stage-$$"
                prior="/restore/.chronicle-restore-prior-$$"
                committed=false
                rollback() {
                    result=$?
                    if [ "$committed" != true ] && [ -d "$prior" ]; then
                        find /restore -mindepth 1 -maxdepth 1 ! -path "$stage" ! -path "$prior" -exec rm -rf -- {} +
                        find "$prior" -mindepth 1 -maxdepth 1 -exec mv -- {} /restore/ \;
                    fi
                    rm -rf -- "$stage" "$prior"
                    exit "$result"
                }
                trap rollback EXIT
                trap '\''exit 129'\'' HUP
                trap '\''exit 130'\'' INT
                trap '\''exit 143'\'' TERM
                mkdir -p "$stage" "$prior"
                tar -xzf /tmp/audit-logs.tar.gz -C "$stage" --strip-components=1
                test -n "$(find "$stage" -mindepth 1 -print -quit)"
                test -z "$(find "$stage" -mindepth 1 ! -type d ! -type f -print -quit)"
                find /restore -mindepth 1 -maxdepth 1 ! -path "$stage" ! -path "$prior" -exec mv -- {} "$prior"/ \;
                find "$stage" -mindepth 1 -maxdepth 1 -exec mv -- {} /restore/ \;
                chmod -R go-rwx /restore
                committed=true
                rm -rf -- "$stage" "$prior"
                trap - EXIT HUP INT TERM
            ' chronicle-audit-restore >/dev/null; then
            log_err "Audit log volume replacement failed; prior logs were rolled back"
            exit 1
        fi
        rm -f -- "$AUDIT_TMP"
        log_ok "Audit logs restored to volume ${AUDIT_VOLUME}"
    else
        log_err "Audit logs are required by the manifest; refusing to start application services"
        exit 1
    fi
else
    log_warn "Audit logs were not declared in this backup manifest"
fi

# ================================================================
log_step 9 "Start all services"
# ================================================================

log "Starting all Chronicle services..."
APPLICATION_START_ATTEMPTED=true
if ! compose_cmd up -d; then
    log_err "Full application startup failed; quiescing any partially started services"
    quiesce_application_services || log_err "Application quiesce verification failed after startup failure"
    exit 1
fi
log "Waiting for dependency-aware service health..."

# ================================================================
log_step 10 "Health checks"
# ================================================================

HEALTH_OK=true

# Check postgres
if docker exec "$CONTAINER" pg_isready -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" >/dev/null 2>&1; then
    log_ok "PostgreSQL is healthy"
else
    log_err "PostgreSQL is not healthy"
    HEALTH_OK=false
fi

critical_health_checks=(
    "chronicle-docker-proxy|Docker API proxy"
    "edge-traefik|Traefik ingress"
    "chronicle-crowdsec|CrowdSec WAF"
    "chronicle-postgres-replica|PostgreSQL replica"
    "chronicle-backend|Backend"
    "chronicle-frontend|Frontend"
    "chronicle-preprocessing-frontend|Preprocessing frontend"
    "chronicle-apk-download|APK download"
    "chronicle-victoria-metrics|VictoriaMetrics"
    "chronicle-victoria-metrics-credential-reloader|Metrics credential reloader"
    "chronicle-victoria-logs|VictoriaLogs"
    "chronicle-fluent-bit|Fluent Bit"
    "chronicle-grafana|Grafana"
)
for health_check in "${critical_health_checks[@]}"; do
    IFS='|' read -r health_container health_label <<< "$health_check"
    wait_for_container_health "$health_container" "${health_label} readiness" || HEALTH_OK=false
done
optional_profile_health_checks=(
    "chronicle-keycloak-postgres|Keycloak PostgreSQL"
    "chronicle-keycloak|Keycloak"
    "chronicle-vault|Development Vault"
)
for health_check in "${optional_profile_health_checks[@]}"; do
    IFS='|' read -r health_container health_label <<< "$health_check"
    if ! optional_state=$(application_container_state "$health_container"); then
        HEALTH_OK=false
    elif [ -n "$optional_state" ]; then
        wait_for_container_health "$health_container" "${health_label} readiness" || HEALTH_OK=false
    fi
done
verify_replica_streaming || HEALTH_OK=false
verify_current_encryption "Post-start" || HEALTH_OK=false
verify_tde_key_contract "Post-start" || HEALTH_OK=false
verify_restored_data_readable || HEALTH_OK=false

if [ "$HEALTH_OK" != true ]; then
    log "Quiescing application services while PostgreSQL remains available for diagnosis..."
    if ! quiesce_application_services; then
        log_err "Failed to quiesce or verify one or more application services after health failure"
    fi
fi

echo ""
echo -e "${BOLD}=========================================="
if [ "$HEALTH_OK" = true ]; then
    echo -e "${GREEN}Recovery Complete${NC}"
else
    echo -e "${RED}Recovery completed with issues — check logs above${NC}"
fi
echo -e "${BOLD}==========================================${NC}"
echo ""

if [ "$HEALTH_OK" != true ]; then
    exit 1
fi
