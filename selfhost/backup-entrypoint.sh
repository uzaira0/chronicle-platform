#!/usr/bin/env bash
set -Eeuo pipefail

# Docker restart policies do not re-evaluate Compose depends_on conditions. After a host
# or Docker daemon restart the backup sidecar can therefore start while PostgreSQL and the
# backend are still coming up, even though its initial Compose creation waited for a
# healthy backend. postgres-backup-local's BACKUP_ON_START then records a failed first run
# and its health endpoint remains unhealthy until the next scheduled backup.
#
# Wait again inside the container before handing control to the image's /init.sh. Requiring
# both PostgreSQL and an HTTP response from the backend preserves the original invariant:
# the immediate dump is taken only after Flyway has finished creating/upgrading the schema.

fail() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 1
}

[[ "$#" -gt 0 ]] || fail "backup entrypoint requires the image startup command"

startup_timeout="${BACKUP_STARTUP_TIMEOUT_SECONDS:-3600}"
poll_interval="${BACKUP_STARTUP_INTERVAL_SECONDS:-2}"
backend_url="${BACKUP_BACKEND_URL:-https://backend:8443/chronicle/v3/study}"
backend_ca="${BACKUP_BACKEND_CA:-/etc/backend-tls/backend.crt}"
postgres_host="${POSTGRES_HOST:-}"
postgres_port="${POSTGRES_PORT:-5432}"
postgres_database="${POSTGRES_DB:-}"
postgres_user="${POSTGRES_USER:-}"

[[ "$startup_timeout" =~ ^[1-9][0-9]*$ ]] ||
  fail "BACKUP_STARTUP_TIMEOUT_SECONDS must be a positive integer"
# Bash arithmetic is 64-bit; longer values would overflow the deadline instead of extending it.
[[ ${#startup_timeout} -le 18 ]] || fail "BACKUP_STARTUP_TIMEOUT_SECONDS must fit in a 64-bit integer"
[[ "$poll_interval" =~ ^[1-9][0-9]*$ ]] ||
  fail "BACKUP_STARTUP_INTERVAL_SECONDS must be a positive integer"
if [[ ${#poll_interval} -gt 2 ]] || (( poll_interval > 60 )); then
  fail "BACKUP_STARTUP_INTERVAL_SECONDS must not exceed 60"
fi
[[ -n "$backend_url" ]] || fail "BACKUP_BACKEND_URL must not be empty"
[[ -n "$postgres_host" ]] || fail "POSTGRES_HOST must not be empty"
[[ "$postgres_port" =~ ^[1-9][0-9]*$ ]] || fail "POSTGRES_PORT must be a positive integer"
if [[ ${#postgres_port} -gt 5 ]] || (( postgres_port > 65535 )); then
  fail "POSTGRES_PORT must not exceed 65535"
fi
[[ -n "$postgres_database" ]] || fail "POSTGRES_DB must not be empty"
[[ -n "$postgres_user" ]] || fail "POSTGRES_USER must not be empty"
command -v pg_isready >/dev/null 2>&1 || fail "pg_isready is unavailable in the backup image"
command -v curl >/dev/null 2>&1 || fail "curl is unavailable in the backup image"

started_at=$SECONDS
deadline=$((started_at + startup_timeout))
next_progress_at=$started_at
database_ready=false
backend_ready=false
http_status=unavailable

while (( SECONDS < deadline )); do
  remaining=$((deadline - SECONDS))
  probe_timeout=5
  (( remaining < probe_timeout )) && probe_timeout=$remaining
  (( probe_timeout < 1 )) && probe_timeout=1

  database_ready=false
  backend_ready=false
  http_status=unavailable

  if pg_isready \
      -h "$postgres_host" \
      -p "$postgres_port" \
      -U "$postgres_user" \
      -d "$postgres_database" \
      -t "$probe_timeout" >/dev/null 2>&1; then
    database_ready=true
    http_status="$(
      curl --silent --show-error --output /dev/null --write-out '%{http_code}' \
        --connect-timeout "$probe_timeout" --max-time "$probe_timeout" \
        --cacert "$backend_ca" "$backend_url" 2>/dev/null || true
    )"
    # Match the backend container's health contract: any 2xx or 4xx proves the Spring
    # request path is serving. The normal unauthenticated response is 401.
    [[ "$http_status" =~ ^[24][0-9][0-9]$ ]] && backend_ready=true
  fi

  if [[ "$database_ready" == true && "$backend_ready" == true ]]; then
    printf 'Backup dependencies are ready; starting the scheduler and initial dump.\n'
    exec "$@"
  fi

  if (( SECONDS >= next_progress_at )); then
    printf 'Waiting for backup dependencies (database=%s, backend_http=%s, timeout=%ss).\n' \
      "$database_ready" "$http_status" "$startup_timeout"
    next_progress_at=$((SECONDS + 15))
  fi

  remaining=$((deadline - SECONDS))
  (( remaining <= 0 )) && break
  sleep_for=$poll_interval
  (( remaining < sleep_for )) && sleep_for=$remaining
  sleep "$sleep_for"
done

fail "backup startup timed out after ${startup_timeout}s waiting for PostgreSQL and the Chronicle backend; the scheduler was not started"
