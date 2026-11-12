#!/bin/bash
# Flyway migration runner for the Chronicle deployment host.
#
# Runs the official Flyway CLI container against the live chronicle-postgres instance,
# using the SQL corpus checked out in this repository (language-neutral: no JVM app
# involvement). Used by scripts/deploy.sh and the backend deploy poller BEFORE the
# backend container is recreated, so a failed migration aborts the deploy and the
# backend never restarts into a broken schema.
#
# Usage:
#   scripts/flyway-migrate.sh migrate    # apply pending migrations (fail-closed)
#   scripts/flyway-migrate.sh info       # show migration status
#   scripts/flyway-migrate.sh validate   # checksum/naming validation only
#
# Fresh-database semantics: if flyway_schema_history does not exist yet AND the schema
# has no framework tables, this script exits 0 without migrating — the backend's own
# FlywayMigrationService performs the framework bootstrap + first migrate at startup.
# A non-empty schema WITHOUT history is an operator error (un-baselined database) and
# fails loudly. Production was baselined explicitly; see docs/db/MIGRATION-LEDGER-AUDIT.md.

set -euo pipefail
umask 077

# This runner accepts database credentials only from the protected deployment env file.
# Remove similarly named ambient variables before the first host utility is spawned so
# they cannot leak into grep, Docker, or any other child process environment.
unset POSTGRES_PASSWORD PGPASSWORD FLYWAY_PASSWORD

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
ENV_FILE="${CHRONICLE_ENV_FILE:-${PROJECT_ROOT}/docker/.env}"
MIGRATION_DIR="${PROJECT_ROOT}/chronicle-server/src/main/resources/db/migration"
# Keep in sync with ext.flyway_version in gradles/chronicle.gradle.
# Digest-pinned (matching the compose files' posture): this transient container runs
# with DB superuser credentials inside the internal network — a re-pushed mutable tag
# must not be able to swap its contents.
FLYWAY_IMAGE="flyway/flyway:11.20.3@sha256:01605f443e1a891b3762f66e66d92403c33b6e0c29099ad550af94b6c1cbc3c1"
# Overridable for cutover rehearsals against a scratch container (no TLS there).
PG_CONTAINER="${CHRONICLE_PG_CONTAINER:-chronicle-postgres}"
PG_NETWORK="${CHRONICLE_PG_NETWORK:-chronicle_chronicle-internal}"
PG_SSLMODE="${CHRONICLE_PG_SSLMODE:-require}"

ACTION="${1:-migrate}"
case "${ACTION}" in
  migrate|info|validate) ;;
  *) echo "Usage: $0 [migrate|info|validate]" >&2; exit 2 ;;
esac

[[ -f "${ENV_FILE}" ]] || { echo "ERROR: env file not found: ${ENV_FILE}" >&2; exit 1; }
[[ -d "${MIGRATION_DIR}" ]] || { echo "ERROR: migration dir not found: ${MIGRATION_DIR}" >&2; exit 1; }

# `|| true`: under set -euo pipefail a missing key would otherwise kill the script at
# the assignment, silently — before the explicit diagnostic below can fire.
pg_env() { { grep -E "^$1=" "${ENV_FILE}" | sed -n 1p | cut -d= -f2-; } || true; }
PGUSER="$(pg_env POSTGRES_USER)"
PGPASSWORD="$(pg_env POSTGRES_PASSWORD)"
PGDB="$(pg_env POSTGRES_DB)"
[[ -n "${PGUSER}" && -n "${PGPASSWORD}" && -n "${PGDB}" ]] || {
  echo "ERROR: POSTGRES_USER/POSTGRES_PASSWORD/POSTGRES_DB missing from ${ENV_FILE}" >&2; exit 1;
}

# All direct DB CLI access goes through the postgres container with -h 127.0.0.1
# (local bare-socket connections hit peer auth — a recurring production footgun).
# PGOPTIONS disables parallel gather: parallel scans over pg_tde tables have
# crashed this cluster before, and as an env option it leaves psql output clean.
psql_scalar() {
  local query="$1"
  {
    printf '%s\n' "${PGPASSWORD}"
    printf '%s\n' "${query}"
  } | docker exec -i \
    -e PGOPTIONS="-c max_parallel_workers_per_gather=0" \
    "${PG_CONTAINER}" \
    /bin/bash -euc '
      IFS= read -r PGPASSWORD
      IFS= read -r query
      export PGPASSWORD
      exec psql -h 127.0.0.1 -U "$1" -d "$2" -Atc "$query"
    ' chronicle-flyway-preflight "${PGUSER}" "${PGDB}"
}

HISTORY_EXISTS="$(psql_scalar "SELECT to_regclass('public.flyway_schema_history') IS NOT NULL")"
TABLE_COUNT="$(psql_scalar "SELECT count(*) FROM pg_class c JOIN pg_namespace n ON c.relnamespace=n.oid WHERE n.nspname='public' AND c.relkind='r'")"

if [[ "${HISTORY_EXISTS}" != "t" ]]; then
  if [[ "${TABLE_COUNT}" == "0" ]]; then
    echo "Fresh database (no tables, no flyway_schema_history) — backend startup will bootstrap and migrate."
    exit 0
  fi
  echo "ERROR: schema has ${TABLE_COUNT} tables but no flyway_schema_history." >&2
  echo "       This database was never baselined. Refusing to guess: run the explicit" >&2
  echo "       baseline procedure from docs/db/MIGRATION-LEDGER-AUDIT.md first." >&2
  exit 1
fi

# Docker has no password-stdin option for `run`. Give it a unique owner-only env file and
# remove that file on success, failure, or signal. The password is therefore absent from
# both Docker argv and Docker's inherited host environment.
FLYWAY_SECRET_PARENT="${CHRONICLE_FLYWAY_SECRET_PARENT:-${PROJECT_ROOT}/build/operator-runs/flyway-migrate}"
FLYWAY_SECRET_RUN=""
FLYWAY_SECRET_ENV=""
FLYWAY_CHILD_PID=""

cleanup_flyway_secret() {
  if [[ -n "$FLYWAY_SECRET_ENV" && -f "$FLYWAY_SECRET_ENV" && ! -L "$FLYWAY_SECRET_ENV" ]]; then
    /bin/rm -f -- "$FLYWAY_SECRET_ENV"
  fi
  if [[ -n "$FLYWAY_SECRET_RUN" && -d "$FLYWAY_SECRET_RUN" && ! -L "$FLYWAY_SECRET_RUN" ]]; then
    /bin/rmdir -- "$FLYWAY_SECRET_RUN" 2>/dev/null || true
  fi
}

terminate_flyway_child() {
  local signal_name="$1" attempt
  [[ -n "$FLYWAY_CHILD_PID" ]] || return 0

  if kill -0 "$FLYWAY_CHILD_PID" 2>/dev/null; then
    # Docker is the runner's direct child and proxies these signals to its attached
    # container. Do not signal -PID: without job control it shares the caller's process
    # group, so a negative PID could terminate the deploy process that launched us.
    kill -s "$signal_name" "$FLYWAY_CHILD_PID" 2>/dev/null || true
    for ((attempt = 0; attempt < 20; attempt++)); do
      kill -0 "$FLYWAY_CHILD_PID" 2>/dev/null || break
      /bin/sleep 0.05
    done
    if kill -0 "$FLYWAY_CHILD_PID" 2>/dev/null; then
      kill -KILL "$FLYWAY_CHILD_PID" 2>/dev/null || true
    fi
  fi
  wait "$FLYWAY_CHILD_PID" 2>/dev/null || true
  FLYWAY_CHILD_PID=""
}

handle_flyway_signal() {
  local signal_name="$1" exit_status="$2"
  trap '' HUP INT TERM
  cleanup_flyway_secret
  terminate_flyway_child "$signal_name"
  exit "$exit_status"
}

trap cleanup_flyway_secret EXIT
trap 'handle_flyway_signal HUP 129' HUP
trap 'handle_flyway_signal INT 130' INT
trap 'handle_flyway_signal TERM 143' TERM

case "$FLYWAY_SECRET_PARENT" in
  /*) ;;
  *) echo "ERROR: CHRONICLE_FLYWAY_SECRET_PARENT must be absolute" >&2; exit 1 ;;
esac
case "$FLYWAY_SECRET_PARENT" in
  /tmp|/tmp/*|/private/tmp|/private/tmp/*|/var/folders|/var/folders/*)
    echo "ERROR: Flyway secret transport must not use a system temporary directory" >&2
    exit 1
    ;;
esac
[[ ! -L "$FLYWAY_SECRET_PARENT" ]] || {
  echo "ERROR: Flyway secret parent must not be a symlink" >&2
  exit 1
}
/bin/mkdir -p "$FLYWAY_SECRET_PARENT"
/bin/chmod 0700 "$FLYWAY_SECRET_PARENT"
[[ -d "$FLYWAY_SECRET_PARENT" && ! -L "$FLYWAY_SECRET_PARENT" && -O "$FLYWAY_SECRET_PARENT" ]] || {
  echo "ERROR: Flyway secret parent must be an owner-controlled directory" >&2
  exit 1
}
FLYWAY_SECRET_RUN="$(/usr/bin/mktemp -d "${FLYWAY_SECRET_PARENT}/run.XXXXXX")"
/bin/chmod 0700 "$FLYWAY_SECRET_RUN"
FLYWAY_SECRET_ENV="$(/usr/bin/mktemp "${FLYWAY_SECRET_RUN}/flyway.env.XXXXXX")"
/bin/chmod 0600 "$FLYWAY_SECRET_ENV"
printf 'FLYWAY_PASSWORD=%s\n' "$PGPASSWORD" >"$FLYWAY_SECRET_ENV"

docker run --rm \
  --network "${PG_NETWORK}" \
  -v "${MIGRATION_DIR}:/flyway/sql:ro" \
  --env-file "$FLYWAY_SECRET_ENV" \
  -e FLYWAY_URL="jdbc:postgresql://${PG_CONTAINER}:5432/${PGDB}?sslmode=${PG_SSLMODE}" \
  -e FLYWAY_USER="${PGUSER}" \
  "${FLYWAY_IMAGE}" \
  -connectRetries=5 \
  -baselineOnMigrate=false \
  -validateMigrationNaming=true \
  "${ACTION}" &
FLYWAY_CHILD_PID=$!
if wait "$FLYWAY_CHILD_PID"; then
  FLYWAY_STATUS=0
else
  FLYWAY_STATUS=$?
fi
FLYWAY_CHILD_PID=""
exit "$FLYWAY_STATUS"
