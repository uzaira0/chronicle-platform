#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
ENTRYPOINT="${ROOT_DIR}/selfhost/backup-entrypoint.sh"
RUN_PARENT="${SELFHOST_BACKUP_TEST_ROOT:-${ROOT_DIR}/build/operator-test-runs/selfhost-backup-readiness}"

fail() {
  echo "self-host backup readiness test failed: $*" >&2
  exit 1
}

[[ "$RUN_PARENT" == /* ]] || fail "test run parent must be absolute"
case "$RUN_PARENT" in
  /tmp|/tmp/*|/private/tmp|/private/tmp/*|/var/folders|/var/folders/*)
    fail "test run parent must not use a system temporary directory"
    ;;
esac
[[ -x "$ENTRYPOINT" ]] || fail "backup entrypoint is missing or not executable"

umask 077
/bin/mkdir -p "$RUN_PARENT"
RUN_DIR="$(/usr/bin/mktemp -d "${RUN_PARENT}/run.XXXXXX")"
trap '/bin/rm -rf -- "$RUN_DIR"' EXIT
COMMAND_DIR="${RUN_DIR}/commands"
/bin/mkdir -p "$COMMAND_DIR"

cat >"${COMMAND_DIR}/pg_isready" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
counter="${BACKUP_TEST_STATE:?}/pg.count"
count=0
[[ ! -f "$counter" ]] || count="$(cat "$counter")"
count=$((count + 1))
printf '%s\n' "$count" >"$counter"
(( count >= BACKUP_TEST_DB_READY_AFTER ))
EOF

cat >"${COMMAND_DIR}/curl" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
counter="${BACKUP_TEST_STATE:?}/curl.count"
count=0
[[ ! -f "$counter" ]] || count="$(cat "$counter")"
count=$((count + 1))
printf '%s\n' "$count" >"$counter"
if (( count >= BACKUP_TEST_BACKEND_READY_AFTER )); then
  # The real unauthenticated study route returns 401; the wrapper must accept that as a
  # serving Spring request path, exactly as the backend container healthcheck does.
  printf '401'
else
  printf '503'
fi
EOF

cat >"${COMMAND_DIR}/image-init" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf 'started\n' >"${BACKUP_TEST_INIT_MARKER:?}"
EOF
/bin/chmod 0755 "${COMMAND_DIR}/pg_isready" "${COMMAND_DIR}/curl" "${COMMAND_DIR}/image-init"

run_entrypoint() {
  local state_dir="$1"
  local timeout="$2"
  local db_ready_after="$3"
  local backend_ready_after="$4"
  local marker="$5"
  local output="$6"
  /bin/mkdir -p "$state_dir"
  PATH="${COMMAND_DIR}:/usr/bin:/bin" \
    BACKUP_TEST_STATE="$state_dir" \
    BACKUP_TEST_DB_READY_AFTER="$db_ready_after" \
    BACKUP_TEST_BACKEND_READY_AFTER="$backend_ready_after" \
    BACKUP_TEST_INIT_MARKER="$marker" \
    BACKUP_STARTUP_TIMEOUT_SECONDS="$timeout" \
    BACKUP_STARTUP_INTERVAL_SECONDS=1 \
    POSTGRES_HOST=postgres \
    POSTGRES_PORT=5432 \
    POSTGRES_DB=chronicle \
    POSTGRES_USER=chronicle \
    /bin/bash "$ENTRYPOINT" "${COMMAND_DIR}/image-init" >"$output" 2>&1
}

success_state="${RUN_DIR}/success-state"
success_marker="${RUN_DIR}/success.init"
success_output="${RUN_DIR}/success.log"
run_entrypoint "$success_state" 6 2 2 "$success_marker" "$success_output" \
  || fail "entrypoint did not recover when dependencies became ready"
[[ -f "$success_marker" ]] || fail "image init was not launched after readiness"
[[ "$(cat "${success_state}/pg.count")" -ge 3 ]] || fail "database readiness was not retried"
[[ "$(cat "${success_state}/curl.count")" -ge 2 ]] || fail "backend readiness was not retried"
grep -Fq 'Backup dependencies are ready' "$success_output" \
  || fail "successful readiness was not reported"

failure_state="${RUN_DIR}/failure-state"
failure_marker="${RUN_DIR}/failure.init"
failure_output="${RUN_DIR}/failure.log"
set +e
run_entrypoint "$failure_state" 1 1 99 "$failure_marker" "$failure_output"
failure_status=$?
set -e
[[ "$failure_status" -ne 0 ]] || fail "entrypoint started after a permanent backend failure"
[[ ! -e "$failure_marker" ]] || fail "image init ran before the backend was ready"
grep -Fq 'backup startup timed out after 1s' "$failure_output" \
  || fail "readiness timeout was not comprehensible"

invalid_output="${RUN_DIR}/invalid.log"
set +e
BACKUP_STARTUP_TIMEOUT_SECONDS=0 /bin/bash "$ENTRYPOINT" "${COMMAND_DIR}/image-init" \
  >"$invalid_output" 2>&1
invalid_status=$?
set -e
[[ "$invalid_status" -ne 0 ]] || fail "entrypoint accepted a zero startup timeout"
grep -Fq 'BACKUP_STARTUP_TIMEOUT_SECONDS must be a positive integer' "$invalid_output" \
  || fail "invalid timeout rejection was not comprehensible"

run_entrypoint "${RUN_DIR}/extended" 7200 1 1 "${RUN_DIR}/extended.init" "${RUN_DIR}/extended.log" \
  || fail "entrypoint refused an operator-selected startup timeout above the default"
[[ -f "${RUN_DIR}/extended.init" ]] || fail "extended timeout did not start the scheduler"

set +e
BACKUP_STARTUP_TIMEOUT_SECONDS=18446744073709551616 /bin/bash "$ENTRYPOINT" "${COMMAND_DIR}/image-init" \
  >"${RUN_DIR}/overflow-timeout.log" 2>&1
overflow_status=$?
set -e
[[ "$overflow_status" -ne 0 ]] || fail "entrypoint accepted a timeout that overflows its deadline"
grep -Fq 'BACKUP_STARTUP_TIMEOUT_SECONDS must fit in a 64-bit integer' "${RUN_DIR}/overflow-timeout.log" ||
  fail "overflow timeout rejection was not comprehensible"

set +e
BACKUP_STARTUP_TIMEOUT_SECONDS=10 BACKUP_STARTUP_INTERVAL_SECONDS=61 \
  /bin/bash "$ENTRYPOINT" "${COMMAND_DIR}/image-init" \
  >"${RUN_DIR}/oversized-interval.log" 2>&1
oversized_status=$?
set -e
[[ "$oversized_status" -ne 0 ]] || fail "entrypoint accepted an excessive readiness interval"
grep -Fq 'BACKUP_STARTUP_INTERVAL_SECONDS must not exceed 60' \
  "${RUN_DIR}/oversized-interval.log" ||
  fail "oversized readiness-interval rejection was not comprehensible"

# Pre-operation safety dumps sit outside the image's daily/weekly/monthly rotation. The
# post-backup hook bounds them by PRE_OP_BACKUP_KEEP_DAYS.
PRUNE_HOOK="${ROOT_DIR}/selfhost/backup-prune-hook.sh"
[[ -x "$PRUNE_HOOK" ]] || fail "pre-operation dump prune hook is missing or not executable"
grep -Fq './backup-prune-hook.sh:/hooks/50-prune-pre-operation-dumps:ro' "${ROOT_DIR}/selfhost/overlays/backups.yml" ||
  fail "backups overlay does not mount the prune hook into /hooks"
PRUNE_DIR="${RUN_DIR}/prune"
# BSD touch (macOS) has no relative dates: GNU's -d '40 days ago' is an illegal time specification there.
age_days() { # days file
  python3 -c 'import os, sys, time; t = time.time() - 86400 * int(sys.argv[1]); os.utime(sys.argv[2], (t, t))' "$1" "$2"
}
/bin/mkdir -p "${PRUNE_DIR}/daily" "${PRUNE_DIR}/secret-rotation"
for name in pre-adopt-20260101T000000Z-123.sql.gz pre-upgrade-1.0.0-to-1.1.0-a.sql.gz \
            pre-restore-20260101T000000Z.abc123.sql.gz \
            pre-restore-20260101T000000Z.abc123.continuity.sql.gz; do
  : >"${PRUNE_DIR}/${name}"; age_days 40 "${PRUNE_DIR}/${name}"
done
: >"${PRUNE_DIR}/pre-restore-20260920T000000Z.def456.sql.gz"
: >"${PRUNE_DIR}/pre-adopt-20260920T000000Z-456.sql.gz"
: >"${PRUNE_DIR}/secret-rotation/pre-tde-rotation-old.sql.gz"
age_days 40 "${PRUNE_DIR}/secret-rotation/pre-tde-rotation-old.sql.gz"
: >"${PRUNE_DIR}/secret-rotation/pre-tde-rotation-recent.sql.gz"
: >"${PRUNE_DIR}/daily/chronicle-20260101.sql.gz"; age_days 40 "${PRUNE_DIR}/daily/chronicle-20260101.sql.gz"
: >"${PRUNE_DIR}/unrelated.sql.gz"; age_days 40 "${PRUNE_DIR}/unrelated.sql.gz"
BACKUP_DIR="$PRUNE_DIR" PRE_OP_BACKUP_KEEP_DAYS=30 "$PRUNE_HOOK" error >/dev/null
[[ -e "${PRUNE_DIR}/pre-upgrade-1.0.0-to-1.1.0-a.sql.gz" ]] || fail "prune hook acted on a failed backup run"
BACKUP_DIR="$PRUNE_DIR" PRE_OP_BACKUP_KEEP_DAYS=30 "$PRUNE_HOOK" post-backup >"${RUN_DIR}/prune.log"
for gone in pre-adopt-20260101T000000Z-123.sql.gz pre-upgrade-1.0.0-to-1.1.0-a.sql.gz \
            pre-restore-20260101T000000Z.abc123.sql.gz \
            pre-restore-20260101T000000Z.abc123.continuity.sql.gz \
            secret-rotation/pre-tde-rotation-old.sql.gz; do
  [[ ! -e "${PRUNE_DIR}/${gone}" ]] || fail "expired pre-operation dump survived: ${gone}"
done
for kept in pre-adopt-20260920T000000Z-456.sql.gz pre-restore-20260920T000000Z.def456.sql.gz \
            daily/chronicle-20260101.sql.gz unrelated.sql.gz \
            secret-rotation/pre-tde-rotation-recent.sql.gz; do
  [[ -e "${PRUNE_DIR}/${kept}" ]] || fail "prune hook removed a file it does not own: ${kept}"
done
if BACKUP_DIR="$PRUNE_DIR" PRE_OP_BACKUP_KEEP_DAYS=0 "$PRUNE_HOOK" post-backup >/dev/null 2>&1; then
  fail "prune hook accepted PRE_OP_BACKUP_KEEP_DAYS=0"
fi
if BACKUP_DIR="$PRUNE_DIR" "$PRUNE_HOOK" post-backup >/dev/null 2>&1; then
  fail "prune hook chose its own retention when PRE_OP_BACKUP_KEEP_DAYS was unset"
fi
: >"${PRUNE_DIR}/pre-upgrade-old.sql.gz"; age_days 400 "${PRUNE_DIR}/pre-upgrade-old.sql.gz"
BACKUP_DIR="$PRUNE_DIR" PRE_OP_BACKUP_KEEP_DAYS=all "$PRUNE_HOOK" post-backup >/dev/null ||
  fail "prune hook refused PRE_OP_BACKUP_KEEP_DAYS=all"
[[ -e "${PRUNE_DIR}/pre-upgrade-old.sql.gz" ]] || fail "PRE_OP_BACKUP_KEEP_DAYS=all still pruned a safety dump"

echo "self-host backup readiness test passed"
