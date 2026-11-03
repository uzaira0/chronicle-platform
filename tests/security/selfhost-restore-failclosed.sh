#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
source "${ROOT_DIR}/tests/security/lib/selfhost-fixtures.sh"
RESTORE_SCRIPT="${ROOT_DIR}/selfhost/restore.sh"
FIXTURE_BIN="${ROOT_DIR}/tests/security/fixtures/selfhost-restore/commands"
RUN_PARENT="${SELFHOST_RESTORE_TEST_ROOT:-${ROOT_DIR}/build/operator-test-runs/selfhost-restore}"

fail() {
  echo "selfhost restore fail-closed test failed: $*" >&2
  exit 1
}

[[ "$RUN_PARENT" == /* ]] || fail "test run parent must be absolute"
case "$RUN_PARENT" in
  /tmp|/tmp/*|/private/tmp|/private/tmp/*|/var/folders|/var/folders/*)
    fail "test run parent must not use a system temporary directory"
    ;;
esac
[[ ! -L "$RUN_PARENT" ]] || fail "test run parent must not be a symlink"

bash -n "$RESTORE_SCRIPT"
# The test intentionally matches the literal default-preserving expansion.
# shellcheck disable=SC2016
grep -Fq 'BACKUPS_DIR="${BACKUPS_DIR:-/backups}"' "$RESTORE_SCRIPT" ||
  fail "restore script must support a caller-owned backup directory for isolated contract tests"
REAL_PYTHON="$(command -v python3)"
export REAL_PYTHON ROOT_DIR
for fixture_command in date gzip pg_dump psql; do
  [[ -x "${FIXTURE_BIN}/${fixture_command}" ]] ||
    fail "required fixture command is missing or not executable: ${FIXTURE_BIN}/${fixture_command}"
done
for database_command in pg_dump psql; do
  resolved_command="$(PATH="${FIXTURE_BIN}:/usr/bin:/bin" command -v "$database_command")"
  [[ "$resolved_command" == "${FIXTURE_BIN}/${database_command}" ]] ||
    fail "database fixture did not resolve exactly: ${database_command} -> ${resolved_command}"
done

umask 077
/bin/mkdir -p "$RUN_PARENT"
RUN_DIR="$(/usr/bin/mktemp -d "${RUN_PARENT}/run.XXXXXX")"
/bin/chmod 0700 "$RUN_DIR"
export TMPDIR="$RUN_DIR" TMP="$RUN_DIR" TEMP="$RUN_DIR"

# The moved validator needs real gzip streams and the fixture's /selfhost mount.
original_fixture_bin="$FIXTURE_BIN"
FIXTURE_BIN="${RUN_DIR}/commands"
mkdir "$FIXTURE_BIN"
cp "${original_fixture_bin}/"* "$FIXTURE_BIN/"
cat >"${FIXTURE_BIN}/python3" <<'SH'
#!/usr/bin/env bash
exec env PYTHONPATH="${ROOT_DIR}/selfhost" PYTHONDONTWRITEBYTECODE=1 "$REAL_PYTHON" -s "$@"
SH
mv "${FIXTURE_BIN}/psql" "${FIXTURE_BIN}/psql-original"
cat >"${FIXTURE_BIN}/psql" <<'PY'
#!/usr/bin/env python3
import os
from pathlib import Path
import sys
from chronicle_ops.dump import CATALOG_GATE_SQL
args = sys.argv[1:]
if '-c' in args and args[args.index('-c') + 1] == CATALOG_GATE_SQL.rstrip('\n'):
    sys.exit(0)
os.execv(str(Path(__file__).with_name('psql-original')), sys.argv)
PY
chmod 0755 "${FIXTURE_BIN}/"*

cleanup() {
  /bin/rm -rf -- "$RUN_DIR"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

run_direct_invocation_case() {
  local case_dir="${RUN_DIR}/direct-invocation"
  local backups_dir="${case_dir}/backups"
  local restore_file="${case_dir}/restore.sql.gz"
  local pg_dump_marker="${case_dir}/pg-dump.invoked"
  local psql_marker="${case_dir}/psql.invoked"
  local output_file="${case_dir}/output.log" trusted_sha256

  /bin/mkdir -p "$backups_dir"
  /bin/chmod 0700 "$case_dir" "$backups_dir"
  trusted_sha256="$(write_trusted_restore_fixture "$restore_file")"

  set +e
  PATH="${FIXTURE_BIN}:/usr/bin:/bin" \
    BACKUPS_DIR="$backups_dir" \
    RESTORE_FILE="$restore_file" \
    CHRONICLE_RESTORE_TRUSTED_SHA256="$trusted_sha256" \
    POSTGRES_PASSWORD="fixture-password" \
    POSTGRES_USER="chronicle" \
    POSTGRES_DB="chronicle" \
    SELFHOST_RESTORE_TEST_PG_DUMP_MARKER="$pg_dump_marker" \
    SELFHOST_RESTORE_TEST_PSQL_MARKER="$psql_marker" \
    "$BASH" "$RESTORE_SCRIPT" >"$output_file" 2>&1
  local result_code=$?
  set -e

  [[ "$result_code" -ne 0 ]] || fail "direct invocation unexpectedly succeeded"
  [[ ! -e "$pg_dump_marker" && ! -e "$psql_marker" ]] ||
    fail "direct invocation reached a database command"
  grep -Fq "direct restore-service execution is disabled" "$output_file" ||
    fail "direct invocation rejection did not explain the guarded command"
}

run_failure_case() {
  local case_name="$1"
  local pg_dump_exit="$2"
  local gzip_exit="$3"
  local case_dir="${RUN_DIR}/${case_name}"
  local backups_dir="${case_dir}/backups"
  local restore_file="${case_dir}/restore.sql.gz"
  local pg_dump_marker="${case_dir}/pg-dump.invoked"
  local psql_marker="${case_dir}/psql.invoked"
  local output_file="${case_dir}/output.log" trusted_sha256

  /bin/mkdir -p "$backups_dir"
  /bin/chmod 0700 "$case_dir" "$backups_dir"
  trusted_sha256="$(write_trusted_restore_fixture "$restore_file")"

  set +e
  PATH="${FIXTURE_BIN}:/usr/bin:/bin" \
    CHRONICLE_RESTORE_ORCHESTRATED=true \
    BACKUPS_DIR="$backups_dir" \
    RESTORE_FILE="$restore_file" \
    CHRONICLE_RESTORE_TRUSTED_SHA256="$trusted_sha256" \
    POSTGRES_PASSWORD="fixture-password" \
    POSTGRES_USER="chronicle" \
    POSTGRES_DB="chronicle" \
    SELFHOST_RESTORE_TEST_PG_DUMP_MARKER="$pg_dump_marker" \
    SELFHOST_RESTORE_TEST_PSQL_MARKER="$psql_marker" \
    SELFHOST_RESTORE_TEST_PG_DUMP_EXIT="$pg_dump_exit" \
    SELFHOST_RESTORE_TEST_GZIP_PIPE_EXIT="$gzip_exit" \
    "$BASH" "$RESTORE_SCRIPT" > "$output_file" 2>&1
  local result_code=$?
  set -e

  [[ "$result_code" -ne 0 ]] || fail "${case_name}: restore returned success after safety dump failure"
  # ./chronicle restore already pinned this file; a second dump-sized copy only costs free space.
  grep -Fq "ok   ${restore_file} passes its gzip integrity check" "$output_file" ||
    fail "${case_name}: restore.sh did not validate the pinned input in place"
  if /usr/bin/find "$backups_dir" -name '.reviewed-restore.*' -print -quit | /usr/bin/grep -q .; then
    fail "${case_name}: restore.sh left a second copy of the pinned input"
  fi
  [[ -f "$pg_dump_marker" ]] || fail "${case_name}: pg_dump failure fixture was not exercised"
  [[ ! -e "$psql_marker" ]] || fail "${case_name}: destructive psql path ran after safety dump failure"
  grep -Fq "FAIL unable to create pre-restore safety dump; refusing to drop the existing schema" "$output_file" ||
    fail "${case_name}: operator output did not explain the fail-closed stop"
  if /usr/bin/find "$backups_dir" -name 'pre-restore-*.sql.gz' -type f -print -quit | /usr/bin/grep -q .; then
    fail "${case_name}: partial safety dump was not removed"
  fi
  if /usr/bin/grep -Fq "continuing" "$output_file"; then
    fail "${case_name}: operator output still claims it will continue"
  fi
}

run_unique_safety_dump_case() {
  local case_dir="${RUN_DIR}/unique-safety-dump"
  local backups_dir="${case_dir}/backups"
  local restore_file="${case_dir}/restore.sql.gz"
  local pg_dump_marker="${case_dir}/pg-dump.invoked"
  local psql_marker="${case_dir}/psql.invoked"
  local output_file="${case_dir}/output.log" trusted_sha256
  local victim="${case_dir}/must-not-be-overwritten"
  local legacy_name="${backups_dir}/pre-restore-20260811T120000Z.sql.gz"

  /bin/mkdir -p "$backups_dir"
  /bin/chmod 0700 "$case_dir" "$backups_dir"
  trusted_sha256="$(write_trusted_restore_fixture "$restore_file")"
  printf 'preserve-me\n' >"$victim"
  /bin/ln -s "$victim" "$legacy_name"

  set +e
  PATH="${FIXTURE_BIN}:/usr/bin:/bin" \
    CHRONICLE_RESTORE_ORCHESTRATED=true \
    BACKUPS_DIR="$backups_dir" \
    RESTORE_FILE="$restore_file" \
    CHRONICLE_RESTORE_TRUSTED_SHA256="$trusted_sha256" \
    POSTGRES_PASSWORD="fixture-password" \
    POSTGRES_USER="chronicle" \
    POSTGRES_DB="chronicle" \
    SELFHOST_RESTORE_TEST_PG_DUMP_MARKER="$pg_dump_marker" \
    SELFHOST_RESTORE_TEST_PSQL_MARKER="$psql_marker" \
    SELFHOST_RESTORE_TEST_PG_DUMP_EXIT=0 \
    SELFHOST_RESTORE_TEST_GZIP_PIPE_EXIT=0 \
    "$BASH" "$RESTORE_SCRIPT" >"$output_file" 2>&1
  local result_code=$?
  set -e

  [[ "$result_code" -ne 0 ]] || fail "unique-safety-dump: destructive fixture unexpectedly succeeded"
  [[ "$(cat "$victim")" == preserve-me ]] ||
    fail "unique-safety-dump: a predictable safety-dump name overwrote an existing target"
  [[ -L "$legacy_name" ]] ||
    fail "unique-safety-dump: existing predictable path was replaced"
  local safety_dump
  safety_dump="$(find "$backups_dir" -name 'pre-restore-*.sql.gz' -type f -print -quit)"
  [[ -n "$safety_dump" && -s "$safety_dump" ]] ||
    fail "unique-safety-dump: no complete safety dump survived the later restore failure"
  local safety_mode
  safety_mode="$(stat -c '%a' "$safety_dump" 2>/dev/null || stat -f '%Lp' "$safety_dump")"
  [[ "$safety_mode" == 600 ]] ||
    fail "unique-safety-dump: safety dump mode is ${safety_mode}, expected 600"
  grep -Fq 'current database saved to' "$output_file" ||
    fail "unique-safety-dump: successful safety dump was not reported"
}

run_direct_invocation_case
run_failure_case "pg-dump-failure" 42 0
run_failure_case "gzip-failure" 0 43
run_unique_safety_dump_case

echo "PASS: restore fail-closed shell fixture cases"
