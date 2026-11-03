#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
source "$ROOT_DIR/tests/security/lib/selfhost-python.sh"
IMAGE_DIR="${ROOT_DIR}/selfhost/backup-image"
RUN_PARENT="${SELFHOST_BACKUP_TEST_ROOT:-${ROOT_DIR}/build/operator-test-runs/selfhost-backup-selfcheck}"

fail() {
  echo "self-host backup self-check test failed: $*" >&2
  exit 1
}

[[ "$RUN_PARENT" == /* ]] || fail "test run parent must be absolute"
case "$RUN_PARENT" in
  /tmp|/tmp/*|/private/tmp|/private/tmp/*|/var/folders|/var/folders/*)
    fail "test run parent must not use a system temporary directory" ;;
esac
umask 077
mkdir -p "$RUN_PARENT"
RUN_DIR="$(mktemp -d "${RUN_PARENT}/run.XXXXXX")"
SCHEDULER_CONTAINER=""
PAUSED_PID=""
cleanup() {
  local status=$?
  if [[ -n "$PAUSED_PID" ]]; then
    kill_tree "$PAUSED_PID"
    wait "$PAUSED_PID" 2>/dev/null || true
  fi
  if [[ -n "$SCHEDULER_CONTAINER" ]]; then
    docker rm -fv "$SCHEDULER_CONTAINER" >/dev/null || status=1
  fi
  rm -rf -- "$RUN_DIR"
  return "$status"
}
trap cleanup EXIT
COMMAND_DIR="${RUN_DIR}/commands"
mkdir -p "$COMMAND_DIR"

cat >"${COMMAND_DIR}/psql" <<'PY'
#!/usr/bin/env python3
import json
import os
from pathlib import Path
import sys

state = Path(os.environ['SELFCHECK_TEST_STATE'])
mode = os.environ['SELFCHECK_TEST_MODE']
args = sys.argv[1:]
database = args[args.index('-d') + 1]
manifest = {'database_bytes': 1024, 'version': '112', 'tables': ['studies', 'study_participants', 'flyway_schema_history'],
            'row_counts': {'public.study_participants': 3, 'public.studies': 2, 'public.flyway_schema_history': 1},
            'extensions': []}
if '-c' in args:
    sql = args[args.index('-c') + 1]
else:
    first = sys.stdin.readline()
    if first.startswith('BEGIN ISOLATION LEVEL REPEATABLE READ'):
        if mode == 'timeout':
            import time
            time.sleep(5)
        buffer = ''
        for line in sys.stdin:
            if 'json_object_agg' in line:
                print(json.dumps(manifest['row_counts']), flush=True)
                continue
            if 'pg_export_snapshot()' in line:
                print('00000003-00000001-1', flush=True)
                continue
            buffer += line
            if 'SELECT json_build_object(' in buffer and line.strip().endswith(';'):
                print(json.dumps(manifest), flush=True)
                buffer = ''
        sys.exit(0)
    sql = first + sys.stdin.read()
with (state / 'sql.log').open('a') as log:
    log.write(database + ': ' + sql + '\n')
if 'DROP DATABASE' in sql:
    (state / 'scratch').unlink(missing_ok=True)
    with (state / 'drops').open('a') as log:
        log.write('drop\n')
elif 'CREATE DATABASE' in sql:
    (state / 'scratch').touch()
elif 'pg_tde_set_key_using_database_key_provider' in sql:
    assert "ALTER DATABASE \"chronicle_restore_selfcheck\" SET default_table_access_method = 'tde_heap'" in sql
    (state / 'tde').touch()
elif 'CREATE EXTENSION' in sql:
    assert database == 'chronicle_restore_selfcheck' and 'WITH SCHEMA public' in sql and 'pg_tde' not in sql
elif "current_setting('default_table_access_method')" in sql:
    assert (state / 'tde').exists()
    print('f' if mode == 'missing_tde' else 't')
elif 'COPY backup_selfcheck_disk FROM PROGRAM' in sql:
    if mode == 'unknown_space':
        sys.exit(3)
    print('Filesystem 1024-blocks Used Available Capacity Mounted on')
    print('volume 999999 1 ' + ('0' if mode == 'insufficient_space' else '999998') + ' 1% /data/db')
elif 'SELECT json_build_object' in sql or 'json_object_agg' in sql:
    if database == 'chronicle_restore_selfcheck':
        if mode == 'row_mismatch':
            manifest['row_counts']['public.study_participants'] = 4
        elif mode == 'studies_mismatch':
            manifest['row_counts']['public.studies'] = 3
        elif mode == 'version_mismatch':
            manifest['version'] = '111'
        elif mode == 'missing_table':
            manifest['tables'].remove('studies')
    elif (state / 'source_changed').exists():
        manifest['row_counts']['public.studies'] = 9
    print(json.dumps(manifest['row_counts'] if 'json_object_agg' in sql else manifest))
elif "a.amname <>" in sql:
    print('0')
elif database == 'chronicle_restore_selfcheck' and '-- PostgreSQL database dump' in sql:
    assert os.environ.get('ENABLE_ENCRYPTION', 'true') == 'false' or (state / 'tde').exists(), 'restored before TDE setup'
    (state / 'restore').touch()
    if mode == 'restore_failure':
        sys.exit(3)
else:
    raise AssertionError('unexpected psql invocation: ' + sql)
PY

cat >"${COMMAND_DIR}/pg_dump" <<'PY'
#!/usr/bin/env python3
import gzip
import os
from pathlib import Path
import sys
from chronicle_ops.dump import DUMP_EXCLUDE_OPTIONS
state = Path(os.environ['SELFCHECK_TEST_STATE'])
args = sys.argv[1:]
if any(argument.startswith('--snapshot=') for argument in args):
    assert '--snapshot=00000003-00000001-1' in args
    assert args == ['-d', 'chronicle', '-Z1', *DUMP_EXCLUDE_OPTIONS, '--snapshot=00000003-00000001-1'], args
    (state / 'snapshot').touch()
(state / 'source_changed').touch()
dump = '-- PostgreSQL database dump\n\\restrict fixture\nCREATE TABLE studies (study_id uuid);\n'
dump += '-- publication run: ' + os.environ.get('FIXTURE_DUMP_ID', 'baseline') + '\n'
if os.environ['SELFCHECK_TEST_MODE'] != 'truncated_dump':
    dump += '-- PostgreSQL database dump complete\n--\n\\unrestrict fixture\n'
if '-f' in args:
    Path(args[args.index('-f') + 1]).write_bytes(gzip.compress(dump.encode()))
else:
    compressed = gzip.compress(dump.encode())
    sys.stdout.buffer.write(compressed[:-4] if os.environ['SELFCHECK_TEST_MODE'] == 'corrupt_gzip' else compressed)
PY

cat >"${COMMAND_DIR}/curl" <<'SH'
#!/usr/bin/env bash
[[ "${SELFCHECK_TEST_HTTP_FAIL:-false}" != true ]]
SH
chmod 0755 "${COMMAND_DIR}/psql" "${COMMAND_DIR}/pg_dump" "${COMMAND_DIR}/curl"
export PATH="${COMMAND_DIR}:$PATH"
export PYTHONPATH="${ROOT_DIR}/selfhost"
export POSTGRES_DB=chronicle POSTGRES_HOST=postgres POSTGRES_PORT=5432 POSTGRES_USER=chronicle
export POSTGRES_PASSWORD=''
export POSTGRES_DB_FILE='**None**' POSTGRES_USER_FILE='**None**' POSTGRES_PASSWORD_FILE='**None**'
export POSTGRES_PASSFILE_STORE='**None**' POSTGRES_CLUSTER=FALSE POSTGRES_EXTRA_OPTS=-Z1
export BACKUP_SUFFIX=.sql.gz BACKUP_LATEST_TYPE=symlink
export BACKUP_KEEP_MINS=1440 BACKUP_KEEP_DAYS=7 BACKUP_KEEP_WEEKS=4 BACKUP_KEEP_MONTHS=6
export SCHEDULE=@daily HEALTHCHECK_PORT=8080
export BACKUP_SUCCESS_MARKER="${RUN_DIR}/published-backup-marker"

run_case() {
  local mode="$1" expected="$2" reason="$3"
  export SELFCHECK_TEST_MODE="$mode" SELFCHECK_TEST_STATE="${RUN_DIR}/${mode}/state"
  export BACKUP_DIR="${RUN_DIR}/${mode}/backups"
  mkdir -p "$BACKUP_DIR" "$SELFCHECK_TEST_STATE"
  rm -f "$BACKUP_SUCCESS_MARKER"
  selfhost_python "${IMAGE_DIR}/selfcheck.py" health && fail "startup health passed before publication"
  # A failure must not leave an earlier run's success reporting healthy.
  [[ "$expected" == true ]] || printf '%s\n' "$BACKUP_SUCCESS_MARKER" >"$BACKUP_SUCCESS_MARKER"
  local status=0
  bash "${IMAGE_DIR}/backup.sh" >"${RUN_DIR}/${mode}/output.log" 2>&1 || status=$?
  if [[ "$expected" == true ]]; then
    [[ "$status" -eq 0 ]] || { cat "${RUN_DIR}/${mode}/output.log" >&2; fail "$mode did not succeed"; }
    selfhost_python "${IMAGE_DIR}/selfcheck.py" health || fail "verified publication remains unhealthy"
  else
    [[ "$status" -ne 0 ]] || fail "$mode unexpectedly succeeded"
    ! selfhost_python "${IMAGE_DIR}/selfcheck.py" health || fail "failed backup is healthy"
    [[ ! -e "${BACKUP_DIR}/daily/chronicle-latest.sql.gz" ]] || fail "$mode published a failed dump"
  fi
  grep -Fq "$reason" "${RUN_DIR}/${mode}/output.log" || fail "$mode omitted its result diagnostic"
  [[ -s "${SELFCHECK_TEST_STATE}/drops" ]] || fail "$mode did not drop scratch on exit"
  [[ ! -e "${SELFCHECK_TEST_STATE}/scratch" ]] || fail "$mode left scratch present"
}

run_case ok true 'restore verified'
[[ -e "${SELFCHECK_TEST_STATE}/snapshot" ]] || fail 'dump did not use the exported snapshot'
[[ -e "${SELFCHECK_TEST_STATE}/restore" ]] || fail 'successful backup was never restored'
[[ -e "${BACKUP_DIR}/daily/chronicle-latest.sql.gz" ]] || fail 'verified backup was not published'
gzip -t "${BACKUP_DIR}/daily/chronicle-latest.sql.gz"
# Preserve pg_dump's footer verbatim; the shared validator accepts it.
selfhost_python -m chronicle_ops.dump "${BACKUP_DIR}/daily/chronicle-latest.sql.gz"
ENABLE_ENCRYPTION=false run_case unencrypted true 'restore verified'
[[ ! -e "${SELFCHECK_TEST_STATE}/tde" ]] || fail 'unencrypted restore initialized TDE'
run_case restore_failure false 'restore failed'
[[ -e "${SELFCHECK_TEST_STATE}/restore" ]] || fail 'restore failure was not reached'
run_case missing_tde false 'lacks TDE'
[[ ! -e "${SELFCHECK_TEST_STATE}/restore" ]] || fail 'restore ran without tde_heap default'
run_case insufficient_space false 'insufficient space'
[[ ! -e "${SELFCHECK_TEST_STATE}/restore" ]] || fail 'restore ran without disk space'
run_case unknown_space false 'insufficient space'
run_case truncated_dump false 'lacks the final PostgreSQL database dump complete marker'
[[ ! -e "${SELFCHECK_TEST_STATE}/restore" ]] || fail 'truncated dump was restored'
run_case row_mismatch false 'study_participants row count mismatch'
run_case studies_mismatch false 'studies row count mismatch'
run_case version_mismatch false 'schema version mismatch'
run_case missing_table false 'missing public tables'

# A missing gzip trailer is rejected before any scratch restore, and cleanup still runs.
run_case corrupt_gzip false 'failed gzip integrity verification'
[[ ! -e "${SELFCHECK_TEST_STATE}/restore" ]] || fail 'corrupt gzip was restored'

BACKUP_VERIFY_TIMEOUT_SECONDS=1 run_case timeout false 'self-check interrupted by signal'

# Publication under SIGKILL and competing runs. A run pauses at one publication step (an os.replace in
# selfcheck/publish_backup, a tier `ln`, or the success-marker `mv`) and is killed there, or resumed after a
# competing run. Whatever is advertised afterwards (verified marker, success marker, tier and latest links)
# must be a complete verified dump, and the next run must converge.
PAUSE_DIR="${RUN_DIR}/pause"
mkdir -p "$PAUSE_DIR"
cat >"${PAUSE_DIR}/sitecustomize.py" <<'PY'
import os
if os.environ.get('PAUSE_REPLACE'):
    from pathlib import Path
    import time
    _replace = os.replace
    def replace(source, target, *args, **kwargs):
        wanted_source, wanted_target = os.environ['PAUSE_REPLACE'].split('|')
        if str(source).endswith(wanted_source) and str(target).endswith(wanted_target):
            Path(os.environ['PAUSE_REACHED']).touch()
            while not Path(os.environ['PAUSE_RELEASE']).exists():
                time.sleep(0.05)
        return _replace(source, target, *args, **kwargs)
    os.replace = replace
PY
for tool in ln mv; do
  cat >"${PAUSE_DIR}/${tool}" <<SH
#!/usr/bin/env bash
if [[ -n "\${PAUSE_${tool^^}:-}" && " \$* " == *"\${PAUSE_${tool^^}}"* ]]; then
  : >"\$PAUSE_REACHED"
  while [[ ! -e "\$PAUSE_RELEASE" ]]; do sleep 0.05; done
fi
exec /usr/bin/${tool} "\$@"
SH
done
cat >"${PAUSE_DIR}/date" <<'SH'
#!/bin/sh
exec /usr/bin/date -u -d "@$FIXTURE_EPOCH" "$@"
SH
chmod 0755 "${PAUSE_DIR}/ln" "${PAUSE_DIR}/mv" "${PAUSE_DIR}/date"

publication_env() { # case-name epoch
  export SELFCHECK_TEST_MODE=ok SELFCHECK_TEST_STATE="${RUN_DIR}/publication-$1/state"
  export BACKUP_DIR="${RUN_DIR}/publication-$1/backups" BACKUP_SUCCESS_MARKER="${RUN_DIR}/publication-$1/success"
  export FIXTURE_EPOCH="$2" PAUSE_REACHED="${RUN_DIR}/publication-$1/reached" PAUSE_RELEASE="${RUN_DIR}/publication-$1/release"
  mkdir -p "$BACKUP_DIR" "$SELFCHECK_TEST_STATE"
}

paused_backup() { # starts backup.sh in its own process group; waits until it reaches the pause
  rm -f "$PAUSE_REACHED" "$PAUSE_RELEASE"
  PATH="${PAUSE_DIR}:$PATH" PYTHONPATH="${PAUSE_DIR}:$PYTHONPATH" \
    setsid bash "${IMAGE_DIR}/backup.sh" >>"${BACKUP_DIR}/../paused.log" 2>&1 &
  PAUSED_PID=$!
  for _ in $(seq 1 200); do [[ -e "$PAUSE_REACHED" ]] && return 0; sleep 0.05; done
  cat "${BACKUP_DIR}/../paused.log" >&2
  fail "backup never reached its pause point (${PAUSE_REPLACE:-}${PAUSE_LN:-}${PAUSE_MV:-})"
}

kill_tree() {
  local child
  kill -STOP "$1" 2>/dev/null || return 0
  for child in $(ps -o pid= --ppid "$1"); do kill_tree "$child"; done
  kill -KILL "$1" 2>/dev/null || true
}

plain_backup() {
  PATH="${PAUSE_DIR}:$PATH" PAUSE_REPLACE='' PAUSE_LN='' PAUSE_MV='' bash "${IMAGE_DIR}/backup.sh" >>"${BACKUP_DIR}/../plain.log" 2>&1
}

assert_advertised_recovery_points() { # every pointer an operator or health check reads is a verified dump
  local file link target
  selfhost_python - "$BACKUP_DIR" <<'PY' || fail "verified marker does not name an intact dump in $BACKUP_DIR"
import hashlib, json, sys
from pathlib import Path
from chronicle_ops.dump import backup_marker, validate_dump
marker = json.loads(backup_marker(sys.argv[1], 'chronicle').read_text())
dump = backup_marker(sys.argv[1], 'chronicle').parent / marker['file']
assert hashlib.sha256(dump.read_bytes()).hexdigest() == marker['sha256'], 'marker digest differs from its dump'
validate_dump(dump)
PY
  if [[ -e "$BACKUP_SUCCESS_MARKER" ]]; then
    while IFS= read -r file; do
      selfhost_python -m chronicle_ops.dump "$file" >/dev/null || fail "success marker advertises an invalid dump: $file"
    done <"$BACKUP_SUCCESS_MARKER"
  fi
  for link in "$BACKUP_DIR"/{last,daily,weekly,monthly}/chronicle-latest.sql.gz; do
    [[ -L "$link" ]] || continue
    target=$(readlink -f "$link") || fail "dangling latest link $link"
    [[ -f "$target" ]] || fail "dangling latest link $link"
    selfhost_python -m chronicle_ops.dump "$target" >/dev/null || fail "latest link $link names an invalid dump"
  done
  for file in "$BACKUP_DIR"/{daily,weekly,monthly}/chronicle-2*.sql.gz; do
    [[ -e "$file" ]] || continue
    selfhost_python -m chronicle_ops.dump "$file" >/dev/null || fail "tier file $file is not a verified dump"
  done
}

assert_converged() {
  assert_advertised_recovery_points
  selfhost_python "${IMAGE_DIR}/selfcheck.py" health || fail 'rerun after the interruption is not healthy'
  [[ -z "$(find "$BACKUP_DIR" -name '*.partial' -o -name '*-new' -o -name '*.new')" ]] ||
    fail "rerun left orphaned publication files: $(find "$BACKUP_DIR" -name '*.partial' -o -name '*-new' -o -name '*.new')"
  [[ ! -e "${SELFCHECK_TEST_STATE}/scratch" ]] || fail 'scratch database survived the rerun'
  local newest
  newest=$(readlink -f "${BACKUP_DIR}/last/chronicle-latest.sql.gz")
  for tier in daily weekly monthly; do
    [[ "$(readlink -f "${BACKUP_DIR}/${tier}/chronicle-latest.sql.gz")" -ef "$newest" ]] ||
      fail "${tier} latest link does not follow the converged run"
  done
}

DAY=86400 BASE_EPOCH=1793329200  # 2026-10-30T03:00:00Z
kill_point=0
for point in 'replace:.sql.gz.partial|.sql.gz' 'replace:.partial.release.partial|.sql.gz.partial' 'replace:-verified.json.partial|-verified.json' \
             'ln:/daily/chronicle-2' 'ln:/weekly/chronicle-2' 'ln:/monthly/chronicle-latest' "mv:${RUN_DIR}"; do
  kill_point=$((kill_point + 1))
  publication_env "kill-${kill_point}" "$BASE_EPOCH"
  plain_backup || fail "baseline backup failed before kill point $point"
  export FIXTURE_EPOCH=$((BASE_EPOCH + DAY))
  PAUSE_REPLACE='' PAUSE_LN='' PAUSE_MV=''
  case "$point" in
    replace:*) PAUSE_REPLACE="${point#replace:}" ;;
    ln:*) PAUSE_LN="${point#ln:}" ;;
    mv:*) PAUSE_MV="${BACKUP_SUCCESS_MARKER}.new" ;;
  esac
  export PAUSE_REPLACE PAUSE_LN PAUSE_MV
  paused_backup
  kill_tree "$PAUSED_PID"  # as a stopped container would: timeout(1) moves selfcheck into its own group
  wait "$PAUSED_PID" 2>/dev/null || true
  PAUSED_PID=""
  assert_advertised_recovery_points
  export FIXTURE_EPOCH=$((BASE_EPOCH + DAY + 3600))
  plain_backup || { cat "${BACKUP_DIR}/../plain.log" >&2; fail "rerun after a kill at $point failed"; }
  assert_converged
done

# A manual run racing the scheduled one, with identical timestamps and distinguishable dump bytes.
# It must be refused even between tier links, keeping the previous healthy recovery point advertised.
for pause in 'ln:/weekly/chronicle-2' 'replace:-verified.json.partial|-verified.json'; do
  publication_env "race-${pause%%:*}" "$BASE_EPOCH"
  plain_backup || fail 'baseline backup failed before the race'
  export FIXTURE_EPOCH=$((BASE_EPOCH + DAY)) PAUSE_LN='' PAUSE_REPLACE='' PAUSE_MV=''
  case "$pause" in
    ln:*) export PAUSE_LN="${pause#ln:}" ;;
    replace:*) export PAUSE_REPLACE="${pause#replace:}" ;;
  esac
  FIXTURE_DUMP_ID=scheduled paused_backup
  # Stepping aside exits 0: go-cron serves 503 after any non-zero run, and the holder reports this slot.
  FIXTURE_DUMP_ID=manual plain_backup || fail 'a run that stepped aside reported failure to go-cron'
  grep -Fq 'Backup skipped: another backup run is still publishing' "${BACKUP_DIR}/../plain.log" ||
    fail 'a competing run entered the backup publication transaction'
  selfhost_python "${IMAGE_DIR}/selfcheck.py" health || fail 'refusing a concurrent run withdrew the previous health marker'
  : >"$PAUSE_RELEASE"
  scheduled_status=0
  wait "$PAUSED_PID" || scheduled_status=$?
  PAUSED_PID=""
  ((scheduled_status == 0)) || { cat "${BACKUP_DIR}/../"*.log >&2; fail "the resumed scheduled run failed ($pause)"; }
  assert_advertised_recovery_points
  selfhost_python "${IMAGE_DIR}/selfcheck.py" health || fail "the resumed backup left health failing ($pause)"
  [[ -z "$(find "$BACKUP_DIR" -type f -name '*.sql.gz' -exec zgrep -lF -e '-- publication run: manual' {} +)" ]] ||
    fail 'the competing run published a dump'
  export FIXTURE_EPOCH=$((BASE_EPOCH + DAY + 3600))
  plain_backup || { cat "${BACKUP_DIR}/../plain.log" >&2; fail "rerun after the race failed ($pause)"; }
  assert_converged
done
export SELFCHECK_TEST_MODE=ok

check_scheduler_health() {
  local expected directory health status image container_name
  image="${SELFHOST_BACKUP_TEST_IMAGE:-${BACKUP_IMAGE:-$(yq -r '.selfhost_images.backup' "$ROOT_DIR/toolchain-manifest.yaml")}}"
  cat >"${RUN_DIR}/scheduled-backup" <<'SH'
#!/bin/bash
set -eu
[[ "$BACKUP_FIXTURE_STATUS" == 0 ]] || exit 42
printf 'verified\n' >/backups/published
printf '/backups/published\n' >"$BACKUP_SUCCESS_MARKER"
SH
  chmod 0755 "${RUN_DIR}/scheduled-backup"
  for status in 0 42; do
    directory="${RUN_DIR}/scheduler-${status}"
    mkdir "$directory"
    container_name="chronicle-backup-selfcheck-${RUN_DIR##*/}-${status}"
    SCHEDULER_CONTAINER="$container_name"
    docker run -d --name "$container_name" --network none --memory 256m --user 0 \
      --health-interval=1s --health-start-period=0s --health-retries=1 \
      -e VALIDATE_ON_START=FALSE -e BACKUP_ON_START=TRUE -e "BACKUP_FIXTURE_STATUS=$status" \
      -e BACKUP_SUCCESS_MARKER=/backups/success-marker \
      -v "${RUN_DIR}/scheduled-backup:/backup.sh:ro" -v "$directory:/backups" \
      -v "$IMAGE_DIR/init.sh:/init.sh:ro" -v "$IMAGE_DIR/selfcheck.py:/selfcheck.py:ro" \
      -v "$ROOT_DIR/selfhost/chronicle_ops/dump.py:/dump.py:ro" "$image" >/dev/null
    expected=healthy
    [[ "$status" == 0 ]] || expected=unhealthy
    health=starting
    for _ in $(seq 1 30); do
      health=$(docker inspect --format '{{.State.Health.Status}}' "$SCHEDULER_CONTAINER")
      [[ "$health" != "$expected" ]] || break
      sleep 0.2
    done
    [[ "$health" == "$expected" ]] || fail "scheduler health did not become $expected"
    [[ $(docker exec "$SCHEDULER_CONTAINER" readlink /proc/1/exe) == /usr/local/bin/go-cron ]] ||
      fail 'scheduler does not own the running job and health endpoint'
    docker rm -fv "$SCHEDULER_CONTAINER" >/dev/null
    SCHEDULER_CONTAINER=""
  done
}
check_scheduler_health
echo 'self-host backup self-check test passed'
