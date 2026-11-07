#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
source "$ROOT_DIR/tests/security/lib/selfhost-fixtures.sh"
RUN_PARENT="${SELFHOST_ROTATION_TEST_ROOT:-${ROOT_DIR}/build/operator-test-runs/selfhost-secret-rotation}"
REAL_PYTHON="$(command -v python3)"
OLD_POSTGRES_APP="$(selfhost_python -c 'from selfhost_fixture import FIXTURE_POSTGRES_APP_PASSWORD; print(FIXTURE_POSTGRES_APP_PASSWORD)')"

fail() {
  echo "self-host secret-rotation test failed: $*" >&2
  exit 1
}

[[ "$RUN_PARENT" == /* ]] || fail "test run parent must be absolute"
case "$RUN_PARENT" in
  /tmp|/tmp/*|/private/tmp|/private/tmp/*|/var/folders|/var/folders/*)
    fail "test run parent must not use a system temporary directory"
    ;;
esac

umask 077
/bin/mkdir -p "$RUN_PARENT"
RUN_DIR="$(/usr/bin/mktemp -d "${RUN_PARENT}/run.XXXXXX")"
/bin/chmod 0700 "$RUN_DIR"
trap '/bin/rm -rf -- "$RUN_DIR"' EXIT

OLD_POSTGRES='fixture-old-postgres-password-0123456789'
OLD_JWT='fixture-old-jwt-signing-secret-0123456789'
OLD_METRICS='fixture-old-metrics-password-0123456789'
OLD_INTERNAL='fixture-old-internal-web-secret-0123456789'
OLD_GRAFANA='fixture-old-grafana-password-0123456789'
DASHBOARD_PASSWORD='fixture-"quoted\dashboard-password-0123456789'
GENERATED='abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789'
BCRYPT='$2a$14$fixturebcryptvalueabcdefghijklmnopqrstuv0123456789ABCDE'
NEW_BCRYPT='$2a$14$fixtureforwardhashvalueabcdefghijklmnopqrst0123456789'

write_secret_file() {
  local path="$1" value="$2"
  printf '%s' "$value" >"$path"
  /bin/chmod 0600 "$path"
}

setup_case() {
  local name="$1"
  CASE_DIR="${RUN_DIR}/${name}"
  SELFHOST_DIR="${CASE_DIR}/selfhost"
  COMMAND_DIR="${CASE_DIR}/commands"
  OUTPUT="${CASE_DIR}/output.txt"
  ARGS_LOG="${CASE_DIR}/argv.log"
  DB_PASSWORD_FILE="${CASE_DIR}/database-password"
  GRAFANA_PASSWORD_FILE="${CASE_DIR}/grafana-password"
  TDE_STATE_FILE="${CASE_DIR}/tde-state"
  GENERATED_FILE="${CASE_DIR}/generated-secret"
  DASHBOARD_FILE="${CASE_DIR}/dashboard-password"
  BCRYPT_FILE="${CASE_DIR}/bcrypt"
  FAIL_FIRST_UP_FILE="${CASE_DIR}/fail-first-up"
  KEYRING_BACKUP_FILE="${SELFHOST_DIR}/backups/keyring/chronicle-keyring.per"
  /bin/mkdir -p "$SELFHOST_DIR" "$COMMAND_DIR"
  copy_selfhost_setup_fixture "$SELFHOST_DIR"
  /bin/chmod 0755 "${SELFHOST_DIR}/rotate-secret.sh"
  cat >"${SELFHOST_DIR}/chronicle" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
[[ "$*" == 'verify --dashboard-password' ]] || exit 80
password="$(cat)"
expected="$(cat "${SELFHOST_ROTATION_TEST_DASHBOARD_FILE}")"
[[ "$password" == "$expected" ]] || exit 81
printf 'verify-dashboard-password\n' >>"${SELFHOST_ROTATION_TEST_ARGS_LOG}"
EOF
  /bin/chmod 0755 "${SELFHOST_DIR}/chronicle"
  write_secret_file "$DB_PASSWORD_FILE" "$OLD_POSTGRES"
  write_secret_file "$GRAFANA_PASSWORD_FILE" "$OLD_GRAFANA"
  write_secret_file "$TDE_STATE_FILE" 'chronicle_key|chronicle_keyring'
  write_secret_file "$GENERATED_FILE" "$GENERATED"
  write_secret_file "$DASHBOARD_FILE" "$DASHBOARD_PASSWORD"
  write_secret_file "$BCRYPT_FILE" "$BCRYPT"

  cat >"${SELFHOST_DIR}/.env" <<EOF
DOMAIN=chronicle.example.test
COMPOSE_PROJECT_NAME=chronicle-selfhost-rotation-fixture
CHRONICLE_STATE_DIR=.
COMPOSE_FILE=docker-compose.yml:overlays/mode-behind-proxy-internal.yml:overlays/backups.yml:overlays/monitoring.yml
ENABLE_ENCRYPTION=true
INTERNAL_BIND=127.0.0.1
INTERNAL_PORT=18081
DASHBOARD_USER=researcher
DASHBOARD_PASSWORD_HASH='$BCRYPT'
POSTGRES_USER=chronicle
POSTGRES_DB=chronicle
POSTGRES_PASSWORD='$OLD_POSTGRES'
POSTGRES_APP_PASSWORD='$OLD_POSTGRES_APP'
JWT_SECRET='$OLD_JWT'
METRICS_PASSWORD='$OLD_METRICS'
CHRONICLE_INTERNAL_WEB_SECRET='$OLD_INTERNAL'
CHRONICLE_REVIEWER_ACCESS_ENABLED=false
CHRONICLE_REVIEWER_ACCESS_SECRET=
CHRONICLE_REVIEWER_STUDY_ID=00000000-0000-0000-0000-000000000001
CHRONICLE_REVIEWER_PARTICIPANT_ID=play-reviewer
GRAFANA_ADMIN_PASSWORD='$OLD_GRAFANA'
GRAFANA_BIND=127.0.0.1
GRAFANA_PORT=13000
CADDY_IMAGE=ghcr.io/example/caddy@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
RELEASE_VERSION=9.8.7-test.1
EOF
  /bin/chmod 0600 "${SELFHOST_DIR}/.env"

  /bin/cp "${ROOT_DIR}/tests/security/fixtures/selfhost-secret-rotation/commands/"* "$COMMAND_DIR/"
  /bin/chmod 0755 "${COMMAND_DIR}/openssl" "${COMMAND_DIR}/python3" \
    "${COMMAND_DIR}/docker" "${COMMAND_DIR}/curl"
}

run_rotation() {
  local fail_first_up="${1:-false}"
  shift || true
  local -a env_args=(
    "CHRONICLE_INTERNAL_WEB_SECRET=fixture-inherited-secret-must-not-reach-startup-probes"
    "JWT_SECRET_PREVIOUS=fixture-inherited-previous-key-must-not-reach-child-environments"
    "PATH=${COMMAND_DIR}:${PATH}"
    "SELFHOST_ROTATION_TEST_REAL_PYTHON=${REAL_PYTHON}"
    "SELFHOST_ROTATION_TEST_GENERATED_FILE=${GENERATED_FILE}"
    "SELFHOST_ROTATION_TEST_DASHBOARD_FILE=${DASHBOARD_FILE}"
    "SELFHOST_ROTATION_TEST_BCRYPT_FILE=${BCRYPT_FILE}"
    "SELFHOST_ROTATION_TEST_OLD_POSTGRES_FILE=${CASE_OLD_POSTGRES_FILE:-$DB_PASSWORD_FILE}"
    "SELFHOST_ROTATION_TEST_DB_PASSWORD_FILE=${DB_PASSWORD_FILE}"
    "SELFHOST_ROTATION_TEST_GRAFANA_PASSWORD_FILE=${GRAFANA_PASSWORD_FILE}"
    "SELFHOST_ROTATION_TEST_TDE_STATE_FILE=${TDE_STATE_FILE}"
    "SELFHOST_ROTATION_TEST_KEYRING_BACKUP_FILE=${KEYRING_BACKUP_FILE}"
    "SELFHOST_ROTATION_TEST_ARGS_LOG=${ARGS_LOG}"
    "SELFHOST_ROTATION_TEST_MONITORING_LOG=${CASE_DIR}/monitoring.jsonl"
    "SELFHOST_ROTATION_TEST_DASHBOARD_CODE=${CASE_DASHBOARD_CODE:-200}"
    "SELFHOST_ROTATION_TEST_CURL_STATUS=${CASE_CURL_STATUS:-0}"
  )
  if [[ "$fail_first_up" == true ]]; then
    env_args+=("SELFHOST_ROTATION_TEST_FAIL_FIRST_UP_FILE=${FAIL_FIRST_UP_FILE}")
  fi
  if [[ "${CASE_LOSE_ALTER_ACK:-false}" == true ]]; then
    env_args+=("SELFHOST_ROTATION_TEST_LOSE_ALTER_ACK=true")
  fi
  if [[ "${CASE_LOSE_GRAFANA_ACK:-false}" == true ]]; then
    env_args+=("SELFHOST_ROTATION_TEST_LOSE_GRAFANA_ACK=true")
  fi
  if [[ "${CASE_GRAFANA_UNREACHABLE:-false}" == true ]]; then
    env_args+=("SELFHOST_ROTATION_TEST_GRAFANA_UNREACHABLE=true")
  fi
  if [[ "${CASE_PG_DUMP_FAIL:-false}" == true ]]; then
    env_args+=("SELFHOST_ROTATION_TEST_PG_DUMP_FAIL=true")
  fi
  (cd "$SELFHOST_DIR" && env "${env_args[@]}" /bin/bash ./rotate-secret.sh "$@") \
    >"$OUTPUT" 2>&1
}

write_transaction() {
  local kind="$1" action="$2" phase="$3"
  local transaction="${SELFHOST_DIR}/.chronicle-secret-rotation"
  /bin/mkdir "$transaction"
  /bin/chmod 0700 "$transaction"
  /bin/cp "${SELFHOST_DIR}/.env" "${transaction}/old.env"
  printf '%s\n' "$kind" >"${transaction}/kind"
  printf '%s\n' "$action" >"${transaction}/action"
  printf '%s\n' "$phase" >"${transaction}/phase"
  # A persisted PID can belong to this unrelated test process after a host reboot.
  printf '%s\n' "$$" >"${transaction}/owner-pid"
  /bin/chmod 0600 "${transaction}/old.env" "${transaction}/kind" \
    "${transaction}/action" "${transaction}/phase"
}

replace_env_value() {
  local key="$1" value="$2" temporary="${SELFHOST_DIR}/.env.replacement"
  printf '%s\0%s\0' "$key" "$value" | \
    "$REAL_PYTHON" /dev/fd/3 "${SELFHOST_DIR}/.env" "$temporary" 3<<'PY'
from pathlib import Path
import re
import sys

source = Path(sys.argv[1])
destination = Path(sys.argv[2])
values = sys.stdin.buffer.read().split(b"\0")
if values and values[-1] == b"":
    values.pop()
if len(values) != 2:
    raise SystemExit("malformed fixture env update")
key, value = (item.decode("utf-8") for item in values)
text = source.read_text(encoding="utf-8")
pattern = re.compile(rf"^{re.escape(key)}=.*$", re.MULTILINE)
if len(pattern.findall(text)) != 1:
    raise SystemExit(f"expected exactly one {key}")
destination.write_text(pattern.sub(lambda _match: f"{key}='{value}'", text), encoding="utf-8")
PY
  /bin/chmod 0600 "$temporary"
  /bin/mv "$temporary" "${SELFHOST_DIR}/.env"
}

assert_custody() {
  local output="$1" args="$2"
  if [[ -e "$args" ]]; then
    ! grep -Eq '^compose-up:.*--wait.* ca-export( |$)' "$args" ||
      fail 'rotation waited for the exited CA export one-shot'
    if grep -Eq '^compose-up:.*--remove-orphans' "$args"; then
      grep -Fq 'compose-run:run --rm --no-deps ca-export' "$args" ||
        fail 'rotation omitted the separate CA export one-shot'
    fi
  fi
  for secret in "$OLD_POSTGRES" "$OLD_POSTGRES_APP" "$OLD_JWT" "$OLD_METRICS" \
    "$OLD_INTERNAL" "$OLD_GRAFANA" "$DASHBOARD_PASSWORD" "$GENERATED"; do
    ! grep -Fq "$secret" "$output" || fail "secret was printed"
    [[ ! -e "$args" ]] || ! grep -Fq "$secret" "$args" || fail "secret reached subprocess argv"
  done
  if [[ -d "${SELFHOST_DIR}/.chronicle-secret-rotation" ]]; then
    fail "successful rotation left its transaction directory"
  fi
  receipt="$(find "${SELFHOST_DIR}/operator-receipts/secret-rotations" -type f -name '*.json' | head -1)"
  [[ -n "$receipt" && -s "$receipt" ]] || fail "successful rotation emitted no receipt"
  /bin/chmod 0600 "$receipt" 2>/dev/null || true
  for secret in "$OLD_POSTGRES" "$OLD_POSTGRES_APP" "$OLD_JWT" "$OLD_METRICS" \
    "$OLD_INTERNAL" "$OLD_GRAFANA" "$DASHBOARD_PASSWORD" "$GENERATED"; do
    ! grep -Fq "$secret" "$receipt" || fail "receipt contains a secret"
  done
}

check_dashboard_transport() {
  local mode bind code expected status module=rotation-http.sh
  for mode in mode-behind-proxy-internal mode-local-https; do
    for scenario in '127.0.0.1 200 0' '10.0.0.5 403 0' '127.0.0.1 403 1' '10.0.0.5 000 60'; do
      read -r bind code expected <<<"$scenario"
      setup_case "dashboard-${mode}-${bind}-${code}"
      replace_env_value COMPOSE_FILE "docker-compose.yml:overlays/${mode}.yml"
      replace_env_value INTERNAL_BIND "$bind"
      printf "%s\n" "DASHBOARD_BASE_URL=https://management.example.test" >>"$SELFHOST_DIR/.env"
      CASE_DASHBOARD_CODE="$code"
      CASE_CURL_STATUS=0
      [[ "$code" != 000 ]] || CASE_CURL_STATUS=60
      status=0
      printf '%s\n%s\n' "$DASHBOARD_PASSWORD" "$DASHBOARD_PASSWORD" | run_rotation false dashboard || status=$?
      [[ "$status" -eq "$expected" ]] || fail "dashboard transport result: $mode $bind $code ($status)"
      if [[ "$expected" -eq 0 ]]; then
        assert_custody "$OUTPUT" "$ARGS_LOG"
        if [[ "$code" == 200 ]]; then
          grep -Fq dashboard-login-ok "$ARGS_LOG" || fail "dashboard login was not checked"
        else
          grep -Fq dashboard_auth=operator_check_required "$OUTPUT" || fail "ACL denial lacks operator guidance"
        fi
      fi
    done
  done
  CASE_DASHBOARD_CODE=200 CASE_CURL_STATUS=0
  setup_case missing-rotation-http
  /bin/rm "$SELFHOST_DIR/$module"
  if printf '%s\n%s\n' "$DASHBOARD_PASSWORD" "$DASHBOARD_PASSWORD" | run_rotation false dashboard; then
    fail "rotation accepted a missing HTTP module"
  fi
  grep -Fq "$module" "$OUTPUT" || fail "module loading failure was not visible"
  ! grep -Fq compose-up: "$ARGS_LOG" || fail "module loading failure changed services"
  echo 'dashboard transport and module loading checks passed'
}

if [[ "${1:-}" == --dashboard-transport ]]; then
  check_dashboard_transport
  exit 0
fi

check_post_acquisition_interlocks() {
  local operation
  for operation in "$@"; do
    setup_case "racing-${operation}"
    /bin/cp "${SELFHOST_DIR}/.env" "${CASE_DIR}/before.env"
    sha256sum "$DB_PASSWORD_FILE" "$GRAFANA_PASSWORD_FILE" "$TDE_STATE_FILE" >"${CASE_DIR}/before.sha256"
    cat >"${CASE_DIR}/race.bash" <<'SH'
function /bin/mkdir() {
  command /bin/mkdir "$@" || return
  if [[ "$#" -eq 1 && "$1" == "$PWD/.chronicle-secret-rotation" ]]; then
    command /bin/mkdir "$PWD/.chronicle-${SELFHOST_ROTATION_RACING_OPERATION}.lock"
  fi
}
SH
    if (export BASH_ENV="${CASE_DIR}/race.bash" SELFHOST_ROTATION_RACING_OPERATION="$operation"
        run_rotation false --yes jwt); then
      fail "rotation ignored a racing ${operation} lock"
    fi
    grep -Fq "${operation} started while the secret-rotation lock was being acquired; rotation did not start" "$OUTPUT" ||
      fail "rotation did not explain the racing ${operation} interlock"
    [[ -d "${SELFHOST_DIR}/.chronicle-${operation}.lock" ]] || fail "race fixture did not acquire its lock"
    [[ ! -e "${SELFHOST_DIR}/.chronicle-secret-rotation" ]] || fail "racing ${operation} left a rotation transaction"
    cmp -s "${CASE_DIR}/before.env" "${SELFHOST_DIR}/.env" || fail "racing ${operation} changed env"
    sha256sum --check --status "${CASE_DIR}/before.sha256" || fail "racing ${operation} changed a secret"
    [[ ! -d "${SELFHOST_DIR}/operator-receipts" ]] || fail "racing ${operation} emitted a rotation receipt"
    ! grep -Eq '^compose-(up|exec|run):' "$ARGS_LOG" || fail "racing ${operation} changed containers"
    echo "racing ${operation} interlock passed without env, secret or container changes"
  done
}

if [[ "${1:-}" == --post-acquisition-interlocks ]]; then
  shift
  if [[ "$#" -eq 0 ]]; then set -- upgrade restore; fi
  check_post_acquisition_interlocks "$@"
  exit 0
fi

check_post_acquisition_interlocks upgrade restore

setup_case restore-interlock
/bin/mkdir "${SELFHOST_DIR}/.chronicle-restore.lock"
printf 'prepared\n' >"${SELFHOST_DIR}/.chronicle-restore.lock/phase"
set +e
run_rotation false --yes jwt
restore_interlock_status=$?
set -e
[[ "$restore_interlock_status" -ne 0 ]] || fail "rotation ignored an active restore lock"
[[ ! -e "${SELFHOST_DIR}/.chronicle-secret-rotation" ]] ||
  fail "restore interlock left a partial rotation transaction"
grep -Fq 'a restore is active or incomplete' "$OUTPUT" ||
  fail "rotation did not explain the restore interlock"
grep -Fq 'Run ./chronicle restore --recover' "$OUTPUT" ||
  fail "rotation did not name the restore recovery command"

setup_case recover-upgrade-interlock
/bin/mkdir "${SELFHOST_DIR}/.chronicle-secret-rotation" "${SELFHOST_DIR}/.chronicle-upgrade.lock"
printf 'jwt\n' >"${SELFHOST_DIR}/.chronicle-secret-rotation/kind"
printf '{"previous": "/releases/previous/selfhost"}\n' >"${SELFHOST_DIR}/.chronicle-upgrade.lock/recovery.json"
set +e
run_rotation false --yes recover --rollback
recover_interlock_status=$?
set -e
[[ "$recover_interlock_status" -ne 0 ]] || fail "rotation recovery ignored an incomplete update"
grep -Fq 'Run ./chronicle update from /releases/previous/selfhost' "$OUTPUT" ||
  fail "rotation recovery did not name the update recovery command"
[[ -e "${SELFHOST_DIR}/.chronicle-secret-rotation/kind" ]] || fail "refused recovery changed the rotation journal"

setup_case tde-restore-interlock
/bin/mkdir "${SELFHOST_DIR}/.chronicle-restore.lock"
printf 'prepared\n' >"${SELFHOST_DIR}/.chronicle-restore.lock/phase"
set +e
run_rotation false --yes tde
tde_restore_interlock_status=$?
set -e
[[ "$tde_restore_interlock_status" -ne 0 ]] ||
  fail "TDE rotation ignored an active restore lock"
! grep -Fq pg_dump "$ARGS_LOG" ||
  fail "TDE rotation took a database backup before acquiring its operation lock"

setup_case jwt
run_rotation false --yes jwt
grep -Fqx "JWT_SECRET='$GENERATED'" "${SELFHOST_DIR}/.env" || fail "JWT secret was not updated"
grep -Fqx "JWT_SECRET_PREVIOUS='$OLD_JWT'" "${SELFHOST_DIR}/.env" || fail "routine JWT rotation did not retain its previous key"
"$REAL_PYTHON" - "$SELFHOST_DIR" <<'PY_JWT_WINDOW'
from pathlib import Path
import sys
import time
sys.path.insert(0, sys.argv[1])
from chronicle_ops.envfile import read_env, value
settings = read_env(Path(sys.argv[1]) / '.env')
remaining = int(value(settings, 'JWT_SECRET_PREVIOUS_EXPIRES_AT')) - int(time.time())
assert 0 < remaining <= int(value(settings, 'DASHBOARD_SESSION_MINUTES', '480')) * 60
PY_JWT_WINDOW
grep -Fq 'compose-up:' "$ARGS_LOG" || fail "JWT rotation did not recreate the backend"
assert_custody "$OUTPUT" "$ARGS_LOG"
/bin/cp "${SELFHOST_DIR}/.env" "${CASE_DIR}/before-overlap-retry"
if run_rotation false --yes jwt; then
  fail "routine rotation silently retired a key whose overlap is active"
fi
cmp -s "${SELFHOST_DIR}/.env" "${CASE_DIR}/before-overlap-retry" || fail "refused overlap retry changed credentials"
grep -Fq 'previous JWT overlap is still active' "$OUTPUT" || fail "overlap retry did not explain its refusal"

setup_case jwt-compromise
printf "JWT_SECRET_PREVIOUS='fixture-older-key-for-overlap-0123456789'\nJWT_SECRET_PREVIOUS_EXPIRES_AT='%s'\n" \
  "$(( $(date +%s) + 600 ))" >>"${SELFHOST_DIR}/.env"
run_rotation false --yes jwt --revoke-sessions
grep -Fqx "JWT_SECRET_PREVIOUS=''" "${SELFHOST_DIR}/.env" || fail "compromise rotation retained a previous key"
grep -Fqx "JWT_SECRET_PREVIOUS_EXPIRES_AT='0'" "${SELFHOST_DIR}/.env" || fail "compromise rotation retained an overlap window"
assert_custody "$OUTPUT" "$ARGS_LOG"

assert_monitoring_refresh() {
  python3 - "${CASE_DIR}/monitoring.jsonl" "$1" <<'PY'
import argparse
import hashlib
import json
from pathlib import Path
import sys

rows = [json.loads(line) for line in Path(sys.argv[1]).read_text().splitlines()]
refresh = next(row for row in rows if row["args"][0] == "run" and row["args"][-1] == "monitoring-config")
assert {"--rm", "--no-deps"} <= set(refresh["args"])
assert refresh["credentialHash"] == hashlib.sha256(sys.argv[2].encode()).hexdigest(), "scraper used stale credentials"
up = next(row for row in rows if row["args"][0] == "up")
parser = argparse.ArgumentParser()
for option in ("-d", "--wait", "--no-deps", "--force-recreate"):
    parser.add_argument(option, action="store_true", required=True)
parser.add_argument("--wait-timeout", type=int, required=True)
parser.add_argument("services", nargs="+")
options = parser.parse_args(up["args"][1:])
assert options.wait_timeout > 0
assert set(options.services) == {"backend", "victoriametrics"}, "wrong recreated service set"
assert any(row["args"][0] == "exec" and "grafana" in row["args"]
           and row["args"][-1] == "http://victoriametrics:8428/api/v1/targets" for row in rows), "target health was not checked"
PY
}

setup_case metrics
run_rotation false --yes metrics
grep -Fqx "METRICS_PASSWORD='$GENERATED'" "${SELFHOST_DIR}/.env" || fail "metrics password was not updated"
assert_monitoring_refresh "$GENERATED"
assert_custody "$OUTPUT" "$ARGS_LOG"

setup_case internal-web
run_rotation false --yes internal-web
grep -Fqx "CHRONICLE_INTERNAL_WEB_SECRET='$GENERATED'" "${SELFHOST_DIR}/.env" \
  || fail "internal web secret was not updated"
grep -Fq 'compose-up:' "$ARGS_LOG" || fail "internal-web rotation did not recreate backend and web"
assert_custody "$OUTPUT" "$ARGS_LOG"

saved_dashboard_password="$DASHBOARD_PASSWORD"
DASHBOARD_PASSWORD=123456789012345
setup_case short-dashboard
if printf '%s\n%s\n' "$DASHBOARD_PASSWORD" "$DASHBOARD_PASSWORD" | run_rotation false dashboard; then
  fail "rotation accepted a 15-character dashboard password"
fi
grep -Fq 'dashboard password must be at least 16 characters' "$OUTPUT" || fail "rotation omitted the short-password diagnostic"
DASHBOARD_PASSWORD=1234567890123456
setup_case boundary-dashboard
printf '%s\n%s\n' "$DASHBOARD_PASSWORD" "$DASHBOARD_PASSWORD" | run_rotation false dashboard || fail "rotation rejected a valid 16-character password"
DASHBOARD_PASSWORD="$saved_dashboard_password"

setup_case dashboard
printf '%s\n%s\n' "$DASHBOARD_PASSWORD" "$DASHBOARD_PASSWORD" | run_rotation false dashboard \
  || fail "dashboard rotation fixture failed"
grep -Fqx "DASHBOARD_PASSWORD_HASH='$BCRYPT'" "${SELFHOST_DIR}/.env" \
  || fail "dashboard bcrypt hash was not updated"
assert_custody "$OUTPUT" "$ARGS_LOG"
grep -Fq 'dashboard-login-ok' "$ARGS_LOG" ||
  fail "dashboard rotation did not verify a backend dashboard session"
grep -Fq 'compose-up:up -d --wait --wait-timeout 300 --no-deps --force-recreate backend web' "$ARGS_LOG" ||
  fail "dashboard rotation did not recreate both backend and web"
# Sessions minted under the old password end once the new hash is live: the backend refuses
# tokens issued at or before the same cutoff restore writes (JwtBlocklist revoke-all).
recreated_line="$(grep -n -m1 -F 'force-recreate backend web' "$ARGS_LOG" | cut -d: -f1)"
cutoff_line="$(grep -n -m1 -Fx 'session-cutoff' "$ARGS_LOG" | cut -d: -f1)" ||
  fail "dashboard rotation left sessions issued under the old password valid"
(( cutoff_line > recreated_line )) || fail "dashboard session cutoff ran before the new password was live"
expected_cutoff="$(cd "${ROOT_DIR}/selfhost" && PYTHONDONTWRITEBYTECODE=1 "$REAL_PYTHON" -c \
  'from chronicle_ops.dump import SESSION_CUTOFF_SQL; print(SESSION_CUTOFF_SQL)')"
[[ "$(<"${CASE_DIR}/session-cutoff.sql")" == "$expected_cutoff" ]] ||
  fail "dashboard rotation wrote a session cutoff other than the restore contract's"

setup_case reviewer
run_rotation false --yes reviewer
grep -Fqx "CHRONICLE_REVIEWER_ACCESS_ENABLED='true'" "${SELFHOST_DIR}/.env" \
  || fail "reviewer rotation did not enable the exact reviewer route"
grep -Fqx "CHRONICLE_REVIEWER_ACCESS_SECRET='$GENERATED'" "${SELFHOST_DIR}/.env" \
  || fail "reviewer rotation did not publish the generated credential"
grep -Fq 'compose-up:up -d --wait --wait-timeout 300 --no-deps --force-recreate backend' "$ARGS_LOG" \
  || fail "reviewer rotation did not recreate only the backend"
# The backend reads its credentials from files (secrets-init.sh); --no-deps skips that job, so
# rotation must rewrite them before the recreate or the backend starts with the old secret.
secrets_line="$(grep -n -m1 -F 'compose-run:run --rm --no-deps secrets-init' "$ARGS_LOG" | cut -d: -f1)" ||
  fail "reviewer rotation did not rewrite the credential files"
recreate_line="$(grep -n -m1 -F -- '--force-recreate backend' "$ARGS_LOG" | cut -d: -f1)"
(( secrets_line < recreate_line )) || fail "credential files were rewritten after the backend was recreated"
assert_custody "$OUTPUT" "$ARGS_LOG"

setup_case postgres
run_rotation false --yes postgres
grep -Fqx "POSTGRES_PASSWORD='$GENERATED'" "${SELFHOST_DIR}/.env" \
  || fail "PostgreSQL password was not updated in .env"
[[ "$(cat "$DB_PASSWORD_FILE")" == "$GENERATED" ]] \
  || fail "PostgreSQL role password was not updated"
grep -Fq 'compose-up:up -d --wait --wait-timeout 300 --remove-orphans' "$ARGS_LOG" \
  || fail "PostgreSQL rotation did not reconcile the complete stack"
assert_custody "$OUTPUT" "$ARGS_LOG"

# ALTER ROLE commits but its acknowledgement is lost: rollback must reverse it rather than
# restore an .env whose password the database no longer accepts.
setup_case postgres-lost-ack
CASE_LOSE_ALTER_ACK=true
# The database password file changes mid-run; give the fake a stable copy of the old value.
CASE_OLD_POSTGRES_FILE="${CASE_DIR}/old-postgres-password"
write_secret_file "$CASE_OLD_POSTGRES_FILE" "$OLD_POSTGRES"
set +e
run_rotation false --yes postgres
lost_ack_status=$?
set -e
unset CASE_LOSE_ALTER_ACK CASE_OLD_POSTGRES_FILE
[[ "$lost_ack_status" -ne 0 ]] || fail "lost ALTER acknowledgement unexpectedly succeeded"
grep -Fqx "POSTGRES_PASSWORD='$OLD_POSTGRES'" "${SELFHOST_DIR}/.env" \
  || fail "lost-acknowledgement rollback did not restore the previous .env"
[[ "$(cat "$DB_PASSWORD_FILE")" == "$OLD_POSTGRES" ]] \
  || fail "lost-acknowledgement rollback left the database on a password no file holds"
[[ ! -e "${SELFHOST_DIR}/.chronicle-secret-rotation" ]] \
  || fail "completed lost-acknowledgement rollback left its transaction"

setup_case grafana
run_rotation false --yes grafana
grep -Fqx "GRAFANA_ADMIN_PASSWORD='$GENERATED'" "${SELFHOST_DIR}/.env" \
  || fail "Grafana password was not updated in .env"
[[ "$(cat "$GRAFANA_PASSWORD_FILE")" == "$GENERATED" ]] \
  || fail "Grafana API password was not updated"
assert_custody "$OUTPUT" "$ARGS_LOG"

# Grafana commits the change but its response is lost. Rollback must reverse
# it rather than restore an .env whose password Grafana no longer accepts.
setup_case grafana-lost-ack
CASE_LOSE_GRAFANA_ACK=true
set +e
run_rotation false --yes grafana
grafana_lost_ack_status=$?
set -e
unset CASE_LOSE_GRAFANA_ACK
[[ "$grafana_lost_ack_status" -ne 0 ]] || fail "lost Grafana acknowledgement unexpectedly succeeded"
grep -Fqx "GRAFANA_ADMIN_PASSWORD='$OLD_GRAFANA'" "${SELFHOST_DIR}/.env" \
  || fail "lost Grafana acknowledgement rollback did not restore the previous .env"
[[ "$(cat "$GRAFANA_PASSWORD_FILE")" == "$OLD_GRAFANA" ]] \
  || fail "lost Grafana acknowledgement left Grafana on a password no file holds"
[[ ! -e "${SELFHOST_DIR}/.chronicle-secret-rotation" ]] \
  || fail "completed lost Grafana acknowledgement rollback left its transaction"

# The change never reached Grafana, so reversing it fails (NEW was never set);
# the old password still works, so rollback is complete and must not keep the transaction.
setup_case grafana-unreachable
CASE_GRAFANA_UNREACHABLE=true
set +e
run_rotation false --yes grafana
grafana_unreachable_status=$?
set -e
unset CASE_GRAFANA_UNREACHABLE
[[ "$grafana_unreachable_status" -ne 0 ]] || fail "unreachable Grafana rotation unexpectedly succeeded"
grep -Fqx "GRAFANA_ADMIN_PASSWORD='$OLD_GRAFANA'" "${SELFHOST_DIR}/.env" \
  || fail "unreachable Grafana rollback did not restore the previous .env"
[[ "$(cat "$GRAFANA_PASSWORD_FILE")" == "$OLD_GRAFANA" ]] \
  || fail "unreachable Grafana rollback changed Grafana's password"
[[ ! -e "${SELFHOST_DIR}/.chronicle-secret-rotation" ]] \
  || fail "unreachable Grafana rollback kept a transaction although the old password still works"

setup_case tde
run_rotation false --yes tde
[[ "$(cat "$TDE_STATE_FILE")" == chronicle_key_*'|chronicle_keyring' ]] \
  || fail "TDE rotation did not activate a new principal key"
backup_count="$(find "${SELFHOST_DIR}/backups/secret-rotation" -type f -name '*.sql.gz' | wc -l | tr -d ' ')"
[[ "$backup_count" == 1 ]] || fail "TDE rotation did not retain exactly one fresh SQL backup"
gzip -t "$(find "${SELFHOST_DIR}/backups/secret-rotation" -type f -name '*.sql.gz' | head -1)" \
  || fail "TDE pre-rotation backup is not a valid gzip stream"
[[ -s "$KEYRING_BACKUP_FILE" ]] || fail "TDE rotation did not refresh the keyring backup"
assert_custody "$OUTPUT" "$ARGS_LOG"

setup_case rollback
set +e
run_rotation true --yes internal-web
rollback_status=$?
set -e
[[ "$rollback_status" -ne 0 ]] || fail "forced service failure unexpectedly succeeded"
grep -Fqx "CHRONICLE_INTERNAL_WEB_SECRET='$OLD_INTERNAL'" "${SELFHOST_DIR}/.env" \
  || fail "failed rotation did not restore the prior .env"
[[ ! -e "${SELFHOST_DIR}/.chronicle-secret-rotation" ]] \
  || fail "successful automatic rollback left a stale transaction"
for secret in "$OLD_INTERNAL" "$GENERATED"; do
  ! grep -Fq "$secret" "$OUTPUT" || fail "rollback output printed a secret"
  ! grep -Fq "$secret" "$ARGS_LOG" || fail "rollback put a secret in subprocess argv"
done

setup_case recover-jwt-forward
write_transaction jwt rotate env-published
replace_env_value JWT_SECRET "$GENERATED"
run_rotation false --yes recover --forward
grep -Fqx "JWT_SECRET='$GENERATED'" "${SELFHOST_DIR}/.env" \
  || fail "JWT forward recovery did not retain the published secret"
assert_custody "$OUTPUT" "$ARGS_LOG"

setup_case recover-internal-rollback
write_transaction internal-web rotate env-published
replace_env_value CHRONICLE_INTERNAL_WEB_SECRET "$GENERATED"
run_rotation false --yes recover --rollback
grep -Fqx "CHRONICLE_INTERNAL_WEB_SECRET='$OLD_INTERNAL'" "${SELFHOST_DIR}/.env" \
  || fail "internal-web rollback recovery did not restore the saved secret"
assert_custody "$OUTPUT" "$ARGS_LOG"

setup_case recover-dashboard-forward
write_transaction dashboard rotate env-published
replace_env_value DASHBOARD_PASSWORD_HASH "$NEW_BCRYPT"
run_rotation false --yes recover --forward
grep -Fqx "DASHBOARD_PASSWORD_HASH='$NEW_BCRYPT'" "${SELFHOST_DIR}/.env" ||
  fail "dashboard forward recovery did not retain the published hash"
grep -Fq 'compose-up:up -d --wait --wait-timeout 300 --no-deps --force-recreate backend web' "$ARGS_LOG" ||
  fail "dashboard forward recovery did not recreate backend and web"
grep -Fqx 'session-cutoff' "$ARGS_LOG" ||
  fail "dashboard forward recovery left sessions issued under the old password valid"
grep -Fq 'rerun ./chronicle verify --dashboard-password' "$OUTPUT" ||
  fail "dashboard recovery did not request the lost cleartext password for operator verification"
assert_custody "$OUTPUT" "$ARGS_LOG"

setup_case recover-dashboard-rollback
write_transaction dashboard rotate env-published
replace_env_value DASHBOARD_PASSWORD_HASH "$NEW_BCRYPT"
run_rotation false --yes recover --rollback
grep -Fqx "DASHBOARD_PASSWORD_HASH='$BCRYPT'" "${SELFHOST_DIR}/.env" ||
  fail "dashboard rollback recovery did not restore the saved hash"
grep -Fq 'compose-up:up -d --wait --wait-timeout 300 --no-deps --force-recreate backend web' "$ARGS_LOG" ||
  fail "dashboard rollback recovery did not recreate backend and web"
assert_custody "$OUTPUT" "$ARGS_LOG"

setup_case recover-metrics-forward
write_transaction metrics rotate env-published
replace_env_value METRICS_PASSWORD "$GENERATED"
run_rotation false --yes recover --forward
assert_monitoring_refresh "$GENERATED"
assert_custody "$OUTPUT" "$ARGS_LOG"

setup_case recover-metrics-rollback
write_transaction metrics rotate env-published
replace_env_value METRICS_PASSWORD "$GENERATED"
run_rotation false --yes recover --rollback
grep -Fqx "METRICS_PASSWORD='$OLD_METRICS'" "${SELFHOST_DIR}/.env" ||
  fail "metrics rollback recovery did not restore the saved credential"
assert_monitoring_refresh "$OLD_METRICS"
assert_custody "$OUTPUT" "$ARGS_LOG"

setup_case recover-postgres-forward
write_transaction postgres rotate env-published
replace_env_value POSTGRES_PASSWORD "$GENERATED"
run_rotation false --yes recover --forward
[[ "$(cat "$DB_PASSWORD_FILE")" == "$GENERATED" ]] \
  || fail "PostgreSQL forward recovery did not reconcile the database role"
assert_custody "$OUTPUT" "$ARGS_LOG"

setup_case recover-grafana-forward
write_transaction grafana rotate env-published
replace_env_value GRAFANA_ADMIN_PASSWORD "$GENERATED"
run_rotation false --yes recover --forward
[[ "$(cat "$GRAFANA_PASSWORD_FILE")" == "$GENERATED" ]] \
  || fail "Grafana forward recovery did not reconcile the API password"
assert_custody "$OUTPUT" "$ARGS_LOG"

setup_case recover-tde-forward
write_transaction tde rotate tde-metadata-ready
printf '%s\n' chronicle_key >"${SELFHOST_DIR}/.chronicle-secret-rotation/old-tde-key"
printf '%s\n' chronicle_key_recovery >"${SELFHOST_DIR}/.chronicle-secret-rotation/new-tde-key"
/bin/chmod 0600 "${SELFHOST_DIR}/.chronicle-secret-rotation/old-tde-key" \
  "${SELFHOST_DIR}/.chronicle-secret-rotation/new-tde-key"
run_rotation false --yes recover --forward
[[ "$(cat "$TDE_STATE_FILE")" == 'chronicle_key_recovery|chronicle_keyring' ]] \
  || fail "TDE forward recovery did not activate the saved new key"
assert_custody "$OUTPUT" "$ARGS_LOG"

setup_case recover-tde-pre-activation
write_transaction tde rotate prepared
# A hard stop can occur while publishing the pair. A partial file is safe to remove because
# the durable tde-metadata-ready checkpoint is always written before PostgreSQL is touched.
printf '%s\n' chronicle_key >"${SELFHOST_DIR}/.chronicle-secret-rotation/old-tde-key"
/bin/chmod 0600 "${SELFHOST_DIR}/.chronicle-secret-rotation/old-tde-key"
run_rotation false --yes recover --rollback
[[ ! -e "${SELFHOST_DIR}/.chronicle-secret-rotation" ]] \
  || fail "pre-activation TDE rollback did not remove its transaction"
[[ "$(cat "$TDE_STATE_FILE")" == 'chronicle_key|chronicle_keyring' ]] \
  || fail "pre-activation TDE rollback changed the active key"
grep -Fq 'before its durable key-activation checkpoint' "$OUTPUT" \
  || fail "pre-activation TDE rollback did not explain the safe boundary"

setup_case reject-tde-pre-activation-forward
write_transaction tde rotate prepared
set +e
run_rotation false --yes recover --forward
pre_activation_forward_status=$?
set -e
[[ "$pre_activation_forward_status" -ne 0 ]] \
  || fail "pre-activation TDE transaction allowed forward recovery"
[[ -d "${SELFHOST_DIR}/.chronicle-secret-rotation" ]] \
  || fail "rejected pre-activation TDE recovery discarded its transaction"
grep -Fq 'only recover --rollback is safe' "$OUTPUT" \
  || fail "rejected pre-activation TDE recovery did not explain the safe direction"

setup_case reject-tde-incomplete-checkpoint
write_transaction tde rotate tde-metadata-ready
printf '%s\n' chronicle_key >"${SELFHOST_DIR}/.chronicle-secret-rotation/old-tde-key"
/bin/chmod 0600 "${SELFHOST_DIR}/.chronicle-secret-rotation/old-tde-key"
set +e
run_rotation false --yes recover --rollback
incomplete_checkpoint_status=$?
set -e
[[ "$incomplete_checkpoint_status" -ne 0 ]] \
  || fail "TDE recovery accepted an incomplete durable metadata checkpoint"
[[ -d "${SELFHOST_DIR}/.chronicle-secret-rotation" ]] \
  || fail "incomplete TDE checkpoint was not preserved for diagnosis"

setup_case unprepared-recovery
/bin/mkdir "${SELFHOST_DIR}/.chronicle-secret-rotation"
/bin/chmod 0700 "${SELFHOST_DIR}/.chronicle-secret-rotation"
# Crashed after its first journal file but before the phase commit point.
printf 'jwt\n' >"${SELFHOST_DIR}/.chronicle-secret-rotation/kind"
run_rotation false --yes recover --rollback
[[ ! -e "${SELFHOST_DIR}/.chronicle-secret-rotation" ]] \
  || fail "rollback recovery did not remove a pre-publication lock"

setup_case recovery-failure-preserved
write_transaction postgres rotate database-updated
replace_env_value POSTGRES_PASSWORD "$GENERATED"
printf '%s' 'fixture-unrelated-database-password' >"$DB_PASSWORD_FILE"
set +e
run_rotation false --yes recover --forward
recovery_status=$?
set -e
[[ "$recovery_status" -ne 0 ]] || fail "ambiguous PostgreSQL recovery unexpectedly succeeded"
[[ -d "${SELFHOST_DIR}/.chronicle-secret-rotation" ]] \
  || fail "failed recovery discarded its transaction evidence"
for secret in "$OLD_POSTGRES" "$GENERATED"; do
  ! grep -Fq "$secret" "$OUTPUT" || fail "failed recovery printed a secret"
  ! grep -Fq "$secret" "$ARGS_LOG" || fail "failed recovery put a secret in subprocess argv"
done

setup_case tde-partial-cleanup
CASE_PG_DUMP_FAIL=true
set +e
run_rotation false --yes tde
backup_failure_status=$?
set -e
unset CASE_PG_DUMP_FAIL
[[ "$backup_failure_status" -ne 0 ]] || fail "failed TDE backup unexpectedly allowed rotation"
if find "${SELFHOST_DIR}/backups/secret-rotation" -type f -name '*.partial' -print -quit 2>/dev/null | grep -q .; then
  fail "failed TDE pre-rotation backup left a partial file"
fi
[[ "$(cat "$TDE_STATE_FILE")" == 'chronicle_key|chronicle_keyring' ]] \
  || fail "TDE key changed after the pre-rotation backup failed"

# The pre-rotation dump holds all participant data: it must never be written into a directory whose 0700
# mode could not be enforced (e.g. a backups tree still owned by an old root-run container).
if [[ "$(id -u)" -ne 0 ]]; then
  setup_case tde-backup-dir-not-private
  /bin/mkdir -p "${SELFHOST_DIR}/backups"
  # A directory this user cannot chmod stands in for the root-owned backups tree.
  /bin/ln -s /usr/share "${SELFHOST_DIR}/backups/secret-rotation"
  set +e
  run_rotation false --yes tde
  backup_dir_status=$?
  set -e
  [[ "$backup_dir_status" -ne 0 ]] || fail "TDE rotation ran with a non-private backup directory"
  ! grep -Fq 'pg_dump' "$ARGS_LOG" 2>/dev/null \
    || fail "pre-rotation participant-data dump started although the backup directory could not be made 0700"
  grep -Fq 'backup directory' "$OUTPUT" \
    || fail "non-private backup directory failure did not name the backup directory"
  [[ "$(cat "$TDE_STATE_FILE")" == 'chronicle_key|chronicle_keyring' ]] \
    || fail "TDE key changed although the pre-rotation backup was refused"
fi

echo "self-host secret-rotation test passed"
