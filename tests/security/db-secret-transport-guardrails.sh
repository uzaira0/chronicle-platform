#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
source "$ROOT_DIR/tests/security/lib/schema-query-fixture.sh"
RUN_PARENT="${DB_SECRET_TRANSPORT_TEST_ROOT:-${ROOT_DIR}/build/operator-test-runs/db-secret-transport}"

[[ "$RUN_PARENT" == /* ]] || { printf 'test run parent must be absolute\n' >&2; exit 2; }
case "$RUN_PARENT" in
  /tmp|/tmp/*|/private/tmp|/private/tmp/*|/var/folders|/var/folders/*)
    printf 'test run parent must not use a system temporary directory\n' >&2
    exit 2
    ;;
esac
umask 077
/bin/mkdir -p "$RUN_PARENT"
/bin/chmod 0700 "$RUN_PARENT"
RUN_DIR="$(/usr/bin/mktemp -d "${RUN_PARENT}/run.XXXXXX")"
/bin/chmod 0700 "$RUN_DIR"
trap '/bin/rm -rf -- "$RUN_DIR"' EXIT HUP INT TERM

SENTINEL='db-secret-transport-sentinel-734902-not-for-production'
PATTERN_FILE="$RUN_DIR/sentinel.pattern"
printf '%s' "$SENTINEL" >"$PATTERN_FILE"
/bin/chmod 0600 "$PATTERN_FILE"
if command -v sha256sum >/dev/null 2>&1; then
  SENTINEL_SHA256="$(printf '%s' "$SENTINEL" | sha256sum | awk '{print $1}')"
else
  SENTINEL_SHA256="$(printf '%s' "$SENTINEL" | shasum -a 256 | awk '{print $1}')"
fi
failures=0

fail() {
  printf 'database secret transport guard failed: %s\n' "$*" >&2
  failures=$((failures + 1))
}

assert_no_secret_material() {
  local inspected_dir="$1" description="$2"
  if grep -R -F -f "$PATTERN_FILE" "$inspected_dir" >/dev/null 2>&1; then
    fail "$description retained or printed the database password sentinel"
  fi
}

report_fixture_failure() {
  local output_file="$1" description="$2"
  if grep -F -f "$PATTERN_FILE" "$output_file" >/dev/null 2>&1; then
    fail "$description failed and its output contained the password sentinel"
    return
  fi
  printf '%s fixture output:\n' "$description" >&2
  /bin/cat "$output_file" >&2
  fail "$description failed"
}

DOCKER_SECRET_ARG_PATTERN='(^|[[:space:]\\])(-e(=|[[:space:]\\]+)?|--env(=|[[:space:]\\]+))["'\'' ]*(POSTGRES_PASSWORD|PGPASSWORD|FLYWAY_PASSWORD)(=|\b)'
cat >"$RUN_DIR/docker-secret-argument-forms.fixture" <<'DOCKER_SECRET_ARGUMENT_FORMS'
docker run -e POSTGRES_PASSWORD=fixture-value image
docker run -e=PGPASSWORD=fixture-value image
docker run --env FLYWAY_PASSWORD=fixture-value image
docker run --env=POSTGRES_PASSWORD=fixture-value image
docker run -e PGPASSWORD image
docker run -e=FLYWAY_PASSWORD image
docker run --env POSTGRES_PASSWORD image
docker run --env=PGPASSWORD image
docker run -ePOSTGRES_PASSWORD image
docker run -ePOSTGRES_PASSWORD=fixture-value image
docker run -ePGPASSWORD image
docker run -ePGPASSWORD=fixture-value image
docker run -eFLYWAY_PASSWORD image
docker run -eFLYWAY_PASSWORD=fixture-value image
docker run -ePOSTGRES_PASSWORD_FILE image
docker run -ePGPASSWORD_FILE=fixture-path image
docker run --env FLYWAY_PASSWORD_FILE image
DOCKER_SECRET_ARGUMENT_FORMS
DOCKER_SECRET_ARG_MATCHES="$(rg -U -c -- "$DOCKER_SECRET_ARG_PATTERN" \
  "$RUN_DIR/docker-secret-argument-forms.fixture" || true)"
[[ "$DOCKER_SECRET_ARG_MATCHES" == 14 ]] ||
  fail 'the static Docker secret-argument scanner must cover bare-name and assignment forms for -e, joined -e, -e=, --env, and --env= without matching *_FILE names'

if rg -U -n --glob '*.sh' -- "$DOCKER_SECRET_ARG_PATTERN" \
    "$ROOT_DIR/scripts" "$ROOT_DIR/selfhost" "$ROOT_DIR/docker" \
    "$ROOT_DIR/deploy" "$ROOT_DIR/k8s" >"$RUN_DIR/maintained.forbidden"; then
  fail 'a maintained operator/deployment script still places a database password in host Docker argv'
fi

FUNCTIONAL_TARGETS=(
  scripts/flyway-migrate.sh
  scripts/verify-schema-postconditions.sh
  scripts/chronicle-dogfood-report.sh
  scripts/android-auto-upload-e2e.sh
)
for target in "${FUNCTIONAL_TARGETS[@]}"; do
  [[ "$(sed -n '1p' "$ROOT_DIR/$target")" == '#!/bin/bash' ]] ||
    fail "$target must launch Bash directly so an env trampoline cannot inherit database credentials"
done

COMMAND_DIR="$RUN_DIR/commands"
/bin/mkdir -m 0700 "$COMMAND_DIR"
REAL_PYTHON="$(command -v python3)"

cat >"$COMMAND_DIR/guarded-command" <<'GUARDED_COMMAND'
#!/usr/bin/env bash
set -euo pipefail
for secret_name in POSTGRES_PASSWORD PGPASSWORD FLYWAY_PASSWORD; do
  if [[ -n "${!secret_name+x}" ]]; then
    printf 'a database credential reached a host helper environment\n' >&2
    exit 96
  fi
done
command_name="${0##*/}"
case "$command_name" in
  dirname) target=/usr/bin/dirname ;;
  awk) target=/usr/bin/awk ;;
  sed) target=/usr/bin/sed ;;
  date)
    if [[ "${1:-}" == -Is ]]; then
      printf '2026-08-17T20:00:00+00:00\n'
      exit 0
    fi
    target=/bin/date
    ;;
  mkdir) target=/bin/mkdir ;;
  grep) target=/usr/bin/grep ;;
  head) target=/usr/bin/head ;;
  cut) target=/usr/bin/cut ;;
  ls) target=/bin/ls ;;
  sort) target=/usr/bin/sort ;;
  tail) target=/usr/bin/tail ;;
  wc) target=/usr/bin/wc ;;
  chmod) target=/bin/chmod ;;
  mktemp) target=/usr/bin/mktemp ;;
  rm) target=/bin/rm ;;
  stat) target=/usr/bin/stat ;;
  id) target=/usr/bin/id ;;
  python3) target="${REAL_PYTHON:?}" ;;
  sleep) exit 0 ;;
  *) printf 'unsupported guarded command: %s\n' "$command_name" >&2; exit 97 ;;
esac
exec "$target" "$@"
GUARDED_COMMAND
/bin/chmod 0700 "$COMMAND_DIR/guarded-command"
for command_name in dirname awk sed date mkdir grep head cut ls sort tail wc chmod mktemp rm stat id python3 sleep; do
  /bin/ln -s guarded-command "$COMMAND_DIR/$command_name"
done

cat >"$COMMAND_DIR/docker" <<'DOCKER_FIXTURE'
#!/usr/bin/env bash
set -euo pipefail

for secret_name in POSTGRES_PASSWORD PGPASSWORD FLYWAY_PASSWORD; do
  if [[ -n "${!secret_name+x}" ]]; then
    printf 'a database credential reached the Docker client environment\n' >&2
    exit 90
  fi
done
for argument in "$@"; do
  case "$argument" in
    POSTGRES_PASSWORD|PGPASSWORD|FLYWAY_PASSWORD|\
    POSTGRES_PASSWORD=*|PGPASSWORD=*|FLYWAY_PASSWORD=*|\
    -ePOSTGRES_PASSWORD|-ePGPASSWORD|-eFLYWAY_PASSWORD|\
    -ePOSTGRES_PASSWORD=*|-ePGPASSWORD=*|-eFLYWAY_PASSWORD=*|\
    -e=POSTGRES_PASSWORD|-e=PGPASSWORD|-e=FLYWAY_PASSWORD|\
    -e=POSTGRES_PASSWORD=*|-e=PGPASSWORD=*|-e=FLYWAY_PASSWORD=*|\
    --env=POSTGRES_PASSWORD|--env=PGPASSWORD|--env=FLYWAY_PASSWORD|\
    --env=POSTGRES_PASSWORD=*|--env=PGPASSWORD=*|--env=FLYWAY_PASSWORD=*)
      printf 'a database credential variable reached Docker argv\n' >&2
      exit 91
      ;;
  esac
  printf '%q ' "$argument" >>"${FAKE_DOCKER_ARGV:?}"
done
printf '\n' >>"$FAKE_DOCKER_ARGV"

hash_value() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum | awk '{print $1}'
  else
    shasum -a 256 | awk '{print $1}'
  fi
}

verify_password() {
  local candidate="$1" actual_hash
  actual_hash="$(printf '%s' "$candidate" | hash_value)"
  [[ "$actual_hash" == "${TEST_SECRET_SHA256:?}" ]] || {
    printf 'the intended password did not arrive on the protected input channel\n' >&2
    exit 92
  }
}

increment_and_report() {
  local counter_name="$1" counter_file="${FAKE_DOCKER_STATE_DIR:?}/$1.count" count=0
  if [[ -f "$counter_file" ]]; then
    IFS= read -r count <"$counter_file"
  fi
  count=$((count + 1))
  printf '%s\n' "$count" >"$counter_file"
  if ((count >= 2)); then printf '1\n'; else printf '0\n'; fi
}

case "${1:-}" in
  exec)
    [[ " $* " == *' -i '* ]] || { printf 'Docker exec must consume stdin\n' >&2; exit 93; }
    IFS= read -r received_password || { printf 'password input was missing\n' >&2; exit 94; }
    verify_password "$received_password"
    unset received_password
    query="$(/bin/cat)"
    [[ -n "$query" ]] || { printf 'SQL input was missing\n' >&2; exit 95; }
    case "${FAKE_DOCKER_MODE:?}" in
      flyway)
        case "$query" in
          *"to_regclass('public.flyway_schema_history')"*) printf 't\n' ;;
          *"count(*) FROM pg_class"*) printf '1\n' ;;
          *) printf 'unexpected Flyway preflight query\n' >&2; exit 98 ;;
        esac
        ;;
      report) printf 'fixture dogfood report row\n' ;;
      sensors) printf 'fixture AndroidSensor setting row\n' ;;
      auto)
        case "$query" in
          *'from devices'*) printf '1\n' ;;
          *'from api_keys'*) printf '1\n' ;;
          *'from chronicle_usage_events'*'activity_class is not null'*) increment_and_report activity ;;
          *'from chronicle_usage_events'*) increment_and_report events ;;
          *'from upload_buffer'*) printf '0\n' ;;
          *) printf 'unexpected auto-upload query\n' >&2; exit 99 ;;
        esac
        ;;
      schema)
        schema_query_fixture "$query"
        ;;
      *) printf 'unexpected Docker fixture mode\n' >&2; exit 100 ;;
    esac
    ;;
  run)
    env_file=""
    previous=""
    for argument in "$@"; do
      if [[ "$previous" == --env-file ]]; then env_file="$argument"; break; fi
      previous="$argument"
    done
    [[ -n "$env_file" && -f "$env_file" && ! -L "$env_file" ]] || {
      printf 'Flyway did not use a protected Docker env file\n' >&2
      exit 101
    }
    mode="$(/usr/bin/stat -c '%a' "$env_file" 2>/dev/null || /usr/bin/stat -f '%Lp' "$env_file")"
    [[ "$mode" == 600 ]] || { printf 'Flyway Docker env file mode was not 0600\n' >&2; exit 102; }
    password_line="$(/usr/bin/grep -E '^FLYWAY_PASSWORD=' "$env_file")"
    verify_password "${password_line#FLYWAY_PASSWORD=}"
    unset password_line
    printf '%s\n' "$env_file" >"${FAKE_DOCKER_SECRET_PATH:?}"
    if [[ "${FAKE_DOCKER_FAIL_RUN:-0}" == 1 ]]; then
      printf 'simulated Flyway client failure\n' >&2
      exit 104
    fi
    if [[ "${FAKE_DOCKER_BLOCK_RUN:-0}" == 1 ]]; then
      block_child_pid=""
      record_signal() {
        trap '' HUP INT TERM
        if [[ -n "$block_child_pid" ]]; then
          kill -TERM "$block_child_pid" 2>/dev/null || true
          wait "$block_child_pid" 2>/dev/null || true
        fi
        printf '%s\n' "$1" >"${FAKE_DOCKER_SIGNAL_FILE:?}"
        exit "$2"
      }
      trap 'record_signal HUP 129' HUP
      trap 'record_signal INT 130' INT
      trap 'record_signal TERM 143' TERM
      printf '%s\n' "$$" >"${FAKE_DOCKER_CHILD_PID_FILE:?}"
      : >"${FAKE_DOCKER_READY_FILE:?}"
      # Bounded so a fixture orphaned by a failed case cannot outlive the suite.
      for _ in {1..12}; do
        /bin/sleep 10 &
        block_child_pid=$!
        wait "$block_child_pid" || true
        block_child_pid=""
      done
    fi
    printf 'Flyway fixture completed\n'
    ;;
  *) printf 'unsupported Docker fixture command\n' >&2; exit 103 ;;
esac
DOCKER_FIXTURE
/bin/chmod 0700 "$COMMAND_DIR/docker"

fake_argv_rejection_case="$RUN_DIR/fake-argv-rejection"
/bin/mkdir -m 0700 "$fake_argv_rejection_case"
: >"$fake_argv_rejection_case/docker.argv"
assert_fake_docker_rejects_secret_argument() {
  local description="$1" fake_argv_rejection_status
  shift
  : >"$fake_argv_rejection_case/docker.argv"
  if FAKE_DOCKER_ARGV="$fake_argv_rejection_case/docker.argv" \
      "$COMMAND_DIR/docker" run "$@" fixture-image \
      >"$fake_argv_rejection_case/output" 2>&1; then
    fake_argv_rejection_status=0
  else
    fake_argv_rejection_status=$?
  fi
  [[ "$fake_argv_rejection_status" == 91 ]] ||
    fail "the fake Docker client must reject ${description} before recording it"
  if rg -q '(POSTGRES_PASSWORD|PGPASSWORD|FLYWAY_PASSWORD)' \
      "$fake_argv_rejection_case/docker.argv"; then
    fail "the fake Docker client recorded ${description}"
  fi
}

assert_fake_docker_rejects_secret_argument 'direct POSTGRES_PASSWORD assignment' \
  'POSTGRES_PASSWORD=fixture-value'
assert_fake_docker_rejects_secret_argument 'bare -e PGPASSWORD inheritance' \
  -e PGPASSWORD
assert_fake_docker_rejects_secret_argument 'bare -e=FLYWAY_PASSWORD inheritance' \
  -e=FLYWAY_PASSWORD
assert_fake_docker_rejects_secret_argument 'bare --env POSTGRES_PASSWORD inheritance' \
  --env POSTGRES_PASSWORD
assert_fake_docker_rejects_secret_argument 'bare --env=PGPASSWORD inheritance' \
  --env=PGPASSWORD
assert_fake_docker_rejects_secret_argument 'joined -ePOSTGRES_PASSWORD inheritance' \
  -ePOSTGRES_PASSWORD
assert_fake_docker_rejects_secret_argument 'joined -ePOSTGRES_PASSWORD assignment' \
  -ePOSTGRES_PASSWORD=fixture-value
assert_fake_docker_rejects_secret_argument 'joined -ePGPASSWORD inheritance' \
  -ePGPASSWORD
assert_fake_docker_rejects_secret_argument 'joined -ePGPASSWORD assignment' \
  -ePGPASSWORD=fixture-value
assert_fake_docker_rejects_secret_argument 'joined -eFLYWAY_PASSWORD inheritance' \
  -eFLYWAY_PASSWORD
assert_fake_docker_rejects_secret_argument 'joined -eFLYWAY_PASSWORD assignment' \
  -eFLYWAY_PASSWORD=fixture-value

assert_fake_docker_allows_file_argument() {
  local description="$1" fake_argv_status
  shift
  : >"$fake_argv_rejection_case/docker.argv"
  if FAKE_DOCKER_ARGV="$fake_argv_rejection_case/docker.argv" \
      "$COMMAND_DIR/docker" run "$@" fixture-image \
      >"$fake_argv_rejection_case/output" 2>&1; then
    fake_argv_status=0
  else
    fake_argv_status=$?
  fi
  [[ "$fake_argv_status" != 91 ]] ||
    fail "the fake Docker client must not treat ${description} as a password value"
}

assert_fake_docker_allows_file_argument 'joined -ePOSTGRES_PASSWORD_FILE inheritance' \
  -ePOSTGRES_PASSWORD_FILE
assert_fake_docker_allows_file_argument 'joined -ePGPASSWORD_FILE assignment' \
  -ePGPASSWORD_FILE=fixture-path

cat >"$COMMAND_DIR/adb" <<'ADB_FIXTURE'
#!/usr/bin/env bash
set -euo pipefail
for secret_name in POSTGRES_PASSWORD PGPASSWORD FLYWAY_PASSWORD; do
  if [[ -n "${!secret_name+x}" ]]; then
    printf 'a database credential reached the adb environment\n' >&2
    exit 89
  fi
done
case " $* " in
  *' shell pm list packages '*) printf 'package:%s\n' "${@: -1}" ;;
  *' get-state '*) printf 'device\n' ;;
  *' logcat -d '*) printf 'fixture logcat\n' ;;
  *' exec-out uiautomator dump '*) printf '<hierarchy/>\n' ;;
  *) ;;
esac
ADB_FIXTURE
/bin/chmod 0700 "$COMMAND_DIR/adb"

prepare_case() {
  local case_dir="$RUN_DIR/$1"
  /bin/mkdir -m 0700 "$case_dir" "$case_dir/state"
  : >"$case_dir/docker.argv"
  printf '%s\n' "$case_dir"
}

common_case_environment() {
  local mode="$1" case_dir="$2"
  export PATH="$COMMAND_DIR:/usr/bin:/bin"
  export REAL_PYTHON
  export TEST_SECRET_SHA256="$SENTINEL_SHA256"
  export FAKE_DOCKER_MODE="$mode"
  export FAKE_DOCKER_ARGV="$case_dir/docker.argv"
  export FAKE_DOCKER_STATE_DIR="$case_dir/state"
  export FAKE_DOCKER_SECRET_PATH="$case_dir/docker-secret-path"
}

flyway_case="$(prepare_case flyway)"
flyway_input="$flyway_case/input.env"
printf 'POSTGRES_USER=chronicle\nPOSTGRES_PASSWORD=%s\nPOSTGRES_DB=chronicle\n' "$SENTINEL" >"$flyway_input"
/bin/chmod 0600 "$flyway_input"
if ! (
  common_case_environment flyway "$flyway_case"
  export CHRONICLE_ENV_FILE="$flyway_input"
  export CHRONICLE_PG_CONTAINER=fixture-postgres
  export CHRONICLE_PG_NETWORK=fixture-network
  export CHRONICLE_FLYWAY_SECRET_PARENT="$flyway_case/secret-parent"
  unset POSTGRES_PASSWORD PGPASSWORD FLYWAY_PASSWORD
  exec "$ROOT_DIR/scripts/flyway-migrate.sh" info
) >"$flyway_case/output" 2>&1; then
  report_fixture_failure "$flyway_case/output" 'flyway-migrate functional secret-transport fixture'
fi
if [[ -s "$flyway_case/docker-secret-path" ]]; then
  flyway_secret_path="$(<"$flyway_case/docker-secret-path")"
  [[ ! -e "$flyway_secret_path" ]] || fail 'flyway-migrate retained its secret Docker env file after exit'
else
  fail 'flyway-migrate never supplied the Flyway password through a protected env file'
fi
/bin/rm -f -- "$flyway_input"
if [[ -d "$flyway_case/secret-parent" ]] &&
   find "$flyway_case/secret-parent" -type f -print -quit | grep -q .; then
  fail 'flyway-migrate retained a secret temporary file after exit'
fi
assert_no_secret_material "$flyway_case" 'flyway-migrate'

flyway_failure_case="$(prepare_case flyway-failure)"
flyway_failure_input="$flyway_failure_case/input.env"
printf 'POSTGRES_USER=chronicle\nPOSTGRES_PASSWORD=%s\nPOSTGRES_DB=chronicle\n' "$SENTINEL" >"$flyway_failure_input"
/bin/chmod 0600 "$flyway_failure_input"
if (
  common_case_environment flyway "$flyway_failure_case"
  export FAKE_DOCKER_FAIL_RUN=1
  export CHRONICLE_ENV_FILE="$flyway_failure_input"
  export CHRONICLE_PG_CONTAINER=fixture-postgres
  export CHRONICLE_PG_NETWORK=fixture-network
  export CHRONICLE_FLYWAY_SECRET_PARENT="$flyway_failure_case/secret-parent"
  unset POSTGRES_PASSWORD PGPASSWORD FLYWAY_PASSWORD
  exec "$ROOT_DIR/scripts/flyway-migrate.sh" validate
) >"$flyway_failure_case/output" 2>&1; then
  fail 'flyway-migrate unexpectedly hid the simulated Flyway client failure'
fi
if [[ -s "$flyway_failure_case/docker-secret-path" ]]; then
  flyway_failure_secret_path="$(<"$flyway_failure_case/docker-secret-path")"
  [[ ! -e "$flyway_failure_secret_path" ]] ||
    fail 'flyway-migrate retained its secret Docker env file after client failure'
else
  fail 'flyway-migrate failure fixture did not reach the protected env-file transport'
fi
/bin/rm -f -- "$flyway_failure_input"
if [[ -d "$flyway_failure_case/secret-parent" ]] &&
   find "$flyway_failure_case/secret-parent" -type f -print -quit | grep -q .; then
  fail 'flyway-migrate retained a secret temporary file after client failure'
fi
assert_no_secret_material "$flyway_failure_case" 'flyway-migrate failure path'

run_flyway_signal_case() {
  local signal_name="$1" expected_status="$2" case_slug="$3"
  local signal_case signal_input runner_pid child_pid secret_path status prompt_cleanup=0
  signal_case="$(prepare_case "flyway-${case_slug}")"
  signal_input="$signal_case/input.env"
  printf 'POSTGRES_USER=chronicle\nPOSTGRES_PASSWORD=%s\nPOSTGRES_DB=chronicle\n' \
    "$SENTINEL" >"$signal_input"
  /bin/chmod 0600 "$signal_input"
  (
    common_case_environment flyway "$signal_case"
    export FAKE_DOCKER_BLOCK_RUN=1
    export FAKE_DOCKER_CHILD_PID_FILE="$signal_case/docker-child.pid"
    export FAKE_DOCKER_READY_FILE="$signal_case/docker.ready"
    export FAKE_DOCKER_SIGNAL_FILE="$signal_case/docker.signal"
    export CHRONICLE_ENV_FILE="$signal_input"
    export CHRONICLE_PG_CONTAINER=fixture-postgres
    export CHRONICLE_PG_NETWORK=fixture-network
    export CHRONICLE_FLYWAY_SECRET_PARENT="$signal_case/secret-parent"
    unset POSTGRES_PASSWORD PGPASSWORD FLYWAY_PASSWORD
    # A suite launched under nohup inherits SIGHUP as ignored, which bash cannot trap.
    exec /usr/bin/env --default-signal=HUP,INT,TERM "$ROOT_DIR/scripts/flyway-migrate.sh" validate
  ) >"$signal_case/output" 2>&1 &
  runner_pid=$!

  for _ in {1..100}; do
    [[ -s "$signal_case/docker-child.pid" && -e "$signal_case/docker.ready" &&
       -s "$signal_case/docker-secret-path" ]] && break
    /bin/sleep 0.02
  done
  if [[ ! -s "$signal_case/docker-child.pid" || ! -e "$signal_case/docker.ready" ||
        ! -s "$signal_case/docker-secret-path" ]]; then
    fail "flyway-migrate ${signal_name} fixture never reached the blocking Docker client"
  else
    child_pid="$(<"$signal_case/docker-child.pid")"
    secret_path="$(<"$signal_case/docker-secret-path")"
    kill -s "$signal_name" "$runner_pid" 2>/dev/null || true
    for _ in {1..100}; do
      if [[ -s "$signal_case/docker.signal" && ! -e "$secret_path" ]]; then
        prompt_cleanup=1
        break
      fi
      /bin/sleep 0.02
    done
    if ((prompt_cleanup == 0)); then
      fail "flyway-migrate ${signal_name} must promptly terminate Docker and remove its secret env file"
      kill -s "$signal_name" "$child_pid" 2>/dev/null || true
    fi
  fi

  for _ in {1..100}; do
    kill -0 "$runner_pid" 2>/dev/null || break
    /bin/sleep 0.02
  done
  if kill -0 "$runner_pid" 2>/dev/null; then
    fail "flyway-migrate ${signal_name} runner did not terminate within the bounded fixture timeout"
    kill -KILL "$runner_pid" 2>/dev/null || true
  fi
  if wait "$runner_pid"; then status=0; else status=$?; fi
  if [[ -s "$signal_case/docker-child.pid" ]]; then
    kill -KILL "$(<"$signal_case/docker-child.pid")" 2>/dev/null || true
  fi
  [[ "$status" == "$expected_status" ]] ||
    fail "flyway-migrate ${signal_name} exited ${status}, expected ${expected_status}"
  [[ -s "$signal_case/docker.signal" ]] &&
    [[ "$(<"$signal_case/docker.signal")" == "$signal_name" ]] ||
    fail "flyway-migrate ${signal_name} did not forward the signal to Docker"

  /bin/rm -f -- "$signal_input"
  if [[ -d "$signal_case/secret-parent" ]] &&
     find "$signal_case/secret-parent" -type f -print -quit | grep -q .; then
    fail "flyway-migrate retained a secret temporary file after ${signal_name}"
  fi
  assert_no_secret_material "$signal_case" "flyway-migrate ${signal_name} path"
}

run_flyway_signal_case TERM 143 term
run_flyway_signal_case HUP 129 hup

schema_case="$(prepare_case schema)"
schema_input="$schema_case/input.env"
printf 'POSTGRES_USER=chronicle\nPOSTGRES_PASSWORD=%s\nPOSTGRES_DB=chronicle\n' "$SENTINEL" >"$schema_input"
/bin/chmod 0600 "$schema_input"
SCHEMA_EXPECTED_MAX="$(find "$ROOT_DIR/chronicle-server/src/main/resources/db/migration" \
  -maxdepth 1 -name 'V*.sql' -print | sed -E 's/.*V([0-9]+)__.*/\1/' | sort -n | tail -n 1)"
SCHEMA_EXPECTED_ROWS="$(find "$ROOT_DIR/chronicle-server/src/main/resources/db/migration" \
  -maxdepth 1 -name 'V*.sql' -print | wc -l | tr -d ' ')"
if ! (
  common_case_environment schema "$schema_case"
  export SCHEMA_EXPECTED_MAX SCHEMA_EXPECTED_ROWS
  export CHRONICLE_ENV_FILE="$schema_input"
  export CHRONICLE_PG_CONTAINER=fixture-postgres
  export CHRONICLE_SKIP_TDE_CHECK=1
  export POSTGRES_PASSWORD="$SENTINEL"
  export PGPASSWORD="$SENTINEL"
  export FLYWAY_PASSWORD="$SENTINEL"
  exec "$ROOT_DIR/scripts/verify-schema-postconditions.sh"
) >"$schema_case/output" 2>&1; then
  report_fixture_failure "$schema_case/output" 'verify-schema-postconditions functional secret-transport fixture'
fi
/bin/rm -f -- "$schema_input"
assert_no_secret_material "$schema_case" 'verify-schema-postconditions'

report_case="$(prepare_case report)"
if ! (
  common_case_environment report "$report_case"
  export CHRONICLE_STUDY_ID=00000000-0000-0000-0000-000000000001
  export CHRONICLE_PARTICIPANT_ID=fixture-participant
  export POSTGRES_USER=chronicle
  export POSTGRES_DB=chronicle
  export POSTGRES_PASSWORD="$SENTINEL"
  exec "$ROOT_DIR/scripts/chronicle-dogfood-report.sh"
) >"$report_case/output" 2>&1; then
  report_fixture_failure "$report_case/output" 'chronicle-dogfood-report functional secret-transport fixture'
fi
assert_no_secret_material "$report_case" 'chronicle-dogfood-report'

auto_case="$(prepare_case auto)"
auto_log_dir="$auto_case/artifacts"
if ! (
  common_case_environment auto "$auto_case"
  export ADB="$COMMAND_DIR/adb"
  export CHRONICLE_STUDY_ID=00000000-0000-0000-0000-000000000001
  export CHRONICLE_PARTICIPANT_ID=fixture-participant
  export POSTGRES_USER=chronicle
  export POSTGRES_DB=chronicle
  export POSTGRES_PASSWORD="$SENTINEL"
  exec "$ROOT_DIR/scripts/android-auto-upload-e2e.sh" \
    --serial fixture-device --timeout 1 --poll 0 --app-seconds 0 \
    --log-dir "$auto_log_dir"
) >"$auto_case/output" 2>&1; then
  report_fixture_failure "$auto_case/output" 'android-auto-upload-e2e functional secret-transport fixture'
fi
assert_no_secret_material "$auto_case" 'android-auto-upload-e2e'

if ((failures > 0)); then
  printf 'database secret transport guard failed with %d finding(s)\n' "$failures" >&2
  exit 1
fi
printf 'database secret transport guard passed\n'
