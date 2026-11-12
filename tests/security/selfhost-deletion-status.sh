#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
source "$ROOT_DIR/tests/security/lib/selfhost-fixtures.sh"
RUN_PARENT="${SELFHOST_DELETION_STATUS_TEST_ROOT:-${ROOT_DIR}/build/operator-test-runs/selfhost-deletion-status}"
REAL_PYTHON="$(command -v python3)"

fail() {
  echo "self-host deletion-status test failed: $*" >&2
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

SELFHOST_DIR="${RUN_DIR}/selfhost"
COMMAND_DIR="${RUN_DIR}/commands"
EXPECTED_INPUT_FILE="${RUN_DIR}/expected-input"
CAPTURED_INPUT_FILE="${RUN_DIR}/captured-input"
DOCKER_MARKER="${RUN_DIR}/docker-invoked"
SECRETS_FILE="${RUN_DIR}/synthetic-secrets"
OUTPUT_FILE="${RUN_DIR}/output.txt"
STUDY_ID='11111111-2222-4333-8444-555555555555'
OPERATION_ID='aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee'

/bin/mkdir -p "$SELFHOST_DIR" "$COMMAND_DIR"
copy_selfhost_setup_fixture "$SELFHOST_DIR"
/bin/chmod 0755 "$SELFHOST_DIR/chronicle"

cat >"${SELFHOST_DIR}/.env" <<'EOF'
COMPOSE_PROJECT_NAME=chronicle-selfhost-deletion-fixture
CHRONICLE_STATE_DIR=.
COMPOSE_FILE=docker-compose.yml:overlays/mode-behind-proxy-internal.yml:overlays/backups.yml
export POSTGRES_PASSWORD='fixture-deletion-db-password-0123456789'
export CHRONICLE_INTERNAL_WEB_SECRET='fixture-deletion-internal-secret-0123456789'
export JWT_SECRET='fixture-deletion-jwt-secret-0123456789'
export METRICS_PASSWORD='fixture-deletion-metrics-password-0123456789'
export GRAFANA_ADMIN_PASSWORD='fixture-deletion-grafana-password-0123456789'
export DASHBOARD_PASSWORD_HASH='fixture-deletion-dashboard-hash-0123456789'
EOF
/bin/chmod 0600 "${SELFHOST_DIR}/.env"

cat >"$SECRETS_FILE" <<'EOF'
fixture-deletion-db-password-0123456789
fixture-deletion-internal-secret-0123456789
fixture-deletion-jwt-secret-0123456789
fixture-deletion-metrics-password-0123456789
fixture-deletion-grafana-password-0123456789
fixture-deletion-dashboard-hash-0123456789
EOF
/bin/chmod 0600 "$SECRETS_FILE"

cat >"${COMMAND_DIR}/python3" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
for key in POSTGRES_PASSWORD \
  CHRONICLE_INTERNAL_WEB_SECRET JWT_SECRET METRICS_PASSWORD GRAFANA_ADMIN_PASSWORD \
  DASHBOARD_PASSWORD_HASH; do
  [[ -z "${!key+x}" ]] || {
    echo "deployment secret ${key} reached Python environment" >&2
    exit 81
  }
done
exec "${SELFHOST_DELETION_STATUS_TEST_REAL_PYTHON:?}" "$@"
EOF

cat >"${COMMAND_DIR}/docker" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

: >"${SELFHOST_DELETION_STATUS_TEST_DOCKER_MARKER:?}"
expected_input="$(cat "${SELFHOST_DELETION_STATUS_TEST_EXPECTED_INPUT_FILE:?}")"
study_id="$(sed -n '1p' "${SELFHOST_DELETION_STATUS_TEST_EXPECTED_INPUT_FILE}")"
operation_id="$(sed -n '2p' "${SELFHOST_DELETION_STATUS_TEST_EXPECTED_INPUT_FILE}")"

for key in POSTGRES_PASSWORD \
  CHRONICLE_INTERNAL_WEB_SECRET JWT_SECRET METRICS_PASSWORD GRAFANA_ADMIN_PASSWORD \
  DASHBOARD_PASSWORD_HASH; do
  [[ -z "${!key+x}" ]] || {
    echo "deployment secret ${key} reached Docker environment" >&2
    exit 82
  }
done

while IFS='=' read -r _ value; do
  [[ "$value" != *"$study_id"* ]] || {
    echo "study UUID reached Docker environment" >&2
    exit 83
  }
  if [[ -n "$operation_id" && "$value" == *"$operation_id"* ]]; then
    echo "operation UUID reached Docker environment" >&2
    exit 84
  fi
done < <(env)

for argument in "$@"; do
  [[ "$argument" != *"$study_id"* ]] || {
    echo "study UUID reached Docker argv" >&2
    exit 85
  }
  if [[ -n "$operation_id" && "$argument" == *"$operation_id"* ]]; then
    echo "operation UUID reached Docker argv" >&2
    exit 86
  fi
  while IFS= read -r secret; do
    [[ "$argument" != *"$secret"* ]] || {
      echo "deployment secret reached Docker argv" >&2
      exit 87
    }
  done <"${SELFHOST_DELETION_STATUS_TEST_SECRETS_FILE:?}"
done

[[ "${1:-}" == compose && "${2:-}" == -p \
  && "${4:-}" == exec && "${5:-}" == -T && "${6:-}" == postgres \
  && "${7:-}" == /bin/bash && "${8:-}" == -euc ]] || exit 88
container_script="${9:-}"
[[ "$container_script" == *'data_deletion_operations'* \
  && "$container_script" == *'data_deletion_tombstones'* \
  && "$container_script" == *'requested_at'* ]] || exit 89
# AF-P11: both identifiers reach the statement as psql variables, quoted by psql as literals inside
# a heredoc the shell does not expand; a predicate assembled as shell text is the form that was removed.
[[ "$container_script" == *'-v study_id="$study_id" -v operation_id="$operation_id"'* \
  && "$container_script" == *"<<'SQL'"* \
  && "$container_script" == *"(:'study_id')::uuid"* \
  && "$container_script" == *"(NULLIF(:'operation_id', ''))::uuid"* \
  && "$container_script" != *'operation_predicate'* ]] || exit 92
[[ "$container_script" != *'participant_id'* \
  && "$container_script" != *'participant_ref'* \
  && "$container_script" != *'requested_by'* ]] || exit 90

cat >"${SELFHOST_DELETION_STATUS_TEST_CAPTURED_INPUT_FILE:?}"
captured_input="$(cat "${SELFHOST_DELETION_STATUS_TEST_CAPTURED_INPUT_FILE}")"
[[ "$captured_input" == "$expected_input" ]] || exit 91

cat <<'STATUS'
             operation_id             |       mode        |   status    |      requested_at      | completed_at | proof_state | failure_code
--------------------------------------+-------------------+-------------+------------------------+--------------+-------------+--------------
 aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee | WITHDRAW_AND_ERASE | QUARANTINED | 2026-08-18 12:00:00+00 |              | pending     |
STATUS
EOF

/bin/chmod 0755 "${COMMAND_DIR}/python3" "${COMMAND_DIR}/docker"

run_status() {
  local expected_operation_id="$1"
  shift
  printf '%s\n%s\n' "$STUDY_ID" "$expected_operation_id" >"$EXPECTED_INPUT_FILE"
  /bin/chmod 0600 "$EXPECTED_INPUT_FILE"
  (
    cd "$SELFHOST_DIR"
    PATH="${COMMAND_DIR}:/usr/bin:/bin" \
      SELFHOST_DELETION_STATUS_TEST_REAL_PYTHON="$REAL_PYTHON" \
      SELFHOST_DELETION_STATUS_TEST_DOCKER_MARKER="$DOCKER_MARKER" \
      SELFHOST_DELETION_STATUS_TEST_EXPECTED_INPUT_FILE="$EXPECTED_INPUT_FILE" \
      SELFHOST_DELETION_STATUS_TEST_CAPTURED_INPUT_FILE="$CAPTURED_INPUT_FILE" \
      SELFHOST_DELETION_STATUS_TEST_SECRETS_FILE="$SECRETS_FILE" \
      ./chronicle deletion-status "$STUDY_ID" "$@"
  ) >"$OUTPUT_FILE"
  grep -Fq 'WITHDRAW_AND_ERASE' "$OUTPUT_FILE" || fail "status output was not returned"
  grep -Fq 'pending' "$OUTPUT_FILE" || fail "proof state was not returned"
  [[ -e "$DOCKER_MARKER" ]] || fail "valid status request did not invoke Docker"
}

run_status "$OPERATION_ID" "$OPERATION_ID"
run_status ""

/bin/rm -f "$DOCKER_MARKER"
status=0
if (
  cd "$SELFHOST_DIR"
  PATH="${COMMAND_DIR}:/usr/bin:/bin" ./chronicle deletion-status not-a-uuid
) >"$OUTPUT_FILE" 2>&1; then
  fail "malformed study UUID was accepted"
else
  status=$?
fi
[[ "$status" == 2 ]] || fail "malformed study UUID exited $status, want usage status 2"
grep -Fq 'invalid study UUID' "$OUTPUT_FILE" || fail "malformed study UUID error was unclear"
[[ ! -e "$DOCKER_MARKER" ]] || fail "malformed study UUID reached Docker"

status=0
if (
  cd "$SELFHOST_DIR"
  PATH="${COMMAND_DIR}:/usr/bin:/bin" ./chronicle deletion-status "$STUDY_ID" not-a-uuid
) >"$OUTPUT_FILE" 2>&1; then
  fail "malformed operation UUID was accepted"
else
  status=$?
fi
[[ "$status" == 2 ]] || fail "malformed operation UUID exited $status, want usage status 2"
grep -Fq 'invalid operation UUID' "$OUTPUT_FILE" || fail "malformed operation UUID error was unclear"
[[ ! -e "$DOCKER_MARKER" ]] || fail "malformed operation UUID reached Docker"

echo "self-host deletion-status test passed"
