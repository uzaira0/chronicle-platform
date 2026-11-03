#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
source "${ROOT_DIR}/tests/security/lib/selfhost-fixtures.sh"
WORK_DIR="${SELFHOST_OPERATOR_TEST_ROOT:-${ROOT_DIR}/build/operator-test-runs/selfhost-operator-setup-credential-reporting}"
mkdir -p "$WORK_DIR"
RUN_DIR="$(mktemp -d "${WORK_DIR}/run.XXXXXX")"
trap 'rm -rf -- "$RUN_DIR"' EXIT
FIXTURE="${RUN_DIR}/selfhost"
BIN="${RUN_DIR}/bin"
PASSWORD='synthetic-dashboard-password-W80'
GENERATED='synthetic-generated-value-for-W80-only'
HASH='$2a$14$syntheticbcryptvalueabcdefghijklmnopqrstuv0123456789ABCDE'

fail() { echo "FAIL selfhost-operator-setup-credential-reporting: $*" >&2; exit 1; }

make_selfhost_setup_fixture "$RUN_DIR"

run_setup() {
  local output="$1" overwrite="$2"
  (
    cd "$FIXTURE"
    write_selfhost_setup_answers "$PASSWORD" "$overwrite" "$overwrite" | env \
      "PATH=${BIN}:${PATH}" \
      "COMPOSE_PROJECT_NAME=pilot-study" \
      "SELFHOST_FIXTURE_GENERATED=${GENERATED}" \
      "SELFHOST_FIXTURE_BCRYPT=${HASH}" \
      bash ./chronicle setup
  ) >"$output" 2>&1
}

run_setup "${RUN_DIR}/first-setup.log" false || {
  cat "${RUN_DIR}/first-setup.log" >&2
  fail 'initial synthetic setup failed'
}
grep -Fq 'secrets generated, mode 600' "${RUN_DIR}/first-setup.log" ||
  fail 'initial setup did not report generated credentials'
[[ -s "${FIXTURE}/.env" ]] || fail 'initial setup did not create .env'
chmod 0600 "${FIXTURE}/.env"

run_setup "${RUN_DIR}/rerun.log" true || {
  cat "${RUN_DIR}/rerun.log" >&2
  fail 'synthetic setup rerun failed'
}
grep -Fq 'existing secrets preserved, no credentials generated, mode 600' "${RUN_DIR}/rerun.log" ||
  fail 'rerun did not report that existing credentials were retained'
if grep -Fq 'secrets generated, mode 600' "${RUN_DIR}/rerun.log"; then
  fail 'rerun still claimed that credentials were generated'
fi
for value in "$PASSWORD" "$GENERATED" "$HASH"; do
  if grep -Fq "$value" "${RUN_DIR}/first-setup.log" "${RUN_DIR}/rerun.log"; then
    fail 'setup output printed credential material'
  fi
done
echo 'PASS selfhost-operator-setup-credential-reporting: first setup reports generated credentials; rerun reports preserved credentials without printing values'
