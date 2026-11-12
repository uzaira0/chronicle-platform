#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
source "${ROOT_DIR}/tests/security/lib/selfhost-fixtures.sh"
WORK_DIR="${SELFHOST_OPERATOR_TEST_ROOT:-${ROOT_DIR}/build/operator-test-runs/selfhost-operator-project-name-validation}"
mkdir -p "$WORK_DIR"
RUN_DIR="$(mktemp -d "${WORK_DIR}/run.XXXXXX")"
trap 'rm -rf -- "$RUN_DIR"' EXIT
PASSWORD='synthetic-dashboard-password-W32'

fail() { echo "FAIL selfhost-operator-project-name-validation: $*" >&2; exit 1; }

run_setup() {
  local case_dir="$1" project="$2" input="$3" output="$4" status
  if (
    cd "${case_dir}/selfhost"
    printf '%s\n' "$input" | env \
      "PATH=${case_dir}/bin:${PATH}" \
      "COMPOSE_PROJECT_NAME=${project}" \
      bash ./chronicle setup
  ) >"$output" 2>&1; then
    return 0
  else
    status=$?
  fi
  return "$status"
}

invalid_dir="${RUN_DIR}/invalid-project"
make_selfhost_setup_fixture "$invalid_dir"
# CHRONICLE_ALERT_EGRESS is the derived key every command writes back when .env lacks it or holds a
# stale value (chronicle_ops/egress.py sync_env_file). The prior .env carries it as setup writes it,
# so the byte comparison below is about setup replacing the configuration and nothing else.
printf '%s\n' 'COMPOSE_PROJECT_NAME=Previous_invalid_name' 'CHRONICLE_STATE_DIR=.' \
  'MOBILE_SIGNING_ENABLED=false' 'MOBILE_SIGNING_REQUIRED=false' 'CHRONICLE_ALERT_EGRESS=closed' \
  >"${invalid_dir}/selfhost/.env"
chmod 0600 "${invalid_dir}/selfhost/.env"
cp "${invalid_dir}/selfhost/.env" "${RUN_DIR}/env-before-invalid-setup"
invalid_input=$(write_selfhost_setup_answers "$PASSWORD" true)
if run_setup "$invalid_dir" 'Bad-Name' "$invalid_input" "${RUN_DIR}/invalid-output.log"; then
  fail 'setup accepted an invalid inherited Compose project name'
fi
grep -Fq 'deployment name must be lowercase letters, digits, dashes or underscores' \
  "${RUN_DIR}/invalid-output.log" || { cat "${RUN_DIR}/invalid-output.log" >&2; fail 'invalid project failure did not explain the Compose naming rule'; }
cmp -s "${invalid_dir}/selfhost/.env" "${RUN_DIR}/env-before-invalid-setup" ||
  fail 'invalid project name changed the prior .env configuration'

valid_dir="${RUN_DIR}/valid-project"
make_selfhost_setup_fixture "$valid_dir"
valid_input=$(write_selfhost_setup_answers "$PASSWORD")
if ! run_setup "$valid_dir" 'pilot-study_2' "$valid_input" "${RUN_DIR}/valid-output.log"; then
  cat "${RUN_DIR}/valid-output.log" >&2
  fail 'setup rejected a valid constrained Compose project name'
fi
grep -Fqx 'COMPOSE_PROJECT_NAME=pilot-study_2' "${valid_dir}/selfhost/.env" ||
  fail 'setup did not preserve the accepted project name in generated configuration'
echo 'PASS selfhost-operator-project-name-validation: invalid project names fail before .env replacement; valid constrained name is retained'
