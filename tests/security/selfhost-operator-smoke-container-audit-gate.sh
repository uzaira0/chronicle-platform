#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)
WORK_DIR="${SELFHOST_OPERATOR_TEST_ROOT:-${ROOT_DIR}/build/operator-test-runs/selfhost-operator-smoke-container-audit-gate}"
mkdir -p "$WORK_DIR"
RUN_DIR=$(mktemp -d "${WORK_DIR}/run.XXXXXX")
trap 'rm -rf -- "$RUN_DIR"' EXIT
SMOKE="$ROOT_DIR/tests/smoke/selfhost-release-smoke.sh"
fail() { echo "FAIL: $*" >&2; exit 1; }

sed -n '/^run_container_security_audit() {/,/^}/p' "$SMOKE" >"$RUN_DIR/audit-function.sh"

mkdir -p "$RUN_DIR/repo/tests/security"
cat >"$RUN_DIR/repo/tests/security/container-security-tests.sh" <<'SH'
#!/usr/bin/env bash
printf 'project=%s\n' "${COMPOSE_PROJECT:-missing}"
if [[ "${AUDIT_RESULT:-pass}" == pass ]]; then
  echo 'PASS: synthetic container audit'
  exit 0
fi
echo 'FAIL: synthetic container audit finding'
exit 9
SH
chmod +x "$RUN_DIR/repo/tests/security/container-security-tests.sh"
source "$RUN_DIR/audit-function.sh"
ROOT_DIR="$RUN_DIR/repo"
PROJECT=operator-w57-fixture
container_security_audit='unset'
run_container_security_audit "$RUN_DIR/pass.log"
[[ "$container_security_audit" == pass ]] || fail 'passing audit was not recorded'
grep -Fxq "project=$PROJECT" "$RUN_DIR/pass.log" || fail 'audit did not receive the smoke project'

status=0
(AUDIT_RESULT=fail run_container_security_audit "$RUN_DIR/fail.log") >"$RUN_DIR/fail.out" 2>&1 || status=$?
[[ $status -ne 0 ]] || fail 'failed audit did not stop the smoke'
grep -Fq 'container security audit failed' "$RUN_DIR/fail.out" ||
  fail 'failed audit has no actionable smoke failure'
grep -Fq 'synthetic container audit finding' "$RUN_DIR/fail.out" ||
  fail 'failed audit output was not preserved'
echo 'PASS: release smoke gates on container-audit failures'
