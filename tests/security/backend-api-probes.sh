#!/usr/bin/env bash
# Probes the isolated test backend: business-logic-tests.sh (test_user1 owns study A,
# test_user2 owns study B with a participant it can export; test_user1's token probes both
# studies, the admin routes, study B's participant export and participant purge), the complete
# route inventory authorization sweep, then Schemathesis with and without authentication.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
export GRADLE_USER_HOME="${GRADLE_USER_HOME:-$ROOT_DIR/build/gradle-verify-home}"
parent="${TMPDIR:-$ROOT_DIR/build/operator-test-runs}"
mkdir -p "$GRADLE_USER_HOME" "$parent"
work=$(mktemp -d "$parent/api-probes.XXXXXX")
backend_pid=''

finish() {
  local status=$?
  trap - EXIT
  touch "$work/done"
  if [[ -n "$backend_pid" ]]; then
    local backend_status=0
    wait "$backend_pid" || backend_status=$?
    if [[ "$status" == 0 ]]; then status=$backend_status; fi
  fi
  rm -rf -- "$work"
  exit "$status"
}
trap finish EXIT

port="${CHRONICLE_TEST_HTTP_PORT:-$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()')}"
backend="http://127.0.0.1:$port"
CHRONICLE_INTERNAL_WEB_SECRET=$(python3 -c 'import secrets; print(secrets.token_hex(32))')
export CHRONICLE_TEST_HTTP_PORT="$port" CHRONICLE_INTERNAL_WEB_SECRET

cd "$ROOT_DIR"
./gradlew :chronicle-server:test --tests '*PlaywrightBackendServer*' --no-daemon \
  -Dchronicle.playwright.backend=true -Dchronicle.playwright.backend.doneFile="$work/done" &
backend_pid=$!
until curl -q --noproxy '*' --silent --fail --connect-timeout 3 --max-time 10 "$backend/chronicle/internal/health/ready" >/dev/null; do
  kill -0 "$backend_pid" 2>/dev/null || { wait "$backend_pid"; exit 1; }
  sleep 0.25
done

token_for() {
  local internal_header="$CHRONICLE_INTERNAL_WEB_SECRET"
  case "$internal_header" in *$'\n'*|*$'\r'*) return 2 ;; esac
  internal_header="${internal_header//\\/\\\\}"
  internal_header="${internal_header//\"/\\\"}"
  printf 'header = "X-Chronicle-Internal-Web: %s"\n' "$internal_header" |
    curl -q --config - --noproxy '*' --silent --fail --connect-timeout 3 --max-time 30 -X POST "$backend/chronicle/v3/auth/testing-login" \
      -H 'Content-Type: application/json' --data "{\"userId\":\"$1\"}" |
    python3 -c 'import json, sys; print(json.load(sys.stdin)["authToken"])'
}

# Creates through selfhost-client's request helper: Idempotency-Key on creates, If-Match on settings edits.
fixture_study() {
  printf '%s\n' "$1" | python3 -s "$ROOT_DIR/tests/deployment/selfhost-client.py" --api-study "$backend/chronicle/v3" \
    --public https://probe.example.org --participant "probe-$2" --records "$work/study-$2.json" >/dev/null
  chmod 600 "$work/study-$2.json"
}

fixture_value() {
  python3 -c 'import json, sys; print(json.load(open(sys.argv[1]))[sys.argv[2]])' "$work/study-$1.json" "$2"
}

researcher=$(token_for test_user1)
fixture_study "$researcher" a
fixture_study "$(token_for test_user2)" b
STUDY_A=$(fixture_value a study)
STUDY_B=$(fixture_value b study)
[[ "$STUDY_A" != "$STUDY_B" ]]

BASE_URL="$backend" AUTH_TOKEN="$researcher" STUDY_A="$STUDY_A" STUDY_B="$STUDY_B" \
  PARTICIPANT_ID="$(fixture_value b participant)" bash "$ROOT_DIR/tests/security/business-logic-tests.sh"
BASE_URL="$backend" AUTH_TOKEN="$researcher" STUDY_B="$STUDY_B" \
  CHRONICLE_PROBE_FIXTURES="$work/study-b.json" CHRONICLE_PROBE_ACTOR_FIXTURES="$work/study-a.json" \
  PARTICIPANT_ID="$(fixture_value b participant)" python3 "$ROOT_DIR/tests/security/route-authorization-probes.py"
CHRONICLE_BASE_URL="$backend" CHRONICLE_AUTH_TOKEN="$researcher" \
  bash "$ROOT_DIR/tests/api-contract/run-schemathesis.sh"
