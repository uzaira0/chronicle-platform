#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export GRADLE_USER_HOME="${GRADLE_USER_HOME:-$ROOT_DIR/build/gradle-verify-home}"
mkdir -p "$GRADLE_USER_HOME"
parent="${TMPDIR:-$ROOT_DIR/build/operator-test-runs}"
mkdir -p "$parent"
work=$(mktemp -d "$parent/web-e2e.XXXXXX")
done_file="$work/done"
backend_pid=''

finish() {
  local status=$?
  trap - EXIT
  touch "$done_file"
  if [[ -n "$backend_pid" ]]; then
    local backend_status=0
    wait "$backend_pid" || backend_status=$?
    if [[ "$status" == 0 ]]; then status=$backend_status; fi
  fi
  rm -rf -- "$work"
  exit "$status"
}
trap finish EXIT

cd "$ROOT_DIR"
# Ports the OS reports free now; a fixed default collides with any other listener or outgoing connection.
read -r free_backend free_proxy < <(python3 -c 'import socket; s=[socket.socket() for _ in range(2)]; [x.bind(("",0)) for x in s]; print(*(x.getsockname()[1] for x in s))')
export CHRONICLE_TEST_HTTP_PORT="${CHRONICLE_TEST_HTTP_PORT:-$free_backend}"
export CHRONICLE_BACKEND_URL="http://127.0.0.1:$CHRONICLE_TEST_HTTP_PORT"
export CHRONICLE_DIRECT_BACKEND_URL="$CHRONICLE_BACKEND_URL"
CHRONICLE_INTERNAL_WEB_SECRET=$(python3 -c 'import secrets; print(secrets.token_hex(32))')
export CHRONICLE_INTERNAL_WEB_SECRET
export CHRONICLE_PROXY_BASE_URL="http://127.0.0.1:$free_proxy"
./gradlew :chronicle-server:test --tests '*PlaywrightBackendServer*' --no-daemon \
  -Dchronicle.playwright.backend=true -Dchronicle.playwright.backend.doneFile="$done_file" &
backend_pid=$!
until curl -q --noproxy '*' --silent --fail --connect-timeout 3 --max-time 10 \
    "$CHRONICLE_BACKEND_URL/chronicle/internal/health/ready" >/dev/null; do
  if ! kill -0 "$backend_pid" 2>/dev/null; then
    wait "$backend_pid"
    exit 1
  fi
  sleep 0.25
done
cd "$ROOT_DIR/chronicle-web"
# Bounded so Chromium workers, Gradle and the backend JVM fit one 10 GiB heavy-job cap.
bunx playwright test --project=desktop-chromium --workers="${CHRONICLE_E2E_WORKERS:-4}" \
  --output "$parent/web-e2e-results" "$@"
