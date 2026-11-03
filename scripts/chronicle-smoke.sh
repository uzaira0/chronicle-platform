#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
failures=0
skips=0

have_cmd() {
  command -v "$1" >/dev/null 2>&1
}

run_step() {
  local label="$1"
  shift
  printf '\n== %s ==\n' "$label"
  if "$@"; then
    printf '[ok] %s\n' "$label"
  else
    printf '[fail] %s\n' "$label"
    failures=$((failures + 1))
  fi
}

skip_step() {
  local label="$1"
  printf '\n== %s ==\n' "$label"
  printf '[skip] %s\n' "$label"
  skips=$((skips + 1))
}

printf 'Chronicle smoke validation\n'
printf 'root: %s\n' "$ROOT_DIR"

if have_cmd java; then
  run_step "gradle-projects" bash -lc "cd '$ROOT_DIR' && ./gradlew projects"
  run_step "chronicle-api-tests" bash -lc "cd '$ROOT_DIR' && ./gradlew :chronicle-api:test"
  run_step "chronicle-server-auth-tests" bash -lc "cd '$ROOT_DIR' && ./scripts/chronicle-server-auth-smoke.sh"
else
  skip_step "gradle-projects (java missing; install a JDK and set JAVA_HOME)"
  skip_step "chronicle-api-tests (java missing; install a JDK and set JAVA_HOME)"
  skip_step "chronicle-server-auth-tests (java missing; install a JDK and set JAVA_HOME)"
fi

if have_cmd bun && have_cmd node; then
  run_step "chronicle-web-check" bash -lc "cd '$ROOT_DIR/chronicle-web' && bun run check"
  run_step "chronicle-web-bun-tests" bash -lc "cd '$ROOT_DIR/chronicle-web' && bun run test"
else
  skip_step "chronicle-web-check (bun or node missing)"
  skip_step "chronicle-web-bun-tests (bun or node missing)"
fi

if have_cmd docker && [[ -f "$ROOT_DIR/docker/.env" ]]; then
  run_step "traefik-compose-config" bash -lc "cd '$ROOT_DIR' && docker compose -f docker/docker-compose.traefik.yml config -q"
else
  skip_step "traefik-compose-config (docker or docker/.env missing)"
fi

if have_cmd rg; then
  run_step "sso-drift-audit" bash -lc "cd '$ROOT_DIR' && ./scripts/check-sso-drift.sh"
else
  skip_step "sso-drift-audit (rg missing)"
fi

printf '\nSummary\n'
printf 'failures=%d skips=%d\n' "$failures" "$skips"

if ! have_cmd java; then
  printf 'note: JVM smoke steps are skipped until a JDK is installed and JAVA_HOME is configured\n'
fi

if (( failures > 0 )); then
  exit 1
fi
