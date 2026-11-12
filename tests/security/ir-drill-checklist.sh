#!/usr/bin/env bash
# Live, operator-run incident-response readiness drill for the maintained self-host stack.
# It never creates, deletes, or rotates participant or backup data.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SELFHOST_DIR="${CHRONICLE_SELFHOST_DIR:-$ROOT_DIR/selfhost}"

PASS=0
FAIL=0

pass() {
  PASS=$((PASS + 1))
  printf 'READY     %s\n' "$*"
}

fail() {
  FAIL=$((FAIL + 1))
  printf 'NOT-READY %s\n' "$*" >&2
}

run_check() {
  local description="$1"
  shift
  if "$@"; then
    pass "$description"
  else
    fail "$description"
  fi
}

env_value() {
  local key="$1"
  sed -n "s/^${key}=//p" .env | sed -n 1p | tr -d "'\""
}

cd "$SELFHOST_DIR"

if [[ ! -f .env ]]; then
  printf 'NOT-READY %s/.env is missing; run ./chronicle setup first\n' "$SELFHOST_DIR" >&2
  exit 1
fi

run_check "configuration passes the deployment guard" ./chronicle check
run_check "service status is available" ./chronicle status
run_check "doctor finds no critical runtime fault" ./chronicle doctor --json

compose_file="$(env_value COMPOSE_FILE)"
if [[ "$compose_file" == *overlays/monitoring.yml* ]]; then
  run_check "private monitoring services are healthy" ./chronicle monitoring status
else
  printf 'INFO      monitoring overlay is not selected; external monitoring evidence is required\n'
fi

state_dir="$(env_value CHRONICLE_STATE_DIR)"
[[ -n "$state_dir" ]] || state_dir=.
if [[ "$state_dir" != /* ]]; then
  state_dir="$SELFHOST_DIR/$state_dir"
fi
backup_dir="$state_dir/backups"

if [[ ! -d "$backup_dir" ]]; then
  fail "backup directory is absent"
elif ! find "$backup_dir" -type f \( -name '*.sql.gz' -o -name '*.manifest' \) \
    -mtime -2 -print -quit 2>/dev/null | grep . >/dev/null; then
  fail "no backup artifact newer than 48 hours was found"
else
  pass "a backup artifact newer than 48 hours exists"
fi

if [[ -f "$backup_dir/keyring/chronicle-keyring.per" ]]; then
  mode="$(stat -c '%a' "$backup_dir/keyring/chronicle-keyring.per" 2>/dev/null ||
    stat -f '%Lp' "$backup_dir/keyring/chronicle-keyring.per")"
  case "$mode" in
    600|400) pass "the recovery keyring copy has a private mode" ;;
    *) fail "the recovery keyring copy is not mode 0600/0400" ;;
  esac
else
  fail "the recovery keyring copy is absent"
fi

printf '\nIncident-response readiness: %s ready, %s not-ready\n' "$PASS" "$FAIL"
if ((FAIL)); then
  printf 'Address every NOT-READY result and record the drill in the operator system of record.\n' >&2
  exit 1
fi
printf 'Record this successful drill in the operator system of record.\n'
