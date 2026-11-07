#!/usr/bin/env bash
# Run one launcher function in an installed copy of selfhost/chronicle against the `docker` found
# on PATH (tests use compose_shim.py). Only steps that need a real host are stubbed: image builds,
# host preflight, the operation lock, release ownership, certificate files and the public origin.
# Usage: chronicle_harness.sh SELFHOST_DIR FUNCTION [ARGUMENTS...]
selfhost="$1"
shift
# shellcheck source=/dev/null
source "$selfhost/chronicle"
eval "real_ops_python() $(declare -f ops_python | tail -n +2)"
ops_python() {
  case "$1" in
    owner-check | public-check | write-operation-receipt | record-operation) return 0 ;;
    certificates)
      case "$2" in
        digest) printf '%s\n' fixture-certificates ;;
        compare) printf '%s\n' unchanged ;;
      esac
      return 0 ;;
    reconcile)
      case "${2:-}" in
        stopped) return 1 ;;
        host) if [[ -v FAKE_RECONCILE_HOST ]]; then printf '%s' "${FAKE_RECONCILE_HOST:+$FAKE_RECONCILE_HOST$'\n'}"; else real_ops_python "$@"; fi ;;
        *) return 0 ;;
      esac ;;
    *) real_ops_python "$@" ;;
  esac
}
ensure_images() { :; }
preflight() { :; }
lock_operation() { :; }

doctor_monitoring() {
  need_env
  # shellcheck source=/dev/null
  source ./doctor.sh
  # shellcheck disable=SC2034 # doctor_add and doctor_render read these through dynamic scope.
  local -a DOCTOR_ROWS=()
  # shellcheck disable=SC2034
  local DOCTOR_FAILED=0
  doctor_check_monitoring "$(dc ps --status running --services)"
  doctor_render false
}

doctor_reconcile_host() {
  need_env
  # shellcheck source=/dev/null
  source ./doctor.sh
  # shellcheck disable=SC2034 # doctor_add and doctor_render read these through dynamic scope.
  local -a DOCTOR_ROWS=()
  # shellcheck disable=SC2034
  local DOCTOR_FAILED=0
  doctor_check_reconcile_host
  doctor_render false
}

runtime_versions() {
  PREFLIGHT_FAILED=0
  preflight_runtime_versions
  printf 'preflight-failed=%s\n' "$PREFLIGHT_FAILED"
}

"$@"
