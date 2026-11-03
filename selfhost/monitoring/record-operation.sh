#!/usr/bin/env bash
set -Eeuo pipefail

mkdir -p /metrics
umask 077
exec 9>/metrics/.operations.lock

record_event() {
  local operation=$1 outcome=$2 category=$3
  flock -x 9 || return $?
  local events=/metrics/operator-events.jsonl
  local version="${RELEASE_VERSION:-unknown}"
  [[ "$version" =~ ^[A-Za-z0-9._+-]{1,48}$ ]] || version=unknown
  local severity=INFO
  [[ "$outcome" == failure ]] && severity=ERROR
  printf '{"failureCategory":"%s","operation":"%s","outcome":"%s","releaseVersion":"%s","severity":"%s","timestamp":"%s"}\n' \
    "$category" "$operation" "$outcome" "$version" "$severity" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >>"$events"
  chmod 0644 "$events"
  if [[ $(wc -c <"$events") -gt 1048576 ]]; then
    local events_tmp="/metrics/.operator-events.jsonl.$$"
    tail -n 1000 "$events" >"$events_tmp"
    chmod 0644 "$events_tmp"
    mv -f "$events_tmp" "$events"
  fi
  flock -u 9
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  operation="${1:-}"
  outcome="${2:-}"
  category="${3:-none}"
  [[ "$operation" =~ ^[a-z0-9-]{1,64}$ ]] || exit 64
  [[ "$outcome" =~ ^(success|failure)$ ]] || exit 64
  [[ "$category" =~ ^[a-z0-9_-]{1,48}$ ]] || exit 64

  flock -x 9
  target=/metrics/operations.prom
  temporary="/metrics/.operations.prom.$$"
  if [[ -f "$target" ]]; then
    awk -v op="$operation" 'index($0, "operation=\"" op "\"") == 0' "$target" >"$temporary"
  else
    cat >"$temporary" <<'EOF'
# HELP chronicle_operator_operation_timestamp_seconds Last completion time of a guarded operator operation.
# TYPE chronicle_operator_operation_timestamp_seconds gauge
EOF
  fi
  printf 'chronicle_operator_operation_timestamp_seconds{operation="%s",outcome="%s",failure_category="%s"} %s\n' \
    "$operation" "$outcome" "$category" "$(date +%s)" >>"$temporary"
  chmod 0644 "$temporary"
  mv -f "$temporary" "$target"

  record_event "$operation" "$outcome" "$category"
fi
