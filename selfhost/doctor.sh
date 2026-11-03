#!/usr/bin/env bash
# Diagnostic checks share the caller's structured doctor rows.

# Returns a secret-free state label for the operator-pinned Play reviewer scope. Inputs are
# delivered over stdin and revalidated in the database container before entering SQL.
reviewer_scope_state() {
  local study_id="$1" participant_id="$2"
  dc exec -T postgres /bin/bash -euc '
    : "${POSTGRES_PASSWORD:?POSTGRES_PASSWORD is unavailable in the postgres container}"
    IFS= read -r study_id
    IFS= read -r participant_id
    uuid_pattern="^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$"
    participant_pattern="^[a-zA-Z0-9_.-]{1,255}$"
    [[ "$study_id" =~ $uuid_pattern ]]
    [[ "$participant_id" =~ $participant_pattern ]]
    export PGPASSWORD="$POSTGRES_PASSWORD"
    exec psql -X -qAt -v ON_ERROR_STOP=1 -h 127.0.0.1 \
      -U "${POSTGRES_USER:-chronicle}" -d "${POSTGRES_DB:-chronicle}" <<SQL
SELECT CASE
  WHEN NOT EXISTS (
    SELECT 1 FROM studies WHERE study_id = '\''${study_id}'\''::uuid
  ) THEN '\''missing-study'\''
  WHEN NOT EXISTS (
    SELECT 1 FROM studies
    WHERE study_id = '\''${study_id}'\''::uuid
      AND lifecycle_status = '\''ACTIVE'\''
      AND CURRENT_TIMESTAMP >= started_at
      AND CURRENT_TIMESTAMP < ended_at
  ) THEN '\''inactive-study'\''
  WHEN NOT EXISTS (
    SELECT 1 FROM study_participants
    WHERE study_id = '\''${study_id}'\''::uuid
      AND participant_id = '\''${participant_id}'\''
  ) THEN '\''missing-participant'\''
  WHEN NOT EXISTS (
    SELECT 1 FROM study_participants
    WHERE study_id = '\''${study_id}'\''::uuid
      AND participant_id = '\''${participant_id}'\''
      AND participation_status = '\''ENROLLED'\''
  ) THEN '\''inactive-participant'\''
  ELSE '\''ok'\''
END;
SQL
  ' <<< "$study_id"$'\n'"$participant_id"
}

doctor_add_rows() {
  local ident outcome summary action
  while IFS=$'\x1f' read -r ident outcome summary action; do
    doctor_add "$ident" "$outcome" "$summary" "$action"
  done <<<"$1"
}

doctor_check_runtime() {
  if ops_python reconcile stopped; then
    doctor_add reconciliation warn "Periodic reconciliation is paused" "Run ./chronicle up from the active release to resume"
  fi
  local recovery
  if ! recovery="$(ops_python reconcile check 2>&1)"; then
    doctor_add operation-lock warn "An incomplete operation is preserved" "${recovery#error: }"
  fi

  if docker info >/dev/null 2>&1; then
    doctor_add docker ok "Docker daemon is reachable" "none"
  else
    doctor_add docker fail "Docker daemon is unreachable" "Start Docker, then rerun ./chronicle doctor"
  fi

  if dc config --quiet >/dev/null 2>&1; then
    doctor_add compose ok "Compose configuration renders" "none"
  else
    doctor_add compose fail "Compose configuration does not render" "Run docker compose config and correct the reported .env or YAML error"
  fi

  local public_check
  if public_check="$(ops_python public-check 2>&1)"; then
    doctor_add public-readiness ok "Public HTTPS has dependency-aware readiness" "none"
  else
    doctor_add public-readiness fail "${public_check:-Public HTTPS could not be checked}" "Resolve the reported public HTTPS check and rerun doctor"
  fi
}

doctor_check_database() {
  local service
  for service in postgres backend web; do
    local health summary action
    health=$(dc ps -a -q "$service" | xargs -r docker inspect --format '{{.State.Status}} {{if .State.Health}}{{.State.Health.Status}}{{end}}' 2>/dev/null) || health=unknown
    if [[ "$health" == 'running healthy' ]]; then
      doctor_add "service-${service}" ok "${service} is healthy" "none"
    else
      action="Run ./chronicle logs ${service}, correct the first error, then run ./chronicle up"
      if [[ "$health" == running* ]]; then
        health="${health#running }"
        summary="${service} is running (health: ${health:-unknown})"
      elif [[ "$health" == unknown ]]; then
        summary="Could not check ${service} container state"
        action="Check Docker connectivity and rerun doctor"
      else
        summary="${service} is not running (state: ${health:-missing})"
      fi
      doctor_add "service-${service}" fail "$summary" "$action"
    fi
  done

  local privileges_status=0 privileges_message privileges_violation privileges_recovery privileges_retry
  local privileges_contract
  if ! privileges_contract="$(ops_python -c \
    'from chronicle_ops.verify import DATABASE_PRIVILEGES_VIOLATION, DATABASE_PRIVILEGES_RECOVERY, DATABASE_PRIVILEGES_RETRY; print("\x1f".join((str(DATABASE_PRIVILEGES_VIOLATION), DATABASE_PRIVILEGES_RECOVERY, DATABASE_PRIVILEGES_RETRY)))')" || [[ -z "$privileges_contract" ]]; then
    doctor_add database-privileges fail "Could not load database privilege checks" "Repair the installed diagnostic package and rerun doctor"
    return
  fi
  IFS=$'\x1f' read -r privileges_violation privileges_recovery privileges_retry <<<"$privileges_contract"
  privileges_message=$(ops_python database-privileges 2>/dev/null) || privileges_status=$?
  if [[ "$privileges_status" -eq 0 ]]; then
    doctor_add database-privileges ok "$privileges_message" "none"
  elif [[ "$privileges_status" -eq "$privileges_violation" ]]; then
    doctor_add database-privileges fail "$privileges_message" "$privileges_recovery"
  else
    doctor_add database-privileges fail "${privileges_message:-Could not check database privileges}" "$privileges_retry"
  fi
}

doctor_check_reviewer() {
  local running="$1"
  if [[ "${CHRONICLE_REVIEWER_ACCESS_ENABLED:-false}" == true ||
        -n "${CHRONICLE_REVIEWER_STUDY_ID:-}" ||
        -n "${CHRONICLE_REVIEWER_PARTICIPANT_ID:-}" ]]; then
    local reviewer_state="query-failed"
    if [[ "${CHRONICLE_REVIEWER_STUDY_ID:-}" =~ ^[0-9A-Fa-f-]{36}$ &&
          "${CHRONICLE_REVIEWER_PARTICIPANT_ID:-}" =~ ^[a-zA-Z0-9_.-]{1,255}$ ]] &&
       grep -Fxq postgres <<<"$running"; then
      reviewer_state="$(reviewer_scope_state \
        "$CHRONICLE_REVIEWER_STUDY_ID" "$CHRONICLE_REVIEWER_PARTICIPANT_ID" 2>/dev/null || true)"
    fi
    if [[ "$reviewer_state" == ok ]]; then
      doctor_add reviewer-scope ok \
        "Play reviewer study and synthetic participant are active" "none"
    else
      doctor_add reviewer-scope fail \
        "Play reviewer scope is unavailable (${reviewer_state:-query-failed})" \
        "Use the dashboard to create/activate the synthetic reviewer study and participant, then rerun ./chronicle doctor"
    fi
  else
    doctor_add reviewer-scope warn "Play reviewer bootstrap is not configured" \
      "Follow the Play reviewer setup in README.md before submitting the app for review"
  fi
}

doctor_check_disk() {
  local rows
  if rows="$(ops_python - <<'PY_DISK'
from chronicle_ops.verify import disk_rows
from chronicle_ops.envfile import read_env
import os
try:
    rows = disk_rows(read_env('.env'), os.environ['CHRONICLE_OPS_STATE'])
except Exception:
    rows = [('disk', 'fail', 'Host filesystem capacity could not be read', 'Check Docker connectivity, then run df -h on the Chronicle state filesystem')]
for row in rows:
    print('\x1f'.join(row))
PY_DISK
)" && [[ -n "$rows" ]]; then
    doctor_add_rows "$rows"
  else
    doctor_add disk fail "Host filesystem capacity could not be read" "Check Docker connectivity, then run df -h on the Chronicle state filesystem"
  fi
}

doctor_check_backups() {
  if [[ "${COMPOSE_FILE:-}" == *overlays/backups.yml* ]]; then

    if ! ops_python backup-storage >/dev/null 2>&1; then
      doctor_add backup-encryption fail "Backup backing-device encryption is unconfirmed" \
        "Enable storage encryption or record a reviewed BACKUP_STORAGE_ENCRYPTION_WAIVER"
    fi

  fi
  # WAL and the pg_tde keyring are plain files on the database volume; only disk encryption covers them.
  if ! ops_python database-storage >/dev/null 2>&1; then
    doctor_add database-encryption fail "Database volume backing-device encryption is unconfirmed" \
      "Put the Docker data root on encrypted storage or record a reviewed BACKUP_STORAGE_ENCRYPTION_WAIVER"
  fi
  local rows
  if rows="$(ops_python - <<'PY_CAPACITY'
from chronicle_ops.verify import capacity_checks
from chronicle_ops.envfile import read_env
import os
try:
    rows = capacity_checks(read_env('.env'), os.environ['CHRONICLE_OPS_BACKUPS'])
except Exception:
    rows = [('backup-capacity', 'fail', 'Could not measure database/backup/WAL capacity', 'Inspect PostgreSQL and backing filesystems')]
for row in rows:
    print('\x1f'.join(row))
PY_CAPACITY
)" && [[ -n "$rows" ]]; then
    doctor_add_rows "$rows"
  else
    doctor_add backup-capacity fail "Could not measure database/backup/WAL capacity" "Inspect PostgreSQL and backing filesystems"
  fi
}

doctor_check_secrets() {
  local rows
  if rows="$(ops_python - <<'PY_SECRET_AGES'
import os
import subprocess
from chronicle_ops.envfile import read_env, value
from chronicle_ops.verify import secret_age_rows, tde_key_generated_at
settings = read_env('.env')
try:
    tde = tde_key_generated_at() if value(settings, 'ENABLE_ENCRYPTION', 'true') == 'true' else None
except (OSError, ValueError, subprocess.SubprocessError):
    tde = None
for row in secret_age_rows(settings, os.environ['CHRONICLE_OPS_STATE'], tde):
    print('\x1f'.join(row))
PY_SECRET_AGES
)" && [[ -n "$rows" ]]; then
    doctor_add_rows "$rows"
  else
    doctor_add secret-ages warn "Secret generation and rotation dates could not be read" \
      "Check CHRONICLE_SECRET_GENERATED_AT in .env and the receipts in operator-receipts/secret-rotations"
  fi
}

doctor_check_monitoring() {
  local running="$1"
  if [[ "${COMPOSE_FILE:-}" == *overlays/monitoring.yml* ]]; then
    local monitor_service
    for monitor_service in victoriametrics victorialogs fluent-bit grafana operational-probe; do
      if grep -Fxq "$monitor_service" <<<"$running"; then
        doctor_add "monitor-${monitor_service}" ok "${monitor_service} is running" "none"
      else
        doctor_add "monitor-${monitor_service}" fail "${monitor_service} is not running" "Run ./chronicle logs ${monitor_service}, correct the first error, then docker compose up -d ${monitor_service}"
      fi
    done
    local rows
    if rows="$(ops_python - <<'PY_MONITORING'
from chronicle_ops.verify import monitoring_checks
try:
    rows = monitoring_checks()
except Exception:
    rows = [('monitoring-pipeline', 'fail', 'Could not qualify metrics/log delivery', 'Inspect monitoring service logs')]
for row in rows:
    print('\x1f'.join(row))
PY_MONITORING
)" && [[ -n "$rows" ]]; then
      doctor_add_rows "$rows"
    else
      doctor_add monitoring-pipeline fail "Could not qualify metrics/log delivery" "Inspect monitoring service logs"
    fi
    if [[ -n "${CHRONICLE_ALERT_WEBHOOK_URL:-}" ]]; then
      doctor_add alert-route ok "A human alert destination is configured" "none"
    else
      doctor_add alert-route fail "Alerts reach no one: CHRONICLE_ALERT_WEBHOOK_URL is unset, so firing alerts stay in Grafana only" \
        "Set CHRONICLE_ALERT_WEBHOOK_URL in .env, apply it with docker compose up -d grafana, then test the contact point in Grafana"
    fi
  else
    doctor_add monitoring warn "Monitoring overlay is disabled" "Run ./chronicle setup to enable it, or add overlays/monitoring.yml as documented"
  fi
}

doctor_render() {
  local json="$1"
  if [[ "$json" == true ]]; then
    printf '%s\0' "${DOCTOR_ROWS[@]}" | DOCTOR_FAILED="$DOCTOR_FAILED" python3 -c '
import json, os, sys
rows=[]
for raw in sys.stdin.buffer.read().split(b"\0"):
    if not raw: continue
    ident,status,summary,action=raw.decode().split("\x1f")
    rows.append({
        "check": ident,
        "status": status,
        "likelyCause": summary,
        "recoveryCommand": action,
    })
print(json.dumps({"overall":"fail" if os.environ["DOCTOR_FAILED"]=="1" else "ok","checks":rows}, separators=(",",":")))
'
  else
    printf '%sChronicle doctor%s\n' "$BLD" "$RST"
    local row id status summary action
    for row in "${DOCTOR_ROWS[@]}"; do
      IFS=$'\x1f' read -r id status summary action <<<"$row"
      case "$status" in
        ok) printf '  %sok%s   %-26s %s\n' "$GRN" "$RST" "$id" "$summary" ;;
        warn) printf '  %swarn%s %-26s %s\n       action: %s\n' "$YEL" "$RST" "$id" "$summary" "$action" ;;
        fail) printf '  %sFAIL%s %-26s %s\n       action: %s\n' "$RED" "$RST" "$id" "$summary" "$action" ;;
      esac
    done
  fi
}

