#!/usr/bin/env bash
# Diagnostic checks share the caller's structured doctor rows.

# Returns a secret-free state label for the operator-pinned Play reviewer scope. Inputs are
# delivered over stdin and revalidated in the database container before entering SQL.
reviewer_scope_state() {
  local study_id="$1" participant_id="$2"
  dc exec -T postgres /bin/bash -euc '
    POSTGRES_PASSWORD="${POSTGRES_PASSWORD:-$(cat "${POSTGRES_PASSWORD_FILE:?POSTGRES_PASSWORD is unavailable in the postgres container}")}"
    IFS= read -r study_id
    IFS= read -r participant_id
    uuid_pattern="^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$"
    participant_pattern="^[a-zA-Z0-9_.-]{1,255}$"
    [[ "$study_id" =~ $uuid_pattern ]]
    [[ "$participant_id" =~ $participant_pattern ]]
    export PGPASSWORD="$POSTGRES_PASSWORD"
    # The values reach the SQL only as psql variables, never spliced into its text (AF-P11).
    exec psql -X -qAt -v ON_ERROR_STOP=1 -v study_id="$study_id" -v participant_id="$participant_id" \
      -h 127.0.0.1 -U "${POSTGRES_USER:-chronicle}" -d "${POSTGRES_DB:-chronicle}" <<'"'"'SQL'"'"'
SELECT CASE
  WHEN NOT EXISTS (
    SELECT 1 FROM studies WHERE study_id = (:'\''study_id'\'')::uuid
  ) THEN '\''missing-study'\''
  WHEN NOT EXISTS (
    SELECT 1 FROM studies
    WHERE study_id = (:'\''study_id'\'')::uuid
      AND lifecycle_status = '\''ACTIVE'\''
      AND CURRENT_TIMESTAMP >= started_at
      AND CURRENT_TIMESTAMP < ended_at
  ) THEN '\''inactive-study'\''
  WHEN NOT EXISTS (
    SELECT 1 FROM study_participants
    WHERE study_id = (:'\''study_id'\'')::uuid
      AND participant_id = :'\''participant_id'\''
  ) THEN '\''missing-participant'\''
  WHEN NOT EXISTS (
    SELECT 1 FROM study_participants
    WHERE study_id = (:'\''study_id'\'')::uuid
      AND participant_id = :'\''participant_id'\''
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

  # Reconcile starts with --no-recreate, so an unapplied .env or Compose edit is reported here (PR-O13).
  local drift
  if drift="$(ops_python config-drift 2>/dev/null)" && [[ -n "$drift" ]]; then
    doctor_add_rows "$drift"
  else
    doctor_add config-drift warn "Could not compare running services with the configuration" "Run docker compose config and correct the reported error"
  fi

  local public_check
  if public_check="$(ops_python public-check 2>&1)"; then
    doctor_add public-readiness ok "Public HTTPS has dependency-aware readiness" "none"
  else
    doctor_add public-readiness fail "${public_check:-Public HTTPS could not be checked}" "Resolve the reported public HTTPS check and rerun doctor"
  fi
}

doctor_check_reconcile_host() {
  local reason
  reason="$(ops_python reconcile host 2>/dev/null)" || reason="could not check the cron prerequisites"
  [[ -n "$reason" ]] || return 0
  doctor_add reconciliation-host warn "Automatic reconciliation is unavailable: $reason" \
    "Install and enable cron (cron or cronie), then run ./chronicle up; or set CHRONICLE_RECONCILE_ENABLED=false"
}

doctor_check_host_versions() {
  local rows row_status message
  if rows="$(ops_python host-versions 2>/dev/null)" && [[ -n "$rows" ]]; then
    while IFS=$'\t' read -r row_status message; do
      [[ -n "$row_status" ]] || continue
      if [[ "$row_status" == ok ]]; then
        doctor_add host-versions ok "$message" "none"
      else
        doctor_add host-versions warn "$message" "Upgrade Docker or the kernel as described; Chronicle keeps running meanwhile"
      fi
    done <<<"$rows"
  else
    doctor_add host-versions warn "Could not read the Docker Engine, containerd, runc and kernel versions" "Run docker version and docker info"
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
    # Update and rollback start db-backup without waiting for its first dump
    # (chronicle_ops/services.py UNAWAITED_BY_UPDATE), so its state is reported here.
    local backup_state
    backup_state=$(dc ps -a -q db-backup | xargs -r docker inspect --format '{{.State.Status}} {{if .State.Health}}{{.State.Health.Status}}{{end}}' 2>/dev/null) || backup_state=unknown
    case "$backup_state" in
      'running healthy')
        doctor_add service-db-backup ok "db-backup is healthy: its last dump passed the restore check" "none" ;;
      'running starting')
        doctor_add service-db-backup warn "db-backup is taking its first backup since it started" \
          "Nothing to do; rerun ./chronicle doctor later. ./chronicle logs db-backup shows its progress" ;;
      *)
        doctor_add service-db-backup fail "db-backup is ${backup_state:-not running}: scheduled backups are not running" \
          "Run ./chronicle logs db-backup, correct the first error, then run ./chronicle up" ;;
    esac

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
  if [[ "${COMPOSE_FILE:-}" == *overlays/monitoring.yml* ]]; then
    # Optional monitoring never gates Chronicle, so its services are warnings; the pipeline
    # check below still fails when metrics or logs are not delivered.
    local health monitor_service monitor_state
    if health="$(ops_python monitoring-health 2>/dev/null)" && [[ -n "$health" ]]; then
      while IFS=$'\t' read -r monitor_service monitor_state; do
        [[ -n "$monitor_service" ]] || continue
        if [[ "$monitor_state" == healthy || "$monitor_state" == completed ]]; then
          doctor_add "monitor-${monitor_service}" ok "${monitor_service} is ${monitor_state}" "none"
        else
          doctor_add "monitor-${monitor_service}" warn "${monitor_service} is ${monitor_state}" "Run ./chronicle logs ${monitor_service}, correct the first error, then docker compose up -d ${monitor_service}"
        fi
      done <<<"$health"
    else
      doctor_add monitoring-services warn "Could not read monitoring service health" "Run ./chronicle monitoring status"
    fi
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
    doctor_check_alerts
    # Where alerts go. With no webhook, the scheduled doctor writes firing alerts to the host's
    # system log (chronicle_ops/alerts.py); with no schedule either, they stay in Grafana only.
    # Never a failure: a failing row here made every reconciliation record a failure (AF-P2).
    local schedule_gap=""
    if [[ "${CHRONICLE_RECONCILE_ENABLED:-true}" != true ]]; then
      schedule_gap="scheduled reconciliation is off"
    else
      schedule_gap="$(ops_python reconcile host 2>/dev/null)" || schedule_gap="the cron prerequisites could not be checked"
    fi
    if [[ -n "${CHRONICLE_ALERT_WEBHOOK_URL:-}" ]]; then
      local also=", and to the host system log"
      [[ -z "$schedule_gap" ]] || also=""
      doctor_add alert-route ok "Alerts go to the configured webhook${also}" "none"
    elif [[ -z "$schedule_gap" ]]; then
      doctor_add alert-route ok "Firing alerts go to the host system log every 15 minutes (journalctl -t chronicle, priority crit); no webhook is set" "none"
    else
      doctor_add alert-route warn "Alerts reach no one: no CHRONICLE_ALERT_WEBHOOK_URL, and ${schedule_gap}, so nothing writes them to the system log" \
        "Install and enable cron, then run ./chronicle up; or add CHRONICLE_ALERT_WEBHOOK_URL=<your alert receiver's https URL> to .env and run ./chronicle up (docs/MONITORING-RUNBOOK.md, Where alerts go)"
    fi
  else
    doctor_add monitoring warn "Monitoring overlay is disabled" "Run ./chronicle setup to enable it, or add overlays/monitoring.yml as documented"
  fi
}

# Firing alerts from Grafana (chronicle_ops/alerts.py). The scheduled run (reconcile.sh sets
# CHRONICLE_ALERT_SYSLOG=true) also writes them to the host's system log.
doctor_check_alerts() {
  local rows
  local -a flags=()
  [[ "${CHRONICLE_ALERT_SYSLOG:-}" != true ]] || flags=(--syslog)
  if rows="$(ops_python alerts "${flags[@]}" 2>/dev/null)" && [[ -n "$rows" ]]; then
    doctor_add_rows "$rows"
  else
    doctor_add alerts-firing warn "Could not read alerts from Grafana" "Run ./chronicle monitoring status"
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

