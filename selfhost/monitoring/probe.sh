#!/usr/bin/env bash
set -Eeuo pipefail

# Two containers run this loop (overlays/monitoring.yml). PROBE_SCOPE=internal (operational-probe)
# holds the database password and measures everything inside the host on internal networks only.
# PROBE_SCOPE=public (public-probe) is the one container that reaches the internet: it fetches the
# public health URL and reads the served certificate, holding no credential, key or data.
: "${PROBE_SCOPE:=internal}"
[[ "$PROBE_SCOPE" == internal || "$PROBE_SCOPE" == public ]] || { printf 'PROBE_SCOPE must be internal or public\n' >&2; exit 64; }
: "${POSTGRES_HOST:=postgres}"
: "${POSTGRES_PORT:=5432}"
: "${POSTGRES_DB:=chronicle}"
: "${POSTGRES_USER:=chronicle}"
# secrets-init writes the password to POSTGRES_PASSWORD_FILE; Compose restarts this probe
# when it changes. The environment variable is still accepted (older Compose files).
if [[ "$PROBE_SCOPE" == internal && -z "${POSTGRES_PASSWORD:-}" && -n "${POSTGRES_PASSWORD_FILE:-}" ]]; then
  POSTGRES_PASSWORD="$(<"$POSTGRES_PASSWORD_FILE")"
fi
[[ "$PROBE_SCOPE" == public ]] || : "${POSTGRES_PASSWORD:?POSTGRES_PASSWORD is required}"
: "${PROBE_INTERVAL_SECONDS:=30}"
: "${RELEASE_VERSION:=unknown}"
: "${DOMAIN:=unknown}"
: "${PUBLIC_HEALTH_URL:=}"
: "${PUBLIC_TLS_URL:=https://${DOMAIN}}"
: "${PUBLIC_CA_FILE:=}"
: "${LOGS_HEALTH_URL:=http://victorialogs:9428/health}"
: "${COMPOSE_FILE_SELECTION:=}"
: "${ENABLE_ENCRYPTION:=true}"
: "${METRICS_DISK_BUDGET_BYTES:=5368709120}"
: "${LOGS_DISK_BUDGET_BYTES:=5368709120}"
# operational-probe copies the one CA certificate public-probe needs here; public-probe never
# mounts the state tls/ directory, which also holds private keys.
PUBLIC_TRUST_FILE=/public-trust/public-ca.crt
[[ -n "$PUBLIC_HEALTH_URL" ]] || PUBLIC_HEALTH_URL="${CHRONICLE_PUBLIC_BASE_URL:-$PUBLIC_TLS_URL}/health"
if [[ "$PROBE_SCOPE" == internal ]]; then
  read -r INTERNAL_TLS_URL INTERNAL_CONNECT < <(python3 - <<'PY_INTERNAL'
from chronicle_ops.common import authority, dashboard_origin
import os
from urllib.parse import urlsplit
origin = dashboard_origin(os.environ)
parsed = urlsplit(origin)
print(origin, authority(parsed.hostname, parsed.port or 443) + ':web:8081')
PY_INTERNAL
)
  : "${INTERNAL_HEALTH_URL:=$INTERNAL_TLS_URL/health}"
fi

escape_label() {
  printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g; s/[[:cntrl:]]//g'
}

# Prints nothing when du cannot read the whole tree: a partial total is not a measurement.
dir_bytes() {
  local usage
  usage="$(du -sb "$1" 2>/dev/null)" || return 0
  printf '%s' "${usage%%[[:space:]]*}"
}

file_epoch() {
  stat -c '%Y' "$1" 2>/dev/null || printf '0'
}

certificate_expiry() {
  local expiry
  expiry="$(openssl x509 -noout -enddate 2>/dev/null | sed 's/^notAfter=//' || true)"
  if [[ -n "$expiry" ]]; then
    date -d "$expiry" +%s 2>/dev/null || true
  fi
}

public_tls_expiry() {
  if [[ "$1" != https://* || "$DOMAIN" == unknown ]] || ! command -v timeout >/dev/null 2>&1 ||
      ! command -v openssl >/dev/null 2>&1; then
    return
  fi
  local tls_authority tls_target tls_server_name
  local -a tls_sni_args=() tls_trust_args=()
  tls_authority="${1#https://}"
  tls_authority="${tls_authority%%/*}"
  tls_authority="${tls_authority%%\?*}"
  tls_authority="${tls_authority%%#*}"
  tls_server_name="$tls_authority"
  case "$tls_authority" in
    \[*\])
      tls_target="${tls_authority}:443"
      tls_server_name="${tls_authority#\[}"
      tls_server_name="${tls_server_name%%\]*}"
      ;;
    \[*\]:*)
      tls_target="$tls_authority"
      tls_server_name="${tls_authority#\[}"
      tls_server_name="${tls_server_name%%\]*}"
      ;;
    *:*)
      tls_target="$tls_authority"
      tls_server_name="${tls_authority%%:*}"
      ;;
    *) tls_target="${tls_authority}:443" ;;
  esac
  if [[ "$tls_server_name" == *:* || "$tls_server_name" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    tls_sni_args=(-noservername -verify_ip "$tls_server_name")
  else
    tls_sni_args=(-servername "$tls_server_name" -verify_hostname "$tls_server_name")
  fi
  [[ -z "${2:-}" ]] || tls_trust_args=(-partial_chain -CAfile "$2")
  # public-probe has no route out of its own: it reaches the public origin through egress-proxy
  # (PUBLIC_TLS_PROXY), as curl does through HTTPS_PROXY. An explicit target is a local one.
  local -a tls_proxy_args=()
  [[ -n "${3:-}" || -z "${PUBLIC_TLS_PROXY:-}" ]] || tls_proxy_args=(-proxy "$PUBLIC_TLS_PROXY")
  tls_target="${3:-$tls_target}"
  local served
  served=$(timeout 8 openssl s_client -verify_return_error -connect "$tls_target" "${tls_proxy_args[@]}" "${tls_sni_args[@]}" "${tls_trust_args[@]}" </dev/null 2>/dev/null) || return 0
  printf '%s\n' "$served" | certificate_expiry
}

# The CA that signs the public origin's certificate: the operator's PUBLIC_CA_FILE, the trial
# CA in local-https mode, or none (public CAs in the system store).
public_ca_file() {
  local public_ca="$PUBLIC_CA_FILE"
  [[ "$COMPOSE_FILE_SELECTION" != *overlays/mode-local-https.yml* ]] || public_ca=/tls/local-ca.crt
  printf '%s' "$public_ca"
}

# Publishes public_ca_file's certificates for public-probe, or removes a stale copy.
share_public_trust() {
  local source target_dir tmp
  target_dir="$(dirname "$PUBLIC_TRUST_FILE")"
  [[ -d "$target_dir" ]] || return 0
  source="$(public_ca_file)"
  tmp="$target_dir/.public-ca.crt.$$"
  # Certificates only: whatever else the file holds (a key pasted by mistake) never crosses over.
  if [[ -n "$source" && -s "$source" ]] && openssl x509 -in "$source" -out "$tmp" 2>/dev/null; then
    chmod 0644 "$tmp"
    mv -f "$tmp" "$PUBLIC_TRUST_FILE"
  else
    rm -f "$tmp" "$PUBLIC_TRUST_FILE"
  fi
}

collect_public() {
  local now tmp public_up=0 cert_expiry public_ca=""
  local -a public_trust=()
  tmp="/metrics/.public.prom.$$"
  [[ ! -s "$PUBLIC_TRUST_FILE" ]] || public_ca="$PUBLIC_TRUST_FILE"
  [[ -z "$public_ca" ]] || public_trust=(--cacert "$public_ca")
  if command -v curl >/dev/null 2>&1; then
    [[ "$(curl "${public_trust[@]}" -sS --max-time 10 -o /dev/null -w '%{http_code}' "$PUBLIC_HEALTH_URL" 2>/dev/null)" == 204 ]] && public_up=1 || true
  fi
  cert_expiry="$(public_tls_expiry "$PUBLIC_TLS_URL" "$public_ca")"
  now="$(date +%s)"
  awk '/^#/ || NF > 1' >"$tmp" <<EOF
# HELP chronicle_public_probe_timestamp_seconds Last completed public endpoint probe.
# TYPE chronicle_public_probe_timestamp_seconds gauge
chronicle_public_probe_timestamp_seconds $now
# HELP chronicle_public_probe_success Configured participant endpoint health probe result.
# TYPE chronicle_public_probe_success gauge
chronicle_public_probe_success $public_up
# HELP chronicle_certificate_expiry_timestamp_seconds Expiry of the certificate served by the public HTTPS origin.
# TYPE chronicle_certificate_expiry_timestamp_seconds gauge
chronicle_certificate_expiry_timestamp_seconds $cert_expiry
EOF
  chmod 0644 "$tmp"
  mv -f "$tmp" /metrics/public.prom
}

collect() {
  local now tmp db_up=0 web_up=0 logs_up=0 internal_cert_expiry backup_epoch=0 backup_valid=0 backups_expected=0
  local backup_max_age
  local db_size="" connections="" max_connections="" commits="" rollbacks="" deadlocks="" flyway="" tde_expected=0 tde_healthy=0
  local metrics_bytes logs_bytes backups_bytes
  tmp="/metrics/.operational.prom.$$"
  [[ "$ENABLE_ENCRYPTION" == true ]] && tde_expected=1

  local database_stats
  export PGPASSWORD="$POSTGRES_PASSWORD" PGCONNECT_TIMEOUT=5 PGOPTIONS='-c statement_timeout=5000'
  if pg_isready -h "$POSTGRES_HOST" -p "$POSTGRES_PORT" -U "$POSTGRES_USER" -d "$POSTGRES_DB" -t 5 >/dev/null 2>&1 &&
      database_stats="$(psql -X -qAt -v ON_ERROR_STOP=1 -F '|' -h "$POSTGRES_HOST" -p "$POSTGRES_PORT" \
  -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c \
  "SELECT pg_database_size(current_database()),numbackends,current_setting('max_connections')::integer,xact_commit,xact_rollback,deadlocks FROM pg_stat_database WHERE datname=current_database()" 2>/dev/null)"; then
    db_up=1
    IFS='|' read -r db_size connections max_connections commits rollbacks deadlocks <<<"$database_stats"
    flyway="$(psql -X -qAt -v ON_ERROR_STOP=1 -h "$POSTGRES_HOST" -p "$POSTGRES_PORT" \
      -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c \
      "SELECT COALESCE(MAX(CASE WHEN version ~ '^[0-9]+$' THEN version::integer END),0) FROM flyway_schema_history WHERE success" 2>/dev/null || true)"
    if [[ $tde_expected -eq 1 ]] && psql -X -qAt -v ON_ERROR_STOP=1 -h "$POSTGRES_HOST" -p "$POSTGRES_PORT" \
      -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c \
      "SELECT CASE WHEN current_setting('default_table_access_method')='tde_heap' AND (SELECT key_name FROM pg_tde_key_info()) IS NOT NULL AND NOT EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace JOIN pg_am a ON a.oid=c.relam WHERE n.nspname='public' AND c.relkind='r' AND a.amname<>'tde_heap') THEN 1 ELSE 0 END" 2>/dev/null | grep -x 1 >/dev/null; then
      tde_healthy=1
    fi
  fi
  unset PGPASSWORD PGCONNECT_TIMEOUT PGOPTIONS

  local internal_ca
  internal_ca="$(python3 -c 'from chronicle_ops.common import dashboard_ca; print(dashboard_ca("/tls"))')"
  share_public_trust
  if command -v curl >/dev/null 2>&1; then
    [[ "$(curl --connect-to "$INTERNAL_CONNECT" --cacert "$internal_ca" -sS --max-time 8 -o /dev/null -w '%{http_code}' "$INTERNAL_HEALTH_URL" 2>/dev/null)" == 204 ]] && web_up=1 || true
    if [[ -n "$logs_probe_category" ]] && curl -fsS --max-time 8 "$LOGS_HEALTH_URL" >/dev/null 2>&1 &&
        curl -fsS --max-time 8 "${LOGS_HEALTH_URL%/health}/select/logsql/query?query=failure_category%3A${logs_probe_category}" |
        grep -F "$logs_probe_category" >/dev/null; then
      logs_up=1
    fi
    local logs_token
    if logs_token="$(openssl rand -hex 8)"; then
      logs_probe_category="probe_${logs_token}"
      if ! record_event logs-probe success "$logs_probe_category"; then
        logs_probe_category=""
        printf 'operational probe could not record its logs event\n' >&2
        return 1
      fi
    else
      logs_probe_category=""
    fi
  fi

  internal_cert_expiry="$(public_tls_expiry "$INTERNAL_TLS_URL" "$internal_ca" web:8081)"

  [[ "$COMPOSE_FILE_SELECTION" == *overlays/backups.yml* ]] && backups_expected=1
  local latest_backup=""
  if [[ -f "/backups/last/$POSTGRES_DB-verified.json" ]]; then
    latest_backup="$(python3 - "$POSTGRES_DB" <<'PY_BACKUP'
from chronicle_ops.dump import BACKUP_VERIFICATION_CACHE, cached_verified_backup
from pathlib import Path
import os
import sys
try:
    print(cached_verified_backup('/backups', sys.argv[1], Path('/metrics') / BACKUP_VERIFICATION_CACHE,
                                 os.environ.get('BACKUP_SCHEDULE', '')).path)
except (OSError, ValueError, KeyError, TypeError):
    sys.exit(0)  # Empty output becomes backup_valid=0 in the emitted metrics.
PY_BACKUP
)"
  fi
  if [[ -n "$latest_backup" && -s "$latest_backup" ]]; then
    backup_epoch="$(file_epoch "$latest_backup")"
    backup_valid=1
  fi
  # An invalid schedule leaves this unmeasured, so the stale-backup alert sees no data and fires.
  backup_max_age="$(python3 -c 'import os; from chronicle_ops.dump import backup_max_age_seconds; print(backup_max_age_seconds(os.environ.get("BACKUP_SCHEDULE", "")))' 2>/dev/null || true)"
  low_free_ratio="$(python3 -c 'from chronicle_ops.common import LOW_FREE_PERCENT; print(LOW_FREE_PERCENT / 100)' 2>/dev/null || true)"
  metrics_bytes="$(dir_bytes /observability-data/metrics)"
  logs_bytes="$(dir_bytes /observability-data/logs)"
  backups_bytes="$(dir_bytes /backups)"

  now="$(date +%s)"
  # A sample with no value was not measured: drop it rather than let it read as zero.
  awk '/^#/ || NF > 1' >"$tmp" <<EOF
# HELP chronicle_release_info Immutable Chronicle release currently observed.
# TYPE chronicle_release_info gauge
chronicle_release_info{version="$(escape_label "$RELEASE_VERSION")"} 1
# HELP chronicle_operational_probe_timestamp_seconds Last completed operational probe.
# TYPE chronicle_operational_probe_timestamp_seconds gauge
chronicle_operational_probe_timestamp_seconds $now
# HELP chronicle_operational_probe_interval_seconds Configured delay between operational collections.
# TYPE chronicle_operational_probe_interval_seconds gauge
chronicle_operational_probe_interval_seconds $PROBE_INTERVAL_SECONDS
# HELP chronicle_database_up PostgreSQL accepted an authenticated readiness query.
# TYPE chronicle_database_up gauge
chronicle_database_up $db_up
# HELP chronicle_web_up Caddy health is reachable inside the Compose network.
# TYPE chronicle_web_up gauge
chronicle_web_up $web_up
# HELP chronicle_logs_pipeline_up Previous probe event traversed Fluent Bit to healthy VictoriaLogs.
# TYPE chronicle_logs_pipeline_up gauge
chronicle_logs_pipeline_up $logs_up
# HELP chronicle_postgres_database_bytes Current Chronicle database size.
# TYPE chronicle_postgres_database_bytes gauge
chronicle_postgres_database_bytes $db_size
# HELP chronicle_postgres_connections Current connections to the Chronicle database.
# TYPE chronicle_postgres_connections gauge
chronicle_postgres_connections $connections
# HELP chronicle_postgres_max_connections Configured PostgreSQL connection ceiling.
# TYPE chronicle_postgres_max_connections gauge
chronicle_postgres_max_connections $max_connections
# HELP chronicle_postgres_transactions_total PostgreSQL transaction outcomes.
# TYPE chronicle_postgres_transactions_total counter
chronicle_postgres_transactions_total{outcome="commit"} $commits
chronicle_postgres_transactions_total{outcome="rollback"} $rollbacks
# HELP chronicle_postgres_deadlocks_total PostgreSQL deadlocks for the Chronicle database.
# TYPE chronicle_postgres_deadlocks_total counter
chronicle_postgres_deadlocks_total $deadlocks
# HELP chronicle_flyway_schema_version Latest successful numeric Flyway migration.
# TYPE chronicle_flyway_schema_version gauge
chronicle_flyway_schema_version $flyway
# HELP chronicle_tde_healthy Active pg_tde key, default table access method, and application table coverage.
# TYPE chronicle_tde_healthy gauge
chronicle_tde_healthy $tde_healthy
# HELP chronicle_tde_expected Whether encryption at rest is enabled for this deployment.
# TYPE chronicle_tde_expected gauge
chronicle_tde_expected $tde_expected
# HELP chronicle_backup_latest_success_timestamp_seconds Latest local backup modification time.
# TYPE chronicle_backup_latest_success_timestamp_seconds gauge
chronicle_backup_latest_success_timestamp_seconds $backup_epoch
# HELP chronicle_backup_max_age_seconds Age at which the newest verified backup is overdue under BACKUP_SCHEDULE.
# TYPE chronicle_backup_max_age_seconds gauge
chronicle_backup_max_age_seconds $backup_max_age
# HELP chronicle_disk_low_free_ratio Free-space share below which doctor and the disk-pressure alert advise capacity.
# TYPE chronicle_disk_low_free_ratio gauge
chronicle_disk_low_free_ratio $low_free_ratio
# HELP chronicle_backups_expected Whether the selected deployment declares scheduled backups.
# TYPE chronicle_backups_expected gauge
chronicle_backups_expected $backups_expected
# HELP chronicle_backup_latest_verified Latest local backup matches its verified marker and file identity.
# TYPE chronicle_backup_latest_verified gauge
chronicle_backup_latest_verified $backup_valid
# HELP chronicle_backup_storage_bytes Local backup storage currently used.
# TYPE chronicle_backup_storage_bytes gauge
chronicle_backup_storage_bytes $backups_bytes
# HELP chronicle_internal_certificate_expiry_timestamp_seconds Expiry of the internal dashboard listener certificate.
# TYPE chronicle_internal_certificate_expiry_timestamp_seconds gauge
chronicle_internal_certificate_expiry_timestamp_seconds $internal_cert_expiry
# HELP chronicle_observability_storage_bytes Local observability data currently retained.
# TYPE chronicle_observability_storage_bytes gauge
chronicle_observability_storage_bytes{store="metrics"} $metrics_bytes
chronicle_observability_storage_bytes{store="logs"} $logs_bytes
# HELP chronicle_observability_storage_budget_bytes Configured local observability budget.
# TYPE chronicle_observability_storage_budget_bytes gauge
chronicle_observability_storage_budget_bytes{store="metrics"} ${METRICS_DISK_BUDGET_BYTES}
chronicle_observability_storage_budget_bytes{store="logs"} ${LOGS_DISK_BUDGET_BYTES}
EOF
  chmod 0644 "$tmp"
  mv -f "$tmp" /metrics/operational.prom
}

# Tests source this file for its functions; only a direct run collects.
[[ "${BASH_SOURCE[0]}" == "$0" ]] || return 0

[[ "$PROBE_INTERVAL_SECONDS" =~ ^[1-9][0-9]*$ ]] || exit 64
(( PROBE_INTERVAL_SECONDS <= 300 )) || exit 64
mkdir -p /metrics
umask 077
if [[ "$PROBE_SCOPE" == public ]]; then
  while true; do
    collect_public || printf 'public probe collection failed\n' >&2
    sleep "$PROBE_INTERVAL_SECONDS"
  done
fi
# shellcheck source=selfhost/monitoring/record-operation.sh
source /monitoring/record-operation.sh
logs_probe_category=""

while true; do
  collect || printf 'operational probe collection failed\n' >&2
  sleep "$PROBE_INTERVAL_SECONDS"
done
