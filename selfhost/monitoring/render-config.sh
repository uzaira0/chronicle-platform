#!/usr/bin/env bash
set -Eeuo pipefail

fail() { printf 'monitoring-config: %s\n' "$*" >&2; exit 1; }

: "${METRICS_USERNAME:=chronicle-metrics}"
: "${METRICS_PASSWORD:?METRICS_PASSWORD is required}"
: "${COMPOSE_PROJECT_NAME:=chronicle-selfhost}"
[[ ${#METRICS_PASSWORD} -ge 32 && ${#METRICS_PASSWORD} -le 1024 ]] ||
  fail "metrics password must contain 32..1024 characters"
[[ "$METRICS_USERNAME" =~ ^[A-Za-z0-9._-]{1,64}$ ]] ||
  fail "metrics username contains unsupported characters"

[[ "$COMPOSE_PROJECT_NAME" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$ ]] ||
  fail "Compose project name cannot be represented safely in the scrape allowlist"

# This mandatory init service also guards independent monitoring starts, where the main
# application config-guard may never run. Never print password bytes.
: "${GRAFANA_ADMIN_PASSWORD:?GRAFANA_ADMIN_PASSWORD is required}"
: "${GRAFANA_BIND:=127.0.0.1}"
[[ ${#GRAFANA_ADMIN_PASSWORD} -ge 32 && ${#GRAFANA_ADMIN_PASSWORD} -le 1024 ]] ||
  fail "Grafana password must contain 32..1024 characters"
case "$GRAFANA_ADMIN_PASSWORD" in *CHANGE_ME*|*changeme*) fail "Grafana password is a placeholder" ;; esac
# The same release digest rule as config-guard, for the images this stack runs from .env.
if [[ "${RELEASE_VERSION:-development}" != development ]]; then
  for image_var in POSTGRES_IMAGE CADDY_IMAGE GRAFANA_IMAGE FLUENT_BIT_IMAGE; do
    [[ "${!image_var:-}" =~ ^[^[:space:]@]+@sha256:[0-9a-f]{64}$ ]] ||
      fail "${image_var} must be digest-pinned (name@sha256:...) in a release"
  done
fi
source "$(dirname "${BASH_SOURCE[0]}")/../network-policy.sh" || exit 1
specific_private_bind "$GRAFANA_BIND" || fail "Grafana must bind one specific private or loopback IP"

: "${CHRONICLE_HOST_UID:?operator UID is required}"
: "${CHRONICLE_HOST_GID:?operator GID is required}"
[[ "$CHRONICLE_HOST_UID" =~ ^[1-9][0-9]*$ && "$CHRONICLE_HOST_GID" =~ ^(0|[1-9][0-9]*)$ ]] ||
  fail "monitoring probe requires a non-root operator UID and numeric GID"
mkdir -p /monitoring-secrets /monitoring-config /metrics
chown -R 65534:65534 /vmdata /vldata
chown -R 100:101 /fluent-bit/state
umask 077
temporary="/monitoring-secrets/.metrics-password.$$"
printf '%s' "$METRICS_PASSWORD" >"$temporary"
mv -f "$temporary" /monitoring-secrets/metrics-password
chown 65534:65534 /monitoring-secrets /monitoring-secrets/metrics-password
# Grafana (uid 472) reads its admin password from this file (GF_SECURITY_ADMIN_PASSWORD__FILE).
mkdir -p /grafana-secrets
temporary="/grafana-secrets/.admin-password.$$"
printf '%s' "$GRAFANA_ADMIN_PASSWORD" >"$temporary"
chown 472:0 "$temporary"
chmod 0400 "$temporary"
mv -f "$temporary" /grafana-secrets/admin-password
chown 472:0 /grafana-secrets
chmod 0500 /grafana-secrets
cp /backend-tls/backend.crt /monitoring-config/backend.crt
chmod 0644 /monitoring-config/backend.crt
config_tmp="/monitoring-config/.scrape.yml.$$"
cat >"$config_tmp" <<EOF
global:
  scrape_interval: 15s
  scrape_timeout: 10s

scrape_configs:
  - job_name: chronicle-backend
    scheme: https
    tls_config:
      ca_file: /etc/vm/backend.crt
      server_name: backend
    metrics_path: /prometheus/
    basic_auth:
      username: ${METRICS_USERNAME}
      password_file: /run/secrets/chronicle-metrics/metrics-password
    static_configs:
      - targets: ["web:9091"]
    metric_relabel_configs:
      # Dashboard-login refusals use the API error counter; retain endpoint/method/status labels.
      - source_labels: [__name__]
        regex: 'chronicle_(api_errors_total|enrollment_total|upload_total|upload_errors_total|sensor_materialization_runs_total|sensor_materialized_samples_total|sensor_materialization_quarantined_rows_total|sensor_materialization_duration_seconds(_bucket|_count|_sum)?|api_request_duration_seconds(_bucket|_count|_sum)?|participant_form_access_total|participant_form_submission_total|data_deletion_operations_total|data_deletion_operation_duration_seconds(_bucket|_count|_sum)?|active_requests|studies_retention_expired|operator_operation_timestamp_seconds|background_task_failures_total|browser_errors_total|api_key_usage_total)'
        action: keep
      - regex: '(study_ref|study_id|participant_id|random_device_id|user_id|source_ip|client_ip|key_name|key_prefix|instance)'
        action: labeldrop
  - job_name: chronicle-containers
    static_configs:
      - targets: ["cadvisor:8080"]
    metric_relabel_configs:
      - source_labels: [name]
        regex: '/?${COMPOSE_PROJECT_NAME}[-_].*'
        action: keep
  - job_name: chronicle-host
    static_configs:
      - targets: ["cadvisor:8080"]
    metric_relabel_configs:
      - source_labels: [__name__, id]
        separator: ';'
        regex: '(machine_.*;.*|container_(cpu_.*|memory_.*|fs_.*);/)'
        action: keep
  - job_name: chronicle-operational
    metrics_path: /operational.prom
    static_configs:
      - targets: ["metrics-exporter:9090"]
  - job_name: chronicle-public
    metrics_path: /public.prom
    static_configs:
      - targets: ["metrics-exporter:9090"]
  - job_name: chronicle-log-forwarder
    metrics_path: /api/v1/metrics/prometheus
    static_configs:
      - targets: ["fluent-bit:2020"]
  - job_name: chronicle-operations
    metrics_path: /operations.prom
    static_configs:
      - targets: ["metrics-exporter:9090"]
  - job_name: chronicle-configuration
    metrics_path: /configuration.prom
    static_configs:
      - targets: ["metrics-exporter:9090"]
EOF
chmod 0644 "$config_tmp"
mv -f "$config_tmp" /monitoring-config/scrape.yml
if [[ ! -e /metrics/operations.prom ]]; then
  cat >/metrics/operations.prom <<'EOF'
# HELP chronicle_operator_operation_timestamp_seconds Last completion time of a guarded operator operation.
# TYPE chronicle_operator_operation_timestamp_seconds gauge
EOF
  chmod 0644 /metrics/operations.prom
fi
if [[ ! -e /metrics/operator-events.jsonl ]]; then
  printf '{"failureCategory":"none","operation":"setup","outcome":"success","releaseVersion":"%s","severity":"INFO","timestamp":"%s"}\n' \
    "${RELEASE_VERSION:-unknown}" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" > /metrics/operator-events.jsonl
  chmod 0644 /metrics/operator-events.jsonl
fi
if [[ ! -e /metrics/configuration.prom ]]; then
  cat >/metrics/configuration.prom <<EOF
# HELP chronicle_configuration_valid Latest configuration guard result.
# TYPE chronicle_configuration_valid gauge
chronicle_configuration_valid 0
# HELP chronicle_configuration_check_timestamp_seconds Latest configuration guard run.
# TYPE chronicle_configuration_check_timestamp_seconds gauge
chronicle_configuration_check_timestamp_seconds $(date +%s)
EOF
  chmod 0644 /metrics/configuration.prom
fi
chown -R "$CHRONICLE_HOST_UID:$CHRONICLE_HOST_GID" /metrics
# public-probe writes /public-probe; operational-probe shares the public CA through /public-trust.
for shared in /public-probe /public-trust; do
  [[ ! -d "$shared" ]] || chown -R "$CHRONICLE_HOST_UID:$CHRONICLE_HOST_GID" "$shared"
done
# egress-proxy's allowlist: host:port of the public URLs and of an off-host HTTPS alert webhook.
if [[ -d /egress ]]; then
  bash "$(dirname "${BASH_SOURCE[0]}")/egress-allowlist.sh" >"/egress/.allow.$$"
  chmod 0644 "/egress/.allow.$$"
  mv -f "/egress/.allow.$$" /egress/allow
fi
printf 'monitoring-config: scraper credential installed without printing it\n'
