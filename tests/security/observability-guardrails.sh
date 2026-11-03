#!/usr/bin/env bash
# Static guardrails for Chronicle's self-hosted observability fallback.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
REPORT_DIR="${1:-/tmp/chronicle-observability-guardrails}"
REPORT_FILE="$REPORT_DIR/observability-guardrails.txt"

mkdir -p "$REPORT_DIR"
: > "$REPORT_FILE"

failures=0

record() {
  printf '%s\n' "$*" | tee -a "$REPORT_FILE"
}

fail() {
  failures=$((failures + 1))
  record "[fail] $*"
}

pass() {
  record "[ok] $*"
}

require_file() {
  local path="$1"
  if [ -f "$ROOT_DIR/$path" ]; then
    pass "found $path"
  else
    fail "missing $path"
  fi
}

require_pattern() {
  local path="$1"
  local pattern="$2"
  local description="$3"
  if grep -Eq -- "$pattern" "$ROOT_DIR/$path"; then
    pass "$description"
  else
    fail "$description"
  fi
}

reject_pattern_recursive() {
  local path="$1"
  local pattern="$2"
  local description="$3"
  local output
  output="$REPORT_DIR/$(basename "$path")-rejected-patterns.txt"
  : > "$output"
  if grep -REn -- "$pattern" "$ROOT_DIR/$path" > "$output"; then
    fail "$description; see $output"
  else
    pass "$description"
  fi
}

record "Chronicle observability guardrails"

require_file "k8s/observability/victoria-lite/victoria-metrics.yaml"
require_file "k8s/observability/victoria-lite/victoria-logs.yaml"
require_file "k8s/observability/victoria-lite/fluent-bit.yaml"
require_file "k8s/observability/victoria-lite/policies.yaml"
require_file "k8s/observability/siem-forwarder/kustomization.yaml"
require_file "k8s/observability/siem-forwarder/fluent-bit-siem-forwarder.yaml"
require_file "k8s/observability/siem-forwarder/external-secrets.yaml"
require_file "k8s/observability/siem-forwarder/policies.yaml"
require_file "k8s/observability/siem-forwarder/config/fluent-bit.conf"
require_file "k8s/observability/grafana-lite/grafana.yaml"
require_file "k8s/observability/grafana-lite/external-secrets.yaml"
require_file "k8s/observability/grafana-lite/policies.yaml"
require_file "k8s/observability/grafana-lite/config/datasources.yml"
require_file "k8s/observability/grafana-lite/config/alerting/contactpoints.yml"
require_file "k8s/observability/grafana-lite/config/alerting/notification-policies.yml"
require_file "k8s/observability/grafana-lite/config/alerting/rules.yml"
require_file "docker/SIEM-INTEGRATION.md"
require_file "docker/siem/victorialogs-fluent-bit.conf"
require_file "docker/siem/fluent-bit-kafka.conf"
require_file "docker/siem/filebeat.yml"


require_pattern "k8s/observability/victoria-lite/victoria-metrics.yaml" \
  '-retentionPeriod=7d' \
  "VictoriaMetrics retention is bounded to seven days"
require_pattern "k8s/observability/victoria-lite/victoria-logs.yaml" \
  '-retentionPeriod=7d' \
  "VictoriaLogs retention is bounded to seven days"
require_pattern "k8s/observability/victoria-lite/victoria-metrics.yaml" \
  'type:[[:space:]]*ClusterIP' \
  "VictoriaMetrics service is private ClusterIP"
require_pattern "k8s/observability/victoria-lite/victoria-logs.yaml" \
  'type:[[:space:]]*ClusterIP' \
  "VictoriaLogs service is private ClusterIP"
require_pattern "k8s/observability/grafana-lite/grafana.yaml" \
  'type:[[:space:]]*ClusterIP' \
  "Grafana service is private ClusterIP"

reject_pattern_recursive "k8s/observability" \
  'kind:[[:space:]]*(Ingress|IngressRoute|HTTPRoute|Gateway|VirtualService)' \
  "Observability fallback must not define public route resources"

require_pattern "k8s/observability/grafana-lite/grafana.yaml" \
  'GF_AUTH_ANONYMOUS_ENABLED[[:space:]]*$' \
  "Grafana anonymous-auth env var is declared"
require_pattern "k8s/observability/grafana-lite/grafana.yaml" \
  'value:[[:space:]]*"false"' \
  "Grafana disables anonymous/sign-up/external reporting flags"
require_pattern "k8s/observability/grafana-lite/grafana.yaml" \
  'secretKeyRef:' \
  "Grafana admin password comes from a Kubernetes Secret reference"
require_pattern "k8s/observability/grafana-lite/external-secrets.yaml" \
  'kind:[[:space:]]*ClusterSecretStore' \
  "Grafana admin Secret is sourced through External Secrets"
require_pattern "k8s/observability/grafana-lite/config/datasources.yml" \
  'url:[[:space:]]*http://victoria-metrics:8428' \
  "Grafana VictoriaMetrics datasource is cluster-internal"
require_pattern "k8s/observability/grafana-lite/config/datasources.yml" \
  'url:[[:space:]]*http://victoria-logs:9428' \
  "Grafana VictoriaLogs datasource is cluster-internal"
require_pattern "k8s/observability/grafana-lite/config/datasources.yml" \
  'access:[[:space:]]*proxy' \
  "Grafana datasources use server-side proxy access"
require_pattern "k8s/observability/grafana-lite/kustomization.yaml" \
  'alert-contactpoints\.yml=config/alerting/contactpoints\.yml' \
  "Grafana alert contact points are provisioned through Kustomize"
require_pattern "k8s/observability/grafana-lite/kustomization.yaml" \
  'alert-notification-policies\.yml=config/alerting/notification-policies\.yml' \
  "Grafana alert notification policies are provisioned through Kustomize"
require_pattern "k8s/observability/grafana-lite/kustomization.yaml" \
  'alert-rules\.yml=config/alerting/rules\.yml' \
  "Grafana alert rules are provisioned through Kustomize"
require_pattern "k8s/observability/grafana-lite/grafana.yaml" \
  '/etc/grafana/provisioning/alerting/contactpoints\.yml' \
  "Grafana mounts provisioned alert contact points"
require_pattern "k8s/observability/grafana-lite/grafana.yaml" \
  '/etc/grafana/provisioning/alerting/notification-policies\.yml' \
  "Grafana mounts provisioned alert notification policies"
require_pattern "k8s/observability/grafana-lite/grafana.yaml" \
  '/etc/grafana/provisioning/alerting/rules\.yml' \
  "Grafana mounts provisioned alert rules"
require_pattern "k8s/observability/grafana-lite/config/alerting/contactpoints.yml" \
  'chronicle-local-placeholder' \
  "Grafana fallback contact point is explicitly marked as a placeholder"
require_pattern "k8s/observability/grafana-lite/config/alerting/contactpoints.yml" \
  'http://127\.0\.0\.1:9/chronicle-alert-placeholder' \
  "Grafana fallback contact point cannot accidentally notify an unapproved external sink"
require_pattern "k8s/observability/grafana-lite/config/alerting/notification-policies.yml" \
  'receiver:[[:space:]]*chronicle-local-placeholder' \
  "Grafana notification policy routes to the explicit placeholder until the operator approves a contact path"
require_pattern "k8s/observability/siem-forwarder/fluent-bit-siem-forwarder.yaml" \
  'replicas:[[:space:]]*0' \
  "operator SIEM forwarder is disabled until endpoint and evidence are approved"
require_pattern "k8s/observability/siem-forwarder/fluent-bit-siem-forwarder.yaml" \
  'SIEM_HOST must identify the approved operator SIEM endpoint' \
  "operator SIEM forwarder rejects placeholder or local endpoints"
require_pattern "k8s/observability/siem-forwarder/fluent-bit-siem-forwarder.yaml" \
  'SIEM_AUTHORIZATION_HEADER must come from the approved secret store' \
  "operator SIEM forwarder requires auth material from Secret, not ConfigMap"
require_pattern "k8s/observability/siem-forwarder/fluent-bit-siem-forwarder.yaml" \
  'secretRef:[[:space:]]*$' \
  "operator SIEM forwarder consumes runtime endpoint/auth from a Secret reference"
require_pattern "k8s/observability/siem-forwarder/external-secrets.yaml" \
  'kind:[[:space:]]*ClusterSecretStore' \
  "operator SIEM forwarder Secret is sourced through External Secrets"
require_pattern "k8s/observability/siem-forwarder/fluent-bit-siem-forwarder.yaml" \
  'claimName:[[:space:]]*chronicle-audit-logs' \
  "operator SIEM forwarder reads Chronicle audit logs through the audit PVC"
require_pattern "k8s/observability/siem-forwarder/fluent-bit-siem-forwarder.yaml" \
  'readOnly:[[:space:]]*true' \
  "operator SIEM forwarder mounts audit logs read-only"
require_pattern "k8s/observability/siem-forwarder/fluent-bit-siem-forwarder.yaml" \
  'type:[[:space:]]*ClusterIP' \
  "operator SIEM forwarder metrics endpoint is private ClusterIP"
require_pattern "k8s/observability/siem-forwarder/policies.yaml" \
  'name:[[:space:]]*chronicle-siem-forwarder-egress' \
  "operator SIEM forwarder egress is constrained by NetworkPolicy"
require_pattern "k8s/observability/siem-forwarder/policies.yaml" \
  'cidr:[[:space:]]*10\.0\.0\.0/8' \
  "operator SIEM forwarder egress is restricted to private network ranges"
require_pattern "k8s/observability/siem-forwarder/policies.yaml" \
  'ingress:[[:space:]]*\[\]' \
  "operator SIEM forwarder rejects inbound pod traffic"
require_pattern "k8s/observability/siem-forwarder/config/fluent-bit.conf" \
  'redaction_contract chronicle-production-observability-v1' \
  "operator SIEM forwarder adds the production redaction contract marker"
require_pattern "k8s/observability/siem-forwarder/config/fluent-bit.conf" \
  'forbidden_fields_removed true' \
  "operator SIEM forwarder adds forbidden-field-removal evidence marker"
for forbidden_field in participantId participant_id sourceDevice source_device randomDeviceId random_device_id requestBody responseBody rawPayload stackTrace authorization mobileSigningKey; do
  require_pattern "k8s/observability/siem-forwarder/config/fluent-bit.conf" \
    "Remove[[:space:]]+${forbidden_field}" \
    "operator SIEM forwarder strips forbidden field: ${forbidden_field}"
done
require_pattern "k8s/observability/siem-forwarder/config/fluent-bit.conf" \
  'tls[[:space:]]+On' \
  "operator SIEM forwarder requires TLS"
require_pattern "k8s/observability/siem-forwarder/config/fluent-bit.conf" \
  'tls\.verify[[:space:]]+On' \
  "operator SIEM forwarder verifies TLS"
reject_pattern_recursive "k8s/observability/siem-forwarder" \
  'Bearer[[:space:]]+|Authorization:[[:space:]]|api[_-]?key[=:]|token[=:]|password[=:]|client[_-]?secret[=:]' \
  "operator SIEM forwarder manifests must not contain raw credentials"
require_pattern "k8s/observability/grafana-lite/config/alerting/rules.yml" \
  'uid:[[:space:]]*chronicle_backend_down' \
  "Grafana fallback alerts include backend-down coverage"
require_pattern "k8s/observability/grafana-lite/config/alerting/rules.yml" \
  'uid:[[:space:]]*chronicle_db_pool_pressure' \
  "Grafana fallback alerts include database-pool pressure coverage"
require_pattern "k8s/observability/grafana-lite/config/alerting/rules.yml" \
  'uid:[[:space:]]*chronicle_backend_5xx_errors' \
  "Grafana fallback alerts include backend 5xx coverage"
require_pattern "k8s/observability/grafana-lite/config/alerting/rules.yml" \
  'uid:[[:space:]]*chronicle_enrollment_failures' \
  "Grafana fallback alerts include enrollment failure coverage"
require_pattern "k8s/observability/grafana-lite/config/alerting/rules.yml" \
  'uid:[[:space:]]*chronicle_backup_stale' \
  "Grafana fallback alerts include backup freshness coverage"
require_pattern "k8s/observability/grafana-lite/config/alerting/rules.yml" \
  'uid:[[:space:]]*chronicle_mobile_upload_failures' \
  "Grafana fallback alerts include mobile upload failure coverage"
require_pattern "k8s/observability/grafana-lite/config/alerting/rules.yml" \
  'chronicle_api_errors_total' \
  "Fallback app-level alerts use sanitized backend API error metrics"
require_pattern "k8s/observability/grafana-lite/config/alerting/rules.yml" \
  'status=~"5\.\."' \
  "Backend 5xx fallback alert scopes by status class without raw IDs"
require_pattern "k8s/observability/grafana-lite/config/alerting/rules.yml" \
  'endpoint=~".*\(enroll\|enrollment\).*"' \
  "Enrollment fallback alert scopes route matching without raw IDs"
require_pattern "k8s/observability/grafana-lite/config/alerting/rules.yml" \
  'endpoint=~".*\(upload\|android\|screen-time\|user-identification\).*"' \
  "Mobile upload fallback alert scopes route matching without raw IDs"



























reject_pattern_recursive "k8s/observability/grafana-lite/config/alerting" \
  'Bearer[[:space:]]+|Authorization:|api[_-]?key[=:]|token[=:]|password[=:]|client[_-]?secret[=:]' \
  "Grafana alert provisioning must not contain raw credentials"

if python3 - "$ROOT_DIR/k8s/observability/grafana-lite/config/alerting" "$REPORT_DIR/alerting-parse.txt" <<'PY'
import pathlib
import sys

import yaml

root = pathlib.Path(sys.argv[1])
out = pathlib.Path(sys.argv[2])

contactpoints = yaml.safe_load((root / "contactpoints.yml").read_text(encoding="utf-8"))
policies = yaml.safe_load((root / "notification-policies.yml").read_text(encoding="utf-8"))
rules = yaml.safe_load((root / "rules.yml").read_text(encoding="utf-8"))

rows = []

if contactpoints.get("apiVersion") != 1:
    raise SystemExit("contactpoints.yml missing apiVersion: 1")
contacts = contactpoints.get("contactPoints")
if not isinstance(contacts, list) or not contacts:
    raise SystemExit("contactpoints.yml has no contactPoints")
receiver_names = {contact.get("name") for contact in contacts}
if "chronicle-local-placeholder" not in receiver_names:
    raise SystemExit("missing chronicle-local-placeholder contact point")
for contact in contacts:
    for receiver in contact.get("receivers", []):
        settings = receiver.get("settings", {})
        url = settings.get("url", "")
        if url and url != "http://127.0.0.1:9/chronicle-alert-placeholder":
            raise SystemExit(f"unapproved fallback contact URL: {url}")

if policies.get("apiVersion") != 1:
    raise SystemExit("notification-policies.yml missing apiVersion: 1")
policy_list = policies.get("policies")
if not isinstance(policy_list, list) or not policy_list:
    raise SystemExit("notification-policies.yml has no policies")
for policy in policy_list:
    receiver = policy.get("receiver")
    if receiver not in receiver_names:
        raise SystemExit(f"policy references unknown receiver: {receiver}")
    for route in policy.get("routes", []):
        route_receiver = route.get("receiver")
        if route_receiver not in receiver_names:
            raise SystemExit(f"route references unknown receiver: {route_receiver}")

if rules.get("apiVersion") != 1:
    raise SystemExit("rules.yml missing apiVersion: 1")
groups = rules.get("groups")
if not isinstance(groups, list) or not groups:
    raise SystemExit("rules.yml has no groups")
required_uids = {
    "chronicle_backend_down",
    "chronicle_db_pool_pressure",
    "chronicle_backend_5xx_errors",
    "chronicle_enrollment_failures",
    "chronicle_backup_stale",
    "chronicle_mobile_upload_failures",
}
seen_uids = set()
for group in groups:
    if not group.get("interval"):
        raise SystemExit(f"alert group missing interval: {group.get('name')}")
    for rule in group.get("rules", []):
        uid = rule.get("uid")
        seen_uids.add(uid)
        if rule.get("condition") != "C":
            raise SystemExit(f"{uid} condition must be C")
        if not rule.get("for"):
            raise SystemExit(f"{uid} missing for duration")
        if rule.get("execErrState") != "Alerting":
            raise SystemExit(f"{uid} must alert on execution errors")
        annotations = rule.get("annotations", {})
        labels = rule.get("labels", {})
        if not annotations.get("runbook_url"):
            raise SystemExit(f"{uid} missing runbook_url")
        if labels.get("team") != "chronicle-platform":
            raise SystemExit(f"{uid} missing chronicle-platform team label")
        if labels.get("severity") not in {"critical", "warning"}:
            raise SystemExit(f"{uid} has unsupported severity")
        refs = {datum.get("refId") for datum in rule.get("data", [])}
        if not {"A", "B", "C"}.issubset(refs):
            raise SystemExit(f"{uid} missing A/B/C expression pipeline")
        rule_text = repr(rule)
        if uid == "chronicle_backup_stale":
            if rule.get("noDataState") != "Alerting":
                raise SystemExit("chronicle_backup_stale must fail closed with noDataState: Alerting")
            if "chronicle_backup_latest_success_timestamp_seconds" not in rule_text:
                raise SystemExit("chronicle_backup_stale must use the latest successful backup timestamp metric")
            if "86400" not in rule_text:
                raise SystemExit("chronicle_backup_stale must retain the 24h degraded local threshold")
        rows.append(f"{uid}\tseverity={labels.get('severity')}\tfor={rule.get('for')}\trunbook={annotations.get('runbook_url')}")
missing = sorted(required_uids - seen_uids)
if missing:
    raise SystemExit(f"missing required alert rule uid(s): {', '.join(missing)}")

out.write_text("\n".join(rows) + "\n", encoding="utf-8")
PY
then
  pass "Grafana alert provisioning parses and links placeholder routing, rule pipelines, labels, and runbooks"
else
  fail "Grafana alert provisioning must parse and link placeholder routing, rule pipelines, labels, and runbooks"
fi

require_pattern "docker/SIEM-INTEGRATION.md" \
  'Safe Event Envelope' \
  "SIEM guide documents the redaction-safe event envelope"
require_pattern "docker/SIEM-INTEGRATION.md" \
  'CHRONICLE_SIEM_EVIDENCE' \
  "SIEM guide documents strict cutover evidence"
require_pattern "docker/SIEM-INTEGRATION.md" \
  'private rehearsal overlay' \
  "SIEM guide rejects local plaintext Kafka rehearsal as production evidence"
require_pattern "docker/SIEM-INTEGRATION.md" \
  'redaction_contract=chronicle-production-observability-v1' \
  "SIEM guide documents redaction-contract evidence marker"
reject_pattern_recursive "docker/SIEM-INTEGRATION.md" \
  '"userId"|"resourceId"|"studyId"|"ipAddress"|"userAgent"|"phiFields"|specific-user-uuid|participant-uuid|study-uuid|192\.168\.' \
  "SIEM guide must not show legacy raw audit fields as forwardable examples"
forbidden_shipper_fields=(
  userId
  user_id
  resourceId
  resource_id
  studyId
  study_id
  participantId
  participant_id
  sourceDevice
  source_device
  randomDeviceId
  random_device_id
  ipAddress
  ip_address
  clientIp
  client_ip
  remoteAddr
  forwardedFor
  xForwardedFor
  userAgent
  user_agent
  phiFields
  errorMessage
  exceptionMessage
  stackTrace
  requestUrl
  request_url
  callbackUrl
  callback_url
  fullUrl
  full_url
  requestBody
  request_body
  responseBody
  response_body
  payload
  rawPayload
  raw_payload
  headers
  authorization
  cookie
  setCookie
  accessToken
  access_token
  refreshToken
  refresh_token
  oidcCode
  oidc_code
  jwt
  sessionId
  session_id
  apiKey
  api_key
  mobileSigningKey
  mobile_signing_key
)
for shipper in \
  docker/siem/victorialogs-fluent-bit.conf \
  docker/siem/fluent-bit-kafka.conf \
  k8s/observability/victoria-lite/config/fluent-bit.conf \
  k8s/observability/siem-forwarder/config/fluent-bit.conf; do
  require_pattern "$shipper" 'redaction_contract[[:space:]]+chronicle-production-observability-v1' \
    "$shipper stamps the Chronicle observability redaction contract"
  require_pattern "$shipper" 'forbidden_fields_removed[[:space:]]+true' \
    "$shipper stamps forbidden-field removal evidence"
  for field in "${forbidden_shipper_fields[@]}"; do
    require_pattern "$shipper" "Remove[[:space:]]+$field" \
      "$shipper removes $field"
  done
done
require_pattern "docker/siem/filebeat.yml" \
  'drop_fields:' \
  "Filebeat removes legacy raw fields before forwarding"
require_pattern "docker/siem/filebeat.yml" \
  'redaction_contract:[[:space:]]*chronicle-production-observability-v1' \
  "Filebeat stamps the Chronicle observability redaction contract"
require_pattern "docker/siem/filebeat.yml" \
  'forbidden_fields_removed:[[:space:]]*true' \
  "Filebeat stamps forbidden-field removal evidence"
for field in "${forbidden_shipper_fields[@]}"; do
  require_pattern "docker/siem/filebeat.yml" \
    "$field" \
    "Filebeat drop_fields includes $field"
done
require_pattern "docker/siem/filebeat.yml" \
  'ssl\.verification_mode:[[:space:]]*"certificate"' \
  "Filebeat production example keeps TLS certificate verification enabled"
if grep -Eq 'ssl\.verification_mode:[[:space:]]*"none"' "$ROOT_DIR/docker/siem/filebeat.yml"; then
  fail "Filebeat/OpenSearch example must not contain ssl.verification_mode none"
else
  pass "Filebeat/OpenSearch example does not contain ssl.verification_mode none"
fi

require_pattern "k8s/observability/victoria-lite/policies.yaml" \
  'name:[[:space:]]*default-deny' \
  "Observability namespace has default-deny NetworkPolicy"
require_pattern "k8s/observability/victoria-lite/policies.yaml" \
  'name:[[:space:]]*victoria-metrics-scrape-chronicle' \
  "Metrics scraping is constrained by explicit NetworkPolicy"
require_pattern "k8s/observability/grafana-lite/policies.yaml" \
  'name:[[:space:]]*grafana-egress-victoria' \
  "Grafana egress is constrained to Victoria services"

require_pattern "k8s/observability/victoria-lite/config/victoria-metrics-scrape.yml" \
  'metrics_path:[[:space:]]*/prometheus/' \
  "VictoriaMetrics scrapes only the backend Prometheus endpoint"
require_pattern "k8s/observability/victoria-lite/config/victoria-metrics-scrape.yml" \
  'basic_auth:' \
  "VictoriaMetrics authenticates to the backend metrics endpoint"
require_pattern "k8s/observability/victoria-lite/config/victoria-metrics-scrape.yml" \
  'password_file:[[:space:]]*/run/secrets/chronicle-metrics/password' \
  "VictoriaMetrics reads its scraper credential from a mounted secret file"
require_pattern "docker/docker-compose.traefik.yml" \
  'metrics scraper password must be between 32 and 1024 characters' \
  "Production backend rejects missing or weak metrics scraper credentials"
require_pattern "k8s/observability/victoria-lite/config/victoria-metrics-scrape.yml" \
  'chronicle-backend\.chronicle\.svc\.cluster\.local:40320' \
  "VictoriaMetrics scrape target is the internal backend Service"
require_pattern "chronicle-server/src/main/kotlin/com/openlattice/chronicle/pods/servlet/SecurityFilterRegistrationsPod.kt" \
  'MetricsAuthenticationFilter\(' \
  "The application filter chain authenticates the dedicated metrics servlet"
require_pattern "chronicle-server/src/main/kotlin/com/openlattice/chronicle/pods/servlet/SecurityFilterRegistrationsPod.kt" \
  'MetricsAuthenticationFilter\.parsePasswordFiles\(passwordFiles\)' \
  "The metrics filter receives reloadable file-backed credentials"
require_pattern "chronicle-server/src/main/kotlin/com/openlattice/chronicle/security/MetricsAuthenticationFilter.kt" \
  'password\.length[[:space:]]+in[[:space:]]+MIN_PASSWORD_LENGTH\.\.MAX_PASSWORD_LENGTH' \
  "Metrics authentication rejects missing or weak credentials during application startup"
require_pattern "docker/monitoring/victoriametrics-scrape.yml" \
  'password_file:[[:space:]]*/run/secrets/chronicle_security_metrics_password' \
  "Compose VictoriaMetrics reads its scraper credential from a secret file"
require_pattern "docker/docker-compose.traefik.yml" \
  'chronicle_security_metrics_password' \
  "Production Compose mounts the dedicated metrics credential"
require_pattern "docker/docker-compose.traefik.yml" \
  'wget -qO- -T 5 http://victoria-metrics:8428/health' \
  "Compose metrics credential reloader exposes a bounded dependency healthcheck"
require_pattern "k8s/base/backend.yaml" \
  'CHRONICLE_SECURITY_METRICS_PASSWORD' \
  "Kubernetes injects the backend metrics credential from the app Secret"
require_pattern "k8s/observability/victoria-lite/victoria-metrics.yaml" \
  'secretName:[[:space:]]*chronicle-metrics-scrape' \
  "Kubernetes mounts the matching scraper credential into VictoriaMetrics"
require_pattern "scripts/local-ci.sh" \
  'chronicle_security_metrics_password' \
  "Local container smoke creates and mounts the dedicated metrics credential"
require_pattern "scripts/local-ci.sh" \
  'CHRONICLE_SECURITY_REQUIRE_MFA=true' \
  "Local container smoke supplies the production-required MFA setting explicitly"
require_pattern "tests/security/smoke-tests.sh" \
  'VM_CONTAINER="chronicle-victoria-metrics"' \
  "Deployment smoke targets the active VictoriaMetrics service"
require_pattern "tests/security/smoke-tests.sh" \
  'VLOGS_CONTAINER="chronicle-victoria-logs"' \
  "Deployment smoke targets the active VictoriaLogs service"
require_pattern "tests/security/smoke-tests.sh" \
  'FLUENT_BIT_CONTAINER="chronicle-fluent-bit"' \
  "Deployment smoke targets the active Fluent Bit service"
require_pattern "tests/security/smoke-tests.sh" \
  'GRAFANA_CONTAINER="chronicle-grafana"' \
  "Deployment smoke targets the active Grafana service"
for required_container_ref in \
  BE_CONTAINER \
  VM_CONTAINER \
  VLOGS_CONTAINER \
  FLUENT_BIT_CONTAINER \
  GRAFANA_CONTAINER; do
  require_pattern "tests/security/smoke-tests.sh" \
    "require_required_container \"\\\$$required_container_ref\"" \
    "Deployment smoke fails when required container $required_container_ref is absent"
done
require_pattern "tests/security/smoke-tests.sh" \
  'http://127\.0\.0\.1:40320/chronicle/internal/health/live' \
  "Deployment smoke exercises the backend's exact liveness route"
require_pattern "tests/security/smoke-tests.sh" \
  'http://127\.0\.0\.1:40320/chronicle/internal/health/ready' \
  "Deployment smoke exercises dependency-aware backend readiness"
for exact_operational_path in \
  /chronicle/internal/health/live \
  /chronicle/internal/health/ready \
  /prometheus \
  /prometheus/; do
  require_pattern "chronicle-server/src/main/resources/rate-limit.yaml" \
    "^[[:space:]]*-[[:space:]]*\"${exact_operational_path}\"[[:space:]]*$" \
    "Rate limiting explicitly bypasses exact operational path ${exact_operational_path}"
done
require_pattern "chronicle-server/src/main/kotlin/com/openlattice/chronicle/configuration/RateLimitFilter.kt" \
  'return path in config\.whitelistedPaths' \
  "Rate-limit path bypass uses exact membership rather than unsafe prefix matching"
require_pattern "tests/security/smoke-tests.sh" \
  'metrics_unauth_status.*=[[:space:]]*"401"' \
  "Deployment smoke requires an exact HTTP 401 for unauthenticated metrics"
require_pattern "tests/security/smoke-tests.sh" \
  'query=up%7Bjob%3D%22chronicle-backend%22%7D' \
  "Deployment smoke requires the Chronicle VictoriaMetrics target to be up"
require_pattern "tests/security/smoke-tests.sh" \
  'http://victoria-metrics:8428/health' \
  "Deployment smoke checks VictoriaMetrics health"
require_pattern "tests/security/smoke-tests.sh" \
  'http://victoria-logs:9428/health' \
  "Deployment smoke checks VictoriaLogs health"
require_pattern "tests/security/smoke-tests.sh" \
  'http://fluent-bit:2020/api/v1/health' \
  "Deployment smoke checks Fluent Bit health"
require_pattern "tests/security/smoke-tests.sh" \
  'http://localhost:3000/api/health' \
  "Deployment smoke checks Grafana health"
require_pattern "tests/security/smoke-tests.sh" \
  'probe_id="chronicle-observability-smoke-' \
  "Deployment smoke creates a unique non-sensitive ingestion marker"
require_pattern "tests/security/smoke-tests.sh" \
  'event":"observability_smoke"' \
  "Deployment smoke writes a synthetic observability event"
require_pattern "tests/security/smoke-tests.sh" \
  '/var/log/chronicle/\$\{probe_id\}\.log' \
  "Deployment smoke sends its probe through Fluent Bit's tailed log path"
require_pattern "docker/siem/victorialogs-fluent-bit.conf" \
  'Path[[:space:]]+/var/log/chronicle/\*\.log' \
  "Fluent Bit tails the dedicated ingestion probe path"
require_pattern "tests/security/smoke-tests.sh" \
  'http://victoria-logs:9428/select/logsql/query' \
  "Deployment smoke queries VictoriaLogs for the ingested marker"
# shellcheck disable=SC2016
require_pattern "tests/security/smoke-tests.sh" \
  'rm -f -- "\$1"' \
  "Deployment smoke removes its exact synthetic probe file"

for active_volume in \
  chronicle_postgres_data \
  chronicle_audit_logs \
  chronicle_traefik_access_logs \
  chronicle_victoria_metrics_data \
  chronicle_victoria_logs_data \
  chronicle_fluentbit_state \
  chronicle_grafana_data; do
  require_pattern "tests/security/smoke-tests.sh" \
    "$active_volume" \
    "Deployment smoke checks current named volume $active_volume"
done

retired_smoke_output="$REPORT_DIR/smoke-tests-retired-observability.txt"
: > "$retired_smoke_output"
if grep -En \
  'PROM_CONTAINER|LOKI_CONTAINER|PROMTAIL_CONTAINER|ALERTMGR_CONTAINER|chronicle-(prometheus|loki|promtail|alertmanager)|chronicle_(prometheus_data|loki_data|promtail_positions|alertmanager_data)|:9090/-/healthy|:9093/-/healthy|:3100/ready|:9080/(ready|targets)' \
  "$ROOT_DIR/tests/security/smoke-tests.sh" > "$retired_smoke_output"; then
  fail "Deployment smoke retains retired Prometheus/Loki/Promtail/Alertmanager assumptions; see $retired_smoke_output"
else
  pass "Deployment smoke contains no retired Prometheus/Loki/Promtail/Alertmanager assumptions"
fi

if grep -Eq '/insert/' "$ROOT_DIR/tests/security/smoke-tests.sh"; then
  fail "Deployment smoke must verify log ingestion through Fluent Bit, not insert directly into VictoriaLogs"
else
  pass "Deployment smoke's VictoriaLogs probe cannot bypass Fluent Bit"
fi
require_pattern "k8s/base/backend.yaml" \
  'path:[[:space:]]*/chronicle/internal/health/live' \
  "Kubernetes backend probes use the dedicated unauthenticated liveness route"
for runtime_config in \
  k8s/base/config-templates/rhizome.yaml.template \
  docker/rhizome-docker.yaml.template \
  docker/hetzner/rhizome-runtime.yaml.template; do
  if awk '
    /^[[:space:]]*connectionTimeout:[[:space:]]*[0-9]+[[:space:]]*$/ {
      found += 1
      if (($2 + 0) != 5000) {
        invalid = 1
      }
    }
    END {
      exit !(found == 2 && invalid == 0)
    }
  ' "$ROOT_DIR/$runtime_config"; then
    pass "$runtime_config fixes both Hikari acquisition timeouts at 5000ms"
  else
    fail "$runtime_config must define exactly two connectionTimeout values at 5000ms"
  fi
done
if grep -Eq 'healthcheck:|livenessProbe:|readinessProbe:|startupProbe:' \
  "$ROOT_DIR/docker/docker-compose.production.yml" \
  "$ROOT_DIR/docker/docker-compose.traefik.yml" \
  "$ROOT_DIR/k8s/base/backend.yaml" &&
  grep -E -A8 'healthcheck:|livenessProbe:|readinessProbe:|startupProbe:' \
    "$ROOT_DIR/docker/docker-compose.production.yml" \
    "$ROOT_DIR/docker/docker-compose.traefik.yml" \
    "$ROOT_DIR/k8s/base/backend.yaml" |
    grep -Eq '/prometheus/'; then
  fail "Backend health probes must not depend on the authenticated metrics endpoint"
else
  pass "Backend health probes are independent of authenticated metrics"
fi

reject_pattern_recursive "k8s/observability/grafana-lite/config/dashboards" \
  'participantId|participant_id|sourceDevice|source_device|randomDeviceId|random_device_id|userId|user_id|email|phone|jwt|api[_-]?key|token|session[_-]?id|raw[_-]?ip|client[_-]?ip|remoteAddr|User-Agent|user_agent' \
  "Grafana dashboards must not query or display forbidden raw identifiers/secrets"

if python3 - "$ROOT_DIR/k8s/observability/grafana-lite/config/dashboards" "$REPORT_DIR/dashboard-parse.txt" <<'PY'
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
out = pathlib.Path(sys.argv[2])
rows = []
required_terms = {
    "chronicle-backend": False,
    "HikariPool": False,
    "victorialogs": False,
}

for path in sorted(root.glob("*.json")):
    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)
    panels = data.get("panels", [])
    rows.append(f"{path.name}\tpanels={len(panels)}\ttitle={data.get('title', '')}")
    text = json.dumps(data, sort_keys=True)
    for term in required_terms:
        if term in text:
            required_terms[term] = True

out.write_text("\n".join(rows) + "\n", encoding="utf-8")
missing = [term for term, seen in required_terms.items() if not seen]
if missing:
    raise SystemExit(f"missing required dashboard coverage terms: {', '.join(missing)}")
PY
then
  pass "Grafana dashboards parse and cover backend, database-pool, and log views"
else
  fail "Grafana dashboards must parse and cover backend, database-pool, and log views"
fi

# shellcheck disable=SC2016

if [ "$failures" -gt 0 ]; then
  record "Observability guardrails failed with $failures finding(s)"
  exit 1
fi

record "Observability guardrails passed"
