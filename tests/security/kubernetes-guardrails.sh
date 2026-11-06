#!/usr/bin/env bash
set -euo pipefail

REPORT_DIR="${1:-/tmp/chronicle-kubernetes-guardrails}"
ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
K8S_DIR="$ROOT_DIR/k8s"

mkdir -p "$REPORT_DIR"

fail() {
  echo "ERROR: $*" >&2
  exit 1
}

[ -d "$K8S_DIR/base" ] || fail "k8s/base is missing"
[ -d "$K8S_DIR/overlays/production" ] || fail "k8s/overlays/production is missing"
[ -d "$K8S_DIR/overlays/rhel9-small" ] || fail "k8s/overlays/rhel9-small is missing"
[ -d "$K8S_DIR/backup/offhost" ] || fail "k8s/backup/offhost is missing"
[ -d "$K8S_DIR/observability/grafana-lite" ] || fail "k8s/observability/grafana-lite is missing"
[ -d "$K8S_DIR/security/crowdsec" ] || fail "k8s/security/crowdsec is missing"

search_n() {
  local pattern="$1"
  shift
  if command -v rg >/dev/null 2>&1; then
    rg -n "$pattern" "$@"
  else
    grep -R -n -E "$pattern" "$@"
  fi
}

search_q() {
  local pattern="$1"
  shift
  if command -v rg >/dev/null 2>&1; then
    rg -q "$pattern" "$@"
  else
    grep -R -q -E "$pattern" "$@"
  fi
}

KUBECTL_BIN=""
if command -v kubectl >/dev/null 2>&1; then
  KUBECTL_BIN="$(command -v kubectl)"
elif [ -x /usr/local/bin/kubectl ]; then
  KUBECTL_BIN="/usr/local/bin/kubectl"
fi

KUSTOMIZE_BIN=""
if command -v kustomize >/dev/null 2>&1; then
  KUSTOMIZE_BIN="$(command -v kustomize)"
elif [ -x /usr/local/bin/kustomize ]; then
  KUSTOMIZE_BIN="/usr/local/bin/kustomize"
fi

if search_n 'kind:[[:space:]]*Secret|^[[:space:]]*stringData:' "$K8S_DIR"; then
  fail "Kubernetes manifests must not commit plaintext Secret resources"
fi

if search_n 'image:[[:space:]].*:latest($|[^[:alnum:]_.-])' "$K8S_DIR"; then
  fail "Kubernetes workloads must not use latest image tags"
fi

if search_n 'privileged:[[:space:]]*true|allowPrivilegeEscalation:[[:space:]]*true|automountServiceAccountToken:[[:space:]]*true' "$K8S_DIR"; then
  fail "Kubernetes workloads must not enable privileged mode, privilege escalation, or service-account token automount"
fi

if ! search_q 'pod-security.kubernetes.io/enforce:[[:space:]]*restricted' "$K8S_DIR/base/namespace.yaml"; then
  fail "Chronicle namespace must enforce restricted pod security"
fi

if ! search_q 'kind:[[:space:]]*ExternalSecret' "$K8S_DIR/base/external-secrets.yaml"; then
  fail "Chronicle Kubernetes secrets must be sourced through ExternalSecret"
fi

if ! search_q 'name:[[:space:]]*default-deny' "$K8S_DIR/base/networkpolicies.yaml"; then
  fail "Chronicle Kubernetes namespace must include a default-deny NetworkPolicy"
fi

if ! search_q 'readOnlyRootFilesystem:[[:space:]]*true' "$K8S_DIR/base/backend.yaml" ||
   ! search_q 'readOnlyRootFilesystem:[[:space:]]*true' "$K8S_DIR/base/frontend.yaml"; then
  fail "Backend and frontend pods must use read-only root filesystems"
fi

python3 - "$K8S_DIR/base/backend.yaml" <<'PY'
import sys

import yaml

documents = list(yaml.safe_load_all(open(sys.argv[1], encoding="utf-8")))
backend = next(
    document
    for document in documents
    if isinstance(document, dict)
    and document.get("kind") == "Deployment"
    and document.get("metadata", {}).get("name") == "chronicle-backend"
)
if backend["spec"].get("replicas") != 1:
    raise SystemExit(
        "Backend replicas must remain 1 until cross-pod authorization cache "
        "coherence is implemented"
    )
strategy = backend["spec"].get("strategy", {})
if strategy.get("type") != "Recreate" or "rollingUpdate" in strategy:
    raise SystemExit(
        "Backend controlled updates must use Recreate while authorization caches are process-local"
    )

pod_spec = backend["spec"]["template"]["spec"]
container = next(item for item in pod_spec["containers"] if item.get("name") == "backend")
environment = {item["name"]: item.get("value") for item in container.get("env", [])}
expected_mobile_environment = {
    "MOBILE_SIGNING_ENABLED": "false",
    "MOBILE_SIGNING_REQUIRED": "false",
    "MOBILE_SIGNING_SECRET": "",
}
for name, expected in expected_mobile_environment.items():
    if environment.get(name) != expected:
        raise SystemExit(f"Backend {name} must use the public-client default {expected!r}")
startup = "\n".join(container.get("command", []))
if "must either both be true or both be false" not in startup:
    raise SystemExit("Backend startup must validate the controlled-legacy flags atomically")
if "must stay blank unless controlled legacy compatibility is enabled" not in startup:
    raise SystemExit("Backend startup must reject a legacy key while compatibility is disabled")
if "production requires mobile signing enabled and required" in startup:
    raise SystemExit("Backend startup still forces controlled legacy HMAC on")
expected_export_environment = {
    "CHRONICLE_EXPORT_DIR": "/var/lib/chronicle/exports",
    "CHRONICLE_EXPORT_MAX_ROWS": "1000000",
    "CHRONICLE_EXPORT_MAX_BYTES": "536870912",
    "CHRONICLE_EXPORT_MAX_RUNTIME_SECONDS": "1800",
    "CHRONICLE_EXPORT_MAX_TOTAL_BYTES": "8589934592",
    "CHRONICLE_EXPORT_MIN_FREE_BYTES": "1073741824",
}
for name, expected in expected_export_environment.items():
    if environment.get(name) != expected:
        raise SystemExit(f"Backend {name} must be {expected}")

mounts = {item["name"]: item for item in container.get("volumeMounts", [])}
export_mount = mounts.get("export-artifacts")
if (
    export_mount is None
    or export_mount.get("mountPath") != "/var/lib/chronicle/exports"
    or export_mount.get("readOnly", False)
):
    raise SystemExit("Backend exports must use the writable export-artifacts mount")

volumes = {item["name"]: item for item in pod_spec.get("volumes", [])}
if (
    volumes.get("export-artifacts", {})
    .get("persistentVolumeClaim", {})
    .get("claimName")
    != "chronicle-export-artifacts"
):
    raise SystemExit("Backend export-artifacts volume must use its durable PVC")

if pod_spec.get("securityContext", {}).get("fsGroup") != 1000:
    raise SystemExit("Backend persistent volumes must be writable through fsGroup 1000")

export_pvcs = [
    document
    for document in documents
    if isinstance(document, dict)
    and document.get("kind") == "PersistentVolumeClaim"
    and document.get("metadata", {}).get("name") == "chronicle-export-artifacts"
]
if len(export_pvcs) != 1:
    raise SystemExit("Exactly one chronicle-export-artifacts PVC is required")
export_pvc = export_pvcs[0]
if export_pvc.get("spec", {}).get("accessModes") != ["ReadWriteOnce"]:
    raise SystemExit("Export artifacts PVC must use ReadWriteOnce")
if export_pvc.get("spec", {}).get("resources", {}).get("requests", {}).get("storage") != "10Gi":
    raise SystemExit("Export artifacts PVC must reserve 10Gi")
PY

if ! search_q 'CHRONICLE_SECURITY_REQUIRE_MFA' "$K8S_DIR/base/backend.yaml" ||
   ! search_q 'MFA enforcement cannot use the disabled upstream SAML example' "$K8S_DIR/base/backend.yaml" ||
   ! search_q 'production requires verified live current-session MFA IdP proof' "$K8S_DIR/base/backend.yaml"; then
  fail "Backend Kubernetes startup must require MFA, reject the disabled SAML example, and require live IdP proof"
fi

if ! search_q 'CHRONICLE_SECURITY_METRICS_PASSWORD_FILES' "$K8S_DIR/base/backend.yaml" ||
   ! search_q '/run/secrets/chronicle-metrics/current' "$K8S_DIR/base/backend.yaml" ||
   ! search_q '/run/secrets/chronicle-metrics/previous' "$K8S_DIR/base/backend.yaml" ||
   ! search_q '/run/secrets/chronicle-metrics/next' "$K8S_DIR/base/backend.yaml" ||
   ! search_q 'metrics_password_previous' "$K8S_DIR/base/external-secrets.yaml" ||
   ! search_q 'metrics_password_next' "$K8S_DIR/base/external-secrets.yaml"; then
  fail "Backend metrics authentication must use current/previous/next projected credentials for gap-free rotation"
fi

if ! search_q 'name:[[:space:]]*credential-reloader' "$K8S_DIR/observability/victoria-lite/victoria-metrics.yaml" ||
   ! search_q 'http://127\.0\.0\.1:8428/-/reload' "$K8S_DIR/observability/victoria-lite/victoria-metrics.yaml" ||
   ! search_q 'alpine:3\.24@sha256:' "$K8S_DIR/observability/victoria-lite/victoria-metrics.yaml" ||
   ! search_q 'runAsNonRoot:[[:space:]]*true' "$K8S_DIR/observability/victoria-lite/victoria-metrics.yaml"; then
  fail "VictoriaMetrics must securely reload its scrape configuration when the projected credential rotates"
fi

if ! search_q 'CHRONICLE_SECURITY_REQUIRE_MFA' "$K8S_DIR/base/keycloak.yaml" ||
   ! search_q 'MFA enforcement cannot use the disabled upstream SAML example' "$K8S_DIR/base/keycloak.yaml" ||
   ! search_q 'production requires verified live current-session MFA IdP proof' "$K8S_DIR/base/keycloak.yaml" ||
   ! search_q 'upstream-oidc requires provisioned Upstream OIDC client credentials' "$K8S_DIR/base/keycloak.yaml" ||
   ! search_q 'value:[[:space:]]*upstream-oidc' "$K8S_DIR/base/keycloak.yaml"; then
  fail "Keycloak Kubernetes startup must default to the provisioned OIDC alias and reject disabled or unproved providers"
fi

if ! search_q 'URLRewrite' "$K8S_DIR/base/gateway.yaml" ||
   ! search_q 'X-Chronicle-Internal-Web' "$K8S_DIR/base/gateway.yaml"; then
  fail "Gateway route must strip web API prefix and remove mobile HMAC-bypass header"
fi
if ! search_q 'replacePrefixMatch:[[:space:]]*/chronicle/v3/' "$K8S_DIR/base/gateway.yaml" ||
   ! search_q 'name:[[:space:]]*X-Chronicle-Internal-Web' "$K8S_DIR/base/gateway.yaml" ||
   ! search_q 'value:[[:space:]]*"true"' "$K8S_DIR/base/gateway.yaml" ||
   [[ "$(grep -c 'X-Chronicle-Internal-Web' "$K8S_DIR/base/gateway.yaml")" -lt 2 ]]; then
  fail "Gateway must map the browser API to v3, stamp its boundary, and scrub that marker from mobile routes"
fi

if ! search_q 'name:[[:space:]]*chronicle-apk-download' "$K8S_DIR/base/apk-download.yaml" ||
   ! search_q 'nginx:1\.29\.4-alpine@sha256:' "$K8S_DIR/base/apk-download.yaml" ||
   ! search_q 'readOnlyRootFilesystem:[[:space:]]*true' "$K8S_DIR/base/apk-download.yaml" ||
   ! search_q 'claimName:[[:space:]]*chronicle-apk-downloads' "$K8S_DIR/base/apk-download.yaml"; then
  fail "APK download service must be pinned, hardened, and backed by an artifact PVC"
fi

if ! search_q 'name:[[:space:]]*chronicle-preprocessing-frontend' "$K8S_DIR/base/preprocessing-frontend.yaml" ||
   ! search_q 'nginx:1\.29\.4-alpine@sha256:' "$K8S_DIR/base/preprocessing-frontend.yaml" ||
   ! search_q 'readOnlyRootFilesystem:[[:space:]]*true' "$K8S_DIR/base/preprocessing-frontend.yaml" ||
   ! search_q 'claimName:[[:space:]]*chronicle-preprocessing-web-dist' "$K8S_DIR/base/preprocessing-frontend.yaml" ||
   ! search_q 'wasm-unsafe-eval' "$K8S_DIR/base/preprocessing-frontend/nginx.preprocessing.conf"; then
  fail "Preprocessing frontend must be pinned, hardened, PVC-backed, and keep the WASM CSP required by the browser app"
fi

if ! search_q 'location = /chronicle/downloads/Chronicle-2026-06-25-beta\.2-debug\.apk' "$K8S_DIR/base/apk-download/nginx.apk-download.conf" ||
   ! search_q 'location = /chronicle/downloads/Chronicle-2026-06-25-beta\.2-debug\.apk\.sha256' "$K8S_DIR/base/apk-download/nginx.apk-download.conf" ||
   ! search_q 'location /' "$K8S_DIR/base/apk-download/nginx.apk-download.conf" ||
   ! search_q 'return 404' "$K8S_DIR/base/apk-download/nginx.apk-download.conf"; then
  fail "APK download nginx config must serve only exact APK/checksum paths and 404 everything else"
fi

if ! search_q 'name:[[:space:]]*keycloak' "$K8S_DIR/base/keycloak.yaml" ||
   ! search_q 'ghcr\.io/uzaira0/chronicle/chronicle-keycloak:sha-' "$K8S_DIR/base/keycloak.yaml" ||
   ! search_q 'postgres:18\.6-alpine@sha256:' "$K8S_DIR/base/keycloak.yaml" ||
   ! search_q 'readOnlyRootFilesystem:[[:space:]]*true' "$K8S_DIR/base/keycloak.yaml"; then
  fail "Keycloak must be rendered with pinned images and restricted writable paths"
fi

if ! search_q 'FROM[[:space:]]+quay\.io/keycloak/keycloak:26\.7\.3@sha256:' "$ROOT_DIR/docker/Dockerfile.keycloak" ||
   ! search_q 'kc\.sh build' "$ROOT_DIR/docker/Dockerfile.keycloak" ||
   ! search_q 'health-enabled=true' "$ROOT_DIR/docker/Dockerfile.keycloak" ||
   ! search_q 'metrics-enabled=true' "$ROOT_DIR/docker/Dockerfile.keycloak"; then
  fail "Chronicle Keycloak image must be built from the pinned upstream image with health and metrics enabled"
fi

if ! search_q 'name:[[:space:]]*grafana' "$K8S_DIR/observability/grafana-lite/grafana.yaml" ||
   ! search_q 'maxSurge:[[:space:]]*0' "$K8S_DIR/observability/grafana-lite/grafana.yaml" ||
   ! search_q 'maxUnavailable:[[:space:]]*1' "$K8S_DIR/observability/grafana-lite/grafana.yaml"; then
  fail "Grafana must use zero-surge rollout strategy so tight single-node observability quotas do not block updates"
fi

if ! search_q 'metadata:[[:space:]]*$' "$K8S_DIR/base/external-secrets.yaml" ||
   ! search_q 'name:[[:space:]]*keycloak' "$K8S_DIR/base/external-secrets.yaml" ||
   ! search_q 'name:[[:space:]]*keycloak-ingress' "$K8S_DIR/base/networkpolicies.yaml" ||
   ! search_q 'name:[[:space:]]*keycloak-egress' "$K8S_DIR/base/networkpolicies.yaml" ||
   ! search_q 'name:[[:space:]]*keycloak-postgres-ingress' "$K8S_DIR/base/networkpolicies.yaml"; then
  fail "Keycloak must source secrets through ExternalSecret and use explicit NetworkPolicies"
fi

if ! search_q 'value:[[:space:]]*/keycloak$' "$K8S_DIR/base/gateway.yaml" ||
   ! search_q 'value:[[:space:]]*/keycloak/' "$K8S_DIR/base/gateway.yaml" ||
   ! search_q 'value:[[:space:]]*/keycloak/admin' "$K8S_DIR/base/gateway.yaml" ||
   ! search_q 'value:[[:space:]]*/keycloak/health' "$K8S_DIR/base/gateway.yaml" ||
   ! search_q 'value:[[:space:]]*/keycloak/metrics' "$K8S_DIR/base/gateway.yaml" ||
   ! search_q 'blocked-route-not-found' "$K8S_DIR/base/gateway.yaml"; then
  fail "Base Gateway must avoid exposing Keycloak admin, health, or metrics paths publicly"
fi

if ! search_q 'value:[[:space:]]*/chronicle/preprocessing-gui' "$K8S_DIR/base/gateway.yaml" ||
   ! search_q 'value:[[:space:]]*/chronicle/preprocessing-gui/' "$K8S_DIR/base/gateway.yaml" ||
   ! search_q 'chronicle-preprocessing-frontend' "$K8S_DIR/base/networkpolicies.yaml"; then
  fail "Base Gateway and NetworkPolicies must route preprocessing GUI explicitly instead of relying on frontend fallback"
fi

if ! search_q 'pod-security.kubernetes.io/enforce:[[:space:]]*restricted' "$K8S_DIR/security/crowdsec-baseline/namespace.yaml" ||
   ! search_q 'name:[[:space:]]*default-deny' "$K8S_DIR/security/crowdsec-baseline/networkpolicies.yaml" ||
   ! search_q 'name:[[:space:]]*allow-traefik-to-crowdsec' "$K8S_DIR/security/crowdsec-baseline/networkpolicies.yaml" ||
   ! search_q '../crowdsec-baseline' "$K8S_DIR/security/crowdsec/kustomization.yaml" ||
   ! search_q 'name:[[:space:]]*chronicle-crowdsec' "$K8S_DIR/security/crowdsec/crowdsec.yaml" ||
   ! search_q 'crowdsecurity/crowdsec:v1\.7\.8@sha256:' "$K8S_DIR/security/crowdsec/crowdsec.yaml" ||
   ! search_q 'readOnlyRootFilesystem:[[:space:]]*true' "$K8S_DIR/security/crowdsec/crowdsec.yaml" ||
   ! search_q 'DISABLE_ONLINE_API' "$K8S_DIR/security/crowdsec/crowdsec.yaml" ||
   ! search_q 'value:[[:space:]]*"true"' "$K8S_DIR/security/crowdsec/crowdsec.yaml" ||
   ! search_q 'BOUNCER_KEY_traefik' "$K8S_DIR/security/crowdsec/crowdsec.yaml" ||
   ! search_q 'kind:[[:space:]]*ExternalSecret' "$K8S_DIR/security/crowdsec/external-secrets.yaml" ||
   ! search_q 'bouncer_api_key' "$K8S_DIR/security/crowdsec/external-secrets.yaml"; then
  fail "CrowdSec Kubernetes package must be pinned, restricted, offline, ExternalSecret-backed, and reachable only from the edge"
fi

if ! search_q 'abortOnPluginFailure:[[:space:]]*true' "$K8S_DIR/security/crowdsec/traefik-values/rke2-traefik-crowdsec-values.yaml" ||
   ! search_q 'localPlugins:' "$K8S_DIR/security/crowdsec/traefik-values/rke2-traefik-crowdsec-values.yaml" ||
   ! search_q 'crowdsec-bouncer' "$K8S_DIR/security/crowdsec/traefik-values/rke2-traefik-crowdsec-values.yaml" ||
   ! search_q 'access.log' "$K8S_DIR/security/crowdsec/traefik-values/rke2-traefik-crowdsec-values.yaml"; then
  fail "CrowdSec edge enforcement must document fail-closed Traefik plugin and access-log settings"
fi

render_overlay() {
  local overlay="$1"
  local output="$REPORT_DIR/kustomize-${overlay}.yaml"
  if [ -n "$KUBECTL_BIN" ]; then
    "$KUBECTL_BIN" kustomize "$K8S_DIR/overlays/$overlay" > "$output"
  elif [ -n "$KUSTOMIZE_BIN" ]; then
    "$KUSTOMIZE_BIN" build "$K8S_DIR/overlays/$overlay" > "$output"
  else
    fail "neither kustomize nor kubectl is available for Kubernetes render validation"
  fi
}

for overlay in production rhel9-small; do
  render_overlay "$overlay"
  rendered="$REPORT_DIR/kustomize-${overlay}.yaml"
  [ -f "$rendered" ] || continue
  if search_n 'kind:[[:space:]]*Secret|^[[:space:]]*stringData:|image:[[:space:]].*:latest($|[^[:alnum:]_.-])|allowPrivilegeEscalation:[[:space:]]*true|automountServiceAccountToken:[[:space:]]*true' "$rendered"; then
    fail "Rendered Kubernetes overlay '$overlay' violates production guardrails"
  fi
  python3 - "$rendered" "$overlay" <<'PY'
import sys

import yaml

rendered_path, overlay = sys.argv[1], sys.argv[2]
documents = [
    document
    for document in yaml.safe_load_all(open(rendered_path, encoding="utf-8"))
    if isinstance(document, dict)
]
backends = [
    document
    for document in documents
    if document.get("kind") == "Deployment"
    and document.get("metadata", {}).get("name") == "chronicle-backend"
]
if len(backends) != 1:
    raise SystemExit(f"{overlay}: expected exactly one chronicle-backend Deployment")
backend = backends[0]
if backend.get("spec", {}).get("replicas") != 1:
    raise SystemExit(f"{overlay}: chronicle-backend replicas must be exactly 1")
strategy = backend.get("spec", {}).get("strategy", {})
if strategy.get("type") != "Recreate" or "rollingUpdate" in strategy:
    raise SystemExit(f"{overlay}: chronicle-backend strategy must be Recreate")

pod_spec = backend["spec"]["template"]["spec"]
container = next(item for item in pod_spec["containers"] if item.get("name") == "backend")
environment = {item["name"]: item.get("value") for item in container.get("env", [])}
expected_export_environment = {
    "CHRONICLE_EXPORT_DIR": "/var/lib/chronicle/exports",
    "CHRONICLE_EXPORT_MAX_ROWS": "1000000",
    "CHRONICLE_EXPORT_MAX_BYTES": "536870912",
    "CHRONICLE_EXPORT_MAX_RUNTIME_SECONDS": "1800",
    "CHRONICLE_EXPORT_MAX_TOTAL_BYTES": "8589934592",
    "CHRONICLE_EXPORT_MIN_FREE_BYTES": "1073741824",
}
for name, expected in expected_export_environment.items():
    if environment.get(name) != expected:
        raise SystemExit(f"{overlay}: backend {name} must be {expected}")

mounts = {item["name"]: item for item in container.get("volumeMounts", [])}
export_mount = mounts.get("export-artifacts")
if (
    export_mount is None
    or export_mount.get("mountPath") != "/var/lib/chronicle/exports"
    or export_mount.get("readOnly", False)
):
    raise SystemExit(f"{overlay}: backend exports must use a writable persistent mount")

volumes = {item["name"]: item for item in pod_spec.get("volumes", [])}
if (
    volumes.get("export-artifacts", {})
    .get("persistentVolumeClaim", {})
    .get("claimName")
    != "chronicle-export-artifacts"
):
    raise SystemExit(f"{overlay}: backend export volume must use chronicle-export-artifacts")

export_pvcs = [
    document
    for document in documents
    if document.get("kind") == "PersistentVolumeClaim"
    and document.get("metadata", {}).get("name") == "chronicle-export-artifacts"
]
if len(export_pvcs) != 1:
    raise SystemExit(f"{overlay}: expected exactly one export artifacts PVC")
for document in documents:
    if document.get("kind") != "HorizontalPodAutoscaler":
        continue
    target = document.get("spec", {}).get("scaleTargetRef", {})
    if target.get("kind") == "Deployment" and target.get("name") == "chronicle-backend":
        raise SystemExit(f"{overlay}: chronicle-backend must not have an HPA")
PY
done

if [ -n "$KUBECTL_BIN" ]; then
  "$KUBECTL_BIN" kustomize "$K8S_DIR/security/crowdsec" > "$REPORT_DIR/kustomize-crowdsec.yaml"
elif [ -n "$KUSTOMIZE_BIN" ]; then
  "$KUSTOMIZE_BIN" build "$K8S_DIR/security/crowdsec" > "$REPORT_DIR/kustomize-crowdsec.yaml"
fi

if [ -f "$REPORT_DIR/kustomize-crowdsec.yaml" ]; then
  rendered="$REPORT_DIR/kustomize-crowdsec.yaml"
  if search_n 'kind:[[:space:]]*Secret|^[[:space:]]*stringData:|image:[[:space:]].*:latest($|[^[:alnum:]_.-])|allowPrivilegeEscalation:[[:space:]]*true|automountServiceAccountToken:[[:space:]]*true' "$rendered"; then
    fail "Rendered CrowdSec package violates production guardrails"
  fi
  if ! search_q 'namespace:[[:space:]]*chronicle-security' "$rendered" ||
     ! search_q 'name:[[:space:]]*chronicle-crowdsec' "$rendered" ||
     ! search_q 'port:[[:space:]]*7422' "$rendered" ||
     ! search_q 'port:[[:space:]]*8080' "$rendered" ||
     ! search_q 'claimName:[[:space:]]*chronicle-crowdsec-data' "$rendered" ||
     ! search_q 'claimName:[[:space:]]*chronicle-traefik-access-logs' "$rendered"; then
    fail "Rendered CrowdSec package must expose only LAPI/AppSec and mount config/data/access-log volumes"
  fi
fi

if [ -n "$KUBECTL_BIN" ]; then
  "$KUBECTL_BIN" kustomize "$K8S_DIR/backup/offhost" > "$REPORT_DIR/kustomize-backup-offhost.yaml"
elif [ -n "$KUSTOMIZE_BIN" ]; then
  "$KUSTOMIZE_BIN" build "$K8S_DIR/backup/offhost" > "$REPORT_DIR/kustomize-backup-offhost.yaml"
fi

if [ -f "$REPORT_DIR/kustomize-backup-offhost.yaml" ]; then
  rendered="$REPORT_DIR/kustomize-backup-offhost.yaml"
  if search_n 'kind:[[:space:]]*Secret|^[[:space:]]*stringData:|image:[[:space:]].*:latest($|[^[:alnum:]_.-])|allowPrivilegeEscalation:[[:space:]]*true|automountServiceAccountToken:[[:space:]]*true' "$rendered"; then
    fail "Rendered off-host backup package violates production guardrails"
  fi
  if ! search_q 'name:[[:space:]]*chronicle-offhost-backups' "$rendered" ||
     ! search_q 'storageClassName:[[:space:]]*chronicle-offhost-backup' "$rendered" ||
     ! search_q 'name:[[:space:]]*chronicle-offhost-backup-export' "$rendered" ||
     ! search_q 'suspend:[[:space:]]*true' "$rendered"; then
    fail "Off-host backup package must render the approved target PVC and suspended export CronJob"
  fi
  if ! search_q 'claimName:[[:space:]]*chronicle-local-backups' "$rendered" ||
     ! search_q 'claimName:[[:space:]]*chronicle-offhost-backups' "$rendered" ||
     ! search_q 'readOnly:[[:space:]]*true' "$rendered"; then
    fail "Off-host backup export must read local backups read-only and write only to the off-host PVC"
  fi
  if ! search_q 'OFFHOST_BACKUP_TARGET_NAME' "$rendered" ||
     ! search_q 'OFFHOST_BACKUP_TARGET_NAME must identify an approved operator target' "$rendered" ||
     ! search_q 'sha256sum -c manifest\.json\.sha256' "$rendered" ||
     ! search_q 'sha256sum -c artifact-sha256sums\.txt' "$rendered" ||
     ! search_q 'manifest-declared artifact is not allowed for off-host export' "$rendered" ||
     ! search_q 'offhost-export-receipt\.json\.sha256' "$rendered"; then
    fail "Off-host backup export must validate freshness, checksums, encrypted-only artifacts, and receipt integrity"
  fi
fi

if [ -f "$REPORT_DIR/kustomize-production.yaml" ]; then
  rendered="$REPORT_DIR/kustomize-production.yaml"
  if ! search_q 'name:[[:space:]]*chronicle-apk-download' "$rendered" ||
     ! search_q 'type:[[:space:]]*Exact' "$rendered" ||
     ! search_q 'Chronicle-2026-06-25-beta\.2-debug\.apk' "$rendered" ||
     ! search_q 'name:[[:space:]]*chronicle-apk-downloads' "$rendered"; then
    fail "Production overlay must include exact-match APK download service and artifact PVC"
  fi
fi

if [ -f "$REPORT_DIR/kustomize-rhel9-small.yaml" ]; then
  python3 - "$REPORT_DIR/kustomize-rhel9-small.yaml" <<'PY'
import re
import sys

rendered = open(sys.argv[1], encoding="utf-8").read()

checks = {
    "backend heap capped at -Xmx2g": r"name:\s*CHRONICLE_SERVER_XMX\s*\n\s*value:\s*-Xmx2g\b",
    "backend replica count is one": r"kind:\s*Deployment\s+metadata:\s+(?:.*\n)*?\s*name:\s*chronicle-backend\s+(?:.*\n)*?spec:\s+(?:.*\n)*?\s*replicas:\s*1\b",
    "frontend replica count is one": r"kind:\s*Deployment\s+metadata:\s+(?:.*\n)*?\s*name:\s*chronicle-frontend\s+(?:.*\n)*?spec:\s+(?:.*\n)*?\s*replicas:\s*1\b",
}

missing = [name for name, pattern in checks.items() if not re.search(pattern, rendered)]
if missing:
    raise SystemExit("RHEL 9 small overlay missing: " + ", ".join(missing))
PY
fi

echo "Kubernetes guardrails complete"
