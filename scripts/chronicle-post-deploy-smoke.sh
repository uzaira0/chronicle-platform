#!/usr/bin/env bash
# Portable post-deploy smoke checks for operator-managed Chronicle targets.
set -euo pipefail

BASE_URL="${CHRONICLE_BASE_URL:-}"
KUBE_NAMESPACE="${CHRONICLE_KUBE_NAMESPACE:-chronicle}"
KUBECTL_BIN="${KUBECTL_BIN:-kubectl}"
CURL_INSECURE="${CHRONICLE_SMOKE_INSECURE:-0}"
TIMEOUT_SECONDS="${CHRONICLE_SMOKE_TIMEOUT_SECONDS:-10}"
RUN_KUBE="${CHRONICLE_SMOKE_KUBE:-auto}"

pass_count=0
fail_count=0
skip_count=0

usage() {
  cat <<'EOF'
Usage: CHRONICLE_BASE_URL=https://host scripts/chronicle-post-deploy-smoke.sh

Options:
  --base-url URL      Public base URL to test.
  --namespace NAME    Kubernetes namespace, default: chronicle.
  --kube             Require Kubernetes rollout checks.
  --no-kube          Skip Kubernetes rollout checks.
  --insecure         Pass -k to curl for temporary rehearsal/self-signed TLS.

Environment:
  CHRONICLE_BASE_URL
  CHRONICLE_KUBE_NAMESPACE=chronicle
  CHRONICLE_SMOKE_KUBE=auto|1|0
  CHRONICLE_SMOKE_INSECURE=0|1
  CHRONICLE_SMOKE_TIMEOUT_SECONDS=10

The script does not print secrets and does not require authenticated requests.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --base-url)
      BASE_URL="${2:?--base-url requires a value}"
      shift 2
      ;;
    --namespace)
      KUBE_NAMESPACE="${2:?--namespace requires a value}"
      shift 2
      ;;
    --kube)
      RUN_KUBE="1"
      shift
      ;;
    --no-kube)
      RUN_KUBE="0"
      shift
      ;;
    --insecure)
      CURL_INSECURE="1"
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [[ -z "$BASE_URL" ]]; then
  echo "CHRONICLE_BASE_URL or --base-url is required" >&2
  usage >&2
  exit 2
fi

BASE_URL="${BASE_URL%/}"

curl_args=(--silent --show-error --location --max-time "$TIMEOUT_SECONDS" --output /dev/null)
if [[ "$CURL_INSECURE" == "1" ]]; then
  curl_args+=(--insecure)
fi

pass() {
  pass_count=$((pass_count + 1))
  printf 'PASS %-36s %s\n' "$1" "$2"
}

fail() {
  fail_count=$((fail_count + 1))
  printf 'FAIL %-36s %s\n' "$1" "$2"
}

skip() {
  skip_count=$((skip_count + 1))
  printf 'SKIP %-36s %s\n' "$1" "$2"
}

check_status() {
  local label="$1"
  local path="$2"
  local allowed="$3"
  local url="${BASE_URL}${path}"
  local status
  status="$(curl "${curl_args[@]}" --write-out '%{http_code}' "$url" 2>/dev/null || true)"
  if [[ ",$allowed," == *",$status,"* ]]; then
    pass "$label" "${path} -> HTTP ${status}"
  else
    fail "$label" "${path} -> HTTP ${status:-curl_failed}; expected one of ${allowed}"
  fi
}

check_prometheus_not_exposed() {
  local path="/prometheus/"
  local url="${BASE_URL}${path}"
  local body_file headers status content_type
  local body_args=(--silent --show-error --location --max-time "$TIMEOUT_SECONDS")
  if [[ "$CURL_INSECURE" == "1" ]]; then
    body_args+=(--insecure)
  fi
  body_file="$(mktemp)"
  headers="$(curl "${body_args[@]}" --dump-header - --output "$body_file" --write-out $'\n%{http_code}' "$url" 2>/dev/null || true)"
  status="$(printf '%s\n' "$headers" | tail -n 1)"
  content_type="$(printf '%s\n' "$headers" | awk 'BEGIN{IGNORECASE=1} /^content-type:/ {print $0}' | tail -n 1)"

  if [[ ",401,403,404,429," == *",$status,"* ]]; then
    rm -f "$body_file"
    pass "prometheus route not exposed" "${path} -> HTTP ${status}"
    return
  fi

  if grep -Eq '^(# HELP|# TYPE)[[:space:]]|^jvm_|^http_server_requests_' "$body_file" ||
    printf '%s\n' "$content_type" | grep -Ei 'text/plain|openmetrics|prometheus' >/dev/null; then
    rm -f "$body_file"
    fail "prometheus route not exposed" "${path} returned metrics-looking content"
    return
  fi

  if [[ "$status" == "200" ]] && printf '%s\n' "$content_type" | grep -Ei 'text/html' >/dev/null; then
    rm -f "$body_file"
    pass "prometheus route not exposed" "${path} -> frontend fallback HTML"
    return
  fi

  rm -f "$body_file"
  fail "prometheus route not exposed" "${path} -> HTTP ${status:-curl_failed}; unexpected content type ${content_type:-unknown}"
}

check_header() {
  local label="$1"
  local path="$2"
  local pattern="$3"
  local url="${BASE_URL}${path}"
  local headers
  local header_args=(--silent --show-error --location --max-time "$TIMEOUT_SECONDS" --dump-header - --output /dev/null)
  if [[ "$CURL_INSECURE" == "1" ]]; then
    header_args+=(--insecure)
  fi
  headers="$(curl "${header_args[@]}" "$url" 2>/dev/null || true)"
  if printf '%s\n' "$headers" | grep -Ei "$pattern" >/dev/null; then
    pass "$label" "${path} header matched ${pattern}"
  else
    fail "$label" "${path} header missing ${pattern}"
  fi
}

check_body_absent() {
  local label="$1"
  local path="$2"
  local pattern="$3"
  local url="${BASE_URL}${path}"
  local body_file status
  local body_args=(--silent --show-error --location --max-time "$TIMEOUT_SECONDS")
  if [[ "$CURL_INSECURE" == "1" ]]; then
    body_args+=(--insecure)
  fi
  body_file="$(mktemp)"
  status="$(curl "${body_args[@]}" --output "$body_file" --write-out '%{http_code}' "$url" 2>/dev/null || true)"
  if grep -Eiq "$pattern" "$body_file"; then
    rm -f "$body_file"
    fail "$label" "${path} leaked sensitive/internal response content"
    return
  fi
  rm -f "$body_file"
  pass "$label" "${path} -> HTTP ${status:-curl_failed}; no sensitive/internal body markers"
}

printf 'Chronicle post-deploy smoke: %s\n' "$BASE_URL"

check_status "backend auth/session reachable" "/chronicle/v3/auth/session" "200,401,403,429"
check_status "blocked keycloak admin route" "/keycloak/admin" "403,404,429"
check_prometheus_not_exposed
check_body_absent "auth/session body redacted" "/chronicle/v3/auth/session" 'stack[ _-]?trace|org\.springframework|java\.[a-z]|kotlin\.[a-z]|Exception[":[:space:]]|password[":=]|token[":=]|api[_-]?key[":=]|authorization[":=]|Bearer[[:space:]]+|participantId|participant_id|sourceDevice|source_device|randomDeviceId|random_device_id|MOBILE_SIGNING_SECRET|PGPASSWORD'
check_body_absent "keycloak/admin body redacted" "/keycloak/admin" 'stack[ _-]?trace|org\.springframework|java\.[a-z]|kotlin\.[a-z]|Exception[":[:space:]]|password[":=]|token[":=]|api[_-]?key[":=]|authorization[":=]|Bearer[[:space:]]+|participantId|participant_id|sourceDevice|source_device|randomDeviceId|random_device_id|MOBILE_SIGNING_SECRET|PGPASSWORD'
check_header "security nosniff header" "/chronicle/v3/auth/session" 'x-content-type-options:[[:space:]]*nosniff'
check_header "security frame deny header" "/chronicle/v3/auth/session" 'x-frame-options:[[:space:]]*deny'
check_header "security referrer policy" "/chronicle/v3/auth/session" 'referrer-policy:[[:space:]]*no-referrer'
check_header "security permissions policy" "/chronicle/v3/auth/session" 'permissions-policy:.*camera=\(\).*microphone=\(\)'
check_header "security hsts header" "/chronicle/v3/auth/session" 'strict-transport-security:[[:space:]]*max-age=31536000'

if [[ "$RUN_KUBE" == "0" ]]; then
  skip "kubernetes checks" "disabled"
elif ! command -v "$KUBECTL_BIN" >/dev/null 2>&1; then
  if [[ "$RUN_KUBE" == "1" ]]; then
    fail "kubernetes checks" "$KUBECTL_BIN not found"
  else
    skip "kubernetes checks" "$KUBECTL_BIN not found"
  fi
else
  for workload in deploy/chronicle-backend deploy/chronicle-frontend statefulset/postgres; do
    if "$KUBECTL_BIN" -n "$KUBE_NAMESPACE" rollout status "$workload" --timeout=60s >/dev/null 2>&1; then
      pass "kubernetes rollout" "$workload ready"
    else
      fail "kubernetes rollout" "$workload not ready"
    fi
  done

  if "$KUBECTL_BIN" -n "$KUBE_NAMESPACE" get pods --no-headers 2>/dev/null |
    awk '$3 !~ /^(Running|Succeeded|Completed)$/ { bad=1 } END { exit bad ? 1 : 0 }'; then
    pass "kubernetes pod states" "all pods Running/Succeeded"
  else
    fail "kubernetes pod states" "one or more pods are not healthy"
  fi
fi

printf 'Result: %s pass, %s fail, %s skip\n' "$pass_count" "$fail_count" "$skip_count"
if [[ "$fail_count" -gt 0 ]]; then
  exit 1
fi
