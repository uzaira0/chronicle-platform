#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
SELFHOST_ROOT="${SELFHOST_MATRIX_ROOT:-${ROOT_DIR}/selfhost}"
# shellcheck source=selfhost/network-policy.sh
source "$SELFHOST_ROOT/network-policy.sh"
local_proxy_sources="$(trusted_proxy_sources own-tls '' '' '')"
RUN_PARENT="${SELFHOST_MATRIX_TEST_ROOT:-${ROOT_DIR}/build/operator-test-runs/selfhost-matrix}"
DOC="${SELFHOST_ROOT}/docs/DEPLOYMENT-COMPATIBILITY.md"

fail() {
  echo "self-host combination matrix failed: $*" >&2
  exit 1
}

[[ "$SELFHOST_ROOT" == /* ]] || fail "SELFHOST_MATRIX_ROOT must be absolute"
[[ "$RUN_PARENT" == /* ]] || fail "test run parent must be absolute"
case "$RUN_PARENT" in
  /tmp|/tmp/*|/private/tmp|/private/tmp/*|/var/folders|/var/folders/*)
    fail "test run parent must not use a system temporary directory"
    ;;
esac
[[ -f "$DOC" ]] || fail "deployment compatibility document is missing"
[[ -x "${SELFHOST_ROOT}/guard-config.sh" ]] || fail "configuration guard is missing or not executable"
command -v docker >/dev/null 2>&1 || fail "docker is required"
command -v python3 >/dev/null 2>&1 || fail "python3 is required"
docker compose version >/dev/null 2>&1 || fail "Docker Compose plugin is required"

if command -v gtimeout >/dev/null 2>&1; then
  TIMEOUT=(gtimeout)
elif command -v timeout >/dev/null 2>&1; then
  TIMEOUT=(timeout)
else
  fail "GNU timeout or gtimeout is required for bounded Compose rendering"
fi

mapfile -t supported_modes < <(
  find "${SELFHOST_ROOT}/overlays" -maxdepth 1 -type f -name 'mode-*.yml' -exec basename {} \; | LC_ALL=C sort
)
expected_modes=$'mode-behind-proxy-internal.yml\nmode-local-https.yml\nmode-own-tls-internal.yml'
[[ "$(printf '%s\n' "${supported_modes[@]}")" == "$expected_modes" ]] ||
  fail "overlays/ must contain exactly the three documented supported modes"

# profile-id | mode-overlay | encryption | backups
profiles=(
  'proxy-encrypted|mode-behind-proxy-internal.yml|true|true'
  'proxy-plain|mode-behind-proxy-internal.yml|false|true'
  'tls-encrypted|mode-own-tls-internal.yml|true|true'
  'tls-plain|mode-own-tls-internal.yml|false|true'
  'trial-encrypted|mode-local-https.yml|true|true'
  'trial-plain-backed-up|mode-local-https.yml|false|true'
  'trial-plain-no-backup|mode-local-https.yml|false|false'
)

for profile in "${profiles[@]}"; do
  profile_id="${profile%%|*}"
  grep -Fq "\`${profile_id}\`" "$DOC" || fail "documentation omits profile ${profile_id}"
done

umask 077
/bin/mkdir -p "$RUN_PARENT"
RUN_DIR="$(/usr/bin/mktemp -d "${RUN_PARENT}/run.XXXXXX")"
trap '/bin/rm -rf -- "$RUN_DIR"' EXIT

DEPLOYMENT="${RUN_DIR}/deployment"
/bin/mkdir -p "${DEPLOYMENT}/overlays"
/bin/cp "${SELFHOST_ROOT}/docker-compose.yml" "${DEPLOYMENT}/docker-compose.yml"
/bin/cp -R "${SELFHOST_ROOT}/config" "${DEPLOYMENT}/config"
for mode in "${supported_modes[@]}"; do
  /bin/cp "${SELFHOST_ROOT}/overlays/${mode}" "${DEPLOYMENT}/overlays/${mode}"
done
/bin/cp "${SELFHOST_ROOT}/overlays/backups.yml" "${DEPLOYMENT}/overlays/backups.yml"
/bin/cp "${SELFHOST_ROOT}/overlays/monitoring.yml" "${DEPLOYMENT}/overlays/monitoring.yml"
# monitoring.yml extends Grafana's network fragment from here (CHRONICLE_ALERT_EGRESS).
/bin/mkdir -p "${DEPLOYMENT}/monitoring"
/bin/cp "${SELFHOST_ROOT}"/monitoring/docker-compose.grafana-alerts-*.yml "${DEPLOYMENT}/monitoring/"

render_env() {
  local output="$1" compose_file="$2" encryption="$3" state_dir="$4" project="$5"
  PYTHONPATH="$ROOT_DIR/selfhost" python3 -s - "$SELFHOST_ROOT/.env.example" "$output" "$compose_file" "$encryption" \
    "$state_dir" "$project" "$local_proxy_sources" <<'PY'
from pathlib import Path
import os
import sys
from chronicle_ops.credentials import POSTGRES, POSTGRES_APP
from chronicle_ops.envfile import parse_env_text, set_env_values, value
from chronicle_ops.images import SOURCE_IMAGES

source, output, compose_file, encryption, state_dir, project, local_proxy = sys.argv[1:]
text = Path(source).read_text(encoding="utf-8")
values = {
    # The trial mode must be addressed by a LAN address; production modes by a public name.
    "DOMAIN": "192.168.1.50" if "mode-local-https.yml" in compose_file else "study.research-matrix.org",
    "COMPOSE_PROJECT_NAME": project,
    "CHRONICLE_STATE_DIR": state_dir,
    "COMPOSE_FILE": compose_file,
    # Setup writes the core network's prefix (network-subnet.py select-core); the matrix picks one.
    "CHRONICLE_CORE_PREFIX": "10.252.9",
    "ENABLE_ENCRYPTION": encryption,
    "HTTP_BIND": "127.0.0.1",
    "INTERNAL_BIND": "127.0.0.1",
    "DASHBOARD_PASSWORD_HASH": "$2b$12$aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "POSTGRES_PASSWORD": "matrix-postgres-password-not-a-secret",
    "JWT_SECRET": "matrix-jwt-signing-key-not-a-secret-123456789",
    "CHRONICLE_INTERNAL_WEB_SECRET": "matrix-internal-web-key-not-a-secret-123456",
    "TESTING_LOGIN_ENABLED": "false",
    "REQUIRE_MFA": "false",
    "METRICS_PASSWORD": "matrix-metrics-password-not-a-secret-1234567",
    "GRAFANA_ADMIN_PASSWORD": "matrix-grafana-password-not-a-secret-1234567",
    # Setup records the operator's retention; the matrix keeps everything and chooses no number.
    **dict.fromkeys(("BACKUP_KEEP_DAYS", "BACKUP_KEEP_WEEKS", "BACKUP_KEEP_MONTHS", "PRE_OP_BACKUP_KEEP_DAYS"), "all"),
}
values[POSTGRES_APP.env_key] = values[POSTGRES.env_key]
values['CADDY_TRUSTED_PROXIES'] = value(parse_env_text(text), 'CADDY_TRUSTED_PROXIES')
if 'mode-behind-proxy-internal.yml' not in compose_file:
    values['CADDY_TRUSTED_PROXIES'] = local_proxy
values.update({image.variable: f'ghcr.io/example/{image.component}@sha256:{index:064x}'
               for index, image in enumerate(SOURCE_IMAGES, 1)})
text = set_env_values(text, values, require_existing=True)
text = set_env_values(text, {"CHRONICLE_HOST_UID": str(os.getuid()), "CHRONICLE_HOST_GID": str(os.getgid())}, require_existing=False)
Path(output).write_text(text, encoding="utf-8")
PY
  chmod 600 "$output"
}

validate_render() {
  local config_json="$1" mode="$2" encryption="$3" backups="$4" monitoring="$5" tls_dir="$6"
  PYTHONPATH="$ROOT_DIR/selfhost" python3 -s - "$config_json" "$mode" "$encryption" "$backups" "$monitoring" \
    "$SELFHOST_ROOT/guard-config.sh" "$tls_dir" <<'PY'
import json
import os
from pathlib import Path
import subprocess
import sys
from chronicle_ops.common import application_services

config_path, mode, encryption, backups_text, monitoring_text, guard, tls_dir = sys.argv[1:]
backups = backups_text == "true"
monitoring = monitoring_text == "true"
config = json.loads(Path(config_path).read_text(encoding="utf-8"))
services = config.get("services", {})

expected = set(application_services([])) | {"config-guard", "cert-init", "caddy-storage-init", "secrets-init", "postgres", "web-forward"}
if mode == "mode-local-https.yml":
    expected.add("ca-export")
if backups:
    expected.add("db-backup")
if monitoring:
    expected.update({"monitoring-config", "monitoring-cert-init", "health-probe", "docker-socket-proxy", "cadvisor", "operational-probe", "public-probe",
                     "metrics-exporter", "victoriametrics", "victorialogs", "fluent-bit", "grafana", "monitoring-forward", "egress-proxy"})
if set(services) != expected:
    raise SystemExit(f"service set mismatch: expected {sorted(expected)}, got {sorted(services)}")
if any("build" in service for service in services.values()):
    raise SystemExit("rendered service contains a local build definition")
for name, service in services.items():
    image = service.get("image")
    if image and "@sha256:" not in image:
        raise SystemExit(f"{name} image is not digest pinned: {image}")

guard_environment = {key: str(value) for key, value in services["config-guard"].get("environment", {}).items()}
# `docker compose config` preserves a literal dollar as `$$`; the container receives one
# dollar when Compose launches it. Reproduce that final interpolation for the direct guard
# execution below.
guard_environment["DASHBOARD_PASSWORD_HASH"] = guard_environment.get("DASHBOARD_PASSWORD_HASH", "").replace("$$", "$")
expected_tls = "local-https" if mode == "mode-local-https.yml" else (
    "own-tls" if mode == "mode-own-tls-internal.yml" else "behind-proxy"
)
expected_guard = {
    "TLS_MODE": expected_tls,
    "DASHBOARD_EXPOSURE": "internal",
    "ENABLE_ENCRYPTION": encryption,
    "BACKUPS_ENABLED": backups_text,
    "MONITORING_ENABLED": monitoring_text,
    "TESTING_LOGIN_ENABLED": "false",
    "REQUIRE_MFA": "false",
}
for key, value in expected_guard.items():
    if guard_environment.get(key) != value:
        raise SystemExit(f"config-guard {key}: expected {value!r}, got {guard_environment.get(key)!r}")

optional = {
    "db-backup": backups,
    "cadvisor": monitoring,
    "docker-socket-proxy": monitoring,
    "monitoring-config": monitoring,
    "monitoring-cert-init": monitoring,
    "operational-probe": monitoring,
    "metrics-exporter": monitoring,
    "victoriametrics": monitoring,
    "victorialogs": monitoring,
    "fluent-bit": monitoring,
    "grafana": monitoring,
    "ca-export": mode == "mode-local-https.yml",
}
for service, wanted in optional.items():
    if (service in services) != wanted:
        raise SystemExit(f"optional service {service} presence does not match matrix")
if any(name.startswith("keycloak") for name in services):
    raise SystemExit("experimental Keycloak service leaked into a supported render")

mounts = services["web"].get("volumes", [])
caddy_mount = next((item for item in mounts if item.get("target") == "/etc/caddy/Caddyfile"), None)
expected_caddy = {
    "mode-behind-proxy-internal.yml": "Caddyfile.split",
    "mode-own-tls-internal.yml": "Caddyfile.split.tls",
    "mode-local-https.yml": "Caddyfile.split.local",
}[mode]
if caddy_mount is None or Path(caddy_mount.get("source", "")).name != expected_caddy:
    raise SystemExit(f"web Caddyfile mismatch for {mode}")

# web publishes nothing: web-forward holds its ports (container 8443 -> web 443, 8880 -> web 80).
if services["web"].get("ports"):
    raise SystemExit("web publishes ports; web-forward must hold them (docs/NETWORK-EGRESS.md)")
targets = {int(item["target"]) for item in services["web-forward"].get("ports", [])}
# Behind a proxy the pool listener is :8080 (plain or POOL_LISTENER_TLS), not the redirect port.
expected_targets = {8080, 8081} if mode == "mode-behind-proxy-internal.yml" else {8880, 8443, 8081}
if targets != expected_targets:
    raise SystemExit(f"published target ports mismatch: expected {expected_targets}, got {targets}")

guard_environment["PATH"] = os.environ.get("PATH", "/usr/bin:/bin")
guard_environment["CHRONICLE_GUARD_TLS_DIR"] = tls_dir
# config-guard reads its credentials from the files secrets-init writes; run directly here, it
# takes the same values from secrets-init's rendered environment.
guard_environment.pop("CHRONICLE_SECRETS_DIR", None)
for key, value in services["secrets-init"].get("environment", {}).items():
    guard_environment.setdefault(key, str(value))
completed = subprocess.run(
    [guard],
    cwd=str(Path(guard).parent),
    env=guard_environment,
    text=True,
    stdout=subprocess.PIPE,
    stderr=subprocess.STDOUT,
    timeout=10,
    check=False,
)
if completed.returncode != 0:
    raise SystemExit("guard rejected supported render:\n" + completed.stdout)
PY
}

case_count=0
baseline_json=""
for profile in "${profiles[@]}"; do
  IFS='|' read -r profile_id mode encryption backups <<< "$profile"
  for monitoring in false true; do
    case_count=$((case_count + 1))
    case_name="${profile_id}-monitoring-${monitoring}"
    case_dir="${RUN_DIR}/${case_name}"
    state_dir="${case_dir}/state"
    /bin/mkdir -p "${state_dir}/tls"
    printf 'matrix certificate\n' > "${state_dir}/tls/cert.pem"
    printf 'matrix private key\n' > "${state_dir}/tls/key.pem"
    chmod 600 "${state_dir}/tls/key.pem"

    compose_file="docker-compose.yml:overlays/${mode}"
    [[ "$backups" == true ]] && compose_file+=":overlays/backups.yml"
    [[ "$monitoring" == true ]] && compose_file+=":overlays/monitoring.yml"
    env_file="${case_dir}/matrix.env"
    /bin/mkdir -p "$case_dir"
    render_env "$env_file" "$compose_file" "$encryption" "$state_dir" \
      "chronicle-matrix-${case_count}"
    config_json="${case_dir}/compose.json"
    (
      cd "$DEPLOYMENT"
      "${TIMEOUT[@]}" 30s docker compose --env-file "$env_file" config --format json > "$config_json"
    ) || fail "Compose did not render ${case_name}"
    validate_render "$config_json" "$mode" "$encryption" "$backups" "$monitoring" "${state_dir}/tls" ||
      fail "render contract failed for ${case_name}"
    [[ -n "$baseline_json" ]] || baseline_json="$config_json"
    echo "  ok   ${case_name}"
  done
done
[[ $case_count -eq 14 ]] || fail "expected 14 rendered combinations, got ${case_count}"

# Mutate one known-good guard environment to prove unsupported shapes fail closed. This
# covers conditions that cannot be represented by the supported Compose files themselves.
python3 - "$baseline_json" "$SELFHOST_ROOT/guard-config.sh" "${RUN_DIR}/negative-tls" "$local_proxy_sources" <<'PY'
import json
import os
from pathlib import Path
import subprocess
import sys

config_path, guard, tls_dir, local_proxy = sys.argv[1:]
Path(tls_dir).mkdir(parents=True, exist_ok=True)
(Path(tls_dir) / "cert.pem").write_text("fixture\n", encoding="utf-8")
(Path(tls_dir) / "key.pem").write_text("fixture\n", encoding="utf-8")
config = json.loads(Path(config_path).read_text(encoding="utf-8"))
base = {key: str(value) for key, value in config["services"]["config-guard"]["environment"].items()}
base["PATH"] = os.environ.get("PATH", "/usr/bin:/bin")
base["CHRONICLE_GUARD_TLS_DIR"] = tls_dir
base["DASHBOARD_PASSWORD_HASH"] = base.get("DASHBOARD_PASSWORD_HASH", "").replace("$$", "$")
base.pop("CHRONICLE_SECRETS_DIR", None)  # credentials as secrets-init would write them (above)
for key, value in config["services"]["secrets-init"].get("environment", {}).items():
    base.setdefault(key, str(value))

cases = [
    ("staff-ip-invalid", {"CHRONICLE_RECORD_STAFF_IP": "no"}, "CHRONICLE_RECORD_STAFF_IP must be exactly true or false"),
    ("mobile-abuse-oversized", {"RATE_LIMIT_MOBILE_ABUSE_EVENTS": "1000001"}, "RATE_LIMIT_MOBILE_ABUSE_EVENTS must be a decimal integer"),
    ("web-abuse-invalid", {"RATE_LIMIT_WEB_ABUSE_EVENTS": "no"}, "RATE_LIMIT_WEB_ABUSE_EVENTS must be a decimal integer"),
    ("guard-abuse-zero", {"RATE_LIMIT_GUARD_EVENTS": "0"}, "RATE_LIMIT_GUARD_EVENTS must be a decimal integer"),
    ("mobile-window-invalid", {"RATE_LIMIT_MOBILE_WINDOW": "forever"}, "RATE_LIMIT_MOBILE_WINDOW must be a positive Caddy duration"),
    ("web-window-zero", {"RATE_LIMIT_WEB_WINDOW": "0s"}, "RATE_LIMIT_WEB_WINDOW must be a positive Caddy duration"),
    ("guard-window-invalid", {"RATE_LIMIT_GUARD_WINDOW": "-1s"}, "RATE_LIMIT_GUARD_WINDOW must be a positive Caddy duration"),
    ("monitoring-bind-wildcard", {"MONITORING_ENABLED": "true", "GRAFANA_BIND": "0.0.0.0"}, "GRAFANA_BIND=0.0.0.0 exposes"),
    ("monitoring-metrics-retention", {"MONITORING_ENABLED": "true", "METRICS_RETENTION": "0d"}, "METRICS_RETENTION must be whole days"),
    ("monitoring-logs-retention", {"MONITORING_ENABLED": "true", "LOGS_RETENTION": "forever"}, "LOGS_RETENTION must be whole days"),
    ("local-http-port-range", {"TLS_MODE": "local-https", "LOCAL_HTTP_PORT": "65536"}, "LOCAL_HTTP_PORT must be between 1 and 65535"),
    ("local-https-port-range", {"TLS_MODE": "local-https", "LOCAL_HTTPS_PORT": "0"}, "LOCAL_HTTPS_PORT must be between 1 and 65535"),
    ("local-ports-collide", {"TLS_MODE": "local-https", "LOCAL_HTTP_PORT": "8443", "LOCAL_HTTPS_PORT": "8443"}, "LOCAL_HTTP_PORT and LOCAL_HTTPS_PORT must be different"),
    ("subnet-public", {"CHRONICLE_SUBNET": "8.8.8.0/24"}, "CHRONICLE_SUBNET must be one canonical, private IPv4 CIDR"),
    ("disk-floor-invalid", {"MIN_FREE_DISK_GIB": "-1"}, "MIN_FREE_DISK_GIB must be a non-negative decimal integer"),
    ("jwt-previous-short", {"JWT_SECRET_PREVIOUS": "short"}, "JWT_SECRET_PREVIOUS must be a distinct generated secret"),
    ("jwt-previous-duplicate", {"JWT_SECRET_PREVIOUS": base["JWT_SECRET"]}, "JWT_SECRET_PREVIOUS must be a distinct generated secret"),
    ("jwt-previous-no-expiry", {"JWT_SECRET_PREVIOUS": "old-jwt-secret-01234567890123456789", "JWT_SECRET_PREVIOUS_EXPIRES_AT": "0"}, "JWT_SECRET_PREVIOUS_EXPIRES_AT must be absolute Unix seconds"),
    ("jwt-previous-unbounded", {"JWT_SECRET_PREVIOUS": "old-jwt-secret-01234567890123456789", "JWT_SECRET_PREVIOUS_EXPIRES_AT": "99999999999"}, "JWT_SECRET_PREVIOUS_EXPIRES_AT must not exceed one dashboard session"),
    ("production-without-backups", {"BACKUPS_ENABLED": "false", "ENABLE_ENCRYPTION": "false"}, "production deployment modes require"),
    ("encrypted-without-backups", {"TLS_MODE": "local-https", "BACKUPS_ENABLED": "false", "ENABLE_ENCRYPTION": "true", "COMPOSE_FILE_SELECTION": "docker-compose.yml:overlays/mode-local-https.yml"}, "encryption at rest is on"),
    ("legacy-login", {"TESTING_LOGIN_ENABLED": "true"}, "TESTING_LOGIN_ENABLED must be false"),
    ("invalid-boolean", {"ENABLE_ENCRYPTION": "treu"}, "must be exactly true or false"),
    ("duplicate-mode", {"COMPOSE_FILE_SELECTION": "docker-compose.yml:overlays/mode-behind-proxy-internal.yml:overlays/mode-own-tls-internal.yml:overlays/backups.yml"}, "exactly one mode overlay"),
    ("public-exposure", {"DASHBOARD_EXPOSURE": "public"}, "unrecognised mode overlay"),
    ("mfa-with-password-login", {"REQUIRE_MFA": "true"}, "REQUIRE_MFA=true with the internal dashboard password login"),
    ("backend-xms-unit-only", {"BACKEND_XMS": "512m"}, "BACKEND_XMS must look like -Xms512m"),
    # One mutation per guard rule that has no other FAIL-line test.
    ("internal-bind-any-v4", {"INTERNAL_BIND": "0.0.0.0"}, "INTERNAL_BIND must be one specific"),
    ("internal-bind-any-v6", {"INTERNAL_BIND": "::"}, "INTERNAL_BIND must be one specific"),
    ("internal-bind-any-v6-bracketed", {"INTERNAL_BIND": "[::]"}, "INTERNAL_BIND must be one specific"),
    ("internal-bind-ipv6", {"INTERNAL_BIND": "fd42:242::1"}, "INTERNAL_BIND=fd42:242::1 is IPv6"),
    ("http-bind-ipv6", {"HTTP_BIND": "fd42:241::1"}, "HTTP_BIND=fd42:241::1 is IPv6"),
    ("http-bind-any-v4-plaintext", {"HTTP_BIND": "0.0.0.0", "POOL_LISTENER_TLS": "false"}, "HTTP_BIND=0.0.0.0 serves participant uploads in plain HTTP"),
    ("http-bind-any-v6-plaintext", {"HTTP_BIND": "::", "POOL_LISTENER_TLS": "false"}, "HTTP_BIND=:: serves participant uploads in plain HTTP"),
    ("jwt-short", {"JWT_SECRET": "only-twenty-chars-xx"}, "JWT_SECRET is only 20 characters"),
    ("session-minutes-text", {"DASHBOARD_SESSION_MINUTES": "8h"}, "DASHBOARD_SESSION_MINUTES must be a whole number"),
    ("allowlist-empty", {"DASHBOARD_ALLOWED_IPS": ""}, "DASHBOARD_ALLOWED_IPS is empty"),
    ("allowlist-any-v4", {"DASHBOARD_ALLOWED_IPS": "10.0.0.0/8 0.0.0.0/0"}, "DASHBOARD_ALLOWED_IPS is malformed or admits the entire"),
    ("allowlist-any-v6", {"DASHBOARD_ALLOWED_IPS": "::/0"}, "DASHBOARD_ALLOWED_IPS is malformed or admits the entire"),
    ("password-hash-empty", {"DASHBOARD_PASSWORD_HASH": ""}, "DASHBOARD_PASSWORD_HASH is empty"),
    ("password-hash-cleartext", {"DASHBOARD_PASSWORD_HASH": "correct horse battery staple"}, "not a bcrypt hash"),
    ("domain-localhost", {"DOMAIN": "localhost"}, "DOMAIN must be a public DNS name"),
    ("domain-documentation-example", {"DOMAIN": "study.example.org"}, "DOMAIN must be a public DNS name"),
    ("metrics-password-short", {"METRICS_PASSWORD": "m" * 20}, "METRICS_PASSWORD is 20 characters"),
    ("own-tls-without-certificates", {"TLS_MODE": "own-tls", "COMPOSE_FILE_SELECTION": "docker-compose.yml:overlays/mode-own-tls-internal.yml:overlays/backups.yml", "CHRONICLE_GUARD_TLS_DIR": tls_dir + "-absent"}, "./tls/cert.pem or ./tls/key.pem is missing"),
    ("compose-file-empty", {"COMPOSE_FILE_SELECTION": ""}, "COMPOSE_FILE is empty"),
    ("trial-public-hostname", {"TLS_MODE": "local-https", "COMPOSE_FILE_SELECTION": "docker-compose.yml:overlays/mode-local-https.yml:overlays/backups.yml", "DOMAIN": "study.research-matrix.org"}, "local trial mode must use a private LAN address"),
    ("trial-public-ip", {"TLS_MODE": "local-https", "COMPOSE_FILE_SELECTION": "docker-compose.yml:overlays/mode-local-https.yml:overlays/backups.yml", "DOMAIN": "8.8.8.8"}, "local trial mode must use a private LAN address"),
    ("release-image-by-tag", {"RELEASE_VERSION": "2026.9.22", "BACKEND_IMAGE": "ghcr.io/example/chronicle-backend:latest"}, "BACKEND_IMAGE must be digest-pinned"),
    ("secret-placeholder", {"POSTGRES_PASSWORD": "CHANGE_ME_postgres_password"}, "still at placeholder/empty values: POSTGRES_PASSWORD"),
    ("app-password-short", {"POSTGRES_APP_PASSWORD": "fifteen-chars-x"}, "POSTGRES_APP_PASSWORD is only 15 characters; use at least 16"),
    ("jwt-unset", {"JWT_SECRET": ""}, "JWT_SECRET is not set"),
    ("trusted-proxies-any", {"CADDY_TRUSTED_PROXIES": "0.0.0.0/0"}, "CADDY_TRUSTED_PROXIES must be explicit valid CIDRs"),
    ("trusted-proxies-mode-mismatch", {"TLS_MODE": "own-tls", "COMPOSE_FILE_SELECTION": "docker-compose.yml:overlays/mode-own-tls-internal.yml:overlays/backups.yml", "CADDY_TRUSTED_PROXIES": "10.242.0.0/24"}, "trusted proxies must match the listener mode"),
]
errors = []
for image_key in ("BACKEND_IMAGE", "SELFHOST_FRONTEND_IMAGE", "CADDY_IMAGE", "POSTGRES_IMAGE"):
    if "@sha256:" not in base.get(image_key, ""):
        errors.append(f"config-guard does not receive a digest-pinned {image_key}")
for name, changes, expected in cases:
    environment = dict(base)
    environment.update(changes)
    completed = subprocess.run(
        [guard],
        cwd=str(Path(guard).parent),
        env=environment,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=10,
        check=False,
    )
    if completed.returncode == 0:
        errors.append(f"guard accepted rejected shape {name}")
    elif expected not in completed.stdout:
        errors.append(f"guard rejection for {name} omitted {expected!r}:\n{completed.stdout}")

# Accepted shapes that must still say something. A warn line is the only signal the operator gets.
remote_proxy = '10.242.0.0/24'
warn_cases = [
    ("http-bind-any-v4-tls", {"HTTP_BIND": "0.0.0.0", "POOL_LISTENER_TLS": "true", "CADDY_TRUSTED_PROXIES": remote_proxy}, "HTTP_BIND=0.0.0.0 serves the pool listener to your whole network"),
    ("http-bind-any-v6-tls", {"HTTP_BIND": "::", "POOL_LISTENER_TLS": "true", "CADDY_TRUSTED_PROXIES": remote_proxy}, "HTTP_BIND=:: serves the pool listener to your whole network"),
    ("http-bind-plaintext-waiver", {"HTTP_BIND": "10.242.0.5", "POOL_LISTENER_TLS": "false", "POOL_PLAINTEXT_WAIVER": "RR-12", "CADDY_TRUSTED_PROXIES": remote_proxy}, "serves plain HTTP under recorded waiver: RR-12"),
    ("plaintext-dumps", {}, "SQL dumps in ./backups are unencrypted"),
    ("trial-lan-address", {"TLS_MODE": "local-https", "COMPOSE_FILE_SELECTION": "docker-compose.yml:overlays/mode-local-https.yml:overlays/backups.yml", "DOMAIN": "192.168.1.50", "CADDY_TRUSTED_PROXIES": local_proxy}, "phones will reach this stack at https://192.168.1.50"),
]
for name, changes, expected in warn_cases:
    environment = dict(base)
    environment.update(changes)
    completed = subprocess.run([guard], cwd=str(Path(guard).parent), env=environment, text=True,
                               stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=10, check=False)
    if completed.returncode != 0:
        errors.append(f"guard rejected accepted shape {name}:\n{completed.stdout}")
    elif expected not in completed.stdout:
        errors.append(f"guard output for {name} omitted {expected!r}")
if errors:
    raise SystemExit("\n".join(errors))
PY

echo "self-host combination RENDER matrix passed (${case_count} renders plus rejected-shape checks; runtime qualification: tests/deployment/selfhost-platform.md)"
