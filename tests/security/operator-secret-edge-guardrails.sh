#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
ROTATE_SECRETS="$ROOT_DIR/scripts/rotate-secrets.sh"
ROTATE_TDE="$ROOT_DIR/scripts/rotate-tde-principal-key.sh"
SECURITY_ALERTS="$ROOT_DIR/scripts/security-log-alerts.sh"
GENERATE_JWT="$ROOT_DIR/docker/generate-jwt.sh"
TRAEFIK_CONFIG="$ROOT_DIR/docker/traefik/traefik.yml"
NGINX_CONFIG="$ROOT_DIR/docker/nginx.conf"
NGINX_PROD_CONFIG="$ROOT_DIR/docker/nginx.prod.conf"
RKE2_TRAEFIK_VALUES="$ROOT_DIR/k8s/security/crowdsec/traefik-values/rke2-traefik-crowdsec-values.yaml"

fail() {
  printf 'operator secret/edge guardrail failed: %s\n' "$*" >&2
  exit 1
}

require_pattern() {
  local file="$1" pattern="$2" message="$3"
  grep -Eq -- "$pattern" "$file" || fail "$message ($file)"
}

reject_pattern() {
  local file="$1" pattern="$2" message="$3"
  if grep -Eq -- "$pattern" "$file"; then
    fail "$message ($file)"
  fi
}

for file in \
  "$ROTATE_SECRETS" \
  "$ROTATE_TDE" \
  "$SECURITY_ALERTS" \
  "$GENERATE_JWT" \
  "$TRAEFIK_CONFIG" \
  "$NGINX_CONFIG" \
  "$NGINX_PROD_CONFIG" \
  "$RKE2_TRAEFIK_VALUES"; do
  [[ -f "$file" ]] || fail "required file is missing: $file"
done

for script in "$ROTATE_SECRETS" "$ROTATE_TDE" "$SECURITY_ALERTS" "$GENERATE_JWT"; do
  bash -n "$script"
  require_pattern "$script" '^umask[[:space:]]+077$' \
    "secret-handling scripts must default newly-created files to owner-only access"
done

require_pattern "$ROTATE_SECRETS" 'require_private_file' \
  "the rotation env file must be checked for mode 0600 before secrets are read"
require_pattern "$ROTATE_SECRETS" 'reset-admin-password[[:space:]]+--password-from-stdin' \
  "Grafana password rotation must consume the new password through stdin"
reject_pattern "$ROTATE_SECRETS" 'reset-admin-password[[:space:]]+"?\$[A-Za-z_][A-Za-z0-9_]*"?' \
  "Grafana passwords must not be passed in argv"
reject_pattern "$ROTATE_SECRETS" 'docker[[:space:]]+exec[^\n]*-e[[:space:]]+PGPASSWORD=' \
  "Postgres passwords must not be passed in docker argv"
reject_pattern "$ROTATE_SECRETS" 'sed[[:space:]].*\$\{?new\}?' \
  "new secret values must not be interpolated into sed argv"

require_pattern "$ROTATE_TDE" 'require_private_file' \
  "TDE rotation must validate protected secret files"
require_pattern "$ROTATE_TDE" 'docker[[:space:]]+exec[[:space:]]+-i' \
  "TDE database credentials and SQL must be delivered over protected stdin"
reject_pattern "$ROTATE_TDE" 'docker[[:space:]]+exec[^\n]*-e[[:space:]]+PGPASSWORD=' \
  "TDE database passwords must not be passed in docker argv"
reject_pattern "$ROTATE_TDE" 'psql[^\n]*-c[[:space:]]+"?\$sql"?' \
  "TDE SQL must not be placed in psql argv"

require_pattern "$SECURITY_ALERTS" 'require_private_file' \
  "the alert scanner must validate its credential file before reading it"
require_pattern "$SECURITY_ALERTS" 'docker[[:space:]]+exec[[:space:]]+-i' \
  "the alert scanner must deliver the database password through stdin"
reject_pattern "$SECURITY_ALERTS" 'docker[[:space:]]+exec[^\n]*-e[[:space:]]+PGPASSWORD=' \
  "the alert scanner must not put the database password in docker argv"
reject_pattern "$SECURITY_ALERTS" 'gh[[:space:]]+issue[[:space:]]+(create|comment)[^\n]*--body[[:space:]]+"?\$body"?' \
  "alert bodies must be passed to gh with --body-file stdin"

require_pattern "$GENERATE_JWT" '--secret-file' \
  "JWT signing secrets must be accepted from a protected file"
require_pattern "$GENERATE_JWT" '--secret-stdin' \
  "JWT signing secrets must be accepted from stdin"
require_pattern "$GENERATE_JWT" '--output' \
  "JWTs must be written only to an explicit protected output file"
require_pattern "$GENERATE_JWT" 'export[[:space:]]+-n[[:space:]]+JWT_SECRET' \
  "ambient JWT_SECRET must be unexported before helper processes start"
reject_pattern "$GENERATE_JWT" 'echo[[:space:]]+"?\$TOKEN"?|printf[^\n]*\$TOKEN' \
  "JWTs must never be emitted on stdout"
reject_pattern "$GENERATE_JWT" 'openssl[^\n]*-hmac[[:space:]]+"?\$' \
  "JWT signing secrets must not be passed to openssl in argv"
reject_pattern "$GENERATE_JWT" '--write-config|chronicle-config\.json' \
  "the JWT helper must not recreate the legacy browser-readable token artifact"
require_pattern "$ROTATE_TDE" 'export[[:space:]]+-n[[:space:]]+POSTGRES_PASSWORD[[:space:]]+PG_TDE_VAULT_TOKEN' \
  "ambient TDE credentials must be unexported before helper processes start"
reject_pattern "$ROTATE_SECRETS" 'embedded in the (Android )?(APK|AAB)|shared with the Android APK|requires APK coordination|until APK update|publish(ing)? a new app' \
  "legacy compatibility rotation must not claim public app artifacts contain deployment-wide secrets"

SCRATCH_DIR="$(mktemp -d "$ROOT_DIR/tests/security/.operator-secret-edge-guardrails.XXXXXX")"
SECRET_FILE="$SCRATCH_DIR/jwt-secret"
INSECURE_SECRET_FILE="$SCRATCH_DIR/insecure-jwt-secret"
TOKEN_FILE="$SCRATCH_DIR/diagnostic.jwt"
AMBIENT_TOKEN_FILE="$SCRATCH_DIR/ambient-diagnostic.jwt"
STDOUT_FILE="$SCRATCH_DIR/stdout"
STDERR_FILE="$SCRATCH_DIR/stderr"
COMMAND_DIR="$SCRATCH_DIR/commands"
PYTHON_ENV_MARKER="$SCRATCH_DIR/python-env-sanitized"
ROTATION_ENV="$SCRATCH_DIR/chronicle.env"
ROTATION_STDOUT="$SCRATCH_DIR/rotation.stdout"
ROTATION_STDERR="$SCRATCH_DIR/rotation.stderr"
SENTINEL='operator-edge-guardrail-secret-never-print'
TDE_POSTGRES_SENTINEL='operator-tde-postgres-fallback-never-print'
TDE_VAULT_SENTINEL='operator-tde-vault-fallback-never-print'
cleanup() {
  rm -f -- \
    "$SECRET_FILE" \
    "$INSECURE_SECRET_FILE" \
    "$TOKEN_FILE" \
    "$AMBIENT_TOKEN_FILE" \
    "$STDOUT_FILE" \
    "$STDERR_FILE" \
    "$ROTATION_ENV" \
    "$ROTATION_STDOUT" \
    "$ROTATION_STDERR" \
    "$PYTHON_ENV_MARKER" \
    "$SCRATCH_DIR/insecure.jwt" \
    "$SCRATCH_DIR/missing-output.stdout" \
    "$SCRATCH_DIR/missing-output.stderr"
  rm -rf -- "$COMMAND_DIR" "$SCRATCH_DIR/tde-fixture"
  rmdir "$SCRATCH_DIR" 2>/dev/null || true
}
trap cleanup EXIT

mkdir -p "$COMMAND_DIR"
REAL_PYTHON="$(command -v python3)"
cat >"$COMMAND_DIR/python3" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
[[ -z "${JWT_SECRET+x}" ]] || {
  echo "JWT_SECRET reached the Python signer environment" >&2
  exit 96
}
printf 'sanitized\n' >"${OPERATOR_JWT_PYTHON_ENV_MARKER}"
exec "${OPERATOR_REAL_PYTHON}" "$@"
EOF
chmod 0755 "$COMMAND_DIR/python3"

printf '%s\n' "$SENTINEL" > "$SECRET_FILE"
chmod 600 "$SECRET_FILE"
"$GENERATE_JWT" --secret-file "$SECRET_FILE" --output "$TOKEN_FILE" \
  >"$STDOUT_FILE" 2>"$STDERR_FILE" || fail "JWT file generation failed"

PATH="$COMMAND_DIR:$PATH" \
  OPERATOR_REAL_PYTHON="$REAL_PYTHON" \
  OPERATOR_JWT_PYTHON_ENV_MARKER="$PYTHON_ENV_MARKER" \
  JWT_SECRET="$SENTINEL" \
  "$GENERATE_JWT" --output "$AMBIENT_TOKEN_FILE" \
  >"$STDOUT_FILE" 2>"$STDERR_FILE" || fail "ambient JWT compatibility input failed"
[[ -s "$AMBIENT_TOKEN_FILE" ]] || fail "ambient JWT compatibility input produced no token"
[[ -s "$PYTHON_ENV_MARKER" ]] || fail "the Python signer environment boundary was not exercised"

[[ -s "$TOKEN_FILE" ]] || fail "JWT output file is empty"
[[ "$(stat -f '%Lp' "$TOKEN_FILE" 2>/dev/null || stat -c '%a' "$TOKEN_FILE")" == "600" ]] || \
  fail "JWT output file must have mode 0600"
grep -Fq "$SENTINEL" "$STDOUT_FILE" "$STDERR_FILE" && \
  fail "JWT signing secret reached process output"
if grep -Eq '[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+' "$STDOUT_FILE" "$STDERR_FILE"; then
  fail "JWT reached process output"
fi

python3 - "$TOKEN_FILE" <<'PY'
import base64
import json
import pathlib
import sys

token = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8").strip()
parts = token.split(".")
if len(parts) != 3:
    raise SystemExit("diagnostic JWT does not have three segments")
payload_segment = parts[1] + "=" * (-len(parts[1]) % 4)
payload = json.loads(base64.urlsafe_b64decode(payload_segment.encode("ascii")))
ttl = int(payload["exp"]) - int(payload["iat"])
if ttl <= 0 or ttl > 3600:
    raise SystemExit(f"diagnostic JWT lifetime is unsafe: {ttl}s")
PY

python3 - "$AMBIENT_TOKEN_FILE" "$SENTINEL" <<'PY'
import base64
import hashlib
import hmac
import pathlib
import sys

token = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8").strip()
header, payload, signature = token.split(".")
expected = base64.urlsafe_b64encode(
    hmac.new(sys.argv[2].encode(), f"{header}.{payload}".encode(), hashlib.sha256).digest()
).rstrip(b"=").decode()
if not hmac.compare_digest(signature, expected):
    raise SystemExit("ambient JWT secret was not retained through the private input fd")
PY

printf '%s\n' "$SENTINEL" > "$INSECURE_SECRET_FILE"
chmod 644 "$INSECURE_SECRET_FILE"
if "$GENERATE_JWT" --secret-file "$INSECURE_SECRET_FILE" --output "$SCRATCH_DIR/insecure.jwt" \
  >"$STDOUT_FILE" 2>"$STDERR_FILE"; then
  fail "JWT helper accepted a group/world-readable signing secret file"
fi
[[ ! -e "$SCRATCH_DIR/insecure.jwt" ]] || fail "rejected JWT input left an output artifact"

if "$GENERATE_JWT" --secret-file "$SECRET_FILE" \
  >"$SCRATCH_DIR/missing-output.stdout" 2>"$SCRATCH_DIR/missing-output.stderr"; then
  fail "JWT helper accepted a request without an explicit output file"
fi
if grep -Eq '[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+' \
  "$SCRATCH_DIR/missing-output.stdout" "$SCRATCH_DIR/missing-output.stderr"; then
  fail "rejected JWT request emitted a token"
fi

printf '%s\n' \
  "JWT_SECRET=$SENTINEL" \
  'POSTGRES_USER=chronicle' \
  'POSTGRES_DB=chronicle' \
  "POSTGRES_PASSWORD=$SENTINEL" \
  'PG_TDE_KEY_PROVIDER=file' \
  > "$ROTATION_ENV"
chmod 600 "$ROTATION_ENV"
CHRONICLE_ENV_FILE="$ROTATION_ENV" "$ROTATE_SECRETS" --dry-run --only JWT_SECRET \
  > "$ROTATION_STDOUT" 2> "$ROTATION_STDERR" || fail "secret rotation dry-run failed"
CHRONICLE_ENV_FILE="$ROTATION_ENV" "$ROTATE_TDE" --dry-run \
  >> "$ROTATION_STDOUT" 2>> "$ROTATION_STDERR" || fail "TDE rotation dry-run failed"
grep -Fq "$SENTINEL" "$ROTATION_STDOUT" "$ROTATION_STDERR" && \
  fail "rotation dry-run emitted a credential"
chmod 644 "$ROTATION_ENV"
if CHRONICLE_ENV_FILE="$ROTATION_ENV" "$ROTATE_SECRETS" --dry-run --only JWT_SECRET \
  > "$ROTATION_STDOUT" 2> "$ROTATION_STDERR"; then
  fail "secret rotation accepted a group/world-readable environment file"
fi

TDE_FIXTURE="$SCRATCH_DIR/tde-fixture"
TDE_COMMAND_DIR="$TDE_FIXTURE/commands"
TDE_POSTGRES_FILE="$TDE_FIXTURE/expected-postgres"
TDE_VAULT_FILE="$TDE_FIXTURE/expected-vault"
TDE_HELPER_MARKER="$TDE_FIXTURE/helper-env-sanitized"
TDE_DOCKER_COUNT="$TDE_FIXTURE/docker-count"
TDE_STDOUT="$TDE_FIXTURE/stdout"
TDE_STDERR="$TDE_FIXTURE/stderr"
mkdir -p "$TDE_FIXTURE/repo/scripts" "$TDE_FIXTURE/repo/docker" "$TDE_COMMAND_DIR"
cp "$ROTATE_TDE" "$TDE_FIXTURE/repo/scripts/rotate-tde-principal-key.sh"
chmod 0755 "$TDE_FIXTURE/repo/scripts/rotate-tde-principal-key.sh"
printf '%s' "$TDE_POSTGRES_SENTINEL" >"$TDE_POSTGRES_FILE"
printf '%s' "$TDE_VAULT_SENTINEL" >"$TDE_VAULT_FILE"
chmod 0600 "$TDE_POSTGRES_FILE" "$TDE_VAULT_FILE"

cat >"$TDE_COMMAND_DIR/dirname" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
[[ -z "${POSTGRES_PASSWORD+x}" ]] || exit 111
[[ -z "${PG_TDE_VAULT_TOKEN+x}" ]] || exit 112
printf 'sanitized\n' >"${OPERATOR_TDE_HELPER_MARKER}"
exec /usr/bin/dirname "$@"
EOF
cat >"$TDE_COMMAND_DIR/docker" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
[[ -z "${POSTGRES_PASSWORD+x}" ]] || exit 113
[[ -z "${PG_TDE_VAULT_TOKEN+x}" ]] || exit 114
expected="$(<"${OPERATOR_TDE_POSTGRES_FILE}")"
IFS= read -r supplied
[[ "$supplied" == "$expected" ]] || exit 115
cat >/dev/null
count=0
[[ ! -f "${OPERATOR_TDE_DOCKER_COUNT}" ]] || count="$(<"${OPERATOR_TDE_DOCKER_COUNT}")"
printf '%s\n' "$((count + 1))" >"${OPERATOR_TDE_DOCKER_COUNT}"
EOF
cat >"$TDE_COMMAND_DIR/vault" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
[[ -z "${POSTGRES_PASSWORD+x}" ]] || exit 116
[[ -z "${PG_TDE_VAULT_TOKEN+x}" ]] || exit 117
expected="$(<"${OPERATOR_TDE_VAULT_FILE}")"
[[ "${VAULT_TOKEN:-}" == "$expected" ]] || exit 118
[[ "${VAULT_ADDR:-}" == 'https://vault.example.org' ]] || exit 119
EOF
chmod 0755 "$TDE_COMMAND_DIR/dirname" "$TDE_COMMAND_DIR/docker" "$TDE_COMMAND_DIR/vault"

set +e
PATH="$TDE_COMMAND_DIR:$PATH" \
  CHRONICLE_ENV_FILE="$TDE_FIXTURE/nonexistent.env" \
  POSTGRES_PASSWORD="$TDE_POSTGRES_SENTINEL" \
  PG_TDE_VAULT_TOKEN="$TDE_VAULT_SENTINEL" \
  PG_TDE_KEY_PROVIDER=vault \
  PG_TDE_VAULT_URL=https://vault.example.org \
  OPERATOR_TDE_HELPER_MARKER="$TDE_HELPER_MARKER" \
  OPERATOR_TDE_POSTGRES_FILE="$TDE_POSTGRES_FILE" \
  OPERATOR_TDE_VAULT_FILE="$TDE_VAULT_FILE" \
  OPERATOR_TDE_DOCKER_COUNT="$TDE_DOCKER_COUNT" \
  "$TDE_FIXTURE/repo/scripts/rotate-tde-principal-key.sh" \
  >"$TDE_STDOUT" 2>"$TDE_STDERR"
tde_fixture_status=$?
set -e
if [[ "$tde_fixture_status" -ne 0 ]]; then
  [[ ! -e "$TDE_HELPER_MARKER" ]] || printf 'TDE fixture reached sanitized dirname helper\n' >&2
  [[ ! -e "$TDE_DOCKER_COUNT" ]] || printf 'TDE fixture completed %s protected SQL calls\n' "$(<"$TDE_DOCKER_COUNT")" >&2
  line_count=0
  while IFS= read -r diagnostic_line && ((line_count < 40)); do
    diagnostic_line="${diagnostic_line//$SENTINEL/[redacted]}"
    diagnostic_line="${diagnostic_line//$TDE_POSTGRES_SENTINEL/[redacted]}"
    diagnostic_line="${diagnostic_line//$TDE_VAULT_SENTINEL/[redacted]}"
    printf '%s\n' "$diagnostic_line" >&2
    line_count=$((line_count + 1))
  done <"$TDE_STDERR"
  fail "TDE ambient fallback fixture failed (status ${tde_fixture_status})"
fi
[[ -s "$TDE_HELPER_MARKER" ]] || fail "TDE helper environment boundary was not exercised"
[[ "$(<"$TDE_DOCKER_COUNT")" == 1 ]] || fail "TDE fallback password did not reach the protected SQL input"
grep -Fq "$TDE_POSTGRES_SENTINEL" "$TDE_STDOUT" "$TDE_STDERR" && \
  fail "ambient Postgres fallback reached TDE rotation output"
grep -Fq "$TDE_VAULT_SENTINEL" "$TDE_STDOUT" "$TDE_STDERR" && \
  fail "ambient Vault fallback reached TDE rotation output"

python3 - "$TRAEFIK_CONFIG" "$RKE2_TRAEFIK_VALUES" "$NGINX_CONFIG" "$NGINX_PROD_CONFIG" <<'PY'
import pathlib
import re
import sys

import yaml

traefik_path, rke2_path, *nginx_paths = map(pathlib.Path, sys.argv[1:])

traefik = yaml.safe_load(traefik_path.read_text(encoding="utf-8"))
fields = traefik.get("accessLog", {}).get("fields", {})
if fields.get("defaultMode") != "drop":
    raise SystemExit("docker Traefik access-log fields must default to drop")
if fields.get("headers", {}).get("defaultMode") != "drop":
    raise SystemExit("docker Traefik access-log headers must default to drop")
safe_fields = {
    "DownstreamStatus",
    "Duration",
    "RequestMethod",
    "RouterName",
    "ServiceName",
    "StartUTC",
    "entryPointName",
}
kept_fields = {name for name, mode in fields.get("names", {}).items() if mode == "keep"}
if kept_fields != safe_fields:
    raise SystemExit(f"docker Traefik must keep only the privacy-safe field set: {sorted(kept_fields)}")

rke2 = yaml.safe_load(rke2_path.read_text(encoding="utf-8"))
access = rke2.get("logs", {}).get("access", {})
general = access.get("fields", {}).get("general", {})
headers = access.get("fields", {}).get("headers", {})
if general.get("defaultmode") != "drop":
    raise SystemExit("RKE2 Traefik access-log fields must default to drop")
if headers.get("defaultmode") != "drop":
    raise SystemExit("RKE2 Traefik access-log headers must default to drop")
kept_fields = {name for name, mode in general.get("names", {}).items() if mode == "keep"}
if kept_fields != safe_fields:
    raise SystemExit(f"RKE2 Traefik must keep only the privacy-safe field set: {sorted(kept_fields)}")

required_args = {
    "--accesslog.fields.defaultmode=drop",
    "--accesslog.fields.headers.defaultmode=drop",
    *(f"--accesslog.fields.names.{name}=keep" for name in safe_fields),
}
args = set(rke2.get("additionalArguments", []))
missing_args = required_args - args
if missing_args:
    raise SystemExit(f"RKE2 Traefik is missing privacy CLI arguments: {sorted(missing_args)}")

sensitive_nginx_vars = re.compile(
    r"\$(?:remote_addr|remote_user|request_uri|uri|args|query_string|http_referer|"
    r"http_user_agent|http_x_forwarded_for)(?![A-Za-z0-9_])|\$request(?![A-Za-z0-9_])"
)
for nginx_path in nginx_paths:
    text = nginx_path.read_text(encoding="utf-8")
    match = re.search(r"log_format\s+main\b(?P<body>.*?);", text, flags=re.DOTALL)
    if not match:
        raise SystemExit(f"missing main access-log format: {nginx_path}")
    if sensitive_nginx_vars.search(match.group("body")):
        raise SystemExit(f"nginx access log retains raw IP/request/identifier data: {nginx_path}")
    if not re.search(r"error_log\s+\S+\s+crit\s*;", text):
        raise SystemExit(f"nginx request errors are not source-filtered at crit: {nginx_path}")
PY

printf 'Operator secret/edge guardrails passed.\n'
