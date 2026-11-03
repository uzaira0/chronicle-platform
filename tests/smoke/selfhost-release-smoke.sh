#!/usr/bin/env bash
set -Eeuo pipefail
export CHRONICLE_RECONCILE_ENABLED="${CHRONICLE_RECONCILE_ENABLED:-false}"
# The isolated 256 MiB PostgreSQL volume deliberately exercises ENOSPC. Image/download
# reserves still apply on Docker/state storage; platform qualification tests the default floor.
export MIN_FREE_DISK_GIB=0
BACKUP_ENCRYPTION_WAIVER=synthetic-release-smoke-fixture-no-study-data

# End-to-end proof for the artifact a self-hoster actually receives. The test builds and
# verifies a release archive, extracts it without source-build access, installs it fresh,
# checks the public/internal boundary, forces dependency-order restart recovery, restores a
# generated SQL dump, and optionally proves the monitoring data path.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
BUILDER="${ROOT_DIR}/scripts/build-selfhost-release.py"
RUN_PARENT="${SELFHOST_SMOKE_ROOT:-${ROOT_DIR}/build/operator-test-runs/selfhost-release-smoke}"
BACKEND_IMAGE="${SELFHOST_SMOKE_BACKEND_IMAGE:-}"
FRONTEND_IMAGE="${SELFHOST_SMOKE_FRONTEND_IMAGE:-}"
CADDY_IMAGE="${SELFHOST_SMOKE_CADDY_IMAGE:-}"
# Candidate backup sidecar pin, checked against the signed archive.
BACKUP_IMAGE="${SELFHOST_SMOKE_BACKUP_IMAGE:-}"
RELEASE_ARCHIVE="${SELFHOST_SMOKE_RELEASE_ARCHIVE:-}"
RELEASE_SHA256_FILE="${SELFHOST_SMOKE_RELEASE_SHA256_FILE:-${RELEASE_ARCHIVE}.sha256}"
RELEASE_SIGNATURE_FILE="${SELFHOST_SMOKE_RELEASE_SIGNATURE_FILE:-${RELEASE_SHA256_FILE}.sig}"
RELEASE_ARCHIVE_SHA256=""
MONITORING="${SELFHOST_SMOKE_MONITORING:-true}"
SMOKE_PASSWORD='chronicle-smoke-only-password'
# The k6 benchmark writes ~70k rows into this volume after the disk drill; 256 MiB hit ENOSPC (SQLSTATE 53100).
# The drill fills the whole tmpfs inside the postgres container, so it must stay well under POSTGRES_MEM_LIMIT (2g).
DISK_SMOKE_VOLUME_BYTES=805306368
DISK_SMOKE_VOLUME_INODES=65536
DISK_DRILL_MAX_SECONDS=60

operator_crontab() {
  if command -v crontab >/dev/null 2>&1; then
    crontab -l 2>/dev/null || [[ $? == 1 ]]
  fi
}

fail() {
  echo "self-host release smoke failed: $*" >&2
  exit 1
}

run_container_security_audit() { # <report-path>
  local report="$1" status
  if COMPOSE_PROJECT="$PROJECT" "${ROOT_DIR}/tests/security/container-security-tests.sh" \
      >"$report" 2>&1; then
    container_security_audit=pass
    return 0
  else
    status=$?
  fi
  container_security_audit=fail
  cat "$report" >&2
  fail "container security audit failed (exit ${status}); see ${report}"
}

bounded_curl() { # Every smoke HTTP request has a short connection and total deadline.
  curl --connect-timeout 5 --max-time 15 "$@"
}

[[ -n "$RELEASE_ARCHIVE" ]] || fail "set SELFHOST_SMOKE_RELEASE_ARCHIVE and its signed checksum"

for command in docker jq python3 sha256sum tar ssh-keygen k6; do
  command -v "$command" >/dev/null 2>&1 || fail "required command is unavailable: $command"
done
[[ -x "$BUILDER" ]] || fail "release builder is missing or not executable"
[[ -n "$BACKEND_IMAGE" ]] || fail "set SELFHOST_SMOKE_BACKEND_IMAGE"
[[ -n "$FRONTEND_IMAGE" ]] || fail "set SELFHOST_SMOKE_FRONTEND_IMAGE"
[[ -n "$CADDY_IMAGE" ]] || fail "set SELFHOST_SMOKE_CADDY_IMAGE"
[[ -n "$BACKUP_IMAGE" ]] || fail "set SELFHOST_SMOKE_BACKUP_IMAGE to the candidate backup pin"
[[ "$MONITORING" == true || "$MONITORING" == false ]] ||
  fail "SELFHOST_SMOKE_MONITORING must be true or false"
[[ "$RUN_PARENT" == /* ]] || fail "SELFHOST_SMOKE_ROOT must be absolute"
case "$RUN_PARENT" in
  /tmp|/tmp/*|/private/tmp|/private/tmp/*|/var/folders|/var/folders/*)
    fail "SELFHOST_SMOKE_ROOT must not use a system temporary directory"
    ;;
esac

docker info >/dev/null 2>&1 || fail "Docker is unavailable"
docker compose version >/dev/null 2>&1 || fail "the Docker Compose plugin is unavailable"

umask 077
# The stack is started with plain `docker compose up` below to keep --wait semantics; the
# `./chronicle` wrapper exports these so db-backup runs as the operator (overlays/backups.yml),
# and `./chronicle verify` fails on root-owned dumps without them.
CHRONICLE_HOST_UID="$(id -u)"
CHRONICLE_HOST_GID="$(id -g)"
export CHRONICLE_HOST_UID CHRONICLE_HOST_GID
/bin/mkdir -p "$RUN_PARENT"
RUN_DIR="$(/usr/bin/mktemp -d "${RUN_PARENT}/run.XXXXXX")"
/bin/chmod 0700 "$RUN_DIR"
BUNDLE=""
fresh_install=not_run
PROJECT=""
SMOKE_PASSED=false
REDIRECT_SERVER_PID=""
TLS_PROXY_CONTAINER=""
BENCHMARK_LISTENER_CONTAINER=""
DISK_VOLUME_KEEPER=""
DOCKER_EVENT_PIDS=""
operator_crontab >"${RUN_DIR}/crontab-before" || fail "could not snapshot the operator crontab"

cleanup() {
  local original_status=$?
  set +e
  if [[ -n "${interrupted_up:-}" ]]; then
    kill -KILL -- "-$interrupted_up" 2>/dev/null || true
    wait "$interrupted_up" 2>/dev/null || true
  fi
  [[ -z "$TLS_PROXY_CONTAINER" ]] || docker rm -f "$TLS_PROXY_CONTAINER" >/dev/null 2>&1
  [[ -z "${BENCHMARK_LISTENER_CONTAINER:-}" ]] || docker rm -f "$BENCHMARK_LISTENER_CONTAINER" >/dev/null 2>&1
  if [[ -n "$REDIRECT_SERVER_PID" ]]; then
    kill "$REDIRECT_SERVER_PID" 2>/dev/null || true
    wait "$REDIRECT_SERVER_PID" 2>/dev/null || true
  fi
  local event_pid
  for event_pid in $DOCKER_EVENT_PIDS; do
    kill "$event_pid" 2>/dev/null || true
    wait "$event_pid" 2>/dev/null || true
  done
  if [[ -n "$BUNDLE" && -d "$BUNDLE" && -n "$PROJECT" ]]; then
    (
      cd "$BUNDLE" || exit 0
      docker compose -p "$PROJECT" ps --all --format json >"${RUN_DIR}/final-compose-state.jsonl" 2>/dev/null
      # A failed run's only diagnosis is the container output; the stack is gone after down.
      if [[ "$SMOKE_PASSED" != true ]]; then
        docker compose -p "$PROJECT" logs --no-color --tail 300 >"${RUN_DIR}/final-compose-logs.txt" 2>&1
        # shellcheck disable=SC2046
        docker network inspect $(docker network ls -q --filter "label=com.docker.compose.project=$PROJECT") \
          >"${RUN_DIR}/final-networks.json" 2>&1
      fi
      [[ -z "$DISK_VOLUME_KEEPER" ]] || docker rm -f "$DISK_VOLUME_KEEPER" >/dev/null 2>&1
      docker compose -p "$PROJECT" down -v --remove-orphans >/dev/null 2>&1
    )
    /bin/rm -f -- "$BUNDLE/.env"
  fi
  if ! operator_crontab >"${RUN_DIR}/crontab-after" ||
     ! cmp -s "${RUN_DIR}/crontab-before" "${RUN_DIR}/crontab-after"; then
    echo 'self-host release smoke changed the operator crontab' >&2
    SMOKE_PASSED=false
    original_status=1
    printf 'status=failed\n' >"${RUN_DIR}/result.txt"
  fi
  if [[ "$SMOKE_PASSED" != true && ! -f "${RUN_DIR}/result.txt" ]]; then
    printf 'status=failed\n' >"${RUN_DIR}/result.txt"
  fi
  /bin/chmod 0600 "${RUN_DIR}/result.txt" 2>/dev/null || true
  if [[ "$SMOKE_PASSED" == true ]]; then
    printf 'Self-host release smoke passed; redacted evidence: %s/result.txt\n' "$RUN_DIR"
  else
    printf 'Self-host release smoke failed; evidence directory: %s\n' "$RUN_DIR" >&2
  fi
  return "$original_status"
}
trap cleanup EXIT

is_immutable_image() {
  [[ "$1" =~ @sha256:[0-9a-f]{64}$ ]]
}

verify_release_signature() {
  python3 - "$BUILDER" "$1" "$2" "$3" <<'PY_SIGNATURE'
from pathlib import Path
import runpy
import sys
builder, checksum, signature, key = map(Path, sys.argv[1:])
helpers = runpy.run_path(str(builder))
helpers['verify_release_signature'](checksum, signature, key)
print(helpers['SMOKE_ARCHIVE_HASH_FIELD'])
PY_SIGNATURE
}

# The release builder and `up` both refuse mutable tags, so every image is a digest
# reference: CI passes registry digests; local runs push to a loopback registry first.
for image in "$BACKEND_IMAGE" "$FRONTEND_IMAGE" "$CADDY_IMAGE" ${BACKUP_IMAGE:+"$BACKUP_IMAGE"}; do
  is_immutable_image "$image" ||
    fail "$image is not a digest reference; push it to a registry (e.g. localhost:5000) and pass name@sha256:..."
done

SMOKE_ARCHIVE_HASH_FIELD="$(verify_release_signature "$RELEASE_SHA256_FILE" "$RELEASE_SIGNATURE_FILE" "${CHRONICLE_RELEASE_VERIFY_KEY:-$ROOT_DIR/selfhost/release-signing.pub}")" ||
  fail "candidate signature does not match the release verification key"
release_metadata="$(python3 - "$BUILDER" "$RELEASE_ARCHIVE" "$RELEASE_SHA256_FILE" <<'PY_ARCHIVE'
from pathlib import Path
import runpy
import sys
helpers = runpy.run_path(sys.argv[1])
manifest = helpers['inspect_release_archive'](Path(sys.argv[2]), Path(sys.argv[3]))
print(manifest['release_version'], manifest['source_revision'], helpers['sha256'](Path(sys.argv[2])), sep="\t")
PY_ARCHIVE
)" || fail "release archive failed checksum or source-free inventory verification"
IFS=$'\t' read -r RELEASE_VERSION REVISION RELEASE_ARCHIVE_SHA256 <<<"$release_metadata"
mkdir "$RUN_DIR/extracted"
tar -xzpf "$RELEASE_ARCHIVE" -C "$RUN_DIR/extracted"
BUNDLE="$RUN_DIR/extracted/chronicle-selfhost-${RELEASE_VERSION}/selfhost"
RUN_DIR="$RUN_DIR" BUNDLE="$BUNDLE" RELEASE_BUILDER="$BUILDER" \
RUNTIME_BACKEND_IMAGE="$BACKEND_IMAGE" RUNTIME_FRONTEND_IMAGE="$FRONTEND_IMAGE" \
RUNTIME_CADDY_IMAGE="$CADDY_IMAGE" RUNTIME_BACKUP_IMAGE="$BACKUP_IMAGE" python3 - <<'PY'
from pathlib import Path
import os
import runpy
import secrets
import socket

bundle = Path(os.environ["BUNDLE"])
helpers = runpy.run_path(os.environ["RELEASE_BUILDER"])
helpers["require_smoke_images"](
    bundle.parent,
    {name: os.environ[key] for name, key in
     (("backend", "RUNTIME_BACKEND_IMAGE"), ("frontend", "RUNTIME_FRONTEND_IMAGE"), ("caddy", "RUNTIME_CADDY_IMAGE"))},
    os.environ["RUNTIME_BACKUP_IMAGE"])
ports = []
while len(ports) < 3:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    if port not in ports:
        ports.append(port)
project = f"chronicle-release-smoke-{os.getpid()}-{secrets.token_hex(3)}"
(Path(os.environ["RUN_DIR"]) / "smoke-metadata.txt").write_text(
    f"project={project}\nhttp_port={ports[0]}\ninternal_port={ports[1]}\ngrafana_port={ports[2]}\n"
    f"same_build_restore_field={helpers['SMOKE_SAME_BUILD_RESTORE_FIELD']}\n")
PY

# The metadata contains no secrets and uses shell-safe generated values.
project=""
http_port=""
internal_port=""
grafana_port=""
same_build_restore_field=""
# shellcheck disable=SC1090
source "${RUN_DIR}/smoke-metadata.txt"
[[ -n "$project" && -n "$http_port" && -n "$internal_port" && -n "$grafana_port" && -n "$same_build_restore_field" ]] ||
  fail "generated smoke metadata is incomplete"
PROJECT="$project"
# The daemon keeps only recent events; record this project's and every network change for diagnosis.
docker events --filter "label=com.docker.compose.project=$project" --format '{{json .}}' >"${RUN_DIR}/docker-events.jsonl" 2>&1 &
DOCKER_EVENT_PIDS="$!"
docker events --filter type=network --format '{{json .}}' >"${RUN_DIR}/docker-network-events.jsonl" 2>&1 &
DOCKER_EVENT_PIDS+=" $!"

# Stands in for the operator's TLS proxy: behind-proxy `verify` requires plain HTTP on the
# public name to redirect to HTTPS. curl reads $CURL_HOME/.curlrc, so only the fixture's
# public name on port 80 reaches this loopback listener; product code is unchanged.
SMOKE_PUBLIC_HOST=selfhost.study-host.org
python3 - "${RUN_DIR}/redirect-port" "$SMOKE_PUBLIC_HOST" >"${RUN_DIR}/redirect-server.log" 2>&1 <<'REDIRECT' &
import http.server
import os
import sys

port_file, host = sys.argv[1], sys.argv[2]


class Redirect(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(301)
        self.send_header("Location", f"https://{host}{self.path}")
        self.send_header("Content-Length", "0")
        self.end_headers()

    do_HEAD = do_GET


server = http.server.HTTPServer(("127.0.0.1", 0), Redirect)
with open(port_file + ".tmp", "w", encoding="utf-8") as handle:
    handle.write(str(server.server_port))
os.replace(port_file + ".tmp", port_file)
server.serve_forever()
REDIRECT
REDIRECT_SERVER_PID=$!
for _ in {1..20}; do
  [[ -s "${RUN_DIR}/redirect-port" ]] && break
  sleep 0.25
done
[[ -s "${RUN_DIR}/redirect-port" ]] || fail "loopback HTTPS-redirect fixture did not become ready"
/bin/mkdir -m 0700 "${RUN_DIR}/curl-home"
printf 'connect-to = %s:80:127.0.0.1:%s\n' "$SMOKE_PUBLIC_HOST" "$(<"${RUN_DIR}/redirect-port")" \
  >"${RUN_DIR}/curl-home/.curlrc"
# Host checks use a real TLS-terminating HAProxy; remote acceptance runs separately below.
mkdir -p "$RUN_DIR/proxy-fixture"
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj /CN=selfhost-smoke-CA \
  -keyout "$RUN_DIR/proxy-fixture/ca.key" -out "$RUN_DIR/proxy-fixture/ca.crt" \
  -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign,cRLSign >/dev/null 2>&1
openssl req -new -newkey rsa:2048 -nodes -subj "/CN=$SMOKE_PUBLIC_HOST" \
  -keyout "$RUN_DIR/proxy-fixture/lb.key" -out "$RUN_DIR/proxy-fixture/lb.csr" >/dev/null 2>&1
printf 'subjectAltName=DNS:%s\n' "$SMOKE_PUBLIC_HOST" >"$RUN_DIR/proxy-fixture/lb.ext"
openssl x509 -req -in "$RUN_DIR/proxy-fixture/lb.csr" -CA "$RUN_DIR/proxy-fixture/ca.crt" \
  -CAkey "$RUN_DIR/proxy-fixture/ca.key" -CAcreateserial -days 2 \
  -extfile "$RUN_DIR/proxy-fixture/lb.ext" -out "$RUN_DIR/proxy-fixture/lb.crt" >/dev/null 2>&1
cat "$RUN_DIR/proxy-fixture/lb.crt" "$RUN_DIR/proxy-fixture/lb.key" >"$RUN_DIR/proxy-fixture/lb.pem"
proxy_port=$(python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1]);s.close()')
cat >"$RUN_DIR/proxy-fixture/lb.cfg" <<EOF
global
    maxconn 128
defaults
    mode http
    timeout connect 5s
    timeout client 300s
    timeout server 300s
frontend public
    bind 127.0.0.1:$proxy_port ssl crt /fixture/lb.pem
    http-request set-header X-Forwarded-For %[src]
    http-request set-header X-Forwarded-Proto https
    default_backend chronicle
backend chronicle
    # The pool listener serves TLS (POOL_LISTENER_TLS=true, the setup default). Its CA is created
    # during setup, after this fixture starts, so the hop is encrypted but unverified here;
    # selfhost-topology verifies it against the stack CA.
    server web 127.0.0.1:$http_port ssl verify none sni str(localhost)
EOF
TLS_PROXY_CONTAINER="${PROJECT}-tls-fixture"
docker run -d --name "$TLS_PROXY_CONTAINER" --network host --read-only --cap-drop ALL \
  --user "$(id -u):$(id -g)" -v "$RUN_DIR/proxy-fixture:/fixture:ro" --entrypoint haproxy \
  "$(sed -n '/image: tecnativa\/docker-socket-proxy/s/^    image: //p' "$BUNDLE/overlays/monitoring.yml")" \
  -W -db -f /fixture/lb.cfg >/dev/null
printf 'connect-to = %s:443:127.0.0.1:%s\ncacert = %s\n' "$SMOKE_PUBLIC_HOST" "$proxy_port" \
  "$RUN_DIR/proxy-fixture/ca.crt" >>"${RUN_DIR}/curl-home/.curlrc"
export CURL_HOME="${RUN_DIR}/curl-home"

setup_release_bundle() { # <clean selfhost directory>
  local bundle="$1"
  shift
  COMPOSE_PROJECT_NAME="$PROJECT" HTTP_PORT="$http_port" INTERNAL_PORT="$internal_port" \
    GRAFANA_PORT="$grafana_port" DOMAIN="$SMOKE_PUBLIC_HOST" SMOKE_PASSWORD="$SMOKE_PASSWORD" \
    ENABLE_MONITORING="$MONITORING" python3 -s "$ROOT_DIR/tests/smoke/selfhost_release_setup.py" "$bundle" "$@"
}

printf 'Installing the signed candidate in a fresh deployment.\n'
setup_release_bundle "$BUNDLE" --backup-storage-encryption-waiver "$BACKUP_ENCRYPTION_WAIVER"
# The isolated ENOSPC fixture needs a smaller WAL reserve than a production deployment.
PYTHONPATH="$BUNDLE" python3 - "$BUNDLE" <<'PY_WAL'
from pathlib import Path
import sys
from chronicle_ops.envfile import set_env_values
from chronicle_ops.receipts import write_text
settings = Path(sys.argv[1]) / ".env"
write_text(settings, set_env_values(settings.read_text(),
           {"POSTGRES_MIN_WAL_SIZE": "32MB", "POSTGRES_MAX_WAL_SIZE": "64MB"}, require_existing=False))
PY_WAL

(
  cd "$BUNDLE"
  config_report="$(./verify-config.sh 2>&1)" ||
    { grep -F FAIL <<<"$config_report" >&2; fail "verify-config failed: $BUNDLE"; }
  compose_args=()
  [[ -f .env ]] || compose_args=(--env-file .env.example)
  docker compose "${compose_args[@]}" config --quiet
  if docker compose "${compose_args[@]}" config --format json | jq -e 'any(.services[]; has("build"))' >/dev/null; then
    fail "extracted release Compose contains a source build: $BUNDLE"
  fi
)

cd "$BUNDLE"
verify_with_dashboard_password() {
  local canary_directory
  canary_directory=$(mktemp -d "$RUN_DIR/mobile-canary.XXXXXX")
  cat "$RUN_DIR/proxy-fixture/ca.crt" \
    "$BUNDLE/tls/$( [[ -f "$BUNDLE/tls/internal-ca.crt" ]] && printf internal-ca.crt || printf internal-cert.pem )" \
    >"$canary_directory/ca.crt"
  printf '%s\n' "$SMOKE_PASSWORD" | python3 "$ROOT_DIR/tests/deployment/selfhost-client.py" \
    --public "https://$SMOKE_PUBLIC_HOST" --management "https://127.0.0.1:$internal_port" \
    --ca "$canary_directory/ca.crt" --resolve-public "127.0.0.1:$proxy_port" \
    --records "$canary_directory/records.json" --mobile-canary "$canary_directory/recipe.json" --seed-only
  PYTHONPATH="$BUNDLE" python3 - "$canary_directory/recipe.json" "https://$SMOKE_PUBLIC_HOST" <<'PY_RELEASE_CANARY'
import sys
from chronicle_ops.mobile_canary import verify_canary
from chronicle_ops.verify import send_canary
verify_canary(sys.argv[1], sys.argv[2], send_canary)
PY_RELEASE_CANARY
  printf '%s\n' "$SMOKE_PASSWORD" | ./chronicle verify --dashboard-password
}
./chronicle check
docker compose config --format json |
  python3 "$ROOT_DIR/tests/security/healthcheck-executables.py" --work-dir "$RUN_DIR"
[[ "$PROJECT" == chronicle-release-smoke-* ]] || fail "capped volume requires the isolated smoke project"
disk_volume="${PROJECT}_postgres_data"
! docker volume inspect "$disk_volume" >/dev/null 2>&1 || fail "smoke database volume already exists"
docker volume create --label "com.docker.compose.project=$PROJECT" \
  --label com.docker.compose.volume=postgres_data --driver local --opt type=tmpfs \
  --opt device=tmpfs --opt "o=size=$DISK_SMOKE_VOLUME_BYTES,nr_inodes=$DISK_SMOKE_VOLUME_INODES,mode=0700" "$disk_volume" >/dev/null
postgres_image=$(docker compose config --format json | jq -er '.services.postgres.image')
# A live reference keeps the bounded tmpfs mounted across database stops and recreations.
DISK_VOLUME_KEEPER=$(timeout "$DISK_DRILL_MAX_SECONDS" docker run --rm -d --user postgres \
  --read-only --cap-drop ALL --security-opt no-new-privileges --network none \
  --memory 8m --pids-limit 8 --entrypoint /bin/sleep \
  --mount "type=volume,source=$disk_volume,target=/hold" "$postgres_image" infinity)
printf 'Starting isolated fresh-install project %s (bounded wait: 300s).\n' "$PROJECT"
START_WAIT_TIMEOUT_SECONDS=300 ./chronicle up
verify_with_dashboard_password
database_encoding="$(docker compose exec -T postgres /bin/bash -ceu \
  'PGPASSWORD="$POSTGRES_PASSWORD" psql -X -qAt -v ON_ERROR_STOP=1 -h 127.0.0.1 -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c "SHOW server_encoding;"')"
[[ "$database_encoding" == UTF8 ]] || fail "fresh database encoding is ${database_encoding}, expected UTF8"
fresh_install=pass

id_range_state="$({
  docker compose exec -T postgres /bin/bash -ceu \
    'PGPASSWORD="$POSTGRES_PASSWORD" psql -h 127.0.0.1 -U "$POSTGRES_USER" -d "$POSTGRES_DB" -tAqc "SELECT count(*) || '\''|'\'' || count(*) FILTER (WHERE msb <> 0) || '\''|'\'' || bool_and(lsb < 0) FROM public.id_gen"'
} | tr -d '[:space:]')"
[[ "$id_range_state" == '65536|0|true' ]] ||
  fail "ID generation ranges are incomplete or do not preserve the initial Range cursor: ${id_range_state}"
printf 'Verified 65,536 partition-safe ID generation ranges.\n'

printf 'Enrolling a real Android client and writing every upload type on the fresh installation.\n'
cat "$RUN_DIR/proxy-fixture/ca.crt" \
  "${BUNDLE}/tls/$( [[ -f "$BUNDLE/tls/internal-ca.crt" ]] && printf internal-ca.crt || printf internal-cert.pem )" \
  >"$RUN_DIR/client-ca.crt"
printf '%s\n' "$SMOKE_PASSWORD" | python3 "$ROOT_DIR/tests/deployment/selfhost-client.py" \
  --public "https://$SMOKE_PUBLIC_HOST" --management "https://127.0.0.1:$internal_port" \
  --ca "$RUN_DIR/client-ca.crt" --resolve-public "127.0.0.1:$proxy_port" --records "$RUN_DIR/client.json" \
  --seed-only
assert_upload_rows() {
  python3 "$ROOT_DIR/tests/deployment/selfhost-client.py" --assert-db --project "$PROJECT" --records "$RUN_DIR/client.json"
}
assert_upload_rows
CHRONICLE_PROXY_BASE_URL="https://127.0.0.1:$internal_port" \
  CHRONICLE_E2E_PUBLIC_BASE_URL="https://127.0.0.1:$proxy_port" \
  CHRONICLE_E2E_DASHBOARD_PASSWORD="$SMOKE_PASSWORD" \
  "$ROOT_DIR/scripts/local-ci.sh" selfhost-browser
# Include aged data in the same-build backup and restore.
docker compose exec -T postgres /bin/bash -ceu \
  'PGPASSWORD="$POSTGRES_PASSWORD" psql -X -q -v ON_ERROR_STOP=1 -h 127.0.0.1 -U "$POSTGRES_USER" -d "$POSTGRES_DB"' <<'SQL_AGED'
CREATE TABLE release_smoke_aged_data AS
SELECT id, now() - interval '6 months' AS collected_at, repeat(md5(id::text), 1024) AS payload
FROM generate_series(1,1024) AS id;
SQL_AGED

printf 'Writing a database sentinel before backup and restore.\n'
docker compose exec -T postgres /bin/bash -ceu \
  'PGPASSWORD="$POSTGRES_PASSWORD" psql -h 127.0.0.1 -U "$POSTGRES_USER" -d "$POSTGRES_DB" -v ON_ERROR_STOP=1 -q' <<'SQL'
CREATE TABLE IF NOT EXISTS release_smoke_sentinel (
  id integer PRIMARY KEY,
  marker text NOT NULL
);
INSERT INTO release_smoke_sentinel (id, marker)
VALUES (1, 'before-backup')
ON CONFLICT (id) DO UPDATE SET marker = EXCLUDED.marker;
SQL

sentinel_marker() {
  docker compose exec -T postgres /bin/bash -ceu \
    'PGPASSWORD="$POSTGRES_PASSWORD" psql -h 127.0.0.1 -U "$POSTGRES_USER" -d "$POSTGRES_DB" -tAqc "SELECT marker FROM release_smoke_sentinel WHERE id = 1"'
}
[[ "$(sentinel_marker)" == before-backup ]] || fail "pre-backup database sentinel is missing"

printf 'Exercising the full device client against the fresh installation.\n'
cp "$RUN_DIR/client-ca.crt" "$RUN_DIR/client-candidate-ca.crt"
candidate_client=(python3 "$ROOT_DIR/tests/deployment/selfhost-client.py"
  --public "https://$SMOKE_PUBLIC_HOST" --management "https://127.0.0.1:$internal_port"
  --ca "$RUN_DIR/client-candidate-ca.crt" --resolve-public "127.0.0.1:$proxy_port"
  --enrollment-credentials "$RUN_DIR/enrollment-credentials.json")
printf '%s\n' "$SMOKE_PASSWORD" | "${candidate_client[@]}" --records "$RUN_DIR/client-candidate.json"
python3 "$ROOT_DIR/tests/deployment/selfhost-client.py" --assert-db --project "$PROJECT" --records "$RUN_DIR/client-candidate.json"
# The upload probes add rows for the same participant, so they run after its receipt is asserted.
printf '%s\n' "$SMOKE_PASSWORD" | "${candidate_client[@]}" --records "$RUN_DIR/client-candidate.json" \
  --upload-security-environment "$RUN_DIR/upload-security.env.sh"
(
  # Generated by the fixture client with shell-quoted values and mode 0600.
  # shellcheck disable=SC1091
  source "$RUN_DIR/upload-security.env.sh"
  bash "$ROOT_DIR/tests/security/run-all-security.sh" upload "$RUN_DIR/upload-security"
)

active_tde_key() {
  docker compose exec -T postgres /bin/bash -ceu \
    'PGPASSWORD="$POSTGRES_PASSWORD" psql -X -qAt -h 127.0.0.1 -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c "SELECT key_name FROM pg_tde_key_info();"'
}

printf 'Rotating the TDE principal key and proving db-init preserves it across reruns.\n'
pre_rotation_key="$(active_tde_key)"
./chronicle rotate-secret --yes tde
rotated_key="$(active_tde_key)"
[[ -n "$rotated_key" && "$rotated_key" != "$pre_rotation_key" ]] \
  || fail "TDE rotation did not advance the active principal key"
docker compose run --rm --no-deps db-init >/dev/null
[[ "$(active_tde_key)" == "$rotated_key" ]] \
  || fail "db-init reset the rotated TDE principal key"
[[ -s "${BUNDLE}/backups/keyring/chronicle-keyring.per" ]] \
  || fail "TDE rotation did not retain a recoverable keyring copy"
verify_with_dashboard_password >/dev/null

service_container() {
  local service="$1" container
  container="$(docker compose ps -q "$service")"
  [[ -n "$container" ]] || fail "service has no container: $service"
  printf '%s' "$container"
}

wait_healthy_container() {
  local container="$1" timeout_seconds="$2" label="$3"
  local started_at=$SECONDS health_state
  while (( SECONDS - started_at < timeout_seconds )); do
    health_state="$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$container")"
    if [[ "$health_state" == healthy ]]; then
      printf '%s is healthy.\n' "$label"
      return 0
    fi
    if [[ "$health_state" == exited || "$health_state" == dead ]]; then
      fail "$label entered state $health_state"
    fi
    sleep 2
  done
  fail "$label did not become healthy within ${timeout_seconds}s"
}

if [[ "$MONITORING" == true ]]; then
  printf 'Proving the supported cAdvisor -> VictoriaMetrics -> Grafana path.\n'
  monitoring_ca="$(PYTHONPATH="$ROOT_DIR/selfhost" python3 - "$BUNDLE" <<'PY_MONITORING_CA'
from pathlib import Path
import sys
from chronicle_ops.envfile import read_env, value

bundle = Path(sys.argv[1])
state = (bundle / (value(read_env(bundle / ".env"), "CHRONICLE_STATE_DIR", ".") or ".")).resolve()
print(state / "tls/monitoring.crt")
PY_MONITORING_CA
)"
  bounded_curl -fsS --cacert "$monitoring_ca" "https://127.0.0.1:${grafana_port}/api/health" | jq -e '.database == "ok"' >/dev/null
  monitoring_deadline=$((SECONDS + 60))
  monitoring_target_ready=false
  while (( SECONDS < monitoring_deadline )); do
    if docker compose exec -T grafana wget -T 10 -qO- http://victoriametrics:8428/api/v1/targets \
      >"${RUN_DIR}/vm-targets.json" &&
      jq -e '.status == "success" and any(.data.activeTargets[]?; .health == "up" and .labels.job == "chronicle-containers")' \
        "${RUN_DIR}/vm-targets.json" >/dev/null; then
      monitoring_target_ready=true
      break
    fi
    sleep 2
  done
  [[ "$monitoring_target_ready" == true ]] || fail "cAdvisor scrape target did not become healthy"

  # `up` is emitted by the VictoriaMetrics scraper for this exact cAdvisor job and is
  # stable across cAdvisor releases. Component-specific informational metric names are not.
  monitoring_deadline=$((SECONDS + 60))
  monitoring_sample_ready=false
  while (( SECONDS < monitoring_deadline )); do
    if docker compose exec -T grafana wget -T 10 -qO- \
      'http://victoriametrics:8428/api/v1/query?query=up%7Bjob%3D%22chronicle-containers%22%7D%20%3D%3D%201' \
      >"${RUN_DIR}/vm-query.json" &&
      jq -e '.status == "success" and (.data.result | length >= 1)' "${RUN_DIR}/vm-query.json" >/dev/null; then
      monitoring_sample_ready=true
      break
    fi
    sleep 2
  done
  [[ "$monitoring_sample_ready" == true ]] || fail "VictoriaMetrics did not ingest the cAdvisor scrape result"
  BUNDLE="$BUNDLE" MONITORING_CA_FILE="$monitoring_ca" GRAFANA_PORT="$grafana_port" python3 - <<'PY'
from base64 import b64encode
import json
import os
from pathlib import Path
import time
import ssl
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

password = ""
for line in (Path(os.environ["BUNDLE"]) / ".env").read_text(encoding="utf-8").splitlines():
    if line.startswith("GRAFANA_ADMIN_PASSWORD="):
        password = line.split("=", 1)[1]
        break
if not password:
    raise SystemExit("generated Grafana password is unavailable")
authorization = b64encode(f"admin:{password}".encode()).decode()
tls = ssl.create_default_context(cafile=os.environ["MONITORING_CA_FILE"])
# The self-signed monitoring certificate has no keyUsage; Python 3.13+ strict mode rejects it
# while browsers and curl accept it. Chain and hostname still verify.
tls.verify_flags &= ~ssl.VERIFY_X509_STRICT
base = f"https://127.0.0.1:{os.environ['GRAFANA_PORT']}"
checks = {
    "/api/datasources/uid/chronicle-victoriametrics": ("uid", "chronicle-victoriametrics"),
    "/api/dashboards/uid/chronicle-containers": ("meta", None),
}
deadline = time.monotonic() + 60
pending = set(checks)
while pending and time.monotonic() < deadline:
    for endpoint in list(pending):
        request = Request(endpoint if endpoint.startswith("http") else base + endpoint)
        request.add_header("Authorization", f"Basic {authorization}")
        try:
            with urlopen(request, timeout=5, context=tls) as response:
                payload = json.load(response)
            key, expected = checks[endpoint]
            if key == "uid" and payload.get(key) == expected:
                pending.remove(endpoint)
            elif key == "meta" and payload.get("dashboard", {}).get("uid") == "chronicle-containers":
                pending.remove(endpoint)
        except (HTTPError, URLError, TimeoutError, json.JSONDecodeError):
            pass
    if pending:
        time.sleep(2)
if pending:
    raise SystemExit(f"Grafana provisioning did not become ready: {sorted(pending)}")
rules = json.loads((Path(os.environ["BUNDLE"]) / "monitoring/grafana-alerting/rules.yml").read_text())
login_rule = next(rule for group in rules["groups"] for rule in group["rules"] if rule["uid"] == "failed-login-spike")
request = Request(base + "/api/ds/query", data=json.dumps({
    "queries": [login_rule["data"][0]["model"]], "from": "now-15m", "to": "now"
}).encode(), headers={"Authorization": f"Basic {authorization}", "Content-Type": "application/json"})
with urlopen(request, timeout=10, context=tls) as response:
    result = json.load(response)["results"]["A"]
if result.get("error") or not any(field["type"] == "number" for frame in result.get("frames", [])
                                  for field in frame["schema"]["fields"]):
    raise SystemExit("Grafana password alert query did not return a numeric failure count")
PY
fi

backup_container="$(service_container db-backup)"
backend_container="$(service_container backend)"
postgres_container="$(service_container postgres)"

printf 'Forcing restart-order inversion: backup first, dependencies unavailable.\n'
backup_restart_started="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
docker stop "$backup_container" "$backend_container" "$postgres_container" >/dev/null
docker start "$backup_container" >/dev/null
sleep 3
[[ "$(docker inspect --format '{{.State.Status}}' "$backup_container")" == running ]] ||
  fail "backup wrapper exited instead of waiting for dependencies"
docker logs --since "$backup_restart_started" "$backup_container" 2>&1 | grep -F 'Waiting for backup dependencies' >/dev/null ||
  fail "backup wrapper did not report dependency waiting"
docker start "$postgres_container" >/dev/null
wait_healthy_container "$postgres_container" 90 'PostgreSQL'
docker start "$backend_container" >/dev/null
wait_healthy_container "$backend_container" 240 'Backend'
wait_healthy_container "$backup_container" 90 'Backup sidecar'
docker logs --since "$backup_restart_started" "$backup_container" 2>&1 | grep -F 'Backup dependencies are ready' >/dev/null ||
  fail "backup wrapper did not hand off after dependency recovery"
printf 'Waiting for a newly published, restore-checked backup.\n'
selfcheck_deadline=$((SECONDS + 600))
while true; do
  backup_log="$(docker logs --since "$backup_restart_started" "$backup_container" 2>&1)"
  ! grep -F 'Restore self-check FAIL' <<<"$backup_log" >&2 || fail "backup restore self-check failed"
  if grep -F 'Restore self-check OK' <<<"$backup_log" >/dev/null &&
      grep -F 'SQL backup created successfully' <<<"$backup_log" >/dev/null; then
    break
  fi
  ((SECONDS < selfcheck_deadline)) || fail "backup publication and restore self-check did not finish"
  sleep 5
done
verify_with_dashboard_password >/dev/null

printf 'Restoring the newest generated dump into the isolated database.\n'
restore_started=$SECONDS
python3 "$ROOT_DIR/tests/deployment/selfhost-client.py" --capture-db --project "$PROJECT" --records "$RUN_DIR/client.json"
CLEAN_RESTORE_SHA256="$(sha256sum "${BUNDLE}/backups/last/chronicle-latest.sql.gz" | awk '{print $1}')"
[[ "$CLEAN_RESTORE_SHA256" =~ ^[0-9a-f]{64}$ ]] || fail "clean restore SHA-256 is unavailable"
# Freeze the selected dump before writing a marker that must disappear on restoration.
CLEAN_RESTORE_FILE="${BUNDLE}/backups/clean-restore-smoke.sql.gz"
cp "${BUNDLE}/backups/last/chronicle-latest.sql.gz" "$CLEAN_RESTORE_FILE"
assert_upload_rows
docker compose exec -T postgres /bin/bash -ceu \
  'PGPASSWORD="$POSTGRES_PASSWORD" psql -X -q -v ON_ERROR_STOP=1 -h 127.0.0.1 -U "$POSTGRES_USER" -d "$POSTGRES_DB"' <<'SQL_MARKER'
INSERT INTO release_smoke_sentinel (id, marker) VALUES (2, 'after-clean-backup');
SQL_MARKER
./chronicle restore /backups/clean-restore-smoke.sql.gz --yes --trusted-sha256="$CLEAN_RESTORE_SHA256"
assert_upload_rows
post_backup_marker="$(docker compose exec -T postgres /bin/bash -ceu \
  'PGPASSWORD="$POSTGRES_PASSWORD" psql -X -qAt -v ON_ERROR_STOP=1 -h 127.0.0.1 -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c "SELECT count(*) FROM release_smoke_sentinel WHERE id = 2"')"
[[ "$post_backup_marker" == 0 ]] || fail "clean restore retained the post-backup marker"
clean_restore_seconds=$((SECONDS - restore_started))
[[ ! -e "${BUNDLE}/.chronicle-restore.lock" ]] || fail "clean restore lock was not released"
verify_with_dashboard_password >/dev/null

printf 'Exhausting the size-capped synthetic database volume and checking recovery.\n'
[[ "$PROJECT" == chronicle-release-smoke-* ]] || fail "disk drill requires the isolated smoke project"
smoke_sql() {
  timeout "$DISK_DRILL_MAX_SECONDS" docker compose exec -T postgres /bin/bash -ceu \
    'PGPASSWORD="$POSTGRES_PASSWORD" psql -X -q -h 127.0.0.1 -U "$POSTGRES_USER" -d "$POSTGRES_DB" -v ON_ERROR_STOP=1'
}
smoke_sql <<'SQL'
CREATE TABLE release_smoke_disk_pressure (payload text);
ALTER TABLE release_smoke_disk_pressure ALTER COLUMN payload SET STORAGE EXTERNAL;
SQL
# The named volume itself is capped; neither the host disk nor another project's data is filled.
# PGDATA's owner writes the file: root has no DAC_OVERRIDE in this container and is refused.
timeout "$DISK_DRILL_MAX_SECONDS" docker compose exec -T -u postgres postgres /bin/bash -ceu '
  total_kb=$(df -Pk "$PGDATA" | awk "NR==2 {print \$2}")
  [[ "$total_kb" =~ ^[0-9]+$ && "$total_kb" -le "$1" ]] || exit 91
  dd if=/dev/zero of="$PGDATA/.chronicle-disk-drill" bs=1M count="$2" 2>/tmp/disk-drill-error && exit 92
  grep -q "No space left on device" /tmp/disk-drill-error
' disk-drill "$((DISK_SMOKE_VOLUME_BYTES / 1024))" "$((DISK_SMOKE_VOLUME_BYTES / 1048576 + 1))" || fail "capped volume did not reach ENOSPC within its bound"
./chronicle doctor --json >"${RUN_DIR}/disk-full-doctor.json" || true
# With the reserve at 0 the full volume is advice on database-disk; the backup reserve on it fails doctor.
jq -e '.overall == "fail"
  and ([.checks[] | select(.check == "database-disk" and .status == "warn")] | length == 1)
  and ([.checks[] | select(.check == "backup-reserve" and .status == "fail")] | length == 1)' \
  "${RUN_DIR}/disk-full-doctor.json" >/dev/null || fail "doctor did not report the full database volume"
if smoke_sql <<'SQL' >"${RUN_DIR}/disk-full-write.log" 2>&1
INSERT INTO release_smoke_disk_pressure SELECT repeat('x', 65536) FROM generate_series(1, 128);
SQL
then
  fail "database writes unexpectedly succeeded on a full volume"
fi
docker compose exec -T -u postgres postgres /bin/bash -ceu 'rm -f "$PGDATA/.chronicle-disk-drill"'
./chronicle up --no-reconcile
docker compose ps --all -q | sort >"${RUN_DIR}/containers-before-reconcile"
CHRONICLE_RECONCILE_RUN=true ./chronicle up --no-reconcile
docker compose ps --all -q | sort >"${RUN_DIR}/containers-after-reconcile"
cmp -s "${RUN_DIR}/containers-before-reconcile" "${RUN_DIR}/containers-after-reconcile" ||
  fail "scheduled up recreated containers with unchanged configuration"
smoke_sql <<'SQL'
INSERT INTO release_smoke_disk_pressure VALUES ('recovered');
DROP TABLE release_smoke_disk_pressure;
SQL
[[ "$(sentinel_marker)" == before-backup ]] || fail "disk recovery lost the restored sentinel"
verify_with_dashboard_password >/dev/null
disk_full_recovery=pass

printf 'Exhausting the inode-capped database volume and checking recovery.\n'
# A throwaway container mounts the volume (PGDATA's root) at /hold, so cleanup works even if
# PostgreSQL stops; its memory limit covers the kernel memory of the filler inodes.
inode_drill() {
  timeout "$DISK_DRILL_MAX_SECONDS" docker run --rm --user postgres --read-only --cap-drop ALL \
    --security-opt no-new-privileges --network none --memory 256m --pids-limit 16 --entrypoint /bin/bash \
    --mount "type=volume,source=$disk_volume,target=/hold" "$postgres_image" -ceu "$@"
}
inode_drill '
  mkdir /hold/.chronicle-inode-drill
  for ((i = 0; i < $1; i++)); do { : >"/hold/.chronicle-inode-drill/$i"; } 2>/dev/null || break; done
  ((i < $1)) || exit 92
  reason=$({ : >/hold/.chronicle-inode-drill/last; } 2>&1) && exit 93
  [[ "$reason" == *"No space left on device"* ]]
' inode-drill "$DISK_SMOKE_VOLUME_INODES" || fail "capped volume did not run out of inodes within its bound"
./chronicle doctor --json >"${RUN_DIR}/inode-full-doctor.json" || true
jq -e '.overall == "fail"
  and ([.checks[] | select(.check == "database-volume-reserve" and .status == "fail")] | length == 1)' \
  "${RUN_DIR}/inode-full-doctor.json" >/dev/null || fail "doctor did not report the exhausted database inodes"
if ./chronicle up --no-reconcile >"${RUN_DIR}/inode-full-up.log" 2>&1; then
  fail "startup accepted a database volume without its inode reserve"
fi
if smoke_sql <<'SQL' >"${RUN_DIR}/inode-full-write.log" 2>&1
CREATE TABLE release_smoke_inode_pressure (id integer);
SQL
then
  fail "a new relation was created on a volume without free inodes"
fi
inode_drill 'rm -rf /hold/.chronicle-inode-drill'
./chronicle up --no-reconcile
smoke_sql <<'SQL'
CREATE TABLE release_smoke_inode_pressure (id integer);
DROP TABLE release_smoke_inode_pressure;
SQL
[[ "$(sentinel_marker)" == before-backup ]] || fail "inode recovery lost the restored sentinel"
verify_with_dashboard_password >/dev/null
inode_full_recovery=pass

printf 'Checking dashboard response headers on the internal listener.\n'
dashboard_user="$(sed -n 's/^DASHBOARD_USER=//p' .env | head -1)"
curl_internal() { # curl_internal <path> [curl args...]
  local path="$1"; shift
  # A 2026.10.3 install keeps its own internal certificate and has no internal-ca.crt.
  bounded_curl -s --cacert "$RUN_DIR/client-candidate-ca.crt" "$@" "https://127.0.0.1:${internal_port}${path}"
}
shell_headers="$(curl_internal /chronicle/ -u "${dashboard_user}:${SMOKE_PASSWORD}" -D - -o /dev/null)"
grep -qi "^content-security-policy: default-src 'self'" <<<"$shell_headers" || fail "dashboard shell lacks a CSP"
grep -qi '^cache-control: no-cache' <<<"$shell_headers" || fail "dashboard shell is cacheable"
chunk_path="$(curl_internal /chronicle/ -u "${dashboard_user}:${SMOKE_PASSWORD}" | grep -oE '/chronicle/chunk-[a-z0-9]+\.js' | head -1)"
[[ -n "$chunk_path" ]] || fail "dashboard shell references no hashed chunk"
curl_internal "$chunk_path" -u "${dashboard_user}:${SMOKE_PASSWORD}" -D - -o /dev/null |
  grep -qi '^cache-control: public, max-age=31536000, immutable' || fail "hashed chunk is not immutable"

printf 'Proving API-created study and researcher permissions survive backend restart.\n'
printf '%s\n' "$SMOKE_PASSWORD" | python3 "$ROOT_DIR/tests/deployment/selfhost-client.py" \
  --create-study --management "https://127.0.0.1:$internal_port" \
  --ca "$RUN_DIR/client-ca.crt" --records "$RUN_DIR/persistent-study.json"
docker compose restart backend >/dev/null
wait_healthy_container "$(service_container backend)" 240 'Backend persistence restart'
printf '%s\n' "$SMOKE_PASSWORD" | python3 "$ROOT_DIR/tests/deployment/selfhost-client.py" \
  --assert-study --management "https://127.0.0.1:$internal_port" \
  --ca "$RUN_DIR/client-ca.crt" --records "$RUN_DIR/persistent-study.json"
study_restart_persistence=pass

printf 'Proving rotated researcher credentials and sessions are refused by the live backend.\n'
dashboard_probe=(python3 "$ROOT_DIR/tests/deployment/selfhost-client.py" --management "https://127.0.0.1:$internal_port"
  --ca "$RUN_DIR/client-ca.crt" --records "$RUN_DIR/persistent-study.json")
session_state() { "${dashboard_probe[@]}" --session-check "$RUN_DIR/$1.json"; }
printf '%s\n' "$SMOKE_PASSWORD" | "${dashboard_probe[@]}" --session-save "$RUN_DIR/session-before-password.json"
[[ "$(session_state session-before-password)" == valid ]] || fail "the saved dashboard session cannot read its study"
rotated_password="smoke-rotated-$(openssl rand -hex 12)"
printf '%s\n%s\n' "$rotated_password" "$rotated_password" | ./chronicle rotate-secret --yes dashboard
printf '%s\n' "$SMOKE_PASSWORD" | "${dashboard_probe[@]}" --expect-login-refused
[[ "$(session_state session-before-password)" == refused ]] || fail "a session from the retired password still reads study data"
SMOKE_PASSWORD="$rotated_password"
printf '%s\n' "$SMOKE_PASSWORD" | "${dashboard_probe[@]}" --session-save "$RUN_DIR/session-before-jwt.json"
./chronicle rotate-secret --yes jwt
[[ "$(session_state session-before-jwt)" == valid ]] || fail "routine JWT rotation ended an active dashboard session"
printf '%s\n' "$SMOKE_PASSWORD" | "${dashboard_probe[@]}" --session-save "$RUN_DIR/session-during-overlap.json"
./chronicle rotate-secret --yes jwt --revoke-sessions
[[ "$(session_state session-before-jwt)" == refused ]] || fail "a session signed with the retired JWT secret is still accepted"
[[ "$(session_state session-during-overlap)" == refused ]] || fail "compromise rotation retained the current-key dashboard session"
printf '%s\n' "$SMOKE_PASSWORD" | "${dashboard_probe[@]}" --session-save "$RUN_DIR/session-after-jwt.json"
docker compose restart backend >/dev/null
wait_healthy_container "$(service_container backend)" 240 'Backend after credential rotation'
for retired in session-before-password session-before-jwt session-during-overlap; do
  [[ "$(session_state "$retired")" == refused ]] || fail "$retired became valid again after backend restart"
done
[[ "$(session_state session-after-jwt)" == valid ]] || fail "the current dashboard session did not survive backend restart"
printf '%s\n' "chronicle-smoke-only-password" | "${dashboard_probe[@]}" --expect-login-refused
# The internal web secret also authorizes the update verifier through a closed ingress.
internal_web_header() {
  PYTHONPATH="$BUNDLE" python3 - "$1" <<'PY_VERIFIER'
import os, sys
from chronicle_ops.envfile import read_env, value
with open(sys.argv[1], "x", opener=lambda path, flags: os.open(path, flags, 0o600)) as output:
    output.write("Authorization: ChronicleUpdate " + value(read_env(".env"), "CHRONICLE_INTERNAL_WEB_SECRET") + "\n")
PY_VERIFIER
}
ingress_fence() { PYTHONPATH="$BUNDLE" python3 -c 'import sys; from chronicle_ops import ingress; getattr(ingress, sys.argv[1])(sys.argv[2])' "$1" "$BUNDLE"; }
fenced_status() { bounded_curl -s -o /dev/null -w '%{http_code}' ${1:+-H "@$1"} "https://$SMOKE_PUBLIC_HOST/chronicle/"; }
internal_web_header "$RUN_DIR/verifier-before.txt"
./chronicle rotate-secret --yes internal-web
internal_web_header "$RUN_DIR/verifier-after.txt"
! cmp -s "$RUN_DIR/verifier-before.txt" "$RUN_DIR/verifier-after.txt" || fail "internal web rotation kept the secret"
open_code="$(fenced_status)"
[[ "$open_code" != 503 ]] || fail "public listener answers 503 with ingress open"
ingress_fence close_ingress
fence_codes="$(fenced_status) $(fenced_status "$RUN_DIR/verifier-before.txt") $(fenced_status "$RUN_DIR/verifier-after.txt")"
ingress_fence open_ingress
rm -f "$RUN_DIR/verifier-before.txt" "$RUN_DIR/verifier-after.txt"
[[ "$fence_codes" == "503 503 $open_code" ]] ||
  fail "update verifier through a closed ingress (none, retired secret, current secret): $fence_codes; open: $open_code"
printf '%s\n' "$SMOKE_PASSWORD" | python3 "$ROOT_DIR/tests/deployment/selfhost-client.py" \
  --assert-study --management "https://127.0.0.1:$internal_port" \
  --ca "$RUN_DIR/client-ca.crt" --records "$RUN_DIR/persistent-study.json"
metrics_credential() {
  PYTHONPATH="$BUNDLE" python3 -c 'import base64; from chronicle_ops.envfile import read_env, value; settings = read_env(".env")
print(base64.b64encode((value(settings, "METRICS_USERNAME", "chronicle-metrics") + ":" + value(settings, "METRICS_PASSWORD")).encode()).decode())'
}
metrics_accepts() { # <base64 credential>: the live backend's own metrics endpoint answers it
  printf '%s\n' "$1" | docker compose exec -T backend sh -c 'IFS= read -r credential
    exec wget -q -O /dev/null --no-check-certificate --header "Authorization: Basic $credential" https://127.0.0.1:8443/prometheus/'
}
retired_metrics="$(metrics_credential)"
metrics_accepts "$retired_metrics" || fail "the backend refused its configured metrics credential"
./chronicle rotate-secret --yes metrics
current_metrics="$(metrics_credential)"
[[ "$current_metrics" != "$retired_metrics" ]] || fail "metrics rotation kept the credential"
! metrics_accepts "$retired_metrics" 2>/dev/null || fail "the backend still accepts the retired metrics credential"
metrics_accepts "$current_metrics" || fail "the backend refused the rotated metrics credential"
retired_metrics=""; current_metrics=""
./chronicle rotate-secret --yes postgres
./chronicle rotate-secret --yes postgres-app
if [[ "$MONITORING" == true ]]; then
  ./chronicle rotate-secret --yes grafana
fi
verify_with_dashboard_password >/dev/null
credential_rotation_consumers=pass

printf 'Renewing expiring service certificates and proving every consumer adopts them.\n'
ca_before="$(sha256sum "$BUNDLE/tls/internal-ca.crt")"
# Short-lived leaves in place of the generated ones: cert-init renews within 30 days of expiry.
expiring_leaf='openssl req -x509 -newkey rsa:2048 -sha256 -days 10 -nodes -keyout "$1/$2.key" -out "$1/$2.crt" -subj "/CN=$2" -addext "subjectAltName=$3" 2>/dev/null'
docker compose run --rm --no-deps --entrypoint /bin/bash cert-init -ceu "
  set -- /postgres-tls postgres DNS:postgres,DNS:localhost,IP:127.0.0.1; $expiring_leaf
  set -- /backend-tls backend DNS:backend,DNS:localhost,IP:127.0.0.1; $expiring_leaf
  openssl x509 -req -in <(openssl req -new -newkey rsa:2048 -nodes -keyout /tls/internal-key.pem -subj /CN=chronicle-dashboard 2>/dev/null) \\
    -CA /tls/internal-ca.crt -CAkey /tls/internal-ca.key -CAcreateserial -days 10 -sha256 \\
    -extfile <(printf 'subjectAltName=DNS:localhost,DNS:web,IP:127.0.0.1\\nextendedKeyUsage=serverAuth\\n') -out /tls/internal-cert.pem 2>/dev/null" >/dev/null
renewed_leaves=(cert-init:/postgres-tls/postgres.crt cert-init:/backend-tls/backend.crt cert-init:/tls/internal-cert.pem)
if [[ "$MONITORING" == true ]]; then
  docker compose run --rm --no-deps --entrypoint /bin/bash monitoring-cert-init -ceu "
    set -- /monitoring-tls monitoring DNS:grafana,DNS:localhost,IP:127.0.0.1; $expiring_leaf" >/dev/null
  renewed_leaves+=(monitoring-cert-init:/monitoring-tls/monitoring.crt)
fi
# A startup interrupted while it recreates services must not record the new certificates as applied.
postgres_before="$(service_container postgres)"
setsid ./chronicle up --no-reconcile >"$RUN_DIR/renewal-interrupted-up.log" 2>&1 &
interrupted_up=$!
renewal_deadline=$((SECONDS + 300))
until [[ "$(docker compose ps -aq postgres)" != "$postgres_before" ]]; do
  ((SECONDS < renewal_deadline)) || fail "startup after certificate renewal did not recreate PostgreSQL"
  sleep 1
done
kill -TERM -- "-$interrupted_up"
! wait "$interrupted_up" || fail "the interrupted startup reported success"
# The operator retries once the interrupted command and its Compose child have exited.
until ! ps -o pid= --sid "$interrupted_up" >/dev/null; do
  ((SECONDS < renewal_deadline)) || fail "the interrupted startup left processes running"
  sleep 1
done
interrupted_up=""
renewal_started="$(date -u '+%Y-%m-%dT%H:%M:%S.%NZ')"
./chronicle up --no-reconcile
for leaf in "${renewed_leaves[@]}"; do
  docker compose run --rm --no-deps --entrypoint /bin/bash "${leaf%%:*}" -ceu 'openssl x509 -checkend $((700 * 86400)) -noout -in "$1"' \
    leaf "${leaf#*:}" >/dev/null || fail "${leaf#*:} was not renewed"
done
[[ "$(sha256sum "$BUNDLE/tls/internal-ca.crt")" == "$ca_before" ]] || fail "certificate renewal replaced the dashboard CA"
for service in postgres backend web db-backup; do
  started="$(docker inspect --format '{{.State.StartedAt}}' "$(service_container "$service")")"
  [[ "$started" > "$renewal_started" ]] || fail "$service was not recreated with the renewed certificate after a failed start"
done
if [[ "$MONITORING" == true ]]; then
  # VictoriaMetrics trusts the backend leaf itself; a stale copy fails this scrape.
  renewal_deadline=$((SECONDS + 120))
  until docker compose exec -T grafana wget -T 10 -qO- http://victoriametrics:8428/api/v1/targets |
      jq -e '.status == "success" and any(.data.activeTargets[]?; .health == "up" and .labels.job == "chronicle-backend")' >/dev/null; do
    ((SECONDS < renewal_deadline)) || fail "backend scrape did not recover with the renewed certificate"
    sleep 5
  done
  bounded_curl -fsS --cacert "$monitoring_ca" "https://127.0.0.1:${grafana_port}/api/health" | jq -e '.database == "ok"' >/dev/null ||
    fail "Grafana is unreachable with the renewed monitoring certificate"
fi
verify_with_dashboard_password >/dev/null
printf '%s\n' "$SMOKE_PASSWORD" | python3 "$ROOT_DIR/tests/deployment/selfhost-client.py" \
  --assert-study --management "https://127.0.0.1:$internal_port" \
  --ca "$RUN_DIR/client-ca.crt" --records "$RUN_DIR/persistent-study.json"
renewal_deadline=$((SECONDS + 600))
while true; do
  backup_log="$(docker logs --since "$renewal_started" "$(service_container db-backup)" 2>&1)"
  ! grep -F 'Restore self-check FAIL' <<<"$backup_log" >&2 || fail "backup restore self-check failed after certificate renewal"
  grep -F 'Restore self-check OK' <<<"$backup_log" >/dev/null && break
  ((SECONDS < renewal_deadline)) || fail "no restore-checked backup after certificate renewal"
  sleep 5
done
certificate_renewal=pass

printf 'Auditing the running self-host containers.\n'
# Every applicable container contract is a release gate. The audit owns explicit N/A cases
# for checks that genuinely do not apply to this configured self-host stack.
container_security_audit=unrun
run_container_security_audit "${RUN_DIR}/container-security.txt"

printf 'Proving the TDE data volume is unreadable without its keyring.\n'
postgres_query() {
  docker compose exec -T postgres /bin/bash -ceu \
    'PGPASSWORD="$POSTGRES_PASSWORD" psql -X -qAt -h 127.0.0.1 -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c "SELECT marker FROM release_smoke_sentinel WHERE id = 1;"'
}
keyring_path=/var/lib/postgresql/tde-keyring/chronicle-keyring.per
docker compose stop backend db-backup postgres >/dev/null
docker compose run --rm --no-deps --entrypoint /bin/sh postgres -ceu "mv '$keyring_path' '$keyring_path.smoke-aside'" \
  || fail "could not move the keyring aside"
docker compose start postgres >/dev/null 2>&1 || true
sleep 5
keyless_output="$(postgres_query 2>&1 || true)"
keyless_output+="$(docker compose logs --tail=50 postgres 2>&1)"
! grep -qx 'before-backup' <<<"$(postgres_query 2>/dev/null || true)" ||
  fail "encrypted data was readable without the keyring"
grep -Eqi 'key provider|principal key' <<<"$keyless_output" ||
  fail "keyless start did not report the missing TDE key"
docker compose stop postgres >/dev/null
docker compose run --rm --no-deps --entrypoint /bin/sh postgres -ceu "mv '$keyring_path.smoke-aside' '$keyring_path'" \
  || fail "could not put the keyring back"
docker compose up -d --wait --wait-timeout 300 >/dev/null
[[ "$(postgres_query)" == before-backup ]] || fail "data did not recover after the keyring was restored"
verify_with_dashboard_password >/dev/null

printf 'Proving the internal password guard rate-limits repeated failures.\n'
sed -i 's/^RATE_LIMIT_GUARD_EVENTS=.*/RATE_LIMIT_GUARD_EVENTS=5/' .env
grep -q '^RATE_LIMIT_GUARD_EVENTS=5$' .env || printf 'RATE_LIMIT_GUARD_EVENTS=5\n' >>.env
docker compose up -d --wait --wait-timeout 120 web >/dev/null
guard_codes="$(for _ in 1 2 3 4 5 6 7 8; do
  printf '%s' '{"password":"wrong-password"}' | curl_internal /chronicle/v3/auth/dashboard-login \
    -H 'Content-Type: application/json' --data-binary @- -o /dev/null -w '%{http_code}\n'
done)"
grep -qx 429 <<<"$guard_codes" || fail "repeated wrong passwords were never rate-limited: $(tr '\n' ' ' <<<"$guard_codes")"
# Caddy writes the 429 itself; it must still carry the security headers and hide the server.
limited_headers="$(printf '%s' '{"password":"wrong-password"}' | curl_internal /chronicle/v3/auth/dashboard-login \
  -H 'Content-Type: application/json' --data-binary @- -o /dev/null -D -)"
grep -q '^HTTP/[0-9.]* 429' <<<"$limited_headers" || fail "the rate-limited login was not answered with 429: $limited_headers"
grep -qi '^Content-Security-Policy:' <<<"$limited_headers" || fail "the Caddy 429 lacks Content-Security-Policy"
grep -qi '^X-Content-Type-Options: nosniff' <<<"$limited_headers" || fail "the Caddy 429 lacks X-Content-Type-Options"
! grep -qi '^Server: Caddy' <<<"$limited_headers" || fail "the Caddy 429 names the server"
if [[ "$MONITORING" == true ]]; then
  login_query_url="$(python3 - "$BUNDLE/monitoring/grafana-alerting/rules.yml" <<'PY_LOGIN_QUERY'
import json
import sys
from urllib.parse import urlencode

with open(sys.argv[1]) as source:
    rules = json.load(source)
rule = next(rule for group in rules["groups"] for rule in group["rules"] if rule["uid"] == "failed-login-spike")
# The alert is a VictoriaMetrics query, so the smoke asks VictoriaMetrics the same question.
print("http://victoriametrics:8428/api/v1/query?" + urlencode({"query": rule["data"][0]["model"]["expr"]}))
PY_LOGIN_QUERY
)"
  login_deadline=$((SECONDS + 60))
  login_failures_visible=false
  while (( SECONDS < login_deadline )); do
    if docker compose exec -T grafana wget -T 10 -qO- "$login_query_url" >"${RUN_DIR}/login-failures.json" &&
        jq -e '(.data.result[0].value[1] // "0" | tonumber) > 0' "${RUN_DIR}/login-failures.json" >/dev/null; then
      login_failures_visible=true
      break
    fi
    sleep 2
  done
  [[ "$login_failures_visible" == true ]] || fail "the password alert query did not observe Caddy guard refusals"
fi

printf 'Qualifying real remote enrollment and persisted uploads through TLS termination.\n'
# Explicit subnets: the bundle default (172.28.0.0/16) may already belong to another stack on this host.
export SELFHOST_TOPOLOGY_SOURCE="$BUNDLE"
TOPOLOGY_SUBNET=10.253.54.0/24 bash "$ROOT_DIR/tests/security/run-all-security.sh" selfhost-topology "$RUN_DIR/topology"
TOPOLOGY_SOURCE_PRESERVING=true TOPOLOGY_SUBNET=10.253.56.0/24 \
  bash "$ROOT_DIR/tests/security/run-all-security.sh" selfhost-topology "$RUN_DIR/topology-source-preserving"
TOPOLOGY_SUBNET=10.253.55.0/24 TOPOLOGY_FORWARD_CLIENT=false \
  bash "$ROOT_DIR/tests/security/run-all-security.sh" selfhost-topology "$RUN_DIR/topology-no-forward"

source "$ROOT_DIR/tests/security/lib/selfhost-python.sh"
SELFHOST_PYTHON_PACKAGE="$BUNDLE" run_selfhost_python_suite test_restore_schemas.FreshVolumeRestoreTests \
  >"$RUN_DIR/fresh-volume-restore.log" 2>&1 || fail 'fresh-volume restore failed'

printf 'Qualifying every k6 benchmark against the enrolled disposable backend.\n'
# Read the peak from the actual benchmark options; its inventory must contain one real
# credential per VU. The initial entry is only for inspect, which performs no requests.
python3 - "$RUN_DIR/enrollment-credentials.json" "$RUN_DIR/benchmark-inspect-devices.json" <<'BENCHMARK_INSPECT'
import json
import os
from pathlib import Path
import sys

credentials = json.loads(Path(sys.argv[1]).read_text())
with open(sys.argv[2], 'x', opener=lambda path, flags: os.open(path, flags, 0o600)) as output:
    json.dump([{'participant_id': credentials['TEST_PARTICIPANT_ID'],
                'random_device_id': credentials['TEST_RANDOM_DEVICE_ID'], 'api_key': credentials['API_KEY']}], output)
BENCHMARK_INSPECT
(
  source "$RUN_DIR/upload-security.env.sh"
  STUDY_ID="$TEST_STUDY_ID" DEVICE_FIXTURES_FILE="$RUN_DIR/benchmark-inspect-devices.json" \
    k6 inspect --include-system-env-vars --execution-requirements "$ROOT_DIR/tests/load/chronicle-load-test.js" \
      >"$RUN_DIR/benchmark-options.json"
)
benchmark_vus="$(jq -er '.maxVUs | select(type == "number" and . > 0 and floor == .)' "$RUN_DIR/benchmark-options.json")"
printf '%s\n' "$SMOKE_PASSWORD" | python3 "$ROOT_DIR/tests/deployment/selfhost-client.py" \
  --public "https://$SMOKE_PUBLIC_HOST" --management "https://127.0.0.1:$internal_port" \
  --ca "$RUN_DIR/client-candidate-ca.crt" --resolve-public "127.0.0.1:$proxy_port" \
  --records "$RUN_DIR/client-candidate.json" --benchmark-device-count "$benchmark_vus" \
  --benchmark-device-fixtures "$RUN_DIR/benchmark-devices.json" \
  --enrollment-credentials "$RUN_DIR/benchmark-credentials.json"
# Rotations above deliberately revoked earlier JWTs; issue a current session and keep
# its credential-bearing environment private rather than placing headers in argv.
printf '%s\n' "$SMOKE_PASSWORD" | "${candidate_client[@]}" --records "$RUN_DIR/client-candidate.json" \
  --enrollment-credentials "$RUN_DIR/benchmark-credentials.json" \
  --upload-security-environment "$RUN_DIR/benchmark.env.sh"

# Public Caddy intentionally denies direct researcher routes. A task-only loopback
# listener exercises their backend contracts without edge throttling. Its upstream
# still verifies the backend certificate, and only researcher paths receive the
# internal-web marker. Derive every network/volume/secret from this owned project.
python3 - "$PROJECT" "$RUN_DIR" <<'BENCHMARK_LISTENER'
import json
import os
from pathlib import Path
import subprocess
import sys

project, folder = sys.argv[1], Path(sys.argv[2])
services = {}
for service in ('backend', 'web'):
    identifier = subprocess.check_output(['docker', 'compose', '-p', project, 'ps', '-q', service], text=True).strip()
    value = json.loads(subprocess.check_output(['docker', 'inspect', identifier], text=True))[0]
    labels = value['Config']['Labels']
    if labels.get('com.docker.compose.project') != project or labels.get('com.docker.compose.service') != service:
        raise RuntimeError('benchmark fixture container ownership mismatch')
    services[service] = value
networks = set(services['backend']['NetworkSettings']['Networks']) & set(services['web']['NetworkSettings']['Networks'])
if len(networks) != 1:
    raise RuntimeError('benchmark requires one shared backend/web network')
trust = [mount for mount in services['web']['Mounts']
         if mount['Destination'] == '/etc/caddy/backend-tls' and mount['Type'] == 'volume']
if len(trust) != 1:
    raise RuntimeError('benchmark backend trust volume is unavailable')
environment = dict(item.split('=', 1) for item in services['backend']['Config']['Env'])
secret = environment['CHRONICLE_INTERNAL_WEB_SECRET']
if not secret or '\n' in secret or '\r' in secret:
    raise RuntimeError('benchmark internal-web capability is invalid')
with open(folder / 'benchmark-listener.env', 'x', opener=lambda path, flags: os.open(path, flags, 0o600)) as output:
    output.write('CHRONICLE_INTERNAL_WEB_SECRET=' + secret + '\n')
(folder / 'benchmark-listener.json').write_text(json.dumps({'network': next(iter(networks)), 'trust': trust[0]['Name']}))
(folder / 'benchmark.Caddyfile').write_text('''{
    admin off
    auto_https off
}
:8080 {
    @researcher path /chronicle/v3/*
    request_header @researcher X-Chronicle-Internal-Web {$CHRONICLE_INTERNAL_WEB_SECRET}
    reverse_proxy https://backend:8443 {
        transport http {
            # HTTP/1.1: over h2 the Go client refuses a request line above Jetty's advertised header bound and
            # caddy answers 502, so the oversized-URI probe would never reach Jetty's 414.
            versions 1.1
            tls_trust_pool file /etc/caddy/backend-tls/backend.crt
        }
    }
}
''')
BENCHMARK_LISTENER
# The release caddy binary carries cap_net_bind_service=ep; the kernel refuses to exec it
# when that capability is outside the bounding set, so keep it as the web service does.
BENCHMARK_LISTENER_CONTAINER="$(docker run -d --name "chronicle-sat-r1-k6-${PROJECT#chronicle-release-smoke-}" \
  --label "chronicle.sat-r1.fixture=$PROJECT" --read-only --user "$(id -u):$(id -g)" \
  --cap-drop ALL --cap-add NET_BIND_SERVICE --security-opt no-new-privileges --memory 128m --pids-limit 64 \
  --network "$(jq -er .network "$RUN_DIR/benchmark-listener.json")" --publish 127.0.0.1::8080 \
  --env-file "$RUN_DIR/benchmark-listener.env" \
  --mount "type=volume,source=$(jq -er .trust "$RUN_DIR/benchmark-listener.json"),target=/etc/caddy/backend-tls,readonly" \
  --mount "type=bind,source=$RUN_DIR/benchmark.Caddyfile,target=/etc/caddy/Caddyfile,readonly" "$CADDY_IMAGE")"
benchmark_endpoint="$(docker port "$BENCHMARK_LISTENER_CONTAINER" 8080/tcp)"
[[ "$benchmark_endpoint" =~ ^127\.0\.0\.1:[0-9]+$ ]] || fail 'benchmark listener is not loopback-only'
(
  source "$RUN_DIR/benchmark.env.sh"
  export BASE_URL="http://$benchmark_endpoint" DEVICE_FIXTURES_FILE="$RUN_DIR/benchmark-devices.json"
  unset MANAGEMENT_URL UPLOAD_CONNECT_TO
  python3 - <<'BENCHMARK_READY'
import json
import os
import time
import urllib.error
import urllib.request

opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
request = urllib.request.Request(os.environ['BASE_URL'] + '/chronicle/v3/study/' + os.environ['TEST_STUDY_ID'],
                                 headers={'Authorization': 'Bearer ' + os.environ['AUTH_TOKEN']})
deadline = time.monotonic() + 30
while True:
    try:
        with opener.open(request, timeout=5) as response:
            if response.status != 200 or json.load(response).get('id') != os.environ['TEST_STUDY_ID']:
                raise RuntimeError('benchmark listener did not read its real fixture study')
        break
    except urllib.error.HTTPError:
        raise
    except urllib.error.URLError:
        if time.monotonic() >= deadline:
            raise
        time.sleep(0.2)
BENCHMARK_READY
  bash "$ROOT_DIR/scripts/local-ci.sh" k6-benchmarks
) >"$RUN_DIR/k6-benchmarks.log" 2>&1 || fail 'k6 benchmark job failed'

{
  echo 'status=passed'
  echo 'fresh_volume_restore=pass'
  echo 'source_free_archive=pass'
  echo 'upload_security=pass'
  echo 'k6_benchmarks=pass'
  echo 'selfhost_topology=pass'
  echo "fresh_install=$fresh_install"
  echo "database_encoding=$database_encoding"
  printf '%s=pass\n' "$same_build_restore_field"
  echo 'tde_rotation_restart_continuity=pass'
  echo 'tde_rotated_keyring_backup=pass'
  echo 'external_boundary_verify=pass'
  echo 'restart_order_recovery=pass'
  echo "study_restart_persistence=$study_restart_persistence"
  echo "credential_rotation_consumers=$credential_rotation_consumers"
  echo "certificate_renewal=$certificate_renewal"
  echo 'clean_restore=pass'
  echo "disk_full_recovery=${disk_full_recovery}"
  echo "inode_full_recovery=${inode_full_recovery}"
  echo "clean_restore_seconds=${clean_restore_seconds}"
  echo 'dashboard_headers=pass'
  echo "container_security_audit=${container_security_audit}"
  echo 'keyless_volume_fails=pass'
  echo 'internal_guard_rate_limit=pass'
  echo 'post_restore_verify=pass'
  echo "monitoring=${MONITORING}"
  [[ "$MONITORING" != true ]] || echo 'monitoring_data_path=pass'
  echo "source_revision=${REVISION}"
  echo "release_version=${RELEASE_VERSION}"
  printf '%s=%s\n' "$SMOKE_ARCHIVE_HASH_FIELD" "$RELEASE_ARCHIVE_SHA256"
} >"${RUN_DIR}/result.txt"
SMOKE_PASSED=true
