#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
source "$ROOT_DIR/tests/security/lib/selfhost-fixtures.sh"
RUN_PARENT="${SELFHOST_VERIFY_TEST_ROOT:-${ROOT_DIR}/build/operator-test-runs/selfhost-verify-secrets}"
REAL_PYTHON="$(command -v python3)"

fail() {
  echo "self-host verify secret-custody test failed: $*" >&2
  exit 1
}

[[ "$RUN_PARENT" == /* ]] || fail "test run parent must be absolute"
case "$RUN_PARENT" in
  /tmp|/tmp/*|/private/tmp|/private/tmp/*|/var/folders|/var/folders/*)
    fail "test run parent must not use a system temporary directory"
    ;;
esac

umask 077
/bin/mkdir -p "$RUN_PARENT"
RUN_DIR="$(/usr/bin/mktemp -d "${RUN_PARENT}/run.XXXXXX")"
/bin/chmod 0700 "$RUN_DIR"
trap '/bin/rm -rf -- "$RUN_DIR"' EXIT

FIXTURE_SELFHOST="${RUN_DIR}/selfhost"
COMMAND_DIR="${RUN_DIR}/commands"
/bin/mkdir -p "$FIXTURE_SELFHOST" "$COMMAND_DIR"
copy_selfhost_setup_fixture "$FIXTURE_SELFHOST"
/bin/chmod 0755 "${FIXTURE_SELFHOST}/chronicle"

# Assert the surviving aggregate zones and their Compose environment transport.
for variable in RATE_LIMIT_MOBILE_ABUSE_EVENTS RATE_LIMIT_WEB_ABUSE_EVENTS; do
  grep -Fq "events {\$${variable}:200}" "${ROOT_DIR}/selfhost/caddy/snippets.caddy" \
    || fail "aggregate abuse zone is missing ${variable}"
done
for variable in RATE_LIMIT_MOBILE_ABUSE_EVENTS RATE_LIMIT_MOBILE_WINDOW RATE_LIMIT_WEB_ABUSE_EVENTS RATE_LIMIT_WEB_WINDOW; do
  grep -Eq "^[[:space:]]+${variable}:.*\\$\\{${variable}" "${ROOT_DIR}/selfhost/docker-compose.yml" \
    || fail "docker-compose.yml does not propagate ${variable} to Caddy"
done

PASSWORD='fixture-"quoted\dashboard-password-never-print-9472'
POSTGRES_SECRET='fixture-postgres-secret-not-for-production'
PASSWORD_FILE="${RUN_DIR}/expected-password"
CURL_ARGS="${RUN_DIR}/curl-args.txt"
DOCKER_ARGS="${RUN_DIR}/docker-args.txt"
CURL_AUTH_MARKERS="${RUN_DIR}/curl-auth-markers.txt"
UPLOAD_COUNT="${RUN_DIR}/upload-count"
POSTGRES_PASSWORD_FILE="${RUN_DIR}/postgres-password"
printf '%s' "$PASSWORD" >"$PASSWORD_FILE"
printf '%s' "$POSTGRES_SECRET" >"$POSTGRES_PASSWORD_FILE"
/bin/chmod 0600 "$PASSWORD_FILE" "$POSTGRES_PASSWORD_FILE"

write_encrypted_storage_fixture "$COMMAND_DIR"
cat >"${FIXTURE_SELFHOST}/.env" <<'EOF'
DOMAIN=chronicle.example.test
COMPOSE_PROJECT_NAME=chronicle-selfhost-verify-fixture
CHRONICLE_STATE_DIR=.
CHRONICLE_CORE_PREFIX=10.252.7
COMPOSE_FILE=docker-compose.yml:overlays/mode-behind-proxy-internal.yml
HTTP_BIND=127.0.0.1
HTTP_PORT=18080
INTERNAL_BIND=127.0.0.1
INTERNAL_PORT=18081
ENABLE_BACKUPS=true
ENABLE_ENCRYPTION=true
RATE_LIMIT_MOBILE_ABUSE_EVENTS=1
RATE_LIMIT_MOBILE_WINDOW=1s
RATE_LIMIT_RETRY_SLEEP=0
DASHBOARD_USER=researcher
POSTGRES_PASSWORD=fixture-postgres-secret-not-for-production
MOBILE_SIGNING_ENABLED=false
MOBILE_SIGNING_REQUIRED=false
MOBILE_SIGNING_SECRET=
MOBILE_SIGNING_SECRET_PREVIOUS=
JWT_SECRET=fixture-jwt-secret-not-for-production
METRICS_PASSWORD=fixture-metrics-secret-not-for-production
CHRONICLE_INTERNAL_WEB_SECRET=fixture-internal-secret-not-for-production
GRAFANA_ADMIN_PASSWORD=fixture-grafana-secret-not-for-production
EOF
/bin/chmod 0600 "${FIXTURE_SELFHOST}/.env"
/bin/mkdir -p "${FIXTURE_SELFHOST}/backups/keyring" "${FIXTURE_SELFHOST}/backups/last"
/bin/chmod 0700 "${FIXTURE_SELFHOST}/backups"
printf 'fixture-keyring\n' >"${FIXTURE_SELFHOST}/backups/keyring/chronicle-keyring.per"
printf '%s\n' '-- PostgreSQL database dump' '\restrict fixture' 'SET statement_timeout = 0;' \
  '\unrestrict fixture' '-- PostgreSQL database dump complete' |
  gzip -c >"${FIXTURE_SELFHOST}/backups/last/chronicle.sql.gz"

cat >"${COMMAND_DIR}/curl" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

for secret_name in DASHBOARD_PASSWORD POSTGRES_PASSWORD MOBILE_SIGNING_SECRET JWT_SECRET \
  METRICS_PASSWORD CHRONICLE_INTERNAL_WEB_SECRET GRAFANA_ADMIN_PASSWORD; do
  [[ -z "${!secret_name+x}" ]] || {
    echo "deployment secret ${secret_name} reached curl environment" >&2
    exit 91
  }
done

expected="$(cat "${SELFHOST_VERIFY_TEST_PASSWORD_FILE}")"
url=""
write_status=false
write_format=''
head_request=false
dump_headers=false
read_config=false
read_config_fd=false
body_stdin=false
device_header=false
request_body=''
cookie_jar=''
previous=""
for argument in "$@"; do
  [[ "$argument" != *"$expected"* ]] || {
    echo "dashboard password reached curl argv" >&2
    exit 92
  }
  printf '%s\n' "$argument" >>"${SELFHOST_VERIFY_TEST_CURL_ARGS}"
  [[ "$argument" == http://* || "$argument" == https://* ]] && url="$argument"
  if [[ "$previous" == -w || "$previous" == --write-out ]]; then
    write_status=true
    write_format="$argument"
  fi
  if [[ "$previous" == -H || "$previous" == --header ]]; then
    [[ "$argument" != 'X-Chronicle-Random-Device-Id: selfhost-verifier' ]] || device_header=true
  fi
  if [[ "$previous" == --data || "$previous" == --data-raw || "$previous" == -d ]]; then
    request_body="$argument"
  fi
  [[ "$argument" == -sI || "$argument" == -I || "$argument" == --head ]] && head_request=true
  if [[ "$previous" == --config && "$argument" == - ]]; then read_config=true; fi
  if [[ "$previous" == --config && "$argument" == /dev/fd/3 ]]; then read_config_fd=true; fi
  if [[ "$previous" == --dump-header && "$argument" == - ]]; then dump_headers=true; fi
  if [[ "$previous" == --data-binary && "$argument" == @- ]]; then body_stdin=true; fi
  if [[ "$previous" == --cookie-jar ]]; then cookie_jar="$argument"; fi
  previous="$argument"
done
[[ -n "$url" ]] || exit 93

if [[ "$body_stdin" == true ]]; then
  request_body="$(cat)"
fi

if [[ "$read_config" == true || "$read_config_fd" == true ]]; then
  if [[ "$read_config_fd" == true ]]; then request_config="$(cat <&3)"; else request_config="$(cat)"; fi
  case "$url" in
    https://127.0.0.1:18081/chronicle/v3/auth/dashboard-login)
      expected_body="$(printf '%s' "$expected" | "${SELFHOST_VERIFY_TEST_REAL_PYTHON}" -c 'import json,sys; print(json.dumps({"password": sys.stdin.read()}), end="")')"
      escaped_body="${expected_body//\\/\\\\}"
      escaped_body="${escaped_body//\"/\\\"}"
      if [[ "$request_config" == "data-binary = \"${escaped_body}\"" ]]; then
        printf '%s\n' correct session-login >>"${SELFHOST_VERIFY_TEST_AUTH_MARKERS}"
        login_code=200
      else
        [[ "$request_config" == *not-the-*-password* ]] || exit 99
        printf '%s\n' wrong >>"${SELFHOST_VERIFY_TEST_AUTH_MARKERS}"
        login_code=401
      fi
      ;;
    https://127.0.0.1:18081/chronicle/v3/auth/session)
      [[ -z "$request_config" && "$*" == *--cookie* ]] || exit 98
      printf '%s\n' session-cookie >>"${SELFHOST_VERIFY_TEST_AUTH_MARKERS}"
      ;;
    https://chronicle.example.test/chronicle/v4/study/*/participant/smoke-*) : ;;
    *) exit 97 ;;
  esac
fi

if [[ "$head_request" == true ]]; then
  printf 'HTTP/2 401\r\nWWW-Authenticate: Basic realm="chronicle"\r\n\r\n'
  exit 0
fi

if [[ "$url" == *'/participant/smoke-'* ]]; then
  "$SELFHOST_VERIFY_TEST_REAL_PYTHON" - "$SELFHOST_VERIFY_TEST_CANARY_FILE" "$url" <<'PY_CANARY_RESPONSE'
import json
import sys
recipe = json.load(open(sys.argv[1]))
name = next(name for name in ('enrollment', 'collection_ack', 'upload') if recipe[name]['url'] == sys.argv[2])
print(json.dumps({'apiKey': recipe['credential']} if name == 'enrollment' else len(recipe[name]['body'])))
print(200)
PY_CANARY_RESPONSE
  exit
fi
code=404
effective_url="$url"
case "$url" in
  http://chronicle.example.test/health)
    [[ "$dump_headers" == true && "$*" == *'--connect-timeout 5'* && "$*" == *'--max-time 10'* ]] || exit 112
    printf 'HTTP/1.1 308 Permanent Redirect\r\nLocation: https://chronicle.example.test/health\r\n\r\n'
    code=308
    ;;
  https://chronicle.example.test/health)
    code=204
    ;;
  https://chronicle.example.test/chronicle|https://chronicle.example.test/chronicle/|https://chronicle.example.test/chronicle/survey)
    code=200
    ;;
  https://chronicle.example.test/privacy)
    # The live proxy follows these anonymous redirects to nonempty Chronicle pages.
    # The focused curl fixture models the final response because it does not implement
    # redirect traversal itself.
    code=200
    effective_url=https://chronicle.example.test/chronicle/privacy
    ;;
  https://chronicle.example.test/withdrawal)
    code=200
    effective_url=https://chronicle.example.test/chronicle/withdrawal
    ;;
  https://chronicle.example.test/reviewer)
    code=200
    effective_url=https://chronicle.example.test/chronicle/reviewer
    ;;
  https://chronicle.example.test/chronicle/v4/study/x/participant/x/enrollment-preview)
    count=0
    [[ ! -f "${SELFHOST_VERIFY_TEST_UPLOAD_COUNT}" ]] || count="$(cat "${SELFHOST_VERIFY_TEST_UPLOAD_COUNT}")"
    count=$((count + 1))
    printf '%s\n' "$count" >"${SELFHOST_VERIFY_TEST_UPLOAD_COUNT}"
    active_dir="${SELFHOST_VERIFY_TEST_UPLOAD_COUNT}.active"
    /bin/mkdir -p "$active_dir"
    active_marker="${active_dir}/${BASHPID}"
    : >"$active_marker"
    sleep 0.1
    active_count="$(/usr/bin/find "$active_dir" -type f | /usr/bin/wc -l | tr -d ' ')"
    /bin/rm -f "$active_marker"
    # The first call is the ordinary reachability probe. The later rate-limit proof only
    # receives 429 when it creates a real concurrent burst; a sequential loop is too slow
    # to exceed the edge's one-second window on a normal TLS listener.
    if (( active_count < 2 )); then code=401; else code=429; fi
    ;;
  https://chronicle.example.test/chronicle/study/x)
    code=404
    ;;
  https://chronicle.example.test/chronicle/v4/study/00000000-0000-0000-0000-000000000000/participant/reviewer/enroll)
    [[ "$device_header" == true ]] || exit 109
    [[ "$request_body" == *'"@class":"com.openlattice.chronicle.sources.AndroidDevice"'* ]] || exit 110
    [[ "$request_body" == *'"randomDeviceId":"selfhost-verifier"'* ]] || exit 111
    code=401
    ;;
  https://127.0.0.1:18081/health)
    code=200
    ;;
  https://127.0.0.1:18081/chronicle/api/web/study)
    code=401
    ;;
  https://127.0.0.1:18081/chronicle/)
    [[ "$read_config" == true ]] && code=200
    ;;
  https://127.0.0.1:18081/chronicle/v3/auth/dashboard-login|https://127.0.0.1:18081/chronicle/v3/auth/session)
    [[ "$read_config" == true ]] && code="${login_code:-200}"
    # Like the backend, each answer sets a fresh CSRF cookie and returns that token.
    csrf="fixture-csrf-${url##*/}"
    [[ -z "$cookie_jar" ]] ||
      printf '# Netscape HTTP Cookie File\n127.0.0.1\tFALSE\t/chronicle\tTRUE\t0\tol_csrf_token\t%s\n' "$csrf" >"$cookie_jar"
    printf '{"authenticated":%s,"csrfToken":"%s"}\n' "$([[ "$code" == 200 ]] && echo true || echo false)" "$csrf"
    ;;
esac

if [[ "$write_status" == true ]]; then
  if [[ "$write_format" == *url_effective* ]]; then
    printf '%s|%s|128' "$code" "$effective_url"
  elif [[ "$write_format" == *size_download* ]]; then
    printf '%s 128' "$code"
  elif [[ "$write_format" == *'\n'* || "$write_format" == *$'\n'* ]]; then
    printf '%s\n' "$code"
  else
    printf '%s' "$code"
  fi
fi
EOF
/bin/chmod 0755 "${COMMAND_DIR}/curl"

cat >"${COMMAND_DIR}/docker" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

for secret_name in DASHBOARD_PASSWORD POSTGRES_PASSWORD MOBILE_SIGNING_SECRET JWT_SECRET \
  METRICS_PASSWORD CHRONICLE_INTERNAL_WEB_SECRET GRAFANA_ADMIN_PASSWORD; do
  [[ -z "${!secret_name+x}" ]] || {
    echo "deployment secret ${secret_name} reached Docker environment" >&2
    exit 101
  }
done

expected_password="$(cat "${SELFHOST_VERIFY_TEST_POSTGRES_PASSWORD_FILE}")"
for argument in "$@"; do
  [[ "$argument" != *"$expected_password"* ]] || {
    echo "PostgreSQL password reached Docker argv" >&2
    exit 102
  }
  printf '%s\n' "$argument" >>"${SELFHOST_VERIFY_TEST_DOCKER_ARGS}"
done

if [[ "$*" == *'exec -T backend grep -qF'*'/server/rendered-config/cors.yaml'* ]]; then
  exit 0
fi
# postgres_sql sends its query on stdin, never in argv.
if [[ "${1:-}" == exec && "${2:-}" == -i && "${3:-}" == "$SELFHOST_VERIFY_TEST_POSTGRES_CONTAINER_ID" ]]; then
  [[ "$(cat)" == *'has_table_privilege('* ]] || exit 120
  printf 't\n'
  exit 0
fi

if [[ "$*" == 'network inspect chronicle-selfhost-verify-fixture_core chronicle-selfhost-verify-fixture_ingress' ]]; then
  printf '%s\n' '[{"Name":"chronicle-selfhost-verify-fixture_core","IPAM":{"Config":[{"Subnet":"10.252.7.0/25"}]},"Containers":{"fixture-web":{"IPv4Address":"10.252.7.2/25"}}},{"Name":"chronicle-selfhost-verify-fixture_ingress","IPAM":{"Config":[{"Subnet":"10.252.7.128/26"}]},"Containers":{"fixture-web-forward":{"IPv4Address":"10.252.7.130/26"},"fixture-web":{"IPv4Address":"10.252.7.160/26"}}}]'
  exit 0
fi
if [[ "${1:-}" == ps || "${1:-} ${2:-}" == 'volume ls' ]]; then exit 0; fi
if [[ "$*" == 'info --format {{.DockerRootDir}}' ]]; then
  printf '%s\n' /fixture/docker
  exit 0
fi
[[ "${1:-}" == compose ]] || exit 103
shift
[[ "${1:-}" == -p ]] || exit 104
shift 2
if [[ "$*" == 'ps -q postgres' ]]; then
  printf '%s\n' "$SELFHOST_VERIFY_TEST_POSTGRES_CONTAINER_ID"
  exit 0
fi
if [[ "$*" == 'ps -q web' ]]; then
  printf '%s\n' fixture-web
  exit 0
fi
if [[ "$*" == 'ps -q web-forward' ]]; then
  printf '%s\n' fixture-web-forward
  exit 0
fi
[[ "${1:-}" == exec ]] || exit 105

IFS= read -r -d '' supplied_password || exit 106
[[ "$supplied_password" == "$expected_password" ]] || exit 107
sql="$(cat)"
if [[ "$sql" == *"a.amname='tde_heap'"* ]]; then
  printf '7\n'
elif [[ "$sql" == *"a.amname<>'tde_heap'"* ]]; then
  printf '0\n'
else
  exit 108
fi
EOF
/bin/chmod 0755 "${COMMAND_DIR}/docker"

canary_setting=$(selfhost_python -c 'from chronicle_ops.mobile_canary import CANARY_FILE_SETTING; print(CANARY_FILE_SETTING)')
canary_file=$(selfhost_python - "$RUN_DIR" <<'PY_CANARY_FIXTURE'
from selfhost_fixture import mobile_canary_fixture
import sys
print(mobile_canary_fixture(sys.argv[1], 'https://chronicle.example.test').path)
PY_CANARY_FIXTURE
)
export "$canary_setting=$canary_file"
export SELFHOST_VERIFY_TEST_CANARY_FILE="$canary_file"

OUTPUT="${RUN_DIR}/verify-output.txt"
set +e
printf '%s\n' "$PASSWORD" | PATH="${COMMAND_DIR}:${PATH}" \
  SELFHOST_VERIFY_TEST_PASSWORD_FILE="$PASSWORD_FILE" \
  SELFHOST_VERIFY_TEST_REAL_PYTHON="$REAL_PYTHON" \
  SELFHOST_VERIFY_TEST_POSTGRES_PASSWORD_FILE="$POSTGRES_PASSWORD_FILE" \
  SELFHOST_VERIFY_TEST_POSTGRES_CONTAINER_ID=fixture-postgres \
  SELFHOST_VERIFY_TEST_CURL_ARGS="$CURL_ARGS" \
  SELFHOST_VERIFY_TEST_DOCKER_ARGS="$DOCKER_ARGS" \
  SELFHOST_VERIFY_TEST_AUTH_MARKERS="$CURL_AUTH_MARKERS" \
  SELFHOST_VERIFY_TEST_UPLOAD_COUNT="$UPLOAD_COUNT" \
  /bin/bash "${FIXTURE_SELFHOST}/chronicle" verify --dashboard-password >"$OUTPUT" 2>&1
verify_status=$?
set -e
if [[ "$verify_status" -ne 0 ]]; then
  diagnostic_count=0
  while IFS= read -r diagnostic_line && ((diagnostic_count < 120)); do
    diagnostic_line="${diagnostic_line//$PASSWORD/[redacted]}"
    diagnostic_line="${diagnostic_line//$POSTGRES_SECRET/[redacted]}"
    diagnostic_line="${diagnostic_line//fixture-jwt-secret-not-for-production/[redacted]}"
    diagnostic_line="${diagnostic_line//fixture-metrics-secret-not-for-production/[redacted]}"
    diagnostic_line="${diagnostic_line//fixture-internal-secret-not-for-production/[redacted]}"
    diagnostic_line="${diagnostic_line//fixture-grafana-secret-not-for-production/[redacted]}"
    printf '%s\n' "$diagnostic_line" >&2
    diagnostic_count=$((diagnostic_count + 1))
  done <"$OUTPUT"
  fail "verify fixture failed (status ${verify_status})"
fi

! grep -Fq "$PASSWORD" "$OUTPUT" || fail "dashboard password was printed"
! grep -Fq "$PASSWORD" "$CURL_ARGS" || fail "dashboard password reached curl argv log"
! grep -Fq "$POSTGRES_SECRET" "$OUTPUT" || fail "PostgreSQL password was printed"
! grep -Fq "$POSTGRES_SECRET" "$DOCKER_ARGS" || fail "PostgreSQL password reached Docker argv log"
[[ "$(grep -Fxc correct "$CURL_AUTH_MARKERS")" == 1 ]] \
  || fail "correct password was not delivered once through curl config stdin"
[[ "$(grep -Fxc wrong "$CURL_AUTH_MARKERS")" == 1 ]] \
  || fail "wrong-password probe did not use curl config stdin"
[[ "$(grep -Fxc session-login "$CURL_AUTH_MARKERS")" == 1 ]] \
  || fail "backend dashboard-login did not receive the password and mint a session"
grep -Fqx -- '--config' "$CURL_ARGS" || fail "curl config stdin was not used"
grep -Fq 'backend issued an authenticated dashboard session' "$OUTPUT" \
  || fail "verify did not confirm a backend-issued dashboard session"
grep -Fq 'Verified' "$OUTPUT" || fail "verify did not reach its success postcondition"

if grep -En 'curl[^#]*(--user|-u)[[:space:]].*DASHBOARD_PASSWORD' \
    "${ROOT_DIR}/selfhost/chronicle" >/dev/null; then
  fail "verify passes DASHBOARD_PASSWORD through curl argv"
fi
if grep -En 'docker exec[^#]*(-e|--env)[[:space:]]+PGPASSWORD' \
    "${ROOT_DIR}/selfhost/chronicle" >/dev/null; then
  fail "verify passes POSTGRES_PASSWORD through Docker argv"
fi

docker_args_before="$(wc -l <"$DOCKER_ARGS" | tr -d ' ')"
/bin/chmod 0644 "${FIXTURE_SELFHOST}/.env"
set +e
PATH="${COMMAND_DIR}:${PATH}" /bin/bash "${FIXTURE_SELFHOST}/chronicle" status \
  >"${RUN_DIR}/insecure-env.log" 2>&1
insecure_status=$?
set -e
[[ "$insecure_status" -ne 0 ]] || fail "operator CLI accepted a world-readable secret file"
grep -Fq '.env is mode 644' "${RUN_DIR}/insecure-env.log" ||
  fail "world-readable .env rejection was not comprehensible"
[[ "$(wc -l <"$DOCKER_ARGS" | tr -d ' ')" == "$docker_args_before" ]] ||
  fail "operator CLI invoked Docker before rejecting an insecure .env"

/bin/chmod 0600 "${FIXTURE_SELFHOST}/.env"
/bin/mv "${FIXTURE_SELFHOST}/.env" "${FIXTURE_SELFHOST}/protected.env"
/bin/ln -s protected.env "${FIXTURE_SELFHOST}/.env"
set +e
PATH="${COMMAND_DIR}:${PATH}" /bin/bash "${FIXTURE_SELFHOST}/chronicle" status \
  >"${RUN_DIR}/symlink-env.log" 2>&1
symlink_status=$?
set -e
[[ "$symlink_status" -ne 0 ]] || fail "operator CLI sourced a symlinked secret file"
grep -Fq '.env must be a regular file' "${RUN_DIR}/symlink-env.log" ||
  fail "symlinked .env rejection was not comprehensible"
[[ "$(wc -l <"$DOCKER_ARGS" | tr -d ' ')" == "$docker_args_before" ]] ||
  fail "operator CLI invoked Docker before rejecting a symlinked .env"
! grep -Fq "$POSTGRES_SECRET" "${RUN_DIR}/insecure-env.log" "${RUN_DIR}/symlink-env.log" ||
  fail "insecure .env rejection printed a deployment secret"

echo "self-host verify secret-custody test passed"
