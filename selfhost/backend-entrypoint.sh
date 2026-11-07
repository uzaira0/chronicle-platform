#!/bin/sh
# Chronicle self-host backend entrypoint.
#
# Two jobs:
#
#  1. Render ./config/*.template into real YAML with envsubst. The backend's config
#     loader reads these; the image ships an EMPTY /server/config, so without this the
#     backend has no database connection at all.
#
#  2. Launch the JVM directly instead of via the Gradle-generated ./bin/chronicle-server.
#     That script hardcodes `--add-modules java.se`, but the image's jlink-built minimal
#     JRE does not include java.se, so it dies at boot with
#     "java.lang.module.FindException: Module java.se not found". Invoking java with an
#     explicit classpath is exactly what the reference deployment does for the same reason.
#
# Defaults below mean a public-client deployment needs no shared mobile key. Public clients
# authenticate with their enrollment-issued per-device API key. envsubst turns an unset
# variable into an empty string, so boolean and numeric fields still need explicit defaults.
set -eu

# Credentials arrive as files written by secrets-init (CHRONICLE_SECRETS_DIR), so the
# container's configuration carries none. Each file sets the variable the config templates
# and Spring read; a variable already set (older Compose files) is left alone.
if [ -n "${CHRONICLE_SECRETS_DIR:-}" ] && [ "${1:-}" = --migrate ]; then
  # migrate connects as the schema owner and reads only that password (secrets-init's migrate volume).
  if [ -z "${POSTGRES_PASSWORD:-}" ]; then
    if [ ! -r "${CHRONICLE_SECRETS_DIR}/postgres-password" ]; then
      echo "FATAL: ${CHRONICLE_SECRETS_DIR}/postgres-password is missing; secrets-init writes it before migrate starts" >&2
      exit 1
    fi
    POSTGRES_PASSWORD=$(cat "${CHRONICLE_SECRETS_DIR}/postgres-password")
    export POSTGRES_PASSWORD
  fi
elif [ -n "${CHRONICLE_SECRETS_DIR:-}" ]; then
  for pair in POSTGRES_APP_PASSWORD:postgres-app-password JWT_SECRET:jwt-secret \
      JWT_SECRET_PREVIOUS:jwt-secret-previous CHRONICLE_SECURITY_METRICS_PASSWORD:metrics-password \
      CHRONICLE_INTERNAL_WEB_SECRET:internal-web-secret CHRONICLE_REVIEWER_ACCESS_SECRET:reviewer-access-secret; do
    variable=${pair%%:*}
    file="${CHRONICLE_SECRETS_DIR}/${pair#*:}"
    eval "current=\${${variable}:-}"
    [ -z "$current" ] || continue
    if [ ! -r "$file" ]; then
      echo "FATAL: $file is missing; secrets-init writes it before the backend starts" >&2
      exit 1
    fi
    value=$(cat "$file")
    export "$variable=$value"
  done
  unset pair variable file current value
fi

if [ "${1:-}" = --migrate ]; then
  [ "$#" -eq 1 ] || exit 1
  : "${POSTGRES_MIGRATION_USER:=${POSTGRES_USER:?POSTGRES_USER is required for migration}}"
  : "${POSTGRES_MIGRATION_JDBC_URL:=jdbc:postgresql://${POSTGRES_HOST:-postgres}:${POSTGRES_PORT:-5432}/${POSTGRES_DB:?POSTGRES_DB is required for migration}?logServerErrorDetail=false&sslmode=${POSTGRES_SSL_MODE:-verify-full}&sslrootcert=${POSTGRES_SSL_ROOT_CERT:-/app/ssl/ca.crt}}"
  umask 077
  migration_password=$(mktemp "${TMPDIR:-/tmp}/chronicle-migration.XXXXXX")
  if [ -n "${POSTGRES_MIGRATION_PASSWORD_FILE:-}" ]; then
    [ -f "$POSTGRES_MIGRATION_PASSWORD_FILE" ] || exit 1
    cat "$POSTGRES_MIGRATION_PASSWORD_FILE" > "$migration_password"
  else
    printf '%s' "${POSTGRES_PASSWORD:?POSTGRES_PASSWORD is required for migration}" > "$migration_password"
  fi
  POSTGRES_MIGRATION_PASSWORD_FILE=$migration_password
  unset POSTGRES_PASSWORD
  export POSTGRES_MIGRATION_USER POSTGRES_MIGRATION_JDBC_URL POSTGRES_MIGRATION_PASSWORD_FILE
  set -- java -Xms64m -Xmx256m -cp '/server/lib/*' com.openlattice.chronicle.upgrades.FlywayMigrationCommand
  if [ "$(id -u)" = 0 ]; then
    chown chronicle:chronicle "$POSTGRES_MIGRATION_PASSWORD_FILE"
    exec su-exec chronicle "$@"
  fi
  exec "$@"
fi

: "${DOMAIN:=localhost}"
: "${CHRONICLE_PUBLIC_BASE_URL:=https://${DOMAIN}}"
: "${POSTGRES_HOST:=postgres}"
: "${POSTGRES_PORT:=5432}"
: "${POSTGRES_DB:=chronicle}"

: "${CHRONICLE_REVIEWER_ACCESS_ENABLED:=false}"
: "${CHRONICLE_REVIEWER_ACCESS_SECRET:=}"
: "${CHRONICLE_REVIEWER_STUDY_ID:=}"
: "${CHRONICLE_REVIEWER_PARTICIPANT_ID:=}"
# X-Chronicle-Internal-Web marks researcher-console traffic so MobileApiSignatureFilter lets
# it through without a mobile HMAC signature. This stack genuinely needs it: Caddy rewrites
# /chronicle/api/web/* to /chronicle/v3/*, which puts dashboard calls squarely inside the
# filter's MOBILE_API_PREFIXES ("/chronicle/v3/study/"), so an unmarked dashboard request is
# rejected as an unsigned upload.
#
# It is therefore a SHARED value, not a per-boot one: Caddy stamps it and the backend
# compares it (in constant time). Production-style self-hosting refuses the historical
# guessable literal "true" (CWE-290).

# CORS allowlist for config/cors.yaml.template. Every host an operator opens the dashboard
# on has to be here: CorsValidationFilter rejects an unlisted Origin, and the failure is
# invisible from the browser — the SPA renders in full, the header reads "awaiting-sso", and
# sign-in never completes. Listing only https://$DOMAIN left the internal-dashboard modes
# broken by construction, since there the researcher API is served *only* on the internal
# listener, whose origin is https://<host>:$INTERNAL_PORT and never equals $DOMAIN.
# INTERNAL_BIND is in the list for the same reason: `./chronicle setup` offers "your VPN or
# management interface" as the answer, and taking that offer makes the dashboard's origin
# https://<that address>:$INTERNAL_PORT. Allowing only the loopback pair assumed every
# operator reaches it through an SSH tunnel, so the offered answer produced a stack that
# started clean, verified clean, and could not be signed in to.
: "${INTERNAL_PORT:=8081}"
: "${INTERNAL_BIND:=127.0.0.1}"
: "${DASHBOARD_ORIGINS:=}"
case "$INTERNAL_BIND" in
  \[*\]) ;;
  *:*) INTERNAL_BIND="[$INTERNAL_BIND]" ;;
esac

validate_https_root_origin() {
  value="$1"
  case "$value" in
    *[[:space:]]*)
      printf 'FATAL: CHRONICLE_PUBLIC_BASE_URL must be an exact HTTPS root origin\n' >&2
      return 1
      ;;
  esac
  if ! printf '%s\n' "$value" | grep -Eq \
    '^https://(\[[0-9A-Fa-f:]+\]|[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?)(:[0-9]{1,5})?$'; then
    printf 'FATAL: CHRONICLE_PUBLIC_BASE_URL must be an exact HTTPS root origin\n' >&2
    return 1
  fi
  authority="${value#https://}"
  case "$authority" in
    *]:*) port="${authority##*:}" ;;
    *:*)
      host="${authority%:*}"
      case "$host" in *:*) port="" ;; *) port="${authority##*:}" ;; esac
      ;;
    *) port="" ;;
  esac
  if [ -n "$port" ] && { [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; }; then
    printf 'FATAL: CHRONICLE_PUBLIC_BASE_URL must be an exact HTTPS root origin\n' >&2
    return 1
  fi
}

validate_https_root_origin "$CHRONICLE_PUBLIC_BASE_URL"
CORS_ALLOWED_ORIGINS_YAML=$(
  for origin in \
    "https://${DOMAIN}" \
    "${CHRONICLE_PUBLIC_BASE_URL}" \
    "https://127.0.0.1:${INTERNAL_PORT}" \
    "https://localhost:${INTERNAL_PORT}" \
    "https://${INTERNAL_BIND}:${INTERNAL_PORT}" \
    "https://${DOMAIN}:${INTERNAL_PORT}" \
    ${DASHBOARD_ORIGINS}; do
    [ -n "$origin" ] && printf '  - "%s"\n' "$origin"
  done | awk '!seen[$0]++'
)
export CORS_ALLOWED_ORIGINS_YAML

: "${TESTING_LOGIN_ENABLED:=false}"
: "${DASHBOARD_PASSWORD_HASH:=}"
: "${JWT_SECRET_PREVIOUS:=}"
: "${JWT_SECRET_PREVIOUS_EXPIRES_AT:=0}"

: "${CHRONICLE_SERVER_XMS:=-Xms512m}"
: "${CHRONICLE_SERVER_XMX:=-Xmx2g}"
: "${CHRONICLE_SERVER_ARGS:=local postgres}"

export DOMAIN POSTGRES_HOST POSTGRES_PORT POSTGRES_DB POSTGRES_APP_PASSWORD \
  CHRONICLE_PUBLIC_BASE_URL JWT_SECRET JWT_SECRET_PREVIOUS JWT_SECRET_PREVIOUS_EXPIRES_AT \
  CHRONICLE_REVIEWER_ACCESS_ENABLED CHRONICLE_REVIEWER_ACCESS_SECRET \
  CHRONICLE_REVIEWER_STUDY_ID CHRONICLE_REVIEWER_PARTICIPANT_ID \
  CHRONICLE_INTERNAL_WEB_SECRET CHRONICLE_RECORD_STAFF_IP TESTING_LOGIN_ENABLED \
  DASHBOARD_PASSWORD_HASH

for required in POSTGRES_APP_PASSWORD JWT_SECRET CHRONICLE_INTERNAL_WEB_SECRET; do
  eval "value=\${$required:-}"
  if [ -z "$value" ]; then
    echo "FATAL: $required is not set — see selfhost/.env.example" >&2
    exit 1
  fi
done

# The AUDIT logger in log4j2.xml writes ONLY to a file under this directory
# (additivity="false"). If it is missing or read-only, the file half of the audit trail --
# the SIEM-facing copy, and the one that outlives the database -- is lost, and nothing
# notices: the backend serves traffic, the health check passes, and ./chronicle verify
# reports a healthy deployment. Refuse to start instead, the same way the production stack
# does.
AUDIT_DIR="${AUDIT_LOG_DIR:-/var/log/chronicle}"
if [ ! -d "$AUDIT_DIR" ]; then
  echo "FATAL: $AUDIT_DIR not mounted (audit logs required)" >&2
  exit 1
fi
if ! touch "$AUDIT_DIR/.write-probe" 2>/dev/null; then
  echo "FATAL: $AUDIT_DIR is not writable by $(id -un) (audit logs required)" >&2
  exit 1
fi
rm -f "$AUDIT_DIR/.write-probe"

RENDERED=/server/rendered-config
mkdir -p "$RENDERED"

for name in rhizome chronicle chronicle-auth mail mobile-security vault cors jetty; do
  src="/server/config/${name}.yaml.template"
  dst="${RENDERED}/${name}.yaml"
  if [ ! -f "$src" ]; then
    echo "FATAL: missing config template $src" >&2
    exit 1
  fi
  envsubst < "$src" > "$dst"
  if [ ! -s "$dst" ]; then
    echo "FATAL: $dst is empty after rendering" >&2
    exit 1
  fi
  # An unresolved ${VAR} means a variable this script does not know about was added to a
  # template. Fail loudly rather than hand the backend YAML it will misparse.
  # shellcheck disable=SC2016  # the literal ${ is intentional, not an expansion
  if grep -q '\${' "$dst"; then
    echo "FATAL: $dst still contains unresolved template variables" >&2
    # shellcheck disable=SC2016
    grep -n '\${' "$dst" >&2
    exit 1
  fi
done

echo "Rendered config into ${RENDERED}:"
find "$RENDERED" -maxdepth 1 -type f -name '*.yaml' -exec basename {} \; | sort | sed 's/^/  /'

# shellcheck disable=SC2086
exec java $CHRONICLE_SERVER_XMS $CHRONICLE_SERVER_XMX \
  -Dhazelcast.socket.bind.any=false \
  -Xss512k -XX:MetaspaceSize=128m -XX:MaxMetaspaceSize=256m \
  -XX:+UseStringDeduplication -XX:MaxGCPauseMillis=200 \
  -XX:+ExitOnOutOfMemoryError \
  -Dlog4j2.formatMsgNoLookups=true \
  -Djava.io.tmpdir=/server/scratch \
  -cp "${RENDERED}:/server/tls:/server/lib/*" \
  com.openlattice.chronicle.ChronicleServer $CHRONICLE_SERVER_ARGS
