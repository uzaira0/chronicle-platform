#!/usr/bin/env bash
# secrets-init: copy the credentials from .env into one volume per consumer, so the
# long-running containers read them from files and their Docker configuration (what
# `docker inspect` shows) carries no secret. One-shot, no network, runs on every `up`;
# Compose restarts the consumers (depends_on restart: true) whenever its inputs change.
#
#   /out/postgres  -> postgres          (uid 26)             postgres-password
#   /out/backend   -> backend           (uid 100, gid 101)   database, JWT, metrics, web-marker secrets
#   /out/operator  -> db-backup, operational-probe, restore (operator uid)   postgres-password
#   /out/database-init -> db-init   (root)                 postgres-password, postgres-app-password
#   /out/migrate   -> migrate       (uid 100, gid 101)   postgres-password
#   /out/guard     -> config-guard  (uid 26 or root)     every credential it checks
#   /out/web       -> web           (uid 10001)          internal-web-secret
#
# Each volume is mounted read-only into its consumers only; files are 0400 for their owner, and
# the guard's are 0440 for group 0 because config-guard runs as root under the monitoring overlay.
# It runs before config-guard, which validates the values it wrote.
set -Eeuo pipefail

fail() { printf 'secrets-init: %s\n' "$1" >&2; exit 1; }

: "${POSTGRES_PASSWORD:?POSTGRES_PASSWORD is required}"
: "${POSTGRES_APP_PASSWORD:?POSTGRES_APP_PASSWORD is required}"
: "${JWT_SECRET:?JWT_SECRET is required}"
: "${METRICS_PASSWORD:?METRICS_PASSWORD is required}"
: "${CHRONICLE_INTERNAL_WEB_SECRET:?CHRONICLE_INTERNAL_WEB_SECRET is required}"
operator_uid="${CHRONICLE_HOST_UID:-0}"
operator_gid="${CHRONICLE_HOST_GID:-0}"
[[ "$operator_uid" =~ ^(0|[1-9][0-9]*)$ && "$operator_gid" =~ ^(0|[1-9][0-9]*)$ ]] ||
  fail "CHRONICLE_HOST_UID and CHRONICLE_HOST_GID must be numeric"

umask 077

# write DIR OWNER NAME VALUE [MODE]: replace DIR/NAME atomically, readable only by OWNER (0400).
write() {
  local directory="$1" owner="$2" name="$3" value="$4" mode="${5:-0400}" temporary
  [[ -d "$directory" ]] || fail "$directory is not mounted"
  temporary="${directory}/.${name}.$$"
  printf '%s' "$value" >"$temporary"
  chown "$owner" "$temporary"
  chmod "$mode" "$temporary"
  mv -f "$temporary" "${directory}/${name}"
}

# own DIR OWNER [MODE]: give DIR to OWNER, list-only for nobody else (0500).
own() {
  [[ -d "$1" ]] || fail "$1 is not mounted"
  chown "$2" "$1"
  chmod "${3:-0500}" "$1"
}

write /out/postgres 26:26 postgres-password "$POSTGRES_PASSWORD"
own /out/postgres 26:26

backend=100:101
write /out/backend "$backend" postgres-app-password "$POSTGRES_APP_PASSWORD"
write /out/backend "$backend" jwt-secret "$JWT_SECRET"
write /out/backend "$backend" jwt-secret-previous "${JWT_SECRET_PREVIOUS:-}"
write /out/backend "$backend" metrics-password "$METRICS_PASSWORD"
write /out/backend "$backend" internal-web-secret "$CHRONICLE_INTERNAL_WEB_SECRET"
write /out/backend "$backend" reviewer-access-secret "${CHRONICLE_REVIEWER_ACCESS_SECRET:-}"
own /out/backend "$backend"

write /out/operator "${operator_uid}:${operator_gid}" postgres-password "$POSTGRES_PASSWORD"
own /out/operator "${operator_uid}:${operator_gid}"

write /out/database-init 0:0 postgres-password "$POSTGRES_PASSWORD"
write /out/database-init 0:0 postgres-app-password "$POSTGRES_APP_PASSWORD"
own /out/database-init 0:0

write /out/migrate "$backend" postgres-password "$POSTGRES_PASSWORD"
own /out/migrate "$backend"

write /out/web 10001:0 internal-web-secret "$CHRONICLE_INTERNAL_WEB_SECRET"
own /out/web 10001:0

guard=26:0
write /out/guard "$guard" postgres-password "$POSTGRES_PASSWORD" 0440
write /out/guard "$guard" postgres-app-password "$POSTGRES_APP_PASSWORD" 0440
write /out/guard "$guard" jwt-secret "$JWT_SECRET" 0440
write /out/guard "$guard" jwt-secret-previous "${JWT_SECRET_PREVIOUS:-}" 0440
write /out/guard "$guard" metrics-password "$METRICS_PASSWORD" 0440
write /out/guard "$guard" internal-web-secret "$CHRONICLE_INTERNAL_WEB_SECRET" 0440
write /out/guard "$guard" reviewer-access-secret "${CHRONICLE_REVIEWER_ACCESS_SECRET:-}" 0440
write /out/guard "$guard" grafana-admin-password "${GRAFANA_ADMIN_PASSWORD:-}" 0440
own /out/guard "$guard" 0550

printf 'secrets-init: wrote the credential files for postgres, backend, the operator services and the one-shot jobs\n'
