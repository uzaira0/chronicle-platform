#!/usr/bin/env bash
# The configuration checks that used to live in `./chronicle check`, moved into a one-shot
# compose service so that `docker compose up -d` cannot start an unsafe deployment. Every
# other service in the stack waits for this one to exit 0.
#
# Only checks that can be answered from configuration alone are here. Three of the checks in
# `./chronicle check` genuinely cannot move, because a container has its own network
# namespace and its own view of the filesystem:
#
#   * whether HTTP_BIND/INTERNAL_BIND is an address this host actually has
#   * whether HTTP_PORT/INTERNAL_PORT is already in use by another process
#   * whether a foreign Compose project of the same name would be adopted
#
# Those stay in `./chronicle check`. On the plain-compose path Docker's own bind error is
# the fallback for the first two, which is later and less clear but not silent.
#
# TLS_MODE and DASHBOARD_EXPOSURE are NOT read from .env here. They are set on this service
# by the mode overlay in COMPOSE_FILE, so what is checked is the overlay that was actually
# composed in -- not a variable that could disagree with it. Composing no mode overlay at
# all leaves them empty and fails below, which is the correct answer for a stack whose web
# listener would publish nothing.
set -uo pipefail

source "$(dirname "${BASH_SOURCE[0]}")/network-policy.sh" || exit 1

parse_public_authority() {
  local authority="$1" port=""
  PUBLIC_HOST=""
  [[ -n "$authority" ]] || return 1
  case "$authority" in
    *[[:space:]]*|*/*|*\?*|*\#*|*@*) return 1 ;;
  esac

  if [[ "$authority" =~ ^\[([0-9A-Fa-f:]+)\](:([0-9]+))?$ ]]; then
    PUBLIC_HOST="${BASH_REMATCH[1]}"
    port="${BASH_REMATCH[3]:-}"
  elif [[ "$authority" =~ ^([A-Za-z0-9.-]+)(:([0-9]+))?$ ]]; then
    PUBLIC_HOST="${BASH_REMATCH[1]}"
    port="${BASH_REMATCH[3]:-}"
  else
    return 1
  fi

  if [[ -n "$port" ]]; then
    [[ "$port" =~ ^[0-9]{1,5}$ ]] || return 1
    ((10#$port >= 1 && 10#$port <= 65535)) || return 1
  fi
  return 0
}

is_valid_ipv4_literal() {
  [[ "$1" != *:* && "$1" != *'['* && "$1" != *']'* ]] && address_bits "$1" >/dev/null
}

is_non_global_ipv4_literal() {
  local host="$1" a b c d
  is_valid_ipv4_literal "$host" || return 1
  IFS=. read -r a b c d <<< "$host"
  a=$((10#$a)); b=$((10#$b)); c=$((10#$c)); d=$((10#$d))

  ((a == 0 || a == 10 || a == 127 || a >= 224)) && return 0
  ((a == 100 && b >= 64 && b <= 127)) && return 0
  ((a == 169 && b == 254)) && return 0
  ((a == 172 && b >= 16 && b <= 31)) && return 0
  ((a == 192 && b == 0 && c == 0)) && return 0
  ((a == 192 && b == 0 && c == 2)) && return 0
  ((a == 192 && b == 88 && c == 99)) && return 0
  ((a == 192 && b == 168)) && return 0
  ((a == 198 && (b == 18 || b == 19))) && return 0
  ((a == 198 && b == 51 && c == 100)) && return 0
  ((a == 203 && b == 0 && c == 113)) && return 0
  return 1
}

# bash 3.2 (macOS /bin/bash) has no case-modifying parameter expansion; lowercase portably.
lowercase() { printf '%s' "$1" | tr '[:upper:]' '[:lower:]'; }

is_non_global_ipv6_literal() {
  local host first_hextet first_value
  host="$(lowercase "$1")"
  [[ "$host" == *:* ]] || return 1
  case "$host" in
    ::|::1|::ffff:*|2001:db8:*|ff*) return 0 ;;
  esac
  first_hextet="${host%%:*}"
  [[ "$first_hextet" =~ ^[0-9a-f]{1,4}$ ]] || return 0
  first_value=$((16#$first_hextet))
  ((first_value >= 0xfc00 && first_value <= 0xfdff)) && return 0
  ((first_value >= 0xfe80 && first_value <= 0xfebf)) && return 0
  return 1
}

is_valid_ipv6_literal() {
  [[ "$1" == *:* && "$1" != *'['* && "$1" != *']'* ]] && address_bits "$1" >/dev/null
}

is_valid_public_dns_name() {
  local host label
  host="$(lowercase "$1")"
  local -a labels
  [[ ${#host} -le 253 && "$host" == *.* && "$host" != .* && "$host" != *. ]] || return 1
  [[ "$host" =~ ^[a-z0-9.-]+$ ]] || return 1
  IFS=. read -r -a labels <<< "$host"
  for label in "${labels[@]}"; do
    [[ -n "$label" && ${#label} -le 63 ]] || return 1
    [[ "$label" =~ ^[a-z0-9]([a-z0-9-]*[a-z0-9])?$ ]] || return 1
  done
  case "$host" in
    localhost|*.localhost|local|*.local|invalid|*.invalid|test|*.test) return 1 ;;
    # RFC 2606 documentation names, and private-use names (RFC 8375, ICANN .internal, .lan).
    example|*.example|example.com|*.example.com|example.net|*.example.net|example.org|*.example.org) return 1 ;;
    internal|*.internal|home.arpa|*.home.arpa|lan|*.lan|corp|*.corp|home|*.home|mail|*.mail) return 1 ;;
  esac
  return 0
}

public_host_is_allowed() {
  local host="$1" normalized
  [[ -n "$host" ]] || return 1
  normalized="$(lowercase "$host")"
  normalized="${normalized%.}"
  if [[ "$host" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]]; then
    is_valid_ipv4_literal "$host" || return 1
    is_non_global_ipv4_literal "$host" && return 1
  elif [[ "$host" == *:* ]]; then
    is_valid_ipv6_literal "$host" || return 1
    is_non_global_ipv6_literal "$host" && return 1
  else
    is_valid_public_dns_name "$normalized" || return 1
  fi
  return 0
}

public_deployment_host_is_allowed() {
  parse_public_authority "$1" || return 1
  public_host_is_allowed "$PUBLIC_HOST"
}

public_root_https_origin_is_allowed() {
  local value="$1" authority
  [[ "$value" == https://* ]] || return 1
  authority="${value#https://}"
  [[ -n "$authority" && "$authority" != "$value" ]] || return 1
  parse_public_authority "$authority" || return 1
  public_host_is_allowed "$PUBLIC_HOST"
}

validate_compose_proxy_subnet() {
  local subnet="$1" trusted="$2" address prefix normalized family bits private=false
  [[ "$subnet" == "$trusted" ]] || return 1
  [[ "$subnet" == */* ]] || return 1
  address="${subnet%/*}"
  prefix="${subnet#*/}"
  [[ "$address" =~ ^(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})$ ]] || return 1
  [[ "$prefix" =~ ^(8|9|1[0-9]|2[0-9]|30)$ ]] || return 1
  normalized="$(address_bits "$address")" || return 1
  read -r family bits <<< "$normalized"
  [[ "$family" == 4 && "${bits:prefix}" != *1* ]] || return 1
  if ((prefix >= 8)) && [[ "${bits:0:8}" == 00001010 ]]; then
    private=true
  elif ((prefix >= 12)) && [[ "${bits:0:12}" == 101011000001 ]]; then
    private=true
  elif ((prefix >= 16)) && [[ "${bits:0:16}" == 1100000010101000 ]]; then
    private=true
  fi
  [[ "$private" == true ]]
}

# CHRONICLE_CORE_PREFIX is the first three octets of the internal core /24 (docker-compose.yml);
# web holds .2 there and the backend trusts forwarded client addresses from that address only
# (Compose derives both from the prefix; ./chronicle verify compares them with the live network).
validate_core_prefix() {
  local prefix="$1" octet first second
  [[ "$prefix" =~ ^(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})$ ]] || return 1
  for octet in "${BASH_REMATCH[@]:1}"; do ((10#$octet <= 255)) || return 1; done
  first=${BASH_REMATCH[1]} second=${BASH_REMATCH[2]}
  ((first == 10 || (first == 172 && second >= 16 && second <= 31) || (first == 192 && second == 168)))
}

# CHRONICLE_ALERT_WEBHOOK_URL carries alert text (and often a token in its path). Off this host it
# must be HTTPS; plain HTTP only to loopback (the default discard port, or a local relay). No
# credentials in the authority, and nothing a shell or YAML quote could break on.
alert_webhook_is_allowed() {
  local url="$1" scheme rest authority host
  [[ -n "$url" && "$url" != *[[:space:]\'\"\\]* ]] || return 1
  [[ "$url" =~ ^(https?)://([^/?#]+)([/?#].*)?$ ]] || return 1
  scheme="${BASH_REMATCH[1]}" authority="${BASH_REMATCH[2]}"
  [[ "$authority" != *@* ]] || return 1
  if [[ "$authority" == \[* ]]; then
    host="${authority%%]*}]"
    rest="${authority#"$host"}"
  else
    host="${authority%%:*}"
    rest="${authority#"$host"}"
  fi
  [[ -n "$host" && ( -z "$rest" || "$rest" =~ ^:[0-9]{1,5}$ ) ]] || return 1
  [[ "$scheme" == https ]] && return 0
  [[ "$(lowercase "$host")" =~ ^(localhost|.+\.localhost|\[::1\]|127\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})$ ]]
}

# A reviewed risk-register reference; setup reads the same rule when it decides POOL_LISTENER_TLS.
pool_plaintext_waived() {
  [[ -n "$1" && "$1" != *CHANGE_ME* ]]
}

valid_session_idle_minutes() {
  local value="$1" numeric
  [[ "$value" =~ ^[0-9]{1,3}$ ]] || return 1
  numeric=$((10#$value))
  ((numeric >= 1 && numeric <= 120))
}

# VictoriaMetrics has no byte cap; it stops writing when free space on the Docker data filesystem
# falls to METRICS_MIN_FREE_DISK_BYTES. Below MIN_FREE_DISK_GIB plus an update's 3 GiB peak
# (chronicle_ops/common.py UPDATE_PEAK_BYTES), metrics alone could fill the disk to the point where
# ./chronicle update refuses. Prints the warning, or nothing. Warn only: it is a sizing choice.
metrics_reserve_shortfall() {
  local floor_gib="${MIN_FREE_DISK_GIB:-}" reserve="${METRICS_MIN_FREE_DISK_BYTES:-8589934592}" needed
  [[ "$floor_gib" =~ ^(0|[1-9][0-9]{0,8})$ ]] || floor_gib=5
  [[ "$reserve" =~ ^[1-9][0-9]{0,18}$ ]] || return 0
  needed=$(( (floor_gib + 3) * 1073741824 ))
  if (( reserve < needed )); then
    printf 'METRICS_MIN_FREE_DISK_BYTES=%s lets metrics fill the disk below what ./chronicle update needs (MIN_FREE_DISK_GIB=%s plus 3 GiB = %s bytes); raise it to at least %s\n' \
      "$reserve" "$floor_gib" "$needed" "$needed"
  fi
}
if [[ "${1:-}" == --metrics-reserve ]]; then
  [[ $# -eq 1 ]] || exit 2
  metrics_reserve_shortfall
  exit 0
fi

# A narrow diagnostic mode lets verify-config.sh exercise the exact classifier used at
# startup without reconstructing an otherwise complete deployment environment.
if [[ "${1:-}" == --validate-public-host ]]; then
  [[ $# -eq 2 ]] || exit 2
  public_deployment_host_is_allowed "$2" && exit 0
  exit 1
fi
if [[ "${1:-}" == --validate-alert-webhook ]]; then
  [[ $# -eq 2 ]] || exit 2
  alert_webhook_is_allowed "$2" && exit 0
  exit 1
fi
if [[ "${1:-}" == --validate-listener-address ]]; then
  [[ $# -eq 2 ]] || exit 2
  is_valid_ipv4_literal "$2" && exit 0
  exit 1
fi
if [[ "${1:-}" == --validate-public-origin ]]; then
  [[ $# -eq 2 ]] || exit 2
  public_root_https_origin_is_allowed "$2" && exit 0
  exit 1
fi
if [[ "${1:-}" == --validate-compose-subnet ]]; then
  [[ $# -eq 3 ]] || exit 2
  validate_compose_proxy_subnet "$2" "$3" && exit 0
  exit 1
fi
if [[ "${1:-}" == --validate-core-prefix ]]; then
  [[ $# -eq 2 ]] || exit 2
  validate_core_prefix "$2" && exit 0
  exit 1
fi
if [[ "${1:-}" == --validate-forwarder-cidrs ]]; then
  [[ $# -eq 2 ]] || exit 2
  validate_dashboard_networks "$2" && exit 0
  exit 1
fi
if [[ "${1:-}" == --pool-plaintext-waived ]]; then
  [[ $# -eq 2 ]] || exit 2
  pool_plaintext_waived "$2" && exit 0
  exit 1
fi
if [[ "${1:-}" == --validate-session-idle-minutes ]]; then
  [[ $# -eq 2 ]] || exit 2
  valid_session_idle_minutes "$2" && exit 0
  exit 1
fi

# The Compose network is IPv4-only. Docker relays a listener bound to an IPv6 address into it through
# its userland proxy, which presents the network gateway as the source of every connection.
IPV4_STACK_NETWORK="The stack network is IPv4: Docker relays an IPv6 listener through a proxy that shows every client as the Docker gateway"
RED=$'\033[31m'; GRN=$'\033[32m'; YEL=$'\033[33m'; BLD=$'\033[1m'; RST=$'\033[0m'
FAILED=0

# The credentials to check: files secrets-init wrote from .env just before this guard ran. Unset
# (a direct run of this script with the values in its environment), they come from the environment.
if [[ -n "${CHRONICLE_SECRETS_DIR:-}" ]]; then
  source "$(dirname "${BASH_SOURCE[0]}")/secret-files.sh"
  load_secret_files "$CHRONICLE_SECRETS_DIR" POSTGRES_PASSWORD:postgres-password \
    POSTGRES_APP_PASSWORD:postgres-app-password JWT_SECRET:jwt-secret JWT_SECRET_PREVIOUS:jwt-secret-previous \
    METRICS_PASSWORD:metrics-password CHRONICLE_INTERNAL_WEB_SECRET:internal-web-secret \
    CHRONICLE_REVIEWER_ACCESS_SECRET:reviewer-access-secret GRAFANA_ADMIN_PASSWORD:grafana-admin-password
fi
ok()   { printf '  %sok%s   %s\n' "$GRN" "$RST" "$1"; }
bad()  { printf '  %sFAIL%s %s\n' "$RED" "$RST" "$1"; FAILED=1; }
warn() { printf '  %swarn%s %s\n' "$YEL" "$RST" "$1"; }

: "${TLS_MODE:=}"
: "${DASHBOARD_EXPOSURE:=}"
: "${COMPOSE_FILE_SELECTION:=}"
: "${BACKUPS_ENABLED:=false}"
: "${MONITORING_ENABLED:=false}"
: "${GRAFANA_ADMIN_PASSWORD:=}"
: "${GRAFANA_BIND:=127.0.0.1}"
: "${GRAFANA_PORT:=3000}"
: "${METRICS_RETENTION:=30d}"
: "${LOGS_RETENTION:=14d}"
: "${METRICS_DISK_BUDGET_BYTES:=5368709120}"
: "${LOGS_MAX_DISK_BYTES:=5368709120}"
: "${METRICS_MIN_FREE_DISK_BYTES:=8589934592}"
: "${FLUENT_BIT_FORWARD_PORT:=24224}"
: "${CHRONICLE_INTERNAL_WEB_SECRET:=}"
: "${CHRONICLE_REVIEWER_ACCESS_ENABLED:=false}"
: "${CHRONICLE_REVIEWER_ACCESS_SECRET:=}"
: "${CHRONICLE_REVIEWER_STUDY_ID:=}"
: "${CHRONICLE_REVIEWER_PARTICIPANT_ID:=}"
: "${ENABLE_ENCRYPTION:=true}"
: "${TESTING_LOGIN_ENABLED:=false}"
: "${CHRONICLE_RECORD_STAFF_IP:=false}"
: "${REQUIRE_MFA:=false}"
: "${HTTP_BIND:=127.0.0.1}"
: "${POOL_LISTENER_TLS:=true}"
: "${POOL_PLAINTEXT_WAIVER:=}"
: "${INTERNAL_BIND:=127.0.0.1}"
: "${INTERNAL_PORT:=8081}"
: "${DASHBOARD_PASSWORD_HASH:=}"
: "${DASHBOARD_ALLOWED_IPS:=}"
: "${CADDY_TRUSTED_PROXIES:=127.0.0.1/32}"
: "${CHRONICLE_SUBNET:=172.28.0.0/16}"
: "${CHRONICLE_CORE_PREFIX:=}"
: "${CHRONICLE_SESSION_IDLE_MINUTES:=15}"
: "${RELEASE_VERSION:=development}"
: "${CHRONICLE_PUBLIC_BASE_URL:=}"

write_configuration_metric() {
  [[ -d /monitoring-metrics && -w /monitoring-metrics ]] || return 0
  local valid="$1" temporary="/monitoring-metrics/.configuration.prom.$$"
  local safe_tls safe_exposure safe_release
  safe_tls="${TLS_MODE//[^A-Za-z0-9_-]/_}"
  safe_exposure="${DASHBOARD_EXPOSURE//[^A-Za-z0-9_-]/_}"
  safe_release="${RELEASE_VERSION//[^A-Za-z0-9_.-]/_}"
  umask 077
  cat >"$temporary" <<EOF
# HELP chronicle_configuration_valid Latest configuration guard result.
# TYPE chronicle_configuration_valid gauge
chronicle_configuration_valid ${valid}
# HELP chronicle_configuration_check_timestamp_seconds Latest configuration guard run.
# TYPE chronicle_configuration_check_timestamp_seconds gauge
chronicle_configuration_check_timestamp_seconds $(date +%s)
# HELP chronicle_configuration_info Non-secret deployment configuration observed by the guard.
# TYPE chronicle_configuration_info gauge
chronicle_configuration_info{tls_mode="${safe_tls}",dashboard_exposure="${safe_exposure}",monitoring="${MONITORING_ENABLED}",version="${safe_release}"} 1
EOF
  chmod 0644 "$temporary"
  mv -f "$temporary" /monitoring-metrics/configuration.prom
}

printf '%sChecking configuration%s\n' "$BLD" "$RST"

# ------------------------------------------------------------------ deployment mode
compose_base_count=0
compose_mode_count=0
compose_seen=$'\n'
if [[ -z "$COMPOSE_FILE_SELECTION" ]]; then
  bad "COMPOSE_FILE is empty — the supported deployment shape cannot be verified"
else
  IFS=: read -r -a compose_files <<< "$COMPOSE_FILE_SELECTION"
  for compose_path in "${compose_files[@]}"; do
    if [[ -z "$compose_path" ]]; then
      bad "COMPOSE_FILE contains an empty path"
      continue
    fi
    case "$compose_seen" in
      *$'\n'"${compose_path}"$'\n'*)
        bad "COMPOSE_FILE contains the same file twice: ${compose_path}"
        continue
        ;;
    esac
    compose_seen+="${compose_path}"$'\n'
    case "$compose_path" in
      docker-compose.yml|*/docker-compose.yml)
        compose_base_count=$((compose_base_count + 1)) ;;
      overlays/mode-behind-proxy-internal.yml|*/overlays/mode-behind-proxy-internal.yml|\
      overlays/mode-own-tls-internal.yml|*/overlays/mode-own-tls-internal.yml|\
      overlays/mode-local-https.yml|*/overlays/mode-local-https.yml)
        compose_mode_count=$((compose_mode_count + 1)) ;;
      overlays/backups.yml|*/overlays/backups.yml|\
      overlays/monitoring.yml|*/overlays/monitoring.yml)
        ;;
      *) bad "unsupported file in COMPOSE_FILE: ${compose_path}" ;;
    esac
  done
  [[ $compose_base_count -eq 1 ]] ||
    bad "COMPOSE_FILE must contain docker-compose.yml exactly once (found ${compose_base_count})"
  [[ $compose_mode_count -eq 1 ]] ||
    bad "COMPOSE_FILE must contain exactly one mode overlay (found ${compose_mode_count})"
fi

if [[ -z "$TLS_MODE" || -z "$DASHBOARD_EXPOSURE" ]]; then
  bad "no deployment mode selected — COMPOSE_FILE has no overlays/mode-*.yml in it."
  printf '       The web listener would publish no ports at all. Copy the COMPOSE_FILE line\n'
  printf '       from .env.example, or pick one of:\n'
  printf '         overlays/mode-behind-proxy-internal.yml   (recommended)\n'
  printf '         overlays/mode-own-tls-internal.yml\n'
  printf '         overlays/mode-local-https.yml             (laptop trial, no domain)\n'
else
  case "${TLS_MODE}/${DASHBOARD_EXPOSURE}" in
    local-https/internal)
      ok "deployment mode: local trial (Caddy's own CA, no domain name needed)"
      warn "This is a TRIAL mode. The certificate is signed by a CA that exists only inside this stack, so every device must install it first — fine for your own test phones, wrong for participants. Move to mode-behind-proxy-internal or mode-own-tls-internal for a real study." ;;
    behind-proxy/internal|own-tls/internal)
      ok "deployment mode: TLS_MODE=${TLS_MODE}, DASHBOARD_EXPOSURE=${DASHBOARD_EXPOSURE}" ;;
    *)
      bad "unrecognised mode overlay (TLS_MODE='${TLS_MODE}', DASHBOARD_EXPOSURE='${DASHBOARD_EXPOSURE}')" ;;
  esac
fi

# A misspelled boolean must not silently turn off encryption, backups, authentication, or
# MFA. Compose passes these values as strings, so validate the contract before branching.
for flag in BACKUPS_ENABLED MONITORING_ENABLED ENABLE_ENCRYPTION \
            TESTING_LOGIN_ENABLED REQUIRE_MFA CHRONICLE_REVIEWER_ACCESS_ENABLED \
            CHRONICLE_RECORD_STAFF_IP POOL_LISTENER_TLS; do
  case "${!flag}" in
    true|false) ;;
    *) bad "${flag} must be exactly true or false (received '${!flag}')" ;;
  esac
done

# These apply only before authentication; normal authenticated requests bypass them.
for setting in RATE_LIMIT_MOBILE_ABUSE_EVENTS RATE_LIMIT_WEB_ABUSE_EVENTS RATE_LIMIT_GUARD_EVENTS; do
  if [[ ! "${!setting:-200}" =~ ^[1-9][0-9]{0,6}$ ]] || (( ${!setting:-200} > 1000000 )); then
    bad "${setting} must be a decimal integer from 1 through 1000000"
  fi
done
if invalid_windows=$(PYTHONPATH="$(dirname "${BASH_SOURCE[0]}")" python3 -c '
import sys
from chronicle_ops.startup import valid_caddy_duration
for name, raw in zip(sys.argv[1::2], sys.argv[2::2]):
    if not valid_caddy_duration(raw):
        print(name)' RATE_LIMIT_MOBILE_WINDOW "${RATE_LIMIT_MOBILE_WINDOW:-1s}" \
        RATE_LIMIT_WEB_WINDOW "${RATE_LIMIT_WEB_WINDOW:-1s}" \
        RATE_LIMIT_GUARD_WINDOW "${RATE_LIMIT_GUARD_WINDOW:-1m}"); then
  for setting in $invalid_windows; do
    bad "${setting} must be a positive Caddy duration representable in nanoseconds (at most 128 characters)"
  done
else
  bad "RATE_LIMIT windows could not be validated"
fi

# Each consumer reads these late or not at all: env.sh does retention arithmetic on them
# (a word evaluates to 0 days) and the JVM rejects -Xmx at start. Empty means Compose's default
# applies.
[[ -z "${MIN_FREE_DISK_GIB:-}" || "$MIN_FREE_DISK_GIB" =~ ^(0|[1-9][0-9]{0,8})$ ]] ||
  bad "MIN_FREE_DISK_GIB must be a non-negative decimal integer (received '${MIN_FREE_DISK_GIB}')"
for setting in BACKUP_KEEP_DAYS BACKUP_KEEP_WEEKS BACKUP_KEEP_MONTHS; do
  [[ -z "${!setting:-}" || "${!setting}" == all || "${!setting}" =~ ^(0|[1-9][0-9]{0,8})$ ]] ||
    bad "${setting} must be all or a non-negative decimal integer (received '${!setting}')"
done
[[ -z "${PRE_OP_BACKUP_KEEP_DAYS:-}" || "$PRE_OP_BACKUP_KEEP_DAYS" == all || "$PRE_OP_BACKUP_KEEP_DAYS" =~ ^[1-9][0-9]{0,3}$ ]] ||
  bad "PRE_OP_BACKUP_KEEP_DAYS must be all or 1 to 9999 days (received '${PRE_OP_BACKUP_KEEP_DAYS}')"
# Backup verification, doctor and the stale-backup alert derive "overdue" from this schedule.
if ! schedule_error=$(PYTHONPATH="$(dirname "${BASH_SOURCE[0]}")" python3 -c '
import sys
from chronicle_ops.dump import backup_max_age_seconds
try:
    backup_max_age_seconds(sys.argv[1])
except ValueError as error:
    sys.exit(str(error))' "${BACKUP_SCHEDULE:-}" 2>&1); then
  bad "$schedule_error"
fi
[[ -z "${BACKEND_XMS:-}" || "$BACKEND_XMS" =~ ^-Xms[1-9][0-9]*[kKmMgG]?$ ]] ||
  bad "BACKEND_XMS must look like -Xms512m (received '${BACKEND_XMS}')"
[[ -z "${BACKEND_XMX:-}" || "$BACKEND_XMX" =~ ^-Xmx[1-9][0-9]*[kKmMgG]?$ ]] ||
  bad "BACKEND_XMX must look like -Xmx2g (received '${BACKEND_XMX}')"

if valid_session_idle_minutes "$CHRONICLE_SESSION_IDLE_MINUTES"; then
  ok "session idle timeout: ${CHRONICLE_SESSION_IDLE_MINUTES} minutes"
else
  bad "CHRONICLE_SESSION_IDLE_MINUTES must be a decimal integer from 1 through 120"
fi

# ------------------------------------------------------------------ secrets
# Placeholder detection has to be separate from the length check: the shipped placeholders
# are long enough to pass a length test and would otherwise sail through.
placeholders=""
for k in DOMAIN POSTGRES_PASSWORD POSTGRES_APP_PASSWORD CHRONICLE_INTERNAL_WEB_SECRET JWT_SECRET METRICS_PASSWORD; do
  case "${!k:-}" in
    *CHANGE_ME*|*chronicle.example*|"") placeholders="${placeholders}${k} " ;;
  esac
done
if [[ "$MONITORING_ENABLED" == true ]]; then
  case "$GRAFANA_ADMIN_PASSWORD" in
    *CHANGE_ME*|*changeme*|admin|"") placeholders="${placeholders}GRAFANA_ADMIN_PASSWORD " ;;
  esac
fi
if [[ -n "${placeholders// }" ]]; then
  bad "still at placeholder/empty values: ${placeholders}"
  printf '       Edit .env — these are the values only you can supply.\n'
else
  ok "every value this deployment uses has been set"
fi

# In every other mode DOMAIN is a name someone else resolves. Here it is the address the
# phones dial directly, so `localhost` is not merely unusual -- it is unreachable from any
# device but this one, and Caddy cannot issue a LAN certificate for it either.
if [[ "$TLS_MODE" == local-https ]]; then
  local_https_port="${LOCAL_HTTPS_PORT:-443}"
  local_http_port="${LOCAL_HTTP_PORT:-80}"
  case "$local_https_port" in
    ''|*[!0-9]*) bad "LOCAL_HTTPS_PORT must be a numeric TCP port" ;;
    *) ((local_https_port >= 1 && local_https_port <= 65535)) || bad "LOCAL_HTTPS_PORT must be between 1 and 65535" ;;
  esac
  case "$local_http_port" in
    ''|*[!0-9]*) bad "LOCAL_HTTP_PORT must be a numeric TCP port" ;;
    *) ((local_http_port >= 1 && local_http_port <= 65535)) || bad "LOCAL_HTTP_PORT must be between 1 and 65535" ;;
  esac
  [[ "$local_http_port" != "$local_https_port" ]] ||
    bad "LOCAL_HTTP_PORT and LOCAL_HTTPS_PORT must be different"
  case "$DOMAIN" in
    localhost|127.*|0.0.0.0|"")
      bad "DOMAIN=${DOMAIN:-<empty>} cannot be reached by a phone."
      printf '       In this mode DOMAIN is the address the phones dial. Set it to this\n'
      printf '       machine'"'"'s address on the wifi, e.g. DOMAIN=192.168.1.50.\n' ;;
    *)
      if public_deployment_host_is_allowed "$DOMAIN"; then
        bad "local trial mode must use a private LAN address, not a public hostname or routable IP (DOMAIN=${DOMAIN})"
        printf '       For a public name use overlays/mode-behind-proxy-internal.yml or mode-own-tls-internal.yml.\n'
      fi
      local_trial_origin="https://${DOMAIN}"
      [[ "$local_https_port" == 443 ]] || local_trial_origin+=":${local_https_port}"
      if [[ -n "$CHRONICLE_PUBLIC_BASE_URL" && "$CHRONICLE_PUBLIC_BASE_URL" != "$local_trial_origin" ]]; then
        bad "local trial CHRONICLE_PUBLIC_BASE_URL must be empty or exactly ${local_trial_origin}"
      else
        ok "phones will reach this stack at ${local_trial_origin}"
      fi
      ;;
  esac
else
  if ! public_deployment_host_is_allowed "$DOMAIN"; then
    bad "DOMAIN must be a public DNS name or globally routable IP address in production modes"
  fi
  effective_public_base_url="${CHRONICLE_PUBLIC_BASE_URL:-https://${DOMAIN}}"
  if ! public_root_https_origin_is_allowed "$effective_public_base_url"; then
    bad "CHRONICLE_PUBLIC_BASE_URL must be an HTTPS root origin with a public DNS name or globally routable IP address"
  fi
fi

for s in POSTGRES_PASSWORD POSTGRES_APP_PASSWORD CHRONICLE_INTERNAL_WEB_SECRET; do
  v="${!s:-}"
  if [[ -z "$v" ]]; then bad "$s is not set"
  elif [[ ${#v} -lt 16 ]]; then bad "$s is only ${#v} characters; use at least 16"
  fi
done

# 32, not 16, and it is a hard requirement rather than advice: JWT_SECRET is an HS256
# signing key, and Spring's NimbusJwtDecoder rejects anything under 256 bits outright with
# "The secret length must be at least 256 bits". Nothing about that is visible at startup --
# the backend boots, reports healthy, and serves the dashboard. The failure appears only
# when someone logs in, as HTTP 500 "configured testing token is invalid", which reads as a
# broken build rather than a short string in .env. A hand-typed passphrase lands under 32
# characters very easily; `openssl rand -base64 32` gives 44.
v="${JWT_SECRET:-}"
if [[ -z "$v" ]]; then
  bad "JWT_SECRET is not set"
elif [[ ${#v} -lt 32 ]]; then
  bad "JWT_SECRET is only ${#v} characters; HS256 needs at least 32 (256 bits)"
  printf '       Below that, the dashboard signs in and fails with 500 "configured testing\n'
  printf '       token is invalid". Generate one: openssl rand -base64 32\n'
fi
if [[ ! "${DASHBOARD_SESSION_MINUTES:-480}" =~ ^[1-9][0-9]{0,4}$ ]]; then
  bad "DASHBOARD_SESSION_MINUTES must be a whole number of minutes, for example 480"
fi
if [[ -n "${JWT_SECRET_PREVIOUS:-}" ]]; then
  if [[ ${#JWT_SECRET_PREVIOUS} -lt 32 || "$JWT_SECRET_PREVIOUS" == "$JWT_SECRET" || "$JWT_SECRET_PREVIOUS" == *CHANGE_ME* ]]; then
    bad "JWT_SECRET_PREVIOUS must be a distinct generated secret of at least 32 characters"
  fi
  if [[ ! "${JWT_SECRET_PREVIOUS_EXPIRES_AT:-}" =~ ^[1-9][0-9]{0,10}$ ]]; then
    bad "JWT_SECRET_PREVIOUS_EXPIRES_AT must be absolute Unix seconds when JWT_SECRET_PREVIOUS is set"
  elif [[ "${DASHBOARD_SESSION_MINUTES:-480}" =~ ^[1-9][0-9]{0,4}$ ]] &&
      (( JWT_SECRET_PREVIOUS_EXPIRES_AT > $(date +%s) + ${DASHBOARD_SESSION_MINUTES:-480} * 60 )); then
    bad "JWT_SECRET_PREVIOUS_EXPIRES_AT must not exceed one dashboard session from now"
  fi
elif [[ "${JWT_SECRET_PREVIOUS_EXPIRES_AT:-0}" != 0 ]]; then
  bad "JWT_SECRET_PREVIOUS_EXPIRES_AT requires JWT_SECRET_PREVIOUS"
fi
if [[ ${#CHRONICLE_INTERNAL_WEB_SECRET} -lt 32 ]]; then
  bad "CHRONICLE_INTERNAL_WEB_SECRET is ${#CHRONICLE_INTERNAL_WEB_SECRET} characters; use at least 32"
fi
if [[ "$CHRONICLE_REVIEWER_ACCESS_ENABLED" == true ]]; then
  case "$CHRONICLE_REVIEWER_ACCESS_SECRET" in
    *CHANGE_ME*|"")
      bad "CHRONICLE_REVIEWER_ACCESS_SECRET must be a generated 32+ character secret when reviewer access is enabled" ;;
    *)
      if [[ ${#CHRONICLE_REVIEWER_ACCESS_SECRET} -lt 32 || ${#CHRONICLE_REVIEWER_ACCESS_SECRET} -gt 256 ]]; then
        bad "CHRONICLE_REVIEWER_ACCESS_SECRET must be 32-256 characters"
      elif [[ "$CHRONICLE_REVIEWER_ACCESS_SECRET" =~ [[:space:]] ]]; then
        bad "CHRONICLE_REVIEWER_ACCESS_SECRET must not contain whitespace"
      fi ;;
  esac
  if [[ ! "$CHRONICLE_REVIEWER_STUDY_ID" =~ ^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$ ]]; then
    bad "CHRONICLE_REVIEWER_STUDY_ID must be the UUID of the synthetic reviewer study"
  fi
  if [[ ! "$CHRONICLE_REVIEWER_PARTICIPANT_ID" =~ ^[a-zA-Z0-9_.-]{1,255}$ ]]; then
    bad "CHRONICLE_REVIEWER_PARTICIPANT_ID must be a non-PII Chronicle participant ID"
  fi
else
  ok "Google Play reviewer bootstrap is disabled"
fi
# The backend hard-fails at startup below 32 (MetricsAuthenticationFilter), so catch it
# here rather than in a crash loop that looks like a broken image.
if [[ ${#METRICS_PASSWORD} -lt 32 ]]; then
  bad "METRICS_PASSWORD is ${#METRICS_PASSWORD} characters; the backend refuses to start below 32"
fi
[[ $FAILED -eq 0 ]] && ok "secrets are set and long enough"

if [[ "$MONITORING_ENABLED" == true ]]; then
  if [[ ${#GRAFANA_ADMIN_PASSWORD} -lt 32 ]]; then
    bad "GRAFANA_ADMIN_PASSWORD is ${#GRAFANA_ADMIN_PASSWORD} characters; use at least 32"
  fi
  if ! specific_private_bind "$GRAFANA_BIND"; then
    bad "GRAFANA_BIND=${GRAFANA_BIND} exposes the monitoring dashboard on every interface"
    printf '       Keep it on 127.0.0.1 and use an SSH tunnel, or bind one reviewed private address.\n'
  fi
  if [[ ! "$GRAFANA_PORT" =~ ^[1-9][0-9]*$ ]] || (( GRAFANA_PORT > 65535 )); then
    bad "GRAFANA_PORT must be an integer from 1 through 65535"
  fi
  if [[ ! "$FLUENT_BIT_FORWARD_PORT" =~ ^[1-9][0-9]*$ ]] || (( FLUENT_BIT_FORWARD_PORT > 65535 )); then
    bad "FLUENT_BIT_FORWARD_PORT must be an integer from 1 through 65535"
  fi
  [[ "$METRICS_RETENTION" =~ ^[1-9][0-9]*d$ ]] || bad "METRICS_RETENTION must be whole days, for example 30d"
  [[ "$LOGS_RETENTION" =~ ^[1-9][0-9]*d$ ]] || bad "LOGS_RETENTION must be whole days, for example 14d"
  for budget in METRICS_DISK_BUDGET_BYTES LOGS_MAX_DISK_BYTES METRICS_MIN_FREE_DISK_BYTES; do
    if [[ ! "${!budget}" =~ ^[1-9][0-9]*$ ]] || (( ${!budget} < 268435456 )); then
      bad "${budget} must be an integer of at least 268435456 bytes (256 MiB)"
    fi
  done
  metrics_reserve_warning="$(metrics_reserve_shortfall)"
  [[ -z "$metrics_reserve_warning" ]] || warn "$metrics_reserve_warning"
  if [[ $FAILED -eq 0 ]]; then
    ok "optional monitoring is private, bounded, and uses a non-default Grafana credential"
  fi
fi

# ------------------------------------------------------------------ encryption / backups
# Encryption without backups is a trap, not a safeguard. Losing the keyring makes the data
# volume permanently unreadable -- pg_dump cannot rescue it either -- and the only key-free
# copy of the data is the plain-SQL dumps the backups overlay writes.
if [[ "$TLS_MODE" != local-https && -n "$TLS_MODE" && "$BACKUPS_ENABLED" != true ]]; then
  bad "production deployment modes require overlays/backups.yml in COMPOSE_FILE."
  printf '       A production install without a recoverable dump is not a supported Chronicle\n'
  printf '       configuration. Add the backups overlay. Only local-https trial mode may run\n'
  printf '       without it, and only when ENABLE_ENCRYPTION=false.\n'
elif [[ "$ENABLE_ENCRYPTION" == true && "$BACKUPS_ENABLED" != true ]]; then
  bad "encryption at rest is on, but overlays/backups.yml is not in COMPOSE_FILE."
  printf '       Encrypted data is unrecoverable if the keyring is lost; the plain-SQL dumps\n'
  printf '       in ./backups are the only copy that needs no key. Add the backups overlay,\n'
  printf '       or set ENABLE_ENCRYPTION=false to run without encryption at rest.\n'
elif [[ "$ENABLE_ENCRYPTION" == true ]]; then
  ok "encryption at rest on, with key-free SQL dumps in ./backups"
else
  warn "encryption at rest is OFF (ENABLE_ENCRYPTION=false)"
fi
if [[ "$BACKUPS_ENABLED" == true ]]; then
  warn "SQL dumps in ./backups are unencrypted participant data on this host (directory 0700, operator-owned). Encrypt before any off-host copy: docs/BACKUP-RESTORE.md"
fi

# ------------------------------------------------------------------ dashboard login
if [[ "$TESTING_LOGIN_ENABLED" == true ]]; then
  bad "TESTING_LOGIN_ENABLED must be false; internal dashboards use explicit dashboard password login"
  printf '       Run ./chronicle up to migrate an existing internal installation.\n'
elif [[ -n "$DASHBOARD_PASSWORD_HASH" ]]; then
  ok "dashboard password login is configured"
fi

# REQUIRE_MFA=true with the built-in password login produces a dashboard that logs in and
# then 401s every API call -- which reads as a broken deployment, not a setting.
if [[ "$REQUIRE_MFA" == true && -n "$DASHBOARD_PASSWORD_HASH" ]]; then
  bad "REQUIRE_MFA=true with the internal dashboard password login"
  printf '       The password login mints a token with no MFA claim, so the dashboard would sign\n'
  printf '       in and then reject every API call with 401. Set REQUIRE_MFA=false in .env; the\n'
  printf '       dashboard stays behind the internal listener, the allowlist and the password.\n'
elif [[ "$REQUIRE_MFA" == true ]]; then
  ok "dashboard tokens must prove MFA (REQUIRE_MFA=true)"
else
  ok "MFA not required on dashboard tokens — gated by the internal listener, allowlist and password"
fi

# ------------------------------------------------------------------ trusted proxy subnet
if validate_compose_proxy_subnet "$CHRONICLE_SUBNET" "$CHRONICLE_SUBNET"; then
  ok "edge network subnet ${CHRONICLE_SUBNET} is one canonical private IPv4 CIDR"
else
  bad "CHRONICLE_SUBNET must be one canonical, private IPv4 CIDR"
fi
if validate_core_prefix "$CHRONICLE_CORE_PREFIX"; then
  ok "internal core network ${CHRONICLE_CORE_PREFIX}.0/24 is a private /24"
else
  bad "CHRONICLE_CORE_PREFIX must be the first three octets of a private /24, such as setup chooses"
fi
validate_dashboard_networks "$CADDY_TRUSTED_PROXIES" ||
  bad "CADDY_TRUSTED_PROXIES must be explicit valid CIDRs and must not trust the entire IPv4 or IPv6 space"
gateway=$(PYTHONPATH="$(dirname "${BASH_SOURCE[0]}")" python3 -c 'from chronicle_ops.common import compose_gateway; import sys; print(compose_gateway(sys.argv[1]))' "$CHRONICLE_SUBNET")
expected_proxies=$(trusted_proxy_sources "$TLS_MODE" "$HTTP_BIND" "$gateway" "$CADDY_TRUSTED_PROXIES") || expected_proxies=""
if [[ -z "$expected_proxies" || "$expected_proxies" != "$CADDY_TRUSTED_PROXIES" ]]; then
  bad "trusted proxies must match the listener mode; a remote LB requires explicit non-loopback source CIDRs"
fi

# ------------------------------------------------------------------ dashboard gate
if [[ "$DASHBOARD_EXPOSURE" == internal ]]; then
  # Neither half of the gate is optional: without a hash Caddy accepts any password, and an
  # empty allowlist accepts any source.
  if [[ -z "$DASHBOARD_PASSWORD_HASH" ]]; then
    bad "DASHBOARD_PASSWORD_HASH is empty — the dashboard would have no password."
    printf '       Run ./chronicle setup, or use the stdin-based hash procedure in README.md;\n'
    printf '       never put the cleartext password in a command argument.\n'
  elif [[ "$DASHBOARD_PASSWORD_HASH" != \$2* ]]; then
    bad "DASHBOARD_PASSWORD_HASH is not a bcrypt hash (must start with \$2). Never put the cleartext password here."
  fi
  if [[ -z "$DASHBOARD_ALLOWED_IPS" ]]; then
    bad "DASHBOARD_ALLOWED_IPS is empty — no source address would be allowed to reach the dashboard"
  fi
  validate_dashboard_networks "$DASHBOARD_ALLOWED_IPS" ||
    bad "DASHBOARD_ALLOWED_IPS is malformed or admits the entire IPv4/IPv6 address space"
  if loopback_networks "$DASHBOARD_ALLOWED_IPS"; then
    warn "DASHBOARD_ALLOWED_IPS covers only loopback; Docker presents the Compose gateway for host access and SSH tunnels. Rerun ./chronicle setup to include it"
  fi
  specific_private_bind "$INTERNAL_BIND" ||
    bad "INTERNAL_BIND must be one specific private, link-local, or loopback IP address"
  if specific_private_bind "$INTERNAL_BIND" && ! is_valid_ipv4_literal "$INTERNAL_BIND"; then
    bad "INTERNAL_BIND=${INTERNAL_BIND} is IPv6. $IPV4_STACK_NETWORK, so DASHBOARD_ALLOWED_IPS would never match. Use an IPv4 address"
  fi
  # The dashboard gate is one control with three parts -- bcrypt password, source allowlist,
  # private bind. Each part still fails on its own line with its own remedy, but when all
  # three hold, saying so three times makes the reader weigh them separately when the only
  # question that matters is whether the gate is shut.
  if ((FAILED == 0)); then
    ok "dashboard gate shut: bcrypt password, allowlist ${DASHBOARD_ALLOWED_IPS}, bound to ${INTERNAL_BIND}:${INTERNAL_PORT}"
  fi
fi

# ------------------------------------------------------------------ image pinning
# `docker compose up -d` is a supported path, so the digest rule cannot live only in the
# ./chronicle wrapper. Source checkouts (RELEASE_VERSION=development) build local tags.
if [[ "$RELEASE_VERSION" != development ]]; then
  image_variables=$(PYTHONPATH="$(dirname "${BASH_SOURCE[0]}")" python3 -c \
    'import sys; from chronicle_ops.images import requested_images; print("\n".join(image.variable for image in requested_images(sys.argv[1])))' "$COMPOSE_FILE_SELECTION") ||
    bad "could not resolve the release image inventory"
  while IFS= read -r image_var; do
    [[ "${!image_var:-}" =~ ^[^[:space:]@]+@sha256:[0-9a-f]{64}$ ]] ||
      bad "${image_var} must be digest-pinned (name@sha256:...) in a release; copy it from the release .env.example"
  done <<<"$image_variables"
fi

# ------------------------------------------------------------------ TLS material
# ./tls is mounted read-only. Docker creates a missing bind-mount source as an empty
# directory, so "the operator never made one" and "the operator made one and left it empty"
# arrive here identically -- both are equally wrong for own-tls, so both fail the same way.
TLS_CERT_DIR="${CHRONICLE_GUARD_TLS_DIR:-/tls}"
if [[ "$TLS_MODE" == own-tls ]]; then
  if [[ -s "${TLS_CERT_DIR}/cert.pem" && -s "${TLS_CERT_DIR}/key.pem" ]]; then
    ok "TLS certificate and key present in ./tls"
    # web has no route off the host, so Caddy staples no OCSP response (docs/NETWORK-EGRESS.md).
    # Browsers that enforce OCSP Must-Staple (the TLS feature extension, RFC 7633, OID
    # 1.3.6.1.5.5.7.1.24, whose only features are status requests) refuse a certificate carrying
    # it without one. LibreSSL prints the OID where OpenSSL prints the name. The text is read
    # whole first: `grep -q` closing the pipe early would fail it under pipefail.
    certificate_text=""
    if command -v openssl >/dev/null 2>&1; then
      certificate_text=$(openssl x509 -in "${TLS_CERT_DIR}/cert.pem" -noout -text 2>/dev/null) || certificate_text=""
    fi
    if grep -qE 'TLS Feature|1\.3\.6\.1\.5\.5\.7\.1\.24' <<<"$certificate_text"; then
      warn "./tls/cert.pem has OCSP Must-Staple, but web cannot fetch OCSP responses to staple (docs/NETWORK-EGRESS.md); Firefox refuses the site. Replace it with a certificate without Must-Staple."
    fi
  else
    bad "TLS_MODE=own-tls but ./tls/cert.pem or ./tls/key.pem is missing or empty"
  fi
elif [[ "$TLS_MODE" == local-https ]]; then
  ok "TLS terminated here with Caddy's internal CA — no certificate to supply"
elif [[ -n "$TLS_MODE" ]]; then
  # No ok line: the "deployment mode:" check above already stated TLS_MODE, and repeating
  # it here is a second green line about a setting the operator has already been told.
  :
  if [[ "$POOL_LISTENER_TLS" == true ]]; then
    ok "pool listener ${HTTP_BIND} serves TLS with ./tls/internal-cert.pem (trust ./tls/internal-ca.crt on the load balancer)"
  elif pool_plaintext_waived "$POOL_PLAINTEXT_WAIVER"; then
    warn "pool listener ${HTTP_BIND} serves plain HTTP under recorded waiver: ${POOL_PLAINTEXT_WAIVER}"
  else
    bad "HTTP_BIND=${HTTP_BIND} serves participant uploads in plain HTTP without a reviewed waiver"
    printf '       Set POOL_LISTENER_TLS=true and have the load balancer trust ./tls/internal-ca.crt,\n'
    printf '       or record a reviewed POOL_PLAINTEXT_WAIVER (risk register reference) in .env.\n'
  fi
  if [[ "$HTTP_BIND" == "0.0.0.0" || "$HTTP_BIND" == "::" || "$HTTP_BIND" == "[::]" ]]; then
    warn "HTTP_BIND=${HTTP_BIND} serves the pool listener to your whole network. Use the address only your proxy can reach unless you intend that."
  elif ! is_valid_ipv4_literal "$HTTP_BIND"; then
    bad "HTTP_BIND=${HTTP_BIND} is IPv6. $IPV4_STACK_NETWORK, so POOL_ALLOWED_IPS and CADDY_TRUSTED_PROXIES would never match your proxy. Use an IPv4 address"
  elif [[ "$HTTP_BIND" =~ ^127\. ]]; then
    # Nothing here can prove where the proxy runs, so this cannot be a hard failure -- a
    # proxy on this same host is a legitimate setup. It is still worth saying loudly,
    # because it is the one misconfiguration every local check passes: an off-host load
    # balancer gets connection refused while everything on this box looks healthy.
    warn "HTTP_BIND=${HTTP_BIND} is loopback, reachable only from this machine. Correct if your proxy runs here; if your load balancer is on another host it will get connection refused. Set HTTP_BIND to an address the proxy can reach."
  fi
fi

echo
if [[ $FAILED -ne 0 ]]; then
  write_configuration_metric 0
  printf '%sConfiguration is not safe to deploy.%s Nothing was started.\n' "$RED" "$RST" >&2
  printf 'Fix the FAIL lines above in .env, then run ./chronicle up again.\n' >&2
  exit 1
fi
write_configuration_metric 1
# No success banner here. This script is one of two check phases, and its caller prints the
# single verdict once both have passed -- "Configuration is valid" from ./chronicle check,
# or the startup line from ./chronicle up. Announcing success mid-run trained the eye to
# stop reading at a green line that was not the final answer.
