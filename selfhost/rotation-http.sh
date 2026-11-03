#!/usr/bin/env bash
# Credential transport and Grafana rotation/recovery for rotate-secret.sh.

escape_curl_config_value() {
  local value="$1"
  case "$value" in
    *$'\n'*|*$'\r'*) return 2 ;;
  esac
  value="${value//\\/\\\\}"
  value="${value//\"/\\\"}"
  CURL_CONFIG_VALUE="$value"
}

curl_basic_code() {
  local username="$1" password="$2" url="$3"
  escape_curl_config_value "${username}:${password}" || return 2
  local -a tls_options=(--cacert "$DASHBOARD_CA")
  [[ "$url" != "$GRAFANA_URL/"* ]] || tls_options=(--cacert "$STATE_ROOT/tls/monitoring.crt")
  curl --config /dev/fd/3 -s "${tls_options[@]}" --noproxy '*' -o /dev/null -w '%{http_code}' --max-time 15 "$url" \
    3< <(printf 'user = "%s"\n' "$CURL_CONFIG_VALUE")
}

grafana_change_password() {
  local old_password="$1" new_password="$2" url="$3" code
  escape_curl_config_value "admin:${old_password}" || return 2
  if code="$({
    printf '%s\0%s\0' "$old_password" "$new_password" |
      python3 /dev/fd/3 3<<'PY'
import json
import sys

values = sys.stdin.buffer.read().split(b"\0")
if values and values[-1] == b"":
    values.pop()
if len(values) != 2:
    raise SystemExit("malformed Grafana password payload")
old, new = (value.decode("utf-8") for value in values)
sys.stdout.write(json.dumps({"oldPassword": old, "newPassword": new, "confirmNew": new}))
PY
  } | curl --config /dev/fd/3 -sS --cacert "$STATE_ROOT/tls/monitoring.crt" --noproxy '*' -o /dev/null -w '%{http_code}' --max-time 15 \
      -X PUT -H 'Content-Type: application/json' --data-binary @- "${url}/api/user/password" \
      3< <(printf 'user = "%s"\n' "$CURL_CONFIG_VALUE"))"; then
    case "$code" in
      200) return 0 ;;
      401|403) printf 'ERROR: Grafana refused password-change authentication (HTTP %s). Check the current credential and follow rotation recovery.\n' "$code" >&2 ;;
      5??) printf 'ERROR: Grafana returned a server error during the password change (HTTP %s). The outcome is unconfirmed; follow rotation recovery.\n' "$code" >&2 ;;
      *) printf 'ERROR: Grafana returned an unexpected password-change response (HTTP %s). Follow rotation recovery.\n' "$code" >&2 ;;
    esac
  else
    printf 'ERROR: The password-change outcome could not be confirmed. Check Grafana connectivity and TLS, then follow rotation recovery.\n' >&2
  fi
  return 1
}

grafana_can_auth() {
  local password="$1" code
  code="$(curl_basic_code admin "$password" "${GRAFANA_URL}/api/user")" || return 1
  [[ "$code" == 200 ]]
}

recover_grafana_rotation() {
  local current_secret old_secret
  configure_apply "$SAVED_ROTATION_KIND"
  current_secret="$(env_value_from_file .env GRAFANA_ADMIN_PASSWORD)" ||
    fail "could not read GRAFANA_ADMIN_PASSWORD from the current .env"
  old_secret="$(env_value_from_file "${ROTATION_DIR}/old.env" GRAFANA_ADMIN_PASSWORD)" ||
    fail "could not read the saved pre-rotation GRAFANA_ADMIN_PASSWORD"
  [[ -n "$current_secret" && -n "$old_secret" ]] || fail "Grafana recovery found an empty password"
  GRAFANA_URL="$(grafana_base_url)"
  ensure_recovery_service_running grafana

  if [[ "$RECOVERY_DIRECTION" == forward ]]; then
    [[ "$current_secret" != "$old_secret" ]] ||
      fail "the new Grafana password was never published; recover --rollback, then start a new rotation"
    if grafana_can_auth "$current_secret"; then
      :
    elif grafana_can_auth "$old_secret"; then
      grafana_change_password "$old_secret" "$current_secret" "$GRAFANA_URL" ||
        return 1
    else
      fail "neither the current nor saved Grafana password authenticates; preserve the transaction directory"
    fi
    apply_configuration
    grafana_can_auth "$current_secret" || fail "Grafana rejected the forward-recovered password"
    complete_recovery "grafana_auth=verified;published_configuration=retained"
  else
    if grafana_can_auth "$old_secret"; then
      :
    elif [[ "$current_secret" != "$old_secret" ]] && grafana_can_auth "$current_secret"; then
      grafana_change_password "$current_secret" "$old_secret" "$GRAFANA_URL" ||
        return 1
    else
      fail "neither the saved nor current Grafana password authenticates; preserve the transaction directory"
    fi
    restore_old_env
    apply_configuration
    grafana_can_auth "$old_secret" || fail "Grafana rejected the restored password"
    complete_recovery "grafana_auth=verified;previous_configuration=restored"
  fi
  current_secret=""; old_secret=""
}

rotate_grafana() {
  [[ "${COMPOSE_FILE:-}" == *overlays/monitoring.yml* ]] ||
    fail "Grafana is not enabled in COMPOSE_FILE"
  service_running grafana
  confirm "Rotate the Grafana administrator password?"
  configure_apply grafana
  OLD_SECRET="${GRAFANA_ADMIN_PASSWORD:?GRAFANA_ADMIN_PASSWORD is not set}"
  NEW_SECRET="$(openssl rand -hex 32)"
  local code
  GRAFANA_URL="$(grafana_base_url)"
  code="$(curl_basic_code admin "$OLD_SECRET" "${GRAFANA_URL}/api/user")"
  [[ "$code" == 200 ]] || fail "the current .env password cannot authenticate to Grafana (HTTP $code)"

  begin_transaction grafana rotate
  env_update GRAFANA_ADMIN_PASSWORD "$NEW_SECRET"
  write_phase env-published
  # As for PostgreSQL: a lost response can hide a committed change. Mark it begun first so a
  # failure reverses it, or preserves the transaction with NEW_SECRET still in .env.
  # shellcheck disable=SC2034 # consumed by rotate-secret.sh
  EXTERNAL_CHANGED=true
  grafana_change_password "$OLD_SECRET" "$NEW_SECRET" "$GRAFANA_URL" ||
    return 1
  write_phase grafana-updated
  apply_configuration
  code="$(curl_basic_code admin "$NEW_SECRET" "${GRAFANA_URL}/api/user")"
  [[ "$code" == 200 ]] || fail "Grafana rejected the rotated password after restart (HTTP $code)"
  # shellcheck disable=SC2034 # consumed by rotate-secret.sh
  RECEIPT_DETAIL="grafana_auth=verified"
  complete_transaction grafana rotate
  GRAFANA_ADMIN_PASSWORD="$NEW_SECRET"
  NEW_SECRET=""; OLD_SECRET=""
  log "Grafana administrator password rotated and verified. The generated value remains only in .env."
}
