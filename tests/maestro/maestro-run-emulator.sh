#!/usr/bin/env bash
set -euo pipefail

: "${API_LEVEL:?API_LEVEL is required}"
: "${APP_PACKAGE:?APP_PACKAGE is required}"
: "${APK_PATH:?APK_PATH is required}"
: "${MAESTRO_ANDROID_CA:?MAESTRO_ANDROID_CA is required}"
: "${MAESTRO_CA_HASH:?MAESTRO_CA_HASH is required}"
: "${CHRONICLE_PUBLIC_BASE_URL:?CHRONICLE_PUBLIC_BASE_URL is required}"
: "${TEST_STUDY_ID:?TEST_STUDY_ID is required}"
: "${TEST_PARTICIPANT_ID:?TEST_PARTICIPANT_ID is required}"
: "${TEST_PARTICIPANT_ID_2:?TEST_PARTICIPANT_ID_2 is required}"
: "${TEST_ENROLLMENT_ACCESS_CODE:?TEST_ENROLLMENT_ACCESS_CODE is required}"
: "${TEST_ENROLLMENT_ACCESS_CODE_2:?TEST_ENROLLMENT_ACCESS_CODE_2 is required}"

if [[ ! "$API_LEVEL" =~ ^[0-9]+$ ]] || (( API_LEVEL < 23 || API_LEVEL > 36 )); then
  echo "ERROR: unsupported or malformed Android API level" >&2
  exit 1
fi

wait_for_adb_device() {
  local phase="$1"
  local attempt
  local state

  echo "Waiting for an online adb device (${phase})"
  for (( attempt = 1; attempt <= 90; attempt++ )); do
    state="$(timeout 5s adb get-state 2>/dev/null || true)"
    if [[ "$state" == "device" ]]; then
      echo "adb device is online (${phase})"
      return 0
    fi
    if (( attempt == 15 || attempt == 45 )); then
      timeout 10s adb reconnect offline >/dev/null 2>&1 || true
    elif (( attempt == 30 )); then
      timeout 10s adb kill-server >/dev/null 2>&1 || true
      timeout 10s adb start-server >/dev/null 2>&1 || true
    fi
    sleep 1
  done

  adb devices -l >&2 || true
  echo "ERROR: adb device did not become online (${phase})" >&2
  return 1
}

wait_for_boot() {
  wait_for_adb_device "boot"
  local attempt
  for (( attempt = 1; attempt <= 120; attempt++ )); do
    if [[ "$(adb shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" == 1 ]]; then
      return 0
    fi
    sleep 1
  done
  echo "ERROR: emulator did not finish booting" >&2
  return 1
}

wait_for_android_services() {
  local required_stable_polls="$1"
  local previous_pid=""
  local stable_polls=0
  local current_pid
  local attempt

  for (( attempt = 1; attempt <= 60; attempt++ )); do
    # Android 6's toolbox image does not reliably provide pidof. Parse the
    # stable process-table contract so this gate works at the minimum SDK.
    current_pid="$(
      adb shell ps 2>/dev/null | tr -d '\r' |
        awk '$NF == "system_server" { print $2 }' || true
    )"
    if [[ -n "$current_pid" ]] &&
       adb shell service check package 2>/dev/null | grep 'found' >/dev/null &&
       adb shell pm path android >/dev/null 2>&1; then
      if [[ "$current_pid" == "$previous_pid" ]]; then
        stable_polls=$((stable_polls + 1))
      else
        stable_polls=1
      fi
      if (( stable_polls >= required_stable_polls )); then
        return 0
      fi
    else
      stable_polls=0
    fi
    previous_pid="$current_pid"
    sleep 2
  done

  echo "ERROR: Android services did not remain stable" >&2
  return 1
}

configure_reverse_proxy() {
  adb reverse --remove tcp:8443 >/dev/null 2>&1 || true
  adb reverse tcp:8443 tcp:8443
  adb reverse --list | grep -E 'tcp:8443[[:space:]]+tcp:8443' >/dev/null || {
    echo "ERROR: HTTPS reverse port was not installed" >&2
    return 1
  }
}

require_root_adb() {
  local root_result
  local current_uid

  current_uid="$(timeout 10s adb shell id -u 2>/dev/null | tr -d '\r' || true)"
  if [[ "$current_uid" == "0" ]]; then
    echo "adb shell is already running as root"
    return 0
  fi

  echo "Restarting adb shell with root privileges"
  if ! root_result="$(timeout 30s adb root 2>&1)" ||
     grep -qi 'cannot run as root' <<<"$root_result"; then
    printf 'adb root output: %s\n' "$root_result" >&2
    echo "ERROR: this emulator cannot install the ephemeral CA noninteractively" >&2
    return 1
  fi
  wait_for_adb_device "adb root restart"
}

install_ephemeral_ca() {
  local certificate_name="${MAESTRO_CA_HASH}.0"
  local destination
  [[ -r "$MAESTRO_ANDROID_CA" ]]
  require_root_adb

  if (( API_LEVEL >= 34 )); then
    local copy_dir="/data/local/tmp/chronicle-maestro-system-cas-${MAESTRO_CA_HASH}"
    local namespace_count=0
    local process_name
    local process_pid
    adb shell test -d /apex/com.android.conscrypt/cacerts
    adb shell test ! -e "$copy_dir"
    adb shell mkdir -m 0755 "$copy_dir"
    adb shell cp /apex/com.android.conscrypt/cacerts/\* "$copy_dir/"
    destination="${copy_dir}/${certificate_name}"
    adb push "$MAESTRO_ANDROID_CA" "$destination" >/dev/null
    adb shell chown root:root "$copy_dir" "$copy_dir"/\*
    adb shell chmod 0755 "$copy_dir"
    adb shell chmod 0644 "$copy_dir"/\*
    adb shell chcon u:object_r:system_security_cacerts_file:s0 \
      "$copy_dir" "$copy_dir"/\*

    # Android 14+ gives zygote a private mount namespace. Apps inherit that
    # namespace, so changing only the adb/root namespace does not change the
    # trust store seen by the app under test. Bind the complete ephemeral store
    # into every live zygote namespace before the APK starts.
    for process_name in zygote64 zygote webview_zygote; do
      for process_pid in $(adb shell pidof "$process_name" 2>/dev/null | tr -d '\r' || true); do
        adb shell nsenter --mount="/proc/${process_pid}/ns/mnt" -- \
          mount --bind "$copy_dir" /apex/com.android.conscrypt/cacerts
        adb shell nsenter --mount="/proc/${process_pid}/ns/mnt" -- \
          test -r "/apex/com.android.conscrypt/cacerts/${certificate_name}"
        namespace_count=$((namespace_count + 1))
      done
    done
    if (( namespace_count == 0 )); then
      echo "ERROR: no Android zygote namespace was available for ephemeral CA installation" >&2
      return 1
    fi
  else
    # The debug APK explicitly trusts Android's user CA store. Installing the
    # one-run test CA there avoids disable-verity/system-partition reboots that
    # make current API 29/30 emulator images permanently lose adb. Release
    # variants do not include that debug network-security override.
    local user_ca_dir="/data/misc/user/0/cacerts-added"
    local staged_ca="/data/local/tmp/${certificate_name}"
    destination="${user_ca_dir}/${certificate_name}"
    adb shell mkdir -p "$user_ca_dir"
    adb push "$MAESTRO_ANDROID_CA" "$staged_ca" >/dev/null
    adb shell cp "$staged_ca" "$destination"
    adb shell rm -f "$staged_ca"
    adb shell chown system:system "$user_ca_dir" "$destination"
    adb shell chmod 0755 "$user_ca_dir"
    adb shell chmod 0644 "$destination"
    adb shell restorecon "$destination"
  fi

  if (( API_LEVEL < 34 )); then
    adb shell test -r "$destination" || {
      echo "ERROR: ephemeral CA is not readable from the Android system trust store" >&2
      return 1
    }
  elif ! adb shell test -r "$destination"; then
    echo "ERROR: ephemeral CA is not readable from the Android system trust store" >&2
    return 1
  fi
}

wait_for_boot
install_ephemeral_ca
if (( API_LEVEL == 23 )); then
  # API 23 may report boot complete before the disable-verity reboot and package
  # manager have settled. A stable system_server window prevents Maestro's
  # driver setup from racing a second framework restart.
  wait_for_android_services 10
fi
configure_reverse_proxy

adb install "$APK_PATH"
adb shell pm list packages | grep -F "$APP_PACKAGE"
adb shell appops set "$APP_PACKAGE" GET_USAGE_STATS allow
if (( API_LEVEL >= 33 )); then
  adb shell pm grant "$APP_PACKAGE" android.permission.POST_NOTIFICATIONS 2>/dev/null || true
  adb shell appops set "$APP_PACKAGE" POST_NOTIFICATIONS allow 2>/dev/null || true
fi
adb shell appops get "$APP_PACKAGE" GET_USAGE_STATS

run_minimum_sdk_startup_smoke() {
  local ui_dump="minimum-sdk-ui.xml"
  local window_dump="minimum-sdk-windows.txt"

  adb shell monkey -p "$APP_PACKAGE" -c android.intent.category.LAUNCHER 1 >/dev/null
  sleep 3
  adb shell uiautomator dump /data/local/tmp/chronicle-minimum-sdk-ui.xml >/dev/null
  adb exec-out cat /data/local/tmp/chronicle-minimum-sdk-ui.xml >"$ui_dump"
  adb shell dumpsys window windows >"$window_dump"
  adb shell ps | tr -d '\r' |
    awk -v package="$APP_PACKAGE" '$NF == package { found = 1 } END { exit !found }'
  grep -Fq "package=\"${APP_PACKAGE}\"" "$ui_dump"
  grep -Fq "$APP_PACKAGE" "$window_dump"
  adb shell rm -f /data/local/tmp/chronicle-minimum-sdk-ui.xml

  printf '%s\n' \
    '<?xml version="1.0" encoding="UTF-8"?>' \
    '<testsuites>' \
    '  <testsuite name="Minimum SDK startup" device="emulator-5554" tests="1" failures="0" time="0">' \
    '    <testcase id="api23-startup" name="API 23 startup" classname="minimum-sdk" time="0" status="SUCCESS" />' \
    '  </testsuite>' \
    '</testsuites>' >maestro-results.xml
  echo "API 23 minimum-SDK startup compatibility passed"
}

if (( API_LEVEL == 23 )); then
  # Maestro's current dadb path asks Android 6's adbd for shell-v2, which the
  # device closes before any flow can begin. Preserve API 23 coverage with a
  # black-box launch/process/window/UI assertion; the full server journey runs
  # on every maintained transport breakpoint above the minimum SDK.
  run_minimum_sdk_startup_smoke
  exit 0
fi

run_maestro() {
  local log_file="$1"
  set +e
  MAESTRO_CLI_NO_ANALYTICS=1 timeout --foreground --signal=TERM --kill-after=30s 12m \
    maestro test \
    --env API_LEVEL="$API_LEVEL" \
    --env APP_PACKAGE="$APP_PACKAGE" \
    --env SERVER_URL="$CHRONICLE_PUBLIC_BASE_URL" \
    --env TEST_STUDY_ID="$TEST_STUDY_ID" \
    --env TEST_PARTICIPANT_ID="$TEST_PARTICIPANT_ID" \
    --env TEST_PARTICIPANT_ID_2="$TEST_PARTICIPANT_ID_2" \
    --env TEST_ENROLLMENT_ACCESS_CODE="$TEST_ENROLLMENT_ACCESS_CODE" \
    --env TEST_ENROLLMENT_ACCESS_CODE_2="$TEST_ENROLLMENT_ACCESS_CODE_2" \
    --format junit \
    --output maestro-results.xml \
    --debug-output maestro-debug/ \
    .maestro/ 2>&1 | tee "$log_file"
  local command_rc=${PIPESTATUS[0]}
  set -e
  if (( command_rc == 124 || command_rc == 137 )); then
    printf 'ERROR: Maestro exceeded the 12-minute flow deadline (exit %s)\n' \
      "$command_rc" | tee -a "$log_file" >&2
  fi
  return "$command_rc"
}

maestro_rc=0
run_maestro maestro-attempt-1.log || maestro_rc=$?

retry_reason=""
if (( maestro_rc != 0 )) &&
     grep -Fq "<failure>Unable to launch app ${APP_PACKAGE}: am force-stop ${APP_PACKAGE}</failure>" \
       maestro-results.xml 2>/dev/null &&
     grep -Fq 'tests="1" failures="1"' maestro-results.xml; then
  retry_reason="pre-flow app-launch transport failure"
elif (( maestro_rc != 0 )) &&
     grep -Fq '<failure>Unknown error</failure>' maestro-results.xml 2>/dev/null &&
     grep -Fq 'tests="1" failures="1"' maestro-results.xml &&
     ! adb shell ps 2>/dev/null | tr -d '\r' |
       awk -v package="$APP_PACKAGE" '$NF == package { found = 1 } END { exit !found }' &&
     ! adb shell dumpsys window windows 2>/dev/null | grep -F "$APP_PACKAGE" >/dev/null; then
  # Maestro can intermittently lose its driver before launch and emit only
  # "Unknown error". Retry is safe only when Android proves Chronicle never
  # acquired either a process or a window, so no enrollment state was created.
  retry_reason="pre-flow driver transport failure"
fi

# Retry once only when Maestro could not begin the flow. Never replay a
# partially executed, stateful enrollment journey.
if [[ -n "$retry_reason" ]]; then
  printf 'Retrying Maestro after %s\n' "$retry_reason" >&2
  wait_for_adb_device "safe Maestro retry"
  wait_for_boot
  wait_for_android_services 3
  configure_reverse_proxy
  adb shell pm path "$APP_PACKAGE" >/dev/null
  rm -f maestro-results.xml
  rm -rf maestro-debug
  maestro_rc=0
  run_maestro maestro-attempt-2.log || maestro_rc=$?
fi

if (( maestro_rc != 0 )); then
  mkdir -p failure-screenshots
  adb exec-out screencap -p > "failure-screenshots/screen-api${API_LEVEL}.png" 2>/dev/null || true
  adb logcat -d > "failure-screenshots/logcat-api${API_LEVEL}.txt" 2>/dev/null || true
  adb shell uiautomator dump /data/local/tmp/chronicle-maestro-ui.xml >/dev/null 2>&1 || true
  adb exec-out cat /data/local/tmp/chronicle-maestro-ui.xml \
    > "failure-screenshots/ui-api${API_LEVEL}.xml" 2>/dev/null || true
  adb shell rm -f /data/local/tmp/chronicle-maestro-ui.xml >/dev/null 2>&1 || true
  adb shell dumpsys window windows \
    > "failure-screenshots/windows-api${API_LEVEL}.txt" 2>/dev/null || true
fi

exit "$maestro_rc"
