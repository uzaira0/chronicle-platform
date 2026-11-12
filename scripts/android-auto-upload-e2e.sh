#!/bin/bash
set -euo pipefail

# Retain the supported credential override only in this shell. None of the Android,
# filesystem, timing, or Docker host children need the database password in their env.
POSTGRES_PASSWORD="${POSTGRES_PASSWORD:-}"
export -n POSTGRES_PASSWORD
unset PGPASSWORD FLYWAY_PASSWORD

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ADB_BIN="${ADB:-}"
SERIAL="${ANDROID_SERIAL:-}"
PACKAGE="${CHRONICLE_ANDROID_PACKAGE:-com.bcm.chronicle.debug}"
MAIN_ACTIVITY="${CHRONICLE_ANDROID_MAIN_ACTIVITY:-com.openlattice.chronicle.MainActivity}"
STUDY_ID="${CHRONICLE_STUDY_ID:?Set CHRONICLE_STUDY_ID to the enrolled study UUID}"
PARTICIPANT_ID="${CHRONICLE_PARTICIPANT_ID:-}"
POSTGRES_CONTAINER="${CHRONICLE_POSTGRES_CONTAINER:-chronicle-postgres}"
POSTGRES_USER="${POSTGRES_USER:-}"
POSTGRES_DB="${POSTGRES_DB:-}"
TIMEOUT_SECONDS="${CHRONICLE_AUTO_UPLOAD_TIMEOUT_SECONDS:-2700}"
POLL_SECONDS="${CHRONICLE_AUTO_UPLOAD_POLL_SECONDS:-30}"
APP_SECONDS="${CHRONICLE_AUTO_UPLOAD_APP_SECONDS:-8}"
REQUIRE_FINAL_STORAGE=1
REQUIRE_ACTIVITY_CLASS=1
LOG_DIR="${CHRONICLE_AUTO_UPLOAD_LOG_DIR:-/tmp}"
EXTRA_APPS="${CHRONICLE_AUTO_UPLOAD_APPS:-}"

usage() {
  cat <<'EOF'
Usage: scripts/android-auto-upload-e2e.sh [options]

Drives a connected Android tablet through a few apps, then waits for Chronicle's
periodic automatic upload to happen. This script does not press Upload Now.

Options:
  --serial SERIAL              adb device serial, e.g. 192.0.2.30:38748
  --package PACKAGE            Android app id (default: com.bcm.chronicle.debug)
  --study-id UUID              Chronicle study UUID
  --participant-id ID          enrolled participant id to verify in Postgres
  --timeout SECONDS            max wait for auto upload (default: 2700)
  --poll SECONDS               DB polling interval (default: 30)
  --app-seconds SECONDS        foreground time per app (default: 8)
  --apps CSV                   additional app packages to try via monkey
  --accept-buffer              pass when backend upload_buffer grows, even before final mover
  --allow-no-activity-class    do not require a new non-null activity_class row
  --log-dir DIR                directory for logcat/UI artifacts (default: /tmp)
  -h, --help                   show this help

Environment overrides use the same names shown in the script constants, for
example CHRONICLE_PARTICIPANT_ID or CHRONICLE_AUTO_UPLOAD_TIMEOUT_SECONDS.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --serial)
      SERIAL="${2:?missing --serial value}"
      shift 2
      ;;
    --package)
      PACKAGE="${2:?missing --package value}"
      shift 2
      ;;
    --study-id)
      STUDY_ID="${2:?missing --study-id value}"
      shift 2
      ;;
    --participant-id)
      PARTICIPANT_ID="${2:?missing --participant-id value}"
      shift 2
      ;;
    --timeout)
      TIMEOUT_SECONDS="${2:?missing --timeout value}"
      shift 2
      ;;
    --poll)
      POLL_SECONDS="${2:?missing --poll value}"
      shift 2
      ;;
    --app-seconds)
      APP_SECONDS="${2:?missing --app-seconds value}"
      shift 2
      ;;
    --apps)
      EXTRA_APPS="${2:?missing --apps value}"
      shift 2
      ;;
    --accept-buffer)
      REQUIRE_FINAL_STORAGE=0
      shift
      ;;
    --allow-no-activity-class)
      REQUIRE_ACTIVITY_CLASS=0
      shift
      ;;
    --log-dir)
      LOG_DIR="${2:?missing --log-dir value}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [[ -z "$ADB_BIN" ]]; then
  for candidate in \
    "$HOME/.local/android-sdk/platform-tools/adb" \
    "${ANDROID_HOME:-}/platform-tools/adb" \
    "${ANDROID_SDK_ROOT:-}/platform-tools/adb" \
    adb; do
    [[ "$candidate" == "/platform-tools/adb" ]] && continue
    if command -v "$candidate" >/dev/null 2>&1; then
      ADB_BIN="$(command -v "$candidate")"
      break
    elif [[ -x "$candidate" ]]; then
      ADB_BIN="$candidate"
      break
    fi
  done
fi

if [[ -z "$ADB_BIN" ]]; then
  echo "adb was not found. Set ADB=/path/to/adb." >&2
  exit 1
fi

if [[ -f "$ROOT_DIR/docker/.env" ]]; then
  if [[ -z "$POSTGRES_USER" ]]; then
    POSTGRES_USER="$(awk -F= '/^POSTGRES_USER=/{print substr($0,index($0,"=")+1)}' "$ROOT_DIR/docker/.env")"
  fi
  if [[ -z "$POSTGRES_DB" ]]; then
    POSTGRES_DB="$(awk -F= '/^POSTGRES_DB=/{print substr($0,index($0,"=")+1)}' "$ROOT_DIR/docker/.env")"
  fi
  if [[ -z "$POSTGRES_PASSWORD" ]]; then
    POSTGRES_PASSWORD="$(awk -F= '/^POSTGRES_PASSWORD=/{print substr($0,index($0,"=")+1)}' "$ROOT_DIR/docker/.env")"
  fi
fi

if [[ -z "$PARTICIPANT_ID" && -f /tmp/chronicle-tablet-upload-test-ids.txt ]]; then
  PARTICIPANT_ID="$(sed -n '1p' /tmp/chronicle-tablet-upload-test-ids.txt)"
fi

if [[ -z "$SERIAL" ]]; then
  SERIAL="$("$ADB_BIN" devices | awk 'NR > 1 && $2 == "device" && !found {print $1; found = 1}')"
fi

if [[ -z "$SERIAL" ]]; then
  echo "No adb device found. Pass --serial or connect a tablet." >&2
  exit 1
fi

if [[ -z "$PARTICIPANT_ID" ]]; then
  echo "Missing participant id. Pass --participant-id or set CHRONICLE_PARTICIPANT_ID." >&2
  exit 1
fi

if [[ -z "$POSTGRES_USER" || -z "$POSTGRES_DB" || -z "$POSTGRES_PASSWORD" ]]; then
  echo "Missing Postgres credentials. Provide docker/.env or POSTGRES_USER/POSTGRES_DB/POSTGRES_PASSWORD." >&2
  exit 1
fi

mkdir -p "$LOG_DIR"
RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)"
LOGCAT_FILE="$LOG_DIR/chronicle-auto-upload-$RUN_ID-logcat.txt"
UI_FILE="$LOG_DIR/chronicle-auto-upload-$RUN_ID-ui.xml"

adb_shell() {
  "$ADB_BIN" -s "$SERIAL" shell "$@"
}

psql_scalar() {
  local sql="$1"
  {
    printf '%s\n' "$POSTGRES_PASSWORD"
    printf '%s\n' "$sql"
  } | docker exec -i \
    "$POSTGRES_CONTAINER" \
    /bin/bash -euc '
      IFS= read -r PGPASSWORD
      IFS= read -r query
      export PGPASSWORD
      exec psql -h 127.0.0.1 -U "$1" -d "$2" -At -c "$query"
    ' chronicle-auto-upload-e2e "$POSTGRES_USER" "$POSTGRES_DB"
}

usage_events_count() {
  psql_scalar "select count(*) from chronicle_usage_events where study_id='$STUDY_ID' and participant_id='$PARTICIPANT_ID';"
}

usage_buffer_elements_count() {
  psql_scalar "select coalesce(sum(jsonb_array_length(data)),0) from upload_buffer where study_id='$STUDY_ID' and participant_id='$PARTICIPANT_ID' and upload_type='Android';"
}

sensor_buffer_elements_count() {
  psql_scalar "select coalesce(sum(jsonb_array_length(data)),0) from upload_buffer where study_id='$STUDY_ID' and participant_id='$PARTICIPANT_ID' and upload_type='AndroidSensor';"
}

usage_activity_class_count() {
  psql_scalar "select count(*) from chronicle_usage_events where study_id='$STUDY_ID' and participant_id='$PARTICIPANT_ID' and activity_class is not null;"
}

usage_buffer_activity_class_count() {
  psql_scalar "select count(*) from upload_buffer cross join lateral jsonb_array_elements(data) elem where study_id='$STUDY_ID' and participant_id='$PARTICIPANT_ID' and upload_type='Android' and elem->'activity_class'->>'value' is not null;"
}

package_installed() {
  local package_name="$1"
  adb_shell pm list packages "$package_name" | grep -x "package:$package_name" >/dev/null
}

launch_package_if_present() {
  local package_name="$1"
  if package_installed "$package_name"; then
    echo "Launching $package_name"
    if ! adb_shell monkey -p "$package_name" -c android.intent.category.LAUNCHER 1 >/dev/null; then
      echo "Warning: failed to launch $package_name; continuing." >&2
      return 0
    fi
    sleep "$APP_SECONDS"
    adb_shell input keyevent 3 || true
    sleep 2
  else
    echo "Skipping missing package $package_name"
  fi
}

launch_action() {
  local label="$1"
  local action="$2"
  echo "Launching $label"
  if ! adb_shell am start -W -a "$action" >/dev/null; then
    echo "Warning: failed to launch $label via $action; continuing." >&2
    return 0
  fi
  sleep "$APP_SECONDS"
  adb_shell input keyevent 3 || true
  sleep 2
}

echo "Chronicle Android auto-upload E2E"
echo "serial=$SERIAL"
echo "package=$PACKAGE"
echo "study_id=$STUDY_ID"
echo "participant_id=$PARTICIPANT_ID"
echo "timeout_seconds=$TIMEOUT_SECONDS poll_seconds=$POLL_SECONDS"
echo "logcat=$LOGCAT_FILE"

"$ADB_BIN" -s "$SERIAL" get-state >/dev/null

if ! package_installed "$PACKAGE"; then
  echo "Package $PACKAGE is not installed on $SERIAL." >&2
  exit 1
fi

device_rows="$(psql_scalar "select count(*) from devices where study_id='$STUDY_ID' and participant_id='$PARTICIPANT_ID';")"
api_key_rows="$(psql_scalar "select count(*) from api_keys where study_id='$STUDY_ID' and participant_id='$PARTICIPANT_ID' and not revoked;")"
if [[ "$device_rows" == "0" || "$api_key_rows" == "0" ]]; then
  echo "Participant is not fully enrolled in backend: devices=$device_rows active_api_keys=$api_key_rows" >&2
  exit 1
fi

echo "Granting usage-stats app-op if shell is permitted."
adb_shell appops set "$PACKAGE" GET_USAGE_STATS allow || true
adb_shell appops get "$PACKAGE" GET_USAGE_STATS || true

before_events="$(usage_events_count)"
before_activity="$(usage_activity_class_count)"
before_usage_buffer="$(usage_buffer_elements_count)"
before_sensor_buffer="$(sensor_buffer_elements_count)"
before_buffer_activity="$(usage_buffer_activity_class_count)"
echo "Before: final_usage_events=$before_events final_activity_class=$before_activity usage_buffer_events=$before_usage_buffer usage_buffer_activity_class=$before_buffer_activity sensor_buffer_samples=$before_sensor_buffer"

"$ADB_BIN" -s "$SERIAL" logcat -c

echo "Launching Chronicle once to ensure periodic WorkManager jobs are scheduled."
if ! adb_shell am start -W -n "$PACKAGE/$MAIN_ACTIVITY" >/dev/null; then
  echo "Warning: failed to launch Chronicle; continuing with app-usage generation." >&2
fi
sleep "$APP_SECONDS"

echo "Generating foreground usage events."
launch_action "Android Settings" "android.settings.SETTINGS"
launch_package_if_present "com.android.chrome"
launch_package_if_present "com.sec.android.gallery3d"
launch_package_if_present "com.google.android.youtube"
launch_package_if_present "com.android.vending"

if [[ -n "$EXTRA_APPS" ]]; then
  IFS=',' read -r -a extra_apps_array <<< "$EXTRA_APPS"
  for app_package in "${extra_apps_array[@]}"; do
    app_package="${app_package//[[:space:]]/}"
    if [[ -n "$app_package" ]]; then
      launch_package_if_present "$app_package"
    fi
  done
fi

echo "Returning to Chronicle, then waiting for automatic periodic upload."
if ! adb_shell am start -W -n "$PACKAGE/$MAIN_ACTIVITY" >/dev/null; then
  echo "Warning: failed to return to Chronicle before wait; continuing." >&2
fi
sleep 3

deadline=$(( $(date +%s) + TIMEOUT_SECONDS ))
observed_buffer=0
observed_final_storage=0
while (( $(date +%s) <= deadline )); do
  current_events="$(usage_events_count)"
  current_activity="$(usage_activity_class_count)"
  current_usage_buffer="$(usage_buffer_elements_count)"
  current_sensor_buffer="$(sensor_buffer_elements_count)"
  current_buffer_activity="$(usage_buffer_activity_class_count)"
  now="$(date -Is)"
  echo "[$now] final_usage_events=$current_events final_activity_class=$current_activity usage_buffer_events=$current_usage_buffer usage_buffer_activity_class=$current_buffer_activity sensor_buffer_samples=$current_sensor_buffer"

  if (( current_events > before_events )); then
    if (( REQUIRE_ACTIVITY_CLASS == 1 && current_activity <= before_activity )); then
      observed_final_storage=1
      echo "Final storage grew, but no new non-null activity_class is present yet."
    else
      echo "PASS: automatic usage upload reached final storage."
      "$ADB_BIN" -s "$SERIAL" logcat -d > "$LOGCAT_FILE"
      "$ADB_BIN" -s "$SERIAL" exec-out uiautomator dump /dev/tty > "$UI_FILE" || true
      echo "Artifacts: $LOGCAT_FILE $UI_FILE"
      exit 0
    fi
  fi

  if (( current_usage_buffer > before_usage_buffer )); then
    observed_buffer=1
    if (( REQUIRE_FINAL_STORAGE == 0 )); then
      if (( REQUIRE_ACTIVITY_CLASS == 1 && current_buffer_activity <= before_buffer_activity )); then
        echo "Usage upload reached backend buffer, but no new non-null activity_class is present yet."
      else
        echo "PASS: automatic usage upload reached backend upload_buffer."
        "$ADB_BIN" -s "$SERIAL" logcat -d > "$LOGCAT_FILE"
        "$ADB_BIN" -s "$SERIAL" exec-out uiautomator dump /dev/tty > "$UI_FILE" || true
        echo "Artifacts: $LOGCAT_FILE $UI_FILE"
        exit 0
      fi
    fi
  fi

  if (( REQUIRE_FINAL_STORAGE == 0 && current_sensor_buffer > before_sensor_buffer && current_usage_buffer <= before_usage_buffer )); then
    echo "Sensor buffer grew, but usage upload has not grown yet; continuing."
  fi

  sleep "$POLL_SECONDS"
done

"$ADB_BIN" -s "$SERIAL" logcat -d > "$LOGCAT_FILE"
"$ADB_BIN" -s "$SERIAL" exec-out uiautomator dump /dev/tty > "$UI_FILE" || true

# Most-specific cause first. observed_final_storage is latched only when usage
# events reached final storage but no new non-null activity_class appeared, so
# it must outrank the buffer-only and no-upload diagnoses.
if (( observed_final_storage == 1 )); then
  echo "FAIL: usage events reached final storage, but no new non-null activity_class observed before timeout." >&2
elif (( observed_buffer == 1 && REQUIRE_FINAL_STORAGE == 1 )); then
  echo "FAIL: automatic usage upload reached upload_buffer, but did not reach final storage before timeout." >&2
elif (( observed_buffer == 1 )); then
  echo "FAIL: automatic usage upload reached upload_buffer, but no new non-null activity_class observed before timeout." >&2
else
  echo "FAIL: no automatic usage upload observed before timeout." >&2
fi
echo "Artifacts: $LOGCAT_FILE $UI_FILE" >&2
exit 1
