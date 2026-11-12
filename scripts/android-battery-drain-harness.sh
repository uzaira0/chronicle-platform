#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ADB_BIN="${ADB:-}"
SERIAL="${ANDROID_SERIAL:-}"
PACKAGE="${CHRONICLE_ANDROID_PACKAGE:-com.bcm.chronicle.debug}"
MAIN_ACTIVITY="${CHRONICLE_ANDROID_MAIN_ACTIVITY:-com.openlattice.chronicle.MainActivity}"
DURATION_SECONDS="${CHRONICLE_BATTERY_TEST_SECONDS:-7200}"
SAMPLE_SECONDS="${CHRONICLE_BATTERY_SAMPLE_SECONDS:-60}"
OUTPUT_DIR="${CHRONICLE_BATTERY_OUTPUT_DIR:-$ROOT_DIR/build/battery-drain}"
ALLOW_CHARGING=0
RESET_BATTERYSTATS=0
KEEP_SCREEN_ON=0
ADB_TIMEOUT_SECONDS="${CHRONICLE_ADB_TIMEOUT_SECONDS:-20}"

usage() {
  cat <<'EOF'
Usage: scripts/android-battery-drain-harness.sh [options]

Runs a controlled Android battery lifecycle sample for Chronicle dogfooding.
The default fails fast if the tablet is charging, because plugged-in runs cannot
prove battery decrease.

Options:
  --serial SERIAL           adb device serial, e.g. 192.0.2.30:38748
  --package PACKAGE         Android app id
  --duration SECONDS        total sample duration, default 7200
  --sample SECONDS          battery sample interval, default 60
  --output-dir DIR          artifact directory, default build/battery-drain
  --allow-charging          allow plugged-in diagnostic runs
  --reset-batterystats      reset Android batterystats before sampling
  --keep-screen-on          keep the screen awake during the run
  -h, --help                show help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --serial) SERIAL="${2:?missing --serial value}"; shift 2 ;;
    --package) PACKAGE="${2:?missing --package value}"; shift 2 ;;
    --duration) DURATION_SECONDS="${2:?missing --duration value}"; shift 2 ;;
    --sample) SAMPLE_SECONDS="${2:?missing --sample value}"; shift 2 ;;
    --output-dir) OUTPUT_DIR="${2:?missing --output-dir value}"; shift 2 ;;
    --allow-charging) ALLOW_CHARGING=1; shift ;;
    --reset-batterystats) RESET_BATTERYSTATS=1; shift ;;
    --keep-screen-on) KEEP_SCREEN_ON=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

if [[ -z "$ADB_BIN" ]]; then
  for candidate in "$HOME/.local/android-sdk/platform-tools/adb" \
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

[[ -n "$ADB_BIN" ]] || { echo "adb was not found. Set ADB=/path/to/adb." >&2; exit 1; }

if [[ -z "$SERIAL" ]]; then
  SERIAL="$("$ADB_BIN" devices | awk 'NR > 1 && $2 == "device" && !found {print $1; found = 1}')"
fi
[[ -n "$SERIAL" ]] || { echo "No adb device found. Pass --serial." >&2; exit 1; }

adb_shell() {
  timeout "$ADB_TIMEOUT_SECONDS" "$ADB_BIN" -s "$SERIAL" shell "$@"
}

battery_value() {
  local key="$1"
  awk -F: -v key="$key" '$1 ~ "^[[:space:]]*" key "$" {gsub(/^[[:space:]]+|[[:space:]]+$/, "", $2); print $2; exit}'
}

bool_field() {
  local key="$1"
  awk -F: -v key="$key" '$1 ~ "^[[:space:]]*" key "$" {gsub(/^[[:space:]]+|[[:space:]]+$/, "", $2); print $2; exit}'
}

uid_for_package() {
  adb_shell dumpsys package "$PACKAGE" \
    | awk -F= '/userId=/ && !found {print $2; found = 1}' \
    | tr -d '\r'
}

mkdir -p "$OUTPUT_DIR"
RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)"
RUN_DIR="$OUTPUT_DIR/chronicle-battery-$RUN_ID"
mkdir -p "$RUN_DIR"

"$ADB_BIN" -s "$SERIAL" get-state >/dev/null
adb_shell pm path "$PACKAGE" >/dev/null

initial_battery="$(adb_shell dumpsys battery)"
ac_powered="$(printf '%s\n' "$initial_battery" | bool_field "AC powered")"
usb_powered="$(printf '%s\n' "$initial_battery" | bool_field "USB powered")"
wireless_powered="$(printf '%s\n' "$initial_battery" | bool_field "Wireless powered")"
if [[ "$ALLOW_CHARGING" != "1" ]] && {
  [[ "$ac_powered" == "true" ]] || [[ "$usb_powered" == "true" ]] || [[ "$wireless_powered" == "true" ]]
}; then
  echo "Device is charging. Unplug it or pass --allow-charging for a diagnostic run." >&2
  printf '%s\n' "$initial_battery" > "$RUN_DIR/battery-initial.txt"
  echo "Artifacts: $RUN_DIR" >&2
  exit 1
fi

if [[ "$RESET_BATTERYSTATS" == "1" ]]; then
  adb_shell dumpsys batterystats --reset || true
fi

if [[ "$KEEP_SCREEN_ON" == "1" ]]; then
  adb_shell svc power stayon true || true
else
  adb_shell svc power stayon false || true
fi

adb_shell am start -n "$PACKAGE/$MAIN_ACTIVITY" > "$RUN_DIR/app-start.txt" 2>&1 || true
if [[ "$KEEP_SCREEN_ON" != "1" ]]; then
  adb_shell input keyevent 26 || true
fi

uid="$(uid_for_package || true)"
{
  echo "run_id=$RUN_ID"
  echo "serial=$SERIAL"
  echo "package=$PACKAGE"
  echo "uid=$uid"
  echo "duration_seconds=$DURATION_SECONDS"
  echo "sample_seconds=$SAMPLE_SECONDS"
  echo "allow_charging=$ALLOW_CHARGING"
  echo "reset_batterystats=$RESET_BATTERYSTATS"
  echo "keep_screen_on=$KEEP_SCREEN_ON"
} > "$RUN_DIR/metadata.txt"

printf '%s\n' "$initial_battery" > "$RUN_DIR/battery-initial.txt"
adb_shell dumpsys batterystats --charged > "$RUN_DIR/batterystats-initial.txt" || true
adb_shell dumpsys jobscheduler "$PACKAGE" > "$RUN_DIR/jobscheduler-initial.txt" || true
adb_shell dumpsys package "$PACKAGE" > "$RUN_DIR/package.txt" || true
# Baseline wake-lock, sensor, network, foreground-service and process state so a
# run can attribute drain to wake locks / sensors / upload work.
adb_shell dumpsys power > "$RUN_DIR/power-initial.txt" || true
adb_shell dumpsys sensorservice > "$RUN_DIR/sensorservice-initial.txt" || true
adb_shell dumpsys netstats > "$RUN_DIR/netstats-initial.txt" || true
adb_shell dumpsys activity services "$PACKAGE" > "$RUN_DIR/foreground-services-initial.txt" || true
adb_shell dumpsys procstats --hours 24 "$PACKAGE" > "$RUN_DIR/procstats-initial.txt" || true
adb_shell dumpsys activity processes "$PACKAGE" > "$RUN_DIR/activity-processes-initial.txt" || true

samples="$RUN_DIR/battery-samples.csv"
echo "timestamp,level,status,health,ac_powered,usb_powered,wireless_powered,temperature_tenths_c,voltage_mv,charge_counter_uah,current_now" > "$samples"

start_epoch="$(date +%s)"
deadline=$(( start_epoch + DURATION_SECONDS ))
echo "Sampling battery until $(date -d "@$deadline" -Is). Artifacts: $RUN_DIR"
while (( $(date +%s) <= deadline )); do
  battery="$(adb_shell dumpsys battery)"
  timestamp="$(date -Is)"
  level="$(printf '%s\n' "$battery" | battery_value "level")"
  status="$(printf '%s\n' "$battery" | battery_value "status")"
  health="$(printf '%s\n' "$battery" | battery_value "health")"
  ac="$(printf '%s\n' "$battery" | bool_field "AC powered")"
  usb="$(printf '%s\n' "$battery" | bool_field "USB powered")"
  wireless="$(printf '%s\n' "$battery" | bool_field "Wireless powered")"
  temp="$(printf '%s\n' "$battery" | battery_value "temperature")"
  voltage="$(printf '%s\n' "$battery" | battery_value "voltage")"
  charge_counter="$(printf '%s\n' "$battery" | battery_value "Charge counter")"
  current_now="$(printf '%s\n' "$battery" | battery_value "current now")"
  echo "$timestamp,$level,$status,$health,$ac,$usb,$wireless,$temp,$voltage,$charge_counter,$current_now" >> "$samples"
  sleep "$SAMPLE_SECONDS"
done

adb_shell dumpsys battery > "$RUN_DIR/battery-final.txt" || true
adb_shell dumpsys batterystats --charged > "$RUN_DIR/batterystats-final.txt" || true
adb_shell dumpsys jobscheduler "$PACKAGE" > "$RUN_DIR/jobscheduler-final.txt" || true
adb_shell dumpsys netstats > "$RUN_DIR/netstats-final.txt" || true
# Final wake-lock, sensor, foreground-service, WorkManager and process state.
adb_shell dumpsys power > "$RUN_DIR/power-final.txt" || true
adb_shell dumpsys sensorservice > "$RUN_DIR/sensorservice-final.txt" || true
adb_shell dumpsys activity services "$PACKAGE" > "$RUN_DIR/foreground-services-final.txt" || true
adb_shell dumpsys procstats --hours 24 "$PACKAGE" > "$RUN_DIR/procstats-final.txt" || true
adb_shell dumpsys activity processes "$PACKAGE" > "$RUN_DIR/activity-processes-final.txt" || true
adb_shell logcat -d > "$RUN_DIR/logcat-final.txt" || true

# Wake-lock summary attributed to the Chronicle uid, from final batterystats.
# Android labels app uid X (user 0) as u0a<X-10000>, e.g. 10234 -> u0a234.
if [[ -n "$uid" ]]; then
  uid_suffix=$((uid - 10000))
  grep -E "Wake lock|Job [0-9]|u0a${uid_suffix}" "$RUN_DIR/batterystats-final.txt" \
    > "$RUN_DIR/wakelock-summary.txt" 2>/dev/null || true
fi
# WorkManager / foreground-service state for the Chronicle package.
grep -E -i "WorkManager|WorkSpec|foreground|combined_upload|usage|sensor_settings_refresh" \
  "$RUN_DIR/jobscheduler-final.txt" "$RUN_DIR/foreground-services-final.txt" \
  > "$RUN_DIR/worker-service-state.txt" 2>/dev/null || true

python3 - "$samples" "$RUN_DIR/summary.txt" <<'PY'
import csv
import sys

samples_path, summary_path = sys.argv[1:3]
with open(samples_path, newline="", encoding="utf-8") as f:
    rows = list(csv.DictReader(f))

with open(summary_path, "w", encoding="utf-8") as out:
    if not rows:
        out.write("no samples collected\n")
        raise SystemExit(0)
    first, last = rows[0], rows[-1]
    out.write(f"first_timestamp={first['timestamp']}\n")
    out.write(f"last_timestamp={last['timestamp']}\n")
    for key in ("level", "temperature_tenths_c", "voltage_mv", "charge_counter_uah"):
        out.write(f"first_{key}={first.get(key, '')}\n")
        out.write(f"last_{key}={last.get(key, '')}\n")
    try:
        out.write(f"level_delta_pct={int(last['level']) - int(first['level'])}\n")
    except Exception:
        out.write("level_delta_pct=unknown\n")
    try:
        delta_uah = int(last["charge_counter_uah"]) - int(first["charge_counter_uah"])
        out.write(f"charge_counter_delta_mAh={delta_uah / 1000.0:.3f}\n")
    except Exception:
        out.write("charge_counter_delta_mAh=unknown\n")
PY

# App process uptime: elapsed wall time the Chronicle process has been alive.
process_uptime="$(
  adb_shell dumpsys activity processes "$PACKAGE" 2>/dev/null \
    | awk '/uptime:/ && !found {print; found = 1}' | tr -d '\r'
)"
{
  echo "process_uptime=${process_uptime:-unknown}"
} >> "$RUN_DIR/summary.txt"

cat "$RUN_DIR/summary.txt"
echo "Artifacts: $RUN_DIR"
