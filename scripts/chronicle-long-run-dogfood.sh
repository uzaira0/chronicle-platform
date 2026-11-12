#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ADB_BIN="${ADB:-}"
SERIAL="${ANDROID_SERIAL:-}"
PACKAGE="${CHRONICLE_ANDROID_PACKAGE:-com.bcm.chronicle.debug}"
STUDY_ID="${CHRONICLE_STUDY_ID:-}"
PARTICIPANT_ID="${CHRONICLE_PARTICIPANT_ID:-}"
DURATION_SECONDS="${CHRONICLE_LONG_RUN_SECONDS:-}"
CYCLE_SECONDS="${CHRONICLE_LONG_RUN_CYCLE_SECONDS:-}"
OUTPUT_DIR="${CHRONICLE_LONG_RUN_OUTPUT_DIR:-/tmp}"
ALLOW_CHARGING=0
PROFILE="${CHRONICLE_LONG_RUN_PROFILE:-8h}"
OFFLINE_INTERVAL_SECONDS="${CHRONICLE_LONG_RUN_OFFLINE_SECONDS:-1800}"

usage() {
  cat <<'EOF'
Usage: scripts/chronicle-long-run-dogfood.sh [options]

Runs a long unattended dogfood cycle. Each cycle generates foreground app usage,
waits for automatic upload, records server data-quality state, and samples
battery before and after the cycle. Final upload counts and a tarball of all
artifacts are written at the end.

Options:
  --serial SERIAL           adb device serial
  --package PACKAGE         Android app id
  --study-id UUID           study UUID
  --participant-id ID       participant ID
  --profile NAME            run profile, default 8h (see below)
  --duration SECONDS        total run duration; overrides the profile default
  --cycle SECONDS           per-cycle auto-upload timeout; overrides profile
  --offline-seconds SECONDS offline window length for offline/reconnect, default 1800
  --output-dir DIR          artifact directory, default /tmp
  --allow-charging          allow plugged-in diagnostic runs
  -h, --help                show help

Run profiles:
  2h           2-hour run, 30-minute cycles
  8h           8-hour run, 30-minute cycles (default)
  24h          24-hour run, 1-hour cycles
  offline      drops connectivity for one offline window, then verifies upload
  reconnect    like offline, then reconnects and runs a normal upload cycle
  power-save   forces Android battery-saver mode for the run
  low-battery  spoofs a low battery level (15%) and unplugged AC for the run
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --serial) SERIAL="${2:?missing --serial value}"; shift 2 ;;
    --package) PACKAGE="${2:?missing --package value}"; shift 2 ;;
    --study-id) STUDY_ID="${2:?missing --study-id value}"; shift 2 ;;
    --participant-id) PARTICIPANT_ID="${2:?missing --participant-id value}"; shift 2 ;;
    --profile) PROFILE="${2:?missing --profile value}"; shift 2 ;;
    --duration) DURATION_SECONDS="${2:?missing --duration value}"; shift 2 ;;
    --cycle) CYCLE_SECONDS="${2:?missing --cycle value}"; shift 2 ;;
    --offline-seconds) OFFLINE_INTERVAL_SECONDS="${2:?missing --offline-seconds value}"; shift 2 ;;
    --output-dir) OUTPUT_DIR="${2:?missing --output-dir value}"; shift 2 ;;
    --allow-charging) ALLOW_CHARGING=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

[[ -n "$STUDY_ID" ]] || { echo "Set CHRONICLE_STUDY_ID or pass --study-id." >&2; exit 1; }

# Profile defaults. An explicit --duration/--cycle always overrides the profile.
profile_duration=28800
profile_cycle=1800
case "$PROFILE" in
  2h)          profile_duration=7200;   profile_cycle=1800 ;;
  8h)          profile_duration=28800;  profile_cycle=1800 ;;
  24h)         profile_duration=86400;  profile_cycle=3600 ;;
  offline)     profile_duration=7200;   profile_cycle=1800 ;;
  reconnect)   profile_duration=7200;   profile_cycle=1800 ;;
  power-save)  profile_duration=14400;  profile_cycle=1800 ;;
  low-battery) profile_duration=7200;   profile_cycle=1800 ;;
  *) echo "unknown --profile: $PROFILE" >&2; usage >&2; exit 2 ;;
esac
[[ -n "$DURATION_SECONDS" ]] || DURATION_SECONDS="$profile_duration"
[[ -n "$CYCLE_SECONDS" ]] || CYCLE_SECONDS="$profile_cycle"

if [[ -z "$PARTICIPANT_ID" && -f /tmp/chronicle-tablet-upload-test-ids.txt ]]; then
  PARTICIPANT_ID="$(sed -n '1p' /tmp/chronicle-tablet-upload-test-ids.txt)"
fi
[[ -n "$PARTICIPANT_ID" ]] || { echo "Missing participant id." >&2; exit 1; }

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

mkdir -p "$OUTPUT_DIR"
RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)"
RUN_DIR="$OUTPUT_DIR/chronicle-long-run-$RUN_ID"
mkdir -p "$RUN_DIR"

echo "Chronicle long-run dogfood"
echo "serial=$SERIAL"
echo "package=$PACKAGE"
echo "study_id=$STUDY_ID"
echo "participant_id=$PARTICIPANT_ID"
echo "profile=$PROFILE"
echo "duration_seconds=$DURATION_SECONDS cycle_seconds=$CYCLE_SECONDS"
echo "artifacts=$RUN_DIR"

adb_shell() {
  "$ADB_BIN" -s "$SERIAL" shell "$@"
}

# Tracks whether a profile altered device state, so the EXIT trap only restores
# what it changed. Restoration is best-effort and must never fail the run.
RESTORE_POWER_SAVE=0
RESTORE_BATTERY=0
RESTORE_CONNECTIVITY=0

restore_device_state() {
  if [[ "$RESTORE_POWER_SAVE" == "1" ]]; then
    echo "Restoring device power mode to normal." >&2
    adb_shell cmd power set-mode 0 >/dev/null 2>&1 || true
  fi
  if [[ "$RESTORE_BATTERY" == "1" ]]; then
    echo "Restoring device battery state." >&2
    adb_shell dumpsys battery reset >/dev/null 2>&1 || true
  fi
  if [[ "$RESTORE_CONNECTIVITY" == "1" ]]; then
    echo "Restoring device connectivity." >&2
    adb_shell svc wifi enable >/dev/null 2>&1 || true
    adb_shell svc data enable >/dev/null 2>&1 || true
  fi
}
trap restore_device_state EXIT

case "$PROFILE" in
  power-save)
    echo "Forcing Android battery-saver mode for the run."
    adb_shell cmd power set-mode 1 >/dev/null 2>&1 || true
    RESTORE_POWER_SAVE=1
    ;;
  low-battery)
    echo "Spoofing low battery (15%, AC unplugged) for the run."
    adb_shell dumpsys battery unplug >/dev/null 2>&1 || true
    adb_shell dumpsys battery set ac 0 >/dev/null 2>&1 || true
    adb_shell dumpsys battery set usb 0 >/dev/null 2>&1 || true
    adb_shell dumpsys battery set level 15 >/dev/null 2>&1 || true
    RESTORE_BATTERY=1
    ;;
esac

# Only forward --allow-charging when explicitly requested. ALLOW_CHARGING is the
# string "0" by default, so a bare ${ALLOW_CHARGING:+...} would always expand.
battery_preflight_args=()
if [[ "$ALLOW_CHARGING" == "1" ]]; then
  battery_preflight_args+=(--allow-charging)
fi
"$ROOT_DIR/scripts/android-battery-drain-harness.sh" \
  --serial "$SERIAL" \
  --package "$PACKAGE" \
  --duration 1 \
  --sample 1 \
  --output-dir "$RUN_DIR" \
  "${battery_preflight_args[@]}" \
  > "$RUN_DIR/battery-preflight.txt"

"$ROOT_DIR/scripts/chronicle-dogfood-report.sh" \
  --study-id "$STUDY_ID" \
  --participant-id "$PARTICIPANT_ID" \
  > "$RUN_DIR/report-before.txt"

# Collects the end-of-run artifacts: debug bundle, a final dogfood report, the
# final upload-counts artifact, and a tarball. Runs on both the success path
# and the cycle-failure path so a failed long run still records final state.
collect_final_artifacts() {
  local cycles_completed="$1"
  "$ROOT_DIR/scripts/android-debug-bundle.sh" \
    --serial "$SERIAL" \
    --package "$PACKAGE" \
    --study-id "$STUDY_ID" \
    --participant-id "$PARTICIPANT_ID" \
    --output-dir "$RUN_DIR" \
    > "$RUN_DIR/debug-bundle.txt" || true

  # Final upload counts: a dedicated end-of-run artifact so a long run always
  # records where the data landed, independent of the per-cycle reports.
  "$ROOT_DIR/scripts/chronicle-dogfood-report.sh" \
    --study-id "$STUDY_ID" \
    --participant-id "$PARTICIPANT_ID" \
    > "$RUN_DIR/report-final.txt" || true
  {
    echo "run_id=$RUN_ID"
    echo "profile=$PROFILE"
    echo "completed_at=$(date -Is)"
    echo "cycles_completed=$cycles_completed"
    echo "# Final upload counts captured from report-final.txt below."
    grep -E -A4 '== (Usage Events Summary|Sensor Data Summary|Last Upload Timestamps By Stream) ==' \
      "$RUN_DIR/report-final.txt" 2>/dev/null || echo "report-final.txt unavailable"
  } > "$RUN_DIR/upload-counts-final.txt"

  # Bundle every artifact for handoff.
  local tarball="$OUTPUT_DIR/chronicle-long-run-$RUN_ID.tar.gz"
  tar -C "$OUTPUT_DIR" -czf "$tarball" "chronicle-long-run-$RUN_ID" || true
  echo "Final upload counts: $RUN_DIR/upload-counts-final.txt"
  echo "Bundle tarball: $tarball"
}

deadline=$(( $(date +%s) + DURATION_SECONDS ))
cycle=1
while (( $(date +%s) < deadline )); do
  cycle_dir="$RUN_DIR/cycle-$cycle"
  mkdir -p "$cycle_dir"
  echo "Starting cycle $cycle at $(date -Is)"

  # offline / reconnect profiles: drop connectivity for one window on cycle 1,
  # so the cycle's auto-upload wait exercises offline buffering then recovery.
  if [[ "$cycle" == "1" ]] && { [[ "$PROFILE" == "offline" ]] || [[ "$PROFILE" == "reconnect" ]]; }; then
    echo "Dropping connectivity for ${OFFLINE_INTERVAL_SECONDS}s (profile=$PROFILE)."
    adb_shell svc wifi disable >/dev/null 2>&1 || true
    adb_shell svc data disable >/dev/null 2>&1 || true
    RESTORE_CONNECTIVITY=1
    "$ROOT_DIR/scripts/chronicle-dogfood-report.sh" \
      --study-id "$STUDY_ID" \
      --participant-id "$PARTICIPANT_ID" \
      > "$cycle_dir/report-offline.txt" || true
    sleep "$OFFLINE_INTERVAL_SECONDS"
    echo "Reconnecting device after offline window."
    adb_shell svc wifi enable >/dev/null 2>&1 || true
    adb_shell svc data enable >/dev/null 2>&1 || true
    RESTORE_CONNECTIVITY=0
    sleep 30
  fi

  "$ADB_BIN" -s "$SERIAL" shell dumpsys battery > "$cycle_dir/battery-before.txt" || true

  set +e
  "$ROOT_DIR/scripts/android-auto-upload-e2e.sh" \
    --serial "$SERIAL" \
    --package "$PACKAGE" \
    --study-id "$STUDY_ID" \
    --participant-id "$PARTICIPANT_ID" \
    --timeout "$CYCLE_SECONDS" \
    --log-dir "$cycle_dir" \
    > "$cycle_dir/auto-upload.txt" 2>&1
  auto_status=$?
  set -e
  echo "$auto_status" > "$cycle_dir/auto-upload-exit-code.txt"

  "$ADB_BIN" -s "$SERIAL" shell dumpsys battery > "$cycle_dir/battery-after.txt" || true
  "$ROOT_DIR/scripts/chronicle-dogfood-report.sh" \
    --study-id "$STUDY_ID" \
    --participant-id "$PARTICIPANT_ID" \
    > "$cycle_dir/report-after.txt" || true

  if [[ "$auto_status" != "0" ]]; then
    echo "Cycle $cycle failed; see $cycle_dir/auto-upload.txt" >&2
    collect_final_artifacts "$((cycle - 1))"
    exit "$auto_status"
  fi
  cycle=$((cycle + 1))
done

collect_final_artifacts "$((cycle - 1))"

echo "PASS: long-run dogfood completed."
echo "Artifacts: $RUN_DIR"
