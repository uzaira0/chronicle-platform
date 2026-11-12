#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ADB_BIN="${ADB:-}"
SERIAL="${ANDROID_SERIAL:-}"
PACKAGE="${CHRONICLE_ANDROID_PACKAGE:-com.bcm.chronicle.debug}"
STUDY_ID="${CHRONICLE_STUDY_ID:-}"
PARTICIPANT_ID="${CHRONICLE_PARTICIPANT_ID:-}"
OUTPUT_DIR="${CHRONICLE_DEBUG_BUNDLE_DIR:-/tmp}"
INCLUDE_DB_REPORT=1
ADB_TIMEOUT_SECONDS="${CHRONICLE_ADB_TIMEOUT_SECONDS:-20}"

usage() {
  cat <<'EOF'
Usage: scripts/android-debug-bundle.sh [options]

Collects a redacted Chronicle Android dogfood debug bundle. It intentionally
does not dump app shared preferences or API keys.

Options:
  --serial SERIAL          adb device serial
  --package PACKAGE        Android app id
  --study-id UUID          study UUID for optional server DB report
  --participant-id ID      participant ID for optional server DB report
  --output-dir DIR         artifact directory, default /tmp
  --no-db-report           skip server-side dogfood report
  -h, --help               show help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --serial) SERIAL="${2:?missing --serial value}"; shift 2 ;;
    --package) PACKAGE="${2:?missing --package value}"; shift 2 ;;
    --study-id) STUDY_ID="${2:?missing --study-id value}"; shift 2 ;;
    --participant-id) PARTICIPANT_ID="${2:?missing --participant-id value}"; shift 2 ;;
    --output-dir) OUTPUT_DIR="${2:?missing --output-dir value}"; shift 2 ;;
    --no-db-report) INCLUDE_DB_REPORT=0; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

if [[ "$INCLUDE_DB_REPORT" == 1 && -n "$PARTICIPANT_ID" && -z "$STUDY_ID" ]]; then
  echo "Set CHRONICLE_STUDY_ID or pass --study-id for the server DB report." >&2
  exit 1
fi

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
BUNDLE_DIR="$OUTPUT_DIR/chronicle-debug-$RUN_ID"
mkdir -p "$BUNDLE_DIR"

adb_shell() {
  timeout "$ADB_TIMEOUT_SECONDS" "$ADB_BIN" -s "$SERIAL" shell "$@"
}

{
  echo "run_id=$RUN_ID"
  echo "serial=$SERIAL"
  echo "package=$PACKAGE"
  echo "study_id=$STUDY_ID"
  echo "participant_id=$PARTICIPANT_ID"
} > "$BUNDLE_DIR/metadata.txt"

"$ADB_BIN" -s "$SERIAL" get-state > "$BUNDLE_DIR/adb-state.txt"
adb_shell getprop ro.product.model > "$BUNDLE_DIR/device-model.txt" || true
adb_shell getprop ro.build.version.release > "$BUNDLE_DIR/android-version.txt" || true
adb_shell dumpsys battery > "$BUNDLE_DIR/battery.txt" || true
adb_shell dumpsys batterystats --charged > "$BUNDLE_DIR/batterystats-charged.txt" || true
adb_shell dumpsys package "$PACKAGE" > "$BUNDLE_DIR/package.txt" || true
adb_shell dumpsys jobscheduler "$PACKAGE" > "$BUNDLE_DIR/jobscheduler.txt" || true
adb_shell dumpsys netstats > "$BUNDLE_DIR/netstats.txt" || true
adb_shell appops get "$PACKAGE" > "$BUNDLE_DIR/appops.txt" 2>&1 || true
adb_shell cmd notification get_app_importance "$PACKAGE" > "$BUNDLE_DIR/notification-importance.txt" 2>&1 || true
"$ADB_BIN" -s "$SERIAL" exec-out uiautomator dump /dev/tty > "$BUNDLE_DIR/ui.xml" 2>/dev/null || true
"$ADB_BIN" -s "$SERIAL" logcat -d \
  | grep -E "Chronicle|openlattice|WorkManager|Upload|Sensor|HMAC|HTTP|Exception|battery" \
  > "$BUNDLE_DIR/logcat-chronicle-filtered.txt" || true

if [[ "$INCLUDE_DB_REPORT" == "1" && -n "$PARTICIPANT_ID" ]]; then
  "$ROOT_DIR/scripts/chronicle-dogfood-report.sh" \
    --study-id "$STUDY_ID" \
    --participant-id "$PARTICIPANT_ID" \
    > "$BUNDLE_DIR/server-dogfood-report.txt" || true
fi

tarball="$OUTPUT_DIR/chronicle-debug-$RUN_ID.tar.gz"
tar -C "$OUTPUT_DIR" -czf "$tarball" "chronicle-debug-$RUN_ID"
echo "Bundle directory: $BUNDLE_DIR"
echo "Bundle tarball: $tarball"
