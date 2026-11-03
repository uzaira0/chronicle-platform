#!/usr/bin/env bash
set -euo pipefail

ADB_BIN="${ADB:-adb}"
ADB_SERIAL=""
APP_PACKAGE=""
UI_DUMP_PATH="/sdcard/chronicle-unlock-notification.xml"
IDENTIFICATION_TAG="com.openlattice.chronicle.private.identify-user"

usage() {
  echo "Usage: $0 --device <adb-serial> --package <application-id>" >&2
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --device)
      ADB_SERIAL="${2:-}"
      shift 2
      ;;
    --package)
      APP_PACKAGE="${2:-}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      usage
      exit 2
      ;;
  esac
done

[[ -n "$ADB_SERIAL" && -n "$APP_PACKAGE" ]] || {
  usage
  exit 2
}
[[ "$APP_PACKAGE" =~ ^[A-Za-z0-9_]+([.][A-Za-z0-9_]+)+$ ]] || {
  echo "Invalid application ID" >&2
  exit 2
}

adb_cmd() {
  "$ADB_BIN" -s "$ADB_SERIAL" "$@"
}

dump_ui() {
  adb_cmd shell uiautomator dump "$UI_DUMP_PATH" >/dev/null
}

node_center() {
  local resource_id="$1"
  local content_description="${2:-}"
  adb_cmd shell cat "$UI_DUMP_PATH" | python3 -c '
import re
import sys
import xml.etree.ElementTree as ET

resource_id = sys.argv[1]
content_description = sys.argv[2]
root = ET.parse(sys.stdin).getroot()
for node in root.iter("node"):
    if node.attrib.get("resource-id") != resource_id:
        continue
    if content_description and node.attrib.get("content-desc") != content_description:
        continue
    match = re.fullmatch(r"\[(\d+),(\d+)\]\[(\d+),(\d+)\]", node.attrib.get("bounds", ""))
    if match:
        left, top, right, bottom = map(int, match.groups())
        print(f"{(left + right) // 2} {(top + bottom) // 2}")
        break
' "$resource_id" "$content_description"
}

notification_present() {
  adb_cmd shell cmd notification list | tr -d '\r' |
    grep -Fq "|${APP_PACKAGE}|13|${IDENTIFICATION_TAG}|"
}

[[ "$(adb_cmd get-state)" == "device" ]] || {
  echo "ADB device is not ready: $ADB_SERIAL" >&2
  exit 1
}

# Use a real screen-off/screen-on cycle so the dynamically registered receiver, foreground
# service, permission gate, and notification path are all exercised together.
adb_cmd shell input keyevent KEYCODE_POWER
sleep 1
adb_cmd shell input keyevent KEYCODE_POWER
adb_cmd shell wm dismiss-keyguard

for _ in {1..10}; do
  notification_present && break
  sleep 1
done
notification_present || {
  echo "Unlock-identification notification was not posted" >&2
  exit 1
}

adb_cmd shell cmd statusbar collapse
adb_cmd shell cmd statusbar expand-notifications
sleep 1
dump_ui

header_center="$(node_center "${APP_PACKAGE}:id/header")"
if [[ -z "$header_center" ]]; then
  expand_center="$(node_center "android:id/expand_button" "Expand")"
  [[ -n "$expand_center" ]] || {
    echo "Chronicle notification group could not be expanded" >&2
    exit 1
  }
  read -r expand_x expand_y <<<"$expand_center"
  adb_cmd shell input tap "$expand_x" "$expand_y"
  sleep 1
  dump_ui
  header_center="$(node_center "${APP_PACKAGE}:id/header")"
fi

[[ -n "$header_center" ]] || {
  echo "Unlock-identification notification content was not visible" >&2
  exit 1
}
read -r header_x header_y <<<"$header_center"
adb_cmd shell input tap "$header_x" "$header_y"

for _ in {1..10}; do
  if adb_cmd shell dumpsys activity activities |
      grep -Fq "${APP_PACKAGE}/com.openlattice.chronicle.UserIdentificationActivity"; then
    echo "Unlock-identification notification opened the participant-choice screen"
    exit 0
  fi
  sleep 1
done

echo "Unlock-identification notification did not open the participant-choice screen" >&2
exit 1
