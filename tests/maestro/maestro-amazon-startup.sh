#!/usr/bin/env bash
set -euo pipefail

: "${APP_PACKAGE:?APP_PACKAGE is required}"
: "${AMAZON_APK_DIR:=amazon-apk}"

apk="$(find "$AMAZON_APK_DIR" -name '*.apk' -print -quit)"
[[ -n "$apk" ]] || {
  echo "Amazon APK was not downloaded" >&2
  exit 1
}
if adb shell pm list packages | grep 'com.google.android.gms' >/dev/null; then
  echo "AOSP image unexpectedly contains Google Play Services" >&2
  exit 1
fi

adb install "$apk"
adb logcat -c >/dev/null 2>&1 || true
adb shell am force-stop "$APP_PACKAGE"
if ! adb shell am start -W \
  -n "$APP_PACKAGE/com.openlattice.chronicle.MainActivity" >amazon-startup.txt 2>&1; then
  cat amazon-startup.txt >&2
  exit 1
fi
cat amazon-startup.txt

# Older AOSP ActivityManager versions do not consistently emit `Status: ok`.
# The package's presence in the live activity state is the portable startup
# assertion, and also detects an immediate launch crash.
started=false
for _ in $(seq 1 15); do
  adb shell dumpsys activity activities >amazon-activities.txt
  if grep -Fq "$APP_PACKAGE" amazon-activities.txt; then
    started=true
    break
  fi
  sleep 2
done
if [[ "$started" != true ]]; then
  cat amazon-activities.txt >&2
  adb logcat -d >amazon-logcat.txt 2>/dev/null || true
  tail -n 200 amazon-logcat.txt >&2 || true
  echo "Chronicle did not remain in the live activity state" >&2
  exit 1
fi
adb logcat -d >amazon-logcat.txt 2>/dev/null || true
if grep -E 'FATAL EXCEPTION|NoClassDefFoundError.*(google|health\.connect)' amazon-logcat.txt; then
  echo "Amazon flavor crashed or linked a Google-only class" >&2
  exit 1
fi
