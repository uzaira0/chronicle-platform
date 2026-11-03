#!/usr/bin/env bash
set -euo pipefail
set +x

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

SERVER_URL="${CHRONICLE_REMOTE_SERVER_URL:-}"
STUDY_ID="${CHRONICLE_STUDY_ID:-}"
PARTICIPANT_ID="${CHRONICLE_PARTICIPANT_ID:-tablet-$(date -u +%Y%m%dT%H%M%SZ)}"
PACKAGE="${CHRONICLE_ANDROID_PACKAGE:-com.bcm.chronicle}"
SERIAL="${ANDROID_SERIAL:-}"
APK_PATH="${CHRONICLE_ANDROID_APK:-}"
ACCESS_CODE_FILE="${CHRONICLE_ENROLLMENT_ACCESS_CODE_FILE:-}"
HOST_HEADER="${CHRONICLE_REMOTE_HOST_HEADER:-}"
RUN_ADB=0
RUN_HMAC_SMOKE=0
SKIP_SERVER_CHECKS=0
EMIT_ENV_FILE=""

usage() {
  cat <<'EOF'
Usage: scripts/android-remote-tablet-enrollment.sh --server-url HTTPS_URL --study-id UUID \
  --access-code-file FILE [options]

Preflights a public HTTPS Chronicle server URL and prints the adb commands needed
to enroll a physical Android tablet that is on another network.

This script is for operator-managed dogfooding/testing. It refuses HTTP because the
Android app rejects insecure enrollment URLs.

Required:
  --server-url URL       Public HTTPS base URL, e.g. https://chronicle.example.com
  --study-id UUID        Chronicle study UUID
  --access-code-file FILE
                         Mode-0600 file containing the one-time enrollment code

Options:
  --participant-id ID    Participant ID to embed in the enrollment link
                         (default: tablet-<utc timestamp>)
  --package PACKAGE      Installed Android app id (default: com.bcm.chronicle)
  --serial SERIAL        adb serial for --run-adb
  --apk PATH             APK to install for --run-adb, or command to print
  --host-header HOST     Curl-only Host header for edge diagnostics
  --hmac-smoke           Run tests/security/test-hmac-enforcement.sh against URL
  --skip-server-checks   Do not curl health/study endpoints
  --emit-env FILE        Write CHRONICLE_* values for follow-up scripts
  --run-adb              Execute adb install/grant/enrollment commands now
  -h, --help             Show this help

Register the participant in the Chronicle web UI, issue a one-time enrollment link,
and place only its accessCode fragment value in the private file. This helper never
prints the code or the complete invitation URL.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --server-url) SERVER_URL="${2:?missing --server-url value}"; shift 2 ;;
    --study-id) STUDY_ID="${2:?missing --study-id value}"; shift 2 ;;
    --participant-id) PARTICIPANT_ID="${2:?missing --participant-id value}"; shift 2 ;;
    --package) PACKAGE="${2:?missing --package value}"; shift 2 ;;
    --serial) SERIAL="${2:?missing --serial value}"; shift 2 ;;
    --apk) APK_PATH="${2:?missing --apk value}"; shift 2 ;;
    --access-code-file) ACCESS_CODE_FILE="${2:?missing --access-code-file value}"; shift 2 ;;
    --host-header) HOST_HEADER="${2:?missing --host-header value}"; shift 2 ;;
    --hmac-smoke) RUN_HMAC_SMOKE=1; shift ;;
    --skip-server-checks) SKIP_SERVER_CHECKS=1; shift ;;
    --emit-env) EMIT_ENV_FILE="${2:?missing --emit-env value}"; shift 2 ;;
    --run-adb) RUN_ADB=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

if [[ -z "$SERVER_URL" && -f "$ROOT_DIR/docker/.env" ]]; then
  domain="$(awk -F= '/^DOMAIN=/{print substr($0,index($0,"=")+1)}' "$ROOT_DIR/docker/.env" | tail -1)"
  if [[ -n "$domain" ]]; then
    SERVER_URL="https://${domain}"
  fi
fi

if [[ -z "$SERVER_URL" || -z "$STUDY_ID" || -z "$ACCESS_CODE_FILE" ]]; then
  usage >&2
  exit 2
fi

if [[ ! "$STUDY_ID" =~ ^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$ ]]; then
  echo "study ID must be a UUID: $STUDY_ID" >&2
  exit 2
fi

if [[ ! "$PARTICIPANT_ID" =~ ^[A-Za-z0-9._:@-]+$ ]]; then
  echo "participant ID may only contain letters, numbers, dot, underscore, colon, at-sign, or hyphen: $PARTICIPANT_ID" >&2
  exit 2
fi

if [[ ! "$PACKAGE" =~ ^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z][A-Za-z0-9_]*)+$ ]]; then
  echo "Android package must be a dotted application ID: $PACKAGE" >&2
  exit 2
fi

if [[ -n "$SERIAL" && ! "$SERIAL" =~ ^[A-Za-z0-9._:-]+$ ]]; then
  echo "adb serial contains unsupported characters" >&2
  exit 2
fi

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "$1 is required" >&2
    exit 1
  }
}

if ! "$ROOT_DIR/selfhost/guard-config.sh" --validate-public-origin "$SERVER_URL"; then
  echo "server URL must be an exact HTTPS root origin with a public host" >&2
  exit 2
fi

if [[ ! -f "$ACCESS_CODE_FILE" || -L "$ACCESS_CODE_FILE" || ! -r "$ACCESS_CODE_FILE" ]]; then
  echo "access-code file must be a readable, non-symlink regular file" >&2
  exit 2
fi
# GNU stat first: GNU `stat -f` is filesystem status and succeeds with the wrong answer.
access_code_mode="$(stat -c '%a' "$ACCESS_CODE_FILE" 2>/dev/null || stat -f '%Lp' "$ACCESS_CODE_FILE")"
if [[ ! "$access_code_mode" =~ ^[0-7]{3,4}$ ]] || (( (8#$access_code_mode & 077) != 0 )); then
  echo "access-code file must not grant group or other permissions (use chmod 600)" >&2
  exit 2
fi
ACCESS_CODE="$(<"$ACCESS_CODE_FILE")"
if [[ "$ACCESS_CODE" == *$'\n'* || "$ACCESS_CODE" == *$'\r'* ||
      ${#ACCESS_CODE} -lt 32 || ${#ACCESS_CODE} -gt 256 ||
      ! "$ACCESS_CODE" =~ ^[A-Za-z0-9_-]+$ ]]; then
  echo "access-code file must contain exactly one valid 32-256 character code" >&2
  exit 2
fi

urlencode() {
  need_cmd node
  node -e 'process.stdout.write(encodeURIComponent(process.argv[1]))' "$1"
}

shell_escape() {
  printf '%q' "$1"
}

curl_args=(--max-time 10)
if [[ -n "$HOST_HEADER" ]]; then
  curl_args+=(-H "Host: ${HOST_HEADER}")
fi

curl_code() {
  local url="$1"
  curl -sS -o /dev/null -w '%{http_code}' --proto '=https' --tlsv1.2 "${curl_args[@]}" "$url" 2>/dev/null || echo "000"
}

if [[ "$SKIP_SERVER_CHECKS" == "0" ]]; then
  health_code="$(curl_code "${SERVER_URL}/chronicle/v3/healthz")"
  case "$health_code" in
    200) health_note="health endpoint reachable" ;;
    401|403) health_note="server reachable; health endpoint requires auth at this edge" ;;
    *)
      echo "health check failed: ${SERVER_URL}/chronicle/v3/healthz returned HTTP ${health_code}" >&2
      echo "The tablet must be able to reach this exact HTTPS URL from its home network." >&2
      exit 1
      ;;
  esac

  study_code="$(curl_code "${SERVER_URL}/chronicle/v3/study/${STUDY_ID}")"
  case "$study_code" in
    200) study_note="study endpoint reachable" ;;
    401|403) study_note="study endpoint reachable but requires researcher auth" ;;
    404) study_note="study endpoint returned 404; confirm the study exists before enrolling" ;;
    000) study_note="study endpoint could not be reached" ;;
    *) study_note="study endpoint returned HTTP ${study_code}" ;;
  esac
else
  health_code="skipped"
  health_note="server checks skipped"
  study_code="skipped"
  study_note="server checks skipped"
fi

encoded_study_id="$(urlencode "$STUDY_ID")"
encoded_participant_id="$(urlencode "$PARTICIPANT_ID")"
encoded_access_code="$(urlencode "$ACCESS_CODE")"
enrollment_uri="${SERVER_URL}/chronicle/enroll?studyId=${encoded_study_id}&participantId=${encoded_participant_id}#accessCode=${encoded_access_code}"

if [[ "$RUN_HMAC_SMOKE" == "1" ]]; then
  BASE_URL="$SERVER_URL" \
    HOST_HEADER="$HOST_HEADER" \
    TEST_STUDY_ID="$STUDY_ID" \
    TEST_PARTICIPANT_ID="$PARTICIPANT_ID" \
    TEST_RANDOM_DEVICE_ID="remote-tablet-preflight" \
    "$ROOT_DIR/tests/security/test-hmac-enforcement.sh"
fi

if [[ -n "$EMIT_ENV_FILE" ]]; then
  umask 077
  {
    printf 'export CHRONICLE_REMOTE_SERVER_URL=%s\n' "$(shell_escape "$SERVER_URL")"
    printf 'export CHRONICLE_STUDY_ID=%s\n' "$(shell_escape "$STUDY_ID")"
    printf 'export CHRONICLE_PARTICIPANT_ID=%s\n' "$(shell_escape "$PARTICIPANT_ID")"
    printf 'export CHRONICLE_ANDROID_PACKAGE=%s\n' "$(shell_escape "$PACKAGE")"
  } > "$EMIT_ENV_FILE"
  if [[ -n "$SERIAL" ]]; then
    printf 'export ANDROID_SERIAL=%s\n' "$(shell_escape "$SERIAL")" >> "$EMIT_ENV_FILE"
  fi
fi

adb_prefix='adb'
if [[ -n "$SERIAL" ]]; then
  adb_prefix="adb -s ${SERIAL}"
fi
apk_display="$(shell_escape "${APK_PATH:-/absolute/path/to/chronicle-release.apk}")"

cat <<EOF
Remote Android tablet enrollment preflight
server_url=${SERVER_URL}
study_id=${STUDY_ID}
participant_id=${PARTICIPANT_ID}
package=${PACKAGE}
health=${health_code} (${health_note})
study=${study_code} (${study_note})
one_time_invitation=loaded securely (URL and credential intentionally not printed)

1. Register this participant in Chronicle web first:
   ${PARTICIPANT_ID}

2. On the home computer, verify adb sees the tablet:
   adb devices -l

3. Install the release-candidate APK if needed:
   ${adb_prefix} install -r ${apk_display}

4. Grant usage-stats app-op when Android allows shell to do it:
   ${adb_prefix} shell appops set ${PACKAGE} GET_USAGE_STATS allow

5. Start enrollment on the tablet by rerunning this helper with --run-adb.
   The HTTPS invitation opens in the browser without printing its credential. Review the
   study details there, then tap Open Chronicle to hand off to the installed Play app.

6. Optional: collect a redacted debug bundle after testing:
   CHRONICLE_REMOTE_SERVER_URL='${SERVER_URL}' scripts/android-debug-bundle.sh \\
     --package ${PACKAGE} \\
     --study-id ${STUDY_ID} \\
     --participant-id ${PARTICIPANT_ID}
EOF

if [[ "$RUN_ADB" == "1" ]]; then
  ADB_BIN="${ADB:-adb}"
  adb_cmd=("$ADB_BIN")
  if [[ -n "$SERIAL" ]]; then
    adb_cmd+=("-s" "$SERIAL")
  fi
  if [[ -n "$APK_PATH" ]]; then
    "${adb_cmd[@]}" install -r "$APK_PATH"
  fi
  "${adb_cmd[@]}" shell appops set "$PACKAGE" GET_USAGE_STATS allow || true
  # Keep the capability out of the host adb process arguments as well as its output.
  # The disposable device shell reads it from stdin and hands it directly to Activity Manager.
  if ! printf '%s\n' "$enrollment_uri" | "${adb_cmd[@]}" shell \
    'IFS= read -r invitation && exec am start -W -a android.intent.action.VIEW -d "$invitation"' \
    >/dev/null 2>&1; then
    echo "adb could not open the one-time HTTPS enrollment invitation" >&2
    exit 1
  fi
fi

unset ACCESS_CODE encoded_access_code enrollment_uri
