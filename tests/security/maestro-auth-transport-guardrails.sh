#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SETUP_SCRIPT="$ROOT_DIR/.maestro/setup-test-data.sh"
TEST_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/chronicle-maestro-auth.XXXXXX")"
trap 'rm -rf -- "$TEST_ROOT"' EXIT HUP INT TERM

fail() {
  printf 'FAIL: %s\n' "$*" >&2
  exit 1
}

mkdir -p "$TEST_ROOT/bin" "$TEST_ROOT/auth"
chmod 700 "$TEST_ROOT/auth"
token_file="$TEST_ROOT/auth/admin.jwt"
token_value='headerPayloadSentinel.payloadPayloadSentinel.signaturePayloadSentinel'
(umask 077; printf '%s\n' "$token_value" >"$token_file")
chmod 600 "$token_file"

cat >"$TEST_ROOT/bin/curl" <<'FAKE_CURL'
#!/usr/bin/env bash
set -euo pipefail
sentinel='headerPayloadSentinel.'
sentinel+='payloadPayloadSentinel.'
sentinel+='signaturePayloadSentinel'
if env | grep -F "$sentinel" >/dev/null; then
  printf 'administrator token reached fake curl environment\n' >&2
  exit 90
fi
if [[ "$*" == *"$sentinel"* ]]; then
  printf 'administrator token reached fake curl argv\n' >&2
  exit 91
fi
config="$(cat)"
[[ "$config" == "header = \"Authorization: Bearer $sentinel\"" ]] || {
  printf 'administrator header was not delivered over curl configuration stdin\n' >&2
  exit 92
}
printf 'curl-invocation-ok\n' >>"${MAESTRO_FAKE_CURL_LOG:?}"
method=GET
url=''
previous=''
for argument in "$@"; do
  if [[ "$previous" == '-X' ]]; then
    method="$argument"
  fi
  if [[ "$argument" == https://* ]]; then
    url="$argument"
  fi
  previous="$argument"
done
if [[ "$*" != *'-w'* ]]; then
  exit 0
fi
case "$method $url" in
  'GET '*'/v3/study')
    printf '200' ;;
  'POST '*'/v3/study')
    printf '"11111111-2222-4333-8444-555555555555"\n200\n' ;;
  'POST '*'/participant')
    printf '{}\n200\n' ;;
  'POST '*'/form-access-codes')
    printf '{"accessCode":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"}\n200\n' ;;
  *)
    printf 'unexpected fake curl request: %s %s\n' "$method" "$url" >&2
    exit 93 ;;
esac
FAKE_CURL
chmod 755 "$TEST_ROOT/bin/curl"

export MAESTRO_FAKE_CURL_LOG="$TEST_ROOT/curl.log"
export GITHUB_ENV="$TEST_ROOT/github.env"
export SERVER_URL='https://192.0.2.10:8443'
export AUTH_TOKEN_FILE="$token_file"
PATH="$TEST_ROOT/bin:$PATH"
export PATH

setup_output="$TEST_ROOT/setup-output.txt"
# Path is resolved from the canonical repository root.
token_file_to_remove="$AUTH_TOKEN_FILE"
# shellcheck disable=SC1090
source "$SETUP_SCRIPT" >"$setup_output" 2>&1

[[ ! -e "$token_file_to_remove" && ! -e "$token_file" && ! -e "$TEST_ROOT/auth" ]] ||
  fail "one-use administrator token transport was not deleted immediately"
[[ -z "${AUTH_TOKEN_FILE+x}" && -z "${AUTH_TOKEN_VALUE+x}" && -z "${AUTH_TOKEN+x}" ]] ||
  fail "administrator token or transport variable survived in the sourced caller"
if rg -Fq "$token_value" "$TEST_ROOT"; then
  fail "administrator token reached output, environment export, or retained test artifacts"
fi
[[ "$(wc -l <"$MAESTRO_FAKE_CURL_LOG" | tr -d ' ')" -ge 6 ]] ||
  fail "functional fixture did not exercise readiness and all seeded API requests"
grep -Fq 'TEST_ENROLLMENT_ACCESS_CODE=' "$GITHUB_ENV" ||
  fail "synthetic invitation outputs were not preserved for later Maestro steps"

printf 'Maestro administrator-token transport guardrails passed.\n'
