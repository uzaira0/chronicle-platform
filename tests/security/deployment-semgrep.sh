#!/usr/bin/env bash
set -euo pipefail
# Named before anything runs: without jq the scan ran to its end and the script then stopped on
# bash's own "jq: command not found" at the first rule lookup.
for tool in semgrep jq timeout; do
  command -v "$tool" >/dev/null || { echo "deployment-semgrep.sh: $tool is not installed" >&2; exit 127; }
done
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
RUN_DIR=$(mktemp -d "${TMPDIR:-/tmp}/chronicle-deployment-semgrep.XXXXXX")
trap 'rm -rf -- "$RUN_DIR"' EXIT
export SEMGREP_SETTINGS_FILE="$RUN_DIR/settings.yml" SEMGREP_LOG_FILE="$RUN_DIR/semgrep.log"
# The findings are read from the JSON report. The text report prefixes each rule id with the path of
# the rules directory as seen from the working directory and wraps at a fixed width, so started from
# outside the repository root a rule id was split over two lines and the fixture counted as missed.
scan() { # JSON report to write
  timeout -k 2 60 semgrep scan --jobs 2 --error --disable-version-check --metrics off --no-git-ignore \
    --json --output "$1" --config "$ROOT_DIR/tests/security/deployment-rules" "$RUN_DIR/fixtures"
}
mkdir "$RUN_DIR/fixtures"
cat >"$RUN_DIR/fixtures/unsafe.sh" <<'SH'
export $(printf 'fixture=value')
SH
printf 'ssl_protocols TLSv1 TLSv1.2;\n' >"$RUN_DIR/fixtures/nginx.conf"
printf 'FROM scratch\nADD https://example.invalid/unverified /input\n' >"$RUN_DIR/fixtures/Dockerfile"
printf 'services:\n  fixture:\n    privileged: true\n' >"$RUN_DIR/fixtures/compose.yml"
status=0
scan "$RUN_DIR/positive.json" >"$RUN_DIR/positive.log" 2>&1 || status=$?
[[ "$status" == 1 ]] || { cat "$RUN_DIR/positive.log" >&2; echo 'FAIL: unsafe deployment fixtures did not fail' >&2; exit 1; }
for rule in shell-export-command-substitution nginx-obsolete-tls dockerfile-remote-add compose-privileged; do
  jq -e --arg rule "$rule" 'any(.results[]; .check_id == $rule or (.check_id | endswith("." + $rule)))' \
    "$RUN_DIR/positive.json" >/dev/null || {
    jq -r '.results[].check_id' "$RUN_DIR/positive.json" >&2
    echo "FAIL: fixture missed $rule" >&2
    exit 1
  }
done
printf 'export FIXTURE=value\n' >"$RUN_DIR/fixtures/unsafe.sh"
printf 'ssl_protocols TLSv1.2 TLSv1.3;\n' >"$RUN_DIR/fixtures/nginx.conf"
printf 'FROM scratch\nCOPY input /input\n' >"$RUN_DIR/fixtures/Dockerfile"
printf 'services:\n  fixture:\n    privileged: false\n' >"$RUN_DIR/fixtures/compose.yml"
scan "$RUN_DIR/corrected.json" >"$RUN_DIR/corrected.log" 2>&1 || { cat "$RUN_DIR/corrected.log" >&2; exit 1; }
echo 'PASS: deployment Semgrep rejects Bash/nginx/Docker/Compose defects and accepts corrected fixtures'
