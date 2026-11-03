#!/usr/bin/env bash
set -euo pipefail
umask 077
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
RUN_DIR=$(mktemp -d "${TMPDIR:-/tmp}/chronicle-gitleaks-history.XXXXXX")
trap 'rm -rf -- "$RUN_DIR"' EXIT
# The ignore list covers private history and is not published; curated public history passes without it.
IGNORE="$ROOT_DIR/tests/security/gitleaks-ignore/methodic-root.gitleaksignore"
ignore_args=()
[[ ! -f "$IGNORE" ]] || ignore_args=(--gitleaks-ignore-path "$IGNORE")
gitleaks git --no-banner --redact "${ignore_args[@]}" \
  --report-format json --report-path "$RUN_DIR/history.json" "$ROOT_DIR" >"$RUN_DIR/history.log" 2>&1 || { cat "$RUN_DIR/history.log" >&2; exit 1; }
mkdir "$RUN_DIR/fixture"
python3 - "$RUN_DIR/fixture/credential.conf" <<'PY'
from pathlib import Path
import hashlib
import sys
# Fixed synthetic input keeps the entropy-sensitive detector control deterministic.
Path(sys.argv[1]).write_text('api_key = "' + hashlib.sha256(b'gitleaks-regression-control').hexdigest() + '"\n')
PY
status=0
gitleaks dir --no-banner --redact --report-format json --report-path "$RUN_DIR/injected.json" \
  "$RUN_DIR/fixture" >"$RUN_DIR/injected.log" 2>&1 || status=$?
[[ "$status" == 1 ]] || { echo 'FAIL: injected credential did not fail secret detection' >&2; exit 1; }
echo 'PASS: redacted history passes exact ignores; injected credential still fails'
