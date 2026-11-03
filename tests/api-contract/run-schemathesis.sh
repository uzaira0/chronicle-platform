#!/usr/bin/env bash
# Schemathesis contract fuzzing of the researcher GET surface described by chronicle-api/chronicle.yaml.
# tests/security/backend-api-probes.sh supplies CHRONICLE_BASE_URL and CHRONICLE_AUTH_TOKEN from the
# isolated test backend.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
: "${CHRONICLE_BASE_URL:?set the backend base URL}"
: "${CHRONICLE_AUTH_TOKEN:?set a researcher bearer token}"
python3 "$ROOT_DIR/tests/security/route-authorization-probes.py" --validate-target "$CHRONICLE_BASE_URL"

# Response bodies are not sanitized by Schemathesis. Keep output/artifacts private, including on failure.
umask 077
report_root="${CHRONICLE_SCHEMATHESIS_REPORT_DIR:-$ROOT_DIR/build/schemathesis}"
mkdir -p "$report_root"
chmod 700 "$report_root"
empty_netrc="$report_root/empty.netrc"
: > "$empty_netrc"
chmod 600 "$empty_netrc"
report_dir="$report_root/authenticated"
mkdir -p "$report_dir"
chmod 700 "$report_dir"
: > "$report_dir/cli.log"
chmod 600 "$report_dir/cli.log"
status=0
# Researcher GET surface only. Anonymous access to every route is covered by route-authorization-probes.py; the wider
# all-method and anonymous run waits on JSON bodies for every error response.
NO_PROXY='*' no_proxy='*' NETRC="$empty_netrc" env -u SCHEMATHESIS_HOOKS schemathesis \
  --config-file "$ROOT_DIR/tests/api-contract/schemathesis-authenticated.toml" run "$ROOT_DIR/chronicle-api/chronicle.yaml" \
  --url "$CHRONICLE_BASE_URL" \
  --include-method GET \
  --checks not_a_server_error,status_code_conformance,content_type_conformance,response_schema_conformance \
  --max-examples 50 \
  --seed 42 \
  --request-timeout 10 \
  --report junit \
  --report-dir "$report_dir" >"$report_dir/cli.log" 2>&1 || status=$?
find "$report_dir" -type d -exec chmod 700 {} +
find "$report_dir" -type f -exec chmod 600 {} +
printf 'Schemathesis authenticated GET: exit%s; private reports: %s\n' "$status" "$report_dir"
exit "$status"
