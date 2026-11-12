#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
REPORT_DIR="${CHRONICLE_LOAD_REPORT_DIR:-$ROOT_DIR/build/pilot-load}"
: "${BASE_URL:?set the clean-stack HTTPS ingest origin}"
: "${DEVICE_FIXTURES_FILE:?set the private enrolled synthetic-device fixture path}"
: "${STUDY_ID:?set the synthetic fixture study UUID}"
: "${COMPOSE_PROJECT_NAME:?set the isolated synthetic study project}"
for tool in docker k6; do command -v "$tool" >/dev/null || { echo "missing tool: $tool" >&2; exit 1; }; done
# Oldest k6 verified to parse tests/load; v0.50.0 cannot parse its optional chaining and exits before any request.
MINIMUM_K6_VERSION=0.57.0
k6_version="$(k6 version | sed -nE 's/^k6 (version )?v([0-9]+[.][0-9]+[.][0-9]+).*/\2/p')"
[[ -n "$k6_version" && "$(printf '%s\n' "$MINIMUM_K6_VERSION" "$k6_version" | sort -V | sed -n 1p)" == "$MINIMUM_K6_VERSION" ]] ||
  { echo "k6 ${k6_version:-of unknown version} is older than the required v${MINIMUM_K6_VERSION}" >&2; exit 1; }
mkdir -p "$REPORT_DIR"
chmod 700 "$REPORT_DIR"
[[ ! -e "$REPORT_DIR/k6-summary.json" ]] || { echo 'use a fresh report directory per run' >&2; exit 1; }
docker compose -p "$COMPOSE_PROJECT_NAME" logs --follow --since 0s --no-color web >"$REPORT_DIR/edge.jsonl" 2>&1 &
EDGE_LOG_PID=$!
trap 'kill "$EDGE_LOG_PID" 2>/dev/null || true; wait "$EDGE_LOG_PID" 2>/dev/null || true' EXIT
k6 run --summary-export "$REPORT_DIR/k6-summary.json" \
  --out "json=$REPORT_DIR/k6-samples.jsonl" "$ROOT_DIR/tests/load/chronicle-load-test.js"
