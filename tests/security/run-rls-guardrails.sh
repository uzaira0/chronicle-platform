#!/usr/bin/env bash
# Focused guardrails for Chronicle RLS request/connection context regressions.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
REPORT_DIR="${1:-$ROOT_DIR/tests/security/reports}"

mkdir -p "$REPORT_DIR"

echo "=== RLS guardrails: context ownership ==="
owner_status=0
ast-grep scan \
  --rule "$ROOT_DIR/tests/security/ast-grep/rls-context-single-owner.yml" \
  "$ROOT_DIR/chronicle-server/src/main/kotlin" \
  --format sarif > "$REPORT_DIR/rls-context-single-owner.ast-grep.sarif" || owner_status=$?

echo "=== RLS guardrails: Semgrep ==="
semgrep scan \
  --config "$ROOT_DIR/tests/security/rules/rls-context.yaml" \
  --error \
  --no-git-ignore \
  --sarif -o "$REPORT_DIR/rls-context.semgrep.sarif" \
  "$ROOT_DIR/chronicle-server/src/main/kotlin"

echo "=== RLS guardrails: ast-grep ==="
ast-grep scan \
  --rule "$ROOT_DIR/tests/security/ast-grep/no-rls-context-manager-call.yml" \
  "$ROOT_DIR/chronicle-server/src/main/kotlin" \
  --format sarif > "$REPORT_DIR/rls-no-context-manager-call.ast-grep.sarif"

ast-grep scan \
  --rule "$ROOT_DIR/tests/security/ast-grep/no-rls-filter-storage-resolver.yml" \
  "$ROOT_DIR/chronicle-server/src/main/kotlin" \
  --format sarif > "$REPORT_DIR/rls-no-filter-storage-resolver.ast-grep.sarif"

if [[ "$owner_status" -ne 0 ]]; then
  exit "$owner_status"
fi
echo "RLS guardrails passed"
