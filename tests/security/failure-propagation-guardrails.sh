#!/usr/bin/env bash
# Guardrails for scripts that used to turn a failure into a success. Each check locks in a
# fix that an adversarial review found; regressions here are silent by construction.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
FAILURES=0

fail() { printf 'failure-propagation guardrail failed: %s\n' "$*" >&2; FAILURES=$((FAILURES + 1)); }
ok()   { printf '[ok] %s\n' "$*"; }

CHANGELOG="$ROOT_DIR/scripts/changelog-draft.sh"

# ── changelog-draft.sh actually exits nonzero on a broken range ──────────────────────
# git-cliff exits 0 on an empty range and 1 on a bad one, so this is a real behavioural
# difference and not just a flag: build a fixture worktree whose recorded public tip does
# not exist and require the draft to abort instead of emitting an incomplete changelog.
if ! command -v git-cliff >/dev/null 2>&1; then
  fail "git-cliff is required for the changelog behavioural check"
else
  fixture="$(mktemp -d)"
  trap 'rm -rf "$fixture"' EXIT
  # A curate worktree git-cliff cannot process (no commits): the draft must abort rather
  # than emit a changelog that silently omits this repository.
  git init -q "$fixture/root"
  status=0
  CHRONICLE_PUBLISH_WORK="$fixture" "$CHANGELOG" 0.0.0 >/dev/null 2>&1 || status=$?
  [[ "$status" -ne 0 ]] \
    && ok "changelog-draft.sh exits $status when git-cliff cannot process a worktree" \
    || fail "changelog-draft.sh exited 0 despite a git-cliff failure; the draft would be incomplete"
fi

echo
if [[ "$FAILURES" -gt 0 ]]; then
  printf 'failure-propagation guardrails: %d failure(s)\n' "$FAILURES" >&2
  exit 1
fi
printf 'failure-propagation guardrails: all checks passed\n'
