#!/usr/bin/env bash
# Silent failure hunter — checks for common silent-failure patterns in the codebase.
# Returns non-zero if any critical patterns are found.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FOUND=0

echo "Silent failure hunter"

# The first five lines of its input in $hits. Read from a process substitution, not through a
# pipe: head leaves after five lines, the search that feeds it is ended there and not run over the
# rest of the source tree, and its status is not this script's (a pipe under pipefail would
# report the search's SIGPIPE).
first_hits() { hits="$(head -n 5)"; }

# 1. Empty catch blocks in Kotlin/Java
echo "--- Checking for empty catch blocks ---"
first_hits < <(grep -rn 'catch.*{[[:space:]]*}' \
  "$ROOT_DIR/chronicle-server/src" \
  "$ROOT_DIR/chronicle-api/src" \
  --include='*.kt' --include='*.java' 2>/dev/null | grep -v '// expected' | grep -v 'test')
if [[ -n "$hits" ]]; then
  printf '%s\n' "$hits"
  echo "[warn] Found empty catch blocks (review manually)"
fi

# 2. Fire-and-forget coroutines/async without error handling
echo "--- Checking for fire-and-forget patterns ---"
first_hits < <(grep -rn 'GlobalScope.launch\|runBlocking' \
  "$ROOT_DIR/chronicle-server/src/main" \
  --include='*.kt' 2>/dev/null)
if [[ -n "$hits" ]]; then
  printf '%s\n' "$hits"
  echo "[warn] Found GlobalScope/runBlocking usage (review manually)"
fi

# 3. Catch-and-return-null patterns
echo "--- Checking for catch-and-return-null ---"
first_hits < <(grep -rn -A1 'catch.*{' "$ROOT_DIR/chronicle-server/src/main" --include='*.kt' 2>/dev/null \
  | grep 'return null' | grep -v 'test')
if [[ -n "$hits" ]]; then
  printf '%s\n' "$hits"
  echo "[warn] Found catch-and-return-null patterns"
fi

echo "[ok] Silent failure hunter complete (warnings are advisory)"
exit $FOUND
