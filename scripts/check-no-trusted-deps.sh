#!/usr/bin/env bash
#
# Supply-chain guard: fail if any manifest re-enables dependency lifecycle scripts.
#
# Bun restricts dependency lifecycle scripts to its built-in trust list, which
# includes the Bun runtime package. It does not disable every dependency script.
# This guard rejects project trust lists and script-enabling knobs so the existing
# policy cannot be silently expanded. `--ignore-scripts` disables all scripts.
#
# If you have a legitimate need to trust a dependency's install script, that is a
# human decision that must NOT pass CI silently — remove this guard deliberately
# in the same PR, with review, rather than working around it.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

status=0

# 1. No trustedDependencies in any package.json (the bun lifecycle-script allowlist).
#    Scan every package.json except installed dependencies (node_modules).
while IFS= read -r -d '' manifest; do
  if grep -Eq '"trustedDependencies"[[:space:]]*:' "$manifest"; then
    printf '[fail] %s declares "trustedDependencies" — this re-enables dependency install scripts (worm payload vector).\n' "$manifest" >&2
    status=1
  fi
done < <(find . -name package.json -not -path '*/node_modules/*' -print0)

# 2. No script-enabling knobs in bunfig.toml files.
while IFS= read -r -d '' bunfig; do
  if grep -Eq 'trustedDependencies|^[[:space:]]*scripts[[:space:]]*=[[:space:]]*true' "$bunfig"; then
    printf '[fail] %s enables dependency lifecycle scripts — remove it.\n' "$bunfig" >&2
    status=1
  fi
done < <(find . -name bunfig.toml -not -path '*/node_modules/*' -print0)

# 3. No `ignore-scripts=false` in any .npmrc (npm equivalent of the same weakening).
while IFS= read -r -d '' npmrc; do
  if grep -Eiq '^[[:space:]]*ignore-scripts[[:space:]]*=[[:space:]]*false' "$npmrc"; then
    printf '[fail] %s sets ignore-scripts=false — this lets npm run dependency install scripts.\n' "$npmrc" >&2
    status=1
  fi
done < <(find . -name '.npmrc' -not -path '*/node_modules/*' -print0)

if [ "$status" -eq 0 ]; then
  echo "[ok] No manifest adds a dependency trust list or enables npm lifecycle scripts."
fi

exit "$status"
