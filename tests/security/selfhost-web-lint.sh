#!/usr/bin/env bash
# Keep the participant export coverage in the repository's existing lint gates.
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
cd "$ROOT_DIR/chronicle-web"
file=src/modern/components/download-participant-data-modal.test.tsx
./node_modules/.bin/eslint "$file"
./node_modules/.bin/biome check "$file"
echo 'PASS: participant download regression passes scoped ESLint and Biome'
