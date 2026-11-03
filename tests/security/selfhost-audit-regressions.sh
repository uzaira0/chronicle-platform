#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
python3 -s "$ROOT_DIR/tests/security/webselfhost-audit-regressions.py"
python3 -s "$ROOT_DIR/tests/security/webselfhost-gate-regressions.py"
