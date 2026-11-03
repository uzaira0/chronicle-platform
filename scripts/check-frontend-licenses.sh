#!/usr/bin/env bash
# check-frontend-licenses.sh — Verify frontend dependency licenses are allowed (GPL-3.0-or-later project).
# Runs via: bash scripts/check-frontend-licenses.sh (from repo root; needs bun, syft and python3 in PATH,
# local-ci's license-compliance job puts the pinned syft there)
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR/chronicle-web"

# SPDX identifiers the GPL-3.0-or-later project accepts in shipped frontend code.
ALLOWED='MIT;ISC;BSD-2-Clause;BSD-3-Clause;0BSD;Apache-2.0;CC0-1.0;Unlicense;CC-BY-3.0;CC-BY-4.0;BlueOak-1.0.0;Python-2.0;OFL-1.1'

echo "=== Frontend license compliance check ==="

# The package.json license field must name the license in LICENSE (GPL v3; upstream headers
# say "or any later version").
PROJECT_LICENSE=$(bun -e 'console.log(require("./package.json").license)')
if grep -q 'GNU GENERAL PUBLIC LICENSE' LICENSE && [ "${PROJECT_LICENSE}" != "GPL-3.0-or-later" ]; then
    echo "ERROR: package.json license is '${PROJECT_LICENSE}' but LICENSE is GPL v3 (expected GPL-3.0-or-later)."
    exit 1
fi
command -v syft >/dev/null 2>&1 || { echo "ERROR: syft is not on PATH (scripts/local-ci.sh license-compliance installs the pinned release)."; exit 127; }
echo "Allowed licenses: ${ALLOWED}"
echo ""

# bun decides what ships: a frozen --production install of the locked graph into a scratch copy
# leaves exactly the production closure in node_modules (devDependencies never install), without
# touching the working tree's full install. Syft then reads each installed package's declared
# license; frontend_license_policy.py refuses anything the allowlist does not name, a package with
# no license, and a production dependency the scan did not see. Install scripts never run here.
mkdir -p "$ROOT_DIR/build"
WORK="$(mktemp -d "$ROOT_DIR/build/frontend-licenses.XXXXXX")"
trap 'rm -rf "${WORK:?}"' EXIT
cp package.json bun.lock bunfig.toml "$WORK/"
cp -R vendor "$WORK/vendor"
(cd "$WORK" && bun install --production --frozen-lockfile --ignore-scripts)
syft scan "dir:$WORK/node_modules" --override-default-catalogers javascript-package-cataloger \
    -o "syft-json=$WORK/catalog.json" -q
STATUS=0
python3 "$ROOT_DIR/scripts/frontend_license_policy.py" "$WORK/catalog.json" package.json "${ALLOWED}" || STATUS=$?

if [ "${STATUS}" -ne 0 ]; then
    echo ""
    echo "ERROR: One or more production dependencies use a license not in the allowlist."
    echo "Review the output above. If a license is acceptable, add its SPDX ID to ALLOWED in this script"
    echo "and to config/allowed-licenses.json for backend parity."
    exit 1
fi

echo ""
echo "All production frontend dependencies use allowed licenses."
