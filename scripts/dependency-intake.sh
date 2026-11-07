#!/usr/bin/env bash
# One scheduled dependency-intake pass (docs/SUPPLY-CHAIN.md): Renovate proposes, the gate runner decides.
#
#   scripts/dependency-intake.sh
#
# 1. scripts/renovate-run.sh opens or updates renovate/* branches against deps/auto, only for versions
#    past their wait (7 days routine, 14 major, 3 security).
# 2. scripts/dependency-gate-runner.py gates each new branch and fast-forwards deps/auto with the
#    ones that pass. Nothing reaches main, nothing is tagged or published.
#
# The launchd job installed by scripts/launchd/install-dependency-intake.sh runs this file. A run
# that finds the previous one still going exits at once rather than queueing: the pass holds a
# kernel lock (lockf -k) on intake.lock, released when the process exits, however it exits.
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
log_dir="${CHRONICLE_RENOVATE_LOG_DIR:-$HOME/Library/Logs/chronicle-dependency-intake}"
mkdir -p "$log_dir"
if [[ -z "${CHRONICLE_DEPENDENCY_INTAKE_LOCKED:-}" ]]; then
  export CHRONICLE_DEPENDENCY_INTAKE_LOCKED=1
  exec /usr/bin/lockf -k -t 0 "$log_dir/intake.lock" /bin/bash "${BASH_SOURCE[0]}" "$@"
fi

stamp=$(date -u +%Y%m%dT%H%M%SZ)
printf 'dependency-intake: %s start\n' "$stamp"
status=0
bash "$root/scripts/renovate-run.sh" --log "$log_dir/renovate-$stamp.log" || status=$?
# A failed Renovate run still leaves earlier branches to gate.
python3 "$root/scripts/dependency-gate-runner.py" --root "$root" || status=$?
printf 'dependency-intake: %s end, exit %s\n' "$(date -u +%Y%m%dT%H%M%SZ)" "$status"
exit "$status"
