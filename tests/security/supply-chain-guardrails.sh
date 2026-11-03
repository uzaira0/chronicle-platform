#!/usr/bin/env bash
# Static supply-chain guardrails for CI/runtime reproducibility.
set -euo pipefail

REPORT_DIR="${1:-/tmp/chronicle-supply-chain-guardrails}"
ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
BUN_VERSION="1.3.12"
# Bun is the sole JS runtime — Node is banned from workflows entirely
# (check_runtime_pins rejects any setup-node / node-version occurrence).

mkdir -p "$REPORT_DIR"
REPORT_FILE="$REPORT_DIR/supply-chain-guardrails.txt"
: > "$REPORT_FILE"

failures=0

record() {
  printf '%s\n' "$*" | tee -a "$REPORT_FILE"
}

fail() {
  failures=$((failures + 1))
  record "[fail] $*"
}

pass() {
  record "[ok] $*"
}

require_file() {
  local path="$1"
  if [ ! -f "$ROOT_DIR/$path" ]; then
    fail "missing required supply-chain file: $path"
  else
    pass "found $path"
  fi
}

check_runtime_pins() {
  local bad_runtime_file="$REPORT_DIR/mutable-runtime-versions.txt"
  : > "$bad_runtime_file"

  while IFS= read -r -d '' file; do
    if grep -nE 'bun-version:[[:space:]]*["'\'']?(latest|canary|nightly)["'\'']?([[:space:]]|$)' "$file" >> "$bad_runtime_file"; then
      :
    fi
    if grep -nE 'node-version:|actions/setup-node' "$file" >> "$bad_runtime_file"; then
      :
    fi
    # Root and every submodule .github (sibling dirs, not under root/.github).
  done < <(find "$ROOT_DIR/.github" "$ROOT_DIR"/*/.github -type f \( -name '*.yml' -o -name '*.yaml' \) -print0 2>/dev/null)

  if [ -s "$bad_runtime_file" ]; then
    fail "forbidden runtime declarations found (Node is banned; Bun must not float); see $bad_runtime_file"
  else
    pass "no floating Bun versions and no Node runtime in GitHub workflow files"
  fi

  if ! python3 - "$ROOT_DIR" "$BUN_VERSION" "$REPORT_DIR/runtime-pin-mismatches.txt" <<'PY'
import pathlib
import re
import sys

root = pathlib.Path(sys.argv[1])
expected_bun = sys.argv[2]
report = pathlib.Path(sys.argv[3])
problems = []

github_dirs = [root / ".github"] + sorted(root.glob("*/.github"))
runtime_files = []
for gh in github_dirs:
    runtime_files += sorted(gh.rglob("*.yml")) + sorted(gh.rglob("*.yaml"))

for path in runtime_files:
    rel = path.relative_to(root)
    for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        bun_match = re.search(r"\bbun-version:\s*['\"]?([^'\"\s#]+)", line)
        if bun_match and bun_match.group(1) != expected_bun:
            problems.append(f"{rel}:{line_no}: bun-version must be {expected_bun}, found {bun_match.group(1)}")

        if re.search(r"\bnode-version:|actions/setup-node", line):
            problems.append(f"{rel}:{line_no}: Node is banned from workflows (Bun is the sole JS runtime)")

report.write_text("\n".join(problems) + ("\n" if problems else ""), encoding="utf-8")
raise SystemExit(1 if problems else 0)
PY
  then
    fail "CI runtime version mismatch; see $REPORT_DIR/runtime-pin-mismatches.txt"
  else
    pass "all declared Bun and Node workflow runtimes match pinned policy"
  fi

  if ! python3 - "$ROOT_DIR/chronicle-web/package.json" "$BUN_VERSION" \
      "$REPORT_DIR/web-runtime-pin-mismatches.txt" <<'PY'
import json
import pathlib
import sys

package_path = pathlib.Path(sys.argv[1])
expected_bun = sys.argv[2]
report = pathlib.Path(sys.argv[3])
package = json.loads(package_path.read_text(encoding="utf-8"))
dev_dependencies = package.get("devDependencies", {})
problems = []

if package.get("engines", {}).get("bun") != expected_bun:
    problems.append(f"chronicle-web engines.bun must be exactly {expected_bun}")
for dependency in ("bun", "bun-types"):
    actual = dev_dependencies.get(dependency)
    if actual != expected_bun:
        problems.append(
            f"chronicle-web devDependency {dependency} must be exactly "
            f"{expected_bun}, found {actual!r}"
        )

report.write_text("\n".join(problems) + ("\n" if problems else ""), encoding="utf-8")
raise SystemExit(1 if problems else 0)
PY
  then
    fail "web package runtime pins mismatch; see $REPORT_DIR/web-runtime-pin-mismatches.txt"
  else
    pass "web engine and types match the installed CI runtime policy"
  fi
}

check_action_pins() {
  if ! python3 - "$ROOT_DIR" "$REPORT_DIR/action-pin-violations.txt" <<'PY'
import pathlib
import re
import sys

root = pathlib.Path(sys.argv[1])
report = pathlib.Path(sys.argv[2])
problems = []
uses_re = re.compile(r"^\s*-?\s*uses:\s*([^#\s]+)")
sha_ref_re = re.compile(r"@[0-9a-f]{40}$")

# Root workflows AND every submodule's workflows: a submodule with a mutable
# action tag is an attack path into the same participant-data backend, so the pin guard must
# not stop at the root .github (its sibling submodule .github dirs were the
# blind spot that let two gitleaks workflows float on @v4/@v2 unnoticed).
github_dirs = [root / ".github"] + sorted(root.glob("*/.github"))
workflow_files = []
for gh in github_dirs:
    workflow_files += sorted(gh.rglob("*.yml")) + sorted(gh.rglob("*.yaml"))

for path in workflow_files:
    rel = path.relative_to(root)
    for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        match = uses_re.match(line)
        if not match:
            continue
        spec = match.group(1).strip("'\"")
        if spec.startswith("./") or spec.startswith("docker://"):
            continue
        if not sha_ref_re.search(spec):
            problems.append(f"{rel}:{line_no}: external action is not pinned to a full commit SHA: {spec}")

report.write_text("\n".join(problems) + ("\n" if problems else ""), encoding="utf-8")
raise SystemExit(1 if problems else 0)
PY
  then
    fail "unpinned GitHub Action references found; see $REPORT_DIR/action-pin-violations.txt"
  else
    pass "all external GitHub Actions are pinned to full commit SHAs"
  fi
}

check_dependency_integrity_files() {
  require_file "gradle/verification-metadata.xml"
  require_file "chronicle-api/gradle.lockfile"
  require_file "chronicle-models/gradle.lockfile"
  require_file "chronicle-server/gradle.lockfile"
  require_file "chronicle/app/gradle.lockfile"
  require_file "rhizome-client/gradle.lockfile"
  require_file "rhizome/gradle.lockfile"
  require_file "chronicle-web/bun.lock"
}

check_scanner_dependency_inputs() {
  local osv_waivers_file="$REPORT_DIR/osv-waiver-configs.txt"
  : > "$osv_waivers_file"

  # Run the real gate jobs with recording stubs in place of the scanners.
  local scanner_calls="$REPORT_DIR/scanner-calls.txt"
  if bash -s -- "$ROOT_DIR/scripts/local-ci.sh" "$scanner_calls" <<'SH'
source "$1"
calls="$2"
: >"$calls"
ensure_osv_scanner() { :; }
ensure_grype() { :; }
osv-scanner() { printf 'osv %s\n' "$*" >>"$calls"; }
grype() { printf 'grype %s\n' "$*" >>"$calls"; }
job_osv && job_grype
SH
  then
    pass "OSV and Grype gate jobs ran against recording stubs"
  else
    fail "OSV/Grype gate jobs failed against recording stubs"
  fi
  if grep -Fq -- "--config $ROOT_DIR/osv-scanner.toml --experimental-exclude r:(^|/)gradle(\$|/)" "$scanner_calls"; then
    pass "OSV scans resolved manifests without treating nested Gradle verification hashes as dependencies"
  else
    fail "OSV source scans must load osv-scanner.toml and recursively exclude Gradle artifact-hash catalog directories"
  fi
  if grep -Fq -- "--config $ROOT_DIR/osv-scanner.toml --lockfile $ROOT_DIR/chronicle/gradle/verification-metadata.xml" "$scanner_calls"; then
    pass "OSV scans the Android build toolchain catalog as a lockfile"
  else
    fail "OSV must scan chronicle/gradle/verification-metadata.xml as a lockfile so build-toolchain advisories reach the gate"
  fi
  if grep -Fq -- "grype --config $ROOT_DIR/.grype.yaml dir:$ROOT_DIR" "$scanner_calls" &&
     grep -Fq 'gradle/verification-metadata.xml' "$ROOT_DIR/.grype.yaml"; then
    pass "Grype uses the checked-in config and excludes Gradle verification hashes"
  else
    fail "Grype runners must load .grype.yaml and exclude gradle/verification-metadata.xml"
  fi

  find "$ROOT_DIR" -maxdepth 2 -type f -name 'osv-scanner.toml' -print \
    > "$osv_waivers_file"
  if ! python3 "$ROOT_DIR/tests/security/check-osv-waivers.py" --self-test; then
    fail "OSV waiver checker self-test failed"
  elif xargs -r python3 "$ROOT_DIR/tests/security/check-osv-waivers.py" < "$osv_waivers_file" > "$osv_waivers_file.problems"; then
    pass "OSV waivers each carry a reason and expire within 62 days"
  else
    fail "OSV waivers need a reason and an expiry within 62 days; see $osv_waivers_file.problems"
  fi

}

check_frozen_web_installs() {
  local unfrozen_file="$REPORT_DIR/unfrozen-web-installs.txt"
  : > "$unfrozen_file"

  if ! python3 - "$ROOT_DIR" "$unfrozen_file" <<'PY'
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
report = pathlib.Path(sys.argv[2])
problems = []
paths = list((root / ".github").rglob("*.yml")) + list((root / ".github").rglob("*.yaml"))
paths += list((root / "scripts").glob("*.sh"))

for path in sorted(paths):
    rel = path.relative_to(root)
    for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if "bun install" not in line:
            continue
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith("description:"):
            continue
        if "--frozen-lockfile" not in line:
            problems.append(f"{rel}:{line_no}: {stripped}")

report.write_text("\n".join(problems) + ("\n" if problems else ""), encoding="utf-8")
raise SystemExit(1 if problems else 0)
PY
  then
    fail "Bun installs without --frozen-lockfile found; see $unfrozen_file"
  else
    pass "all CI/script Bun installs are frozen"
  fi
}

check_dependency_check_suppressions() {
  if python3 -s -m unittest "$ROOT_DIR/tests/security/test_supply_chain_policy.py" &&
     python3 -s "$ROOT_DIR/tests/security/check-dependency-check-suppressions.py" \
       "$ROOT_DIR/config/dependency-check-suppression.xml" "$ROOT_DIR"; then
    pass "Dependency-Check package-wide suppressions have bounded expiry and exclude resolved dependencies"
  else
    fail "Dependency-Check package-wide suppression policy or negative XML fixtures failed"
  fi
}

record "Chronicle supply-chain guardrails"
check_runtime_pins
check_action_pins
check_dependency_integrity_files
check_scanner_dependency_inputs
check_dependency_check_suppressions
check_frozen_web_installs

if [ "$failures" -gt 0 ]; then
  record "Supply-chain guardrails failed with $failures finding(s)"
  exit 1
fi

record "Supply-chain guardrails passed"
