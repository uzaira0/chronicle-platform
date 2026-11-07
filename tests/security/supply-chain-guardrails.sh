#!/usr/bin/env bash
# Static supply-chain guardrails for CI/runtime reproducibility.
set -euo pipefail

REPORT_DIR="${1:-/tmp/chronicle-supply-chain-guardrails}"
ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
# The Bun pin's one source is toolchain-manifest.yaml (read with sed: this guard cannot depend on yq).
BUN_VERSION="$(sed -nE 's/^bun: "([^"]+)".*/\1/p' "$ROOT_DIR/toolchain-manifest.yaml")"
[ -n "$BUN_VERSION" ] || { echo '[fail] toolchain-manifest.yaml has no bun pin' >&2; exit 1; }
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
actual = dev_dependencies.get("bun-types")
if actual != expected_bun:
    problems.append(f"chronicle-web devDependency bun-types must be exactly {expected_bun}, found {actual!r}")
# Installs run with --ignore-scripts, so the `bun` npm package keeps its placeholder bin, and an
# installed placeholder shadows the runtime for every nested `bun run` (node_modules/.bin wins).
for section in ("dependencies", "devDependencies", "optionalDependencies"):
    if "bun" in package.get(section, {}):
        problems.append(f"chronicle-web {section} must not list the bun npm package (its bin needs a postinstall)")

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
    pass "OSV waivers each carry a reason, an owner and a dated recheck, expire within 62 days on staggered dates, and name a resolved version"
  else
    fail "OSV waivers need a reason, an owner, a dated recheck, a staggered expiry within 62 days and a resolved version; see $osv_waivers_file.problems"
  fi
  # The stale-entry rule for Trivy needs the release scans (publish-images.sh, local-ci.sh image-gate);
  # the fields, the expiry bound and the stagger are checked here on every run.
  if python3 -s -m unittest discover -s "$ROOT_DIR/tests/security" -p test_vulnerability_waivers.py &&
     python3 "$ROOT_DIR/tests/security/check-trivy-waivers.py" "$ROOT_DIR/.trivyignore.yaml"; then
    pass "Trivy waivers each carry a statement, an owner and a dated recheck, and expire within 62 days on staggered dates"
  else
    fail "Trivy waivers need a statement, an owner, a dated recheck and a staggered expiry within 62 days of it"
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
# Every place that installs web dependencies: workflows, scripts, the security runners and every
# Dockerfile (release images install inside BuildKit, where a lifecycle script runs as root).
paths = list((root / ".github").rglob("*.yml")) + list((root / ".github").rglob("*.yaml"))
paths += list((root / "scripts").glob("*.sh")) + list((root / "tests").rglob("*.sh"))
paths += [path for path in root.rglob("Dockerfile*")
          if path.is_file() and not {"node_modules", ".git", "build"} & set(path.relative_to(root).parts)]

for path in sorted(set(paths)):
    rel = path.relative_to(root)
    for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if "bun install" not in line or '"bun install"' in line:  # a quoted string is a matcher, not a run
            continue
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith("description:"):
            continue
        missing = [flag for flag in ("--frozen-lockfile", "--ignore-scripts") if flag not in line]
        if missing:
            problems.append(f"{rel}:{line_no}: missing {' '.join(missing)}: {stripped}")
        # Bun reads [install] (release age, peers) only from a bunfig.toml beside package.json.
        earlier = "\n".join(path.read_text(encoding="utf-8").splitlines()[:line_no - 1])
        if path.name.startswith("Dockerfile") and "bunfig.toml" not in earlier:
            problems.append(f"{rel}:{line_no}: bunfig.toml is not copied before this install: {stripped}")

report.write_text("\n".join(problems) + ("\n" if problems else ""), encoding="utf-8")
raise SystemExit(1 if problems else 0)
PY
  then
    fail "Bun installs without --frozen-lockfile --ignore-scripts found; see $unfrozen_file"
  else
    pass "every workflow, script and Dockerfile Bun install is frozen and runs no lifecycle scripts"
  fi
}

check_web_install_policy() {
  # bunfig.toml is the second layer behind Renovate and scripts/check-dependency-age.py: Bun itself
  # refuses to resolve a version younger than 7 days, and peers stay off (see the bunfig comment).
  if python3 - "$ROOT_DIR/chronicle-web/bunfig.toml" <<'PY'
import sys
import tomllib
with open(sys.argv[1], "rb") as handle:
    install = tomllib.load(handle).get("install", {})
problems = []
age = install.get("minimumReleaseAge")
if not isinstance(age, int) or age < 604800:
    problems.append(f"[install] minimumReleaseAge must be at least 604800 seconds, found {age!r}")
if install.get("peer") is not False:
    problems.append("[install] peer must be false")
for line in problems:
    print(f"chronicle-web/bunfig.toml: {line}")
raise SystemExit(1 if problems else 0)
PY
  then
    pass "chronicle-web/bunfig.toml holds back npm versions younger than 7 days"
  else
    fail "chronicle-web/bunfig.toml must set [install] minimumReleaseAge >= 604800 and peer = false"
  fi
}

check_dependency_check_suppressions() {
  # discover, not a file path: unittest maps a path to a module name, which breaks under a dotted
  # ROOT_DIR such as the release snapshot (chronicle-release-sca.XXXXXX).
  if python3 -s -m unittest discover -s "$ROOT_DIR/tests/security" -p test_supply_chain_policy.py &&
     python3 -s "$ROOT_DIR/tests/security/check-dependency-check-suppressions.py" \
       "$ROOT_DIR/config/dependency-check-suppression.xml" "$ROOT_DIR"; then
    pass "Dependency-Check suppressions expire within 90 days on staggered dates, name an owner and a recheck, pin versions, still match the runtime, and package-wide ones exclude resolved dependencies"
  else
    fail "Dependency-Check suppression policy or negative XML fixtures failed"
  fi
}

record "Chronicle supply-chain guardrails"
check_runtime_pins
check_action_pins
check_dependency_integrity_files
check_scanner_dependency_inputs
check_dependency_check_suppressions
check_frozen_web_installs
check_web_install_policy

if [ "$failures" -gt 0 ]; then
  record "Supply-chain guardrails failed with $failures finding(s)"
  exit 1
fi

record "Supply-chain guardrails passed"
