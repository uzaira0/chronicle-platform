#!/usr/bin/env bash
PMD_VERSION="7.18.0"
WEB_E2E_TIMEOUT_SECONDS=900
# Run the parts of GitHub CI that are meaningful on a developer workstation.
#
# This intentionally does not emulate GitHub-only plumbing such as artifact
# upload, SARIF upload to the Security tab, PR annotations, or Actions cache
# restore/save. It does run the same underlying build, test, and scanner
# commands so failures can be reproduced before pushing.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=tests/security/lib/selfhost-python.sh
source "$ROOT_DIR/tests/security/lib/selfhost-python.sh"
WEB_DIR="$ROOT_DIR/chronicle-web"
LOCAL_BIN_DIR="${CHRONICLE_LOCAL_BIN_DIR:-$ROOT_DIR/.local/bin}"
LOCAL_REPORT_DIR="${CHRONICLE_LOCAL_CI_REPORT_DIR:-}"
# One NVD database for every checkout and worktree; a per-checkout copy re-downloads the whole feed.
export CHRONICLE_DEPCHECK_DATA_DIR="${CHRONICLE_DEPCHECK_DATA_DIR:-$HOME/.cache/chronicle/dependency-check-data}"
if [[ -n "$LOCAL_REPORT_DIR" && "$LOCAL_REPORT_DIR" != /* ]]; then
  LOCAL_REPORT_DIR="$PWD/$LOCAL_REPORT_DIR"
fi

export PATH="$LOCAL_BIN_DIR:$PATH"

# shellcheck disable=SC2034 # job_group_members reads this array through indirect expansion.
fast_jobs=(engineering preflight architecture duplication migration-safety web web-e2e api-probes web-a11y jvm-smoke repo-automation linkml-ssot dead-code security-layers dependency-sbom license-compliance android-unit selfhost-python diff-coverage)
# shellcheck disable=SC2034 # job_group_members reads this array through indirect expansion.
security_jobs=(engineering gitleaks dependency-age gradle-depcheck bun-audit deps-freshness detekt pmd bearer osv grype syft fuzz)
# shellcheck disable=SC2034 # job_group_members reads this array through indirect expansion.
containers_jobs=(selfhost dockerfile-lint iac-scan container-structure upload-body-limit-edge android-replay route-surface-edge fluent-bit-config)
# shellcheck disable=SC2034 # job_group_members reads this array through indirect expansion.
all_jobs=(fast security containers contract-drift parity k6-benchmarks)
job_groups=(fast security containers all)

job_group_members() {
  local group="${1}_jobs[*]"
  printf '%s\n' "${!group}"
}

usage() {
  cat <<'EOF'
Usage: scripts/local-ci.sh <job> [job...]

Fast jobs:
  preflight             Validate local toolchain and workspace basics
  route-surface-edge    Public/retired routes across pinned Caddy, Nginx and Traefik
  engineering           Native ast-grep and Semgrep defect rules and tests
  architecture          Source ownership, dependency boundaries, negative fixtures
  migration-safety      Fresh baseline SQL, destructive-change approval, unique versions
  selfhost-restore      Restore continuity, failure, and orchestration fixture suites
  selfhost-python       Strict operator Python suite with coverage
  contract-drift        Shared contract values across current consumers
  diff-coverage         Require 80% coverage of changed executable lines per repository
  duplication           Reject new production clones against the CPD baseline
  migration-lint        Squawk only SQL migrations added since the base
  web                   chronicle-web audit, checks, tests, build, size
  web-a11y              chronicle-web axe WCAG 2 A/AA scans in Chromium (Playwright)
  web-e2e               Every browser spec against the isolated Testcontainers backend
  api-probes            Cross-study/admin/export authorization probes and GET Schemathesis against that backend
  jvm-smoke             Gradle project list, OpenAPI validation, shared/API/server tests, JaCoCo, Checkstyle, SpotBugs, PIT
  repo-automation       Compose config + repo guardrail scripts
  linkml-ssot           LinkML schema freshness and domain contract drift checks
  dead-code             chronicle-web knip dead-code analysis
  security-layers       every offline tests/security/run-all-security.sh layer
  dependency-sbom       Backend CycloneDX SBOM generation
  license-compliance    Backend and frontend license checks
  detekt                Kotlin Detekt scan with the pinned CI CLI jar
  android-unit          Android SAST, lintOpenRelease, verifier self-tests, unit tests of every app flavor
  android-instrumented  Room/Keystore instrumented tests of every module on the attached device (ANDROID_SERIAL)

Container/IaC jobs:
  selfhost              Turnkey setup, monitoring privacy, release bundle, supported matrix
  dockerfile-lint       Hadolint the Dockerfiles
  iac-scan              Checkov Dockerfile and compose scans
  container-structure   Build/test every shipped selfhost image structure
  image-gate            Release images as published (linux/amd64, committed HEAD): structure, SSH, listeners, image policy, trivy
  upload-body-limit-edge  Android maximum upload bodies through the shipped Caddy and server filters
  android-replay        Android-captured enrollment, uploads, identity labels and survey links into server, export and web
  http-smoke-stack      Disposable-host only: build/start smoke stack, HTTP/upload tests, tear down
  http-security         Upload, load smoke and race tests against a disposable self-host fixture
  selfhost-browser      Deployed archive journey; requires both listeners and dashboard password

Operator evidence job:

Security/dependency jobs:
  depcheck-locks        Validate/optionally clean stale Dependency-Check locks
  gradle-depcheck       OWASP Dependency-Check with shared NVD update
  bun-audit             Bun high/critical dependency audit
  deps-freshness        Pins vs upstream releases; fails on unaccepted major lag
  dependency-age        New or changed pins younger than the wait (7/14/3 days), unreviewed new names, OSV MAL-
  fluent-bit-config     Every shipped fluent-bit config loads on the manifest-pinned image
  gitleaks              Full-history secrets scan across root and all submodules
  pmd                   PMD bug-pattern scan
  bearer                Bearer SAST data-flow scan
  osv                   OSV-Scanner recursive SARIF scan
  grype                 Grype recursive repository scan
  syft                  Syft SPDX JSON SBOM
  gate-tools            Fetch every security tool and grype's database (the dependency gate's tools step)

Slow/specialized jobs:
  pit                   PIT mutation test for chronicle-server
  fuzz                  Jazzer fuzz tests
  parity                Kotlin and TypeScript parity tests
  web-mutation          Stryker mutation tests
  k6-benchmarks         Every load script against explicitly enrolled synthetic devices
  ios-verify            iOS contract freshness + simulator test suite (macOS)

Groups:
EOF
  local group
  for group in "${job_groups[@]}"; do
    printf '  %-22s %s\n' "$group" "$(job_group_members "$group")"
  done
  printf '\n'
  usage_environment
}

usage_environment() {
  cat <<'EOF'
Environment:
  NVD_API_KEY           Required for gradle-depcheck
  CHRONICLE_NVD_API_KEY_FILE
                        Optional private file containing NVD_API_KEY on line 1
  CHRONICLE_NVD_KEYCHAIN_SERVICE, CHRONICLE_NVD_KEYCHAIN_ACCOUNT
                        Optional macOS Keychain service/account override.
                        Default service: chronicle-nvd-api-key
  scripts/chronicle-store-nvd-api-key.sh
                        Safe one-time helper for installing the NVD key into
                        Keychain or a private file without printing it.
  SKIP_NVD_UPDATE=1     Reuse the existing NVD database for gradle-depcheck; it must
                        carry the update record a keyed run writes
                        (chronicle-nvd-updated-utc) and be no older than
                        CHRONICLE_DEPCHECK_MAX_AGE_HOURS, else the job exits 2
  CHRONICLE_DEPCHECK_MAX_AGE_HOURS
                        Oldest NVD database a cache-only run accepts, default 168
  CHRONICLE_DEPCHECK_DATA_DIR
                        Shared NVD database for all checkouts, default
                        ~/.cache/chronicle/dependency-check-data
  CHRONICLE_LOCAL_BIN_DIR
                        Tool download/cache dir, default ./.local/bin
  CHRONICLE_LOCAL_CI_REPORT_DIR
                        Optional report directory for scanner outputs. When unset,
                        outputs stay at the GitHub Actions-compatible paths.
                        For, the bundle is written directly to
                        this directory.
  API_KEY, TEST_STUDY_ID, TEST_PARTICIPANT_ID, TEST_RANDOM_DEVICE_ID
                        Enrolled sensor fixture required by http-security and http-smoke-stack
  BASE_URL, AUTH_TOKEN, MOBILE_SIGNING_SECRET
                        Fixture URL, researcher bearer and legacy HMAC secret for http-security
  HMAC_TEST_PATH, MOBILE_ENROLLMENT_BODY
                        Valid legacy enrollment fixture for the strict HMAC live probe
  CHRONICLE_DIFF_BASE   Optional root Git base for diff-coverage and migration-lint
  CHRONICLE_DUPLICATION_UPDATE_BASELINE=1
                        Regenerate the baseline with the duplication job (pinned PMD)
  CHRONICLE_MIGRATION_BASE
                        Optional server Git base for migration-lint; otherwise the
                        root base's submodule commit, then origin/main / HEAD~1
  GRYPE_FAIL_ON         Failure threshold for grype; empty means evidence-only
  CHRONICLE_LOCAL_CI_KEEP_GOING=1
                        Continue running requested top-level jobs after a
                        failure, then exit nonzero. Use for evidence collection
                        so later scanner artifacts are still produced.
  CHRONICLE_DEPCHECK_RERUN=1
                        Pass --rerun-tasks to Dependency-Check analysis so
                        reports are regenerated after scanner config changes.
  CHRONICLE_DEPCHECK_UPDATE_TIMEOUT_SECONDS
                        Timeout for fresh NVD update, default 3600. Set 0 to
                        disable only for supervised first-time cache seeding.
  CHRONICLE_DEPCHECK_UPDATE_LOG
                        Optional path for the redacted fresh NVD update log.
                        Default: dependency-check-update.log in the report dir.
  CHRONICLE_DEPCHECK_CLEAN_STALE_LOCKS=1
                        Remove stale NVD database *.lock files before
                        a fresh update, but only when no Gradle/Dependency-Check
                        process is running. Default is fail-closed on locks.
EOF
}

log() {
  printf '\n[local-ci] %s\n' "$*"
}

run_with_timeout() {
  local seconds="$1"
  shift
  if [[ "$seconds" == "0" ]]; then
    "$@"
    return
  fi
  require_cmd python3 "install Python 3 or set CHRONICLE_DEPCHECK_UPDATE_TIMEOUT_SECONDS=0 for supervised runs"
  python3 - "$seconds" "$@" <<'PY'
import os
import signal
import subprocess
import sys
import time

timeout = float(sys.argv[1])
cmd = sys.argv[2:]
proc = subprocess.Popen(cmd, preexec_fn=os.setsid)
try:
    sys.exit(proc.wait(timeout=timeout))
except subprocess.TimeoutExpired:
    sys.stderr.write(f"[local-ci] command timed out after {int(timeout)}s: {' '.join(cmd)}\n")
    try:
        os.killpg(proc.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            sys.exit(124)
        time.sleep(0.5)
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    sys.exit(124)
PY
}

run_with_timeout_logged() {
  local seconds="$1" log_file="$2"
  shift 2
  require_cmd python3 "install Python 3"
  ensure_dir "$(dirname "$log_file")"
  : > "$log_file"
  if [[ "$seconds" == 0 ]]; then
    "$@" 2>&1 | python3 "$ROOT_DIR/scripts/local-ci-timeout.py" "$seconds" "$log_file"
    return "${PIPESTATUS[0]}"
  fi
  python3 "$ROOT_DIR/scripts/local-ci-timeout.py" "$seconds" "$log_file" "$@"
}

dependency_check_data_snapshot() {
  local output="$1"
  local data_dir="$CHRONICLE_DEPCHECK_DATA_DIR"
  ensure_dir "$(dirname "$output")"
  {
    printf 'timestamp_utc\t%s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    printf 'data_dir\t%s\n' "$data_dir"
    if [[ ! -d "$data_dir" ]]; then
      printf 'status\tmissing\n'
      return
    fi
    printf 'status\tpresent\n'
    printf 'locks\t%s\n' "$(dependency_check_lock_listing | tr '\n' ' ' | sed 's/[[:space:]]*$//')"
    printf 'files:\n'
    while IFS= read -r file; do
      [[ -z "$file" ]] && continue
      if stat -f '%z	%Sm	%N' "$file" >/dev/null 2>&1; then
        stat -f '%z	%Sm	%N' "$file"
      else
        stat -c '%s	%y	%n' "$file"
      fi
    done < <(find "$data_dir" -maxdepth 1 -type f -print 2>/dev/null | sort)
  } > "$output"
}

diagnose_dependency_check_data() {
  local data_dir="$CHRONICLE_DEPCHECK_DATA_DIR"
  if [[ ! -d "$data_dir" ]]; then
    return
  fi
  local lock_listing
  lock_listing="$(dependency_check_lock_listing)"
  if [[ -z "$lock_listing" ]]; then
    return
  fi

  printf '[local-ci] Dependency-Check lock file(s) present before fresh update:\n' >&2
  while IFS= read -r lock_file; do
    [[ -z "$lock_file" ]] && continue
    if stat -f '%Sm %N' "$lock_file" >/dev/null 2>&1; then
      stat -f '[local-ci]   %Sm %N' "$lock_file" >&2
    else
      stat -c '[local-ci]   %y %n' "$lock_file" >&2
    fi
  done <<<"$lock_listing"

  local active_processes
  active_processes="$(dependency_check_active_processes)"
  if [[ -n "$active_processes" ]]; then
    printf '[local-ci] refusing to touch Dependency-Check locks while related process(es) are running:\n%s\n' "$active_processes" >&2
    exit 2
  fi

  if [[ "${CHRONICLE_DEPCHECK_CLEAN_STALE_LOCKS:-0}" == "1" ]]; then
    while IFS= read -r lock_file; do
      [[ -z "$lock_file" ]] && continue
      rm -f -- "$lock_file"
      printf '[local-ci] removed stale Dependency-Check lock: %s\n' "$lock_file" >&2
    done <<<"$lock_listing"
  else
    cat >&2 <<'EOF'
[local-ci] refusing fresh Dependency-Check update with pre-existing lock files.
[local-ci] If no Gradle/Dependency-Check process is running and these are stale
[local-ci] locks from an interrupted update, rerun with:
[local-ci]   CHRONICLE_DEPCHECK_CLEAN_STALE_LOCKS=1 scripts/local-ci.sh gradle-depcheck
EOF
    exit 2
  fi
}

# When the shared NVD database last finished an update. Dependency-Check keeps that time inside its H2
# database, which nothing outside the JVM reads, so this job records it next to the database after a
# successful update; the gate runner's copy carries the record with it.
DEPCHECK_UPDATED_RECORD=chronicle-nvd-updated-utc

dependency_check_record_update() {
  date -u '+%Y-%m-%dT%H:%M:%SZ' > "$CHRONICLE_DEPCHECK_DATA_DIR/$DEPCHECK_UPDATED_RECORD"
}

# A cache-only scan (SKIP_NVD_UPDATE=1) of an undated or stale database would pass exactly like a fresh
# one, so it prints the database's age and refuses (status 2) one with no record of its last update or
# one older than CHRONICLE_DEPCHECK_MAX_AGE_HOURS.
dependency_check_require_fresh() {
  python3 - "$CHRONICLE_DEPCHECK_DATA_DIR/$DEPCHECK_UPDATED_RECORD" "${CHRONICLE_DEPCHECK_MAX_AGE_HOURS:-168}" <<'PY'
import datetime as dt
import sys
from pathlib import Path

record, limit = Path(sys.argv[1]), int(sys.argv[2])
refresh = 'refresh it with the NVD key: scripts/local-ci.sh gradle-depcheck (without SKIP_NVD_UPDATE)'
try:
    updated = dt.datetime.strptime(record.read_text().strip(), '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=dt.UTC)
except (OSError, ValueError):
    print(f'[local-ci] no record of when the NVD database in {record.parent} was last updated ({record.name}); {refresh}',
          file=sys.stderr)
    sys.exit(2)
hours = int((dt.datetime.now(dt.UTC) - updated).total_seconds() // 3600)
stamp = updated.strftime('%Y-%m-%dT%H:%M:%SZ')
if hours > limit:
    print(f'[local-ci] NVD database is stale: last updated {stamp} ({hours} hours ago; limit {limit}); {refresh}',
          file=sys.stderr)
    sys.exit(2)
print(f'[local-ci] NVD database last updated {stamp} ({hours} hours ago; limit {limit})')
PY
}

dependency_check_lock_listing() {
  local data_dir="$CHRONICLE_DEPCHECK_DATA_DIR"
  find "$data_dir" -maxdepth 1 -type f -name '*.lock' -print 2>/dev/null | sort || true
}

dependency_check_active_processes() {
  ps -axo pid=,ppid=,command= |
    grep -E 'dependencyCheck|dependency-check|org\.gradle|GradleDaemon|odc\.mv\.db|jsrepository\.json' |
    grep -v -E 'grep -E|scripts/local-ci\.sh' || true
}

require_cmd() {
  local cmd="$1"
  local hint="${2:-install $cmd and retry}"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    printf '[local-ci] missing required command: %s (%s)\n' "$cmd" "$hint" >&2
    exit 127
  fi
}

require_jdk21() {
  local java_bin
  if [[ -n "${JAVA_HOME:-}" && -x "$JAVA_HOME/bin/java" ]]; then
    java_bin="$JAVA_HOME/bin/java"
  else
    # Prefer manifest JDK from the usual local install dirs over whatever java is on PATH.
    local jdk_major cand
    jdk_major="$(yq -r '.jdk.build_runtime' "$ROOT_DIR/toolchain-manifest.yaml" 2>/dev/null || echo 25)"
    # Homebrew's openjdk@N is not registered with /usr/libexec/java_home, so name its prefix too.
    for cand in "$HOME/.local/jdks/temurin-$jdk_major" "$HOME/.sdkman/candidates/java/current" \
                "/usr/lib/jvm/temurin-$jdk_major-jdk" "/usr/lib/jvm/java-$jdk_major-openjdk" \
                "${HOMEBREW_PREFIX:-/opt/homebrew}/opt/openjdk@$jdk_major/libexec/openjdk.jdk/Contents/Home" \
                "/usr/local/opt/openjdk@$jdk_major/libexec/openjdk.jdk/Contents/Home"; do
      if [[ -x "$cand/bin/java" ]]; then
        export JAVA_HOME="$cand"
        break
      fi
    done
    if [[ -n "${JAVA_HOME:-}" && -x "$JAVA_HOME/bin/java" ]]; then
      java_bin="$JAVA_HOME/bin/java"
    else
      require_cmd java "install JDK $jdk_major and set JAVA_HOME"
      java_bin="$(command -v java)"
    fi
  fi

  local version major
  version="$("$java_bin" -version 2>&1 | awk -F '"' '/version/ { print $2; exit }')"
  major="${version%%.*}"
  if [[ "$major" == "1" ]]; then
    major="$(cut -d. -f2 <<<"$version")"
  fi
  if [[ -z "$major" || "$major" -lt 21 ]]; then
    printf '[local-ci] JDK 21+ is required; found java version %s at %s.\n' "${version:-unknown}" "$java_bin" >&2
    printf '[local-ci] Try: export JAVA_HOME=$HOME/.local/jdks/temurin-25 (see toolchain-manifest.yaml)\n' >&2
    exit 127
  fi
}

sha256_check() {
  local expected="$1"
  local file="$2"
  # The "<file>: OK" report goes to stderr: callers capture `ensure_<tool>; command -v <tool>`.
  if command -v sha256sum >/dev/null 2>&1; then
    printf '%s  %s\n' "$expected" "$file" | sha256sum -c - >&2
  elif command -v shasum >/dev/null 2>&1; then
    printf '%s  %s\n' "$expected" "$file" | shasum -a 256 -c - >&2
  else
    printf '[local-ci] missing sha256sum/shasum for verifying %s\n' "$file" >&2
    exit 127
  fi
}

# Prints $1 distinct ports the OS reports free right now. A fixed default port collides with
# whatever else listens on, or holds an outgoing connection from, this host.
free_ports() {
  python3 - "$1" <<'PY'
import socket
import sys

sockets = [socket.socket() for _ in range(int(sys.argv[1]))]
for server in sockets:
    server.bind(('', 0))
print(' '.join(str(server.getsockname()[1]) for server in sockets))
PY
}

gradle() {
  CHRONICLE_TEST_HTTP_PORT="${CHRONICLE_TEST_HTTP_PORT:-$(free_ports 1)}" "$ROOT_DIR/gradlew" --no-daemon "$@"
}

ensure_dir() {
  mkdir -p "$1"
}

report_path() {
  local default_path="$1"
  local report_name="$2"
  if [[ -n "$LOCAL_REPORT_DIR" ]]; then
    ensure_dir "$LOCAL_REPORT_DIR"
    printf '%s/%s\n' "$LOCAL_REPORT_DIR" "$report_name"
  else
    printf '%s\n' "$default_path"
  fi
}

copy_dependency_check_reports() {
  if [[ -z "$LOCAL_REPORT_DIR" ]]; then
    return 0
  fi

  local report_dir="$LOCAL_REPORT_DIR/dependency-check"
  local manifest="$LOCAL_REPORT_DIR/dependency-check-reports.txt"
  local count=0
  ensure_dir "$report_dir"
  : > "$manifest"

  while IFS= read -r -d '' report; do
    local rel safe_name dest
    rel="${report#$ROOT_DIR/}"
    safe_name="${rel//\//__}"
    dest="$report_dir/$safe_name"
    cp "$report" "$dest"
    printf '%s\t%s\n' "$rel" "${dest#$LOCAL_REPORT_DIR/}" >> "$manifest"
    count=$((count + 1))
  done < <(find "$ROOT_DIR" -path '*/build/reports/dependency-check-report.*' -type f -print0 | sort -z)

  if [[ "$count" -eq 0 ]]; then
    printf '[local-ci] no OWASP Dependency-Check reports found under */build/reports.\n' >&2
    return 1
  fi

  printf '[local-ci] copied %s OWASP Dependency-Check report(s) into %s\n' "$count" "$report_dir"
}

write_dependency_check_skip_report() {
  local reason="$1"
  local report_dir="$ROOT_DIR/build/reports/security"
  ensure_dir "$report_dir"
  {
    printf 'OWASP Dependency-Check did not run.\n'
    printf 'reason=%s\n' "$reason"
    printf 'mode=cache-only\n'
    printf 'required_followup=Run scheduled or manual Security Vulnerability Scan for fresh keyed NVD analysis.\n'
  } > "$report_dir/dependency-check-skipped.txt"
}

machine_os() {
  case "$(uname -s)" in
    Linux) echo linux ;;
    Darwin) echo darwin ;;
    *) printf '[local-ci] unsupported OS: %s\n' "$(uname -s)" >&2; exit 127 ;;
  esac
}

export_docker_host_from_context() {
  [[ -z "${DOCKER_HOST:-}" && "$(uname -s)" == Darwin ]] || return 0
  command -v docker >/dev/null 2>&1 || return 0
  local host
  host="$(docker context inspect --format '{{.Endpoints.docker.Host}}' 2>/dev/null)" || return 0
  [[ "$host" == unix://* && -S "${host#unix://}" ]] || return 0
  export DOCKER_HOST="$host"
  export TESTCONTAINERS_DOCKER_SOCKET_OVERRIDE="${TESTCONTAINERS_DOCKER_SOCKET_OVERRIDE:-/var/run/docker.sock}"
}

machine_arch() {
  case "$(uname -m)" in
    x86_64|amd64) echo amd64 ;;
    arm64|aarch64) echo arm64 ;;
    *) printf '[local-ci] unsupported architecture: %s\n' "$(uname -m)" >&2; exit 127 ;;
  esac
}

gate_tool_temp() {
  local directory="$ROOT_DIR/build/tool-downloads"
  ensure_dir "$directory"
  mktemp "$@" "$directory/work.XXXXXX"
}

download_asset() {
  local url="$1"
  local output="$2"
  require_cmd curl
  curl -fsSL \
    --max-time 60 \
    --retry 5 \
    --retry-all-errors \
    --retry-delay 2 \
    --retry-max-time 120 \
    --connect-timeout 20 \
    "$url" \
    -o "$output"
}

# Prints the sha256 toolchain-manifest.yaml commits for a gate tool's asset at this version and
# platform (os-arch, or "any"). Exits when the manifest has no digest for it or names another version,
# so every downloaded tool needs a committed digest.
pinned_tool_sha256() {
  local tool="$1" version="$2" platform="$3" manifest="$ROOT_DIR/toolchain-manifest.yaml" pinned_version sha
  require_cmd yq
  pinned_version="$(yq -r ".gate_tools.\"$tool\".version // \"\"" "$manifest")"
  sha="$(yq -r ".gate_tools.\"$tool\".sha256.\"$platform\" // \"\"" "$manifest")"
  if [[ "$pinned_version" != "$version" ]]; then
    printf '[local-ci] %s %s: toolchain-manifest.yaml gate_tools pins version %s; update the version and digests together\n' \
      "$tool" "$version" "${pinned_version:-none}" >&2
    exit 1
  fi
  if [[ ! "$sha" =~ ^[0-9a-f]{64}$ ]]; then
    printf '[local-ci] %s %s: no committed sha256 for %s in toolchain-manifest.yaml gate_tools\n' "$tool" "$version" "$platform" >&2
    exit 1
  fi
  printf '%s\n' "$sha"
}

# The committed digest is the trust root; the release's checksums file must agree with it.
download_asset_with_checksum() {
  local pinned="$1"
  local asset_url="$2"
  local checksum_url="$3"
  local asset_name="$4"
  local output="$5"
  local checksum_file expected
  if [[ ! "$pinned" =~ ^[0-9a-f]{64}$ ]]; then
    printf '[local-ci] %s: no committed sha256 (toolchain-manifest.yaml gate_tools); refusing to download\n' "$asset_name" >&2
    exit 1
  fi
  checksum_file="$(gate_tool_temp)"
  download_asset "$asset_url" "$output"
  download_asset "$checksum_url" "$checksum_file"
  expected="$(awk -v asset="$asset_name" '
    {
      if (NF == 1 && $1 ~ /^[0-9a-fA-F]{64}$/) {
        print $1
        exit
      }
      name=$NF
      sub(/^\*\//, "", name)
      sub(/^\*/, "", name)
      sub(/^\.\//, "", name)
      if (name == asset) {
        print $1
        exit
      }
    }
  ' "$checksum_file")"
  rm -f "$checksum_file"
  if [[ -z "$expected" ]]; then
    printf '[local-ci] could not find checksum for %s in %s\n' "$asset_name" "$checksum_url" >&2
    exit 1
  fi
  if [[ "$expected" != "$pinned" ]]; then
    printf '[local-ci] %s: release checksum %s differs from the committed digest %s (toolchain-manifest.yaml gate_tools)\n' \
      "$asset_name" "$expected" "$pinned" >&2
    exit 1
  fi
  sha256_check "$pinned" "$output"
}

extract_binary_from_tar() {
  local archive="$1"
  local binary_name="$2"
  local output="$3"
  local tmp_dir found
  tmp_dir="$(gate_tool_temp -d)"
  tar -xzf "$archive" -C "$tmp_dir"
  found="$(find "$tmp_dir" -type f -name "$binary_name" -perm -111 | head -1)"
  if [[ -z "$found" ]]; then
    found="$(find "$tmp_dir" -type f -name "$binary_name" | head -1)"
  fi
  if [[ -z "$found" ]]; then
    printf '[local-ci] could not find %s in %s\n' "$binary_name" "$archive" >&2
    rm -rf "$tmp_dir"
    exit 1
  fi
  mv "$found" "$output"
  chmod +x "$output"
  rm -rf "$tmp_dir"
}

extract_binary_from_zip() {
  local archive="$1"
  local binary_name="$2"
  local output="$3"
  local tmp_dir found
  require_cmd unzip
  tmp_dir="$(gate_tool_temp -d)"
  unzip -q "$archive" -d "$tmp_dir"
  found="$(find "$tmp_dir" -type f -name "$binary_name" -perm -111 | head -1)"
  if [[ -z "$found" ]]; then
    found="$(find "$tmp_dir" -type f -name "$binary_name" | head -1)"
  fi
  if [[ -z "$found" ]]; then
    printf '[local-ci] could not find %s in %s\n' "$binary_name" "$archive" >&2
    rm -rf "$tmp_dir"
    exit 1
  fi
  mv "$found" "$output"
  chmod +x "$output"
  rm -rf "$tmp_dir"
}

ensure_container_structure_test() {
  if command -v container-structure-test >/dev/null 2>&1; then
    return 0
  fi

  ensure_dir "$LOCAL_BIN_DIR"
  local version="v1.22.1"
  local os arch asset tmp
  os="$(machine_os)"
  arch="$(machine_arch)"
  case "$os-$arch" in
    darwin-amd64) asset="container-structure-test-darwin-amd64" ;;
    darwin-arm64) asset="container-structure-test-darwin-arm64" ;;
    linux-amd64) asset="container-structure-test-linux-amd64" ;;
    linux-arm64) asset="container-structure-test-linux-arm64" ;;
    *) printf '[local-ci] unsupported container-structure-test platform: %s-%s\n' "$os" "$arch" >&2; exit 127 ;;
  esac
  tmp="$(gate_tool_temp)"
  download_asset_with_checksum \
    "$(pinned_tool_sha256 container-structure-test "$version" "$os-$arch")" \
    "https://github.com/GoogleContainerTools/container-structure-test/releases/download/${version}/${asset}" \
    "https://github.com/GoogleContainerTools/container-structure-test/releases/download/${version}/checksums.txt" \
    "$asset" \
    "$tmp"
  mv "$tmp" "$LOCAL_BIN_DIR/container-structure-test"
  chmod +x "$LOCAL_BIN_DIR/container-structure-test"
}

tool_has_version() {
  local actual
  actual="$("$1" --version 2>/dev/null)" || return 1
  [[ "$actual" == "$2" ]]
}

ensure_hadolint() {
  local bin="$LOCAL_BIN_DIR/hadolint" version="v2.14.0" expected
  expected="Haskell Dockerfile Linter ${version#v}"
  if [[ -x "$bin" ]] && tool_has_version "$bin" "$expected"; then
    hash -r
    return 0
  fi
  ensure_dir "$LOCAL_BIN_DIR"
  local os arch asset tmp
  os="$(machine_os)"
  arch="$(machine_arch)"
  case "$os-$arch" in
    linux-amd64) asset="hadolint-linux-x86_64" ;;
    linux-arm64) asset="hadolint-linux-arm64" ;;
    darwin-amd64) asset="hadolint-macos-x86_64" ;;
    darwin-arm64) asset="hadolint-macos-arm64" ;;
    *) printf '[local-ci] unsupported hadolint platform: %s-%s\n' "$os" "$arch" >&2; exit 127 ;;
  esac
  tmp="$(gate_tool_temp)"
  download_asset_with_checksum \
    "$(pinned_tool_sha256 hadolint "$version" "$os-$arch")" \
    "https://github.com/hadolint/hadolint/releases/download/${version}/${asset}" \
    "https://github.com/hadolint/hadolint/releases/download/${version}/${asset}.sha256" \
    "$asset" \
    "$tmp"
  mv "$tmp" "$bin"
  chmod +x "$bin"
  hash -r
  tool_has_version "$bin" "$expected" || {
    printf '[local-ci] installed hadolint must report %s\n' "$expected" >&2
    return 1
  }
}

ensure_ast_grep() {
  local bin="$LOCAL_BIN_DIR/ast-grep" version="0.42.1" expected
  expected="ast-grep $version"
  if [[ -x "$bin" ]] && tool_has_version "$bin" "$expected"; then
    hash -r
    return 0
  fi
  if command -v ast-grep >/dev/null 2>&1 && tool_has_version ast-grep "$expected"; then
    return 0
  fi

  ensure_dir "$LOCAL_BIN_DIR"
  local os arch asset sha tmp
  os="$(machine_os)"
  arch="$(machine_arch)"
  case "$os-$arch" in
    darwin-amd64)
      asset="app-x86_64-apple-darwin.zip"
      ;;
    darwin-arm64)
      asset="app-aarch64-apple-darwin.zip"
      ;;
    linux-amd64)
      asset="app-x86_64-unknown-linux-gnu.zip"
      ;;
    linux-arm64)
      asset="app-aarch64-unknown-linux-gnu.zip"
      ;;
    *) printf '[local-ci] unsupported ast-grep platform: %s-%s\n' "$os" "$arch" >&2; exit 127 ;;
  esac
  sha="$(pinned_tool_sha256 ast-grep "$version" "$os-$arch")"
  tmp="$(gate_tool_temp)"
  download_asset "https://github.com/ast-grep/ast-grep/releases/download/${version}/${asset}" "$tmp"
  sha256_check "$sha" "$tmp"
  extract_binary_from_zip "$tmp" ast-grep "$bin"
  rm -f "$tmp"
  hash -r
  tool_has_version "$bin" "$expected" || {
    printf '[local-ci] installed ast-grep must report %s\n' "$expected" >&2
    return 1
  }
}

prepare_checkov_runtime() {
  if command -v checkov >/dev/null 2>&1 && checkov --version >/dev/null 2>&1; then
    return 0
  fi

  local expat_lib="/opt/homebrew/opt/expat/lib"
  if command -v checkov >/dev/null 2>&1 &&
    [[ -d "$expat_lib" ]] &&
    DYLD_LIBRARY_PATH="$expat_lib${DYLD_LIBRARY_PATH:+:$DYLD_LIBRARY_PATH}" checkov --version >/dev/null 2>&1; then
    export DYLD_LIBRARY_PATH="$expat_lib${DYLD_LIBRARY_PATH:+:$DYLD_LIBRARY_PATH}"
    log "using Homebrew expat for local Checkov Python runtime"
    return 0
  fi

  # No unpinned pip bootstrap at gate time: the operator installs the pinned release.
  require_cmd checkov "install Checkov 3.3.0, for example: pipx install checkov==3.3.0"
  checkov --version
}

ensure_pmd() {
  local version="$PMD_VERSION"
  local pmd_home="$LOCAL_BIN_DIR/pmd-${version}"
  if [[ -x "$pmd_home/bin/pmd" ]]; then
    return 0
  fi
  require_cmd unzip
  ensure_dir "$LOCAL_BIN_DIR"
  local zip tmp_dir sha
  sha="$(pinned_tool_sha256 pmd "$version" any)"
  zip="$(gate_tool_temp)"
  tmp_dir="$(gate_tool_temp -d)"
  download_asset "https://github.com/pmd/pmd/releases/download/pmd_releases%2F${version}/pmd-dist-${version}-bin.zip" "$zip"
  sha256_check "$sha" "$zip"
  unzip -q "$zip" -d "$tmp_dir"
  rm -f "$zip"
  rm -rf "$pmd_home"
  mv "$tmp_dir/pmd-bin-${version}" "$pmd_home"
  rm -rf "$tmp_dir"
}

ensure_bearer() {
  local version="2.0.2"
  local bin="$LOCAL_BIN_DIR/bearer"
  if [[ -x "$bin" ]]; then
    return 0
  fi
  ensure_dir "$LOCAL_BIN_DIR"
  local os arch asset archive
  os="$(machine_os)"
  arch="$(machine_arch)"
  asset="bearer_${version}_${os}_${arch}.tar.gz"
  archive="$(gate_tool_temp)"
  download_asset_with_checksum \
    "$(pinned_tool_sha256 bearer "$version" "$os-$arch")" \
    "https://github.com/Bearer/bearer/releases/download/v${version}/${asset}" \
    "https://github.com/Bearer/bearer/releases/download/v${version}/checksums.txt" \
    "$asset" \
    "$archive"
  extract_binary_from_tar "$archive" bearer "$bin"
  rm -f "$archive"
}

ensure_osv_scanner() {
  local version="v2.3.8"
  local bin="$LOCAL_BIN_DIR/osv-scanner"
  if [[ -x "$bin" ]]; then
    return 0
  fi
  ensure_dir "$LOCAL_BIN_DIR"
  local os arch asset tmp
  os="$(machine_os)"
  arch="$(machine_arch)"
  asset="osv-scanner_${os}_${arch}"
  tmp="$(gate_tool_temp)"
  download_asset_with_checksum \
    "$(pinned_tool_sha256 osv-scanner "$version" "$os-$arch")" \
    "https://github.com/google/osv-scanner/releases/download/${version}/${asset}" \
    "https://github.com/google/osv-scanner/releases/download/${version}/osv-scanner_SHA256SUMS" \
    "$asset" \
    "$tmp"
  mv "$tmp" "$bin"
  chmod +x "$bin"
}

ensure_grype() {
  local version="0.115.0"
  local bin="$LOCAL_BIN_DIR/grype"
  if [[ -x "$bin" ]]; then
    return 0
  fi
  ensure_dir "$LOCAL_BIN_DIR"
  local os arch asset archive
  os="$(machine_os)"
  arch="$(machine_arch)"
  asset="grype_${version}_${os}_${arch}.tar.gz"
  archive="$(gate_tool_temp)"
  download_asset_with_checksum \
    "$(pinned_tool_sha256 grype "$version" "$os-$arch")" \
    "https://github.com/anchore/grype/releases/download/v${version}/${asset}" \
    "https://github.com/anchore/grype/releases/download/v${version}/grype_${version}_checksums.txt" \
    "$asset" \
    "$archive"
  extract_binary_from_tar "$archive" grype "$bin"
  rm -f "$archive"
}

ensure_syft() {
  local version="1.46.0"
  local bin="$LOCAL_BIN_DIR/syft"
  if [[ -x "$bin" ]]; then
    return 0
  fi
  ensure_dir "$LOCAL_BIN_DIR"
  local os arch asset archive
  os="$(machine_os)"
  arch="$(machine_arch)"
  asset="syft_${version}_${os}_${arch}.tar.gz"
  archive="$(gate_tool_temp)"
  download_asset_with_checksum \
    "$(pinned_tool_sha256 syft "$version" "$os-$arch")" \
    "https://github.com/anchore/syft/releases/download/v${version}/${asset}" \
    "https://github.com/anchore/syft/releases/download/v${version}/syft_${version}_checksums.txt" \
    "$asset" \
    "$archive"
  extract_binary_from_tar "$archive" syft "$bin"
  rm -f "$archive"
}

ensure_detekt() {
  if [[ -x "$LOCAL_BIN_DIR/detekt-cli-1.23.7-all.jar" ]]; then
    return 0
  fi
  require_cmd curl
  require_jdk21
  ensure_dir "$LOCAL_BIN_DIR"
  local version="1.23.7"
  local jar="$LOCAL_BIN_DIR/detekt-cli-${version}-all.jar"
  local sha256
  sha256="$(pinned_tool_sha256 detekt-cli "$version" any)"
  curl -fsSL --connect-timeout 20 --max-time 120 --retry-max-time 120 --retry 3 \
    "https://github.com/detekt/detekt/releases/download/v${version}/detekt-cli-${version}-all.jar" \
    -o "$jar"
  sha256_check "$sha256" "$jar"
  chmod +x "$jar"
}

job_preflight() {
  "$ROOT_DIR/scripts/chronicle-preflight.sh"
}

require_semgrep_pin() {
  local pinned active
  pinned="$(yq -r '.semgrep' "$ROOT_DIR/toolchain-manifest.yaml")"
  require_cmd semgrep "install Semgrep $pinned: uv tool install semgrep==$pinned"
  active="$(semgrep --version 2>/dev/null | head -1)"
  if [[ "$active" != "$pinned" ]]; then
    printf '[local-ci] semgrep %s is not the manifest pin %s\n' "${active:-unknown}" "$pinned" >&2
    return 1
  fi
}

job_engineering() {
  local project
  run_job detekt
  require_cmd ruff "install Ruff"
  require_cmd shellcheck "install ShellCheck"
  python3 -m unittest discover -s "$ROOT_DIR/tests/quality" -p 'test_*.py' || return
  python3 -m unittest discover -s "$ROOT_DIR/tests/security" -p 'test_*.py' || return
  python3 "$ROOT_DIR/scripts/check-python-shell.py" || return
  python3 "$ROOT_DIR/scripts/check-machine-paths.py" || return
  require_semgrep_pin || return
  python3 "$ROOT_DIR/scripts/generate-engineering-rules.py" --check || return
  for project in "$ROOT_DIR" "$ROOT_DIR/chronicle" "$ROOT_DIR/chronicle-server" "$ROOT_DIR/chronicle-web"; do
    (cd "$project" && ast-grep scan --config sgconfig.yml \
      --globs '!**/lint/**' --globs '!tests/security/fixtures/**' --globs '!docker/**' --globs '!k8s/**' \
      --globs '!tests/security/semgrep-tests/**' --globs '!chronicle-ios/**' . &&
      ast-grep test --config sgconfig.yml --skip-snapshot-tests) || return
  done
  semgrep --test --config "$ROOT_DIR/tests/security/semgrep" "$ROOT_DIR/tests/security/semgrep-tests" || return
  semgrep --error --metrics off --disable-version-check --no-git-ignore --timeout 0 \
    --config "$ROOT_DIR/tests/security/semgrep" \
    --include '*.kt' --include '*.java' --include '*.py' --include '*.ts' --include '*.tsx' \
    --include '*.sh' --include '*.sql' --include '*.yml' \
    --exclude '**/build/**' --exclude '**/node_modules/**' --exclude '**/.gradle/**' \
    --exclude '**/.git/**' --exclude 'chronicle-ios/**' --exclude '.claude/**' --exclude 'docker/**' --exclude 'k8s/**' \
    --exclude '**/lint/**' --exclude 'tests/security/fixtures/**' \
    --exclude 'tests/security/semgrep-tests/**' --exclude 'chronicle-web/vendor/**' "$ROOT_DIR"
}

job_architecture() {
  require_cmd python3 "install Python 3"
  require_cmd flock "install util-linux flock (macOS: brew install flock); the operation-writer tests run it"
  python3 "$ROOT_DIR/scripts/check-architecture-boundaries.py" --self-test
  python3 "$ROOT_DIR/scripts/check-architecture-boundaries.py"
  python3 "$ROOT_DIR/scripts/check-selfhost-capabilities.py"
  python3 "$ROOT_DIR/tests/security/check-setting-readers.py"
  selfhost_python "$ROOT_DIR/tests/security/selfhost-monitoring.py"
  require_cmd uvx "install uv"
  # --check-untyped-defs: without it mypy skipped every unannotated body and reported 0 errors (AF-P12).
  uvx --with types-PyYAML==6.0.12.20250915 --from mypy==1.18.2 mypy --check-untyped-defs "$ROOT_DIR/selfhost/chronicle_ops"
}

job_migration_safety() {
  "$ROOT_DIR/scripts/check-migrations-safe.sh" --server-dir "$ROOT_DIR/chronicle-server"
  "$ROOT_DIR/tests/security/migration-safety.sh"
}

job_diff_coverage() {
  require_cmd git
  require_cmd python3
  require_cmd diff-cover "install diff-cover 10.6.0"
  local args=()
  if [[ -n "${CHRONICLE_DIFF_BASE:-}" ]]; then
    args=(--base "$CHRONICLE_DIFF_BASE")
  fi
  bash "$ROOT_DIR/tests/quality/diff-coverage-selftest.sh" || return
  # The fast group's own producers: jvm-smoke writes server JaCoCo, web writes chronicle-web lcov.
  (cd "$ROOT_DIR" && scripts/diff-coverage.py "${args[@]}" --require chronicle-server=jacoco --require chronicle-web=lcov --require chronicle=jacoco --require .=cobertura)
}

job_duplication() {
  require_cmd python3
  require_cmd pmd "put PMD $PMD_VERSION on PATH"
  local args=()
  if [[ "${CHRONICLE_DUPLICATION_UPDATE_BASELINE:-0}" == "1" ]]; then
    args=(--update-baseline)
  fi
  python3 "$ROOT_DIR/tests/quality/test_check_duplication.py"
  python3 "$ROOT_DIR/scripts/check-duplication.py" "${args[@]}"
}

job_migration_lint() {
  require_cmd git
  require_cmd python3
  require_cmd squawk "install squawk 2.67.0 and put it on PATH"
  local server_dir="$ROOT_DIR/chronicle-server" base file status=0 count=0
  base="${CHRONICLE_MIGRATION_BASE:-}"
  if [[ -n "$base" ]]; then
    base="$(git -C "$server_dir" rev-parse --verify "$base^{commit}")" || return 2
  else
    base="$(cd "$ROOT_DIR" && scripts/diff-coverage.py ${CHRONICLE_DIFF_BASE:+--base "$CHRONICLE_DIFF_BASE"} --print-base chronicle-server)" || return 2
  fi
  # Include untracked additions, but never modified or renamed published migrations.
  local added
  added="$(git -C "$server_dir" diff --name-only --diff-filter=A "$base" -- src/main/resources/db/migration)" || return 2
  added+=$'\n'"$(git -C "$server_dir" ls-files --others --exclude-standard -- src/main/resources/db/migration)" || return 2
  while IFS= read -r file; do
    [[ "$file" == src/main/resources/db/migration/*.sql && -f "$server_dir/$file" ]] || continue
    # An untracked replacement of a base migration is still an existing migration.
    if git -C "$server_dir" cat-file -e "$base:$file" 2>/dev/null; then continue; fi
    count=$((count + 1))
    squawk --config "$ROOT_DIR/.squawk.toml" "$server_dir/$file" || status=1
  done <<< "$added"
  log "migration-lint: checked $count new migration(s) against $base"
  return "$status"
}

job_selfhost_python() {
  require_cmd python3 "install Python 3"
  require_cmd uvx "install uv"
  local coverage_dir="$ROOT_DIR/build/coverage"
  mkdir -p "$coverage_dir"
  PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="${SELFHOST_PYTHON_PACKAGE:-$ROOT_DIR/selfhost}:$ROOT_DIR/tests/selfhost-py" \
    uvx --python "$(command -v python3)" --with-requirements "$ROOT_DIR/requirements-dev.txt" --from coverage==7.6.1 \
      coverage run --data-file="$coverage_dir/selfhost.coverage" --source="$ROOT_DIR/selfhost" \
      "$ROOT_DIR/tests/selfhost-py/run_suite.py" discover -s "$ROOT_DIR/tests/selfhost-py" -v || return $?
  uvx --python "$(command -v python3)" --from coverage==7.6.1 \
    coverage xml --data-file="$coverage_dir/selfhost.coverage" -o "$coverage_dir/coverage.xml"
}

job_selfhost() {
  require_cmd docker "install Docker with Compose v2"
  require_cmd python3 "install Python 3"
  require_cmd flock "install util-linux flock (macOS: brew install flock); the operation-writer tests run it"
  selfhost_python "$ROOT_DIR/tests/security/selfhost-monitoring.py" || return $?
  # Shipped alert rules through real Grafana (built from Dockerfile.grafana) to a webhook recorder.
  selfhost_python "$ROOT_DIR/tests/security/selfhost-monitoring.py" --alert-delivery || return $?
  run_job selfhost-python || return $?
  selfhost_python -m unittest discover -s "$ROOT_DIR/tests/deployment" -p test_selfhost_client.py -v || return $?
  "$ROOT_DIR/tests/security/selfhost-release-bundle.sh"
}

job_selfhost_restore() {
  local suite status=0
  for suite in selfhost-restore-failclosed selfhost-restore-orchestration; do
    "$ROOT_DIR/tests/security/$suite.sh" || status=1
  done
  run_selfhost_python_suite test_restore test_restore_deployment test_restore_schemas || status=1
  return "$status"
}

job_contract_drift() {
  selfhost_python "$ROOT_DIR/tests/security/contract-drift-diff.py" || return $?
  selfhost_python "$ROOT_DIR/tests/security/test_contract_drift.py" || return $?
  selfhost_python "$ROOT_DIR/tests/security/test_contract_generator.py" || return $?
  (cd "$ROOT_DIR" && bun test ./tests/security/endpoint-consumers.test.ts ./tests/security/diagnostic-openapi.test.ts ./tests/security/string-length-contract.test.ts) || return $?
  run_selfhost_python_suite test_ops_batch.OpsBatchTests.test_diagnostic_drift_in_each_consumer_fails
}

job_web() {
  require_cmd bun "install Bun 1.3.x"
  ensure_ast_grep
  # CHRONICLE_WEB_AUDIT=0: the dependency gate runs this job with no network after a separate
  # install, and runs bun-audit in its security step.
  [[ "${CHRONICLE_WEB_AUDIT:-1}" == 0 ]] || run_job bun-audit
  log "web check"
  (cd "$WEB_DIR" && bun run check)
  log "web modern tests"
  (cd "$WEB_DIR" && bun test --coverage --coverage-reporter=text --coverage-reporter=lcov src/modern scripts)
  log "k6 probe self-tests"
  (cd "$ROOT_DIR" && bun test tests/security/k6-race-conditions.test.ts)
  log "OpenAPI type generation check"
  (cd "$WEB_DIR" && bun run check:api-types)
  log "contract drift detection"
  (cd "$WEB_DIR" && bun test src/modern/state/contract-drift.test.ts)
  log "web build"
  (cd "$WEB_DIR" && bun run build)
}

job_web_e2e() {
  log "all browser specs against the isolated test backend"
  run_with_timeout_logged "$WEB_E2E_TIMEOUT_SECONDS" "$(report_path "$ROOT_DIR/build/web-e2e.log" "web-e2e.log")" \
    bash "$ROOT_DIR/scripts/run-web-e2e.sh"
}

job_api_probes() {
  require_cmd schemathesis "install schemathesis 4.x"
  bash "$ROOT_DIR/tests/security/backend-api-probes.sh"
}

job_selfhost_browser() {
  : "${CHRONICLE_PROXY_BASE_URL:?Set the deployed management listener}"
  : "${CHRONICLE_E2E_PUBLIC_BASE_URL:?Set the deployed public listener}"
  : "${CHRONICLE_E2E_DASHBOARD_PASSWORD:?Set the deployed dashboard password}"
  (cd "$WEB_DIR" && CHRONICLE_E2E_SELFHOST=1 bunx playwright test e2e/selfhost-journey.spec.ts --project=desktop-chromium)
}

job_web_a11y() {
  require_cmd bun "install Bun 1.3.x"
  local args=()
  # The theme-menu and mobile-nav scans need the signed-in shell, so a backend harness
  # (CHRONICLE_BACKEND_URL, see chronicle-web/README.md). Without one, scan every route that
  # renders unauthenticated: landing, login, 404, participant forms and the session panels.
  if [[ -z "${CHRONICLE_BACKEND_URL:-}" ]]; then
    log "CHRONICLE_BACKEND_URL unset: skipping the signed-in shell scans"
    args=(--grep-invert "dark mode|mobile nav overlay")
  fi
  log "web accessibility (axe WCAG 2 A/AA)"
  (
    cd "$WEB_DIR"
    if [[ -z "${CHRONICLE_PROXY_BASE_URL:-}" ]]; then
      require_cmd python3 "install Python 3"
      local proxy_port
      proxy_port="$(free_ports 1)" || exit $?
      export CHRONICLE_PROXY_BASE_URL="http://127.0.0.1:$proxy_port"
      log "CHRONICLE_PROXY_BASE_URL unset: using $CHRONICLE_PROXY_BASE_URL"
    fi
    bunx playwright test e2e/pa11y.spec.ts e2e/accessibility.spec.ts --project=desktop-chromium "${args[@]}"
  )
}

job_jvm_smoke() {
  require_jdk21
  log "Gradle project listing"
  gradle projects
  log "OpenAPI spec validation"
  gradle :chronicle-api:validateOpenApiSpec --build-cache
  log "chronicle-api tests"
  gradle :chronicle-api:test --build-cache
  log "shared models and rhizome tests"
  gradle :chronicle-models:test :rhizome:test :rhizome-client:test --build-cache
  log "rhizome documentation archive"
  gradle :rhizome:javadocJar --build-cache
  log "chronicle-server tests"
  gradle :chronicle-server:test --build-cache
  log "JaCoCo report"
  gradle :chronicle-server:jacocoTestReport --build-cache
  log "server Checkstyle and SpotBugs, rhizome SpotBugs"
  gradle :chronicle-server:check :rhizome:spotbugsMain --build-cache
  job_pit
}

job_repo_automation() {
  run_job architecture
  log "toolchain manifest verification"
  bash "$ROOT_DIR/scripts/verify-toolchain.sh"
  python3 "$ROOT_DIR/tests/security/semgrep-version-pin.py"
  python3 "$ROOT_DIR/tests/security/local-ci-docker-host.py"
  log "trusted dependency script guard"
  bash "$ROOT_DIR/scripts/check-no-trusted-deps.sh"
  log "silent failure hunter"
  bash "$ROOT_DIR/scripts/silent-failure-hunter.sh"
  log "Kotlin daemon state ignored and refused in every Kotlin repository"
  python3 "$ROOT_DIR/tests/quality/test_kotlin_daemon_state_untracked.py"
  log "JDK discovery and the web dependency age rule (gate tool digests run in verify-toolchain.sh)"
  python3 "$ROOT_DIR/tests/quality/test_jdk_discovery.py"
  python3 "$ROOT_DIR/tests/quality/test_web_dependency_age.py"
  log "dependency age gate and dependency intake scripts"
  python3 "$ROOT_DIR/tests/quality/test_check_dependency_age.py"
}

job_dead_code() {
  require_cmd bun "install Bun 1.3.x"
  (cd "$WEB_DIR" && bun run dead-code)
}

job_security_layers() {
  # SCA is owned by web/bun-audit, license by license-compliance; live fixtures have dedicated jobs.
  local layer failed=()
  for layer in sast secrets iac deploy auth injection crypto collection compliance; do
    bash "$ROOT_DIR/tests/security/run-all-security.sh" "$layer" \
      "${LOCAL_REPORT_DIR:-$ROOT_DIR/tests/security/reports}/$layer" || failed+=("$layer")
  done
  [[ ${#failed[@]} -eq 0 ]] || { log "security layers failed: ${failed[*]}"; return 1; }
}

job_dependency_sbom() {
  require_jdk21
  gradle :chronicle-server:cyclonedxBom
}

# Inventory selfhost, including nested overlays and init scripts; docker/ and k8s/ are frozen.
deployment_files() {
  {
    rg --files --hidden "$ROOT_DIR/selfhost" \
      -g 'Dockerfile*' -g '*.sh' -g chronicle -g 'docker-compose*.yml' -g 'docker-compose*.yaml' \
      -g '**/selfhost/overlays/*.yml' -g '**/selfhost/overlays/*.yaml'
  } | sort
}

job_dockerfile_lint() {
  ensure_hadolint
  local target
  while IFS= read -r target; do
    [[ "${target##*/}" == Dockerfile* ]] || continue
    hadolint "$target" || return $?
  done < <(deployment_files)
}

job_iac_scan() {
  prepare_checkov_runtime
  require_cmd shellcheck
  require_cmd conftest
  # Scan every target and report all failures together, so one red file cannot hide the rest.
  local target
  local -a failed=()
  conftest verify --policy "$ROOT_DIR/tests/security/policies" || failed+=("conftest verify")
  while IFS= read -r target; do
    case "${target##*/}" in
      Dockerfile*)
        checkov -f "$target" --framework dockerfile --quiet --skip-download || failed+=("$target") ;;
      *.sh|chronicle)
        shellcheck -S warning "$target" || failed+=("$target") ;;
      *.yml|*.yaml)
        conftest test "$target" --policy "$ROOT_DIR/tests/security/policies" || failed+=("$target") ;;
    esac
  done < <(deployment_files)
  ((${#failed[@]} == 0)) && return 0
  printf 'iac-scan: %d target(s) failed:\n' "${#failed[@]}" >&2
  printf '  %s\n' "${failed[@]}" >&2
  return 1
}

job_license_compliance() {
  require_jdk21
  gradle :chronicle-server:checkLicense
  bash "$ROOT_DIR/tests/security/run-all-security.sh" license \
    "${LOCAL_REPORT_DIR:-$ROOT_DIR/tests/security/reports}/license"
  run_job bun-audit
  # The allowlist that checkLicense reads must not admit a GPL-incompatible single license.
  python3 "$ROOT_DIR/tests/selfhost-py/test_license_allowlist.py"
  python3 "$ROOT_DIR/tests/quality/test_frontend_license_policy.py"
  ensure_syft
  bash "$ROOT_DIR/scripts/check-frontend-licenses.sh"
}

build_selfhost_serving_image() {
  docker build -f "$ROOT_DIR/selfhost/Dockerfile.frontend" -t chronicle-selfhost-frontend:test "$ROOT_DIR" || return $?
  docker build -f "$ROOT_DIR/selfhost/Dockerfile.caddy" --build-context chronicle-selfhost-frontend:release=docker-image://chronicle-selfhost-frontend:test \
    -t "$SELFHOST_CADDY_TEST_IMAGE" "$ROOT_DIR"
}

job_upload_body_limit_edge() (
  require_cmd docker
  require_jdk21
  local work
  mkdir -p "$ROOT_DIR/chronicle-server/build" || return $?
  work="$(mktemp -d "${TMPDIR:-$ROOT_DIR/chronicle-server/build}/upload-edge.XXXXXX")" || return $?
  trap 'rm -r -- "$work"' EXIT
  export CHRONICLE_ANDROID_BATCH_DIR="$work/android-bodies"
  export CHRONICLE_CADDY_SNIPPETS="$ROOT_DIR/selfhost/caddy/snippets.caddy"
  export SELFHOST_CADDY_TEST_IMAGE="chronicle-selfhost-caddy:test"
  build_selfhost_serving_image || return $?
  (cd "$ROOT_DIR/chronicle" && ./gradlew --no-daemon :app:testOpenDebugUnitTest --rerun \
    --tests '*CollectedRequestBatcherTest.maximumBodiesUseTheRealRetrofitBytesAndExportForCaddy') || return $?
  gradle :chronicle-server:uploadBodyLimitEdgeTest
)

# The bytes the real Android client sends, captured by its unit tests, replayed into the server, its export and the web
# survey page; the web invitation is produced first for the Android handoff consumer (EnrollmentHandoffUriTest).
job_android_replay() (
  require_cmd docker
  require_cmd bun "install Bun 1.3.x"
  require_jdk21
  local work
  mkdir -p "$ROOT_DIR/chronicle-server/build" || return $?
  work="$(mktemp -d "$ROOT_DIR/chronicle-server/build/android-replay.XXXXXX")" || return $?
  trap 'rm -r -- "$work"' EXIT
  export TZ=America/Santiago
  export CHRONICLE_ENROLLMENT_HANDOFF_FIXTURE="$work/enrollment-handoff.json"
  export CHRONICLE_ANDROID_ENROLL_DIR="$work/enroll" CHRONICLE_ANDROID_PILOT_UPLOAD_DIR="$work/pilot-upload"
  export CHRONICLE_ANDROID_IDENTITY_DIR="$work/identity" CHRONICLE_ANDROID_SURVEY_DIR="$work/survey"
  (cd "$WEB_DIR" && bun test src/modern/routes/public-enrollment-page.test.tsx) || return $?
  (cd "$ROOT_DIR/chronicle" && ./gradlew --no-daemon :app:testOpenDebugUnitTest --rerun \
    --tests '*EnrollmentWireContractTest' --tests '*PilotUploadFixtureTest' --tests '*IdentityLabelUploadJourneyTest' \
    --tests '*SurveyReminderTapJourneyTest' --tests '*EnrollmentHandoffUriTest') || return $?
  gradle :chronicle-server:androidReplayTest || return $?
  (cd "$WEB_DIR" && bun test src/modern/app/android-survey-replay.test.tsx)
)

job_route_surface_edge() {
  require_cmd docker
  export SELFHOST_CADDY_TEST_IMAGE="chronicle-selfhost-caddy:test"
  build_selfhost_serving_image || return $?
  selfhost_python -m unittest discover -s "$ROOT_DIR/tests/deployment" -p test_route_surface.py -v
}

job_container_structure() {
  require_cmd docker
  require_cmd python3
  ensure_container_structure_test
  docker build -f "$ROOT_DIR/docker/Dockerfile.backend" -t chronicle-backend:test "$ROOT_DIR"
  container-structure-test test --image chronicle-backend:test --config "$ROOT_DIR/tests/container/backend.yaml"
  for component in frontend caddy backup; do
    local context="$ROOT_DIR" serving=()
    [[ "$component" != backup ]] || context="$ROOT_DIR/selfhost"
    [[ "$component" != caddy ]] || serving=(--build-context chronicle-selfhost-frontend:release=docker-image://chronicle-selfhost-frontend:test)
    docker build -f "$ROOT_DIR/selfhost/Dockerfile.$component" "${serving[@]}" -t "chronicle-selfhost-$component:test" "$context"
    if [[ "$component" == caddy ]]; then
      SELFHOST_CADDY_TEST_IMAGE="chronicle-selfhost-$component:test" \
        CADDY_BODY_TEST_LOG_DIR="$(report_path "$ROOT_DIR/tests/security/reports/caddy-body-limit" caddy-body-limit)" \
        python3 -s "$ROOT_DIR/tests/deployment/test_caddy_body_limit.py"
    fi
    container-structure-test test --image "chronicle-selfhost-$component:test" --config "$ROOT_DIR/tests/container/selfhost-$component.yaml"
  done
}

# Release images exactly as publish-images.sh builds them: linux/amd64, from the committed HEAD through
# chronicle_ops.images (same context, Dockerfile and gitlinks), then container-structure-test, the
# SSH-server, listener and image-policy checks and the release trivy scan (vulnerabilities and
# secrets). CHRONICLE_IMAGE_GATE_COMPONENTS picks the images (default: all); caddy brings frontend,
# whose output it serves. CHRONICLE_IMAGE_GATE_RUNTIME=1 also scans and checks the third-party runtime
# images of the release inventory and, when every component was built, fails on a .trivyignore.yaml
# entry that suppressed nothing in any image. CHRONICLE_IMAGE_GATE_SOURCE builds
# another repository (the dependency gate runner's candidate) with this checkout's image inventory,
# structure tests, SSH check and scanner: nothing from that repository runs on the host, only its
# committed tree goes to the builds (which run inside BuildKit).
job_image_gate() {
  require_cmd docker
  require_cmd python3
  require_cmd trivy
  ensure_container_structure_test
  local requested=" ${CHRONICLE_IMAGE_GATE_COMPONENTS:-backend frontend caddy backup grafana fluentbit postgres} "
  [[ "$requested" != *" caddy "* || "$requested" == *" frontend "* ]] || requested+="frontend "
  trivy image --quiet --download-db-only
  trivy image --quiet --download-java-db-only
  local revision component context dockerfile tag config image_failed=0 extra source="${CHRONICLE_IMAGE_GATE_SOURCE:-$ROOT_DIR}"
  local reports built=" "
  revision="$(git -C "$source" rev-parse HEAD)"
  # A fresh directory per run: a report left by an earlier run would hide a stale ignore entry.
  mkdir -p "$ROOT_DIR/build"
  reports="$(mktemp -d "$ROOT_DIR/build/image-gate-trivy-${revision:0:16}.XXXXXX")"
  # Component order of chronicle_ops.images.SOURCE_IMAGES puts frontend before caddy.
  while read -r component context dockerfile; do
    [[ "$requested" == *" $component "* ]] || continue
    tag="chronicle-image-gate-$component:${revision:0:16}"
    extra=()
    [[ "$component" != caddy ]] || extra=(--build-context "chronicle-selfhost-frontend:release=docker-image://chronicle-image-gate-frontend:${revision:0:16}")
    log "image-gate: build $component"
    if ! selfhost_python -c 'from chronicle_ops.images import SOURCE_IMAGES; import sys
next(image for image in SOURCE_IMAGES if image.component == sys.argv[3]).archive(sys.argv[1], sys.argv[2], sys.stdout.buffer)' \
        "$source" "$revision" "$component" |
      docker build --platform linux/amd64 -f "$dockerfile" ${extra[@]+"${extra[@]}"} -t "$tag" -; then
      printf '[local-ci] image-gate: %s build failed\n' "$component" >&2
      image_failed=1
      continue
    fi
    config="$ROOT_DIR/tests/container/selfhost-$component.yaml"
    [[ "$component" != backend ]] || config="$ROOT_DIR/tests/container/backend.yaml"
    if [[ -f "$config" ]]; then
      container-structure-test test --platform linux/amd64 --image "$tag" --config "$config" || image_failed=1
    fi
    bash "$ROOT_DIR/scripts/check-image-no-ssh-server.sh" "$tag" || image_failed=1
    bash "$ROOT_DIR/scripts/check-image-listeners.sh" "$tag" || image_failed=1
    python3 "$ROOT_DIR/scripts/check-image-policy.py" "$component=$tag" || image_failed=1
    CHRONICLE_TRIVY_REPORT_DIR="$reports" bash "$ROOT_DIR/scripts/scan-selfhost-release-images.sh" "$tag" || image_failed=1
    built+="$component "
  done < <(selfhost_python - <<'PY_IMAGE_GATE'
import os
from chronicle_ops.images import SOURCE_IMAGES
for image in SOURCE_IMAGES:
    context = os.path.normpath('selfhost/' + image.context)
    print(image.component, context, os.path.relpath('selfhost/' + image.dockerfile, context))
PY_IMAGE_GATE
  )
  if [[ "${CHRONICLE_IMAGE_GATE_RUNTIME:-0}" == 1 ]]; then
    CHRONICLE_TRIVY_REPORT_DIR="$reports" bash "$ROOT_DIR/scripts/scan-selfhost-release-images.sh" --inventory "$source/selfhost" || image_failed=1
    selfhost_python "$ROOT_DIR/scripts/check-runtime-images.py" --inventory "$source/selfhost" || image_failed=1
    # Stale entries can be judged only against every shipped image.
    if [[ "$built" == *" backend "* && "$built" == *" frontend "* && "$built" == *" caddy "* && "$built" == *" backup "* &&
          "$built" == *" grafana "* && "$built" == *" fluentbit "* && "$built" == *" postgres "* ]]; then
      python3 "$ROOT_DIR/tests/security/check-trivy-waivers.py" "$ROOT_DIR/.trivyignore.yaml" --reports "$reports" || image_failed=1
    fi
  fi
  return "$image_failed"
}

write_ci_smoke_files() {
  local env_file="$1"
  local override_file="$2"
  local secrets_dir="$3"
  local certs_dir="$4"
  local backend_port="$5"
  local frontend_port="$6"
  write_ci_smoke_tls "$secrets_dir" "$certs_dir"
  write_ci_smoke_environment "$env_file"
  write_ci_smoke_override "$override_file" "$secrets_dir" "$certs_dir" "$backend_port" "$frontend_port"
}

write_ci_smoke_tls() {
  local secrets_dir="$1" certs_dir="$2"
  mkdir -p "$secrets_dir"
  printf '%s' 'chronicle_ci_test' > "$secrets_dir/postgres_password"
  printf '%s' 'ci-smoke-test-jwt-secret-not-for-production' > "$secrets_dir/jwt_secret"
  printf '%s' 'ci-hz-server' > "$secrets_dir/hazelcast_server_password"
  printf '%s' 'ci-hz-client' > "$secrets_dir/hazelcast_client_password"
  printf '%s' 'ci-mobile-signing-secret-not-for-production-32-bytes' > "$secrets_dir/mobile_signing_secret"
  printf '%s' 'ci-metrics-password-not-for-production-32-bytes' > "$secrets_dir/chronicle_security_metrics_password"
  mkdir -p "$certs_dir/ca" "$certs_dir/server"
  openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
    -subj "/CN=Chronicle local smoke CA" \
    -addext 'basicConstraints=critical,CA:TRUE' -addext 'keyUsage=critical,keyCertSign,cRLSign' \
    -addext 'subjectKeyIdentifier=hash' \
    -keyout "$certs_dir/ca/ca.key" \
    -out "$certs_dir/ca/ca.crt" >/dev/null 2>&1
  cat > "$certs_dir/server/server.cnf" <<'EOF'
[req]
distinguished_name=req_distinguished_name
req_extensions=v3_req
prompt=no

[req_distinguished_name]
CN=postgres

[v3_req]
subjectAltName=@alt_names

[v3_server]
subjectAltName=@alt_names
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer

[alt_names]
DNS.1=postgres
DNS.2=localhost
IP.1=127.0.0.1
EOF
  openssl req -new -newkey rsa:2048 -nodes \
    -config "$certs_dir/server/server.cnf" \
    -keyout "$certs_dir/server/server.key" \
    -out "$certs_dir/server/server.csr" >/dev/null 2>&1
  openssl x509 -req -days 1 \
    -in "$certs_dir/server/server.csr" \
    -CA "$certs_dir/ca/ca.crt" \
    -CAkey "$certs_dir/ca/ca.key" \
    -CAcreateserial \
    -extensions v3_server \
    -extfile "$certs_dir/server/server.cnf" \
    -out "$certs_dir/server/server.crt" >/dev/null 2>&1
  # The CI smoke key is generated in a temporary directory and bind-mounted
  # read-only. It must be readable by the container user so Postgres can copy it
  # into its runtime directory and then chmod the runtime copy to 0600.
  chmod 644 "$certs_dir/server/server.key"
}

write_ci_smoke_environment() {
  local env_file="$1"
  cat > "$env_file" <<EOF
DOMAIN=localhost
CHRONICLE_PUBLIC_BASE_URL=https://localhost
TRAEFIK_NETWORK=traefik
TRAEFIK_ENTRYPOINT=web
POSTGRES_USER=chronicle
POSTGRES_PASSWORD=chronicle_ci_test
POSTGRES_DB=chronicle
# The smoke compose stack defaults tables to tde_heap, so its ephemeral database
# must initialize pg_tde and the already-mounted temporary file keyring.
PG_TDE_KEY_PROVIDER=file
JWT_SECRET=ci-smoke-test-jwt-secret-not-for-production
CHRONICLE_INTERNAL_WEB_SECRET=ci-smoke-test-internal-web-secret-not-for-production-32-bytes
HAZELCAST_SERVER_PASSWORD=ci-hz-server
HAZELCAST_CLIENT_PASSWORD=ci-hz-client
MOBILE_SIGNING_SECRET=ci-mobile-signing-secret-not-for-production-32-bytes
CROWDSEC_BOUNCER_API_KEY=ci-crowdsec-key
GRAFANA_ADMIN_PASSWORD=ci-grafana-admin-not-for-production
CHRONICLE_SECURITY_COOKIE_SECURE=true
CHRONICLE_SECURITY_REQUIRE_MFA=true
# Synthetic CI assurance fixture; production deploy.sh requires separate live IdP evidence.
CHRONICLE_SECURITY_MFA_IDP_PROOF_VERIFIED=true
SMTP_ENABLED=false
VAULT_ENABLED=false
GIT_SHA=${GITHUB_SHA:-local}
EOF
}

write_ci_smoke_override() {
  local override_file="$1" secrets_dir="$2" certs_dir="$3" backend_port="$4" frontend_port="$5"
  cat > "$override_file" <<EOF
services:
  postgres:
    environment:
      PGDATA: /data/db/pgdata
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U chronicle -d chronicle"]
      interval: 5s
      timeout: 5s
      retries: 30
      start_period: 60s
    volumes:
      - postgres_data:/data/db
      - postgres_tde_keyring:/var/lib/postgresql/tde-keyring
      - ./init-db-roles.sql:/docker-entrypoint-initdb.d/10-init-db-roles.sql:ro
      - ./init-db-encryption.sh:/docker-entrypoint-initdb.d/20-init-db-encryption.sh:ro
      - ./init-replication.sh:/docker-entrypoint-initdb.d/25-init-replication.sh:ro
      - ./init-audit-immutability.sh:/docker-entrypoint-initdb.d/30-init-audit-immutability.sh:ro
      - "$certs_dir/server/server.crt:/etc/postgres-ssl-src/server.crt:ro"
      - "$certs_dir/server/server.key:/etc/postgres-ssl-src/server.key:ro"
      - "$certs_dir/ca/ca.crt:/etc/postgres-ssl-src/ca.crt:ro"
      - ./postgres-ssl/pg_hba-ssl.conf:/data/db/pg_hba.conf:ro
  chronicle-backend:
    ports:
      - "${backend_port}:40320"
    networks:
      - chronicle-internal
      - chronicle-sso-broker
      - chronicle-backend-bridge
      - ci-smoke
    volumes:
      - audit_logs:/var/log/chronicle
      - "$certs_dir/ca/ca.crt:/app/ssl/ca.crt:ro"
      - ./rhizome-docker.yaml.template:/server/config/rhizome.yaml.template:ro
      - ./chronicle-auth.yaml.template:/server/config/chronicle-auth.yaml.template:ro
      - ./mail.yaml.template:/server/config/mail.yaml.template:ro
      - ./mobile-security.yaml.template:/server/config/mobile-security.yaml.template:ro
      - ./vault.yaml.template:/server/config/vault.yaml.template:ro
      - ./cors.yaml.template:/server/config/cors.yaml.template:ro
  chronicle-frontend:
    ports:
      - "${frontend_port}:8080"
    networks:
      - chronicle-internal
      - ci-smoke
networks:
  ci-smoke:
    driver: bridge
secrets:
  postgres_password:
    file: "$secrets_dir/postgres_password"
  jwt_secret:
    file: "$secrets_dir/jwt_secret"
  hazelcast_server_password:
    file: "$secrets_dir/hazelcast_server_password"
  hazelcast_client_password:
    file: "$secrets_dir/hazelcast_client_password"
  mobile_signing_secret:
    file: "$secrets_dir/mobile_signing_secret"
  chronicle_security_metrics_password:
    file: "$secrets_dir/chronicle_security_metrics_password"
EOF
}

job_http_smoke_stack() {
  require_cmd docker
  require_cmd curl
  require_cmd openssl
  local tmp_dir env_file override_file secrets_dir certs_dir compose_args
  local repo_env_file repo_env_created metrics_password metrics_status
  local backend_port frontend_port backend_url frontend_url free_backend free_frontend
  read -r free_backend free_frontend <<<"$(free_ports 2)"
  backend_port="${CHRONICLE_CI_BACKEND_PORT:-$free_backend}"
  frontend_port="${CHRONICLE_CI_FRONTEND_PORT:-$free_frontend}"
  if [[ ! "$backend_port" =~ ^[0-9]+$ ]] || (( 10#$backend_port < 1 || 10#$backend_port > 65535 )); then
    log "invalid CHRONICLE_CI_BACKEND_PORT: $backend_port"
    return 2
  fi
  if [[ ! "$frontend_port" =~ ^[0-9]+$ ]] || (( 10#$frontend_port < 1 || 10#$frontend_port > 65535 )); then
    log "invalid CHRONICLE_CI_FRONTEND_PORT: $frontend_port"
    return 2
  fi
  if [[ "$backend_port" == "$frontend_port" ]]; then
    log "CHRONICLE_CI_BACKEND_PORT and CHRONICLE_CI_FRONTEND_PORT must differ"
    return 2
  fi
  tmp_dir="$(gate_tool_temp -d)"
  env_file="$tmp_dir/ci-smoke.env"
  override_file="$tmp_dir/docker-compose.ci-smoke.yml"
  secrets_dir="$tmp_dir/secrets"
  certs_dir="$tmp_dir/postgres-ssl"
  backend_url="http://localhost:${backend_port}"
  frontend_url="http://localhost:${frontend_port}"
  write_ci_smoke_files "$env_file" "$override_file" "$secrets_dir" "$certs_dir" "$backend_port" "$frontend_port"
  repo_env_file="$ROOT_DIR/docker/.env"
  repo_env_created=0
  if [[ ! -e "$repo_env_file" ]]; then
    cp "$env_file" "$repo_env_file"
    repo_env_created=1
  fi
  # docker-compose.traefik.yml declares `name: chronicle` plus fixed container, network and
  # volume names, so on a host that runs that stack the teardown below would adopt it and
  # `down -v` would delete its database. Own project, and refuse to share a host
  # with anything that file names.
  compose_args=(-p chronicle-ci-smoke --env-file "$env_file" -f "$ROOT_DIR/docker/docker-compose.traefik.yml" -f "$override_file")
  local clash
  clash=$(docker compose "${compose_args[@]}" config --format json |
    jq -r '(.services[] | .container_name // empty), (.networks[] | .name // empty)' |
    grep -Fxf - <({ docker ps -a --format '{{.Names}}'; docker network ls --format '{{.Name}}'; }) || true)
  if [[ -n "$clash" || -n "$(docker ps -aq --filter label=com.docker.compose.project=chronicle)" ]]; then
    log "refusing: this host already runs the chronicle stack (${clash//$'\n'/ }); run http-smoke-stack on a disposable host"
    [[ "$repo_env_created" != 1 ]] || rm -f "$repo_env_file"
    rm -rf "$tmp_dir"
    return 1
  fi

  # Freeze these function-local paths now; they are out of scope when the
  # process-level EXIT trap runs after the selected job returns.
  # shellcheck disable=SC2064
  trap "docker compose -p chronicle-ci-smoke --env-file '$env_file' -f '$ROOT_DIR/docker/docker-compose.traefik.yml' -f '$override_file' down -v --remove-orphans >/dev/null 2>&1 || true; if [ '$repo_env_created' = '1' ]; then rm -f '$repo_env_file'; fi; rm -rf '$tmp_dir'" EXIT

  run_ci_smoke_stack
}

# Uses the disposable paths and Compose argv scoped by job_http_smoke_stack.
run_ci_smoke_stack() {
  docker build -f "$ROOT_DIR/docker/Dockerfile.backend" -t chronicle-backend:test "$ROOT_DIR"
  docker build -f "$ROOT_DIR/docker/Dockerfile.frontend.prod" -t chronicle-frontend-prod:test "$ROOT_DIR"
  if ! docker compose "${compose_args[@]}" up -d postgres chronicle-backend chronicle-frontend; then
    docker compose "${compose_args[@]}" logs postgres --tail=160 || true
    docker compose "${compose_args[@]}" logs chronicle-backend --tail=160 || true
    docker compose "${compose_args[@]}" ps || true
    return 1
  fi

  log "waiting for backend"
  # A first boot applies the full Flyway corpus onto encrypted tables. Keep this
  # bounded, but allow enough time for a cold runner rather than racing startup.
  for i in $(seq 1 60); do
    if curl -q --noproxy '*' -sf --connect-timeout 3 --max-time 10 "${backend_url}/chronicle/internal/health/ready" >/dev/null 2>&1; then
      break
    fi
    if [[ "$i" -eq 60 ]]; then
      docker compose "${compose_args[@]}" logs postgres --tail=160
      docker compose "${compose_args[@]}" logs chronicle-backend --tail=100
      exit 1
    fi
    sleep 5
  done

  metrics_password=$(<"$secrets_dir/chronicle_security_metrics_password")
  local metrics_credentials="chronicle-metrics:$metrics_password"
  case "$metrics_credentials" in *$'\n'*|*$'\r'*) return 2 ;; esac
  metrics_credentials="${metrics_credentials//\\/\\\\}"
  metrics_credentials="${metrics_credentials//\"/\\\"}"
  metrics_status=$(printf 'user = "%s"\n' "$metrics_credentials" | \
    curl -q --config - --noproxy '*' --silent --show-error --output /dev/null --write-out '%{http_code}' \
    --connect-timeout 3 --max-time 10 \
    "${backend_url}/prometheus/" 2>/dev/null || true)
  if [[ "$metrics_status" != "200" ]]; then
    log "authenticated metrics smoke failed with HTTP ${metrics_status:-000}"
    docker compose "${compose_args[@]}" logs chronicle-backend --tail=100
    return 1
  fi

  log "waiting for frontend"
  for i in $(seq 1 12); do
    if curl -q --noproxy '*' -sf --connect-timeout 3 --max-time 10 "${frontend_url}/health" >/dev/null 2>&1; then
      break
    fi
    if [[ "$i" -eq 12 ]]; then
      docker compose "${compose_args[@]}" logs chronicle-frontend --tail=100
      exit 1
    fi
    sleep 5
  done

  MOBILE_SIGNING_SECRET=$(<"$secrets_dir/mobile_signing_secret") run_http_smoke_probes "$backend_url" "$frontend_url"
}

run_http_smoke_probes() {
  local backend_url="$1" frontend_url="$2"
  "$ROOT_DIR/scripts/smoke-test.sh" "$backend_url" "$frontend_url" || return $?
  BASE_URL="$backend_url" job_http_security
}

job_http_security() {
  log "live upload, load smoke and race validation"
  bash "$ROOT_DIR/tests/security/run-all-security.sh" upload \
    "${LOCAL_REPORT_DIR:-$ROOT_DIR/tests/security/reports}/upload"
}

job_k6_benchmarks() {
  require_cmd k6 "install k6"
  : "${BASE_URL:?Set the disposable fixture listener}"
  : "${AUTH_TOKEN:?Set its researcher token}"
  : "${TEST_STUDY_ID:?Set its synthetic study}"
  : "${TEST_PARTICIPANT_ID:?Set its synthetic participant}"
  : "${TEST_RANDOM_DEVICE_ID:?Set its enrolled synthetic device}"
  : "${API_KEY:?Set its enrolled device API key}"
  : "${DEVICE_FIXTURES_FILE:?Set its enrolled synthetic device inventory}"
  local suite
  for suite in "$ROOT_DIR"/tests/load/chronicle-load-test.js "$ROOT_DIR"/tests/load/k6-*.js; do
    JWT_TOKEN="$AUTH_TOKEN" STUDY_ID="$TEST_STUDY_ID" PARTICIPANT_ID="$TEST_PARTICIPANT_ID" \
      k6 run --include-system-env-vars "$suite"
  done
}

job_pit() {
  require_jdk21
  log "server PIT mutation tests"
  gradle :chronicle-server:pitest
}

job_fuzz() {
  require_jdk21
  require_cmd python3 "install Python 3"
  local targets target
  targets="$(python3 - "$ROOT_DIR/chronicle-server/src/test" <<'PY'
from pathlib import Path
import re
import sys

for path in sorted(Path(sys.argv[1]).rglob('*FuzzTest.kt')):
    source = path.read_text()
    package = re.search(r'^package (\S+)', source, re.M).group(1)
    methods = re.findall(r'@FuzzTest\((.*?)\)\s+fun\s+(\w+)\(', source, re.S)
    if len(methods) != source.count('@FuzzTest'):
        raise SystemExit(f'unrecognized fuzz target in {path}')
    for options, method in methods:
        if not re.search(r'maxDuration\s*=\s*"[1-9][0-9]*[smh]"', options):
            raise SystemExit(f'fuzz target requires a bounded maxDuration: {path}:{method}')
        print(f'{package}.{path.stem}.{method}')
PY
  )"
  [[ -n "$targets" ]] || { log "no bounded fuzz targets found"; return 2; }
  # Jazzer permits one target per JVM; each annotation supplies its time limit.
  while IFS= read -r target; do
    log "fuzz target: $target"
    JAZZER_FUZZ=1 gradle :chronicle-server:test --tests "$target" \
      --no-build-cache --rerun-tasks
  done <<< "$targets"
}

job_parity() {
  require_jdk21
  require_cmd bun "install Bun 1.3.x"
  gradle :chronicle-server:test --tests "*ParityTest"
  (cd "$WEB_DIR" && bun install --frozen-lockfile --ignore-scripts && bun test src/modern/test/parity.test.ts)
}

job_android_unit() {
  require_jdk21
  require_cmd python3 "install Python 3"
  require_cmd uv "install uv for the locked upload-tool tests"
  bash "$ROOT_DIR/tests/security/run-all-security.sh" sast "${LOCAL_REPORT_DIR:-$ROOT_DIR/tests/security/reports}" || return $?
  (cd "$ROOT_DIR/chronicle" && ./gradlew :app:checkLicense --no-daemon) || return $?
  (cd "$ROOT_DIR/chronicle" && ./gradlew -I "$ROOT_DIR/scripts/android-unused-resources.init.gradle" :app:lintOpenRelease --no-daemon) || return $?
  python3 "$ROOT_DIR/chronicle/scripts/test-ui-resource-contracts.py" || return $?
  python3 "$ROOT_DIR/chronicle/scripts/test-android-batch-1007.py" || return $?
  python3 "$ROOT_DIR/chronicle/scripts/test-gate-regressions.py" || return $?
  log "Android Play and release verifier self-tests"
  local audit_work="${LOCAL_REPORT_DIR:-$ROOT_DIR/chronicle/app/build}/release-audit-tests"
  local suite android_status=0
  mkdir -p "$audit_work/tmp"
  TMPDIR="$audit_work/tmp" python3 "$ROOT_DIR/chronicle/scripts/test-collected-upload-mapping.py" || android_status=1
  bash "$ROOT_DIR/chronicle/scripts/test-verify-play-submission.sh" || android_status=1
  uv run --no-project --python 3.12 --with-requirements "$ROOT_DIR/chronicle/scripts/play-upload.requirements.txt" \
    python "$ROOT_DIR/chronicle/scripts/test-play-upload.py" || android_status=1
  python3 "$ROOT_DIR/chronicle/scripts/test-verify-retrofit-map-signatures.py" || android_status=1
  ANDROID_AUDIT_WORK="$audit_work" python3 "$ROOT_DIR/chronicle/scripts/test-release-audit.py" || android_status=1
  ANDROID_AUDIT_WORK="$audit_work" python3 "$ROOT_DIR/chronicle/scripts/test-release-signing-policy.py" || android_status=1
  ANDROID_AUDIT_WORK="$audit_work" python3 "$ROOT_DIR/chronicle/scripts/test-release-gate-evidence.py" || android_status=1
  log "Android unit tests (library modules + all distribution app variants; ScreenLayoutTest goldens verified)"
  # roborazzi.test.verify makes ScreenLayoutTest compare every capture with src/testOpen/screenshots
  # and fail on a difference, in the same run (same as verifyRoborazziOpenDebug).
  local -a coverage_tasks=(:app:createOpenDebugUnitTestCoverageReport :app:createResearchDebugUnitTestCoverageReport :app:createAmazonDebugUnitTestCoverageReport :libraryCoverageFromAppTests)
  local module
  for module in "$ROOT_DIR"/chronicle/collection-*; do
    [[ -n "$(find "$module/src/test" -type f -print -quit 2>/dev/null)" ]] || continue
    coverage_tasks+=(":${module##*/}:createDebugUnitTestCoverageReport")
  done
  (cd "$ROOT_DIR/chronicle" && ./gradlew -I "$ROOT_DIR/scripts/android-coverage.init.gradle" -I scripts/test-workmanager-runtime.gradle verifyWorkManagerRuntime testDebugUnitTest :app:testOpenDebugUnitTest :app:testResearchDebugUnitTest :app:testAmazonDebugUnitTest "${coverage_tasks[@]}" -Proborazzi.test.verify=true --no-daemon --build-cache) || android_status=1
  return "$android_status"
}

job_android_instrumented() {
  require_jdk21
  require_cmd adb "install Android platform-tools"
  # Debug and test packages only; the installed release app is never replaced or uninstalled.
  [[ "$(adb get-state 2>/dev/null)" == device ]] || { log "android-instrumented: no device attached (set ANDROID_SERIAL)"; return 2; }
  (cd "$ROOT_DIR/chronicle" && ./gradlew connectedDebugAndroidTest --no-daemon)
}

job_ios_verify() {
  require_cmd python3
  require_cmd xcodebuild "run on macOS with Xcode installed"
  require_cmd rg "install ripgrep (brew install ripgrep)"
  log "iOS generated contract freshness"
  (cd "$ROOT_DIR/chronicle-ios" && python3 scripts/generate-ios-contracts.py --check)
  log "iOS simulator test suite (no-AWS harness; physical-device checks skipped)"
  local destination="${SIMULATOR_DESTINATION:-}"
  if [[ -z "$destination" ]]; then
    # Pick any available iPhone simulator: runner images and dev machines ship
    # different device sets, and a hard-coded name rots (e.g. "iPhone 17e").
    local sim_name
    sim_name="$(xcrun simctl list devices available | sed -n 's/^ *\(iPhone[^(]*\)(.*/\1/p' | sed 's/ *$//' | head -1)"
    if [[ -z "$sim_name" ]]; then
      printf '[local-ci] no available iPhone simulator found\n' >&2
      return 1
    fi
    destination="platform=iOS Simulator,name=$sim_name"
  fi
  RUN_PHYSICAL_DEVICE=0 SIMULATOR_DESTINATION="$destination" \
    REPORT_DIR="$ROOT_DIR/chronicle-ios/build/ios-no-aws" \
    "$ROOT_DIR/chronicle-ios/scripts/ios-no-aws-verify.sh"
}

job_gitleaks() {
  # Local twin of each repo's gitleaks.yml "Scan for secrets" workflow (full
  # git-history scan). The private repos get no free Actions minutes, so this
  # is the proof gate that actually runs. Known historical/false-positive
  # fingerprints live in tests/security/gitleaks-ignore/<name>.gitleaksignore;
  # only NEW findings fail the job.
  require_cmd gitleaks "install gitleaks (brew install gitleaks)"
  local repo name ignore toplevel failed=() unscanned=()
  for repo in . chronicle chronicle-api chronicle-ios chronicle-models \
    chronicle-server chronicle-web rhizome rhizome-client; do
    name="$repo"
    [[ "$repo" == "." ]] && name="chronicle-platform-root"
    if [[ "$repo" == chronicle-ios && ! -e "$ROOT_DIR/$repo/.git" && \
          "$(git config -f "$ROOT_DIR/.gitmodules" --get submodule.chronicle-ios.update)" == none ]]; then
      log "gitleaks: chronicle-ios is outside the initialized module scope (update=none)"
      continue
    fi
    ignore="$ROOT_DIR/tests/security/gitleaks-ignore/$name.gitleaksignore"
    [[ -f "$ignore" ]] || ignore="/dev/null"
    log "gitleaks: $name"
    toplevel="$(git -C "$ROOT_DIR/$repo" rev-parse --show-toplevel 2>/dev/null || true)"
    if [[ -z "$toplevel" || "$(cd "$toplevel" && pwd -P)" != "$(cd "$ROOT_DIR/$repo" && pwd -P)" ]]; then
      printf '[local-ci] gitleaks: %s is not a git checkout\n' "$name" >&2
      unscanned+=("$name")
      continue
    fi
    if ! (cd "$ROOT_DIR/$repo" && \
      gitleaks git --no-banner --redact --gitleaks-ignore-path "$ignore" .); then
      failed+=("$name")
    fi
  done
  if ((${#failed[@]} > 0)); then
    printf '[local-ci] gitleaks found leaks in: %s\n' "${failed[*]}" >&2
  fi
  if ((${#unscanned[@]} > 0)); then
    printf '[local-ci] gitleaks could not scan: %s\n' "${unscanned[*]}" >&2
  fi
  ((${#failed[@]} + ${#unscanned[@]} == 0))
}

job_depcheck_locks() {
  local lock_listing active_processes
  lock_listing="$(dependency_check_lock_listing)"
  if [[ -z "$lock_listing" ]]; then
    printf '[local-ci] no Dependency-Check lock files present.\n'
    return 0
  fi

  active_processes="$(dependency_check_active_processes)"
  printf '[local-ci] Dependency-Check lock file(s) present:\n' >&2
  while IFS= read -r lock_file; do
    [[ -z "$lock_file" ]] && continue
    if stat -f '%Sm %N' "$lock_file" >/dev/null 2>&1; then
      stat -f '[local-ci]   %Sm %N' "$lock_file" >&2
    else
      stat -c '[local-ci]   %y %n' "$lock_file" >&2
    fi
  done <<<"$lock_listing"

  if [[ -n "$active_processes" ]]; then
    printf '[local-ci] related process(es) are active; not cleaning locks:\n%s\n' "$active_processes" >&2
    return 2
  fi

  if [[ "${CHRONICLE_DEPCHECK_CLEAN_STALE_LOCKS:-0}" != "1" ]]; then
    cat >&2 <<'EOF'
[local-ci] no related Gradle/Dependency-Check process is running.
[local-ci] To remove stale locks before a keyed fresh update, rerun:
[local-ci]   CHRONICLE_DEPCHECK_CLEAN_STALE_LOCKS=1 scripts/local-ci.sh depcheck-locks
EOF
    return 2
  fi

  while IFS= read -r lock_file; do
    [[ -z "$lock_file" ]] && continue
    rm -f -- "$lock_file"
    printf '[local-ci] removed stale Dependency-Check lock: %s\n' "$lock_file" >&2
  done <<<"$lock_listing"

  if [[ -n "$(dependency_check_lock_listing)" ]]; then
    printf '[local-ci] Dependency-Check lock cleanup incomplete.\n' >&2
    return 1
  fi
  printf '[local-ci] Dependency-Check lock cleanup complete.\n'
}

job_gradle_depcheck() {
  require_jdk21
  # Loads from env, a private file, macOS Keychain, or pass without printing.
  # The later check still fails closed when no key is available.
  # shellcheck source=/dev/null
  source "$ROOT_DIR/scripts/chronicle-load-nvd-api-key.sh"
  if [[ "${SKIP_NVD_UPDATE:-0}" != "1" && -z "${NVD_API_KEY:-}" ]]; then
    printf '[local-ci] NVD_API_KEY is required for gradle-depcheck.\n' >&2
    exit 2
  fi
  if [[ "${SKIP_NVD_UPDATE:-0}" != "1" ]]; then
    diagnose_dependency_check_data
    local update_timeout="${CHRONICLE_DEPCHECK_UPDATE_TIMEOUT_SECONDS:-3600}"
    local update_log="${CHRONICLE_DEPCHECK_UPDATE_LOG:-$(report_path "$ROOT_DIR/build/reports/dependency-check-update.log" "dependency-check-update.log")}"
    local update_snapshot_before
    local update_snapshot_after
    update_snapshot_before="$(report_path "$ROOT_DIR/build/reports/dependency-check-update-data-before.txt" "dependency-check-update-data-before.txt")"
    update_snapshot_after="$(report_path "$ROOT_DIR/build/reports/dependency-check-update-data-after.txt" "dependency-check-update-data-after.txt")"
    local update_args=(
      dependencyCheckUpdateShared
      --no-daemon
      --max-workers=1
      --console=plain
    )
    if [[ -n "${CHRONICLE_DEPCHECK_NVD_DELAY_MILLIS:-}" ]]; then
      update_args+=("-PdependencyCheckNvdDelayMillis=$CHRONICLE_DEPCHECK_NVD_DELAY_MILLIS")
    fi
    if [[ -n "${CHRONICLE_DEPCHECK_NVD_MAX_RETRY_COUNT:-}" ]]; then
      update_args+=("-PdependencyCheckNvdMaxRetryCount=$CHRONICLE_DEPCHECK_NVD_MAX_RETRY_COUNT")
    fi
    if [[ -n "${CHRONICLE_DEPCHECK_NVD_RESULTS_PER_PAGE:-}" ]]; then
      update_args+=("-PdependencyCheckNvdResultsPerPage=$CHRONICLE_DEPCHECK_NVD_RESULTS_PER_PAGE")
    fi
    if [[ -n "${CHRONICLE_DEPCHECK_GRADLE_LOG_LEVEL:-}" ]]; then
      update_args+=("$CHRONICLE_DEPCHECK_GRADLE_LOG_LEVEL")
    fi
    printf '[local-ci] running Dependency-Check NVD update timeout=%ss\n' "$update_timeout"
    printf '[local-ci] Dependency-Check update log: %s\n' "$update_log"
    dependency_check_data_snapshot "$update_snapshot_before"
    local update_status=0
    run_with_timeout_logged "$update_timeout" "$update_log" "$ROOT_DIR/gradlew" "${update_args[@]}" || update_status=$?
    if [[ "$update_status" -ne 0 ]]; then
      dependency_check_data_snapshot "$update_snapshot_after"
      printf '[local-ci] Dependency-Check update failed with status %s.\n' "$update_status" >&2
      printf '[local-ci] Data snapshots: %s %s\n' "$update_snapshot_before" "$update_snapshot_after" >&2
      printf '[local-ci] Redacted update log: %s\n' "$update_log" >&2
      return "$update_status"
    fi
    dependency_check_data_snapshot "$update_snapshot_after"
    dependency_check_record_update
  elif [[ ! -s "$CHRONICLE_DEPCHECK_DATA_DIR/odc.mv.db" ]]; then
    if [[ "${CHRONICLE_DEPCHECK_ALLOW_MISSING_CACHE:-0}" == "1" ]]; then
      local reason="SKIP_NVD_UPDATE=1 requested but no warmed NVD database (odc.mv.db) was found"
      printf '[local-ci] %s; writing skip report.\n' "$reason" >&2
      write_dependency_check_skip_report "$reason"
      return 0
    fi
    printf '[local-ci] SKIP_NVD_UPDATE=1 requires a warmed %s cache.\n' "$CHRONICLE_DEPCHECK_DATA_DIR/odc.mv.db" >&2
    exit 2
  else
    dependency_check_require_fresh || exit 2
  fi
  local status=0
  local depcheck_args=(-PdependencyCheckAutoUpdate=false)
  if [[ "${SKIP_NVD_UPDATE:-0}" == "1" ]]; then
    depcheck_args+=(-PdependencyCheckOffline=true)
  fi
  local gradle_task_args=(dependencyCheckAll)
  if [[ "${CHRONICLE_DEPCHECK_RERUN:-0}" == "1" ]]; then
    gradle_task_args+=(--rerun-tasks)
  fi
  gradle "${gradle_task_args[@]}" --max-workers=1 "${depcheck_args[@]}" || status=$?
  copy_dependency_check_reports || {
    if [[ "$status" -eq 0 ]]; then
      status=1
    fi
  }
  return "$status"
}

job_dependency_age() {
  # Base: CHRONICLE_DEPENDENCY_BASE (the gate runner passes deps/auto), else origin/main.
  local report
  report="$(report_path "$ROOT_DIR/build/reports/dependency-age.txt" "dependency-age.txt")"
  python3 "$ROOT_DIR/scripts/check-dependency-age.py" --root "$ROOT_DIR" --report "$report"
}

job_deps_freshness() {
  local report
  report="$(report_path "$ROOT_DIR/build/reports/deps-freshness.json" "deps-freshness.json")"
  "$ROOT_DIR/scripts/deps-freshness.sh" --json > "$report" || { cat "$report" >&2; return 1; }
  "$ROOT_DIR/scripts/deps-freshness.sh"
}

job_fluent_bit_config() {
  # Every shipped fluent-bit config must load on the manifest-pinned image (`--dry-run`
  # validates plugins, parsers and the Lua filter). This is what makes a major bump of the
  # log shipper safe to take: 4.x -> 5.x was accepted on this check.
  local image
  local conf="selfhost/monitoring/fluent-bit.conf"
  image="$(yq -r '.selfhost_images.fluent_bit' "$ROOT_DIR/toolchain-manifest.yaml")"
  [[ -n "$image" && "$image" != "null" ]] || { echo "[fail] selfhost_images.fluent_bit missing from toolchain-manifest.yaml" >&2; return 1; }
  if docker run --rm --network none \
      -v "$ROOT_DIR/$(dirname "$conf"):/fluent-bit/etc:ro" \
      -e KAFKA_USER=ci -e KAFKA_PASSWORD=ci \
      -e SIEM_HOST=siem.invalid -e SIEM_PORT=514 -e SIEM_URI=/ -e SIEM_AUTHORIZATION_HEADER=none \
      "$image" --dry-run -c "/fluent-bit/etc/$(basename "$conf")" >/dev/null 2>&1; then
    echo "[ok] $conf loads on $image"
  else
    echo "[fail] $conf does not load on $image" >&2
    return 1
  fi

}

job_bun_audit() {
  require_cmd bun "install Bun 1.3.x"
  bash "$ROOT_DIR/tests/security/run-all-security.sh" sca \
    "${LOCAL_REPORT_DIR:-$ROOT_DIR/tests/security/reports}/sca"
}

job_detekt() {
  ensure_detekt
  ensure_ast_grep
  local sarif_report all_sarif_report html_report android_sources fresh
  android_sources="$(printf '%s,' "$ROOT_DIR"/chronicle/*/src)"
  sarif_report="$(report_path "$ROOT_DIR/detekt-results.sarif" "detekt-results.sarif")"
  all_sarif_report="$(report_path "$ROOT_DIR/detekt-all-results.sarif" "detekt-all-results.sarif")"
  html_report="$(report_path "$ROOT_DIR/detekt-results.html" "detekt-results.html")"
  local -a detekt=(java -jar "$LOCAL_BIN_DIR/detekt-cli-1.23.7-all.jar"
    --input "$ROOT_DIR/chronicle-server/src,$ROOT_DIR/chronicle-api/src,$ROOT_DIR/rhizome/src,${android_sources%,}"
    --base-path "$ROOT_DIR" --excludes '**/build/**,**/.gradle/**' --config "$ROOT_DIR/detekt.yml" --build-upon-default-config)
  local status=0 filtered_status=0 all_status=0
  "${detekt[@]}" --baseline "$ROOT_DIR/detekt-baseline.xml" --report "sarif:$sarif_report" --report "html:$html_report" || filtered_status=$?
  if [[ "$filtered_status" != 0 && "$filtered_status" != 2 ]]; then return "$filtered_status"; fi
  "${detekt[@]}" --report "sarif:$all_sarif_report" || all_status=$?
  if [[ "$all_status" != 0 && "$all_status" != 2 ]]; then return "$all_status"; fi
  status="$filtered_status"
  # The ast-grep ensure_ast_grep resolved (LOCAL_BIN_DIR is first on PATH); the check refuses any other version.
  CHRONICLE_AST_GREP="$(command -v ast-grep)" python3 "$ROOT_DIR/scripts/check-detekt-waiver-source.py" \
    --all-sarif "$all_sarif_report" --filtered-sarif "$sarif_report" || status=1
  # A stale baseline entry would admit a new finding with the same signature, so it fails too.
  # detekt reads an existing --baseline file before writing it, so the path must not exist yet.
  fresh="$(gate_tool_temp -d)"
  "${detekt[@]}" --baseline "$fresh/baseline.xml" --create-baseline >/dev/null || { rm -rf -- "$fresh"; return 1; }
  python3 - "$ROOT_DIR/detekt-baseline.xml" "$fresh/baseline.xml" <<'PY' || status=$?
import sys
import xml.etree.ElementTree as ET
committed, current = ({node.text for node in ET.parse(path).getroot().iter("ID")} for path in sys.argv[1:3])
for entry in sorted(committed - current):
    print(f"STALE detekt-baseline.xml entry: {entry}")
sys.exit(1 if committed - current else 0)
PY
  rm -rf -- "$fresh"
  return "$status"
}

job_gate_tools() {
  # The dependency gate runner's tools step: every checksum-pinned tool the security and web jobs
  # download, and grype's database, fetched into LOCAL_BIN_DIR by this script alone, so that those
  # jobs then run with no network and no write access to their tools.
  ensure_detekt
  ensure_ast_grep
  ensure_pmd
  ensure_bearer
  ensure_osv_scanner
  ensure_grype
  ensure_syft
  "$LOCAL_BIN_DIR/grype" db update
}

job_pmd() {
  require_jdk21
  ensure_pmd
  "$LOCAL_BIN_DIR/pmd-${PMD_VERSION}/bin/pmd" check \
    -d "$ROOT_DIR/chronicle-server/src/main/java" \
    -R rulesets/java/quickstart.xml \
    -f text
}

job_bearer() {
  ensure_bearer
  local sarif_report
  sarif_report="$(report_path "$ROOT_DIR/bearer-results.sarif" "bearer-results.sarif")"
  BEARER_SCANNER=sast \
    BEARER_FORMAT=sarif \
    BEARER_OUTPUT="$sarif_report" \
    BEARER_HIDE_PROGRESS_BAR=true \
    bearer scan "$ROOT_DIR"
  python3 - "$sarif_report" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
doc = json.loads(path.read_text())
for run in doc.get("runs", []):
    if run.get("results") is None:
        run["results"] = []
path.write_text(json.dumps(doc, indent=2) + "\n")
PY
}

job_osv() {
  ensure_osv_scanner
  local sarif_report
  sarif_report="$(report_path "$ROOT_DIR/osv-results.sarif" "osv-results.sarif")"
  osv-scanner scan source \
    --recursive \
    --config "$ROOT_DIR/osv-scanner.toml" \
    --experimental-exclude 'r:(^|/)gradle($|/)' \
    --format=sarif \
    --output-file="$sarif_report" \
    "$ROOT_DIR"
  # The recursive scan skips gradle/ hash catalogs; the Android build toolchain (AGP, lint,
  # bundletool) resolves only there, so scan that catalog as a lockfile of its own.
  osv-scanner scan source \
    --config "$ROOT_DIR/osv-scanner.toml" \
    --lockfile "$ROOT_DIR/chronicle/gradle/verification-metadata.xml" \
    --format=sarif \
    --output-file="$(report_path "$ROOT_DIR/osv-android-toolchain.sarif" "osv-android-toolchain.sarif")"
}

job_grype() {
  ensure_grype
  local fail_on="${GRYPE_FAIL_ON-high}"
  local sarif_report
  sarif_report="$(report_path "$ROOT_DIR/grype-results.sarif" "grype-results.sarif")"
  if [[ -n "$fail_on" ]]; then
    grype --config "$ROOT_DIR/.grype.yaml" "dir:$ROOT_DIR" \
      --fail-on "$fail_on" -o "sarif=$sarif_report"
  else
    grype --config "$ROOT_DIR/.grype.yaml" "dir:$ROOT_DIR" \
      -o "sarif=$sarif_report"
  fi
}

job_syft() {
  ensure_syft
  local sbom_report
  sbom_report="$(report_path "$ROOT_DIR/sbom-spdx.json" "sbom-spdx.json")"
  syft "$ROOT_DIR" -o spdx-json="$sbom_report"
}

job_linkml_ssot() {
  require_cmd python3 "install Python 3"
  local models_dir="${CHRONICLE_MODELS_DIR:-}"
  if [[ -z "$models_dir" && -f "$ROOT_DIR/chronicle-models/generated/domain-contracts/chronicle-domain-contracts.json" ]]; then
    models_dir="$ROOT_DIR/chronicle-models"
  elif [[ -z "$models_dir" && -f "$ROOT_DIR/../chronicle-models/generated/domain-contracts/chronicle-domain-contracts.json" ]]; then
    models_dir="$ROOT_DIR/../chronicle-models"
  fi
  if [[ -n "$models_dir" ]]; then
    CHRONICLE_MODELS_DIR="$models_dir" "$ROOT_DIR/tests/security/schema-guardrails.sh"
    CHRONICLE_MODELS_DIR="$models_dir" "$ROOT_DIR/tests/security/domain-contract-guardrails.sh"
  else
    "$ROOT_DIR/tests/security/schema-guardrails.sh"
    "$ROOT_DIR/tests/security/domain-contract-guardrails.sh"
  fi
}

job_web_mutation() {
  require_cmd bun "install Bun 1.3.x"
  (cd "$WEB_DIR" && bun run test:mutate)
}

run_job() {
  local completed
  for completed in "${completed_jobs[@]:-}"; do
    [[ "$completed" != "$1" ]] || return 0
  done
  case "$1" in
    fast|security|containers|all) ;;
    *)
      if [[ "${CHRONICLE_LOCAL_CI_KEEP_GOING:-0}" == "1" ]]; then
        local status
        # Testing a function with if/|| disables errexit in every nested call.
        set +e
        ( set -e; CHRONICLE_LOCAL_CI_KEEP_GOING=0 run_job "$1" )
        status=$?
        set -e
        if [[ "$status" -ne 0 ]]; then
          failures=$((failures + 1))
          printf '[local-ci] job failed: %s status=%s\n' "$1" "$status" >&2
        fi
        completed_jobs+=("$1")
        return 0
      fi
      ;;
  esac
  # Under `run_job x || ...` errexit is off, so return the job's own status instead of the append's.
  local job_status
  dispatch_job "$1"
  job_status=$?
  [[ "$job_status" -ne 0 ]] || completed_jobs+=("$1")
  return "$job_status"
}

run_job_group() {
  local job resolved
  local -a members
  resolved="$(job_group_members "$1")"
  read -r -a members <<<"$resolved"
  for job in "${members[@]}"; do
    run_job "$job"
  done
}

dispatch_job() {
  case "$1" in
    preflight) job_preflight ;;
    engineering) job_engineering ;;
    architecture) job_architecture ;;
    migration-safety) job_migration_safety ;;
    selfhost-restore) job_selfhost_restore ;;
    contract-drift) job_contract_drift ;;
    diff-coverage) job_diff_coverage ;;
    duplication) job_duplication ;;
    migration-lint) job_migration_lint ;;
    web) job_web ;;
    web-a11y) job_web_a11y ;;
    web-e2e) job_web_e2e ;;
    api-probes) job_api_probes ;;
    selfhost-browser) job_selfhost_browser ;;
    k6-benchmarks) job_k6_benchmarks ;;
    jvm-smoke) job_jvm_smoke ;;
    repo-automation) job_repo_automation ;;
    linkml-ssot) job_linkml_ssot ;;
    dead-code) job_dead_code ;;
    security-layers) job_security_layers ;;
    dependency-sbom) job_dependency_sbom ;;
    selfhost-python) job_selfhost_python ;;
    selfhost) job_selfhost ;;
    dockerfile-lint) job_dockerfile_lint ;;
    iac-scan) job_iac_scan ;;
    license-compliance) job_license_compliance ;;
    container-structure) job_container_structure ;;
    image-gate) job_image_gate ;;
    upload-body-limit-edge) job_upload_body_limit_edge ;;
    android-replay) job_android_replay ;;
    route-surface-edge) job_route_surface_edge ;;
    http-smoke-stack) job_http_smoke_stack ;;
    http-security) job_http_security ;;
    pit) job_pit ;;
    fuzz) job_fuzz ;;
    parity) job_parity ;;
    android-unit) job_android_unit ;;
    android-instrumented) job_android_instrumented ;;
    ios-verify) job_ios_verify ;;
    gitleaks) job_gitleaks ;;
    depcheck-locks) job_depcheck_locks ;;
    gradle-depcheck) job_gradle_depcheck ;;
    bun-audit) job_bun_audit ;;
    deps-freshness) job_deps_freshness ;;
    dependency-age) job_dependency_age ;;
    fluent-bit-config) job_fluent_bit_config ;;
    detekt) job_detekt ;;
    pmd) job_pmd ;;
    bearer) job_bearer ;;
    osv) job_osv ;;
    grype) job_grype ;;
    syft) job_syft ;;
    gate-tools) job_gate_tools ;;
    web-mutation) job_web_mutation ;;
    fast|security|containers|all) run_job_group "$1" ;;
    -h|--help|help) usage ;;
    *) printf '[local-ci] unknown job: %s\n\n' "$1" >&2; usage >&2; exit 2 ;;
  esac
}

local_ci_main() {
  if [[ "$#" -eq 0 ]]; then
    usage
    return 2
  fi
  failures=0
  completed_jobs=()
  export_docker_host_from_context
  local job
  for job in "$@"; do
    log "job: $job"
    run_job "$job"
  done
  if [[ "$failures" -gt 0 ]]; then
    printf '[local-ci] %s job(s) failed\n' "$failures" >&2
    return 1
  fi
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  local_ci_main "$@"
fi
