#!/usr/bin/env bash
# Read-only host profile validator for operator-managed Chronicle RHEL 9 targets.
set -euo pipefail

MIN_VCPU="${CHRONICLE_MIN_VCPU:-8}"
MIN_MEMORY_MIB="${CHRONICLE_MIN_MEMORY_MIB:-15000}"
MIN_ROOT_FREE_GIB="${CHRONICLE_MIN_ROOT_FREE_GIB:-40}"
REQUIRE_RHEL9="${CHRONICLE_REQUIRE_RHEL9:-true}"
REQUIRE_SELINUX="${CHRONICLE_REQUIRE_SELINUX:-true}"

failures=0
warnings=0

usage() {
  cat <<'EOF'
Usage: scripts/validate-rhel9-host-profile.sh

Read-only validator for the Chronicle production/fallback host profile.

Environment overrides:
  CHRONICLE_MIN_VCPU=8
  CHRONICLE_MIN_MEMORY_MIB=15000
  CHRONICLE_MIN_ROOT_FREE_GIB=40
  CHRONICLE_REQUIRE_RHEL9=true
  CHRONICLE_REQUIRE_SELINUX=true

This script does not mutate the host. It is intended to run on the target
RHEL 9 server before Ansible platform validation.
EOF
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

record() {
  local status="$1"
  local label="$2"
  local detail="$3"
  printf '%-6s %-36s %s\n' "$status" "$label" "$detail"
}

pass() {
  record "PASS" "$1" "$2"
}

warn() {
  warnings=$((warnings + 1))
  record "WARN" "$1" "$2"
}

fail() {
  failures=$((failures + 1))
  record "FAIL" "$1" "$2"
}

is_true() {
  [[ "$1" == "true" || "$1" == "1" || "$1" == "yes" ]]
}

service_active() {
  local service="$1"
  if ! command -v systemctl >/dev/null 2>&1; then
    return 2
  fi
  systemctl is-active --quiet "$service"
}

printf 'Chronicle RHEL 9 host profile validator\n'
printf 'Required profile: >=%s vCPU, >=%s MiB RAM, >=%s GiB free on /\n\n' \
  "$MIN_VCPU" "$MIN_MEMORY_MIB" "$MIN_ROOT_FREE_GIB"

if [[ "$(uname -s)" != "Linux" ]]; then
  fail "operating system" "expected Linux/RHEL 9 target, found $(uname -s)"
else
  pass "operating system" "Linux"
fi

if [[ -r /etc/os-release ]]; then
  # shellcheck disable=SC1091
  . /etc/os-release
  os_name="${NAME:-unknown}"
  os_version="${VERSION_ID:-unknown}"
  if is_true "$REQUIRE_RHEL9"; then
    if [[ "${ID:-}" == "rhel" && "$os_version" == 9* ]]; then
      pass "rhel version" "$os_name $os_version"
    else
      fail "rhel version" "expected RHEL 9, found ${ID:-unknown} $os_version"
    fi
  else
    warn "rhel version" "not enforced; found $os_name $os_version"
  fi
else
  fail "rhel version" "/etc/os-release is missing"
fi

vcpu_count="$(getconf _NPROCESSORS_ONLN 2>/dev/null || nproc 2>/dev/null || echo 0)"
if [[ "$vcpu_count" =~ ^[0-9]+$ && "$vcpu_count" -ge "$MIN_VCPU" ]]; then
  pass "cpu capacity" "$vcpu_count online vCPU"
else
  fail "cpu capacity" "$vcpu_count online vCPU; need >= $MIN_VCPU"
fi

if [[ -r /proc/meminfo ]]; then
  mem_mib="$(awk '/^MemTotal:/ {printf "%d", $2 / 1024}' /proc/meminfo)"
  if [[ "$mem_mib" -ge "$MIN_MEMORY_MIB" ]]; then
    pass "memory capacity" "${mem_mib} MiB"
  else
    fail "memory capacity" "${mem_mib} MiB; need >= ${MIN_MEMORY_MIB} MiB"
  fi
else
  fail "memory capacity" "/proc/meminfo is unavailable"
fi

root_free_gib="$(df -Pk / | awk 'NR==2 {printf "%d", $4 / 1024 / 1024}')"
if [[ "$root_free_gib" -ge "$MIN_ROOT_FREE_GIB" ]]; then
  pass "root filesystem free" "${root_free_gib} GiB"
else
  fail "root filesystem free" "${root_free_gib} GiB; need >= ${MIN_ROOT_FREE_GIB} GiB"
fi

if command -v getenforce >/dev/null 2>&1; then
  selinux_state="$(getenforce)"
  if is_true "$REQUIRE_SELINUX"; then
    if [[ "$selinux_state" == "Enforcing" ]]; then
      pass "selinux" "Enforcing"
    else
      fail "selinux" "$selinux_state; expected Enforcing"
    fi
  else
    warn "selinux" "not enforced; current state is $selinux_state"
  fi
else
  if is_true "$REQUIRE_SELINUX"; then
    fail "selinux" "getenforce not found"
  else
    warn "selinux" "getenforce not found"
  fi
fi

for service in chronyd auditd firewalld; do
  if service_active "$service"; then
    pass "service $service" "active"
  else
    rc=$?
    if [[ "$rc" -eq 2 ]]; then
      fail "service $service" "systemctl unavailable"
    else
      fail "service $service" "not active"
    fi
  fi
done

if command -v timedatectl >/dev/null 2>&1; then
  if timedatectl show -p NTPSynchronized --value 2>/dev/null | grep -x true >/dev/null; then
    pass "time sync" "NTP synchronized"
  else
    fail "time sync" "NTP is not synchronized"
  fi
else
  warn "time sync" "timedatectl unavailable"
fi

if [[ -d /etc/rancher/rke2 || -x /usr/local/bin/rke2 || -x /var/lib/rancher/rke2/bin/rke2 ]]; then
  pass "rke2 footprint" "RKE2 files detected"
else
  warn "rke2 footprint" "RKE2 not detected yet; acceptable before platform install"
fi

printf '\nResult: %s failure(s), %s warning(s)\n' "$failures" "$warnings"
if [[ "$failures" -gt 0 ]]; then
  exit 1
fi
