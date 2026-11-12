#!/usr/bin/env bash
# =============================================================================
# Chronicle Docker Container Runtime Security Audit
# =============================================================================
# Inspects running Chronicle containers for security misconfigurations:
#   - Non-root users, dropped capabilities, read-only filesystems
#   - Privilege escalation prevention, volume mount hygiene
#   - PID/network namespace isolation, memory limits
#
# Usage:
#   ./tests/security/container-security-tests.sh
#
# Requires: docker CLI access, Chronicle stack running (docker-compose -p chronicle)
# =============================================================================
set -euo pipefail

PASS=0
FAIL=0
WARN=0
SKIP=0

# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------
log()  { echo -e "\033[1;34m[AUDIT]\033[0m $*"; }
pass() { echo -e "  \033[1;32m[PASS]\033[0m $*"; PASS=$((PASS + 1)); }
fail() { echo -e "  \033[1;31m[FAIL]\033[0m $*"; FAIL=$((FAIL + 1)); }
warn() { echo -e "  \033[1;33m[WARN]\033[0m $*"; WARN=$((WARN + 1)); }
skip() { echo -e "  \033[1;33m[SKIP]\033[0m $*"; SKIP=$((SKIP + 1)); }
info() { echo -e "  \033[0;36m[INFO]\033[0m $*"; }

# ---------------------------------------------------------------------------
# Discover containers belonging to the chronicle compose project
# ---------------------------------------------------------------------------
COMPOSE_PROJECT="${COMPOSE_PROJECT:-chronicle}"
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
source "$ROOT_DIR/tests/security/lib/selfhost-python.sh"

mapfile -t CONTAINERS < <(
  docker ps --filter "label=com.docker.compose.project=${COMPOSE_PROJECT}" \
    --format '{{.Names}}' 2>/dev/null
)

if [ "${#CONTAINERS[@]}" -eq 0 ]; then
  echo "No running containers found for compose project '${COMPOSE_PROJECT}'."
  echo "Start the stack first:  docker compose -p chronicle up -d"
  exit 1
fi

echo ""
log "Chronicle Container Runtime Security Audit"
log "Containers discovered: ${CONTAINERS[*]}"
echo ""

# Pre-fetch all container inspect data in a single docker call
# (replaces N*8 individual docker inspect calls with one batch call)
_INSPECT_JSON=$(docker inspect "${CONTAINERS[@]}" 2>/dev/null || echo "[]")
eval "$(echo "$_INSPECT_JSON" | selfhost_python -c "
import json, sys, shlex
from chronicle_ops.common import WRITABLE_ROOT_REASON_LABEL
data = json.load(sys.stdin)
for c in data:
    name = c.get('Name','').lstrip('/')
    user = c.get('Config',{}).get('User','')
    cap_drop = ' '.join(c.get('HostConfig',{}).get('CapDrop') or [])
    cap_add = ' '.join(c.get('HostConfig',{}).get('CapAdd') or [])
    sec_opts = ' '.join(c.get('HostConfig',{}).get('SecurityOpt') or [])
    readonly_rootfs = str(c.get('HostConfig',{}).get('ReadonlyRootfs', False)).lower()
    writable_reason = (c.get('Config', {}).get('Labels') or {}).get(WRITABLE_ROOT_REASON_LABEL, '')
    pid_mode = c.get('HostConfig',{}).get('PidMode','')
    net_mode = c.get('HostConfig',{}).get('NetworkMode','')
    mem = c.get('HostConfig',{}).get('Memory', 0) or 0
    mounts = json.dumps(c.get('Mounts',[]))
    safe = name.replace('-','_')
    print(f'declare -- _user_{safe}={shlex.quote(user)}')
    print(f'declare -- _capdrop_{safe}={shlex.quote(cap_drop)}')
    print(f'declare -- _capadd_{safe}={shlex.quote(cap_add)}')
    print(f'declare -- _secopt_{safe}={shlex.quote(sec_opts)}')
    print(f'declare -- _readonly_{safe}={shlex.quote(readonly_rootfs)}')
    print(f'declare -- _writable_reason_{safe}={shlex.quote(writable_reason)}')
    print(f'declare -- _pidmode_{safe}={shlex.quote(pid_mode)}')
    print(f'declare -- _netmode_{safe}={shlex.quote(net_mode)}')
    print(f'declare -- _mem_{safe}={shlex.quote(str(mem))}')
    print(f'declare -- _mounts_{safe}={shlex.quote(mounts)}')
" 2>/dev/null)" 2>/dev/null || true
unset _INSPECT_JSON

_cget() {
  local var="_${1}_${2//-/_}"
  echo "${!var:-}"
}

# Classify containers -------------------------------------------------------
APP_CONTAINERS=()
for c in "${CONTAINERS[@]}"; do
  case "$c" in
    *backend*|*frontend*) APP_CONTAINERS+=("$c") ;;
  esac
done

# Helper: check if a container name matches a pattern
is_app_container() {
  local name="$1"
  case "$name" in
    *backend*|*frontend*) return 0 ;;
  esac
  return 1
}

is_monitoring_container() {
  local name="$1"
  case "$name" in
    *prometheus*|*grafana*|*loki*|*promtail*|*falco*) return 0 ;;
  esac
  return 1
}

# =============================================================================
# Test 1: Non-Root User Audit
# =============================================================================
log "Test 1: Non-Root User Audit"
for container in "${CONTAINERS[@]}"; do
  if ! is_app_container "$container"; then
    continue
  fi
  user=$(_cget user "$container")
  # Docker accepts USER as either a name/UID or a user:group pair. Treat every
  # root spelling as root so a runtime privilege drop is actually verified.
  if [[ -z "$user" || "$user" == "root" || "$user" == "root:"* || "$user" == "0" || "$user" == "0:"* ]]; then
    # Check PID 1's actual user (handles su-exec/gosu privilege drop patterns)
    pid1_user=$(docker exec "$container" sh -c 'stat -c "%U" /proc/1/exe 2>/dev/null || ps -o user= -p 1 2>/dev/null | tr -d " "' 2>/dev/null || echo "")
    if [ -n "$pid1_user" ] && [ "$pid1_user" != "root" ] && [ "$pid1_user" != "0" ]; then
      pass "$container — PID 1 runs as '${pid1_user}' (su-exec privilege drop)"
    else
      cap_drop=$(_cget capdrop "$container")
      no_new_priv=$(_cget secopt "$container")
      if echo "$cap_drop" | grep "ALL" >/dev/null && echo "$no_new_priv" | grep "no-new-privileges" >/dev/null; then
        warn "$container — runs as root but has cap_drop:ALL + no-new-privileges (hardened)"
      else
        fail "$container — runs as root or no user specified (User='${user:-<empty>}')"
      fi
    fi
  else
    pass "$container — runs as non-root user '${user}'"
  fi
done

# =============================================================================
# Test 2: Capability Audit
# =============================================================================
echo ""
log "Test 2: Linux Capability Audit"
for container in "${CONTAINERS[@]}"; do
  cap_add=$(_cget capadd "$container")
  # Normalize: docker returns [] or <nil> or [CAP1 CAP2]
  if [ -z "$cap_add" ] || [ "$cap_add" = "[]" ] || [ "$cap_add" = "<nil>" ]; then
    pass "$container — no added capabilities"
  else
    # Check exceptions
    case "$container" in
      *postgres*)
        info "$container — added capabilities: ${cap_add} (database — may be expected)"
        ;;
      *vault*)
        if echo "$cap_add" | grep "IPC_LOCK" >/dev/null; then
          pass "$container — IPC_LOCK capability (expected for Vault)"
        else
          warn "$container — unexpected capabilities: ${cap_add}"
        fi
        ;;
      *fail2ban*)
        if echo "$cap_add" | grep -E "NET_ADMIN|NET_RAW" >/dev/null; then
          pass "$container — NET_ADMIN/NET_RAW capabilities (expected for fail2ban)"
        else
          warn "$container — unexpected capabilities: ${cap_add}"
        fi
        ;;
      *backend*)
        # Backend needs SETUID/SETGID (su-exec privilege drop) + CHOWN/DAC_OVERRIDE (config ownership)
        cap_drop=$(_cget capdrop "$container")
        if echo "$cap_drop" | grep "ALL" >/dev/null; then
          pass "$container — minimal caps with cap_drop: ALL (su-exec: ${cap_add})"
        else
          warn "$container — has capabilities without cap_drop: ALL: ${cap_add}"
        fi
        ;;
      *frontend*)
        # nginx needs minimal caps to bind port 80 and manage workers
        cap_drop=$(_cget capdrop "$container")
        if echo "$cap_drop" | grep "ALL" >/dev/null; then
          pass "$container — nginx caps with cap_drop: ALL (hardened: ${cap_add})"
        else
          warn "$container — has capabilities without cap_drop: ALL: ${cap_add}"
        fi
        ;;
      *)
        if is_app_container "$container"; then
          fail "$container — has added capabilities: ${cap_add}"
        else
          warn "$container — has added capabilities: ${cap_add}"
        fi
        ;;
    esac
  fi
done

# =============================================================================
# Test 3: Read-Only Root Filesystem
# =============================================================================
echo ""
log "Test 3: Read-Only Root Filesystem"
for container in "${CONTAINERS[@]}"; do
  readonly_rootfs=$(_cget readonly "$container")
  if [ "$readonly_rootfs" = "true" ]; then
    pass "$container — read-only root filesystem"
  else
    reason=$(_cget writable_reason "$container")
    if [[ -n "${reason//[[:space:]]/}" ]]; then
      warn "$container — writable root exemption: $reason"
    else
      fail "$container — root filesystem is writable without a justified exemption"
    fi
  fi
done

# =============================================================================
# Test 4: No New Privileges
# =============================================================================
echo ""
log "Test 4: No New Privileges Flag"
for container in "${CONTAINERS[@]}"; do
  sec_opts=$(_cget secopt "$container")
  if echo "$sec_opts" | grep -E "no-new-privileges(:true)?" >/dev/null; then
    pass "$container — no-new-privileges is set"
  else
    warn "$container — no-new-privileges not set (SecurityOpt='${sec_opts}')"
  fi
done

# =============================================================================
# Test 5: Volume Mount Audit
# =============================================================================
echo ""
log "Test 5: Volume Mount Audit"

SENSITIVE_PATHS=("/" "/etc" "/var/run/docker.sock")

for container in "${CONTAINERS[@]}"; do
  mounts_json=$(_cget mounts "$container")
  if [ -z "$mounts_json" ] || [ "$mounts_json" = "null" ] || [ "$mounts_json" = "[]" ]; then
    info "$container — no volume mounts"
    continue
  fi

  # Check for Docker socket mount
  has_docker_sock=false
  docker_sock_ro=false
  if echo "$mounts_json" | grep "docker.sock" >/dev/null; then
    has_docker_sock=true
    if echo "$mounts_json" | python3 -c "
import json, sys
mounts = json.loads(sys.stdin.read())
for m in mounts:
    src = m.get('Source', '')
    if 'docker.sock' in src:
        if m.get('RW', True):
            sys.exit(1)
sys.exit(0)
" 2>/dev/null; then
      docker_sock_ro=true
    fi
  fi

  if $has_docker_sock; then
    if is_app_container "$container"; then
      fail "$container — Docker socket mounted in app container!"
    elif is_monitoring_container "$container"; then
      if $docker_sock_ro; then
        pass "$container — Docker socket mounted read-only (monitoring — acceptable)"
      else
        warn "$container — Docker socket mounted read-write in monitoring container"
      fi
    else
      warn "$container — Docker socket mounted"
    fi
  fi

  # Check for sensitive host path mounts that are writable
  for spath in "${SENSITIVE_PATHS[@]}"; do
    # Skip docker.sock (handled above)
    [ "$spath" = "/var/run/docker.sock" ] && continue

    echo "$mounts_json" | python3 -c "
import json, sys
mounts = json.loads(sys.stdin.read())
target = '${spath}'
for m in mounts:
    src = m.get('Source', '')
    # Exact match for / or /etc (avoid matching /etc/ssl which is fine)
    if target == '/':
        if src == '/':
            rw = m.get('RW', True)
            if rw:
                print('WRITABLE_ROOT')
                sys.exit(0)
    elif src == target:
        rw = m.get('RW', True)
        if rw:
            print('WRITABLE')
            sys.exit(0)
" 2>/dev/null | while read -r result; do
      if [ "$result" = "WRITABLE_ROOT" ]; then
        fail "$container — host root (/) mounted writable!"
      elif [ "$result" = "WRITABLE" ]; then
        fail "$container — sensitive path '${spath}' mounted writable!"
      fi
    done
  done

  # If no issues found for this container, report pass
  if is_app_container "$container" && ! $has_docker_sock; then
    pass "$container — no Docker socket or dangerous host mounts"
  fi
done

# =============================================================================
# Test 6: PID Namespace Isolation
# =============================================================================
echo ""
log "Test 6: PID Namespace Isolation"
for container in "${CONTAINERS[@]}"; do
  pid_mode=$(_cget pidmode "$container")
  if [ "$pid_mode" = "host" ]; then
    if is_app_container "$container"; then
      fail "$container — uses host PID namespace"
    else
      warn "$container — uses host PID namespace"
    fi
  else
    pass "$container — PID namespace isolated (mode='${pid_mode:-default}')"
  fi
done

# =============================================================================
# Test 7: Network Mode
# =============================================================================
echo ""
log "Test 7: Network Mode"
for container in "${CONTAINERS[@]}"; do
  net_mode=$(_cget netmode "$container")
  if [ "$net_mode" = "host" ]; then
    case "$container" in
      *fail2ban*)
        pass "$container — host networking (expected for fail2ban)"
        ;;
      *)
        if is_app_container "$container"; then
          fail "$container — uses host networking"
        else
          warn "$container — uses host networking"
        fi
        ;;
    esac
  else
    pass "$container — network mode '${net_mode}'"
  fi
done

# =============================================================================
# Test 8: Memory Limits
# =============================================================================
echo ""
log "Test 8: Memory Limits"
for container in "${CONTAINERS[@]}"; do
  mem_limit=$(_cget mem "$container")
  if [ -z "$mem_limit" ] || [ "$mem_limit" = "0" ]; then
    warn "$container — no memory limit set (unlimited)"
  else
    # Convert bytes to MB for readability
    mem_mb=$(( mem_limit / 1048576 ))
    pass "$container — memory limit set (${mem_mb} MB)"
  fi
done

# =============================================================================
# Test 9: Process Headroom
# =============================================================================
# Go runtimes and HAProxy start about one thread per host CPU. On a 32-CPU host the 2026.11.2
# Grafana used 509 of its 512 pids, its health-check exec could not start and it stayed
# unhealthy; a service that needs most of its pids limit at idle fails on a larger host.
echo ""
log "Test 9: Process Headroom"
for container in "${CONTAINERS[@]}"; do
  pids_limit=$(docker inspect --format '{{.HostConfig.PidsLimit}}' "$container" 2>/dev/null || echo "")
  pids_used=$(docker stats --no-stream --format '{{.PIDs}}' "$container" 2>/dev/null || echo "")
  if [[ ! "$pids_limit" =~ ^[0-9]+$ ]] || [ "$pids_limit" -le 0 ]; then
    warn "$container — no pids limit set"
  elif [[ ! "$pids_used" =~ ^[0-9]+$ ]]; then
    fail "$container — could not read its process count"
  elif [ $((pids_used * 2)) -gt "$pids_limit" ]; then
    fail "$container — uses ${pids_used} of ${pids_limit} pids at idle on $(nproc 2>/dev/null || sysctl -n hw.ncpu) CPUs"
  else
    pass "$container — ${pids_used} of ${pids_limit} pids"
  fi
done

# =============================================================================
# Summary
# =============================================================================
echo ""
echo "=============================================="
echo "  CONTAINER SECURITY AUDIT SUMMARY"
echo "=============================================="
echo -e "  \033[32mPassed:\033[0m  $PASS"
echo -e "  \033[31mFailed:\033[0m  $FAIL"
echo -e "  \033[33mWarned:\033[0m  $WARN"
echo -e "  \033[33mSkipped:\033[0m $SKIP"
echo "=============================================="
echo ""

if [ "$FAIL" -gt 0 ]; then
  echo "Review failed checks above and harden container configurations."
  exit 1
fi
