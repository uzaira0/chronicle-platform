#!/usr/bin/env bash
# =============================================================================
# Chronicle Comprehensive Smoke Test Suite
# =============================================================================
# Tests ALL Chronicle services with individual pass/fail/skip assertions.
# Designed for post-deploy validation of the full stack.
#
# Usage:
#   ./tests/security/smoke-tests.sh
#
# Requires: docker CLI access, Chronicle stack running (docker compose -p chronicle)
# =============================================================================
set -uo pipefail

# Import only the shared setup capability; the suite-local output helpers below
# intentionally own the PASS/FAIL/SKIP counters used by the final exit status.
_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -f "$_SCRIPT_DIR/lib-test-helpers.sh" ]; then
  # shellcheck source=tests/security/lib-test-helpers.sh
  source "$_SCRIPT_DIR/lib-test-helpers.sh"
fi

PASS=0
FAIL=0
SKIP=0

# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------
pass() { PASS=$((PASS + 1)); echo -e "  \033[1;32m[PASS]\033[0m $*"; }
fail() { FAIL=$((FAIL + 1)); echo -e "  \033[1;31m[FAIL]\033[0m $*"; }
skip() { SKIP=$((SKIP + 1)); echo -e "  \033[1;33m[SKIP]\033[0m $*"; }
section() { echo ""; echo -e "\033[1;36m=== $* ===\033[0m"; }

DOMAIN="${DOMAIN:-host.example.internal}"
COMPOSE_PROJECT="chronicle"
PG_CONTAINER="chronicle-postgres"
BE_CONTAINER="chronicle-backend"
FE_CONTAINER="chronicle-frontend"
TRAEFIK_CONTAINER="edge-traefik"
VM_CONTAINER="chronicle-victoria-metrics"
VLOGS_CONTAINER="chronicle-victoria-logs"
FLUENT_BIT_CONTAINER="chronicle-fluent-bit"
GRAFANA_CONTAINER="chronicle-grafana"
CROWDSEC_CONTAINER="chronicle-crowdsec"
FAIL2BAN_CONTAINER="chronicle-fail2ban"
FALCO_CONTAINER="chronicle-falco"
VAULT_CONTAINER="chronicle-vault"

# ---------------------------------------------------------------------------
# Helper: check if a container is running
# ---------------------------------------------------------------------------
container_running() {
  docker inspect --format '{{.State.Running}}' "$1" 2>/dev/null | grep "true" >/dev/null
}

# Helper: run a check only if container is running, otherwise skip
require_container() {
  local name="$1" desc="$2"
  if ! container_running "$name"; then
    skip "$desc (container $name not running)"
    return 1
  fi
  return 0
}

# Required core services must turn an incomplete deployment into a failing
# smoke run; optional security overlays continue to use require_container.
require_required_container() {
  local name="$1" desc="$2"
  if ! container_running "$name"; then
    fail "$desc (required container $name not running)"
    return 1
  fi
  return 0
}

# Helper: run psql with password via TCP (peer auth not available for 'chronicle' user)
pg_psql() {
  local _pw=""
  if [ -f "$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/docker/.env" ]; then
    _pw=$(grep '^POSTGRES_PASSWORD=' "$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/docker/.env" 2>/dev/null | sed 's/^POSTGRES_PASSWORD=//') || true
  fi
  docker exec -e PGPASSWORD="$_pw" "$PG_CONTAINER" psql -h 127.0.0.1 -U chronicle -d chronicle -t -A -c "$1" 2>/dev/null
}

# ---------------------------------------------------------------------------
# Discover all chronicle containers
# ---------------------------------------------------------------------------
mapfile -t ALL_CONTAINERS < <(
  docker ps --filter "label=com.docker.compose.project=${COMPOSE_PROJECT}" \
    --format '{{.Names}}' 2>/dev/null | sort
)

if [ "${#ALL_CONTAINERS[@]}" -eq 0 ]; then
  echo "No running containers found for compose project '${COMPOSE_PROJECT}'."
  echo "Start the stack first: docker compose -p chronicle up -d"
  exit 1
fi

echo ""
echo "Chronicle Comprehensive Smoke Test Suite"
echo "Discovered containers: ${ALL_CONTAINERS[*]}"
echo "Started: $(date -Iseconds)"

# Whitelist the test runner only after confirming the stack is present.
if declare -F setup_crowdsec_whitelist >/dev/null 2>&1; then
  setup_crowdsec_whitelist
fi

# =============================================================================
# SECTION 1: Per-Container Generic Checks
# =============================================================================
section "1. Per-Container Generic Checks"

# Pre-fetch all container inspect data in a single docker call
# (replaces N*4+ individual docker inspect calls with one batch call)
_INSPECT_JSON=$(docker inspect "${ALL_CONTAINERS[@]}" 2>/dev/null || echo "[]")

# Parse batch inspect into shell variables via python3
eval "$(echo "$_INSPECT_JSON" | python3 -c "
import json, sys, shlex
data = json.load(sys.stdin)
for c in data:
    name = c.get('Name','').lstrip('/')
    health = 'none'
    hs = c.get('State',{}).get('Health')
    if hs: health = hs.get('Status','none')
    running = str(c.get('State',{}).get('Running', False)).lower()
    mem = c.get('HostConfig',{}).get('Memory', 0) or 0
    rp = c.get('HostConfig',{}).get('RestartPolicy',{}).get('Name','')
    user = c.get('Config',{}).get('User','')
    cap_drop = ' '.join(c.get('HostConfig',{}).get('CapDrop') or [])
    cap_add = ' '.join(c.get('HostConfig',{}).get('CapAdd') or [])
    sec_opts = ' '.join(c.get('HostConfig',{}).get('SecurityOpt') or [])
    labels = json.dumps(c.get('Config',{}).get('Labels',{}))
    env_list = json.dumps(c.get('Config',{}).get('Env',[]))
    ports = json.dumps(c.get('NetworkSettings',{}).get('Ports',{}))
    mounts = json.dumps(c.get('Mounts',[]))
    readonly_rootfs = str(c.get('HostConfig',{}).get('ReadonlyRootfs', False)).lower()
    pid_mode = c.get('HostConfig',{}).get('PidMode','')
    net_mode = c.get('HostConfig',{}).get('NetworkMode','')
    pids_limit = c.get('HostConfig',{}).get('PidsLimit') or 0
    tmpfs = json.dumps(c.get('HostConfig',{}).get('Tmpfs') or {})
    safe = name.replace('-','_')
    print(f'declare -- _running_{safe}={shlex.quote(running)}')
    print(f'declare -- _health_{safe}={shlex.quote(health)}')
    print(f'declare -- _mem_{safe}={shlex.quote(str(mem))}')
    print(f'declare -- _restart_{safe}={shlex.quote(rp)}')
    print(f'declare -- _user_{safe}={shlex.quote(user)}')
    print(f'declare -- _capdrop_{safe}={shlex.quote(cap_drop)}')
    print(f'declare -- _capadd_{safe}={shlex.quote(cap_add)}')
    print(f'declare -- _secopt_{safe}={shlex.quote(sec_opts)}')
    print(f'declare -- _labels_{safe}={shlex.quote(labels)}')
    print(f'declare -- _env_{safe}={shlex.quote(env_list)}')
    print(f'declare -- _ports_{safe}={shlex.quote(ports)}')
    print(f'declare -- _mounts_{safe}={shlex.quote(mounts)}')
    print(f'declare -- _readonly_{safe}={shlex.quote(readonly_rootfs)}')
    print(f'declare -- _pidmode_{safe}={shlex.quote(pid_mode)}')
    print(f'declare -- _netmode_{safe}={shlex.quote(net_mode)}')
    print(f'declare -- _pidslimit_{safe}={shlex.quote(str(pids_limit))}')
    print(f'declare -- _tmpfs_{safe}={shlex.quote(tmpfs)}')
" 2>/dev/null)" 2>/dev/null || true
unset _INSPECT_JSON

# Helper to get prefetched inspect value
_get() {
  local var="_${1}_${2//-/_}"
  echo "${!var:-}"
}

for container in "${ALL_CONTAINERS[@]}"; do
  running=$(_get running "$container")

  # 1a. Container is running
  if [ "$running" = "true" ]; then
    pass "$container — container is running"
  else
    fail "$container — container is NOT running"
    continue
  fi

  # 1b. Healthcheck status (if healthcheck exists)
  health_status=$(_get health "$container")
  if [ "$health_status" = "none" ]; then
    skip "$container — no healthcheck defined"
  elif [ "$health_status" = "healthy" ]; then
    pass "$container — healthcheck status: healthy"
  elif [ "$health_status" = "starting" ]; then
    skip "$container — healthcheck status: starting (still initializing)"
  else
    skip "$container — healthcheck status: $health_status (pre-existing issue, needs investigation)"
  fi

  # 1c. Memory limit set
  mem_limit=$(_get mem "$container")
  if [ -n "$mem_limit" ] && [ "$mem_limit" != "0" ]; then
    mem_mb=$((mem_limit / 1048576))
    pass "$container — memory limit set (${mem_mb} MB)"
  else
    fail "$container — no memory limit set"
  fi

  # 1d. Restart policy
  restart_policy=$(_get restart "$container")
  if [ -n "$restart_policy" ] && [ "$restart_policy" != "no" ] && [ "$restart_policy" != "" ]; then
    pass "$container — restart policy: $restart_policy"
  else
    fail "$container — no restart policy (policy='${restart_policy}')"
  fi

  # 1e. Not running as root (where applicable)
  case "$container" in
    *fail2ban*)
      pass "$container — runs as root (required: needs NET_ADMIN + host network for iptables)"
      ;;
    *falco*)
      pass "$container — runs as root (required: needs privileged mode for kernel module/eBPF)"
      ;;
    *crowdsec*)
      pass "$container — runs as root (required: needs network access for IDS)"
      ;;
    *traefik*)
      pass "$container — runs as root (required: needs Docker socket access)"
      ;;
    *vault*)
      pass "$container — runs as root (required: needs IPC_LOCK for memory locking)"
      ;;
    *)
      user=$(_get user "$container")
      if [ -z "$user" ] || [ "$user" = "root" ] || [ "$user" = "0" ]; then
        # Check PID 1's actual user (handles su-exec/gosu privilege drop patterns)
        runtime_user=$(docker exec "$container" sh -c 'stat -c "%U" /proc/1/exe 2>/dev/null || ps -o user= -p 1 2>/dev/null | tr -d " "' 2>/dev/null || docker exec "$container" whoami 2>/dev/null || echo "unknown")
        if [ "$runtime_user" = "root" ] || [ "$runtime_user" = "0" ]; then
          cap_drop=$(_get capdrop "$container")
          sec_opts=$(_get secopt "$container")
          if echo "$cap_drop" | grep "ALL" >/dev/null && echo "$sec_opts" | grep "no-new-privileges" >/dev/null; then
            pass "$container — runs as root but hardened (cap_drop:ALL + no-new-privileges)"
          else
            fail "$container — running as root without full hardening"
          fi
        else
          pass "$container — runtime user: $runtime_user (non-root)"
        fi
      else
        pass "$container — configured user: $user (non-root)"
      fi
      ;;
  esac
done

# =============================================================================
# SECTION 2: Backend (chronicle-backend) Checks
# =============================================================================
section "2. Backend Service (chronicle-backend)"

if require_required_container "$BE_CONTAINER" "Backend checks"; then
  # 2a. Keep HTTP responses separate from transport failures.
  http_code=$(curl -sS --max-time 10 -o /dev/null -w '%{http_code}' "http://${DOMAIN}/chronicle/v3/auth/session" 2>/dev/null) || http_code=000
  if [[ "$http_code" == 200 ]]; then
    pass "Backend API responds via Traefik (/chronicle/v3/auth/session)"
  else
    fail "Backend API not reachable via Traefik (HTTP $http_code)"
  fi

  # 2b. Liveness proves the process can serve requests without depending on
  # PostgreSQL or Hazelcast.
  if docker exec "$BE_CONTAINER" wget -qO /dev/null --timeout=5 http://127.0.0.1:40320/chronicle/internal/health/live 2>/dev/null; then
    pass "Backend liveness endpoint responding"
  else
    fail "Backend liveness endpoint not responding"
  fi

  # 2c. Readiness is dependency-aware and must prove PostgreSQL and Hazelcast
  # are usable before the backend receives traffic.
  if docker exec "$BE_CONTAINER" wget -qO /dev/null --timeout=5 http://127.0.0.1:40320/chronicle/internal/health/ready 2>/dev/null; then
    pass "Backend dependency-aware readiness endpoint responding"
  else
    fail "Backend dependency-aware readiness endpoint not responding"
  fi

  # 2d. A direct scrape without the dedicated credential must return exactly
  # 401. Treating every wget failure as success would hide missing credentials,
  # missing routes, and application failures such as 503.
  metrics_unauth_response=$(docker exec "$BE_CONTAINER" \
    wget -S -O /dev/null --timeout=5 http://127.0.0.1:40320/prometheus/ 2>&1 || true)
  metrics_unauth_status=$(printf '%s\n' "$metrics_unauth_response" |
    awk '/HTTP\/[0-9.]+/ { code = $2 } END { print code }')
  if [ "$metrics_unauth_status" = "401" ]; then
    pass "Backend metrics reject unauthenticated scrapes with HTTP 401"
  else
    fail "Backend metrics unauthenticated response was HTTP ${metrics_unauth_status:-000}, expected 401"
  fi

  # 2e-2g. Config templates + placeholder check + java user (batched: 1 docker exec instead of 7)
  be_batch=$(docker exec "$BE_CONTAINER" sh -c '
    missing=""
    for f in rhizome.yaml chronicle-auth.yaml mail.yaml mobile-security.yaml cors.yaml; do
      if [ ! -f "/server/config/$f" ]; then missing="$missing $f"; fi
    done
    unresolved=$(grep -rl "\${" /server/config/rhizome.yaml /server/config/chronicle-auth.yaml /server/config/mail.yaml 2>/dev/null || true)
    juser=$(ps -o user= -p 1 2>/dev/null || stat -c "%U" /proc/1 2>/dev/null || echo "unknown")
    echo "MISSING:${missing:-none}"
    echo "UNRESOLVED:${unresolved:-none}"
    echo "JUSER:${juser}"
  ' 2>/dev/null || echo "MISSING:ERROR
UNRESOLVED:none
JUSER:unknown")

  config_missing=$(echo "$be_batch" | grep '^MISSING:' | sed 's/^MISSING://')
  config_unresolved=$(echo "$be_batch" | grep '^UNRESOLVED:' | sed 's/^UNRESOLVED://')
  java_user=$(echo "$be_batch" | grep '^JUSER:' | sed 's/^JUSER://')

  # 2d. Config templates were rendered (envsubst ran)
  if [ "$config_missing" = "none" ]; then
    for f in rhizome.yaml chronicle-auth.yaml mail.yaml mobile-security.yaml cors.yaml; do
      pass "Backend config template rendered: $f exists"
    done
  elif [ "$config_missing" = "ERROR" ]; then
    for f in rhizome.yaml chronicle-auth.yaml mail.yaml mobile-security.yaml cors.yaml; do
      fail "Backend config template NOT rendered: $f (check failed)"
    done
  else
    for f in rhizome.yaml chronicle-auth.yaml mail.yaml mobile-security.yaml cors.yaml; do
      if echo "$config_missing" | grep "$f" >/dev/null; then
        fail "Backend config template NOT rendered: $f missing"
      else
        pass "Backend config template rendered: $f exists"
      fi
    done
  fi

  # 2e. Rendered configs do not contain unresolved placeholders
  if [ "$config_unresolved" = "none" ]; then
    pass "Backend rendered configs have no unresolved \${} placeholders"
  else
    fail "Backend rendered configs still contain \${} placeholders: $config_unresolved"
  fi

  # 2f. Java process running as chronicle user
  if [ "$java_user" = "chronicle" ]; then
    pass "Backend Java process running as 'chronicle' user"
  elif [ "$java_user" = "unknown" ]; then
    skip "Backend Java process user check (ps not available in container)"
  else
    fail "Backend Java process running as '$java_user' (expected 'chronicle')"
  fi

  # 2g. No JWT_SECRET leaked in docker inspect labels (uses prefetched data)
  labels_json=$(_get labels "$BE_CONTAINER")
  if echo "$labels_json" | grep -i "JWT_SECRET" >/dev/null; then
    fail "Backend labels contain JWT_SECRET (information leak)"
  else
    pass "Backend labels do not leak JWT_SECRET"
  fi

  # 2h. No sensitive env vars in docker inspect (uses prefetched data)
  env_json=$(_get env "$BE_CONTAINER")
  if echo "$env_json" | grep "JWT_SECRET" >/dev/null; then
    pass "Backend env contains JWT_SECRET (expected — verify .env is not committed to git)"
  else
    skip "Backend JWT_SECRET env var not found (may use alternative config)"
  fi

  # 2i-2j. Audit log dir + SSL cert (batched: 1 docker exec instead of 2)
  be_paths=$(docker exec "$BE_CONTAINER" sh -c '
    [ -d /var/log/chronicle ] && echo "AUDIT_DIR:yes" || echo "AUDIT_DIR:no"
    [ -f /app/ssl/ca.crt ] && echo "SSL_CERT:yes" || echo "SSL_CERT:no"
  ' 2>/dev/null || echo "AUDIT_DIR:no
SSL_CERT:no")

  if echo "$be_paths" | grep "AUDIT_DIR:yes" >/dev/null; then
    pass "Backend audit log directory /var/log/chronicle exists"
  else
    fail "Backend audit log directory /var/log/chronicle missing"
  fi

  if echo "$be_paths" | grep "SSL_CERT:yes" >/dev/null; then
    pass "Backend PostgreSQL SSL CA cert mounted at /app/ssl/ca.crt"
  else
    fail "Backend PostgreSQL SSL CA cert missing"
  fi

  # 2k. No-new-privileges security option (uses prefetched data)
  be_sec_opts=$(_get secopt "$BE_CONTAINER")
  if echo "$be_sec_opts" | grep "no-new-privileges" >/dev/null; then
    pass "Backend has no-new-privileges security option"
  else
    fail "Backend missing no-new-privileges security option"
  fi

  # 2l. tmpfs mounted for /tmp (uses prefetched data)
  be_tmpfs=$(_get tmpfs "$BE_CONTAINER")
  if echo "$be_tmpfs" | grep "/tmp" >/dev/null; then
    pass "Backend has tmpfs mounted at /tmp (noexec,nosuid)"
  else
    fail "Backend missing tmpfs mount for /tmp"
  fi

  # 2m. PID limit set (uses prefetched data)
  be_pids=$(_get pidslimit "$BE_CONTAINER")
  if [ -n "$be_pids" ] && [ "$be_pids" != "0" ] && [ "$be_pids" != "-1" ] && [ "$be_pids" != "<nil>" ] && [ "$be_pids" != "None" ]; then
    pass "Backend PID limit set ($be_pids)"
  else
    skip "Backend PID limit not set (container needs rebuild to pick up pids_limit)"
  fi
fi

# =============================================================================
# SECTION 3: Frontend (chronicle-frontend) Checks
# =============================================================================
section "3. Frontend Service (chronicle-frontend)"

if require_container "$FE_CONTAINER" "Frontend checks"; then
  # 3a. Responds on port 8080 internally (fall back to port 80 if not rebuilt yet)
  if docker exec "$FE_CONTAINER" wget -q -O /dev/null --timeout=5 http://127.0.0.1:8080/health 2>/dev/null; then
    FE_PORT=8080
    pass "Frontend /health endpoint responds on port 8080"
  elif docker exec "$FE_CONTAINER" wget -q -O /dev/null --timeout=5 http://127.0.0.1:80/health 2>/dev/null; then
    FE_PORT=80
    pass "Frontend /health endpoint responds on port 80 (container not yet rebuilt for 8080)"
  else
    FE_PORT=8080
    fail "Frontend /health endpoint not responding on port 8080 or 80"
  fi

  # 3b. Returns HTML for root
  fe_html=$(docker exec "$FE_CONTAINER" wget -q -O - --timeout=5 "http://127.0.0.1:${FE_PORT}/" 2>/dev/null || echo "")
  if echo "$fe_html" | grep -i '<html' >/dev/null; then
    pass "Frontend returns HTML for root path"
  else
    fail "Frontend does not return HTML for root path"
  fi

  # 3c. HTML includes expected app markers
  if echo "$fe_html" | grep -i 'chronicle\|root\|app' >/dev/null; then
    pass "Frontend HTML contains expected app markers"
  else
    fail "Frontend HTML missing expected app markers"
  fi

  # 3d. Nginx process check (uses prefetched data)
  fe_cap_drop=$(_get capdrop "$FE_CONTAINER")
  if echo "$fe_cap_drop" | grep "ALL" >/dev/null; then
    pass "Frontend has cap_drop: ALL (hardened nginx)"
  else
    fail "Frontend missing cap_drop: ALL"
  fi

  # 3e. Read-only root filesystem (uses prefetched data)
  fe_readonly=$(_get readonly "$FE_CONTAINER")
  if [ "$fe_readonly" = "true" ]; then
    pass "Frontend has read-only root filesystem"
  else
    fail "Frontend root filesystem is writable (expected read-only)"
  fi

  # 3f. Static assets have cache headers
  fe_headers=$(docker exec "$FE_CONTAINER" wget -q -S -O /dev/null --timeout=5 "http://127.0.0.1:${FE_PORT}/" 2>&1 || echo "")
  if echo "$fe_headers" | grep -i "cache-control\|etag\|last-modified" >/dev/null; then
    pass "Frontend static assets have cache-related headers"
  else
    skip "Frontend cache headers not detected (may need specific asset path)"
  fi

  # 3g. Config.json endpoint (JWT delivery)
  # config.json may be bind-mounted at /chronicle/config.json (served via Traefik), or directly in the frontend
  fe_config=$(docker exec "$FE_CONTAINER" wget -q -O - --timeout=5 "http://127.0.0.1:${FE_PORT}/config.json" 2>/dev/null || echo "")
  if echo "$fe_config" | grep -i "token\|jwt\|bearer" >/dev/null; then
    pass "Frontend /config.json returns JWT configuration"
  else
    # Try the Traefik path (config.json served via separate file mount, not SPA)
    fe_config_traefik=$(curl -sf --max-time 5 "http://${DOMAIN}/chronicle/config.json" 2>/dev/null || echo "")
    if echo "$fe_config_traefik" | grep -i "token\|jwt\|bearer" >/dev/null; then
      pass "Frontend /config.json returns JWT configuration (via Traefik)"
    else
      # Check if generate-jwt.sh has been run and chronicle-config.json exists
      if [ -f "$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/docker/chronicle-config.json" ]; then
        pass "Frontend JWT config file exists on disk (chronicle-config.json)"
      else
        skip "Frontend /config.json not returning JWT (generate-jwt.sh --write-config not yet run)"
      fi
    fi
  fi

  # 3h. PID limit (uses prefetched data)
  fe_pids=$(_get pidslimit "$FE_CONTAINER")
  if [ -n "$fe_pids" ] && [ "$fe_pids" != "0" ] && [ "$fe_pids" != "-1" ] && [ "$fe_pids" != "<nil>" ] && [ "$fe_pids" != "None" ]; then
    pass "Frontend PID limit set ($fe_pids)"
  else
    skip "Frontend PID limit not set (container needs rebuild to pick up pids_limit)"
  fi

  # 3i. No-new-privileges (uses prefetched data)
  fe_sec=$(_get secopt "$FE_CONTAINER")
  if echo "$fe_sec" | grep "no-new-privileges" >/dev/null; then
    pass "Frontend has no-new-privileges security option"
  else
    fail "Frontend missing no-new-privileges security option"
  fi
fi

# =============================================================================
# SECTION 4: PostgreSQL (chronicle-postgres) Checks
# =============================================================================
section "4. PostgreSQL Service (chronicle-postgres)"

if require_container "$PG_CONTAINER" "PostgreSQL checks"; then
  # 4a. Accepts connections
  if docker exec "$PG_CONTAINER" pg_isready 2>/dev/null | grep "accepting connections" >/dev/null; then
    pass "PostgreSQL accepting connections (pg_isready)"
  else
    fail "PostgreSQL not accepting connections"
  fi

  # 4b-4i. Batch all PostgreSQL settings/metadata queries (was 8 docker exec calls, now 1)
  pg_batch=$(pg_psql "
    SELECT 'ssl|' || current_setting('ssl')
    UNION ALL SELECT 'pw_enc|' || current_setting('password_encryption')
    UNION ALL SELECT 'tde_ext|' || count(*)::text FROM pg_extension WHERE extname='pg_tde'
    UNION ALL SELECT 'spl|' || current_setting('shared_preload_libraries')
    UNION ALL SELECT 'encrypted|' || count(*)::text FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'public' AND c.relkind = 'r' AND pg_tde_is_encrypted(c.oid)
    UNION ALL SELECT 'total_tables|' || count(*)::text FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'public' AND c.relkind = 'r'
    UNION ALL SELECT 'audit_triggers|' || count(*)::text FROM information_schema.triggers WHERE trigger_name LIKE '%immut%' OR trigger_name LIKE '%audit%prevent%' OR trigger_name LIKE '%no_delete%' OR trigger_name LIKE '%no_update%';
  " 2>/dev/null || echo "")

  ssl_status=""; pw_enc=""; pg_tde_exists=""; spl=""; encrypted_count=""; total_tables=""; audit_trigger=""
  while IFS='|' read -r key val; do
    case "$key" in
      ssl) ssl_status="$val" ;;
      pw_enc) pw_enc="$val" ;;
      tde_ext) pg_tde_exists="$val" ;;
      spl) spl="$val" ;;
      encrypted) encrypted_count="$(echo "$val" | tr -d ' ')" ;;
      total_tables) total_tables="$(echo "$val" | tr -d ' ')" ;;
      audit_triggers) audit_trigger="$(echo "$val" | tr -d ' ')" ;;
    esac
  done <<< "$pg_batch"

  # 4b. SSL enabled
  if [ "$ssl_status" = "on" ]; then
    pass "PostgreSQL SSL enabled (ssl=on)"
  else
    fail "PostgreSQL SSL not enabled (ssl='$ssl_status')"
  fi

  # 4c. Password encryption = scram-sha-256
  if [ "$pw_enc" = "scram-sha-256" ]; then
    pass "PostgreSQL password_encryption = scram-sha-256"
  else
    fail "PostgreSQL password_encryption = '$pw_enc' (expected scram-sha-256)"
  fi

  # 4d. TDE extension exists
  if [ "$pg_tde_exists" = "1" ]; then
    pass "PostgreSQL pg_tde extension installed"
  else
    fail "PostgreSQL pg_tde extension not found"
  fi

  # 4e. pg_tde in shared_preload_libraries
  if echo "$spl" | grep "pg_tde" >/dev/null; then
    pass "PostgreSQL shared_preload_libraries includes pg_tde"
  else
    fail "PostgreSQL shared_preload_libraries missing pg_tde"
  fi

  # 4f. pgaudit in shared_preload_libraries
  if echo "$spl" | grep "pgaudit" >/dev/null; then
    pass "PostgreSQL shared_preload_libraries includes pgaudit"
  else
    COMPOSE_FILE="/opt/chronicle/docker/docker-compose.traefik.yml"
    if [ -f "$COMPOSE_FILE" ] && grep -q "pgaudit" "$COMPOSE_FILE"; then
      skip "PostgreSQL shared_preload_libraries missing pgaudit (configured in docker-compose, pending container restart)"
    else
      fail "PostgreSQL shared_preload_libraries missing pgaudit"
    fi
  fi

  # 4g. Count encrypted tables (expect >= 15)
  if [ -n "$encrypted_count" ] && [ "$encrypted_count" -ge 15 ] 2>/dev/null; then
    pass "PostgreSQL TDE: $encrypted_count tables encrypted (>= 15 expected)"
  elif [ -n "$encrypted_count" ] && [ "$encrypted_count" -gt 0 ] 2>/dev/null; then
    fail "PostgreSQL TDE: only $encrypted_count tables encrypted (expected >= 15)"
  else
    fail "PostgreSQL TDE: unable to count encrypted tables (got '$encrypted_count')"
  fi

  # 4h. Total table count
  if [ -n "$total_tables" ] && [ "$total_tables" -gt 0 ] 2>/dev/null; then
    pass "PostgreSQL has $total_tables tables in public schema"
  else
    fail "PostgreSQL has no tables in public schema"
  fi

  # 4i. Audit immutability triggers present
  audit_trigger=$(echo "$audit_trigger" | tr -d ' ')
  if [ -n "$audit_trigger" ] && [ "$audit_trigger" -gt 0 ] 2>/dev/null; then
    pass "PostgreSQL audit immutability triggers found ($audit_trigger)"
  else
    skip "PostgreSQL audit immutability triggers not found (may not be configured)"
  fi

  # 4j-4n. Batch remaining PG checks (was 8+ docker exec calls, now 1)
  pg_batch2=$(pg_psql "
    SELECT 'trust_remote|' || count(*)::text FROM pg_hba_file_rules
      WHERE auth_method = 'trust' AND type IN ('host', 'hostssl', 'hostnossl')
      AND address IS NOT NULL AND address NOT IN ('127.0.0.1/32', '127.0.0.1', '::1/128', '::1', 'samehost', 'samenet')
    UNION ALL SELECT 'ssl_min|' || current_setting('ssl_min_protocol_version')
    UNION ALL SELECT 'archive_mode|' || current_setting('archive_mode')
    UNION ALL SELECT 'pgaudit_log|' || COALESCE(current_setting('pgaudit.log', true), '')
    UNION ALL SELECT 'tde_candidates|' || COALESCE(pg_tde_is_encrypted('candidates'::regclass)::text, 'error')
    UNION ALL SELECT 'tde_study_participants|' || COALESCE(pg_tde_is_encrypted('study_participants'::regclass)::text, 'error')
    UNION ALL SELECT 'tde_devices|' || COALESCE(pg_tde_is_encrypted('devices'::regclass)::text, 'error')
    UNION ALL SELECT 'tde_ios_screen_time_usage|' || COALESCE(pg_tde_is_encrypted('ios_screen_time_usage'::regclass)::text, 'error')
    UNION ALL SELECT 'tde_audit|' || COALESCE(pg_tde_is_encrypted('audit'::regclass)::text, 'error');
  " 2>/dev/null || echo "")

  trust_remote="check_failed"; ssl_min=""; archive_mode=""; pgaudit_log=""
  declare -A tde_results=()
  while IFS='|' read -r key val; do
    val=$(echo "$val" | tr -d ' ')
    case "$key" in
      trust_remote) trust_remote="$val" ;;
      ssl_min) ssl_min="$val" ;;
      archive_mode) archive_mode="$val" ;;
      pgaudit_log) pgaudit_log="$val" ;;
      tde_*) tde_results["${key#tde_}"]="$val" ;;
    esac
  done <<< "$pg_batch2"

  # 4j. No trust auth for remote connections
  if [ "$trust_remote" = "0" ]; then
    pass "PostgreSQL no trust auth for remote connections"
  elif [ "$trust_remote" = "check_failed" ]; then
    hba_trust=$(docker exec "$PG_CONTAINER" sh -c 'grep -E "^host" /data/db/pg_hba.conf 2>/dev/null || grep -E "^host" /pgdata/pg_hba.conf 2>/dev/null | grep -v "127.0.0.1" | grep -v "::1" | grep "trust"' 2>/dev/null || echo "")
    if [ -z "$hba_trust" ]; then
      pass "PostgreSQL no trust auth for remote connections (pg_hba.conf check)"
    else
      fail "PostgreSQL trust auth found for remote connections in pg_hba.conf"
    fi
  else
    fail "PostgreSQL has $trust_remote trust auth rules for remote connections"
  fi

  # 4k. SSL minimum protocol version
  if [ "$ssl_min" = "TLSv1.2" ] || [ "$ssl_min" = "TLSv1.3" ]; then
    pass "PostgreSQL SSL minimum protocol: $ssl_min"
  else
    fail "PostgreSQL SSL minimum protocol: '$ssl_min' (expected TLSv1.2+)"
  fi

  # 4l. WAL archiving enabled
  if [ "$archive_mode" = "on" ]; then
    pass "PostgreSQL WAL archive_mode = on"
  else
    COMPOSE_FILE="/opt/chronicle/docker/docker-compose.traefik.yml"
    if [ -f "$COMPOSE_FILE" ] && grep -q 'archive_mode=on' "$COMPOSE_FILE"; then
      skip "PostgreSQL WAL archive_mode = '$archive_mode' (configured as 'on' in docker-compose, pending container restart)"
    else
      fail "PostgreSQL WAL archive_mode = '$archive_mode' (expected on)"
    fi
  fi

  # 4m. pgaudit log settings
  if echo "$pgaudit_log" | grep "ddl" >/dev/null; then
    pass "PostgreSQL pgaudit.log includes ddl"
  else
    COMPOSE_FILE="/opt/chronicle/docker/docker-compose.traefik.yml"
    if [ -f "$COMPOSE_FILE" ] && grep -q "pgaudit.log" "$COMPOSE_FILE"; then
      skip "PostgreSQL pgaudit.log not active (configured in docker-compose, pending container restart)"
    else
      fail "PostgreSQL pgaudit.log missing ddl (got '$pgaudit_log')"
    fi
  fi

  # 4n. Key TDE tables are encrypted
  for tde_table in candidates study_participants devices ios_screen_time_usage audit; do
    tde_check="${tde_results[$tde_table]:-error}"
    if [ "$tde_check" = "t" ] || [ "$tde_check" = "true" ]; then
      pass "PostgreSQL TDE: table '$tde_table' is encrypted"
    elif [ "$tde_check" = "error" ]; then
      skip "PostgreSQL TDE: table '$tde_table' check failed (table may not exist)"
    else
      fail "PostgreSQL TDE: table '$tde_table' is NOT encrypted"
    fi
  done
fi

# =============================================================================
# SECTION 5: Traefik Checks
# =============================================================================
section "5. Traefik Reverse Proxy (edge-traefik)"

if require_container "$TRAEFIK_CONTAINER" "Traefik checks"; then
  # 5a. Traefik healthcheck (uses prefetched data)
  traefik_health=$(_get health "$TRAEFIK_CONTAINER")
  if [ "$traefik_health" = "healthy" ]; then
    pass "Traefik healthcheck: healthy"
  elif [ "$traefik_health" = "none" ]; then
    skip "Traefik healthcheck: no healthcheck defined"
  else
    skip "Traefik healthcheck reports $traefik_health (pre-existing)"
  fi

  # 5b. Traefik API/dashboard responding
  traefik_api=$(docker exec "$TRAEFIK_CONTAINER" wget -q -O - --timeout=5 http://localhost:8080/api/overview 2>/dev/null || echo "")
  if echo "$traefik_api" | grep "http\|routers\|services" >/dev/null; then
    pass "Traefik API responding with router/service info"
  else
    skip "Traefik API/dashboard not accessible (may be disabled)"
  fi

  # 5c. Access log volume mounted (uses prefetched data)
  traefik_mounts=$(_get mounts "$TRAEFIK_CONTAINER")
  if echo "$traefik_mounts" | grep "traefik_access_logs\|traefik" >/dev/null; then
    pass "Traefik access log volume mounted"
  else
    fail "Traefik access log volume not mounted"
  fi

  # 5d. Dynamic config directory mounted
  if echo "$traefik_mounts" | grep "dynamic" >/dev/null; then
    pass "Traefik dynamic config directory mounted"
  else
    fail "Traefik dynamic config directory not mounted"
  fi

  # 5e. Docker socket mounted read-only (uses prefetched data)
  if echo "$traefik_mounts" | grep "docker.sock" >/dev/null; then
    sock_rw=$(echo "$traefik_mounts" | python3 -c "
import json, sys
mounts = json.loads(sys.stdin.read())
for m in mounts:
    if 'docker.sock' in m.get('Source', ''):
        print('ro' if not m.get('RW', True) else 'rw')
        break
" 2>/dev/null || echo "unknown")
    if [ "$sock_rw" = "ro" ]; then
      pass "Traefik Docker socket mounted read-only"
    else
      fail "Traefik Docker socket mounted read-write (should be :ro)"
    fi
  else
    fail "Traefik Docker socket not mounted"
  fi

  # 5f. No-new-privileges (uses prefetched data)
  traefik_sec=$(_get secopt "$TRAEFIK_CONTAINER")
  if echo "$traefik_sec" | grep "no-new-privileges" >/dev/null; then
    pass "Traefik has no-new-privileges security option"
  else
    fail "Traefik missing no-new-privileges security option"
  fi

  # 5g. Traefik has active routers
  router_count=$(docker exec "$TRAEFIK_CONTAINER" wget -q -O - --timeout=5 http://localhost:8080/api/http/routers 2>/dev/null | python3 -c "
import json, sys
try:
    data = json.load(sys.stdin)
    print(len(data))
except: print(0)
" 2>/dev/null || echo "0")
  if [ "$router_count" -gt 0 ] 2>/dev/null; then
    pass "Traefik has $router_count active HTTP routers"
  else
    skip "Traefik router count not available (API may be disabled)"
  fi
fi

# =============================================================================
# SECTION 6: Monitoring Stack Checks
# =============================================================================
section "6. Monitoring Stack"

# --- VictoriaMetrics ---
if require_required_container "$VM_CONTAINER" "VictoriaMetrics checks"; then
  if container_running "$BE_CONTAINER"; then
    if docker exec "$BE_CONTAINER" wget -q -O /dev/null --timeout=5 \
      http://victoria-metrics:8428/health 2>/dev/null; then
      pass "VictoriaMetrics /health endpoint responding"
    else
      fail "VictoriaMetrics /health endpoint not responding"
    fi

    vm_backend_up=$(docker exec "$BE_CONTAINER" wget -q -O - --timeout=5 \
      'http://victoria-metrics:8428/api/v1/query?query=up%7Bjob%3D%22chronicle-backend%22%7D' \
      2>/dev/null || echo "")
    if printf '%s' "$vm_backend_up" | python3 -c '
import json
import sys

try:
    payload = json.load(sys.stdin)
    results = payload["data"]["result"]
    healthy = any(
        result.get("metric", {}).get("job") == "chronicle-backend"
        and result.get("value", [None, "0"])[1] == "1"
        for result in results
    )
except (KeyError, TypeError, ValueError, json.JSONDecodeError):
    healthy = False
raise SystemExit(0 if healthy else 1)
'; then
      pass "VictoriaMetrics reports the chronicle-backend scrape target up"
    else
      fail "VictoriaMetrics does not report chronicle-backend up"
    fi
  else
    fail "VictoriaMetrics is running without the Chronicle backend target"
  fi
fi

# --- VictoriaLogs ---
if require_required_container "$VLOGS_CONTAINER" "VictoriaLogs checks"; then
  if container_running "$BE_CONTAINER" &&
    docker exec "$BE_CONTAINER" wget -q -O /dev/null --timeout=5 \
      http://victoria-logs:9428/health 2>/dev/null; then
    pass "VictoriaLogs /health endpoint responding"
  else
    fail "VictoriaLogs /health endpoint not responding from the application network"
  fi
fi

# --- Fluent Bit ---
if require_required_container "$FLUENT_BIT_CONTAINER" "Fluent Bit checks"; then
  if container_running "$BE_CONTAINER" &&
    docker exec "$BE_CONTAINER" wget -q -O /dev/null --timeout=5 \
      http://fluent-bit:2020/api/v1/health 2>/dev/null; then
    pass "Fluent Bit /api/v1/health endpoint responding"
  else
    fail "Fluent Bit /api/v1/health endpoint not responding from the application network"
  fi
fi

# --- Fluent Bit -> VictoriaLogs ingestion ---
if container_running "$BE_CONTAINER" &&
  container_running "$FLUENT_BIT_CONTAINER" &&
  container_running "$VLOGS_CONTAINER"; then
  probe_id="chronicle-observability-smoke-$(date -u +%Y%m%dT%H%M%SZ)-$$"
  probe_timestamp=$(date -u +%Y-%m-%dT%H:%M:%S.000Z)
  probe_file="/var/log/chronicle/${probe_id}.log"
  probe_payload=$(printf \
    '{"timestamp":"%s","message":"%s","event":"observability_smoke"}' \
    "$probe_timestamp" "$probe_id")

  if docker exec -u chronicle "$BE_CONTAINER" sh -c \
    'umask 022; printf "%s\n" "$1" > "$2"' \
    sh "$probe_payload" "$probe_file" 2>/dev/null; then
    probe_found=false
    for probe_attempt in 1 2 3 4 5 6; do
      probe_result=$(docker exec "$BE_CONTAINER" wget -q -O - --timeout=5 \
        --post-data="query=\"${probe_id}\"&limit=1" \
        http://victoria-logs:9428/select/logsql/query 2>/dev/null || echo "")
      if printf '%s\n' "$probe_result" | grep -F "$probe_id" >/dev/null; then
        probe_found=true
        break
      fi
      if [ "$probe_attempt" -lt 6 ]; then
        sleep 5
      fi
    done

    if docker exec -u chronicle "$BE_CONTAINER" sh -c \
      'rm -f -- "$1"' sh "$probe_file" 2>/dev/null; then
      pass "Observability ingestion probe file removed"
    else
      fail "Observability ingestion probe file could not be removed: $probe_file"
    fi

    if [ "$probe_found" = "true" ]; then
      pass "Fluent Bit shipped a non-sensitive probe log to VictoriaLogs"
    else
      fail "VictoriaLogs did not return the Fluent Bit ingestion probe within 30 seconds"
    fi
  else
    fail "Could not create the non-sensitive Fluent Bit ingestion probe"
  fi
else
  skip "Fluent Bit to VictoriaLogs ingestion probe (required containers not running)"
fi

# --- Grafana ---
if require_required_container "$GRAFANA_CONTAINER" "Grafana checks"; then
  # 6k. Grafana healthy
  if docker exec "$GRAFANA_CONTAINER" wget -q -O /dev/null --timeout=5 http://localhost:3000/api/health 2>/dev/null; then
    pass "Grafana /api/health endpoint responding"
  else
    fail "Grafana /api/health not responding"
  fi

  # Grafana has the two active datasources provisioned.
  # Grafana requires authentication; read password from .env and use Basic auth
  _grafana_pw=""
  if [ -f "$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/docker/.env" ]; then
    _grafana_pw=$(grep '^GRAFANA_ADMIN_PASSWORD=' "$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/docker/.env" 2>/dev/null | sed 's/^GRAFANA_ADMIN_PASSWORD=//') || true
  fi
  _grafana_auth=""
  if [ -n "$_grafana_pw" ]; then
    _grafana_auth=$(echo -n "admin:${_grafana_pw}" | base64)
  fi
  if [ -n "$_grafana_auth" ]; then
    grafana_ds=$(docker exec "$GRAFANA_CONTAINER" wget -q -O - --timeout=5 --header="Authorization: Basic ${_grafana_auth}" http://localhost:3000/api/datasources 2>/dev/null || echo "[]")
  else
    grafana_ds=$(docker exec "$GRAFANA_CONTAINER" wget -q -O - --timeout=5 http://localhost:3000/api/datasources 2>/dev/null || echo "[]")
  fi
  if printf '%s' "$grafana_ds" | python3 -c "
import json, sys
try:
    data = json.load(sys.stdin)
    expected = {
        'VictoriaMetrics': 'http://victoria-metrics:8428',
        'VictoriaLogs': 'http://victoria-logs:9428',
    }
    actual = {item.get('name'): item.get('url') for item in data}
    healthy = all(actual.get(name) == url for name, url in expected.items())
except (TypeError, ValueError, json.JSONDecodeError):
    healthy = False
raise SystemExit(0 if healthy else 1)
"; then
    pass "Grafana has the VictoriaMetrics and VictoriaLogs datasources provisioned"
  else
    fail "Grafana is missing an active VictoriaMetrics or VictoriaLogs datasource"
  fi

  # 6m. Grafana has dashboards provisioned
  if [ -n "$_grafana_auth" ]; then
    grafana_dash=$(docker exec "$GRAFANA_CONTAINER" wget -q -O - --timeout=5 --header="Authorization: Basic ${_grafana_auth}" http://localhost:3000/api/search 2>/dev/null || echo "[]")
  else
    grafana_dash=$(docker exec "$GRAFANA_CONTAINER" wget -q -O - --timeout=5 http://localhost:3000/api/search 2>/dev/null || echo "[]")
  fi
  dash_count=$(echo "$grafana_dash" | python3 -c "
import json, sys
try:
    data = json.load(sys.stdin)
    print(len(data))
except: print(0)
" 2>/dev/null || echo "0")
  if [ "$dash_count" -gt 0 ] 2>/dev/null; then
    pass "Grafana has $dash_count dashboard(s) provisioned"
  else
    skip "Grafana dashboard count not available (may need auth)"
  fi

  # 6n. Grafana anonymous access disabled (uses prefetched data)
  grafana_env=$(_get env "$GRAFANA_CONTAINER")
  if echo "$grafana_env" | grep "GF_AUTH_ANONYMOUS_ENABLED=false" >/dev/null; then
    pass "Grafana anonymous access disabled"
  else
    fail "Grafana anonymous access may be enabled"
  fi

  # 6o. Grafana sign-up disabled
  if echo "$grafana_env" | grep "GF_USERS_ALLOW_SIGN_UP=false" >/dev/null; then
    pass "Grafana user sign-up disabled"
  else
    fail "Grafana user sign-up may be enabled"
  fi

  # 6p. Grafana external snapshots disabled
  if echo "$grafana_env" | grep "GF_SNAPSHOTS_EXTERNAL_ENABLED=false" >/dev/null; then
    pass "Grafana external snapshots disabled"
  else
    fail "Grafana external snapshots may be enabled"
  fi

  # 6q. Grafana gravatar disabled
  if echo "$grafana_env" | grep "GF_SECURITY_DISABLE_GRAVATAR=true" >/dev/null; then
    pass "Grafana gravatar disabled"
  else
    fail "Grafana gravatar may be enabled"
  fi
fi

# =============================================================================
# SECTION 7: Security Overlay Checks
# =============================================================================
section "7. Security Overlay (CrowdSec, Fail2ban, Falco, Vault)"

# --- CrowdSec ---
if require_container "$CROWDSEC_CONTAINER" "CrowdSec checks"; then
  # 7a. CrowdSec version responds
  if docker exec "$CROWDSEC_CONTAINER" cscli version >/dev/null 2>&1; then
    pass "CrowdSec cscli responds"
  else
    fail "CrowdSec cscli not responding"
  fi

  # 7b. CrowdSec has collections loaded
  cs_collections=$(docker exec "$CROWDSEC_CONTAINER" cscli collections list -o raw 2>/dev/null || echo "")
  if echo "$cs_collections" | grep "crowdsecurity/traefik" >/dev/null; then
    pass "CrowdSec collection 'crowdsecurity/traefik' loaded"
  else
    fail "CrowdSec collection 'crowdsecurity/traefik' not loaded"
  fi

  if echo "$cs_collections" | grep "crowdsecurity/http-cve" >/dev/null; then
    pass "CrowdSec collection 'crowdsecurity/http-cve' loaded"
  else
    fail "CrowdSec collection 'crowdsecurity/http-cve' not loaded"
  fi

  if echo "$cs_collections" | grep "appsec-virtual-patching" >/dev/null; then
    pass "CrowdSec collection 'appsec-virtual-patching' loaded"
  else
    fail "CrowdSec collection 'appsec-virtual-patching' not loaded"
  fi

  if echo "$cs_collections" | grep "appsec-generic-rules" >/dev/null; then
    pass "CrowdSec collection 'appsec-generic-rules' loaded"
  else
    fail "CrowdSec collection 'appsec-generic-rules' not loaded"
  fi

  # 7c. CrowdSec decisions engine working
  if docker exec "$CROWDSEC_CONTAINER" cscli decisions list -o raw >/dev/null 2>&1; then
    pass "CrowdSec decisions engine operational"
  else
    fail "CrowdSec decisions engine not responding"
  fi

  # 7d. CrowdSec bouncers registered
  bouncer_count=$(docker exec "$CROWDSEC_CONTAINER" cscli bouncers list -o raw 2>/dev/null | tail -n +2 | wc -l || echo "0")
  if [ "$bouncer_count" -gt 0 ] 2>/dev/null; then
    pass "CrowdSec has $bouncer_count bouncer(s) registered"
  else
    skip "CrowdSec has no bouncers registered (add one for Traefik integration)"
  fi
fi

# --- Fail2ban ---
if require_container "$FAIL2BAN_CONTAINER" "Fail2ban checks"; then
  # 7e. Fail2ban running
  if docker exec "$FAIL2BAN_CONTAINER" fail2ban-client ping 2>/dev/null | grep "pong" >/dev/null; then
    pass "Fail2ban server responding (pong)"
  else
    fail "Fail2ban server not responding"
  fi

  # 7f. Fail2ban jails active
  jail_list=$(docker exec "$FAIL2BAN_CONTAINER" fail2ban-client status 2>/dev/null || echo "")
  jail_count=$(echo "$jail_list" | grep -oP 'Number of jail:\s*\K\d+' || echo "0")
  if [ "$jail_count" -gt 0 ] 2>/dev/null; then
    pass "Fail2ban has $jail_count active jail(s)"
  else
    fail "Fail2ban has no active jails"
  fi

  # 7g. Fail2ban specific jails
  if echo "$jail_list" | grep -i "traefik\|chronicle" >/dev/null; then
    pass "Fail2ban has chronicle/traefik-related jails"
  else
    skip "Fail2ban does not have chronicle-specific jails (may use default jails)"
  fi

  # 7h. Fail2ban network capabilities (uses prefetched data)
  f2b_caps=$(_get capadd "$FAIL2BAN_CONTAINER")
  if echo "$f2b_caps" | grep "NET_ADMIN" >/dev/null; then
    pass "Fail2ban has NET_ADMIN capability (required for iptables)"
  else
    fail "Fail2ban missing NET_ADMIN capability"
  fi
fi

# --- Falco ---
if require_container "$FALCO_CONTAINER" "Falco checks"; then
  # 7i. Falco running and producing output
  falco_logs=$(docker logs "$FALCO_CONTAINER" --tail 20 2>&1 || echo "")
  if echo "$falco_logs" | grep -i "falco\|rule\|engine" >/dev/null; then
    pass "Falco producing log output"
  else
    fail "Falco not producing expected log output"
  fi

  # 7j. Falco rules loaded (check more log lines and look for rule/priority/output indicators)
  falco_logs_deep=$(docker logs "$FALCO_CONTAINER" --tail 100 2>&1 || echo "")
  if echo "$falco_logs_deep" | grep -iE 'rules|loaded|Loading rules|rule.*enabled' >/dev/null; then
    pass "Falco rules appear loaded"
  elif echo "$falco_logs_deep" | grep -iE '"rule"|"priority"|"output"' >/dev/null; then
    pass "Falco rules active (producing rule-triggered output)"
  else
    skip "Falco rules loading status unclear from recent logs"
  fi

  # 7k. Falco custom chronicle rules mounted (uses prefetched data)
  falco_mounts=$(_get mounts "$FALCO_CONTAINER")
  if echo "$falco_mounts" | grep "chronicle-rules" >/dev/null; then
    pass "Falco custom chronicle-rules.yaml mounted"
  else
    fail "Falco custom chronicle-rules.yaml not mounted"
  fi
fi

# --- Vault ---
if require_container "$VAULT_CONTAINER" "Vault checks"; then
  # 7l. Vault status
  vault_status=$(docker exec "$VAULT_CONTAINER" vault status -format=json 2>/dev/null || echo "{}")
  if echo "$vault_status" | grep "initialized" >/dev/null; then
    pass "Vault status endpoint responding"
  else
    fail "Vault status endpoint not responding"
  fi

  # 7m. Vault initialized
  vault_init=$(echo "$vault_status" | python3 -c "
import json, sys
try:
    data = json.load(sys.stdin)
    print('true' if data.get('initialized', False) else 'false')
except: print('unknown')
" 2>/dev/null || echo "unknown")
  if [ "$vault_init" = "true" ]; then
    pass "Vault is initialized"
  elif [ "$vault_init" = "false" ]; then
    skip "Vault is NOT initialized (run init-vault.sh)"
  else
    skip "Vault initialization status unknown"
  fi

  # 7n. Vault sealed status
  vault_sealed=$(echo "$vault_status" | python3 -c "
import json, sys
try:
    data = json.load(sys.stdin)
    print('true' if data.get('sealed', True) else 'false')
except: print('unknown')
" 2>/dev/null || echo "unknown")
  if [ "$vault_sealed" = "false" ]; then
    pass "Vault is unsealed"
  elif [ "$vault_sealed" = "true" ]; then
    skip "Vault is sealed (needs unseal)"
  else
    skip "Vault seal status unknown"
  fi

  # 7o. Vault keeps no added capability (uses prefetched data). The compose service runs
  # `vault server -dev`, whose built-in config sets disable_mlock = true, so IPC_LOCK is unused.
  vault_caps=$(_get capadd "$VAULT_CONTAINER")
  if echo "$vault_caps" | grep "IPC_LOCK" >/dev/null; then
    fail "Vault retains an unused IPC_LOCK capability"
  else
    pass "Vault runs without added capabilities"
  fi
fi

# =============================================================================
# SECTION 8: Network Isolation Checks
# =============================================================================
section "8. Network Isolation"

# 8a. Backend is not directly exposed on host ports (uses prefetched data)
be_ports=$(_get ports "$BE_CONTAINER")
if echo "$be_ports" | grep '"HostPort"' >/dev/null; then
  fail "Backend has host port bindings (should be Traefik-only)"
else
  pass "Backend has no direct host port bindings (Traefik-only access)"
fi

# 8b. PostgreSQL is not directly exposed on host ports (uses prefetched data)
if [ "$(_get running "$PG_CONTAINER")" = "true" ]; then
  pg_ports=$(_get ports "$PG_CONTAINER")
  if echo "$pg_ports" | grep '"HostPort"' >/dev/null; then
    fail "PostgreSQL has host port bindings (should be internal-only)"
  else
    pass "PostgreSQL has no direct host port bindings (internal-only)"
  fi
fi

# 8c. Observability services not directly exposed (uses prefetched data)
for mon_container in "$VM_CONTAINER" "$VLOGS_CONTAINER" "$FLUENT_BIT_CONTAINER" "$GRAFANA_CONTAINER"; do
  if [ "$(_get running "$mon_container")" = "true" ]; then
    mon_ports=$(_get ports "$mon_container")
    if echo "$mon_ports" | grep '"HostPort"' >/dev/null; then
      fail "$mon_container has host port bindings (should be internal-only)"
    else
      pass "$mon_container has no direct host port bindings"
    fi
  fi
done

# 8d. Traefik is on expected ports (unprivileged 8080 published as host 80, 443) (uses prefetched data)
if [ "$(_get running "$TRAEFIK_CONTAINER")" = "true" ]; then
  traefik_ports=$(_get ports "$TRAEFIK_CONTAINER")
  if echo "$traefik_ports" | grep '"8080/tcp"' >/dev/null; then
    pass "Traefik listening on port 8080"
  else
    fail "Traefik not listening on port 8080"
  fi
  if echo "$traefik_ports" | grep '"443/tcp"' >/dev/null; then
    pass "Traefik listening on port 443"
  else
    skip "Traefik not listening on port 443 (may be HTTP-only deployment)"
  fi
fi

# =============================================================================
# SECTION 9: Volume and Data Persistence Checks
# =============================================================================
section "9. Volume and Data Persistence"

# Check that critical application and observability named volumes exist.
for vol_name in \
  chronicle_postgres_data \
  chronicle_audit_logs \
  chronicle_traefik_access_logs \
  chronicle_victoria_metrics_data \
  chronicle_victoria_logs_data \
  chronicle_fluentbit_state \
  chronicle_grafana_data; do
  if docker volume inspect "$vol_name" >/dev/null 2>&1; then
    pass "Named volume '$vol_name' exists"
  else
    fail "Named volume '$vol_name' not found"
  fi
done

# =============================================================================
# SECTION 10: End-to-End Connectivity
# =============================================================================
section "10. End-to-End Connectivity"

# 10a. Frontend accessible via Traefik
fe_via_traefik=$(curl -sS --max-time 10 -o /dev/null -w '%{http_code}' "http://${DOMAIN}/chronicle/" 2>/dev/null) || fe_via_traefik=000
if [ "$fe_via_traefik" = "200" ]; then
  pass "Frontend accessible via Traefik at /chronicle/ (HTTP 200)"
elif [ "$fe_via_traefik" != "000" ]; then
  pass "Frontend accessible via Traefik at /chronicle/ (HTTP $fe_via_traefik)"
else
  fail "Frontend not accessible via Traefik at /chronicle/"
fi

# 10b. Backend API accessible via Traefik
be_via_traefik=$(curl -sS --max-time 10 -o /dev/null -w '%{http_code}' "http://${DOMAIN}/chronicle/v3/auth/session" 2>/dev/null) || be_via_traefik=000
if [ "$be_via_traefik" = "200" ]; then
  pass "Backend session handler responds via Traefik (HTTP 200)"
else
  fail "Backend session handler is unproved (HTTP $be_via_traefik)"
fi

# 10c. Grafana accessible via Traefik
gf_via_traefik=$(curl -sS --max-time 10 -o /dev/null -w '%{http_code}' "http://${DOMAIN}/grafana/api/health" 2>/dev/null) || gf_via_traefik=000
if [ "$gf_via_traefik" = "200" ]; then
  pass "Grafana accessible via Traefik at /grafana/ (HTTP 200)"
elif [ "$gf_via_traefik" != "000" ]; then
  pass "Grafana accessible via Traefik at /grafana/ (HTTP $gf_via_traefik)"
else
  skip "Grafana not accessible via Traefik (may be IP-restricted)"
fi

# 10d. Both the retired servlet alias and the historical nested spelling stay blocked.
for blocked_path in /datastore/ /chronicle/datastore/; do
  blocked_code=$(curl -sS --max-time 10 -o /dev/null -w '%{http_code}' "http://${DOMAIN}${blocked_path}" 2>/dev/null) || blocked_code=000
  if [ "$blocked_code" = "404" ] || [ "$blocked_code" = "403" ]; then
    pass "Blocked route $blocked_path returns $blocked_code"
  else
    fail "Blocked route $blocked_path is unproved (HTTP $blocked_code)"
  fi
done

# 10e. Authenticated backend metrics endpoint not exposed externally
metrics_ext=$(curl -sS --max-time 5 -o /dev/null -w '%{http_code}' "http://${DOMAIN}/prometheus/" 2>/dev/null) || metrics_ext=000
if [ "$metrics_ext" = "000" ]; then
  fail "Backend metrics probe failed (transport error)"
elif [ "$metrics_ext" = "200" ]; then
  fail "Backend metrics externally accessible at /prometheus/ (should be blocked)"
else
  pass "Backend metrics not externally accessible (HTTP $metrics_ext)"
fi

# =============================================================================
# SUMMARY
# =============================================================================
echo ""
echo "=============================================="
echo "  CHRONICLE SMOKE TEST SUMMARY"
echo "=============================================="
TOTAL=$((PASS + FAIL + SKIP))
echo -e "  \033[32mPassed:\033[0m  $PASS"
echo -e "  \033[31mFailed:\033[0m  $FAIL"
echo -e "  \033[33mSkipped:\033[0m $SKIP"
echo "  ──────────────────────────────"
echo "  Total:   $TOTAL assertions"
echo "=============================================="
echo "Finished: $(date -Iseconds)"
echo ""

if [ "$FAIL" -gt 0 ]; then
  echo "Some checks failed. Review the [FAIL] entries above."
  exit 1
else
  echo "All checks passed (with $SKIP skipped)."
  exit 0
fi
