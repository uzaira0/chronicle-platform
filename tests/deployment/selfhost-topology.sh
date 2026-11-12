#!/usr/bin/env bash
set -Eeuo pipefail
# Fixture keys and secrets stay private; the copied bundle keeps its release modes (tar -p below),
# because its containers read it as their own users.
umask 077
ROOT=$(cd "$(dirname "$0")/../.." && pwd -P)
SOURCE=${1:-$ROOT/selfhost}
RUN_PARENT=${TMPDIR:-$ROOT/build}
mkdir -p "$RUN_PARENT"
RUN=$(mktemp -d "$RUN_PARENT/selfhost-topology.XXXXXX")
STACK="$RUN/selfhost"
TOPOLOGY_FIXTURE="$RUN/fixture"
PROJECT="chronicle-topology-$$"
TOPOLOGY_PROJECT="${PROJECT}-clients"
export TOPOLOGY_FIXTURE
CHRONICLE_HOST_UID=$(id -u)
CHRONICLE_HOST_GID=$(id -g)
export CHRONICLE_RECONCILE_ENABLED=false CHRONICLE_HOST_UID CHRONICLE_HOST_GID
mkdir -p "$STACK" "$TOPOLOGY_FIXTURE/lb" "$TOPOLOGY_FIXTURE/client" "$RUN/pki"
tar -C "$SOURCE" --exclude=.env --exclude='.env.*' --exclude='.chronicle-*' --exclude=reconcile.sh --exclude=tls --exclude=backups --exclude=operator-receipts --exclude=upgrade-receipts --exclude='*.lock' --exclude=__pycache__ -cf - . | tar -C "$STACK" -xpf -
cp "$SOURCE/.env.example" "$STACK/.env.example"
# Compose bind-mounts the database role script from the bundle's sibling docker/ directory.
mkdir -p "$RUN/docker"
cp -p "$SOURCE/../docker/init-db-roles.sql" "$RUN/docker/init-db-roles.sql"
cp "$ROOT/tests/deployment/selfhost-topology-lb.cfg" "$TOPOLOGY_FIXTURE/lb/lb.cfg"
cp "$ROOT/tests/deployment/selfhost-topology-lb-start.sh" "$TOPOLOGY_FIXTURE/lb/start.sh"
CLIENT_COMPOSE="$ROOT/tests/deployment/selfhost-topology.compose.yml"
clients() { docker compose -p "$TOPOLOGY_PROJECT" -f "$CLIENT_COMPOSE" "$@"; }
transport_options=()
remote_curl() { clients exec -T "$1" curl "${transport_options[@]}" "${@:2}"; }
host_routes() {
  docker run --rm --network host --user 0 --read-only --cap-drop ALL --cap-add NET_ADMIN \
    --mount type=bind,src=/proc/sys/net/ipv4/conf,dst=/host-ipv4-conf \
    --entrypoint /bin/sh "$caddy_image" -ceu "$1"
}
cleanup() {
  local status=$?
  if [[ -e "$RUN/routes-installed" ]]; then
    host_routes "failed=0;
      ip -4 rule del priority $route_priority 2>/dev/null || true;
      ip -4 rule del priority $((route_priority+1)) 2>/dev/null || true;
      for table in $route_table $((route_table+1)); do ip -4 route flush table \"\$table\" || failed=1; done;
      printf '%s' '$rpf_all' >/host-ipv4-conf/all/rp_filter || failed=1;
      printf '%s' '$rpf_pool' >/host-ipv4-conf/$TOPOLOGY_POOL_BRIDGE/rp_filter || failed=1;
      exit \"\$failed\"" || status=1
  fi
  if (( status != 0 )); then
    # The stack is removed below; keep the reason a one-shot service refused.
    (cd "$STACK" && docker compose -p "$PROJECT" logs --no-color --tail 80 config-guard migrate backend postgres) >&2 2>&1 || true
    clients logs --no-color --tail 40 lb >&2 2>&1 || true
  fi
  # Both projects with their volumes, the anonymous ones of recreated containers included.
  export ROOT_DIR="$ROOT"  # the library's name for the repository root
  # shellcheck source=tests/security/lib/selfhost-python.sh
  source "$ROOT/tests/security/lib/selfhost-python.sh"
  remove_compose_project "$TOPOLOGY_PROJECT" -f "$CLIENT_COMPOSE" >/dev/null 2>&1 || true
  (cd "$STACK" && remove_compose_project "$PROJECT" >/dev/null 2>&1) || true
  printf 'status=%s\n' "$status" >"$RUN/result.txt"
  return "$status"
}
trap cleanup EXIT
# Most checks are bare conditions under errexit; name the one that failed.
trap '[[ $- != *e* ]] || echo "selfhost-topology: line $LINENO failed: $BASH_COMMAND" >&2' ERR
TOPOLOGY_CLIENT_IMAGE=${SELFHOST_SMOKE_BACKUP_IMAGE:-$(sed -n 's/^    image: //p' "$STACK/overlays/backups.yml" | head -1)}
TOPOLOGY_LB_IMAGE=$(sed -n '/image: tecnativa\/docker-socket-proxy/s/^    image: //p' "$STACK/overlays/monitoring.yml")
[[ "$TOPOLOGY_LB_IMAGE" == *@sha256:* ]]
export TOPOLOGY_CLIENT_IMAGE TOPOLOGY_LB_IMAGE
export TOPOLOGY_PUBLIC_PREFIX=${TOPOLOGY_PUBLIC_PREFIX:-10.240.0}
# The ingress admits exactly the product's request ceiling (generated/upload-limits.json).
TOPOLOGY_BODY_LIMIT=${TOPOLOGY_BODY_LIMIT:-$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["MAX_REQUEST_SIZE_BYTES"])' "$ROOT/generated/upload-limits.json")}
export TOPOLOGY_BODY_LIMIT
export TOPOLOGY_POOL_PREFIX=${TOPOLOGY_POOL_PREFIX:-10.241.0}
export TOPOLOGY_VPN_PREFIX=${TOPOLOGY_VPN_PREFIX:-10.242.0}
export TOPOLOGY_PEER_PREFIX=${TOPOLOGY_PEER_PREFIX:-10.243.0}
export TOPOLOGY_PUBLIC_HOST=${TOPOLOGY_PUBLIC_HOST:-chronicle.topology-host.org}
export TOPOLOGY_MANAGEMENT_HOST=${TOPOLOGY_MANAGEMENT_HOST:-dashboard.topology-host.org}
export TOPOLOGY_PUBLIC_PORT=${TOPOLOGY_PUBLIC_PORT:-8443}
export TOPOLOGY_MANAGEMENT_PORT=${TOPOLOGY_MANAGEMENT_PORT:-8444}
export TOPOLOGY_POOL_PORT=${TOPOLOGY_POOL_PORT:-18080}
export TOPOLOGY_INTERNAL_PORT=${TOPOLOGY_INTERNAL_PORT:-18081}
export TOPOLOGY_PUBLIC_BRIDGE="ctpub$$" TOPOLOGY_POOL_BRIDGE="ctpool$$"
export TOPOLOGY_LB_UID=$CHRONICLE_HOST_UID
for prefix in "$TOPOLOGY_PUBLIC_PREFIX" "$TOPOLOGY_POOL_PREFIX" "$TOPOLOGY_VPN_PREFIX" "$TOPOLOGY_PEER_PREFIX"; do
  bash "$STACK/guard-config.sh" --validate-compose-subnet "$prefix.0/24" "$prefix.0/24"
done
bash "$STACK/guard-config.sh" --validate-compose-subnet "${TOPOLOGY_SUBNET:-172.28.0.0/16}" "${TOPOLOGY_SUBNET:-172.28.0.0/16}"
bash "$STACK/guard-config.sh" --validate-public-origin "https://$TOPOLOGY_PUBLIC_HOST:$TOPOLOGY_PUBLIC_PORT"
bash "$STACK/guard-config.sh" --validate-public-origin "https://$TOPOLOGY_MANAGEMENT_HOST:$TOPOLOGY_MANAGEMENT_PORT"
if [[ ${TOPOLOGY_SOURCE_PRESERVING:-false} == true ]]; then
  TOPOLOGY_LB_UID=0
  export TOPOLOGY_TRANSPARENT_CLIENTS=$TOPOLOGY_PUBLIC_PREFIX.0/24
  transport_options=(--ipv4)
  perl -pi -e 's/\n\z/ source 0.0.0.0 usesrc clientip\n/ if /server chronicle /' "$TOPOLOGY_FIXTURE/lb/lb.cfg"
fi
POOL_BIND=$TOPOLOGY_POOL_PREFIX.1
MANAGEMENT_BIND=$TOPOLOGY_VPN_PREFIX.1
export TOPOLOGY_POOL_ENDPOINT="$POOL_BIND:$TOPOLOGY_POOL_PORT"
export TOPOLOGY_MANAGEMENT_ENDPOINT="$MANAGEMENT_BIND:$TOPOLOGY_INTERNAL_PORT"
# shellcheck source=tests/security/lib/fixture-pki.sh
source "$ROOT/tests/security/lib/fixture-pki.sh"
fixture_ca "$RUN/pki" topology-test-CA
fixture_leaf "$RUN/pki" lb "$TOPOLOGY_PUBLIC_HOST"
cat "$RUN/pki/lb.crt" "$RUN/pki/lb.key" >"$TOPOLOGY_FIXTURE/lb/lb.pem"
chmod 640 "$TOPOLOGY_FIXTURE/lb/lb.pem"
chgrp "$CHRONICLE_HOST_GID" "$TOPOLOGY_FIXTURE/lb/lb.pem"
chmod 755 "$TOPOLOGY_FIXTURE" "$STACK"
# The transparent variant runs HAProxy as root without DAC capabilities; it reads through the group.
chmod 750 "$TOPOLOGY_FIXTURE/lb"
chmod 644 "$TOPOLOGY_FIXTURE/lb/lb.cfg" "$TOPOLOGY_FIXTURE/lb/start.sh" "$RUN/pki/ca.crt"
# The load balancer trusts the pool listener's CA, which the stack creates on first start;
# create it now (its networks carry HTTP_BIND) and start it once the CA exists.
clients up --no-start lb
clients up -d phone-a phone-b forbidden
cd "$STACK"
TOPOLOGY_STACK="$STACK" TOPOLOGY_PROJECT_NAME="$PROJECT" POOL_BIND="$POOL_BIND" MANAGEMENT_BIND="$MANAGEMENT_BIND" PYTHONPATH="$STACK" python3 - <<'PY'
import os, secrets, subprocess, sys
from pathlib import Path
from chronicle_ops.envfile import read_env, value, quote_env
from chronicle_ops.credentials import SETUP_SECRETS
raw=read_env('.env.example')
values={key:value(raw,key) for key in raw}
pins={'BACKEND_IMAGE':'SELFHOST_SMOKE_BACKEND_IMAGE','SELFHOST_FRONTEND_IMAGE':'SELFHOST_SMOKE_FRONTEND_IMAGE','CADDY_IMAGE':'SELFHOST_SMOKE_CADDY_IMAGE'}
for key, env in pins.items():
    values[key]=os.environ.get(env) or values[key]
    if '@sha256:' not in values[key]: raise SystemExit('digest-pinned '+key+' is required')
values.update(COMPOSE_PROJECT_NAME=os.environ['TOPOLOGY_PROJECT_NAME'], CHRONICLE_STATE_DIR='.',
    COMPOSE_FILE='docker-compose.yml:overlays/mode-behind-proxy-internal.yml:overlays/backups.yml',
    DOMAIN=os.environ['TOPOLOGY_PUBLIC_HOST'], CHRONICLE_PUBLIC_BASE_URL='https://'+os.environ['TOPOLOGY_PUBLIC_HOST']+':'+os.environ['TOPOLOGY_PUBLIC_PORT'],
    CHRONICLE_SUBNET=os.environ.get('TOPOLOGY_SUBNET','172.28.0.0/16'), HTTP_BIND=os.environ['POOL_BIND'], HTTP_PORT=os.environ['TOPOLOGY_POOL_PORT'],
    INTERNAL_BIND=os.environ['MANAGEMENT_BIND'], INTERNAL_PORT=os.environ['TOPOLOGY_INTERNAL_PORT'], INTERNAL_CERT_SANS='DNS:'+os.environ['TOPOLOGY_MANAGEMENT_HOST'],
    DASHBOARD_BASE_URL='https://'+os.environ['TOPOLOGY_MANAGEMENT_HOST']+':'+os.environ['TOPOLOGY_MANAGEMENT_PORT'], DASHBOARD_ORIGINS='https://'+os.environ['TOPOLOGY_MANAGEMENT_HOST']+':'+os.environ['TOPOLOGY_MANAGEMENT_PORT'],
    DASHBOARD_ALLOWED_IPS=os.environ['TOPOLOGY_VPN_PREFIX']+'.0/24', CADDY_TRUSTED_PROXIES=os.environ['TOPOLOGY_POOL_PREFIX']+'.2/32', POOL_ALLOWED_IPS=os.environ['TOPOLOGY_POOL_PREFIX']+'.2/32',
    POOL_LISTENER_TLS='true', REQUIRE_MFA='false', TESTING_LOGIN_ENABLED='false', CHRONICLE_RECONCILE_ENABLED='false', PUBLIC_HTTP_ENABLED='false',
    BACKUP_STORAGE_ENCRYPTION_WAIVER='isolated synthetic Docker fixture',
    # Retention is the operator's choice; the fixture keeps everything rather than choose a number.
    BACKUP_KEEP_DAYS='all', BACKUP_KEEP_WEEKS='all', BACKUP_KEEP_MONTHS='all', PRE_OP_BACKUP_KEEP_DAYS='all')
# Setup writes the internal core network's prefix; choose it as setup does (./chronicle runs
# network-subnet.py select-core with the edge subnet and project), clear of the networks already on
# this host: the release smoke's own stack runs beside this one.
values['CHRONICLE_CORE_PREFIX']=subprocess.run(
    [sys.executable, 'network-subnet.py', 'select-core', values['CHRONICLE_SUBNET'], os.environ['TOPOLOGY_PROJECT_NAME']],
    check=True, capture_output=True, text=True, timeout=60).stdout.strip()
if os.environ.get('TOPOLOGY_SOURCE_PRESERVING') == 'true':
    sources=' '+os.environ['TOPOLOGY_PUBLIC_PREFIX']+'.0/24'
    for key in ('CADDY_TRUSTED_PROXIES','POOL_ALLOWED_IPS'): values[key]+=sources
for secret in SETUP_SECRETS:
    values[secret.env_key]=secrets.token_urlsafe(32)
Path('.env').write_text('\n'.join(k+'='+quote_env(v) for k,v in values.items())+'\n')
os.chmod('.env',0o600)
PY
# Fixed synthetic password over stdin; credentials never enter process arguments.
caddy_image=$(PYTHONPATH="$STACK" python3 -c 'from chronicle_ops.envfile import read_env, value;print(value(read_env(".env"),"CADDY_IMAGE"))')
if [[ ${TOPOLOGY_SOURCE_PRESERVING:-false} == true ]]; then
  # The original client source needs a return path through HAProxy. Incoming packets
  # from the public client bridge cannot reach the server bridge directly.
  route_priority=$((20000 + $$ % 10000))
  # The helper image's busybox ip accepts table ids up to 255 only; 253-255 are the kernel's.
  route_table=$((100 + $$ % 150))
  stack_subnet=$(PYTHONPATH="$STACK" python3 -c 'from chronicle_ops.envfile import read_env, value;print(value(read_env(".env"),"CHRONICLE_SUBNET"))')
  host_routes "command -v ip; ! ip -4 rule list | grep -E '^($route_priority|$((route_priority+1))):';
    test -z \"\$(ip -4 route show table $route_table 2>/dev/null)\";
    test -z \"\$(ip -4 route show table $((route_table+1)) 2>/dev/null)\""
  rpf_all=$(host_routes 'cat /host-ipv4-conf/all/rp_filter')
  rpf_pool=$(host_routes "cat /host-ipv4-conf/$TOPOLOGY_POOL_BRIDGE/rp_filter")
  [[ "$rpf_all" =~ ^[012]$ && "$rpf_pool" =~ ^[012]$ ]]
  touch "$RUN/routes-installed"
  host_routes "printf 0 >/host-ipv4-conf/all/rp_filter;
    printf 0 >/host-ipv4-conf/$TOPOLOGY_POOL_BRIDGE/rp_filter;
    ip -4 route add blackhole default table $route_table;
    ip -4 route add $TOPOLOGY_PUBLIC_PREFIX.0/24 via $TOPOLOGY_POOL_PREFIX.2 dev $TOPOLOGY_POOL_BRIDGE table $((route_table+1));
    ip -4 rule add priority $route_priority iif $TOPOLOGY_PUBLIC_BRIDGE to $stack_subnet lookup $route_table;
    ip -4 rule add priority $((route_priority+1)) from $stack_subnet to $TOPOLOGY_PUBLIC_PREFIX.0/24 lookup $((route_table+1))"
fi
hash=$(printf '%s\n' 'chronicle-smoke-only-password' | docker run --rm -i --network none --read-only --entrypoint caddy "$caddy_image" hash-password)
printf "DASHBOARD_PASSWORD_HASH='%s'\n" "$hash" >>.env
# The template has an empty hash; replace it, avoiding duplicate assignments.
python3 - <<'PY'
from pathlib import Path
lines=Path('.env').read_text().splitlines(); hashes=[x for x in lines if x.startswith('DASHBOARD_PASSWORD_HASH=')]
Path('.env').write_text('\n'.join(x for x in lines if not x.startswith('DASHBOARD_PASSWORD_HASH='))+'\n'+hashes[-1]+'\n')
PY
docker compose up -d --wait --wait-timeout "${START_WAIT_TIMEOUT_SECONDS:-3600}"
install -m 644 tls/internal-ca.crt "$TOPOLOGY_FIXTURE/lb/pool-ca.crt"
clients up -d lb
sleep 3
cp tls/internal-ca.crt "$TOPOLOGY_FIXTURE/client/dashboard-ca.crt"
cat "$RUN/pki/ca.crt" "$TOPOLOGY_FIXTURE/client/dashboard-ca.crt" >"$TOPOLOGY_FIXTURE/client/client-ca.crt"
chmod 644 "$TOPOLOGY_FIXTURE/client/client-ca.crt"
public=https://$TOPOLOGY_PUBLIC_HOST:$TOPOLOGY_PUBLIC_PORT
management=https://$TOPOLOGY_MANAGEMENT_HOST:$TOPOLOGY_MANAGEMENT_PORT
client_pids=()
for phone in phone-a phone-b; do
  printf '%s\n' 'chronicle-smoke-only-password' | clients exec -T "$phone" python3 /repo/tests/deployment/selfhost-client.py "${transport_options[@]}" --public "$public" --management "$management" --ca /fixture/client-ca.crt --records "/fixture/$phone.json" --transport-recipe "/fixture/$phone-private.json" &
  client_pids+=("$!")
done
for pid in "${client_pids[@]}"; do wait "$pid"; done
for phone in phone-a phone-b; do
  python3 "$ROOT/tests/deployment/selfhost-client.py" --assert-db --project "$PROJECT" --records "$TOPOLOGY_FIXTURE/client/$phone.json"
done
transfer_client() {
  clients exec -T "$1" python3 /repo/tests/deployment/selfhost-client.py "${transport_options[@]}" --ca /fixture/client-ca.crt \
    --records "/fixture/$1.json" --transport-recipe "/fixture/$1-private.json" --transport-replay "${@:2}"
}
browser_pids=()
for phone in phone-a phone-b; do transfer_client "$phone" --browser-burst & browser_pids+=("$!"); done
for pid in "${browser_pids[@]}"; do wait "$pid"; done
# Exercise Caddy's body deadline independently of the LB idle timer: bytes keep arriving.
body_deadline_test_seconds=1
original_read_deadline=$(sed -n 's/^[[:space:]]*read_body //p' "$STACK/caddy/snippets.caddy")
perl -pi -e "s/read_body ${original_read_deadline}/read_body ${body_deadline_test_seconds}s/" "$STACK/caddy/snippets.caddy"
docker compose up -d --force-recreate --wait web
clients exec -T phone-a python3 /repo/tests/deployment/selfhost-client.py "${transport_options[@]}" --public "$public" --management "$management" \
  --ca /fixture/client-ca.crt --records /fixture/phone-a.json --body-deadline-test-seconds "$body_deadline_test_seconds"
perl -pi -e "s/read_body ${body_deadline_test_seconds}s/read_body ${original_read_deadline}/" "$STACK/caddy/snippets.caddy"
docker compose up -d --force-recreate --wait web
TOPOLOGY_IDLE_TIMEOUT=1s clients up -d --force-recreate lb
sleep 3
transfer_client phone-a --idle-failure
TOPOLOGY_IDLE_TIMEOUT=300s clients up -d --force-recreate lb
sleep 3
transfer_client phone-a
python3 "$ROOT/tests/deployment/selfhost-client.py" --assert-db --project "$PROJECT" --records "$TOPOLOGY_FIXTURE/client/phone-a.json"
rm "$TOPOLOGY_FIXTURE/client/phone-a-private.json" "$TOPOLOGY_FIXTURE/client/phone-b-private.json"
# Direct pool access is refused by address; -k because only the load balancer trusts the pool CA.
bypass_code=$(remote_curl phone-a -sk --max-time 5 -o /dev/null -w '%{http_code}' "https://$TOPOLOGY_POOL_ENDPOINT/health" || true)
[[ "$bypass_code" == 403 || "$bypass_code" == 000 ]]
[[ $(remote_curl forbidden -sk --max-time 10 -o /dev/null -w '%{http_code}' "https://$TOPOLOGY_POOL_ENDPOINT/health") == 403 ]]
[[ $(remote_curl forbidden -s --max-time 10 --cacert /fixture/client-ca.crt -o /dev/null -w '%{http_code}' "https://$TOPOLOGY_MANAGEMENT_ENDPOINT/chronicle/") == 403 ]]
remote_curl phone-a --fail --cacert /fixture/client-ca.crt --max-time 10 -D /fixture/headers -o /dev/null -H 'X-Forwarded-For: 198.51.100.66' -H 'X-Forwarded-For: 198.51.100.67' -H 'X-Forwarded-Proto: http, https' "$public/health"
grep -qi '^strict-transport-security:' "$TOPOLOGY_FIXTURE/client/headers"
health_pids=()
for _ in {1..8}; do remote_curl phone-a --fail --cacert /fixture/client-ca.crt --max-time 10 -o /dev/null "$public/health" & health_pids+=("$!"); done
for pid in "${health_pids[@]}"; do wait "$pid"; done
# Fixture CA trust is explicit; unknown roots and wrong names must fail before HTTP.
set +e
remote_curl phone-a -sS --noproxy '*' --max-time 10 "$public/health" >/dev/null 2>&1
unknown_ca_status=$?
remote_curl phone-a -sS --noproxy '*' --cacert /fixture/client-ca.crt --max-time 10 \
  --resolve "wrong.topology.example.org:$TOPOLOGY_PUBLIC_PORT:$TOPOLOGY_PUBLIC_PREFIX.2" "https://wrong.topology.example.org:$TOPOLOGY_PUBLIC_PORT/health" >/dev/null 2>&1
wrong_san_status=$?
set -e
[[ "$unknown_ca_status" == 60 && "$wrong_san_status" == 60 ]]
# Forwarded identity, host, scheme and internal credentials are client-controlled text. None of
# them may open the researcher surface, the pool, or metrics to a client outside the allowlists.
vpn_client=$TOPOLOGY_VPN_PREFIX.10
forged_headers=(-H "X-Forwarded-For: $vpn_client" -H "X-Real-IP: $vpn_client" -H "X-Forwarded-Proto: https"
  -H "Forwarded: for=$vpn_client;host=$TOPOLOGY_MANAGEMENT_HOST;proto=https"
  -H "X-Forwarded-Host: $TOPOLOGY_MANAGEMENT_HOST" -H "X-Original-Forwarded-For: $vpn_client"
  -H "X-Chronicle-Internal-Web: forged-internal-web" -H "Authorization: ChronicleUpdate forged-verifier")
forged_status() { remote_curl "$1" -s --noproxy '*' --max-time 10 -o /dev/null -w '%{http_code}' "${forged_headers[@]}" "${@:2}" || true; }
for path in /chronicle/api/web/study /chronicle/api/web/studies/settings /chronicle/limits/study /prometheus/ /chronicle/datastore/x; do
  for host in "$TOPOLOGY_PUBLIC_HOST" "$TOPOLOGY_MANAGEMENT_HOST"; do
    [[ $(forged_status phone-a --cacert /fixture/client-ca.crt -H "Host: $host" "$public$path") == 404 ]]
  done
done
[[ $(forged_status phone-a --cacert /fixture/client-ca.crt -H 'Content-Type: application/json' -d '{"password":"chronicle-smoke-only-password"}' \
  "$public/chronicle/v3/auth/dashboard-login") == 404 ]]
for path in /chronicle/ /chronicle/api/web/study /chronicle/v3/auth/dashboard-login; do
  [[ $(forged_status forbidden --cacert /fixture/client-ca.crt "https://$TOPOLOGY_MANAGEMENT_ENDPOINT$path") == 403 ]]
done
# The pool admits only the load balancer's socket address, whatever the request claims.
pool_forged=(-H "X-Forwarded-For: $TOPOLOGY_POOL_PREFIX.2" -H "X-Real-IP: $TOPOLOGY_POOL_PREFIX.2")
for path in /health /chronicle/v4/study/00000000-0000-0000-0000-000000000000/participant/forged/android; do
  [[ $(forged_status forbidden -k "${pool_forged[@]}" "https://$TOPOLOGY_POOL_ENDPOINT$path") == 403 ]]
  forged_pool=$(forged_status phone-a -k "${pool_forged[@]}" "https://$TOPOLOGY_POOL_ENDPOINT$path")
  [[ "$forged_pool" == 403 || "$forged_pool" == 000 ]]
done
# Positive control: an allowlisted researcher still reaches the dashboard while naming a forbidden address.
[[ $(remote_curl phone-a -s --noproxy '*' --cacert /fixture/client-ca.crt --max-time 10 -o /dev/null -w '%{http_code}' \
  -H "X-Forwarded-For: $TOPOLOGY_PEER_PREFIX.10" -H "X-Real-IP: $TOPOLOGY_PEER_PREFIX.10" "$management/chronicle/") == 200 ]]
# A body over the ingress limit is rejected before the application sees a valid batch.
clients exec -T phone-a python3 -c 'import sys; open("/fixture/oversized.json","w").write("["+" "*(int(sys.argv[1])-1)+"]")' "$TOPOLOGY_BODY_LIMIT"
[[ $(remote_curl phone-a -s --cacert /fixture/client-ca.crt --max-time 30 -o /dev/null -w '%{http_code}' \
  -H 'Content-Type: application/json' --data-binary @/fixture/oversized.json "$public/chronicle/v4/study/x/upload") == 413 ]]
rm "$TOPOLOGY_FIXTURE/client/oversized.json"
# Expired leaves and missing intermediate chains are rejected by the separate phone.
cp "$TOPOLOGY_FIXTURE/lb/lb.pem" "$RUN/pki/valid-lb.pem"
touch "$RUN/pki/index"
printf '01\n' >"$RUN/pki/serial"
cat >"$RUN/pki/ca.conf" <<EOF
[ca]
default_ca=fixture
[fixture]
database=$RUN/pki/index
serial=$RUN/pki/serial
new_certs_dir=$RUN/pki
default_md=sha256
policy=subject
[subject]
commonName=supplied
[server]
subjectAltName=DNS:$TOPOLOGY_PUBLIC_HOST
extendedKeyUsage=serverAuth
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
EOF
openssl ca -batch -notext -config "$RUN/pki/ca.conf" -cert "$RUN/pki/ca.crt" -keyfile "$RUN/pki/ca.key" \
  -in "$RUN/pki/lb.csr" -startdate 20200101000000Z -enddate 20200102000000Z -extensions server \
  -out "$RUN/pki/expired.crt" >/dev/null 2>&1
openssl req -new -newkey rsa:2048 -nodes -subj /CN=topology-intermediate \
  -keyout "$RUN/pki/intermediate.key" -out "$RUN/pki/intermediate.csr" >/dev/null 2>&1
printf 'basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\n' >"$RUN/pki/intermediate.ext"
openssl x509 -req -in "$RUN/pki/intermediate.csr" -CA "$RUN/pki/ca.crt" -CAkey "$RUN/pki/ca.key" \
  -CAcreateserial -days 2 -extfile "$RUN/pki/intermediate.ext" -out "$RUN/pki/intermediate.crt" >/dev/null 2>&1
openssl x509 -req -in "$RUN/pki/lb.csr" -CA "$RUN/pki/intermediate.crt" -CAkey "$RUN/pki/intermediate.key" \
  -CAcreateserial -days 2 -extfile "$RUN/pki/lb.ext" -out "$RUN/pki/incomplete.crt" >/dev/null 2>&1
for invalid in expired incomplete; do
  cat "$RUN/pki/$invalid.crt" "$RUN/pki/lb.key" >"$TOPOLOGY_FIXTURE/lb/lb.pem"
  clients restart lb
  tls_status=0
  for _ in {1..20}; do
    remote_curl phone-a -sS --cacert /fixture/client-ca.crt --max-time 5 "$public/health" >/dev/null 2>&1 && tls_status=0 || tls_status=$?
    [[ "$tls_status" != 7 ]] && break
    sleep 1
  done
  [[ "$tls_status" == 60 ]]
done
cp "$RUN/pki/valid-lb.pem" "$TOPOLOGY_FIXTURE/lb/lb.pem"
clients restart lb
sleep 3

# Failed authentication exhausts the backend IP bucket; a distinct client retains its own quota.
# Read the shipped policy rather than inventing a separate probe limit.
identity_attempts=$(python3 - "$ROOT/chronicle-server/src/main/resources/rate-limit.yaml" <<'PY_LIMIT'
import sys, yaml
policy = yaml.safe_load(open(sys.argv[1]))
print(int(policy['auth-requests-per-minute'] * policy['burst-capacity-multiplier']) + 1)
PY_LIMIT
)
identity_path=/chronicle/v4/study/00000000-0000-0000-0000-000000000000/participant/identity-probe/android
identity_options=(-sS --noproxy '*' --cacert /fixture/client-ca.crt --max-time 10
  -H 'X-Forwarded-For: 198.51.100.66' -H 'X-Api-Key: topology-invalid-credential'
  -H 'Content-Type: application/json' -d '[]' -o /dev/null -w '%{http_code}')
# Execute the burst inside one client so Docker exec startup does not refill the bucket between requests.
identity_a=$(clients exec -T phone-a bash -ceu '
  attempts=$1; shift
  for ((attempt=0; attempt<attempts; attempt++)); do
    status=$(curl "$@")
    [[ "$status" != 429 ]] || break
    [[ "$status" == 401 ]]
  done
  printf %s "$status"
' identity-probe "$identity_attempts" "${transport_options[@]}" "${identity_options[@]}" "$public$identity_path")
[[ "$identity_a" == 429 ]]
identity_b=$(remote_curl phone-b "${identity_options[@]}" "$public$identity_path")
if [[ "${TOPOLOGY_FORWARD_CLIENT:-true}" == true || "${TOPOLOGY_SOURCE_PRESERVING:-false}" == true ]]; then
  [[ "$identity_b" == 401 ]]
else
  [[ "$identity_b" == 429 ]]
fi
printf 'exhausted_client=%s peer=%s\n' "$identity_a" "$identity_b" >"$TOPOLOGY_FIXTURE/client/backend-identity.txt"

# Exact readiness removes a pool even while the SPA still has healthy static assets.
docker compose stop postgres
sleep 8
[[ $(remote_curl phone-a -s --cacert /fixture/client-ca.crt --max-time 10 -o /dev/null -w '%{http_code}' "$public/health") == 503 ]]
docker compose up -d --wait --wait-timeout 300 postgres
sleep 8
remote_curl phone-a --fail --cacert /fixture/client-ca.crt --max-time 10 "$public/health"
# An operator restore of an older backup carries post-backup protections forward in the continuity
# checkpoint the server consumes at startup, and keeps narrowed ACLs. The rollback-only refusal of such
# a backup runs against real Postgres in tests/selfhost-py/test_restore_schemas.py.
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="$STACK" python3 - "$PROJECT" "$STACK" <<'PY_RESTORE'
import os, subprocess, sys
from pathlib import Path
from chronicle_ops.dump import file_sha256
from chronicle_ops.release import ROLLBACK_DUMP, postgres_sql, rollback_dump
from chronicle_ops.verify import verify_database_privileges
project, stack = sys.argv[1], Path(sys.argv[2])
command = ['docker', 'compose', '-p', project]
subprocess.run([*command, 'stop', 'backend', 'web', 'db-init', 'db-backup'], check=True)
container = subprocess.run([*command, 'ps', '-q', 'postgres'], check=True, text=True, capture_output=True).stdout.strip()
assert int(postgres_sql(container, "SELECT count(*) FROM participant_form_access_codes WHERE form_kind = 'ENROLLMENT' AND revoked_at IS NULL")) > 0
postgres_sql(container, "CREATE TABLE public.selfhost_restore_probe (value TEXT); INSERT INTO public.selfhost_restore_probe VALUES ('before-backup')")
backup = stack / 'backups/rollback-transaction-fixture.sql.gz'
digest = rollback_dump([*command, 'exec', '-T', 'postgres', '/bin/bash', '-ceu', ROLLBACK_DUMP], backup)
postgres_sql(container, "UPDATE public.selfhost_restore_probe SET value = 'after-backup'; UPDATE public.participant_form_access_codes SET revoked_at = now() WHERE form_kind = 'ENROLLMENT' AND revoked_at IS NULL")
result = subprocess.run(['./chronicle', 'restore', '--yes', '--no-start', '--trusted-sha256=' + digest,
                         '/backups/' + backup.name], text=True, capture_output=True)
assert result.returncode == 0, result.stdout + result.stderr
assert 'withdrawal and erasure continuity checkpoint captured' in result.stdout + result.stderr, result.stdout + result.stderr
assert 'Startup remains blocked until the server consumes the continuity checkpoint' in result.stdout + result.stderr
assert postgres_sql(container, 'SELECT value FROM public.selfhost_restore_probe') == 'before-backup'
assert not (stack / '.chronicle-restore.lock').exists()
assert digest == file_sha256(backup)
os.environ['CHRONICLE_OPS_PROJECT'] = project
privileges_status, privileges_message = verify_database_privileges()
assert privileges_status == 0, privileges_message
print('PASS older-backup restore captures continuity for startup and keeps database ACLs')
subprocess.run([*command, 'stop', 'backend', 'web', 'db-init', 'db-backup'], check=True)
fresh = backup.with_name('restore-acl-fixture.sql.gz')
fresh_digest = rollback_dump([*command, 'exec', '-T', 'postgres', '/bin/bash', '-ceu', ROLLBACK_DUMP], fresh)
result = subprocess.run(['./chronicle', 'restore', '--yes', '--no-start', '--trusted-sha256=' + fresh_digest,
                         '/backups/' + fresh.name], text=True, capture_output=True)
assert result.returncode == 0, result.stdout + result.stderr
assert postgres_sql(container, 'SELECT value FROM public.selfhost_restore_probe') == 'before-backup'
privileges_status, privileges_message = verify_database_privileges()
assert privileges_status == 0, privileges_message
print('PASS successful restore retains narrowed ACLs despite broad creation defaults')
PY_RESTORE
printf 'PASS off-host strict TLS, sessions, enrollment, uploads, ACLs, forged headers, concurrent readiness and pool removal; evidence %s\n' "$RUN"
