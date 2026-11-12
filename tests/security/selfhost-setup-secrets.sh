#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
source "${ROOT_DIR}/tests/security/lib/selfhost-fixtures.sh"
RUN_PARENT="${SELFHOST_SETUP_TEST_ROOT:-${ROOT_DIR}/build/operator-test-runs/selfhost-setup-secrets}"
REAL_PYTHON="$(command -v python3)"

fail() {
  echo "self-host setup secret-custody test failed: $*" >&2
  exit 1
}

[[ "$RUN_PARENT" == /* ]] || fail "test run parent must be absolute"
case "$RUN_PARENT" in
  /tmp|/tmp/*|/private/tmp|/private/tmp/*|/var/folders|/var/folders/*)
    fail "test run parent must not use a system temporary directory"
    ;;
esac

umask 077
/bin/mkdir -p "$RUN_PARENT"
RUN_DIR="$(/usr/bin/mktemp -d "${RUN_PARENT}/run.XXXXXX")"
/bin/chmod 0700 "$RUN_DIR"
trap '/bin/rm -rf -- "$RUN_DIR"' EXIT

FIXTURE_SELFHOST="${RUN_DIR}/selfhost"
COMMAND_DIR="${RUN_DIR}/commands"
/bin/mkdir -p "$FIXTURE_SELFHOST" "$COMMAND_DIR"
copy_selfhost_setup_fixture "$FIXTURE_SELFHOST"
write_encrypted_storage_fixture "$COMMAND_DIR"

PASSWORD='fixture-pass-123' # Exactly 16 characters; shared setup/rotation boundary fixture. gitleaks:allow (test fixture)
GENERATED='fixture-generated-secret-value-abcdefghijklmnopqrstuvwxyz0123456789'
DOCKER_ARGS="${RUN_DIR}/docker-args.txt"
PYTHON_ARGS="${RUN_DIR}/python-args.txt"
export SELFHOST_SETUP_TEST_NETWORKS='[{"Name":"other_default","Labels":{"com.docker.compose.project":"other","com.docker.compose.network":"default"},"IPAM":{"Config":[{"Subnet":"172.28.0.0/16"},{"Subnet":"10.253.0.128/25"},{"Subnet":"fd00::/64"}]}}]'

cat >"${COMMAND_DIR}/crontab" <<'EOF'
#!/usr/bin/env bash
if [[ "$1" == -l ]]; then echo "no crontab for fixture" >&2; exit 1; fi
cat >/dev/null
EOF
cat >"${COMMAND_DIR}/docker" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
[[ -z "${SELFHOST_SETUP_TEST_PREFLIGHT_CALLS:-}" ]] ||
  printf '%s\n' "$*" >>"${SELFHOST_SETUP_TEST_PREFLIGHT_CALLS}"
if [[ "$*" == 'info --format {{.DockerRootDir}}' ]]; then
  printf '%s\n' /fixture/docker
  exit 0
fi
# Setup's architecture check (chronicle_ops/host_versions.py daemon_architecture).
if [[ "$*" == 'info --format {{.Architecture}}' ]]; then
  printf '%s\n' x86_64
  exit 0
fi
if [[ "${1:-}" == network ]]; then
  [[ "${SELFHOST_SETUP_TEST_NETWORK_QUERY_FAIL:-0}" == 0 ]] || exit 98
  case "${2:-}" in
    ls) printf 'fixture-network\n' ;;
    inspect) printf '%s\n' "${SELFHOST_SETUP_TEST_NETWORKS}" ;;
    *) exit 99 ;;
  esac
  exit 0
fi
if [[ "${1:-}" == ps ]]; then
  if [[ -n "${SELFHOST_SETUP_TEST_OWN_PROJECT:-}" && "$*" == *"project=${SELFHOST_SETUP_TEST_OWN_PROJECT}"* && "$*" == *'service=web'* ]]; then
    printf 'fixture-web\n'
  fi
  exit 0
fi
if [[ "${1:-}" == inspect && "$*" == *NetworkSettings.Ports* ]]; then
  printf '%s\n' '{"443/tcp":[{"HostIp":"0.0.0.0","HostPort":"444"}],"80/tcp":[{"HostIp":"0.0.0.0","HostPort":"81"}],"8081/tcp":[{"HostIp":"127.0.0.1","HostPort":"8082"}]}'
  exit 0
fi
if [[ "${1:-}" == volume && "${2:-}" == ls ]]; then
  exit 0
fi
if [[ "${1:-}" == compose && "${2:-}" == version ]]; then
  printf '2.39.0\n'
  exit 0
fi
if [[ "${1:-}" == compose && "$*" == *' config --format json' ]]; then
  python3 - <<'PY'
import json
import os
from pathlib import Path

values = dict(line.split("=", 1) for line in Path(".env").read_text().splitlines()
              if line and not line.startswith("#") and "=" in line)
subnet = os.environ.get("SELFHOST_SETUP_TEST_RENDERED_SUBNET", values["CHRONICLE_SUBNET"])
print(json.dumps({"name": values["COMPOSE_PROJECT_NAME"], "networks": {"default": {
    "name": values["COMPOSE_PROJECT_NAME"] + "_default",
    "ipam": {"config": [{"subnet": subnet}]},
}}}))
PY
  exit 0
fi
if [[ "${1:-}" == compose && "$*" == *' ls '* ]]; then
  # Stands in for an operator rotating a secret while setup waits at a prompt.
  if [[ -n "${SELFHOST_SETUP_TEST_MUTATE_ENV:-}" ]]; then
    count_file="${SELFHOST_SETUP_TEST_MUTATE_ENV}.ownership-probes"
    count=0
    [[ ! -f "$count_file" ]] || read -r count <"$count_file"
    count=$((count + 1)); printf '%s\n' "$count" >"$count_file"
    # The first probe guards ownership before the snapshot; race after that snapshot.
    if ((count == 2)); then
      perl -pi -e 's/^POSTGRES_PASSWORD=.*/POSTGRES_PASSWORD=rotated-while-setup-waited/' "${SELFHOST_SETUP_TEST_MUTATE_ENV}"
    fi
  fi
  printf '[]\n'
  exit 0
fi
for argument in "$@"; do
  [[ "$argument" != *"${SELFHOST_SETUP_TEST_PASSWORD}"* ]] || {
    echo "dashboard password reached Docker argv" >&2
    exit 91
  }
done
# Only the Caddy hash container reads standard input. Setup shares its own standard input, the
# operator's answers, with every child, so a call this fixture does not know must fail here instead
# of reading them: an unknown `docker info` query once consumed every answer, and setup then ran on
# its defaults and stopped at the example hostname.
[[ "${1:-}" == run && "${!#}" == hash-password ]] || {
  echo "selfhost-setup-secrets fixture: unexpected docker call: $*" >&2
  exit 90
}
printf '%s\n' "$@" >"${SELFHOST_SETUP_TEST_DOCKER_ARGS}"
plaintext="$(cat)"
[[ "$plaintext" == "${SELFHOST_SETUP_TEST_PASSWORD}" ]] || {
  echo "dashboard password was not delivered to Caddy over stdin" >&2
  exit 92
}
printf '%s\n' '$2a$14$fixturebcryptvalueabcdefghijklmnopqrstuv0123456789ABCDE'
EOF

cat >"${COMMAND_DIR}/openssl" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
[[ "$*" == "rand -base64 32" ]] || exit 93
printf '%s\n' "${SELFHOST_SETUP_TEST_GENERATED}"
EOF

cat >"${COMMAND_DIR}/ss" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
[[ "$*" == "-lnt" ]] || exit 96
cat <<'SOCKETS'
State  Recv-Q Send-Q Local Address:Port Peer Address:Port
LISTEN 0      128    127.0.0.1:8081   0.0.0.0:*
LISTEN 0      128    0.0.0.0:443      0.0.0.0:*
LISTEN 0      128    0.0.0.0:80       0.0.0.0:*
SOCKETS
if [[ "${SELFHOST_SETUP_TEST_HELD_TRIAL:-false}" == true ]]; then
  printf '%s\n' 'LISTEN 0 128 0.0.0.0:444 0.0.0.0:*' 'LISTEN 0 128 0.0.0.0:81 0.0.0.0:*'
fi
EOF

cat >"${COMMAND_DIR}/ifconfig" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
cat <<'ADDRESSES'
lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 16384
        inet 127.0.0.1 netmask 0xff000000
en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
        inet 192.168.50.10 netmask 0xffffff00 broadcast 192.168.50.255
ADDRESSES
EOF

cat >"${COMMAND_DIR}/ip" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
if [[ "$*" == *'-j route show table all'* ]]; then printf '[]\n'; exit 0; fi
[[ "$*" == '-o addr show' ]] || exit 97
printf '%s\n' \
  '1: lo    inet 127.0.0.1/8 scope host lo' \
  '2: en0   inet 192.168.50.10/24 brd 192.168.50.255 scope global en0'
EOF

cat >"${COMMAND_DIR}/python3" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
for argument in "$@"; do
  [[ "$argument" != *"${SELFHOST_SETUP_TEST_PASSWORD}"* ]] || {
    echo "dashboard password reached Python argv" >&2
    exit 94
  }
  [[ "$argument" != *"${SELFHOST_SETUP_TEST_GENERATED}"* ]] || {
    echo "generated deployment secret reached Python argv" >&2
    exit 95
  }
done
printf '%s\n' "$@" >"${SELFHOST_SETUP_TEST_PYTHON_ARGS}"
# Records whether setup holds the shared operation lock while the installed setup command renders .env.
if [[ -n "${SELFHOST_SETUP_TEST_LOCK_PROBE:-}" && "${1:-}" == -m && "${2:-}" == chronicle_ops && "${3:-}" == setup-env ]]; then
  "${SELFHOST_SETUP_TEST_REAL_PYTHON}" -c '
import fcntl, os, sys
try:
    fcntl.flock(os.open(sys.argv[1], os.O_RDWR), fcntl.LOCK_EX | fcntl.LOCK_NB)
except BlockingIOError:
    print("held")
else:
    print("free")' "${SELFHOST_SETUP_TEST_LOCK_FILE}" >"${SELFHOST_SETUP_TEST_LOCK_PROBE}"
fi
exec "${SELFHOST_SETUP_TEST_REAL_PYTHON}" "$@"
EOF
/bin/chmod 0755 \
  "${COMMAND_DIR}/crontab" \
  "${COMMAND_DIR}/docker" \
  "${COMMAND_DIR}/ifconfig" \
  "${COMMAND_DIR}/ip" \
  "${COMMAND_DIR}/openssl" \
  "${COMMAND_DIR}/python3" \
  "${COMMAND_DIR}/ss"

SHORT_SELFHOST="${RUN_DIR}/short-selfhost"
copy_selfhost_setup_fixture "$SHORT_SELFHOST"
if write_selfhost_setup_answers 123456789012345 |
    env PATH="${COMMAND_DIR}:${PATH}" SELFHOST_SETUP_TEST_PASSWORD="$PASSWORD" \
      SELFHOST_SETUP_TEST_GENERATED="$GENERATED" SELFHOST_SETUP_TEST_DOCKER_ARGS="$DOCKER_ARGS" \
      SELFHOST_SETUP_TEST_PYTHON_ARGS="$PYTHON_ARGS" SELFHOST_SETUP_TEST_REAL_PYTHON="$REAL_PYTHON" \
      bash "$SHORT_SELFHOST/chronicle" setup >"${RUN_DIR}/short-password.log" 2>&1; then
  fail "setup accepted a 15-character dashboard password"
fi
grep -Fq 'dashboard password must be at least 16 characters' "${RUN_DIR}/short-password.log" || { cat "${RUN_DIR}/short-password.log" >&2; fail "setup omitted the short-password diagnostic"; }

OUTPUT="${RUN_DIR}/setup-output.txt"
printf 'MemTotal:        3900000 kB\n' >"${RUN_DIR}/meminfo-4g"
OUTPUT="${RUN_DIR}/setup-output.txt"
if ! (
  # Deliberately remove the caller's protection. The operator script itself must set its
  # private umask before the first generated secret or sibling publication file is created.
  umask 000
  write_selfhost_setup_answers "$PASSWORD" | PATH="${COMMAND_DIR}:${PATH}" \
      SELFHOST_SETUP_TEST_PASSWORD="$PASSWORD" \
      SELFHOST_SETUP_TEST_GENERATED="$GENERATED" \
      SELFHOST_SETUP_TEST_DOCKER_ARGS="$DOCKER_ARGS" \
      SELFHOST_SETUP_TEST_PYTHON_ARGS="$PYTHON_ARGS" \
      SELFHOST_SETUP_TEST_REAL_PYTHON="$REAL_PYTHON" \
      CHRONICLE_MEMINFO="${RUN_DIR}/meminfo-4g" \
      /bin/bash "${FIXTURE_SELFHOST}/chronicle" setup >"$OUTPUT" 2>&1
); then
  cat "$OUTPUT" >&2
  fail "interactive setup fixture failed"
fi

if ! PYTHONPATH="$FIXTURE_SELFHOST" "$REAL_PYTHON" -s - "$FIXTURE_SELFHOST" <<'PY_SANS'
import ipaddress, sys
from pathlib import Path
from urllib.parse import urlsplit
from chronicle_ops.envfile import read_env,value
settings=read_env(Path(sys.argv[1])/'.env')
sans=value(settings,'INTERNAL_CERT_SANS').split(',')
assert all(sans), 'fresh setup generated an empty INTERNAL_CERT_SANS entry'
host=urlsplit(value(settings,'DASHBOARD_BASE_URL')).hostname
try:
    ipaddress.ip_address(host)
    san='IP:'+host
except ValueError:
    san='DNS:'+host
assert san in sans, 'fresh setup omitted the management SAN'
PY_SANS
then
  fail "fresh setup generated invalid internal certificate SANs"
fi
echo 'PASS: fresh proxy setup has non-empty internal certificate SANs and the management SAN'

[[ -s "${FIXTURE_SELFHOST}/.env" ]] || fail "setup did not create .env"
mode="$(stat -c '%a' "${FIXTURE_SELFHOST}/.env" 2>/dev/null || stat -f '%Lp' "${FIXTURE_SELFHOST}/.env")"
[[ "$mode" == 600 ]] || fail "generated .env mode is ${mode}, expected 600"

! grep -Fq "$PASSWORD" "$OUTPUT" || fail "dashboard password was printed"
! grep -Fq "$GENERATED" "$OUTPUT" || fail "generated deployment secret was printed"
! grep -Fq "$PASSWORD" "$DOCKER_ARGS" || fail "dashboard password reached Docker argv log"
! grep -Fq "$PASSWORD" "$PYTHON_ARGS" || fail "dashboard password reached Python argv log"
! grep -Fq "$GENERATED" "$PYTHON_ARGS" || fail "generated deployment secret reached Python argv log"
! grep -Fqx -- '--plaintext' "$DOCKER_ARGS" || fail "Caddy hash command used a plaintext argv"
grep -Fqx -- '-i' "$DOCKER_ARGS" || fail "Caddy hash container did not read stdin"
grep -Fqx -- '--network' "$DOCKER_ARGS" || fail "Caddy hash container did not disable networking"

python3 - "${FIXTURE_SELFHOST}/.env" <<'PY'
from pathlib import Path
import ipaddress
import re
import sys

values = {}
for line in Path(sys.argv[1]).read_text(encoding="utf-8").splitlines():
    match = re.match(r"^([A-Z][A-Z0-9_]*)=(.*)$", line)
    if match:
        if match.group(1) in values:
            raise SystemExit(f"duplicate generated setting: {match.group(1)}")
        values[match.group(1)] = match.group(2)

subnet = ipaddress.ip_network(values["CHRONICLE_SUBNET"])
assert str(subnet) == "10.253.1.0/24", "setup did not select the first free candidate"
assert not subnet.overlaps(ipaddress.ip_network("172.28.0.0/16"))
assert not subnet.overlaps(ipaddress.ip_network("10.253.0.128/25"))

for key in (
    "POSTGRES_PASSWORD",
    "POSTGRES_APP_PASSWORD",
    "JWT_SECRET",
    "METRICS_PASSWORD",
    "CHRONICLE_INTERNAL_WEB_SECRET",
    "GRAFANA_ADMIN_PASSWORD",
):
    value = values.get(key, "")
    if not value or "CHANGE_ME" in value:
        raise SystemExit(f"setup did not generate {key}")
if any(key.startswith("MOBILE_SIGNING_") for key in values):
    raise SystemExit("setup retained deployment-wide mobile signing configuration")
if values.get("HTTP_PORT") != "8080":
    raise SystemExit("setup changed the reviewed pool port")
if values.get("INTERNAL_PORT") != "8082":
    raise SystemExit("setup reused the selected public port for the internal listener")
# A 4 GB host gets memory ceilings that fit it (README sizing: pilot minimum 2 vCPU / 4 GB).
for key, expected in (("BACKEND_MEM_LIMIT", "1536m"), ("BACKEND_XMX", "-Xmx1g"),
                      ("POSTGRES_MEM_LIMIT", "1g"), ("POSTGRES_SHARED_BUFFERS", "256MB"),
                      ("POSTGRES_EFFECTIVE_CACHE_SIZE", "768MB")):
    if values.get(key) != expected:
        raise SystemExit(f"setup on a 4 GB host left {key}={values.get(key)!r}, expected {expected}")
if not values.get("DASHBOARD_PASSWORD_HASH", "").startswith("'$2"):
    raise SystemExit("setup did not store a single-quoted bcrypt hash")
PY

grep -Fq 'Docker network range 10.253.1.0/24 is free; using that for CHRONICLE_SUBNET.' "$OUTPUT" \
  || fail "setup did not explain its selected subnet"
bash "${FIXTURE_SELFHOST}/guard-config.sh" --validate-compose-subnet 10.253.1.0/24 10.253.1.0/24 \
  || fail "selected subnet does not satisfy the trusted-proxy contract"

# Re-running setup over an existing deployment (proxy mode answers, existing secrets kept).
resetup_proxy() { # <output> [extra env assignments...]
  local output="$1"
  shift
  write_selfhost_setup_answers "$PASSWORD" true true --keep-retention | env PATH="${COMMAND_DIR}:${PATH}" \
      SELFHOST_SETUP_TEST_PASSWORD="$PASSWORD" \
      SELFHOST_SETUP_TEST_GENERATED="$GENERATED" \
      SELFHOST_SETUP_TEST_DOCKER_ARGS="$DOCKER_ARGS" \
      SELFHOST_SETUP_TEST_PYTHON_ARGS="$PYTHON_ARGS" \
      SELFHOST_SETUP_TEST_REAL_PYTHON="$REAL_PYTHON" \
      "$@" /bin/bash "${FIXTURE_SELFHOST}/chronicle" setup >"$output" 2>&1
}

# Unasked production controls and the canonical alias survive a real blank-answer rerun.
PYTHONPATH="$FIXTURE_SELFHOST" "$REAL_PYTHON" -s - "$FIXTURE_SELFHOST" <<'PY_PRESERVE'
import shlex, sys
from pathlib import Path
from chronicle_ops.envfile import read_env
path=Path(sys.argv[1])/'.env'
settings=read_env(path)
changed={'POSTGRES_DB':'customdb','POSTGRES_USER':'customuser','CHRONICLE_PUBLIC_BASE_URL':'https://alias.study-host.org:8443',
         'DASHBOARD_ALLOWED_IPS':'10.242.0.0/24 fd42:242::/64','INTERNAL_CERT_SANS':'DNS:saved.mgmt.example.org',
         'SMTP_HOST':'smtp.example.org','BACKUP_KEEP_DAYS':'3','CHRONICLE_EXPORT_WORKERS':'2'}
settings.update({key:shlex.quote(val) for key,val in changed.items()})
path.write_text('\n'.join(key+'='+val for key,val in settings.items())+'\n')
PY_PRESERVE
# A rerun keeps the deployment's own Compose project (and so its database volume).
perl -pi -e 's/^COMPOSE_PROJECT_NAME=.*/COMPOSE_PROJECT_NAME=pilot-study/' "${FIXTURE_SELFHOST}/.env"
perl -pi -e 's|^CHRONICLE_SUBNET=.*|CHRONICLE_SUBNET=10.253.99.0/24|' "${FIXTURE_SELFHOST}/.env"
resetup_proxy "${RUN_DIR}/setup-project-output.txt" || fail "re-setup with a custom project failed"
grep -Fqx 'COMPOSE_PROJECT_NAME=pilot-study' "${FIXTURE_SELFHOST}/.env" \
  || fail "re-setup replaced the existing custom COMPOSE_PROJECT_NAME"
grep -Fqx 'CHRONICLE_SUBNET=10.253.99.0/24' "${FIXTURE_SELFHOST}/.env" \
  || fail "re-setup moved the existing deployment's subnet"

PYTHONPATH="$FIXTURE_SELFHOST" "$REAL_PYTHON" -s - "$FIXTURE_SELFHOST" <<'PY_PRESERVE'
import sys
from pathlib import Path
from chronicle_ops.envfile import read_env,value
settings=read_env(Path(sys.argv[1])/'.env')
for key,wanted in {'POSTGRES_DB':'customdb','POSTGRES_USER':'customuser','CHRONICLE_PUBLIC_BASE_URL':'https://alias.study-host.org:8443',
                   'DASHBOARD_ALLOWED_IPS':'10.242.0.0/24 fd42:242::/64','SMTP_HOST':'smtp.example.org','BACKUP_KEEP_DAYS':'3',
                   'CHRONICLE_EXPORT_WORKERS':'2'}.items():
    assert value(settings,key)==wanted,key+' reset during setup'
assert 'DNS:saved.mgmt.example.org' in value(settings,'INTERNAL_CERT_SANS')
assert value(settings,'DASHBOARD_BASE_URL')=='https://127.0.0.1:8082'
PY_PRESERVE
echo 'PASS: production re-setup preserves database, ACL, SAN, SMTP, retention and public alias'

# Up checks the rendered subnet before starting config-guard or any other container.
image_keys="$(selfhost_python -c 'from chronicle_ops.images import SOURCE_IMAGES; print("|".join(image.variable for image in SOURCE_IMAGES))')"
perl -pi -e "s~^(${image_keys})=.*~\$1=fixture/image@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa~" \
  "${FIXTURE_SELFHOST}/.env"
if env PATH="${COMMAND_DIR}:${PATH}" \
    SELFHOST_SETUP_TEST_PASSWORD="$PASSWORD" \
    SELFHOST_SETUP_TEST_GENERATED="$GENERATED" \
    SELFHOST_SETUP_TEST_PYTHON_ARGS="$PYTHON_ARGS" \
    SELFHOST_SETUP_TEST_REAL_PYTHON="$REAL_PYTHON" \
    SELFHOST_SETUP_TEST_RENDERED_SUBNET=172.28.0.0/16 \
    SELFHOST_SETUP_TEST_PREFLIGHT_CALLS="${RUN_DIR}/preflight-calls" \
    /bin/bash "${FIXTURE_SELFHOST}/chronicle" up >"${RUN_DIR}/subnet-preflight-output.txt" 2>&1; then
  : # An overlap only warns; the fixture's later steps decide the exit status.
fi
if ! grep -Fq 'warning: CHRONICLE_SUBNET 172.28.0.0/16 overlaps Docker network other_default (172.28.0.0/16); set CHRONICLE_SUBNET in .env to a free private range' \
    "${RUN_DIR}/subnet-preflight-output.txt"; then
  cat "${RUN_DIR}/subnet-preflight-output.txt" >&2
  fail "up did not warn about the conflict and name its remedy"
fi
own_warnings="$(printf '%s\n' '{"name":"other","networks":{"default":{"name":"other_default","ipam":{"config":[{"subnet":"172.28.0.0/16"}]}}}}' |
  PATH="${COMMAND_DIR}:${PATH}" "$REAL_PYTHON" "${FIXTURE_SELFHOST}/network-subnet.py" check 2>&1)" \
  || fail "subnet check failed on the project's own network"
[[ -z "$own_warnings" ]] || fail "subnet check warned about the project's own network: $own_warnings"
# Same name without this project's Compose labels is someone else's network, not ours.
impostor_warnings="$(printf '%s\n' '{"name":"other","networks":{"default":{"name":"other_default","ipam":{"config":[{"subnet":"172.28.0.0/16"}]}}}}' |
  SELFHOST_SETUP_TEST_NETWORKS='[{"Name":"other_default","IPAM":{"Config":[{"Subnet":"172.28.0.0/16"}]}}]' \
  PATH="${COMMAND_DIR}:${PATH}" "$REAL_PYTHON" "${FIXTURE_SELFHOST}/network-subnet.py" check 2>&1)" \
  || fail "subnet check failed instead of warning"
[[ "$impostor_warnings" == *"overlaps Docker network other_default"* ]] \
  || fail "subnet check excluded an unlabelled network that only shares the project's name"
echo "PASS: subnet selection, rerun preservation, and pre-start overlap warning"

# Setup refuses while a rotation/restore/upgrade lock is held, and never publishes values it
# read before another operation changed .env under it.
/bin/cp "${FIXTURE_SELFHOST}/.env" "${RUN_DIR}/env-before-locked-setup"
/bin/mkdir "${FIXTURE_SELFHOST}/.chronicle-secret-rotation"
printf 'prepared\n' >"${FIXTURE_SELFHOST}/.chronicle-secret-rotation/phase"
! resetup_proxy "${RUN_DIR}/setup-locked-output.txt" || fail "setup ran while a secret rotation was active"
grep -Fq 'incomplete operation at' "${RUN_DIR}/setup-locked-output.txt" \
  || fail "setup did not explain the rotation interlock"
cmp -s "${FIXTURE_SELFHOST}/.env" "${RUN_DIR}/env-before-locked-setup" || fail "locked setup changed .env"
/bin/rm -f "${FIXTURE_SELFHOST}/.chronicle-secret-rotation/phase"
/bin/rmdir "${FIXTURE_SELFHOST}/.chronicle-secret-rotation"
! resetup_proxy "${RUN_DIR}/setup-race-output.txt" \
  SELFHOST_SETUP_TEST_MUTATE_ENV="${FIXTURE_SELFHOST}/.env" || fail "setup overwrote a concurrent .env change"
grep -Fq '.env changed while setup was running' "${RUN_DIR}/setup-race-output.txt" \
  || fail "setup did not explain the concurrent .env change"
grep -Fqx 'POSTGRES_PASSWORD=rotated-while-setup-waited' "${FIXTURE_SELFHOST}/.env" \
  || fail "setup discarded a value changed while it waited"
# The final check and the .env write happen under the operation lock that rotation, restore and update hold.
resetup_proxy "${RUN_DIR}/setup-lock-output.txt" SELFHOST_SETUP_TEST_LOCK_PROBE="${RUN_DIR}/lock-probe" \
  SELFHOST_SETUP_TEST_LOCK_FILE="${FIXTURE_SELFHOST}/.reconcile.lock" \
  || fail "setup failed with the lock probe"
[[ "$(cat "${RUN_DIR}/lock-probe")" == held ]] || fail "setup wrote .env without holding the operation lock"
[[ ! -e "${FIXTURE_SELFHOST}/.chronicle-upgrade.lock" ]] || fail "setup left an upgrade marker behind"
/bin/mkdir "${FIXTURE_SELFHOST}/.chronicle-upgrade.lock"
printf '{}\n' >"${FIXTURE_SELFHOST}/.chronicle-upgrade.lock/recovery.json"
! resetup_proxy "${RUN_DIR}/setup-upgrade-locked.txt" || fail "setup ran while an upgrade lock was held"
/bin/rm -f "${FIXTURE_SELFHOST}/.chronicle-upgrade.lock/recovery.json"
/bin/rmdir "${FIXTURE_SELFHOST}/.chronicle-upgrade.lock"

FIXTURE_LOCAL_SELFHOST="${RUN_DIR}/selfhost-local"
/bin/mkdir -p "$FIXTURE_LOCAL_SELFHOST"
copy_selfhost_setup_fixture "$FIXTURE_LOCAL_SELFHOST"
LOCAL_OUTPUT="${RUN_DIR}/setup-local-output.txt"
if ! (
  umask 000
  write_selfhost_setup_answers "$PASSWORD" false false --mode 3 --public-host 192.168.50.10 |
    PATH="${COMMAND_DIR}:${PATH}" \
      SELFHOST_SETUP_TEST_PASSWORD="$PASSWORD" \
      SELFHOST_SETUP_TEST_GENERATED="$GENERATED" \
      SELFHOST_SETUP_TEST_DOCKER_ARGS="$DOCKER_ARGS" \
      SELFHOST_SETUP_TEST_PYTHON_ARGS="$PYTHON_ARGS" \
      SELFHOST_SETUP_TEST_REAL_PYTHON="$REAL_PYTHON" \
      SELFHOST_SETUP_TEST_NETWORK_QUERY_FAIL=1 \
      /bin/bash "${FIXTURE_LOCAL_SELFHOST}/chronicle" setup >"$LOCAL_OUTPUT" 2>&1
); then
  fail "local HTTPS setup fixture failed"
fi
python3 - "${FIXTURE_LOCAL_SELFHOST}/.env" <<'PY'
from pathlib import Path
import sys

values = dict(
    line.split("=", 1)
    for line in Path(sys.argv[1]).read_text(encoding="utf-8").splitlines()
    if "=" in line
)
if values.get("LOCAL_HTTPS_PORT") != "444":
    raise SystemExit("local setup did not move occupied HTTPS port 443 to 444")
if values.get("LOCAL_HTTP_PORT") != "81":
    raise SystemExit("local setup did not move occupied CA/redirect port 80 to 81")
if values.get("CHRONICLE_PUBLIC_BASE_URL") != "https://192.168.50.10:444":
    raise SystemExit("local setup did not publish the exact selected HTTPS origin")
if values.get("COMPOSE_FILE") != "docker-compose.yml:overlays/mode-local-https.yml:overlays/backups.yml":
    raise SystemExit("local setup did not select the local HTTPS deployment mode")
if values.get("CHRONICLE_SUBNET") != "172.28.0.0/16":
    raise SystemExit("setup did not keep the default when Docker networks were unavailable")
PY
grep -Fq 'Trial HTTPS/CA ports 444 and 81 are free; using those.' "$LOCAL_OUTPUT" \
  || fail "local setup did not explain its selected fallback ports"

trial_project=$(sed -n 's/^COMPOSE_PROJECT_NAME=//p' "${FIXTURE_LOCAL_SELFHOST}/.env")
if ! write_selfhost_setup_answers "$PASSWORD" true true --mode 3 --public-host '' |
    env PATH="${COMMAND_DIR}:${PATH}" SELFHOST_SETUP_TEST_PASSWORD="$PASSWORD" \
      SELFHOST_SETUP_TEST_GENERATED="$GENERATED" SELFHOST_SETUP_TEST_DOCKER_ARGS="$DOCKER_ARGS" \
      SELFHOST_SETUP_TEST_PYTHON_ARGS="$PYTHON_ARGS" SELFHOST_SETUP_TEST_REAL_PYTHON="$REAL_PYTHON" \
      SELFHOST_SETUP_TEST_OWN_PROJECT="$trial_project" SELFHOST_SETUP_TEST_HELD_TRIAL=true \
      bash "${FIXTURE_LOCAL_SELFHOST}/chronicle" setup >"${RUN_DIR}/trial-rerun.log" 2>&1; then
  fail "running trial setup could not be repeated"
fi
for assignment in LOCAL_HTTPS_PORT=444 LOCAL_HTTP_PORT=81 CHRONICLE_PUBLIC_BASE_URL=https://192.168.50.10:444; do
  grep -Fqx "$assignment" "${FIXTURE_LOCAL_SELFHOST}/.env" || fail "running trial changed $assignment"
done

# Re-running setup to leave the trial must not carry the trial's private-address origin into
# a production .env: guard-config rejects it and names a variable setup never asked about.
RESETUP_OUTPUT="${RUN_DIR}/setup-resetup-output.txt"
if ! (
  write_selfhost_setup_answers "$PASSWORD" true true | PATH="${COMMAND_DIR}:${PATH}" \
      SELFHOST_SETUP_TEST_PASSWORD="$PASSWORD" \
      SELFHOST_SETUP_TEST_GENERATED="$GENERATED" \
      SELFHOST_SETUP_TEST_DOCKER_ARGS="$DOCKER_ARGS" \
      SELFHOST_SETUP_TEST_PYTHON_ARGS="$PYTHON_ARGS" \
      SELFHOST_SETUP_TEST_REAL_PYTHON="$REAL_PYTHON" \
      /bin/bash "${FIXTURE_LOCAL_SELFHOST}/chronicle" setup >"$RESETUP_OUTPUT" 2>&1
); then
  fail "re-setup from the local HTTPS trial failed"
fi
! grep -Eq "^CHRONICLE_PUBLIC_BASE_URL=.*192\.168\.50\.10" "${FIXTURE_LOCAL_SELFHOST}/.env" \
  || fail "re-setup into production kept the trial's private-address CHRONICLE_PUBLIC_BASE_URL"

echo "self-host setup secret-custody test passed"

# Optional delivery destination is collected silently and only HTTPS is accepted off this host.
# Setup refuses any other destination at the prompt, before anything is written, and asks again;
# a blank answer leaves the deployment without one. (The same rule at render time and its
# "error: alert webhook must be an HTTPS URL" line are in tests/selfhost-py/test_setup_env.py.)
webhook='https://alerts.example.test/fixture-private-destination'
for alert_case in https http http-then-blank; do
  scheme="${alert_case%%-*}"
  alert_selfhost="${RUN_DIR}/alerts-${alert_case}/selfhost"
  copy_selfhost_setup_fixture "$alert_selfhost"
  alert_output="${RUN_DIR}/alerts-${alert_case}.log"
  alert_status=0
  write_selfhost_setup_answers "$PASSWORD" false false --monitoring \
    --alert-webhook "${webhook/https:/$scheme:}" |
    awk -v blank_after="$([[ "$alert_case" != http-then-blank ]] || printf '%s' "${webhook/https:/http:}")" \
      '{ print } blank_after != "" && $0 == blank_after { print "" }' |
    env PATH="${COMMAND_DIR}:${PATH}" SELFHOST_SETUP_TEST_PASSWORD="$PASSWORD" \
      SELFHOST_SETUP_TEST_GENERATED="$GENERATED" SELFHOST_SETUP_TEST_DOCKER_ARGS="$DOCKER_ARGS" \
      SELFHOST_SETUP_TEST_PYTHON_ARGS="$PYTHON_ARGS" SELFHOST_SETUP_TEST_REAL_PYTHON="$REAL_PYTHON" \
      bash "$alert_selfhost/chronicle" setup >"$alert_output" 2>&1 || alert_status=$?
  ! grep -Fq 'fixture-private-destination' "$alert_output" || fail 'setup printed the secret destination'
  if [[ "$alert_case" == https ]]; then
    [[ "$alert_status" == 0 ]] || fail 'setup rejected the HTTPS alert destination'
    grep -Fqx "CHRONICLE_ALERT_WEBHOOK_URL=$webhook" "$alert_selfhost/.env" || fail 'setup did not save the HTTPS alert destination'
    grep -Fq 'Alert destination saved' "$alert_output" || fail 'setup did not request a delivery test'
    continue
  fi
  grep -Fq 'The alert webhook must be HTTPS' "$alert_output" || fail 'setup did not say why the HTTP alert destination was refused'
  grep -Fq 'It was not saved; enter it again, or leave it blank.' "$alert_output" ||
    fail 'setup did not ask for the alert destination again'
  if [[ "$alert_case" == http ]]; then
    # No blank answer: the answers that follow are read as further attempts and refused, so setup
    # ends without its backup-retention answers and publishes nothing.
    [[ "$alert_status" != 0 ]] || fail 'setup accepted an HTTP alert destination'
    [[ ! -e "$alert_selfhost/.env" ]] || fail 'invalid destination was published'
  else
    [[ "$alert_status" == 0 ]] || { cat "$alert_output" >&2; fail 'setup stopped after a refused alert destination was left blank'; }
    grep -Fqx 'CHRONICLE_ALERT_WEBHOOK_URL=' "$alert_selfhost/.env" || fail 'a refused alert destination was saved'
    grep -Fqx 'CHRONICLE_ALERT_EGRESS=closed' "$alert_selfhost/.env" || fail 'a refused alert destination opened Grafana egress'
    ! grep -Fq 'Alert destination saved' "$alert_output" || fail 'setup reported a refused alert destination as saved'
  fi
done
echo 'PASS: optional HTTPS alert destination is private and validated before publication'
