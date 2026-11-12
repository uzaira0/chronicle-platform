#!/usr/bin/env bash
# Runtime proof that a running self-host project cannot send data out (docs/NETWORK-EGRESS.md).
#
#   tests/security/selfhost-egress.sh PROJECT
#
# Every probe runs in a throwaway container that joins the target container's network
# namespace (--network container:ID), so it sees exactly the target's interfaces, routes and
# resolver, whatever tools the target image lacks. Nothing is changed in the project.
#
# Checks:
#   - the platform: Docker Engine and kernel versions are printed, because internal networks
#     stop forwarding DNS only from Engine 25.0.5 (CVE-2024-29018) and the proof holds for the
#     engine it ran on;
#   - controls: a throwaway container on Docker's own `bridge` network reaches 1.1.1.1:443 and
#     resolves example.com. Without both, nothing below proves anything, so the proof fails;
#   - every running container that joins only internal networks has no default route (IPv4 or
#     IPv6) in its namespace, TCP to 1.1.1.1:443 does not connect and example.com does not
#     resolve. The route check does not depend on the host's upstream: a namespace with no
#     default route cannot send a packet off the host whoever routes its subnet;
#   - every container on a network with a way out is one services.py names as an edge;
#   - egress-proxy, the one edge with a route out, refuses a CONNECT to a host outside its
#     allowlist, and public-probe reaches the internet only through it;
#   - web (Caddy, the TLS edge) cannot open a connection to postgres:5432;
#   - the internal paths still work: web->backend, backend->postgres, db-backup->postgres and
#     backend, operational-probe->postgres and web:8081, every VictoriaMetrics scrape target
#     up, and container logs arriving in VictoriaLogs through fluent-bit;
#   - the Docker socket proxy returns container inspect with Env blanked;
#   - no container's configuration holds a credential except the secret writers.
# Each probe reports connected, blocked, or could not run; a probe that could not run is a
# failure, never a pass. Exit 0 when every check passes, 1 otherwise. Prints no secret.
set -Eeuo pipefail

project="${1:?usage: selfhost-egress.sh PROJECT}"
[[ "$project" =~ ^[a-z0-9][a-z0-9_-]*$ ]] || { echo "invalid project name: $project" >&2; exit 2; }
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
selfhost="$(cd "${here}/../../selfhost" && pwd)"
failures=0
pass() { printf '  ok    %s\n' "$1"; }
fail() { printf '  FAIL  %s\n' "$1"; failures=$((failures + 1)); }

container() { # SERVICE -> running container id, or empty
  docker ps -q --filter "label=com.docker.compose.project=${project}" \
    --filter "label=com.docker.compose.service=$1" --filter status=running | sed -n 1p
}

printf 'Platform\n'
printf '  Docker Engine %s, kernel %s\n' \
  "$(docker version --format '{{.Server.Version}}' 2>/dev/null || echo unknown)" \
  "$(docker info --format '{{.KernelVersion}} ({{.OperatingSystem}})' 2>/dev/null || echo unknown)"

postgres_id="$(container postgres)"
[[ -n "$postgres_id" ]] || { echo "project ${project} has no running postgres" >&2; exit 2; }
probe_image="$(docker inspect -f '{{.Config.Image}}' "$postgres_id")"

# Edge services and their reasons, from the one owner (chronicle_ops/services.py).
edges="$(PYTHONPATH="$selfhost" python3 -c '
from chronicle_ops.services import EDGE_SERVICES
for name, reason in sorted(EDGE_SERVICES.items()):
    print(name + "\t" + reason)')"
writers="$(PYTHONPATH="$selfhost" python3 -c 'from chronicle_ops.services import SECRET_WRITERS; print("\n".join(SECRET_WRITERS))')"

# probe NETWORK COMMAND -> prints "yes" when COMMAND succeeded in a probe container on NETWORK
# (a network name, or container:ID), "no" when it ran and failed, "error" when the probe
# container itself could not run. COMMAND runs as nobody with no capabilities.
probe() {
  local output
  output="$(docker run --rm --network "$1" --entrypoint /bin/bash --user 65534:65534 \
    --read-only --cap-drop ALL --security-opt no-new-privileges:true "$probe_image" \
    -c "if $2; then echo PROBE:yes; else echo PROBE:no; fi" 2>/dev/null)" || true
  case "$output" in
    *PROBE:yes*) echo yes ;;
    *PROBE:no*) echo no ;;
    *) echo error ;;
  esac
}

in_netns() { # SERVICE COMMAND -> probe in SERVICE's network namespace; error when SERVICE is not running
  local id
  id="$(container "$1")"
  if [[ -z "$id" ]]; then echo error; return; fi
  probe "container:${id}" "$2"
}

tcp() { # HOST PORT -> bash snippet that succeeds when a TCP connection opens within 5 s
  printf 'timeout 5 bash -c %q' "exec 3<>/dev/tcp/$1/$2"
}
dns='timeout 10 getent hosts example.com >/dev/null'
# Succeeds when the namespace has a default route: IPv4 destination and mask 0, or an IPv6 ::/0
# that is not the kernel's unreachable entry on lo. A subshell, so its exit ends only itself.
default_route='( while read -r iface destination gateway flags refcount use metric mask rest; do
    [[ "$destination" == 00000000 && "$mask" == 00000000 ]] && exit 0; done < /proc/net/route
  [[ -r /proc/net/ipv6_route ]] && while read -r destination prefix source sprefix hop metric refcount use flags iface; do
    [[ "$destination" == 00000000000000000000000000000000 && "$prefix" == 00 && "$iface" != lo ]] && exit 0
  done < /proc/net/ipv6_route; exit 1 )'

# expect LABEL RESULT WANTED: pass when RESULT is WANTED, fail otherwise; a probe that could not
# run is always a failure.
expect() {
  case "$2" in
    error) fail "$1: the probe could not run" ;;
    "$3") pass "$1" ;;
    *) fail "$1" ;;
  esac
}

printf '\nControls (a container with an ordinary route must get out, or the checks below prove nothing)\n'
expect "control on Docker's bridge network reaches 1.1.1.1:443" "$(probe bridge "$(tcp 1.1.1.1 443)")" yes
expect "control on Docker's bridge network resolves example.com" "$(probe bridge "$dns")" yes

services="$(docker ps --filter "label=com.docker.compose.project=${project}" --filter status=running \
  --format '{{.Label "com.docker.compose.service"}}' | sort -u)"
printf '\nProject %s: %s\n' "$project" "$(tr '\n' ' ' <<<"$services")"

printf '\nNo route out\n'
for service in $services; do
  id="$(container "$service")"
  networks="$(docker inspect -f '{{range $name, $_ := .NetworkSettings.Networks}}{{println $name}}{{end}}' "$id")"
  outside=()
  for network in $networks; do
    [[ "$network" == none ]] && continue
    [[ "$(docker network inspect -f '{{.Internal}}' "$network")" == true ]] || outside+=("${network#"${project}"_}")
  done
  if ((${#outside[@]})); then
    reason="$(awk -F '\t' -v name="$service" '$1 == name { print $2 }' <<<"$edges")"
    if [[ -n "$reason" ]]; then
      pass "${service}: edge on ${outside[*]} (${reason})"
    else
      fail "${service}: joins ${outside[*]}, which can reach beyond the host, and is not an edge service"
    fi
    continue
  fi
  expect "${service}: no default route" "$(in_netns "$service" "$default_route")" no
  expect "${service}: TCP to 1.1.1.1:443 does not connect" "$(in_netns "$service" "$(tcp 1.1.1.1 443)")" no
  expect "${service}: example.com does not resolve" "$(in_netns "$service" "$dns")" no
done
if grep -qx egress-proxy <<<"$services"; then
  expect "egress-proxy reaches 1.1.1.1:443 (its edge route works)" "$(in_netns egress-proxy "$(tcp 1.1.1.1 443)")" yes
  # A CONNECT to a host outside the allowlist: the proxy answers 403 without resolving it.
  connect="$(printf 'timeout 10 bash -c %q' 'exec 3<>/dev/tcp/egress-proxy/3128; printf "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n" >&3; read -r status <&3; [[ "$status" == "HTTP/1.1 403"* ]]')"
  expect "egress-proxy refuses CONNECT example.com:443 (not in its allowlist)" "$(in_netns public-probe "$connect")" yes
  allowed="$(docker run --rm --network none -v "${project}_egress_allowlist:/egress:ro" --entrypoint cat "$probe_image" /egress/allow 2>/dev/null || true)"
  if [[ -n "$allowed" ]]; then pass "egress-proxy allowlist: $(tr '\n' ' ' <<<"$allowed")"
  else fail "egress-proxy allowlist is empty or unreadable"; fi
fi

printf '\nTiers\n'
if grep -qx web <<<"$services"; then
  expect "web -> postgres:5432 does not connect (web is not on the database network)" \
    "$(in_netns web "$(tcp postgres 5432)")" no
fi

printf '\nInternal paths\n'
path() { # FROM HOST PORT
  if grep -qx "$1" <<<"$services"; then
    expect "$1 -> $2:$3" "$(in_netns "$1" "$(tcp "$2" "$3")")" yes
  fi
}
path web backend 8443
path backend postgres 5432
path db-backup postgres 5432
path db-backup backend 8443
path operational-probe postgres 5432
path operational-probe web 8081
path metrics-exporter victoriametrics 8428

# fetch SERVICE URL -> the body an HTTP probe reads in SERVICE's namespace, or empty
fetch() {
  local id
  id="$(container "$1")"
  [[ -n "$id" ]] || return 0
  docker run --rm --network "container:${id}" --user 65534:65534 --entrypoint curl --read-only --cap-drop ALL \
    --security-opt no-new-privileges:true "$probe_image" -fsS --max-time 10 "${@:2}" 2>/dev/null || true
}

if grep -qx victoriametrics <<<"$services"; then
  targets="$(fetch grafana http://victoriametrics:8428/api/v1/targets)"
  summary="$(python3 -c '
import json, sys
try:
    active = json.load(sys.stdin)["data"]["activeTargets"]
except Exception:
    print("unreadable"); sys.exit()
down = sorted({t["labels"].get("job", "?") for t in active if t.get("health") != "up"})
print("down:" + ",".join(down) if down else "up:%d" % len(active))' <<<"$targets")"
  if [[ "$summary" == up:* ]]; then
    pass "every VictoriaMetrics scrape target is up (${summary#up:})"
  else
    fail "VictoriaMetrics scrape targets: ${summary}"
  fi
  # Docker hands container stdout to fluent-bit through the monitoring forwarder; VictoriaLogs holds what arrived.
  logs="$(fetch grafana http://victorialogs:9428/select/logsql/query --data-urlencode 'query=_time:15m | stats count() rows')"
  rows="$(python3 -c 'import json,sys
try: print(int(json.loads(sys.stdin.read().splitlines()[0])["rows"]))
except Exception: print(0)' <<<"$logs")"
  if ((rows > 0)); then pass "fluent-bit delivered ${rows} log lines to VictoriaLogs in the last 15 minutes"
  else fail "no container log lines reached VictoriaLogs through fluent-bit"; fi
fi

printf '\nCredentials\n'
if grep -qx docker-socket-proxy <<<"$services"; then
  guard="$(docker ps -aq --filter "label=com.docker.compose.project=${project}" \
    --filter label=com.docker.compose.service=config-guard | sed -n 1p)"
  if [[ -n "$guard" ]]; then
    inspect="$(fetch cadvisor "http://docker-socket-proxy:2375/containers/${guard}/json")"
    if [[ "$inspect" == *'"Env":[]'* && "$inspect" != *PASSWORD=* && "$inspect" != *SECRET=* ]]; then
      pass "socket proxy returns config-guard's inspect with Env blanked"
    else
      fail "socket proxy inspect of config-guard still carries its environment (or failed)"
    fi
  fi
fi
for id in $(docker ps -aq --filter "label=com.docker.compose.project=${project}"); do
  service="$(docker inspect -f '{{index .Config.Labels "com.docker.compose.service"}}' "$id")"
  grep -qx "$service" <<<"$writers" && continue  # the secret writers copy .env into files
  # Names only; a value is never printed. Empty and the backup image's "**None**" placeholder
  # mean unset.
  names="$(docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$id" |
    grep -E '^[A-Z0-9_]*(PASSWORD|SECRET)=' | grep -vE '=$|=\*\*None\*\*$' | sed 's/=.*//' || true)"
  if [[ -n "$names" ]]; then fail "${service} configuration holds $(tr '\n' ' ' <<<"$names")"
  else pass "${service} configuration holds no credential"; fi
done

printf '\n%s\n' "$([[ $failures -eq 0 ]] && echo "egress proof: PASS" || echo "egress proof: FAIL ($failures)")"
((failures == 0))
