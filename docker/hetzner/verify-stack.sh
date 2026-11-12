#!/usr/bin/env bash
set -euo pipefail

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
compose=(podman compose -f "$script_dir/compose.yml")
domain=dev-vps.example.ts.net
bind_port=${CHRONICLE_BIND_PORT:-18082}
crowdsec_log_path=${CHRONICLE_STATE_DIR:?Set CHRONICLE_STATE_DIR}/audit-logs/crowdsec/crowdsec.log

services=$("${compose[@]}" config --services | sort | tr '\n' ' ')
[[ "$services" == "backend crowdsec postgres traefik " ]] || {
  echo "unexpected services in backend-only stack: $services" >&2
  exit 1
}

"${compose[@]}" ps
for service in postgres backend crowdsec traefik; do
  cid=$(podman ps \
    --filter label=io.podman.compose.project=chronicle-next \
    --filter label="io.podman.compose.service=$service" \
    --filter status=running \
    --format '{{.ID}}')
  cid_count=$(grep -c . <<<"$cid" || true)
  (( cid_count == 1 ))
  inspect=$(podman inspect "$cid")
  jq -e '.[0].HostConfig.ReadonlyRootfs == true' <<<"$inspect" >/dev/null
  jq -e '.[0].HostConfig.SecurityOpt | index("no-new-privileges") != null' <<<"$inspect" >/dev/null
  case "$service" in
    postgres)
      expected_caps='["CAP_CHOWN","CAP_DAC_OVERRIDE","CAP_FOWNER","CAP_SETGID","CAP_SETUID"]'
      ;;
    backend)
      expected_caps='["CAP_CHOWN","CAP_DAC_OVERRIDE","CAP_SETGID","CAP_SETUID"]'
      ;;
    crowdsec)
      expected_caps='["CAP_CHOWN","CAP_SETGID","CAP_SETUID"]'
      ;;
    traefik)
      expected_caps='[]'
      ;;
  esac
  # Podman expands cap_drop: ALL instead of retaining a literal ALL marker in
  # HostConfig.CapDrop. Assert the actual runtime sets exactly instead.
  jq -e --argjson expected "$expected_caps" '
    ((.[0].EffectiveCaps // []) | sort) == ($expected | sort) and
    ((.[0].BoundingCaps // []) | sort) == ($expected | sort)
  ' <<<"$inspect" >/dev/null
  jq -e '.[0].HostConfig.Memory > 0 and .[0].HostConfig.PidsLimit > 0' <<<"$inspect" >/dev/null
  if [[ "$service" == backend ]]; then
    jq -e '
      [
        .[0].Mounts[]
        | select(.Destination == "/var/lib/chronicle/exports")
        | select((.Type == "bind" or .Type == "volume") and .RW == true)
      ] | length == 1
    ' <<<"$inspect" >/dev/null
    podman exec --user chronicle "$cid" test -w /var/lib/chronicle/exports
  fi
  case "$service" in
    crowdsec)
      jq -e --arg path "$crowdsec_log_path" '
        .[0].HostConfig.LogConfig as $log
        | $log.Type == "k8s-file"
          and $log.Path == $path
          and ($log.Size | test("^[1-9][0-9]*(\\.[0-9]+)?[KMG]?B$"))
      ' <<<"$inspect" >/dev/null
      ;;
    *)
      jq -e '.[0].HostConfig.LogConfig.Type != "k8s-file"' <<<"$inspect" >/dev/null
      ;;
  esac

  # Root is allowed only as a bounded bootstrap identity. The steady-state
  # main process must be non-root and must have no effective/permitted caps.
  pid=$(jq -er '.[0].State.Pid | select(. > 0)' <<<"$inspect")
  status_file="/proc/$pid/status"
  [[ -r "$status_file" ]]
  awk '
    /^Uid:/ {
      for (i = 2; i <= 5; i++) {
        if ($i == 0) exit 1
      }
      uid_ok = 1
    }
    /^CapPrm:/ { if ($2 != "0000000000000000") exit 1; permitted_ok = 1 }
    /^CapEff:/ { if ($2 != "0000000000000000") exit 1; effective_ok = 1 }
    END { exit !(uid_ok && permitted_ok && effective_ok) }
  ' "$status_file"
done

[[ -f "$crowdsec_log_path" && ! -L "$crowdsec_log_path" ]] || {
  echo "CrowdSec k8s-file log is missing or is a symlink: $crowdsec_log_path" >&2
  exit 1
}

mapfile -t listen_addresses < <(ss -ltnH "sport = :$bind_port" | awk '{ print $4 }')
(( ${#listen_addresses[@]} > 0 ))
for listen_address in "${listen_addresses[@]}"; do
  [[ "$listen_address" == "127.0.0.1:$bind_port" ]] || {
    echo "Chronicle listener is not loopback-only: $listen_address" >&2
    exit 1
  }
done

proxy_curl=(curl --silent --show-error --fail --http1.1 \
  --haproxy-protocol --resolve "$domain:$bind_port:127.0.0.1")
proxy_base_url="http://$domain:$bind_port"
"${proxy_curl[@]}" "$proxy_base_url/health" | grep '^OK$' >/dev/null

for forbidden in / /chronicle /prometheus/ /chronicle/v3/auth /chronicle/api/web/; do
  code=$(curl --silent --output /dev/null --write-out '%{http_code}' --http1.1 \
    --haproxy-protocol --resolve "$domain:$bind_port:127.0.0.1" \
    "http://$domain:$bind_port$forbidden")
  [[ "$code" == 404 ]] || {
    echo "forbidden route $forbidden returned $code" >&2
    exit 1
  }
done

# Exercise the actual mobile router and its middleware chain, not /health (the
# health router intentionally omits AppSec). The exact FreeMarker marker is an
# in-band CrowdSec rule and must be rejected before the unsigned request can
# reach Chronicle. An internal-web header supplied by a client must not bypass
# mobile HMAC authentication.
mobile_probe_path=/chronicle/v4/study/00000000-0000-0000-8000-00000000000b/participant/hetzner-s5/enroll
waf_code=$(curl --silent --output /dev/null --write-out '%{http_code}' --http1.1 \
  --haproxy-protocol --resolve "$domain:$bind_port:127.0.0.1" \
  --header 'content-type: application/json' \
  --data '{"probe":"freemarker.template.utility.Execute"}' \
  "$proxy_base_url$mobile_probe_path")
[[ "$waf_code" == 403 ]] || {
  echo "CrowdSec in-band AppSec probe returned $waf_code, expected 403" >&2
  exit 1
}

for extra_header in '' 'X-Chronicle-Internal-Web: true'; do
  curl_args=(--silent --output /dev/null --write-out '%{http_code}' --http1.1
    --haproxy-protocol --resolve "$domain:$bind_port:127.0.0.1"
    --header 'content-type: application/json' --data '{}')
  [[ -z "$extra_header" ]] || curl_args+=(--header "$extra_header")
  unsigned_code=$(curl "${curl_args[@]}" "$proxy_base_url$mobile_probe_path")
  [[ "$unsigned_code" == 401 ]] || {
    echo "unsigned/spoofed mobile probe returned $unsigned_code, expected 401" >&2
    exit 1
  }
done

# The backend is reachable only from the private Podman edge network. Host-side
# access to its fixed container address must fail; Traefik is the sole ingress.
direct_code=$(curl --silent --connect-timeout 2 --output /dev/null \
  --write-out '%{http_code}' http://10.89.40.3:40320/prometheus/ 2>/dev/null || true)
[[ -z "$direct_code" || "$direct_code" == 000 ]] || {
  echo "Chronicle backend was directly reachable from the host: HTTP $direct_code" >&2
  exit 1
}

echo "backend-only Chronicle perimeter verified on 127.0.0.1:$bind_port"
