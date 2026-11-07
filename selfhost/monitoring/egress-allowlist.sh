#!/usr/bin/env bash
# Prints egress-proxy's allowlist, one host:port per line (docs/NETWORK-EGRESS.md): the hosts of the
# public URLs public-probe checks and, while it points off this host over HTTPS, the alert
# webhook's. Only the host and port leave this script; a URL's path, which often carries a token,
# never does. Run by render-config.sh (monitoring-config), which writes the result into the
# egress_allowlist volume that egress-proxy mounts read-only.
#
#   PUBLIC_TLS_URL, PUBLIC_HEALTH_URL, CHRONICLE_ALERT_WEBHOOK_URL   (unset or empty: skipped)
set -Eeuo pipefail

# https_target URL: host:port of an https:// URL with no credentials, or nothing (status 1).
https_target() {
  local authority host port
  [[ "$1" =~ ^[Hh][Tt][Tt][Pp][Ss]://([^/?#]+)([/?#].*)?$ ]] || return 1
  authority="${BASH_REMATCH[1]}"
  if [[ "$authority" =~ ^(\[[0-9A-Fa-f:.]+\])(:([0-9]{1,5}))?$ ]] ||
     [[ "$authority" =~ ^([A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?\.?)(:([0-9]{1,5}))?$ ]]; then
    host="${BASH_REMATCH[1],,}"
    port="${BASH_REMATCH[${#BASH_REMATCH[@]}-1]}"
  else
    return 1
  fi
  port="${port:-443}"
  ((10#$port >= 1 && 10#$port <= 65535)) || return 1
  printf '%s:%s\n' "${host%.}" "$((10#$port))"
}

is_loopback() {
  [[ "${1,,}" =~ ^(localhost|.+\.localhost|\[::1\]|127\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}):[0-9]+$ ]]
}

{
  for url in "${PUBLIC_TLS_URL:-}" "${PUBLIC_HEALTH_URL:-}"; do
    [[ -n "$url" ]] || continue
    https_target "$url" || printf 'egress-allowlist: a public URL is not an https:// URL; public-probe cannot check it\n' >&2
  done
  webhook="${CHRONICLE_ALERT_WEBHOOK_URL:-}"
  if [[ -n "$webhook" ]]; then
    if target="$(https_target "$webhook")"; then
      is_loopback "$target" || printf '%s\n' "$target"
    elif [[ ! "$webhook" =~ ^[Hh][Tt][Tt][Pp]://(localhost|[^/@]*\.localhost|\[::1\]|127\.[0-9.]+)([:/?#]|$) ]]; then
      # Never print the URL: its path often carries the receiver's token.
      printf 'egress-allowlist: the alert webhook is not HTTPS (or carries credentials); alerts cannot leave this host until CHRONICLE_ALERT_WEBHOOK_URL is an https:// URL\n' >&2
    fi
  fi
} | awk '!seen[$0]++'
