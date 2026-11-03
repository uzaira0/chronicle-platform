#!/usr/bin/env bash
# Pure-shell IP normalization, usable by the PostgreSQL-based configuration jobs.
address_bits() {
  local address="${1#[}" part value bit left right zeros word
  address="${address%]}"
  local -a parts=() before=() after=()
  if [[ "$address" == *.* && "$address" != *:* ]]; then
    [[ "$address" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || return 1
    IFS=. read -r -a parts <<< "$address"
    printf '4 '
    for part in "${parts[@]}"; do
      value=$((10#$part)); ((value <= 255)) || return 1
      for ((bit=7; bit>=0; bit--)); do printf '%d' "$(((value >> bit) & 1))"; done
    done
  else
    address="$(printf '%s' "$address" | tr '[:upper:]' '[:lower:]')"
    # IPv4-mapped addresses are not accepted as private listener addresses.
    [[ "$address" == *:* && "$address" != *[^0-9a-f:]* && "$address" != *:::* ]] || return 1
    if [[ "$address" == *::* ]]; then
      left="${address%%::*}"; right="${address#*::}"
      [[ "$right" != *::* ]] || return 1
      [[ -z "$left" ]] || IFS=: read -r -a before <<< "$left"
      [[ -z "$right" ]] || IFS=: read -r -a after <<< "$right"
      zeros=$((8 - ${#before[@]} - ${#after[@]})); ((zeros > 0)) || return 1
      parts=("${before[@]}")
      for ((word=0; word<zeros; word++)); do parts+=(0); done
      parts+=("${after[@]}")
    else
      [[ "$address" != :* && "$address" != *: ]] || return 1
      IFS=: read -r -a parts <<< "$address"
      ((${#parts[@]} == 8)) || return 1
    fi
    printf '6 '
    for part in "${parts[@]}"; do
      [[ "$part" =~ ^[0-9a-f]{1,4}$ ]] || return 1
      value=$((16#$part))
      for ((bit=15; bit>=0; bit--)); do printf '%d' "$(((value >> bit) & 1))"; done
    done
  fi
  printf '\n'
}

specific_private_bind() {
  local normalized family bits
  normalized="$(address_bits "$1")" || return 1
  read -r family bits <<< "$normalized"
  if [[ "$family" == 4 ]]; then
    case "$bits" in
      0110010001*|00001010*|01111111*|101011000001*|1100000010101000*|1010100111111110*) return 0 ;;
    esac
  else
    case "$bits" in 1111110*|1111111010*) return 0 ;; esac
    [[ "$bits" == "$(printf '%0127d' 0)1" ]] && return 0
  fi
  return 1
}

validate_dashboard_networks() (
  set -o pipefail
  local cidr address mask normalized family bits max
  [[ -n "$1" ]] || return 1
  (
    for cidr in $1; do
      address="${cidr%/*}"; mask="${cidr#*/}"
      [[ "$cidr" == */* && "$mask" =~ ^[0-9]{1,3}$ ]] || exit 1
      normalized="$(address_bits "$address")" || exit 1
      read -r family bits <<< "$normalized"
      max=${#bits}; mask=$((10#$mask)); ((mask <= max)) || exit 1
      printf '%s:%s\n' "$family" "${bits:0:mask}"
    done
  ) | awk '
    {
      family=substr($0,1,1); prefix=substr($0,3); seen[family ":" prefix]=1
      while (length(prefix)) {
        parent=substr(prefix,1,length(prefix)-1)
        last=substr(prefix,length(prefix),1)
        sibling=parent (last == "0" ? "1" : "0")
        if (!seen[family ":" sibling]) break
        prefix=parent; seen[family ":" prefix]=1
      }
    }
    END { if (seen["4:"] || seen["6:"]) exit 1 }
  '
)

grafana_base_url() {
  local host="${GRAFANA_BIND:-127.0.0.1}"
  [[ "$host" == 0.0.0.0 ]] && host=127.0.0.1
  [[ "$host" == *:* && "$host" != \[*\] ]] && host="[$host]"
  printf 'https://%s:%s' "$host" "${GRAFANA_PORT:-3000}"
}

loopback_networks() {
  local cidr normalized family bits mask
  [[ -n "$1" ]] || return 1
  for cidr in $1; do
    normalized="$(address_bits "${cidr%/*}")" || return 1
    read -r family bits <<< "$normalized"
    mask="${cidr#*/}"
    [[ "$mask" =~ ^[0-9]{1,3}$ ]] || return 1
    if [[ "$family" == 4 ]]; then
      [[ "$bits" == 01111111* ]] && ((10#$mask >= 8 && 10#$mask <= 32)) || return 1
    else
      [[ "$bits" == "$(printf '%0127d' 0)1" && "$mask" == 128 ]] || return 1
    fi
  done
}

# Direct listeners have no proxy asserting identity. A remote LB must be named explicitly;
# the loopback listener alone can safely use Docker's host gateway as its proxy source.
trusted_proxy_sources() {
  local mode="$1" bind="$2" gateway="$3" configured="$4"
  if [[ "$mode" != behind-proxy ]]; then
    printf '%s\n' '127.0.0.1/32'
  elif [[ "$bind" == 127.* || "$bind" == ::1 ]]; then
    printf '%s\n' "${configured:-$gateway/32}"
  elif [[ -n "$configured" && "$configured" != "$gateway/32" ]] &&
      ! loopback_networks "$configured" && validate_dashboard_networks "$configured"; then
    printf '%s\n' "$configured"
  else
    return 1
  fi
}
