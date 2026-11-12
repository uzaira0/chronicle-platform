#!/usr/bin/env bash
# Fail if an image, started as it ships, listens on a TCP port it does not declare.
#
#   scripts/check-image-listeners.sh IMAGE [IMAGE ...]
#
# check-image-no-ssh-server.sh finds sshd and Dropbear by file name; a Go or Rust binary that embeds
# an SSH server (or any other remote shell or debug listener) has no such name. This starts each
# image with its own entrypoint and command on `--network none`, so nothing can reach it and it can
# reach nothing, watches /proc/net/tcp and /proc/net/tcp6 in its namespace for CHRONICLE_LISTEN_WATCH
# seconds (default 20), and fails on any listening socket bound to a non-loopback address whose port
# the image does not declare with EXPOSE. Loopback listeners are reported, not refused: no other
# container can reach them. An image that exits at once (it needs configuration it was not given)
# opened nothing while it ran, which is reported.
#
# The sockets are read with the image's own `cat` when it has one, else from a reader container that
# joins the namespace (CHRONICLE_LISTEN_READER, default the Alpine digest Dockerfile.grafana pins).
set -euo pipefail

[[ $# -gt 0 ]] || { echo 'usage: check-image-listeners.sh IMAGE [IMAGE ...]' >&2; exit 2; }
command -v docker >/dev/null 2>&1 || { echo 'error: docker is required to start the images' >&2; exit 127; }

watch_seconds="${CHRONICLE_LISTEN_WATCH:-20}"
[[ "$watch_seconds" =~ ^[1-9][0-9]*$ ]] || { echo 'error: CHRONICLE_LISTEN_WATCH must be whole seconds' >&2; exit 2; }
reader="${CHRONICLE_LISTEN_READER:-alpine:3.24@sha256:3f4d6b32e26703c6082839234f43769d5046b3ac7c910033911d1e71d8cd630a}"

# sockets ID -> the namespace's /proc/net/tcp and tcp6 tables, or nothing once the container stopped
sockets() {
  docker exec "$1" cat /proc/net/tcp /proc/net/tcp6 2>/dev/null ||
    docker run --rm --network "container:$1" --entrypoint cat "$reader" /proc/net/tcp /proc/net/tcp6 2>/dev/null || true
}

# listeners: "ADDRESS PORT" for each socket in state 0A (LISTEN) of the tables on stdin.
listeners() {
  local local_address state address port
  while read -r _ local_address _ state _; do
    [[ "$state" == 0A && "$local_address" == *:* ]] || continue
    address="${local_address%:*}"
    port=$((16#${local_address#*:}))
    case "$address" in
      0100007F | 00000000000000000000000001000000) echo "loopback $port" ;;
      *) echo "any $port" ;;
    esac
  done
}

status=0
for image in "$@"; do
  [[ -n "$image" && "$image" != -* && "$image" != *[[:space:]]* ]] || {
    echo 'error: expected an image reference without whitespace or a leading hyphen' >&2
    exit 2
  }
  declared=" $(docker image inspect -f '{{range $port, $_ := .Config.ExposedPorts}}{{$port}} {{end}}' "$image") "
  if ! container=$(docker run -d --network none --memory 1g --pids-limit 512 "$image" 2>/dev/null); then
    printf 'no listener in %s: it does not start without a command (nothing to run)\n' "$image" >&2
    continue
  fi
  seen=""
  for ((second = 0; second < watch_seconds; second++)); do
    [[ "$(docker inspect -f '{{.State.Running}}' "$container")" == true ]] || break
    seen+="$(sockets "$container" | listeners)"$'\n'
    sleep 1
  done
  running="$(docker inspect -f '{{.State.Running}}' "$container")"
  docker rm -fv "$container" >/dev/null
  undeclared=() loopback=() exposed=()
  while read -r scope port; do
    [[ -n "$port" ]] || continue
    if [[ "$scope" == loopback ]]; then
      loopback+=("$port")
    elif [[ "$declared" != *" ${port}/tcp "* ]]; then
      undeclared+=("$port")
    else
      exposed+=("$port")
    fi
  done < <(sort -u <<<"$seen")
  if ((${#undeclared[@]})); then
    printf 'error: %s listens on undeclared TCP port(s) %s (EXPOSE declares:%s); remove the listener or declare it\n' \
      "$image" "${undeclared[*]}" "${declared% }" >&2
    status=1
  else
    printf 'no undeclared listener in %s (%s; declared: %s; loopback only: %s)\n' "$image" \
      "$([[ "$running" == true ]] && echo "ran ${watch_seconds} s" || echo 'exited before the watch ended')" \
      "${exposed[*]:-none}" "${loopback[*]:-none}" >&2
  fi
done
exit "$status"
