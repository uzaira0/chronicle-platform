# shellcheck shell=bash
# k6_latency_budget_mode CONTAINER prints the K6_LATENCY_BUDGETS mode for a backend container
# (tests/load/latency-budgets.js): "gate" when its image is built for the Docker host's OS and CPU
# architecture, otherwise "record IMAGE_PLATFORM HOST_PLATFORM", because the backend then runs under
# emulation and its latency measures the emulator. Fails when either platform cannot be read.
k6_latency_budget_mode() {
  local image_id image host
  image_id="$(docker inspect --format '{{.Image}}' "$1")" || return 1
  image="$(docker image inspect --format '{{.Os}}/{{.Architecture}}' "$image_id")" || return 1
  host="$(docker version --format '{{.Server.Os}}/{{.Server.Arch}}')" || return 1
  [[ "$image" == */?* && "$host" == */?* ]] || return 1
  if [[ "$image" == "$host" ]]; then
    printf 'gate\n'
  else
    printf 'record %s %s\n' "$image" "$host"
  fi
}
