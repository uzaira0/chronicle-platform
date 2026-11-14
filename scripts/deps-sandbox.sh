#!/usr/bin/env bash
# Run a command over a source tree inside the dependency sandbox.
#
#   scripts/deps-sandbox.sh [--image deps|jdk|go|gate | --base-image REPOSITORY[:TAG]@sha256:DIGEST]
#                           [--network none|registries|browsers|gomodules] [--platform linux/amd64|linux/arm64]
#                           [--mount /HOST:/CONTAINER[:ro]]... [--env NAME=VALUE]... SOURCE -- COMMAND...
#
# Images:
#   deps (default)  scripts/sandbox/Dockerfile.deps: Bun, Python, the scan tools.
#   jdk             scripts/sandbox/Dockerfile.jdk: the JDK docker/Dockerfile.backend builds with (same
#                   digest, read from that file) plus git, for Gradle lock and verification-metadata
#                   regeneration, which executes the build's plugins.
#   go              selfhost/Dockerfile.backup's digest-pinned Go builder image as it is, for go mod tidy.
#   gate            scripts/sandbox/Dockerfile.gate: what the dependency gate runner's local-ci jobs need
#                   (the backend JDK, Bun, git, Python, semgrep, ruff, shellcheck, gitleaks, yq).
# --base-image REF runs a digest-pinned image as it is, as root with only CHOWN, DAC_OVERRIDE, FOWNER,
#                   SETGID and SETUID (apt drops to its _apt user to download) and without the shared
#                   cache volume: scripts/os-package-pins.py resolving apt pins inside a Dockerfile's own
#                   base image.
# The sandbox images install their OS packages through selfhost/os-packages/ (the os-packages build
# context), at exact versions older than the dependency wait, as the release images do.
# --jdk is --image jdk; --offline is --network none. --platform builds and runs the image for that
# platform instead of the host's (the gate's fuzz job: Jazzer has no linux/aarch64 native library).
#
# Dependency installs execute code a package publisher wrote (Gradle plugins, build and test code,
# any install hook a package manager runs), and scans read whatever the install fetched. The sandbox
# gets SOURCE at /work and nothing else from the host: no inherited environment (only the --env values
# given here), no Docker socket or ~/.docker credentials, no SSH agent, no home directory, no
# GHCR_TOKEN or gh token, all capabilities dropped, no privilege escalation.
#
# Network:
#   none (default)  no network at all: tests and builds.
#   registries      the container joins an internal Docker network (no gateway; its resolver knows only
#                   container names) whose one other member is scripts/sandbox/egress-proxy.py, which
#                   forwards HTTPS CONNECT to the hosts in scripts/sandbox/egress-allowlist.txt and
#                   refuses the rest. The container gets HTTPS_PROXY and the JVM proxy properties.
#                   Installs, lockfile regeneration and the scanners' databases.
#   browsers        registries plus the hosts in scripts/sandbox/egress-allowlist-browsers.txt: only the
#                   gate runner's `playwright install chromium-headless-shell`, whose Chrome for Testing
#                   builds redirect to storage.googleapis.com.
#   gomodules       registries plus scripts/sandbox/egress-allowlist-gomodules.txt (storage.googleapis.com,
#                   where proxy.golang.org redirects the zip of a large module), and only with --image go:
#                   scripts/deps-regenerate.py's `go mod tidy`. The Go toolchain downloads modules and checks
#                   them against sum.golang.org; it runs none of their code. storage.googleapis.com serves
#                   every public bucket, so no image that installs or runs dependency code gets it apart
#                   from the browsers step above.
#
# Caches live in the named volume chronicle-deps-sandbox-cache, which holds only downloaded packages
# and tools. Exit status is the command's.
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
image=deps
network=none
platform=''
mounts=()
envs=(-e HOME=/home/bun -e CI=1 -e BUN_INSTALL_CACHE_DIR=/cache/bun -e GRADLE_USER_HOME=/cache/gradle
      -e CHRONICLE_LOCAL_BIN_DIR=/cache/bin -e PLAYWRIGHT_BROWSERS_PATH=/cache/ms-playwright)
base_image=''
usage='usage: scripts/deps-sandbox.sh [--image deps|jdk|go|gate | --base-image REF@sha256:DIGEST] [--network none|registries|browsers|gomodules] [--platform linux/amd64|linux/arm64] [--mount /HOST:/CONTAINER[:ro]]... [--env NAME=VALUE]... SOURCE -- COMMAND...'
while [[ $# -gt 0 ]]; do
  case "$1" in
    --image)
      [[ "${2:-}" =~ ^(deps|jdk|go|gate)$ ]] || { echo "deps-sandbox: --image takes deps, jdk, go or gate" >&2; exit 2; }
      image=$2; shift 2 ;;
    --jdk) image=jdk; shift ;;
    --base-image)
      [[ "${2:-}" =~ ^[a-z0-9][a-z0-9._/:-]*@sha256:[0-9a-f]{64}$ ]] || {
        echo 'deps-sandbox: --base-image takes a reference pinned by digest (REPOSITORY[:TAG]@sha256:DIGEST)' >&2; exit 2; }
      image=base; base_image=$2; shift 2 ;;
    --network)
      [[ "${2:-}" =~ ^(none|registries|browsers|gomodules)$ ]] || { echo 'deps-sandbox: --network takes none, registries, browsers or gomodules' >&2; exit 2; }
      network=$2; shift 2 ;;
    --offline) network=none; shift ;;
    --platform)
      [[ "${2:-}" =~ ^linux/(amd64|arm64)$ ]] || { echo 'deps-sandbox: --platform takes linux/amd64 or linux/arm64' >&2; exit 2; }
      platform=$2; shift 2 ;;
    --mount)
      [[ "${2:-}" =~ ^/[^:]+:/[^:]+(:ro)?$ ]] || { echo 'deps-sandbox: --mount takes /host/path:/container/path[:ro]' >&2; exit 2; }
      case "${2%%:*}" in
        /var/run/docker.sock|*/docker.sock|"$HOME"|"$HOME"/.docker*|"$HOME"/.ssh*|"$HOME"/.config*)
          echo "deps-sandbox: refusing to mount ${2%%:*} into the sandbox" >&2; exit 2 ;;
      esac
      mounts+=(-v "$2"); shift 2 ;;
    --env)
      [[ "${2:-}" =~ ^[A-Z_][A-Z0-9_]*=.*$ ]] || { echo 'deps-sandbox: --env takes NAME=VALUE' >&2; exit 2; }
      case "${2%%=*}" in
        *TOKEN*|*SECRET*|*PASSWORD*|*KEY*|SSH_AUTH_SOCK|DOCKER_*|HTTP*_PROXY|JAVA_TOOL_OPTIONS)
          echo "deps-sandbox: refusing to pass ${2%%=*} into the sandbox" >&2; exit 2 ;;
      esac
      envs+=(-e "$2"); shift 2 ;;
    --) shift; break ;;
    -*) echo "deps-sandbox: unknown option $1" >&2; exit 2 ;;
    *) source_dir=$1; shift ;;
  esac
done
[[ -n "${source_dir:-}" && -d "$source_dir" && $# -gt 0 ]] || { echo "$usage" >&2; exit 2; }
source_dir=$(cd "$source_dir" && pwd -P)
[[ "$network" != gomodules || "$image" == go ]] || { echo 'deps-sandbox: --network gomodules takes --image go only' >&2; exit 2; }

# Build an image from a Dockerfile in scripts/sandbox, tagged by the hash of its inputs (the Dockerfile,
# the OS-package helpers it mounts from the os-packages context, the build arguments) so an edited
# Dockerfile, helper or moved pin always rebuilds.
build() { # build <name> <dockerfile> [--build-arg NAME=VALUE]...
  local name=$1 dockerfile=$2 tag
  shift 2
  [[ -z "$platform" ]] || set -- "$@" --platform "$platform"
  tag="$name:$( { cat "$dockerfile" "$root"/selfhost/os-packages/*.sh; printf '%s\n' "$@"; } | shasum -a 256 | cut -c1-16)"
  if ! docker image inspect "$tag" >/dev/null 2>&1; then
    # Command substitution does not inherit set -e: a failed build must stop here, not leave a tag
    # that `docker run` then tries to pull.
    docker build --quiet "$@" --build-context "os-packages=$root/selfhost/os-packages" \
      -t "$tag" -f "$dockerfile" "$root/scripts/sandbox" >/dev/null ||
      { echo "deps-sandbox: could not build $tag from ${dockerfile#"$root"/}" >&2; return 1; }
  fi
  printf '%s' "$tag"
}
manifest_value() { sed -nE "s/^$1: \"([^\"]+)\".*/\\1/p" "$root/toolchain-manifest.yaml"; }
from_line() { # from_line <file> <pattern>: the digest-pinned image of the matching FROM line
  sed -nE "s/^FROM ($2@sha256:[0-9a-f]{64}) AS builder$/\\1/p" "$1"
}
# The JDK images' `ARG JDK_IMAGE=` default is what scripts/os-package-pins.py resolves their apt pins
# against, and the build gets docker/Dockerfile.backend's builder: they must be the same image.
require_jdk_default() { # require_jdk_default <dockerfile> <image>
  local default
  default=$(sed -nE 's/^ARG JDK_IMAGE=(.+)$/\1/p' "$1")
  [[ "$default" == "$2" ]] || {
    echo "deps-sandbox: ${1#"$root"/} ARG JDK_IMAGE=${default:-<none>} is not docker/Dockerfile.backend's builder $2" >&2
    exit 1
  }
}

user=(--user 1000:1000)
home=/home/bun
case "$image" in
  deps)
    tag=$(build chronicle-deps-sandbox "$root/scripts/sandbox/Dockerfile.deps") ;;
  jdk|gate)
    jdk_image=$(from_line "$root/docker/Dockerfile.backend" 'eclipse-temurin:[^ ]+')
    [[ -n "$jdk_image" ]] || { echo 'deps-sandbox: no digest-pinned eclipse-temurin builder in docker/Dockerfile.backend' >&2; exit 1; }
    require_jdk_default "$root/scripts/sandbox/Dockerfile.$image" "$jdk_image"
    if [[ "$image" == jdk ]]; then
      tag=$(build chronicle-deps-sandbox-jdk "$root/scripts/sandbox/Dockerfile.jdk" --build-arg "JDK_IMAGE=$jdk_image")
      # The JDK image has no passwd entry for 1000, so the JVM gets its home explicitly.
      home=/home/sandbox
    else
      semgrep=$(manifest_value semgrep)
      [[ -n "$semgrep" ]] || { echo 'deps-sandbox: toolchain-manifest.yaml has no semgrep pin' >&2; exit 1; }
      tag=$(build chronicle-deps-sandbox-gate "$root/scripts/sandbox/Dockerfile.gate" \
        --build-arg "JDK_IMAGE=$jdk_image" --build-arg "SEMGREP_VERSION=$semgrep")
    fi ;;
  go)
    tag=$(from_line "$root/selfhost/Dockerfile.backup" 'golang:[^ ]+')
    [[ -n "$tag" ]] || { echo 'deps-sandbox: no digest-pinned golang builder in selfhost/Dockerfile.backup' >&2; exit 1; }
    home=/home/sandbox
    envs+=(-e GOPATH=/cache/go -e GOMODCACHE=/cache/go/mod -e GOCACHE=/cache/go/build -e GOTOOLCHAIN=local
           -e GOFLAGS=-mod=mod -e GONOSUMDB= -e GOPRIVATE= -e GOPROXY=https://proxy.golang.org
           -e GOSUMDB=sum.golang.org) ;;
  base)
    tag=$base_image
    envs=(-e HOME=/root -e CI=1)  # no cache volume, so none of the cache locations
    user=(--user 0:0 --cap-add CHOWN --cap-add DAC_OVERRIDE --cap-add FOWNER --cap-add SETGID --cap-add SETUID)
    home=/root ;;
esac
# Same uid as the deps image's bun user, which owns the shared /cache volume: with every capability
# dropped, root could not write into it.
envs=("${envs[@]/HOME=\/home\/bun/HOME=$home}")
java_options="-Duser.home=$home"

id="chronicle-deps-$$-$RANDOM"
proxy=''
cleanup() {
  [[ -z "$proxy" ]] || docker rm -fv "$proxy" >/dev/null 2>&1 || true
  if [[ "$network" != none ]]; then
    docker network rm "$id-internal" "$id-egress" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT
# create_network NAME DEFAULT_SUBNET [OPTION...] creates a Docker network on a chosen subnet
# (selfhost/network-subnet.py select: DEFAULT_SUBNET when it overlaps no Docker network and no host
# route, else the first free 10.253.N.0/24), not one from Docker's default address pools. A host
# that runs many Compose projects has none of those left, and the sandbox must still start there.
# Another sandbox can take the chosen subnet between the choice and the create, so both are tried again.
create_network() {
  local name=$1 default=$2 subnet error=''
  shift 2
  for _ in 1 2 3 4 5; do
    subnet=$(python3 "$root/selfhost/network-subnet.py" select "$default" "$name") || break
    error=$(docker network create --subnet "$subnet" "$@" "$name" 2>&1 >/dev/null) && return 0
  done
  echo "deps-sandbox: could not create the network $name${error:+: $error}" >&2
  return 1
}
network_args=(--network none)
allowlists=(--allowlist /proxy/allowlist.txt)
proxy_mounts=(-v "$root/scripts/sandbox/egress-allowlist.txt:/proxy/allowlist.txt:ro")
if [[ "$network" == browsers ]]; then
  allowlists+=(--allowlist /proxy/allowlist-browsers.txt)
  proxy_mounts+=(-v "$root/scripts/sandbox/egress-allowlist-browsers.txt:/proxy/allowlist-browsers.txt:ro")
fi
if [[ "$network" == gomodules ]]; then
  allowlists+=(--allowlist /proxy/allowlist-gomodules.txt)
  proxy_mounts+=(-v "$root/scripts/sandbox/egress-allowlist-gomodules.txt:/proxy/allowlist-gomodules.txt:ro")
fi
if [[ "$network" != none ]]; then
  proxy_tag=$(platform='' build chronicle-deps-sandbox "$root/scripts/sandbox/Dockerfile.deps")
  create_network "$id-internal" 10.251.9.0/24 --internal
  create_network "$id-egress" 10.251.10.0/24
  proxy="$id-proxy"
  docker run -d --name "$proxy" --network "$id-egress" --cap-drop ALL --security-opt no-new-privileges \
    --read-only --pids-limit 256 --user 1000:1000 \
    -v "$root/scripts/sandbox/egress-proxy.py:/proxy/egress-proxy.py:ro" \
    "${proxy_mounts[@]}" \
    "$proxy_tag" python3 /proxy/egress-proxy.py "${allowlists[@]}" --port 3128 >/dev/null
  docker network connect --alias egress-proxy "$id-internal" "$proxy"
  network_args=(--network "$id-internal")
  for variable in HTTPS_PROXY HTTP_PROXY https_proxy http_proxy; do envs+=(-e "$variable=http://egress-proxy:3128"); done
  envs+=(-e 'NO_PROXY=localhost,127.0.0.1' -e 'no_proxy=localhost,127.0.0.1')
  java_options+=" -Dhttps.proxyHost=egress-proxy -Dhttps.proxyPort=3128 -Dhttp.proxyHost=egress-proxy"
  java_options+=" -Dhttp.proxyPort=3128 -Dhttp.nonProxyHosts=localhost|127.0.0.1"
fi
[[ "$image" == deps || "$image" == base ]] || envs+=(-e "JAVA_TOOL_OPTIONS=$java_options")
# Only the sandbox's own images share the package cache; a base image run as root never writes into it.
cache=(-v chronicle-deps-sandbox-cache:/cache)
[[ "$image" != base ]] || cache=()

user_id=1000
[[ "$image" != base ]] || user_id=0
status=0
platform_args=()
[[ -z "$platform" ]] || platform_args=(--platform "$platform")
docker run --rm --init ${platform_args[@]+"${platform_args[@]}"} "${network_args[@]}" \
  --cap-drop ALL --security-opt no-new-privileges --pids-limit 4096 "${user[@]}" \
  --tmpfs /tmp:rw,exec,size=4g --tmpfs "$home:rw,exec,size=1g,uid=${user_id},gid=${user_id}" \
  ${cache[@]+"${cache[@]}"} \
  -v "$source_dir:/work" ${mounts[@]+"${mounts[@]}"} -w /work \
  "${envs[@]}" "$tag" "$@" || status=$?
if [[ "$status" -ne 0 && -n "$proxy" ]]; then
  # What the command tried to reach and was refused, for the log of a failed step.
  docker logs "$proxy" 2>&1 | grep -E '^(deny|fail) ' | sort | uniq -c | sed 's/^/deps-sandbox: proxy /' >&2 || true
fi
exit "$status"
