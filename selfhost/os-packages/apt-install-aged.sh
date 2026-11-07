#!/bin/sh
# Install (or download) Debian/Ubuntu packages only at exact versions that have passed the dependency
# wait (docs/SUPPLY-CHAIN.md).
#
#   apt-install-aged.sh DISTRO SNAPSHOT [--https] [--download] [--add NAME...] [--pin NAME=VERSION...] [--upgrade NAME=VERSION...]
#   apt-install-aged.sh DISTRO SNAPSHOT [--https] --resolve NAME...
#
# DISTRO is the base image's /etc/os-release ID (debian, ubuntu). SNAPSHOT (YYYYMMDDTHHMMSSZ) is a
# snapshot.debian.org / snapshot.ubuntu.com timestamp at which every pin was in the archive: the source
# once the live mirror has replaced a pin. It does not set the age; each pin is aged on its own.
# --add names what the stage needs; --pin fixes the exact version of each package the base lacks
# and --upgrade of each newer version of one the base has (apt upgrades a base package only when a
# new package depends on the newer version). scripts/os-package-pins.py writes the pins: it
# resolves --add against the snapshot taken one wait period ago (--resolve, which prints `pin` and
# `upgrade` lines), so every version it pins was published before that moment, and the age gate
# checks each changed pin against snapshot first_seen (Debian) or Launchpad date_published (Ubuntu).
# With --download the pinned packages are downloaded into the working directory, not installed.
# With --https the snapshot is fetched over HTTPS, through HTTPS_PROXY when that is set: the dependency
# sandbox's egress proxy (scripts/sandbox/egress-proxy.py) forwards only CONNECT to port 443, and
# scripts/os-package-pins.py resolves through it (the caller provides /etc/ssl/certs/ca-certificates.crt).
#
# On a non-amd64 Ubuntu host the live ports mirror is the only source (snapshot.ubuntu.com has no ports).
# The live mirror keeps only the newest version of a package; the snapshot keeps every version. Both
# are configured, so a pin installs from the live mirror while it is current and from the snapshot
# once it is not, and the build still works while either service is down. Fails closed: a pin that
# neither source has fails the build, and after an install every package must be at its base version
# or at a pinned version.
set -eu

usage() { echo 'usage: apt-install-aged.sh DISTRO SNAPSHOT [--https] [--download] [--add NAME...] [--pin|--upgrade NAME=VERSION...] | [--https] --resolve NAME...' >&2; exit 2; }
[ $# -ge 3 ] || usage
distro=$1 snapshot=$2
shift 2
case "$snapshot" in
  [0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]T[0-9][0-9][0-9][0-9][0-9][0-9]Z) ;;
  *) echo "apt-install-aged: snapshot must be YYYYMMDDTHHMMSSZ, not $snapshot" >&2; exit 2 ;;
esac
# shellcheck disable=SC1091 # the base image's
id=$(. /etc/os-release && echo "$ID")
[ "$id" = "$distro" ] || { echo "apt-install-aged: the base image is $id, the pins are for $distro" >&2; exit 1; }

mode=install download='' https='' section='' wanted='' pins='' upgrades=''
for word in "$@"; do
  case "$word" in
    --https) https=1 ;;
    --download) download=1; [ "$mode" = resolve ] || mode=download ;;
    --resolve) mode=resolve; section=add ;;
    --add) section=add ;;
    --pin) section=pin ;;
    --upgrade) section=upgrade ;;
    -*) usage ;;
    *)
      case "$section" in
        add) wanted="$wanted $word" ;;
        pin) case "$word" in *=*) pins="$pins $word" ;; *) usage ;; esac ;;
        upgrade) case "$word" in *=*) upgrades="$upgrades $word" ;; *) usage ;; esac ;;
        *) usage ;;
      esac ;;
  esac
done

scheme=http
[ -z "$https" ] || scheme=https
case "$distro" in
  debian) snapshot_url="$scheme://snapshot.debian.org/archive" ;;
  ubuntu) snapshot_url="$scheme://snapshot.ubuntu.com" ;;
  *) echo "apt-install-aged: no snapshot service for $distro" >&2; exit 1 ;;
esac
if [ -n "$https" ] && [ -n "${HTTPS_PROXY:-}" ]; then
  printf 'Acquire::https::Proxy "%s";\n' "$HTTPS_PROXY" > /etc/apt/apt.conf.d/90apt-install-aged-proxy
fi
# The snapshot copy of every configured source. --resolve uses it alone, so nothing newer than
# SNAPSHOT can be resolved; installs keep the live sources too.
rewrite() {
  sed -E \
    -e "s#https?://(deb|httpredir)\.debian\.org/debian-security/?#$snapshot_url/debian-security/$snapshot/#g" \
    -e "s#https?://security\.debian\.org(/debian-security)?/?#$snapshot_url/debian-security/$snapshot/#g" \
    -e "s#https?://(deb|httpredir)\.debian\.org/debian/?#$snapshot_url/debian/$snapshot/#g" \
    -e "s#https?://(archive|security)\.ubuntu\.com/ubuntu/?#$snapshot_url/ubuntu/$snapshot/#g" \
    -e "s#^(Types:.*)\$#\\1\\nCheck-Valid-Until: no#" \
    -e "s#^deb (http)#deb [check-valid-until=no] \\1#" "$1"
}
lists=/etc/apt/sources.list.d
for source in /etc/apt/sources.list "$lists"/*.list "$lists"/*.sources; do
  [ -f "$source" ] || continue
  # snapshot.ubuntu.com keeps no ubuntu-ports (every ports path answers 401), so a source build on a
  # non-amd64 host installs the exact pins from the live ports mirror alone, under the same exact-version
  # check below. Resolving has no such source: pins are resolved for the amd64 release images.
  if [ "$mode" != resolve ] && grep -q 'ports\.ubuntu\.com' "$source"; then
    echo "apt-install-aged: $source names ubuntu-ports, which has no snapshot; it installs the exact pins from the live mirror only" >&2
    continue
  fi
  case "$source" in *.sources) target="$lists/snapshot-$(basename "$source")" ;; *) target="$lists/snapshot-$(basename "$source" .list).list" ;; esac
  rewrite "$source" > "$target"
  [ "$mode" != resolve ] || mv "$source" "$source.live"
done
if grep -hE '^(URIs:|deb )' "$lists"/snapshot-* | grep -v "$snapshot_url/" | grep -q .; then
  echo 'apt-install-aged: a configured source has no snapshot equivalent:' >&2
  grep -hE '^(URIs:|deb )' "$lists"/snapshot-* | grep -v "$snapshot_url/" >&2
  exit 1
fi

# Installing, a source that cannot be reached is tolerated: the exact-version check below is the gate.
# Resolving, it is not: a missing security pocket would silently resolve to an older, vulnerable build.
updated=0
apt-get -o Acquire::Retries=4 -o Acquire::http::Timeout=60 update > /tmp/apt-update.log 2>&1 || updated=$?
cat /tmp/apt-update.log
if [ "$updated" != 0 ] || grep -qE '^(Err:|E:|W: (Failed to fetch|Some index files failed))' /tmp/apt-update.log; then
  if [ "$mode" = resolve ]; then
    echo 'apt-install-aged: a snapshot source did not update; not resolving from a partial index' >&2
    exit 1
  fi
  echo 'apt-install-aged: some sources did not update; installing exact pins from the others' >&2
fi
rm -f /tmp/apt-update.log

if [ "$mode" = resolve ] && [ -n "$download" ]; then
  for name in $wanted; do
    version=$(apt-cache policy "$name" | awk '$1 == "Candidate:" { print $2 }')
    [ -n "$version" ] && [ "$version" != '(none)' ] && echo "pin $name=$version"
  done
  exit 0
fi
if [ "$mode" = resolve ]; then
  # shellcheck disable=SC2086 # one word per package
  apt-get install --dry-run -y --no-install-recommends $wanted |
    sed -nE -e 's/^Inst ([^ ]+) \[[^]]*\] \(([^ ]+) .*/upgrade \1=\2/p' -e 's/^Inst ([^ ]+) \(([^ ]+) .*/pin \1=\2/p' | sort
  exit 0
fi

installed() { dpkg-query -W -f '${Package}=${Version}\n' | sort; }
work=$(mktemp -d)
installed > "$work/before"
in_base() { grep -q "^$1=" "$work/before"; }
for name in $wanted; do
  case " $pins $upgrades " in *" $name="*) ;; *) echo "apt-install-aged: --add $name has no pin" >&2; exit 1 ;; esac
done
if [ "$mode" = install ]; then
  for pin in $pins; do
    ! in_base "${pin%%=*}" || { echo "apt-install-aged: --pin $pin names a package the base has; it belongs under --upgrade" >&2; exit 1; }
  done
  for pin in $upgrades; do
    in_base "${pin%%=*}" || { echo "apt-install-aged: --upgrade $pin names a package the base lacks; it belongs under --pin" >&2; exit 1; }
  done
fi
for pin in $pins $upgrades; do
  if ! apt-cache madison "${pin%%=*}" | awk -F' [|] ' '{ gsub(/ /, "", $2); print $2 }' | grep -qxF "${pin#*=}"; then
    echo "apt-install-aged: $pin is in neither the live mirror nor the $snapshot snapshot" >&2
    exit 1
  fi
done

if [ "$mode" = download ]; then
  # shellcheck disable=SC2086 # one word per pin
  apt-get download $pins $upgrades
  rm -rf /var/lib/apt/lists/* "$work"
  exit 0
fi

# shellcheck disable=SC2086 # one word per pin
DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends $pins $upgrades
rm -rf /var/lib/apt/lists/*
unexpected=''
for line in $(installed); do
  grep -qxF "$line" "$work/before" && continue
  case " $pins $upgrades " in *" $line "*) continue ;; esac
  unexpected="$unexpected $line"
done
rm -r "$work"
if [ -n "$unexpected" ]; then
  echo "apt-install-aged: installed versions that are neither the base image's nor pinned:$unexpected" >&2
  exit 1
fi
