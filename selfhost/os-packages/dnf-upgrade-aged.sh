#!/bin/sh
# Upgrade RPM packages of the base image only to exact builds that have passed the dependency wait
# (docs/SUPPLY-CHAIN.md).
#
#   dnf-upgrade-aged.sh RELEASE --upgrade NAME=VERSION-RELEASE...
#
# RELEASE is the Enterprise Linux major the pins are for (el9); the base image must be on it. Every
# NAME must already be installed. scripts/check-dependency-age.py ages each changed pin by the UBI
# repository metadata (primary.xml) and scripts/os-package-pins.py proposes newer builds once aged.
#
# The UBI repositories keep only the current build of a package, so a pinned build disappears once
# Red Hat replaces it; that upgrade is then skipped and the base version stays (as old as the base
# image digest, which the age gate checks). Fails closed: after the upgrade, every package must be at
# its base version or at a pinned one; anything else dnf pulled in fails the build. Repository metadata
# that does not load, or a query that fails, exits 2 (indeterminate): only a build the loaded metadata
# lacks keeps the base version.
set -eu

usage() { echo 'usage: dnf-upgrade-aged.sh RELEASE --upgrade NAME=VERSION-RELEASE...' >&2; exit 2; }
[ $# -ge 2 ] && [ "$2" = --upgrade ] || usage
release=$1
shift 2
actual="el$(rpm -E '%{rhel}')"
[ "$actual" = "$release" ] || { echo "dnf-upgrade-aged: the base image is $actual, the pins are for $release" >&2; exit 1; }

installed() { rpm -qa --qf '%{NAME}=%{VERSION}-%{RELEASE}\n' | sort -u; }
work=$(mktemp -d)
installed > "$work/before"
attempt=1
until dnf -q makecache; do
  if [ "$attempt" -ge 3 ]; then
    echo "dnf-upgrade-aged: the repository metadata did not load after $attempt attempts; nothing was upgraded" >&2
    exit 2
  fi
  sleep "$((attempt * ${DNF_METADATA_BACKOFF:-5}))"
  attempt=$((attempt + 1))
done
upgrade='' pins=''
for pin in "$@"; do
  case "$pin" in *=*-*) ;; *) usage ;; esac
  name=${pin%%=*}
  pins="$pins $pin"
  grep -q "^$name=" "$work/before" || { echo "dnf-upgrade-aged: $name is not installed in the base image" >&2; exit 1; }
  grep -qx "$pin" "$work/before" && continue
  found=$(dnf -q --cacheonly repoquery --available "$name-${pin#*=}") ||
    { echo "dnf-upgrade-aged: the repository query for $pin failed" >&2; exit 2; }
  if [ -n "$found" ]; then
    upgrade="$upgrade $name-${pin#*=}"
  else
    echo "dnf-upgrade-aged: $pin is no longer in the repositories; keeping the base image's" \
      "$(grep "^$name=" "$work/before")" >&2
  fi
done
if [ -n "$upgrade" ]; then
  # shellcheck disable=SC2086 # one word per build
  dnf -y upgrade $upgrade
fi
dnf clean all

unexpected=''
for line in $(installed); do
  grep -qx "$line" "$work/before" && continue
  case " $pins " in *" $line "*) continue ;; esac
  unexpected="$unexpected $line"
done
rm -r "$work"
if [ -n "$unexpected" ]; then
  echo "dnf-upgrade-aged: installed versions that are neither the base image's nor pinned:$unexpected" >&2
  exit 1
fi
