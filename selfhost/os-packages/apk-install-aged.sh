#!/bin/sh
# Install Alpine packages only at versions that have passed the dependency wait (docs/SUPPLY-CHAIN.md).
#
#   apk-install-aged.sh BRANCH [--add NAME...] [--pin NAME=VERSION...] [--upgrade NAME=VERSION...]
#
# BRANCH is the Alpine branch the pins were computed for (v3.24); the base image must be on it.
# --add names the packages the image needs that its base lacks. --pin fixes the exact version of each
# of them and of every dependency the base lacks; --upgrade fixes a newer version of a package the base
# already has. scripts/os-package-pins.py writes both lists from the APK index, choosing only versions
# whose build time (`t:`) is older than the wait, and the age gate checks every changed one.
#
# Alpine's index holds one version per package, so a pinned version disappears once Alpine replaces
# it. An --upgrade whose version has gone is skipped and the base version stays (it is as old as the
# base image digest, which the age gate checks). A --pin has no such fallback: the build fails until
# os-package-pins.py proposes a replacement that has aged.
#
# Fails closed: --pin names must be absent from the base and --upgrade names present, and after the
# install every package must be at its base version or at a pinned one; anything else apk pulled in
# (an unpinned dependency at the index's newest version) fails the build.
set -eu

usage() { echo 'usage: apk-install-aged.sh BRANCH [--add NAME...] [--pin NAME=VERSION...] [--upgrade NAME=VERSION...]' >&2; exit 2; }
[ $# -ge 1 ] || usage
branch=$1
shift
section='' wanted='' pins='' upgrades=''
for word in "$@"; do
  case "$word" in
    --add) section=add ;;
    --pin) section=pin ;;
    --upgrade) section=upgrade ;;
    -*) usage ;;
    *=*)
      case "$section" in pin) pins="$pins $word" ;; upgrade) upgrades="$upgrades $word" ;; *) usage ;; esac ;;
    *) [ "$section" = add ] || usage; wanted="$wanted $word" ;;
  esac
done

release="v$(cut -d. -f1,2 /etc/alpine-release)"
if [ "$release" != "$branch" ]; then
  echo "apk-install-aged: the base image is Alpine $release but the pins are for $branch;" \
    'rerun scripts/os-package-pins.py --write' >&2
  exit 1
fi

installed() { awk -F: '/^P:/ { name = $2 } /^V:/ { print name "=" $2 }' /lib/apk/db/installed | sort; }
work=$(mktemp -d)
installed > "$work/before"
in_base() { grep -q "^$1=" "$work/before"; }

for name in $wanted; do
  case " $pins " in
    *" $name="*) ;;
    *) echo "apk-install-aged: --add $name has no --pin; rerun scripts/os-package-pins.py --write" >&2; exit 1 ;;
  esac
done
for pin in $pins; do
  if in_base "${pin%%=*}"; then
    echo "apk-install-aged: --pin $pin names a package the base has; it belongs under --upgrade" >&2
    exit 1
  fi
done
for pin in $upgrades; do
  if ! in_base "${pin%%=*}"; then
    echo "apk-install-aged: --upgrade $pin names a package the base lacks; it belongs under --pin" >&2
    exit 1
  fi
done

# An index that does not load is indeterminate (exit 2), not a policy failure: retry it, then say so.
attempt=1
until apk update --quiet; do
  if [ "$attempt" -ge 3 ]; then
    echo "apk-install-aged: the $branch index did not update after $attempt attempts; nothing was installed" >&2
    exit 2
  fi
  sleep "$((attempt * ${APK_UPDATE_BACKOFF:-5}))"
  attempt=$((attempt + 1))
done
install=''
for pin in $pins $upgrades; do
  name=${pin%%=*}
  grep -qx "$pin" "$work/before" && continue
  if apk search --exact "$name" | grep -x "$name-${pin#*=}" >/dev/null; then
    install="$install $pin"
  elif in_base "$name"; then
    echo "apk-install-aged: $pin is no longer in the $branch index; keeping the base image's" \
      "$(grep "^$name=" "$work/before")" >&2
  else
    echo "apk-install-aged: $pin is no longer in the $branch index and the base lacks $name;" \
      'rerun scripts/os-package-pins.py --write once a replacement has aged' >&2
    exit 1
  fi
done
if [ -n "$install" ]; then
  # shellcheck disable=SC2086 # one word per pin
  apk add $install
fi
rm -rf /var/cache/apk/*

unexpected=''
for line in $(installed); do
  grep -qx "$line" "$work/before" && continue
  case " $pins $upgrades " in *" $line "*) continue ;; esac
  unexpected="$unexpected $line"
done
rm -r "$work"
if [ -n "$unexpected" ]; then
  echo "apk-install-aged: installed versions that are neither the base image's nor pinned:$unexpected;" \
    'rerun scripts/os-package-pins.py --write' >&2
  exit 1
fi
