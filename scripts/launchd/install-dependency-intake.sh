#!/usr/bin/env bash
# Render the dependency-intake launchd job (docs/SUPPLY-CHAIN.md) for this checkout.
#
#   scripts/launchd/install-dependency-intake.sh [--root CHECKOUT] [--target-dir DIR]
#
# Writes com.chronicle.dependency-intake.plist into DIR (default ~/Library/LaunchAgents) with the
# checkout's absolute path, lints it with plutil, and prints the launchctl command that would load
# it. It never loads, bootstraps or kickstarts the job: loading it is the user's step.
set -euo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
root=$(cd "$here/../.." && pwd -P)
target_dir="$HOME/Library/LaunchAgents"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --root) root=$(cd "$2" && pwd -P); shift 2 ;;
    --target-dir) target_dir=$2; shift 2 ;;
    *) echo 'usage: scripts/launchd/install-dependency-intake.sh [--root CHECKOUT] [--target-dir DIR]' >&2; exit 2 ;;
  esac
done
[[ -f "$root/scripts/dependency-intake.sh" ]] || { echo "install-dependency-intake: $root has no scripts/dependency-intake.sh" >&2; exit 1; }
for value in "$root" "$HOME"; do
  # The values go into XML text and a sed replacement unescaped.
  [[ "$value" != *[\&\<\>\|\\]* ]] || { echo "install-dependency-intake: unsupported character in $value" >&2; exit 1; }
done

label=com.chronicle.dependency-intake
mkdir -p "$target_dir" "$HOME/Library/Logs/chronicle-dependency-intake"
plist="$target_dir/$label.plist"
sed -e "s|__ROOT__|$root|g" -e "s|__HOME__|$HOME|g" "$here/$label.plist.template" >"$plist.part"
plutil -lint "$plist.part" >/dev/null
mv "$plist.part" "$plist"
printf 'wrote %s (runs %s/scripts/dependency-intake.sh daily at 04:17)\n' "$plist" "$root"
printf 'not loaded; to load it: launchctl bootstrap gui/%s %q\n' "$(id -u)" "$plist"
