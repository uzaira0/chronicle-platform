#!/usr/bin/env bash
# Render the dependency-intake launchd job (docs/SUPPLY-CHAIN.md) for a dedicated runner checkout.
#
#   scripts/launchd/install-dependency-intake.sh [--checkout DIR] [--ref REF] [--target-dir DIR]
#
# The job runs the gate runner and the age gate from DIR (default ~/chronicle/dependency-intake): that
# checkout's code decides every gate, so it must be one nothing else moves. A task or release worktree is
# checked out, rebased and removed as work goes on, which would change or delete the code the 04:17 run
# trusts. When DIR does not exist it is created as a detached worktree of this script's repository at REF
# (default: this checkout's HEAD), with the submodules the gates read initialised. When it exists it is
# used as it is, and must be such a dedicated checkout: a detached HEAD at a commit, not a branch other
# work moves. Moving the runner to newer policy is a reviewed step:
#   git -C DIR checkout --detach <reviewed commit> && git -C DIR submodule update --init <...>
#
# Writes com.chronicle.dependency-intake.plist into --target-dir (default ~/Library/LaunchAgents),
# lints it with plutil, and prints the launchctl command that loads it. It never loads, bootstraps or
# kickstarts the job itself.
set -euo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
source_root=$(cd "$here/../.." && pwd -P)
checkout="$HOME/chronicle/dependency-intake"
ref=HEAD
target_dir="$HOME/Library/LaunchAgents"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --checkout) checkout=$2; shift 2 ;;
    --ref) ref=$2; shift 2 ;;
    --target-dir) target_dir=$2; shift 2 ;;
    *) echo 'usage: scripts/launchd/install-dependency-intake.sh [--checkout DIR] [--ref REF] [--target-dir DIR]' >&2; exit 2 ;;
  esac
done
# The submodules whose files the age gate, the regeneration driver and the gate steps read.
submodules=(chronicle-web chronicle-server chronicle-api chronicle-models rhizome rhizome-client)

if [[ ! -e "$checkout" ]]; then
  commit=$(git -C "$source_root" rev-parse --verify "$ref^{commit}")
  mkdir -p "$(dirname "$checkout")"
  git -C "$source_root" worktree add --detach "$checkout" "$commit" >/dev/null
  git -C "$checkout" submodule update --init --quiet -- "${submodules[@]}"
  printf 'created %s at %s\n' "$checkout" "$commit"
fi
checkout=$(cd "$checkout" && pwd -P)
[[ -f "$checkout/scripts/dependency-intake.sh" ]] || { echo "install-dependency-intake: $checkout has no scripts/dependency-intake.sh" >&2; exit 1; }
if git -C "$checkout" symbolic-ref -q HEAD >/dev/null; then
  echo "install-dependency-intake: $checkout has a branch checked out; the runner checkout must be a detached commit nothing else moves" >&2
  exit 1
fi
for value in "$checkout" "$HOME"; do
  # The values go into XML text and a sed replacement unescaped.
  [[ "$value" != *[\&\<\>\|\\]* ]] || { echo "install-dependency-intake: unsupported character in $value" >&2; exit 1; }
done

label=com.chronicle.dependency-intake
mkdir -p "$target_dir" "$HOME/Library/Logs/chronicle-dependency-intake"
plist="$target_dir/$label.plist"
sed -e "s|__ROOT__|$checkout|g" -e "s|__HOME__|$HOME|g" "$here/$label.plist.template" >"$plist.part"
plutil -lint "$plist.part" >/dev/null
mv "$plist.part" "$plist"
printf 'wrote %s (runs %s/scripts/dependency-intake.sh daily at 04:17, at %s)\n' \
  "$plist" "$checkout" "$(git -C "$checkout" rev-parse --short HEAD)"
printf 'to load it: launchctl bootstrap gui/%s %q\n' "$(id -u)" "$plist"
