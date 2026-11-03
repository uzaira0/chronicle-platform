#!/usr/bin/env bash
# Draft the CHANGELOG section for a release from the curated commits staged for publish
# (scripts/publish.sh stage), across the root and every submodule.
#
#   scripts/changelog-draft.sh <release>        e.g. scripts/changelog-draft.sh 2026.9.10
#
# Prints Markdown to stdout: paste it under a new "## [<release>]" heading in CHANGELOG.md
# and edit it into prose a user can read. For each repository with a curate worktree, the
# commits after the public tip are read; the private history is never used, since it is
# scratch and carries no Conventional Commits guarantee.
# Set CHRONICLE_PUBLISH_WORK to the same explicit directory used by publish.sh.
set -euo pipefail
RELEASE="${1:?usage: scripts/changelog-draft.sh <release>}"
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="${CHRONICLE_PUBLISH_WORK:?set CHRONICLE_PUBLISH_WORK to the publication work directory}"
command -v git-cliff >/dev/null || { echo "git-cliff is required (https://github.com/orhun/git-cliff/releases)" >&2; exit 1; }
cd "$ROOT_DIR"
echo "## [$RELEASE]"
echo
for label in $(git config -f .gitmodules --get-regexp 'submodule\..*\.path' | awk '{print $2}' | xargs -n1 basename) root; do
  wt="$WORK/$label"; [[ -d "$wt" ]] || continue
  branch="$(cat "$WORK/.branch-$label" 2>/dev/null || true)"
  tip="$(git -C "$wt" rev-parse -q --verify "refs/remotes/public/${branch:-main}" 2>/dev/null || true)"
  range="${tip:+$tip..}HEAD"
  # An empty range exits 0 with no output; any nonzero status is a broken range or config,
  # and swallowing it silently drops that repository's changes from the release notes.
  body="$(git -C "$wt" cliff --config "$ROOT_DIR/cliff.toml" --tag "$RELEASE" "$range")" \
    || { echo "FATAL: git-cliff failed for '$label' (range ${range}); changelog is incomplete" >&2; exit 1; }
  body="$(printf '%s\n' "$body" | sed '/^[[:space:]]*$/d')"
  [[ -n "$body" ]] || continue
  echo "<!-- $label -->"
  echo "$body"
  echo
done
