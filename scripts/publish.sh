#!/usr/bin/env bash
# Publish curated history from the private development repositories to the public mirrors.
#
#   scripts/publish.sh stage  <repo|all> [--base <commit>]   lay the filtered snapshot over the public tip
#   scripts/publish.sh status                                 what is staged, what is still uncommitted
#   scripts/publish.sh verify-source                         prove public source matches private HEAD
#   scripts/publish.sh push   <repo|all> [--dry-run] [--replace]  gate and fast-forward the curated commits
#   scripts/publish.sh abandon <repo|all>                     drop the worktree and curate branch
#
# Model: the private `origin` remotes are scratch; commit there however you like. The public
# `public` remotes carry the curated history: each publish condenses the private work since the
# last publish into logical commits with Conventional Commits messages. `stage` creates a
# worktree on the public tip whose working tree is the current private HEAD minus every path in
# `.publishignore` (root gitlinks point at the public submodule commits, `.gitmodules` at the
# public URLs). You then read that diff and build the commits by hand. `push` refuses unless the
# curated tip's tree equals the filtered snapshot, every new commit message passes
# scripts/check-commit-msg.sh and carries no banned trailer, gitleaks finds nothing in the new
# commits, and the tree carries no banned term outside `.publishallow`. Banned terms are regexes
# in `.publishterms` (private; BANNED_TERMS, BANNED_ALLOW, BANNED_TRAILERS).
#
# Repos are labelled by directory basename; "root" is the monorepo itself. Push submodules before
# the root: the root's gitlinks must already be on the public remotes.
# Set CHRONICLE_PUBLISH_WORK to the explicit directory for publication worktrees.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="${CHRONICLE_PUBLISH_WORK:?set CHRONICLE_PUBLISH_WORK to the publication work directory}"
CURATE_BRANCH=curate
BANNED_TERMS=''; BANNED_ALLOW=''; BANNED_TRAILERS=''
# shellcheck disable=SC1091
[[ -f "$ROOT_DIR/.publishterms" ]] && source "$ROOT_DIR/.publishterms"

fail() { echo "publish: $*" >&2; exit 1; }
need() { command -v "$1" >/dev/null || fail "missing tool: $1"; }
need gitleaks; need gh; need rg; need jq
# gitleaks_json <report>: the report gitleaks wrote; a missing or malformed one fails, never reads as "no findings"
gitleaks_json() { [[ -s "$1" ]] && jq -e 'type == "array"' "$1" >/dev/null 2>&1 || fail "gitleaks wrote no readable report at $1"; }

cd "$ROOT_DIR"
mapfile -t SUBMODULES < <(git config -f .gitmodules --get-regexp 'submodule\..*\.path' | awk '{print $2}')

repo_dir()   { [[ "$1" == root ]] && echo "$ROOT_DIR" || echo "$ROOT_DIR/$1"; }
public_slug() { git -C "$1" remote get-url public | sed -E 's#.*github\.com[:/]##; s#\.git$##'; }
public_branch() {  # <label>; cached per label so the root and a same-named submodule never collide
  local label="$1" cache; cache="$WORK/.branch-$label"
  if [[ ! -s "$cache" ]]; then mkdir -p "$WORK"; gh repo view "$(public_slug "$(repo_dir "$label")")" --json defaultBranchRef -q .defaultBranchRef.name > "$cache"; fi
  cat "$cache"
}
public_tip() {  # <label>; empty when the public branch does not exist yet
  local label="$1" dir branch; dir="$(repo_dir "$label")"; branch="$(public_branch "$label")"
  git -C "$dir" fetch -q public "$branch" 2>/dev/null || true
  git -C "$dir" rev-parse -q --verify "refs/remotes/public/$branch" 2>/dev/null || true
}
worktree_of() { echo "$WORK/$1"; }
all_labels() { local p; for p in "${SUBMODULES[@]}"; do basename "$p"; done; echo root; }
labels_for() { [[ "$1" == all ]] && all_labels || echo "$1"; }

# The commit the root should pin for a submodule path: its curated tip if one is staged,
# otherwise the public tip.
pointer_for() {
  local path="$1" label wt; label="$(basename "$path")"; wt="$(worktree_of "$label")"
  if [[ -d "$wt" ]]; then git -C "$wt" rev-parse HEAD; else public_tip "$label"; fi
}

# build_tree <label> -> the filtered snapshot tree of the private HEAD
build_tree() {
  local label="$1" dir; dir="$(repo_dir "$label")"
  local idx="$WORK/.index-$label"; mkdir -p "$WORK"; rm -f "$idx"
  GIT_INDEX_FILE="$idx" git -C "$dir" read-tree HEAD
  if [[ -f "$dir/.publishignore" ]]; then
    GIT_INDEX_FILE="$idx" git -C "$dir" ls-files -z --cached -i --exclude-from="$dir/.publishignore" \
      | GIT_INDEX_FILE="$idx" xargs -0 -r git -C "$dir" update-index --force-remove --
  fi
  if [[ "$label" == root ]]; then
    local path sha
    for path in "${SUBMODULES[@]}"; do
      sha="$(pointer_for "$path")"
      [[ -n "$sha" ]] || fail "root: no public commit for $path yet; stage or push it first"
      GIT_INDEX_FILE="$idx" git -C "$dir" update-index --add --cacheinfo "160000,$sha,$path"
    done
    local blob
    blob="$(sed -E 's#(url = https://github\.com/[^/]+/[A-Za-z0-9_.-]+)-dev\.git#\1.git#' "$dir/.gitmodules" | git -C "$dir" hash-object -w --stdin)"
    GIT_INDEX_FILE="$idx" git -C "$dir" update-index --add --cacheinfo "100644,$blob,.gitmodules"
  fi
  GIT_INDEX_FILE="$idx" git -C "$dir" write-tree
}

# gate_tree <label> <tree>: no ignored path survived, no secrets, no banned terms
gate_tree() {
  local label="$1" tree="$2" dir; dir="$(repo_dir "$label")"
  local export="$WORK/.tree-$label"; rm -rf "$export"; (umask 077 && mkdir -p "$export")
  trap 'rm -rf "$WORK"/.tree-* "$WORK"/.gitleaks-*.json "$WORK"/.allow-*' EXIT
  git -C "$dir" archive "$tree" | tar -x -C "$export"
  if [[ -f "$dir/.publishignore" ]]; then
    # ls-files needs a repo to evaluate patterns against; a throwaway one inside
    # the export. Command failure here must fail the gate, never pass it.
    local leaked
    leaked="$(cd "$export" && git init -q . && git ls-files --others -i --exclude-from="$dir/.publishignore" && rm -rf .git)" \
      || fail "$label: ignored-path check could not run"
    [[ -z "$leaked" ]] || fail "$label: ignored paths survived the filter: $leaked"
  fi
  local allow="$WORK/.allow-$label"; : > "$allow"
  [[ -f "$dir/.publishallow" ]] && sed -E 's/[[:space:]]+#.*$//' "$dir/.publishallow" | grep -v '^#' | grep -v '^$' > "$allow" || true
  local report="$WORK/.gitleaks-$label.json"; rm -f "$report"
  gitleaks detect --no-git --no-banner -s "$export" --exit-code 0 --report-format json --report-path "$report" >/dev/null 2>&1
  gitleaks_json "$report"
  local hits; hits="$(jq -r '.[] | (.File|sub(".*/\\.tree-[^/]+/";""))' "$report" | sort -u | { grep -vxFf "$allow" || true; })"
  [[ -z "$hits" ]] || fail "$label: gitleaks findings outside .publishallow: $(tr '\n' ' ' <<<"$hits")"
  if [[ -n "$BANNED_TERMS" ]]; then
    local banned="" f
    while IFS= read -r f; do
      if rg -i "$BANNED_TERMS" "$f" | rg -v "${BANNED_ALLOW:-^\$}" >/dev/null; then banned+="${f#$export/}"$'\n'; fi
    done < <(rg -il --no-messages "$BANNED_TERMS" "$export" || true)
    banned="$(grep -vxFf "$allow" <<<"$banned" | grep -v '^$' || true)"
    [[ -z "$banned" ]] || fail "$label: banned terms outside .publishallow in: $(tr '\n' ' ' <<<"$banned")"
  fi
  rm -rf "$export"
}

# gate_commits <label> <base> <tip>: every new commit has a conforming message and no secrets
gate_commits() {
  local label="$1" base="$2" tip="$3" wt; wt="$(worktree_of "$label")"
  local range="$tip"; [[ -n "$base" ]] && range="$base..$tip"
  local c msgfile="$WORK/.msg-$label"
  for c in $(git -C "$wt" rev-list --reverse "$range"); do
    git -C "$wt" log -1 --format=%B "$c" > "$msgfile"
    "$ROOT_DIR/scripts/check-commit-msg.sh" "$msgfile" >/dev/null 2>&1 || fail "$label: commit ${c:0:8} message rejected: $(head -1 "$msgfile")"
    if [[ -n "$BANNED_TRAILERS$BANNED_TERMS" ]] && rg -qi "${BANNED_TRAILERS:+$BANNED_TRAILERS|}${BANNED_TERMS:-^\$}" "$msgfile"; then
      fail "$label: commit ${c:0:8} message carries a banned trailer or term"
    fi
    if [[ "$(git -C "$wt" log -1 --format='%an <%ae>' "$c")" != "$(git -C "$wt" log -1 --format='%cn <%ce>' "$c")" ]]; then
      fail "$label: commit ${c:0:8} author and committer differ"
    fi
  done
  local allow="$WORK/.allow-$label"
  local report="$WORK/.gitleaks-commits-$label.json"; rm -f "$report"
  gitleaks detect --no-banner -s "$wt" --log-opts="$range" --exit-code 0 --report-format json --report-path "$report" >/dev/null 2>&1
  gitleaks_json "$report"
  local hits; hits="$(jq -r '.[] | .File' "$report" | sort -u | { grep -vxFf "$allow" || true; })"
  [[ -z "$hits" ]] || fail "$label: gitleaks findings in the new commits outside .publishallow: $(tr '\n' ' ' <<<"$hits")"
}

cmd_stage() {
  local label="$1" base="${2:-}" dir wt tip tree
  dir="$(repo_dir "$label")"; wt="$(worktree_of "$label")"
  [[ -z "$(git -C "$dir" status --porcelain --untracked-files=no)" ]] || fail "$label: private working tree has uncommitted changes"
  tree="$(build_tree "$label")"
  if [[ ! -d "$wt" ]]; then
    mkdir -p "$WORK"
    if [[ -n "$base" ]]; then
      git -C "$dir" worktree add -q -B "$CURATE_BRANCH" "$wt" "$base"
    else
      tip="$(public_tip "$label")"
      if [[ -n "$tip" ]]; then
        git -C "$dir" worktree add -q -B "$CURATE_BRANCH" "$wt" "$tip"
      else
        git -C "$dir" worktree add -q --detach "$wt"
        git -C "$wt" checkout -q --orphan "$CURATE_BRANCH"
        git -C "$wt" rm -rfq --cached . >/dev/null 2>&1 || true
        find "$wt" -mindepth 1 -maxdepth 1 ! -name .git -exec rm -rf {} +
      fi
    fi
  fi
  # Working tree = filtered snapshot, index = curated tip: `git status` is the remaining delta.
  git -C "$wt" read-tree --reset -u "$tree"
  git -C "$wt" clean -fdxq            # a previously staged path that left the snapshot must go too
  git -C "$wt" reset -q
  if [[ "$label" == root ]]; then
    # Gitlinks have no working-tree form here, so the new pointers go straight into the index
    # and show up as staged changes ready for a "chore: update submodules ..." commit.
    local path sha
    for path in "${SUBMODULES[@]}"; do
      sha="$(git -C "$wt" rev-parse -q --verify "$tree:$path" 2>/dev/null || true)"
      [[ -n "$sha" ]] && git -C "$wt" update-index --add --cacheinfo "160000,$sha,$path"
    done
  fi
  local pending; pending="$(git -C "$wt" status --porcelain | wc -l)"
  echo "$label: staged at $wt (branch $CURATE_BRANCH at $(git -C "$wt" rev-parse --short HEAD 2>/dev/null || echo 'orphan'), $pending paths to curate)" >&2
}

cmd_status() {
  local label wt dir tip
  for label in $(all_labels); do
    wt="$(worktree_of "$label")"; dir="$(repo_dir "$label")"
    [[ -d "$wt" ]] || continue
    tip="$(public_tip "$label")"
    local n; n="$(git -C "$wt" rev-list --count HEAD 2>/dev/null || echo 0)"; [[ -n "$tip" ]] && n="$(git -C "$wt" rev-list --count "$tip..HEAD" 2>/dev/null || echo 0)"
    echo "$label: $n curated commit(s), $(git -C "$wt" status --porcelain | wc -l) path(s) uncommitted"
    git -C "$wt" log --max-count=50 --format='    %h %s' ${tip:+"$tip..HEAD"} 2>/dev/null
  done
}

cmd_verify_source() {
  local label tip tree
  for label in $(all_labels); do
    tip="$(public_tip "$label")"
    [[ -n "$tip" ]] || fail "$label: public source is missing; publish source first"
    # A frozen repo ships its current public commit; the root tree check pins exactly that commit.
    [[ " ${CHRONICLE_PUBLISH_FROZEN:-} " == *" $label "* ]] && continue
    tree="$(build_tree "$label")"
    [[ "$(git -C "$(repo_dir "$label")" rev-parse "$tip^{tree}")" == "$tree" ]] \
      || fail "$label: public source differs from filtered HEAD; publish source first"
  done
  printf '%s\n' "$tip"
}

cmd_push() {
  local label="$1" dry="$2" replace="$3" dir wt slug branch tip tree curated
  dir="$(repo_dir "$label")"; wt="$(worktree_of "$label")"
  [[ -d "$wt" ]] || fail "$label: nothing staged"
  [[ -z "$(git -C "$wt" status --porcelain)" ]] || fail "$label: uncommitted paths remain in $wt; commit or abandon them"
  slug="$(public_slug "$dir")"; branch="$(public_branch "$label")"; tip="$(public_tip "$label")"
  curated="$(git -C "$wt" rev-parse HEAD)"
  if [[ "$label" == root ]]; then
    local path sha
    for path in "${SUBMODULES[@]}"; do
      sha="$(git -C "$wt" rev-parse "HEAD:$path")"
      if [[ "$dry" -eq 1 ]]; then
        [[ "$sha" == "$(pointer_for "$path")" ]] || fail "root: gitlink $path ($sha) is not that submodule's curated tip; stage root again"
      else
        [[ "$sha" == "$(public_tip "$(basename "$path")")" ]] || fail "root: gitlink $path ($sha) is not the public tip; push that submodule first"
      fi
    done
  fi
  tree="$(build_tree "$label")"
  [[ "$(git -C "$wt" rev-parse 'HEAD^{tree}')" == "$tree" ]] || fail "$label: curated tree differs from the filtered snapshot; run stage again and commit the rest"
  if [[ -n "$tip" && $replace -eq 0 ]]; then
    [[ "$(git -C "$wt" merge-base "$tip" HEAD 2>/dev/null)" == "$tip" ]] || fail "$label: curated branch is not a fast-forward of public/$branch"
    [[ "$tip" != "$curated" ]] || { echo "$label: nothing new to publish" >&2; return; }
  fi
  gate_tree "$label" "$tree"
  gate_commits "$label" "$([[ $replace -eq 1 ]] && echo '' || echo "$tip")" "$curated"
  local n
  if [[ -n "$tip" && $replace -eq 0 ]]; then n="$(git -C "$wt" rev-list --count "$tip..HEAD")"; else n="$(git -C "$wt" rev-list --count HEAD)"; fi
  if [[ "$dry" -eq 1 ]]; then
    echo "$label: would push $n commit(s) to $slug:$branch (tip ${curated:0:8}$([[ $replace -eq 1 ]] && echo ', replacing history'))" >&2
    return
  fi
  if [[ $replace -eq 1 ]]; then
    git -C "$dir" push -q -f public "$curated:refs/heads/$branch"
  else
    git -C "$dir" push -q public "$curated:refs/heads/$branch"
  fi
  local stamp; stamp="$(date -u +%Y-%m-%d)"
  git -C "$dir" tag -f "published-$stamp" HEAD >/dev/null
  git -C "$dir" push -q -f origin "refs/tags/published-$stamp" 2>/dev/null || true
  git -C "$dir" worktree remove --force "$wt"
  git -C "$dir" branch -q -D "$CURATE_BRANCH" 2>/dev/null || true
  echo "$label: pushed $n commit(s) to $slug:$branch (tip ${curated:0:8})" >&2
}

cmd_abandon() {
  local label="$1" dir wt; dir="$(repo_dir "$label")"; wt="$(worktree_of "$label")"
  [[ -d "$wt" ]] && git -C "$dir" worktree remove --force "$wt"
  git -C "$dir" branch -q -D "$CURATE_BRANCH" 2>/dev/null || true
  echo "$label: abandoned" >&2
}

cmd="${1:-}"; shift || true
case "$cmd" in
  stage)
    target="${1:?usage: publish.sh stage <repo|all> [--base <commit>]}"; shift
    base=""; [[ "${1:-}" == "--base" ]] && base="${2:?--base needs a commit}"
    [[ -n "$base" && "$target" == all ]] && fail "--base applies to one repo"
    for l in $(labels_for "$target"); do cmd_stage "$l" "$base"; done ;;
  status) cmd_status ;;
  verify-source) cmd_verify_source ;;
  push)
    target="${1:?usage: publish.sh push <repo|all> [--dry-run] [--replace]}"; shift
    dry=0; replace=0
    for a in "$@"; do case "$a" in --dry-run) dry=1 ;; --replace) replace=1 ;; *) fail "unknown flag $a" ;; esac; done
    for l in $(labels_for "$target"); do cmd_push "$l" "$dry" "$replace"; done ;;
  abandon)
    target="${1:?usage: publish.sh abandon <repo|all>}"
    for l in $(labels_for "$target"); do cmd_abandon "$l"; done ;;
  *) sed -n '2,20p' "$0"; exit 1 ;;
esac
