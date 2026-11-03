# Git workflow

How this project uses git, and why.

## The two kinds of history

**Private history** (the `*-dev` repositories, remote `origin`) is scratch. Commit whenever
the tree is at a point you might want back. The messages can be anything; this history is
never published. The only gate on a private commit is that it carries no secret
(`gitleaks` in the pre-commit hook).

**Public history** (the mirror repositories, remote `public`) is curated: one logical
change per commit, a subject that says what it does, a body that says why. It is produced
from the private tree at publish time, not committed to directly.

## Publishing

`scripts/publish.sh` (or the `make publish-*` targets) turns the private state into public
commits:

Set `CHRONICLE_PUBLISH_WORK` to the directory for publication worktrees before running
the publish, changelog or release-image commands. The commands require this explicit location.

1. `make publish-stage` creates, for each repository, a worktree under
   `$CHRONICLE_PUBLISH_WORK/<repo>` checked out at the public tip. Its working tree
   is the current private HEAD minus every path in `.publishignore`; the index is the
   public tip. `git status` in that worktree is therefore exactly the delta that still
   needs to become public commits.
2. In each worktree, build the commits by hand: read the delta, group it into logical
   changes, stage each group by path (or `git apply --cached` for part of a file), and
   commit with a Conventional Commits message (below). Re-run `make publish-stage` at any
   time; it refreshes the working tree and keeps the commits already made.
3. `make publish-status` lists the curated commits and the paths not yet committed.
4. `make changelog RELEASE=<version>` drafts the changelog entry from the curated commits;
   paste it into `CHANGELOG.md` in the private tree, then stage again so the changelog is
   part of the delta.
5. `make publish-push DRY_RUN=1` runs the gates; `make publish-push` fast-forwards the
   public branches. Submodules are pushed before the root, whose gitlinks must already be
   public.

The gates, all of which must pass before anything leaves the machine:

- the curated tip's tree is byte-identical to the filtered snapshot (nothing forgotten,
  nothing added);
- every new commit message passes `scripts/check-commit-msg.sh`, carries no banned trailer or
  term, and has the same author and committer;
- `gitleaks` finds nothing in the new commits or in the final tree, outside the paths listed
  in `.publishallow`;
- no path matched by `.publishignore` survived, and no banned term is in the tree.

Nothing on the public repositories is force-pushed or deleted in normal operation. If a
secret does slip through, rotate it first; rewriting public history is the last step.

## What a good public commit is

A commit is one logical change that leaves the tree working. In practice:

- **One reason per commit.** "Add the pseudo-locale" and "fix the import order it exposed"
  are two commits, because a reader may want one without the other and `git bisect` can
  tell them apart.
- **Refactors are separate from behaviour changes.** Move the code in one commit, change what
  it does in the next.
- **Tests ship with the code they test.** A generated-file refresh, a dependency bump, and a
  documentation change are each their own commit.
- **Small is better, but complete beats small.** A commit that touches forty files to rename
  one symbol is complete.

The delta being curated may span days of private work. The public commits do not mirror
how the work happened; they read as if the change had been made once, correctly.

## What a good commit message is

Subjects follow [Conventional Commits](https://www.conventionalcommits.org): a type, an
optional scope for the surface, and an imperative lowercase subject.

```
<type>(<scope>)!: <what changes, lowercase, no period, under 72 chars>

<Why. What was wrong, what changed, what was rejected. Terse: fragments,
no articles, wrapped at 72.>

Closes #123
```

| Type | Use for | Changelog |
|------|---------|-----------|
| `feat` | new user-visible behaviour | Added |
| `fix` | a bug fix | Fixed |
| `perf` | a performance change | Performance |
| `refactor` | code change with no behaviour change | Changed |
| `docs` | documentation only | Documentation |
| `revert` | reverting a commit | Reverted |
| `test`, `build`, `ci`, `chore`, `style` | tests, build system, local CI, housekeeping, formatting | not listed |

Scopes name the surface when a repository has several: `web`, `android`, `ios`, `server`,
`api`, `models`, `selfhost`, `docker`, `i18n`. A `!` after the type or scope marks a
breaking change. Example:

```
fix(android): reject hardcoded English in Kotlin UI sinks

Lint HardcodedText covers layout XML only. Toast/Snackbar/dialog/
notification text from Kotlin invisible to it; translations cannot
override. Add ast-grep rules for those sinks, SetTextI18n -> error.
Rules kind-based: pattern rules break on comments inside call chains.
```

- **Subject**: what changes. Imperative: "add", "fix", "remove". No articles: "add
  pseudo-locale", not "add the pseudo-locale". Lowercase after the colon, no period.
- **Body**: why, in the fewest words. Fragments and arrows are fine. Skip it only when
  the subject is the whole story (typo, version bump).
- No tool banners, no session links, no co-author trailers for tools.

## Branches in the private repositories

- `develop` (or `main` for the root and chronicle-models) is the branch the publish reads
  from. Keep it at a state you would publish.
- Topic branches are optional and short-lived; delete them after merging. Rewriting a
  branch nobody else has pulled is normal.
- Never `git stash` as a workflow. Commit a work-in-progress commit instead; the private
  history does not mind.
- `git worktree add ../<repo>-<topic> <branch>` for a second checkout without disturbing
  caches in the main one.

## Receiving outside changes

Pull requests arrive on the public repositories. Apply them to the private tree
(`gh pr diff <n> --patch | git am`, or a fresh commit with `Co-authored-by` naming the
human), review, and let the next publish carry them. The public commit keeps the
contributor's authorship. Close the public pull request with a note naming the commit it
shipped in; it cannot be merged there because public history is written only by publish.

