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

### Drafts, promotion and the publication ledger

`scripts/publish-images.sh <release>` builds, signs and uploads a release as a **draft**. A draft
is not a publication: it can be replaced or deleted, no server is offered it, and GitHub creates
its tag only when it publishes it. Cutting a draft changes nothing in this repository.

A cut checks its local prerequisites first (registry token, keys, tools, a clean tree, the
changelog entry) and asks GitHub nothing until they hold. Its first requests are the public
repository's name and its release list. It then refuses, before it verifies, builds or pushes
anything, when that list already holds a release with the tag, draft or public (a leading `v`
makes no difference). `gh release create
--draft` would not refuse: gh looks for an existing release only when the new one is not a
draft, and a draft holds no git tag for GitHub to reject, so a second cut leaves two drafts
under one tag. `gh release view`, `download` and `edit` then act on the one draft GitHub returns
for the tag, and neither GitHub's REST reference for releases nor the gh manual says which, so
a promotion could verify one bundle and publish another. To replace a stale draft, remove it
yourself and cut again; the script deletes no release:

```bash
gh release delete <tag> --repo <owner>/<repository>
```

A version that is already public is never cut again; cut the next version.

`scripts/publish-images.sh <release> --promote <smoke-result.txt>` publishes the draft after the
smoke drill. Once GitHub has published it, the script, in the checkout it runs from:

1. fetches the release's tag from `public` (that one tag);
2. adds the release to `selfhost/published-migrations.json`, from the manifest of the bundle it
   promoted.

Commit `selfhost/published-migrations.json` afterwards, before building another release. The
ledger freezes the migrations each published release shipped (`require_immutable_migrations` in
`selfhost/chronicle_ops/migrations.py`), and the release builder reads the PostgreSQL major and
the database volume names of every recorded release from its tag
(`require_database_volume_continuity`), so the entry and the tag arrive together. Until
2026-11-11 the entry was written when the draft was cut: every bundle build then failed until the
promotion, and a replaced draft left an entry that had to be removed by hand.

A release the ledger cannot take, because it lacks or changes a migration that a published
release shipped, is refused while it is still a draft.

`--promote` first asks GitHub whether the release is a draft. A draft is verified, published and
recorded. A release that is **already public** is verified the same way (signature, checksum,
smoke result, images, tag) and recorded, and nothing is published: that is how a promotion that
published the release and then failed is finished, by running the same command again. The
failures that leave a public release without its entry:

- `gh release edit --draft=false` exits non-zero although GitHub applied the edit (the connection
  was lost after the request was accepted). The script asks GitHub what the release is now. If
  it is public, the script goes on to the tag and the ledger. If it is still a draft, nothing was
  published. If GitHub does not answer, the script says so and prints the command to run again.
- The tag fetch or the ledger write fails. The script says that the release is public, exits
  non-zero and prints the two commands that finish the record; running the same promotion again
  does the same.

**Every published release at or above the upgrade floor must be in the ledger** before a cut
starts or a draft is published. The ledger checks a new release only against the releases
recorded in it, so a public release without an entry would let the next one change a migration
it shipped. `scripts/publish-images.sh <release>` therefore reads GitHub's release list before
it builds or pushes anything, and `--promote` reads it before it publishes; each stops and
prints `scripts/publish-images.sh <tag> --promote <smoke-result.txt>` for every published
release the ledger lacks (`unrecorded_publications` in `selfhost/chronicle_ops/migrations.py`).
If another checkout has already recorded the release, bring that commit here instead.

### The public repository's former name

The public root repository was `uzaira0/methodic` until 2026-11-10 and has been
`uzaira0/chronicle-platform` since. **No repository named `uzaira0/methodic` may ever be
created**: no new repository, no fork, no rename or transfer of another repository to that
name.

A server on 2026.11.2 finds updates at one address,
`https://api.github.com/repos/uzaira0/methodic/releases?per_page=100`, written in its own
updater (`selfhost/chronicle_ops/update.py` at the `2026.11.2` tag). That code is installed and
cannot be changed, and it has no second source. GitHub answers the old address with a redirect
to the renamed repository only while no repository holds the old name; its documentation on
renaming a repository says that if the original name is reused, "redirects to the renamed
repository will no longer work". From that day every 2026.11.2 server would read the new
repository's releases, or none, and would never be offered an update again. An archive still
needs a valid release signature to be installed, so what breaks is updates that stop without a
message, not a foreign release being installed. The only way back for such a server is the
operator step in `selfhost/docs/UPGRADE-ROLLBACK.md`, "The first update from 2026.11.2"
(`CHRONICLE_RELEASES_URL`).

Releases from 2026.11.12 ask under the current name, on the API and on the releases feed, and
read the feed's links under whatever name GitHub serves. The same rule holds for any later
rename: the name a published release asks for must stay free for as long as that release can
update.

`scripts/publish-images.sh --promote` checks this before it publishes
(`scripts/check-release-discovery.py`): the release-list address each supported installed
release builds in its own code is asked, without credentials, by that release's own updater,
and must answer with this repository's published releases. The check tells three outcomes
apart, and only the first is about the name:

- **The address is lost**: a 404, or a list that holds none of this repository's releases.
  Promotion stops and points here.
- **GitHub could not be asked**: nothing was published and the same promotion can be run again.
  GitHub allows 60 API requests an hour without credentials from one address; the next one is
  refused with 403 or 429 and `x-ratelimit-remaining: 0`, and the check prints the limit and the
  reset time from `x-ratelimit-reset`
  ([Rate limits for the REST API](https://docs.github.com/en/rest/using-the-rest-api/rate-limits-for-the-rest-api)).
  A connection that fails, or a 5xx answer, is asked again with backoff for at most 120
  seconds (less when `CHRONICLE_TRANSFER_TIMEOUT_SECONDS` is lower) and then reported with
  curl's own error. The releases feed request is handled the same way.
- **An earlier list of this repository**: some of this repository's releases and no others.
  GitHub serves requests without credentials from a cache, which can be older than the last
  publish. Release ids are GitHub-wide, so those rows can only be this repository's; the check
  passes and prints the releases the list lacks. A local `public` remote
may keep the old URL; `publish-images.sh` resolves the current name with `gh repo view` for
every release call.

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

