# Contributing

Chronicle is developed in private repositories and published to these public mirrors.
Each publish condenses the private work into logical commits with Conventional Commits
messages. Experiments, reverts, and operational detail stay private.

## How to contribute

- **Issues** are open on the root repository ([uzaira0/chronicle-platform](https://github.com/uzaira0/chronicle-platform)).
  Include the commit you are on (`git rev-parse --short HEAD`) and what you observed.
- **Pull requests** are welcome against the default branch of any public repository. A
  maintainer integrates an accepted change into the private tree, and the next publish
  carries it here with your authorship preserved (the original commit, or a fresh one with
  `Co-authored-by`, and a changelog line linking the pull request). The pull request itself
  is closed at that point rather than merged, because public history is written only by the
  publish step.
- **Security problems**: do not open an issue. See [SECURITY.md](SECURITY.md).

## Before opening a pull request

1. Run the local checks. There is no hosted CI; everything runs on your machine:

   ```bash
   lefthook install                # secrets scan on commit, lint gates on push
   scripts/local-ci.sh fast        # run explicitly; publishing runs no test gate
   scripts/i18n-lint.sh            # no hardcoded user-facing English
   ```

2. Keep the change focused: one behaviour per pull request, tests alongside the code,
   and no unrelated reformatting.
3. Commit messages follow Conventional Commits (`fix(web): keep the switcher off the diary`),
   with a body that says why; `scripts/check-commit-msg.sh <file>` checks a draft and
   `docs/GIT-WORKFLOW.md` has the types, scopes, and examples.
4. User-facing strings go through the translation tables (web `src/modern/i18n`, Android
   `values/strings.xml`, iOS String Catalogs, server `messages.properties`). Never author
   translations; add the English key and leave the other languages to translators. The one
   exception is an owner-approved draft in a translator's own wording, recorded in
   `docs/i18n-provenance-<code>.tsv`.
5. Changing English that already has a translation makes that translation stale:
   `docs/i18n-source-<code>.tsv` records the English each translated line was made from, and
   `make i18n-source-check LANG=es` (also run by `scripts/local-ci.sh fast`) lists the lines
   whose English has changed, and the Android strings some build flavor would show untranslated
   (including a flavor's own English that only main's translation covers). Send them to the
   translators; a workbook import (`make i18n-sheet-import`) records the new English for the
   rows it changes. When the
   translation still fits (a capitalisation change, say), confirm it with
   `make i18n-source-stamp LANG=es KEYS="<key> ..."`.

## Working with the submodules

The root repository pins every submodule to a public commit. Clone recursively:

```bash
git clone --recurse-submodules https://github.com/uzaira0/chronicle-platform.git chronicle
```

Changes that span repositories should be one pull request per repository, cross-linked.

## Licence

By contributing you agree that your contribution is licensed under the licence of the
repository it lands in (see each repository's `LICENSE`).
