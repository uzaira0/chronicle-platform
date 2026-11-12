#!/usr/bin/env bash
# Prerequisites: authenticated gh, Docker/BuildKit with a running daemon, git, python3,
# trivy, syft, gitleaks, rg, jq, initialized source submodules, a public root remote named public, and GHCR_TOKEN:
# a dedicated token with only write:packages (never the operator's general gh token). Run from the
# main session under CAP_MEM=12G cap: CAP_MEM=12G cap scripts/publish-images.sh <release>
# <release> alone cuts a draft and records nothing; it refuses a tag that already has a release, draft
# or public (remove a stale draft yourself: gh release delete <tag> --repo <repository>).
# --promote <smoke-result.txt> publishes the draft,
# then fetches its tag and records it in selfhost/published-migrations.json; commit that file.
# --promote on a release that is already public publishes nothing: it verifies the bundle and records it.
set -euo pipefail

[[ $# -eq 1 || ( $# -eq 2 && ${2:-} == --dry-run ) ||
   ( $# -eq 3 && ${2:-} == --promote ) ]] || {
  echo 'usage: scripts/publish-images.sh <release> [--dry-run | --promote <smoke-result.txt>]' >&2
  exit 1
}
release=$1
[[ "$release" =~ ^v?[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]] || {
  echo 'error: release must be a Docker-tag-compatible semantic version' >&2
  exit 1
}
dry_run=${2:-}
# GHCR_TOKEN reaches only the docker login right before the push. Keep it in an unexported shell
# variable so no build, dependency install or scan step can read it from its environment.
ghcr_token=${GHCR_TOKEN:-}
unset GHCR_TOKEN
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
release_verify_key=${CHRONICLE_RELEASE_VERIFY_KEY:-$root/selfhost/release-signing.pub}

# The published releases at or above the upgrade floor that selfhost/published-migrations.json has
# no entry for, one tag per line. $1: `gh api --paginate --slurp repos/<repository>/releases`.
unrecorded_publications() {
  PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="$root/selfhost" python3 -c '
import json, sys
from chronicle_ops.migrations import unrecorded_publications
print("\n".join(unrecorded_publications(sys.argv[1], [row for page in json.load(sys.stdin) for row in page])))
' "$root" <<<"$1"
}

# The ledger stops a release from changing or dropping a migration that a published release shipped,
# for the releases recorded in it. A release whose promotion published it and then failed to record
# it is invisible to that check, so nothing is cut or published while one exists.
# $1: the release list as above; $2: what this refusal left undone.
require_recorded_publications() {
  local unrecorded tag
  unrecorded=$(unrecorded_publications "$1") || {
    echo "error: GitHub's release list could not be compared with selfhost/published-migrations.json (the reason is above); $2" >&2
    return 1
  }
  [[ -n "$unrecorded" ]] || return 0
  {
    while IFS= read -r tag; do
      printf 'error: %s has published %s, and selfhost/published-migrations.json does not record it.\n' "$public_repo" "$tag"
    done <<<"$unrecorded"
    printf 'That file is what stops a release from changing or dropping a migration that a published release shipped,\n'
    printf 'and it checks only the releases recorded in it; %s.\n' "$2"
    printf 'If another checkout has recorded the release, bring that commit here. Otherwise record it with the command\n'
    printf 'below: on a release that is already public it publishes nothing, downloads the bundle, verifies it against\n'
    printf 'its smoke result and writes the entry. Then commit selfhost/published-migrations.json.\n'
    while IFS= read -r tag; do
      printf '  scripts/publish-images.sh %s --promote <smoke-result.txt>\n' "$tag"
    done <<<"$unrecorded"
  } >&2
  return 1
}

# true while the release is a draft, false once GitHub has published it.
release_is_draft() { gh release view "$release" --repo "$public_repo" --json isDraft -q .isDraft; }

# Publish the draft whose verified bundle is $candidate_dir/$name. Returns once GitHub says the
# release is public; exits when it was not published or GitHub does not say.
publish_draft() {
  local catalog discovery latest now
  catalog=$(gh api --paginate --slurp "repos/$public_repo/releases")
  # The ledger check before this compared the release with the recorded releases only.
  require_recorded_publications "$catalog" 'nothing was published' || exit 1
  # Installed servers discover updates with their own updater; 2026.11.2's refuses the whole catalog
  # for one row it cannot parse. Run each supported release's discovery on the catalog as it will be,
  # and the downloaded bundle's own updater on the catalog and on the releases feed GitHub serves now
  # (a candidate bundle built before the repository was renamed could not list a release from it).
  # Each installed release's own release-list address must also still answer with this repository:
  # 2026.11.2 asks under uzaira0/methodic, which GitHub redirects only while nothing else takes that
  # name (docs/GIT-WORKFLOW.md, "The public repository's former name").
  discovery=0
  PYTHONDONTWRITEBYTECODE=1 python3 "$root/scripts/check-release-discovery.py" "$release" --bundle "$candidate_dir/$name" <<<"$catalog" || discovery=$?
  if ((discovery == 75)); then
    # The checker asked GitHub without credentials and got no answer to judge: a rate-limit
    # refusal, a failed connection, a server error. Its lines above name which.
    echo 'error: the discovery check could not be completed; nothing was published, and the promotion can be run again' >&2
    exit 1
  elif ((discovery)); then
    echo 'error: an installed release, or this bundle itself, would not discover this release; nothing was published' >&2
    exit 1
  fi
  latest=$(PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="$root/selfhost" python3 -c '
import json,sys
from chronicle_ops.update import is_stable_release, latest_stable_release, version_key
candidate = sys.argv[1]
releases = [release for page in json.load(sys.stdin) for release in page]
stable = [release for release in releases if not release.get("draft") and not release.get("prerelease")]
print(str(is_stable_release(candidate) and (not stable or version_key(candidate) >= version_key(latest_stable_release(stable)["tag_name"]))).lower())
' "$release" <<<"$catalog")
  if ! gh release edit "$release" --repo "$public_repo" --draft=false --latest="$latest"; then
    # gh can report a failure for an edit that GitHub applied: the connection is lost after the
    # request was accepted. Ask GitHub what the release is now and go on from its answer alone.
    now=$(release_is_draft) || now=unknown
    case "$now" in
      false)
        printf 'gh release edit reported a failure, but %s is public on %s: GitHub applied the edit. Recording it.\n' "$release" "$public_repo" >&2 ;;
      true)
        echo "error: gh release edit failed and $release is still a draft on $public_repo; nothing was published, and the promotion can be run again" >&2
        exit 1 ;;
      *)
        {
          printf 'error: gh release edit failed, and GitHub did not say whether %s is public now (both answers are above).\n' "$release"
          printf 'Run the same promotion again. It asks GitHub first: a release that is still a draft is published and\n'
          printf 'recorded, and one that is already public is verified and recorded without being published again.\n'
          printf '  scripts/publish-images.sh %s --promote %q\n' "$release" "$smoke_result"
        } >&2
        exit 1 ;;
    esac
  fi
}

if [[ "$dry_run" == --promote ]]; then
  smoke_result=$3
  # Every gh release call names the repository as GitHub calls it now. The public remote can
  # still carry a name from before a rename (uzaira0/methodic until 2026-11-10); GitHub redirects
  # reads of it, and a write must not depend on that redirect.
  public_remote=$(git -C "$root" remote get-url public)
  public_repo=$(gh repo view "$public_remote" --json nameWithOwner -q .nameWithOwner)
  # A draft is published and then recorded. A release that is already public is only recorded: an
  # earlier promotion can have published it without writing its entry (GitHub applied the edit and
  # gh lost the connection, or the tag fetch or the ledger write failed afterwards).
  is_draft=$(release_is_draft) || {
    echo "error: gh could not read release $release on $public_repo (its answer is above); a release that does not exist yet is cut first: scripts/publish-images.sh $release" >&2
    exit 1
  }
  [[ "$is_draft" == true || "$is_draft" == false ]] || {
    echo "error: gh did not say whether $release is a draft (it answered: $is_draft)" >&2
    exit 1
  }
  candidate_dir=$(mktemp -d)
  trap 'rm -rf -- "$candidate_dir"' EXIT
  name="chronicle-selfhost-${release#v}.tar.gz"
  # The manifest of the bundle being promoted, kept outside the temporary directory: the ledger is
  # written from it after publication, and the commands printed if that fails name it.
  promoted_manifest="$root/build/releases/chronicle-selfhost-${release#v}.promoted-manifest.json"
  gh release download "$release" --repo "$public_repo" --dir "$candidate_dir" \
    --pattern "$name" --pattern "$name.sha256" --pattern "$name.sha256.sig"
  python3 - "$root" "$candidate_dir/$name" "$smoke_result" "$release_verify_key" "$public_remote" "$release" "$promoted_manifest" <<'PY_PROMOTE'
from pathlib import Path
import json
import os
import runpy
import sys
import tarfile
root, archive, result, verify_key = map(Path, sys.argv[1:5])
public_remote, release, kept = sys.argv[5:]
builder = runpy.run_path(str(root / 'scripts/build-selfhost-release.py'))
checksum = Path(str(archive) + '.sha256')
builder['verify_release_signature'](checksum, Path(str(checksum) + '.sig'), verify_key)
builder['require_archive_checksum'](archive, checksum)
builder['require_smoke_result'](result, archive)
builder['require_public_archive_images'](archive)
with tarfile.open(archive, 'r:gz') as source:
    manifest = builder['archive_manifest'](source)
if manifest['release_version'] != release.removeprefix('v'):
    builder['fail']('candidate release version does not match the promotion tag')
builder['require_public_release_tag'](public_remote, release, manifest.get('public_revision', ''))
Path(kept).parent.mkdir(parents=True, exist_ok=True)
Path(kept).write_text(json.dumps(manifest, indent=2, sort_keys=True) + '\n')
PY_PROMOTE
  # A release the ledger cannot take (it changed or dropped a migration that a published release
  # shipped) is refused while it is still a draft. After publication only the write itself can fail.
  PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="$root/selfhost" python3 -m chronicle_ops.migrations --check "$root" "$promoted_manifest" || {
    if [[ "$is_draft" == true ]]; then
      echo 'error: selfhost/published-migrations.json cannot record this release; nothing was published' >&2
    else
      echo "error: $release is public on $public_repo and selfhost/published-migrations.json cannot record it (the reason is above)" >&2
    fi
    exit 1
  }
  if [[ "$is_draft" == true ]]; then
    publish_draft
    outcome="$release is published."
  else
    outcome="$release was already public on $public_repo."
  fi
  # The release is public from here, and only now is it recorded in selfhost/published-migrations.json,
  # from the manifest of the bundle that was promoted. A draft is not a publication: it can be replaced
  # or deleted, and GitHub creates its tag only when it publishes it. The release builder reads each
  # recorded release's Dockerfile.postgres and docker-compose.yml from refs/tags/<version> in this
  # repository (chronicle_ops/migrations.py), so that one tag is fetched before the entry is written.
  ledger="$root/selfhost/published-migrations.json"
  ledger_before=''
  [[ ! -f "$ledger" ]] || ledger_before=$(cksum <"$ledger")
  fetch_tag=(git -C "$root" fetch --no-tags public "refs/tags/$release:refs/tags/${release#v}")
  record=(env PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="$root/selfhost" python3 -m chronicle_ops.migrations "$root" "$promoted_manifest")
  if ! { "${fetch_tag[@]}" && "${record[@]}"; }; then
    fetch_line=$(printf '%q ' "${fetch_tag[@]}") record_line=$(printf '%q ' "${record[@]}")
    {
      printf 'error: %s is published on %s, but this checkout has not recorded it (the error is above).\n' "$release" "$public_repo"
      printf 'The release is public and complete. What is missing is its entry in selfhost/published-migrations.json\n'
      printf 'and its tag in this repository. Until the entry is committed no release is cut or published from here,\n'
      printf 'because a release could change or drop a migration that %s shipped without a check failing.\n' "$release"
      printf 'Correct what the error names. Then run the same promotion again (on a public release it publishes nothing:\n'
      printf 'it verifies the bundle and records it), or run these two commands; then commit selfhost/published-migrations.json:\n'
      printf '  %s\n' "${fetch_line% }" "${record_line% }"
    } >&2
    exit 1
  fi
  if [[ "$(cksum <"$ledger")" != "$ledger_before" ]]; then
    printf '%s Commit selfhost/published-migrations.json, which now records it, before building another release.\n' "$outcome"
  elif [[ "$is_draft" == true ]]; then  # a draft when this run started: this run published it
    printf '%s selfhost/published-migrations.json already recorded it, so that file has nothing new to commit.\n' "$outcome"
  else
    printf '%s is public on %s and selfhost/published-migrations.json already records it; nothing was changed.\n' "$release" "$public_repo"
  fi
  exit
fi
release_signing_key=${CHRONICLE_RELEASE_SIGNING_KEY:-$HOME/.config/chronicle/release-signing-key}
# Images are signed with a cosign key kept beside the release-signing key (scripts/create-image-signing-key.sh
# makes it once); its public half ships in the bundle, and ./chronicle update checks every first-party
# digest against it before pulling (chronicle_ops/image_signatures.py).
image_signing_key=${CHRONICLE_IMAGE_SIGNING_KEY:-$HOME/.config/chronicle/image-signing.key}
image_verify_key="$root/selfhost/image-signing.pub"
# capture assigns these variables by name, including symbolic values in dry runs.
login='' revision='' epoch='' backend_digest='' frontend_digest='' caddy_digest='' backup_digest='' postgres_digest='' grafana_digest='' fluentbit_digest=''
public_remote='' public_repo='' release_list='' notes_dir='' public_revision='' sbom_output='' release_key_fingerprint='' dependency_base=''
inputs_tree='' inputs_tree_label='' trivy_reports='' attestations=''

run() {
  if [[ -n "$dry_run" ]]; then
    printf '%q ' "$@"
    printf '\n'
  else
    "$@"
  fi
}

capture() {
  local variable=$1
  shift
  if [[ -n "$dry_run" ]]; then
    # shellcheck disable=SC2016 # Print a command substitution without executing it.
    printf '%s=$(' "$variable"
    printf '%q ' "$@"
    printf ')\n'
    printf -v "$variable" '%s' "\${${variable}}"
  else
    local value
    value=$("$@")
    printf -v "$variable" '%s' "$value"
  fi
}

# Phase timestamps on stderr: the 2026.9.25 run lost ~45 min that no log could place.
stamp() { printf '[%(%H:%M:%S)T] %s\n' -1 "$*" >&2; }

require_unchanged_source() {
  [[ $(git -C "$root" rev-parse HEAD) == "$revision" ]] || {
    echo 'error: source HEAD changed during publication' >&2
    return 1
  }
  local state submodules
  state=$(git -C "$root" status --porcelain --untracked-files=all --ignore-submodules=none) || return 1
  [[ -z "$state" ]] || {
    echo 'error: working tree is dirty; commit or clean before publishing' >&2
    return 1
  }
  submodules=$(git -C "$root" submodule status --recursive) || return 1
  ! rg -q '^[-+U]' <<<"$submodules" || {
    echo 'error: submodules do not match their gitlinks; sync before publishing' >&2
    return 1
  }
}

# The frontend dependency install (bun install) and the scans run on a snapshot of the release
# source inside scripts/deps-sandbox.sh: no host environment, no Docker or registry credentials,
# no SSH agent, no signing key, and only the allowlisted registries and scanner databases through
# the sandbox's egress proxy. Only the report directory is mounted back.
scan_publication_source() (
  local evidence="$1" snapshot reports
  reports="$root/build/releases/sca-${release#v}"
  if [[ -n "$dry_run" ]]; then
    run bash "$root/scripts/deps-sandbox.sh" --network registries --mount "$reports:/reports" --env CHRONICLE_LOCAL_CI_REPORT_DIR=/reports \
      '<snapshot>' -- bash scripts/local-ci.sh bun-audit osv
    return
  fi
  mkdir -p "$root/build/releases" "$reports"
  snapshot=$(mktemp -d "$root/build/releases/chronicle-release-sca.XXXXXX")
  trap 'rm -rf -- "$snapshot"' EXIT
  PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="$root/selfhost" python3 -c \
    'from chronicle_ops.images import archive_source; import sys; archive_source(*sys.argv[1:4], sys.stdout.buffer)' \
    "$root" "$revision" . | tar -xf - -C "$snapshot"
  bash "$root/scripts/deps-sandbox.sh" --network registries --mount "$reports:/reports" --env CHRONICLE_LOCAL_CI_REPORT_DIR=/reports \
    "$snapshot" -- bash scripts/local-ci.sh bun-audit osv
  PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="$root/selfhost" python3 - "$revision" "$reports" "$evidence" <<'PY_SCA_EVIDENCE'
from pathlib import Path
import sys
from chronicle_ops.dump import file_sha256
from chronicle_ops.receipts import write_json
revision, directory, target = sys.argv[1:]
root = Path(directory)
write_json(target, dict(sourceRevision=revision, status="passed", artifacts={
    path.relative_to(root).as_posix(): file_sha256(path) for path in root.rglob('*') if path.is_file()}))
PY_SCA_EVIDENCE
)

# `gh release create --draft` does not look for a release that already has the tag (gh 2.103.0 makes
# that lookup only for a release that is not a draft, pkg/cmd/release/create/create.go), and a draft
# holds no git tag that GitHub could refuse. A second cut of one version would leave two drafts under
# the tag; `gh release view`, `download` and `edit` then act on the one draft GitHub returns for it
# (pkg/cmd/release/shared/fetch.go), and no GitHub document says which. Promotion could verify one
# bundle and publish another. So a cut needs a tag that no release has, draft or public.
# $1: GitHub's release list. A stale draft is removed by the person running the cut, never here.
require_unused_release_tag() {
  python3 -c '
import json, sys
release, repository = sys.argv[1:]
rows = [row for page in json.load(sys.stdin) for row in page if isinstance(row, dict)]
same = [row for row in rows if str(row.get("tag_name", "")).removeprefix("v") == release.removeprefix("v")]
drafts = [row for row in same if row.get("draft")]
lines = []
for row in same:
    tag, url = row.get("tag_name"), row.get("html_url")
    if not row.get("draft"):
        lines += [f"error: {repository} has already published {tag} ({url}).",
                  "A published release is never cut again or replaced: servers and selfhost/published-migrations.json",
                  "hold it as it is. Cut the next version."]
if drafts:
    count = "a draft release" if len(drafts) == 1 else f"{len(drafts)} draft releases"
    tag = drafts[0].get("tag_name")
    urls = ", ".join(str(row.get("html_url")) for row in drafts)
    last = "and publish another. If the draft is stale, remove it yourself and cut again; this script deletes no release"
    lines += [f"error: {repository} already has {count} tagged {tag} ({urls}).",
              "gh release create --draft would add another draft under the same tag, and gh release view, download and",
              "edit would then act on whichever of them GitHub returns for the tag: a promotion could verify one bundle",
              last + (":" if len(drafts) == 1 else " (run the command once for each draft):"),
              *dict.fromkeys("  gh release delete " + str(row.get("tag_name")) + " --repo " + repository for row in drafts)]
if lines:
    print("\n".join([*lines, "Nothing was built or pushed."]), file=sys.stderr)
    sys.exit(1)
' "$release" "$public_repo" <<<"$1"
}

# A cut starts only on a tag no release has and when every published release is recorded.
# $1: GitHub's release list.
require_cut_allowed() {
  local allowed=0
  require_unused_release_tag "$1" || allowed=1
  require_recorded_publications "$1" 'nothing was built or pushed' || allowed=1
  return "$allowed"
}

run cd "$root"
capture revision git rev-parse HEAD
capture inputs_tree_label env PYTHONPATH="$root/selfhost" python3 -c 'from chronicle_ops.images import INPUTS_TREE_LABEL; print(INPUTS_TREE_LABEL)'
capture inputs_tree env PYTHONPATH="$root/selfhost" python3 -c 'from chronicle_ops.images import source_inputs_tree; import sys; print(source_inputs_tree(*sys.argv[1:]))' "$root" "$revision"
if [[ -z "$dry_run" ]]; then
  [[ -n "$ghcr_token" ]] || {
    echo 'error: GHCR_TOKEN is unset; export a dedicated token with only write:packages' >&2
    exit 1
  }
  [[ -f "$release_signing_key" ]] || {
    echo 'error: release signing key is missing; set CHRONICLE_RELEASE_SIGNING_KEY or install the default release-signing-key' >&2
    exit 1
  }
  [[ -f "$release_verify_key" ]] || {
    echo 'error: release verification key is missing; set CHRONICLE_RELEASE_VERIFY_KEY to the trusted public key' >&2
    exit 1
  }
  [[ -f "$image_signing_key" ]] || {
    echo 'error: image signing key is missing; run scripts/create-image-signing-key.sh once, or set CHRONICLE_IMAGE_SIGNING_KEY' >&2
    exit 1
  }
  git -C "$root" ls-files --error-unmatch selfhost/image-signing.pub >/dev/null 2>&1 || {
    echo 'error: selfhost/image-signing.pub is not committed; scripts/create-image-signing-key.sh writes it' >&2
    exit 1
  }
  command -v ssh-keygen >/dev/null || { echo 'error: missing tool: ssh-keygen' >&2; exit 1; }
  for tool in docker gh git python3 trivy syft jq rg cosign openssl; do
    command -v "$tool" >/dev/null || { echo "error: missing tool: $tool" >&2; exit 1; }
  done
  # The build tars the working tree but the release attests git rev-parse HEAD, so a dirty
  # tree or a submodule off its gitlink would ship bytes that exist in no commit.
  require_unchanged_source
  # Match the builder before any registry side effects (calendar-style 09 is invalid).
  python3 - "$release" "$root/scripts/build-selfhost-release.py" <<'PY'
from pathlib import Path
import runpy
import sys
version = sys.argv[1].removeprefix("v")
core, _, pre = version.partition("-")
if (any(len(p) > 1 and p.startswith("0") for p in core.split("."))
        or (pre and any(not p or (p.isdigit() and len(p) > 1 and p.startswith("0"))
                        for p in pre.split(".")))):
    sys.exit("error: release must use semantic versioning without numeric leading zeroes")
builder = runpy.run_path(sys.argv[2])
builder["require_changelog"](Path(sys.argv[2]).resolve().parents[1] / "CHANGELOG.md", version)
PY
fi
# What the public repository holds now, before anything is verified, downloaded, built or pushed.
# These are the first requests of a cut: the token, the keys, the tools, the clean tree and the
# changelog entry above are checked without asking GitHub anything. The repository is named as
# GitHub calls it today (see the promotion path above).
capture public_remote git remote get-url public
capture public_repo gh repo view "$public_remote" --json nameWithOwner -q .nameWithOwner
capture release_list gh api --paginate --slurp "repos/$public_repo/releases"
run require_cut_allowed "$release_list"
# Verify all filtered source trees, including submodules, before registry side effects.
release_signer=$(PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="$root/selfhost" python3 -c \
  'from chronicle_ops.release import RELEASE_SIGNER; print(RELEASE_SIGNER)')
capture public_revision bash "$root/scripts/publish.sh" verify-source
run python3 -c '
import runpy, sys
runpy.run_path(sys.argv[1])["require_public_release_tag"](*sys.argv[2:])
' "$root/scripts/build-selfhost-release.py" "$public_remote" "$release" "$public_revision"
# Every pin changed since the last published source must be past its wait (docs/SUPPLY-CHAIN.md):
# 7 days routine, 14 major, 3 security, or an entry in dependency-exceptions.toml. Any OSV MAL- fails.
stamp 'dependency age gate'
capture dependency_base git -C "$root" describe --tags --abbrev=0 --match 'published-*' "$revision^"
run python3 "$root/scripts/check-dependency-age.py" --root "$root" --base "${CHRONICLE_DEPENDENCY_BASE:-$dependency_base}" \
  --report "$root/build/releases/dependency-age-${release#v}.txt"
# Fetch the vulnerability DBs first so a slow or failed download shows up before any build.
stamp 'trivy db download'
run trivy image --quiet --download-db-only
run trivy image --quiet --download-java-db-only
capture login gh api user -q .login
[[ -n "$dry_run" ]] || login=${login,,}
capture epoch git log -1 --format=%ct
backend="ghcr.io/$login/chronicle-backend:$release"
frontend="ghcr.io/$login/chronicle-selfhost-frontend:$release"
caddy="ghcr.io/$login/chronicle-selfhost-caddy:$release"
backup="ghcr.io/$login/chronicle-selfhost-backup:$release"
postgres="ghcr.io/$login/chronicle-selfhost-postgres:$release"
grafana="ghcr.io/$login/chronicle-selfhost-grafana:$release"
fluentbit="ghcr.io/$login/chronicle-selfhost-fluentbit:$release"
# Build from a tar of tracked files. The directory walk of the checkout (hundreds of MB of
# untracked build output) starves the BuildKit session healthcheck on a loaded host and
# dockerd cancels the build; the tracked tree is a few tens of MB.
# Release images are linux/amd64 on every build host (the 2026.11.2 images were; Dockerfile.fluentbit
# unpacks an amd64 libbrotli; .trivyignore.yaml purls name arch=x86_64). An unpinned build on an
# arm64 Mac produced arm64 images. scan-selfhost-release-images.sh scans the same platform.
release_platform=linux/amd64
# BuildKit records each build's SLSA provenance (mode=max: Dockerfile, build arguments, base image
# digests) in the metadata file; after the push it is attested with cosign against the pushed digest.
# The daemon's docker driver cannot attach attestations to an image itself.
build_image() { # build_image <component> <context dir> <dockerfile in context> <tag> [docker build args...]
  local component=$1 ctx=$2 dockerfile=$3 tag=$4
  shift 4
  if [[ -n "$dry_run" ]]; then
    # shellcheck disable=SC2016 # The plan intentionally prints the revision variable literally.
    printf '(cd %q && git archive --format=tar "$revision") | ' "$ctx"
    printf '%q ' env BUILDX_METADATA_PROVENANCE=max docker build --platform "$release_platform" -f "$dockerfile" -t "$tag" --label "org.opencontainers.image.revision=$revision" --label "$inputs_tree_label=$inputs_tree" --metadata-file "$attestations/$component.metadata.json" "$@" -
    printf '\n'
  else
    PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="$root/selfhost" python3 -c 'from chronicle_ops.images import SOURCE_IMAGES; import sys
next(image for image in SOURCE_IMAGES if image.component == sys.argv[3]).archive(sys.argv[1], sys.argv[2], sys.stdout.buffer)' "$root" "$revision" "$component" |
      BUILDX_METADATA_PROVENANCE=max docker build --platform "$release_platform" -f "$dockerfile" -t "$tag" --label "org.opencontainers.image.revision=$revision" --label "$inputs_tree_label=$inputs_tree" --metadata-file "$attestations/$component.metadata.json" "$@" -
  fi
}
# Nothing reaches the registry with a fixable HIGH or CRITICAL finding or a secret in a layer. Each
# image is scanned right after its build, smallest first, so a finding fails the run before the next
# build. Every image, built here or third-party (scripts/check-runtime-images.py below), must have no SSH
# server, no undeclared listener, and a non-root USER, a HEALTHCHECK, no setuid file and no build tool
# unless config/image-policy.toml says why. The scans' JSON reports go to $trivy_reports, so the run
# can fail on a .trivyignore.yaml entry that suppressed nothing.
scan_image() { # scan_image <tag> <component>
  stamp "scan $1"
  run bash "$root/scripts/check-image-no-ssh-server.sh" "$1"
  run bash "$root/scripts/check-image-listeners.sh" "$1"
  run python3 "$root/scripts/check-image-policy.py" "$2=$1"
  run env CHRONICLE_TRIVY_REPORT_DIR="$trivy_reports" bash "$root/scripts/scan-selfhost-release-images.sh" "$1"
}
build_component() {
  local component=$1 tag=$2 paths context dockerfile
  shift 2
  paths=$(PYTHONPATH="$root/selfhost" python3 - "$component" <<'PY_IMAGE_PATHS'
import os
import sys
from chronicle_ops.images import SOURCE_IMAGES
image = next(image for image in SOURCE_IMAGES if image.component == sys.argv[1])
context = os.path.normpath('selfhost/' + image.context)
print(context, os.path.relpath('selfhost/' + image.dockerfile, context))
PY_IMAGE_PATHS
  )
  read -r context dockerfile <<<"$paths"
  stamp "build $tag"
  build_image "$component" "$context" "$dockerfile" "$tag" "$@"
  scan_image "$tag" "$component"
}
run mkdir -p "$root/build/releases"
capture trivy_reports mktemp -d "$root/build/releases/trivy-reports-${release#v}.XXXXXX"
capture attestations mktemp -d "$root/build/releases/image-attestations-${release#v}.XXXXXX"
build_component backup "$backup"
build_component postgres "$postgres"
build_component frontend "$frontend" \
  --build-arg "GIT_SHA=$revision" --build-arg "SOURCE_REF=$release"
build_component caddy "$caddy" --build-arg "SOURCE_REF=$release" --build-context "chronicle-selfhost-frontend:release=docker-image://$frontend"
build_component grafana "$grafana"
build_component fluentbit "$fluentbit"
build_component backend "$backend" \
  --build-arg "VCS_REF=$revision" --build-arg "SOURCE_REF=$release"
stamp 'scan release runtime dependencies'
run env CHRONICLE_TRIVY_REPORT_DIR="$trivy_reports" bash "$root/scripts/scan-selfhost-release-images.sh"
run python3 "$root/scripts/check-runtime-images.py"
run python3 "$root/tests/security/check-trivy-waivers.py" "$root/.trivyignore.yaml" --reports "$trivy_reports"
run require_unchanged_source
stamp 'frontend lockfile vulnerability evidence'
run mkdir -p "$root/build/releases"
sca_evidence="$root/build/releases/chronicle-frontend-vulnerabilities-${release#v}.json"
run scan_publication_source "$sca_evidence"
run require_unchanged_source
stamp push
# Registry credentials exist only from here to the logout after the last push.
if [[ -n "$dry_run" ]]; then
  # shellcheck disable=SC2016 # The dry-run login is intentionally literal.
  printf '%s\n' 'printf %s "$ghcr_token" | docker login ghcr.io --username "${login}" --password-stdin'
else
  trap 'docker logout ghcr.io >/dev/null 2>&1 || true' EXIT
  printf %s "$ghcr_token" | docker login ghcr.io --username "$login" --password-stdin
fi
run docker push "$backend"
run docker push "$frontend"
run docker push "$caddy"
run docker push "$backup"
run docker push "$postgres"
run docker push "$grafana"
run docker push "$fluentbit"
resolve_published_digest() {
  docker inspect --format '{{json .RepoDigests}}' "$1" |
    jq -er --arg repository "${1%:*}" '
      [.[] | select(startswith($repository + "@sha256:")) | select(test("@sha256:[0-9a-f]{64}$"))]
      | if length == 1 then .[0] else error("missing or ambiguous published repository digest") end'
}
capture backend_digest resolve_published_digest "$backend"
capture frontend_digest resolve_published_digest "$frontend"
capture caddy_digest resolve_published_digest "$caddy"
capture backup_digest resolve_published_digest "$backup"
capture postgres_digest resolve_published_digest "$postgres"
capture grafana_digest resolve_published_digest "$grafana"
capture fluentbit_digest resolve_published_digest "$fluentbit"
# Sign each pushed digest and attest its provenance, still logged in: cosign stores both beside the image
# in the registry and writes the Sigstore bundles the release ships. No transparency log
# (scripts/cosign-signing-config.json): the key, not a public log, is what operators pin.
stamp 'sign images and attest provenance'
if [[ -z "$dry_run" && -z "${COSIGN_PASSWORD+set}" ]]; then
  read -rsp 'image-signing key password: ' cosign_password </dev/tty
  printf '\n' >&2
  COSIGN_PASSWORD=$cosign_password
fi
export COSIGN_PASSWORD
sign_image() { # sign_image <component> <digest reference>
  run python3 -c '
import json, sys
metadata = json.load(open(sys.argv[1]))
json.dump(metadata["buildx.build.provenance"], open(sys.argv[2], "w"), sort_keys=True)
' "$attestations/$1.metadata.json" "$attestations/$1.provenance.json"
  run cosign sign --yes --key "$image_signing_key" --signing-config "$root/scripts/cosign-signing-config.json" \
    --bundle "$attestations/$1.signature.sigstore.json" "$2"
  run cosign attest --yes --key "$image_signing_key" --signing-config "$root/scripts/cosign-signing-config.json" \
    --type slsaprovenance02 --predicate "$attestations/$1.provenance.json" \
    --bundle "$attestations/$1.provenance.sigstore.json" "$2"
  # The registry copies verify with the public key that ships in the bundle.
  run cosign verify --key "$image_verify_key" --insecure-ignore-tlog "$2"
  run cosign verify-attestation --key "$image_verify_key" --insecure-ignore-tlog --type slsaprovenance02 "$2"
}
sign_image backend "$backend_digest"
sign_image frontend "$frontend_digest"
sign_image caddy "$caddy_digest"
sign_image backup "$backup_digest"
sign_image postgres "$postgres_digest"
sign_image grafana "$grafana_digest"
sign_image fluentbit "$fluentbit_digest"
unset COSIGN_PASSWORD
run docker logout ghcr.io
[[ -n "$dry_run" ]] || trap - EXIT
# The private HEAD exists in no public repository. Record and tag the curated public commit
# verified above so the bundle maps to published source.
stamp 'bundle and GitHub release'
bundle="build/releases/chronicle-selfhost-${release#v}.tar.gz"
if [[ -z "$dry_run" && ( -e "$bundle.sha256.sig" || -L "$bundle.sha256.sig" ) ]]; then
  echo 'error: refusing to replace an existing release signature' >&2
  exit 1
fi
run python3 scripts/build-selfhost-release.py --version "$release" \
  --source-revision "$revision" --public-revision "$public_revision" --source-date-epoch "$epoch" \
  --backend-image "$backend_digest" --frontend-image "$frontend_digest" --caddy-image "$caddy_digest" \
  --backup-image "$backup_digest" --grafana-image "$grafana_digest" --postgres-image "$postgres_digest" --fluentbit-image "$fluentbit_digest" \
  --image-signatures "$attestations"
run ssh-keygen -Y sign -n "$release_signer" -f "$release_signing_key" "$bundle.sha256"
run python3 -c '
from pathlib import Path
import runpy
import sys
root, checksum, verify_key = map(Path, sys.argv[1:])
runpy.run_path(str(root / "scripts/build-selfhost-release.py"))["verify_release_signature"](
    checksum, Path(str(checksum) + ".sig"), verify_key)
' "$root" "$bundle.sha256" "$release_verify_key"
capture sbom_output env CHRONICLE_SBOM_SOURCE_REVISION="$revision" bash "$root/scripts/write-image-sboms.sh" "$release" "$root/build/releases" \
  "$backend_digest" "$frontend_digest" "$caddy_digest" "$backup_digest" "$grafana_digest" "$postgres_digest" "$fluentbit_digest"
mapfile -t sbom_assets <<< "$sbom_output"
run mkdir -p "$HOME/tmp"
capture notes_dir mktemp -d -p "$HOME/tmp" chronicle-release-notes.XXXXXX
if [[ -z "$dry_run" ]]; then
  trap 'rm -rf -- "$notes_dir"' EXIT
fi
# Operators land on this page, and `./chronicle update --check` prints it: lead with the steps.
capture release_key_fingerprint ssh-keygen -lf "$release_verify_key" -E sha256
# shellcheck disable=SC2016 # Python writes literal shell commands into the release notes.
run python3 -c '
from pathlib import Path
import sys
release, destination, fingerprint, signer = sys.argv[1:]
v = release.removeprefix("v")
Path(destination).write_text(f"""## New installation

Download `chronicle-selfhost-{v}.tar.gz`, its `.sha256` and `.sha256.sig` sidecars.
The public key ships in the bundle. Extract only the key and show its fingerprint:

```bash
set -e
tar -xzOf chronicle-selfhost-{v}.tar.gz chronicle-selfhost-{v}/selfhost/release-signing.pub > release-signing.pub
ssh-keygen -lf release-signing.pub -E sha256
```

Compare it with the fingerprint the maintainer sent separately by email or message from
the Chronicle contact for your study. If it differs, stop. Do not install.
This release expects `{fingerprint.split()[1]}`.
Run the next commands on the Linux server, as a user in the `docker` group:

```bash
set -e
printf "{signer} %s\\n" "$(cat release-signing.pub)" > allowed_signers
ssh-keygen -Y verify -f allowed_signers -I {signer} -n {signer} \\
  -s chronicle-selfhost-{v}.tar.gz.sha256.sig < chronicle-selfhost-{v}.tar.gz.sha256
# Check the download and unpack it. Images are pulled later.
sha256sum -c chronicle-selfhost-{v}.tar.gz.sha256
tar -xzpf chronicle-selfhost-{v}.tar.gz
cd chronicle-selfhost-{v}/selfhost
# Configure the domain, TLS mode and dashboard password. Secrets are generated.
./chronicle setup
# Check the host, pull the images and start.
./chronicle up
# Check server access, backups and health.
./chronicle verify
./chronicle doctor
```

Use an SSH tunnel for the private dashboard at `https://127.0.0.1:8081/chronicle`.
The public domain serves only phones. See `selfhost/README.md`, section "Quick start".

## Image signatures and provenance

Each first-party image digest in `release-manifest.json` (`images`) is signed with the key in
`selfhost/image-signing.pub` and carries a signed SLSA provenance attestation of its build.
`./chronicle update` checks both, offline, before it pulls a new release. To check the registry
copies yourself with cosign:

```bash
cosign verify --key selfhost/image-signing.pub --insecure-ignore-tlog IMAGE@DIGEST
cosign verify-attestation --key selfhost/image-signing.pub --insecure-ignore-tlog --type slsaprovenance02 IMAGE@DIGEST
```

The signatures are not in a public transparency log; the pinned key is the trust anchor.

To discard an existing installation and its data, first follow `selfhost/docs/UNINSTALL-DATA-DELETION.md`,
section "Remove the application and all installation storage".

## Updating an existing installation

From the current installation'"'"'s `selfhost/` directory:

```bash
./chronicle update --check
./chronicle update
```

Post-reset installations upgrade in place and keep their data. The signed manifest declares
`upgrade_from_minimum`. Installs below that floor require a fresh installation with fresh
volumes. Pre-reset backups cannot migrate into this baseline. See `selfhost/docs/UPGRADE-ROLLBACK.md`.
A failed update automatically restores its safety dump and previous release.

## What changed

See `CHANGELOG.md` in the bundle, section [{v}].
""")
' "$release" "$notes_dir/notes.md" "$release_key_fingerprint" "$release_signer"
# Keep candidates out of the update channel until the downloaded artifact has been drilled.
release_flags=(--draft --latest=false)
[[ "$release" != *-* ]] || release_flags+=(--prerelease)
run gh release create "$release" --repo "$public_repo" --target "$public_revision" \
  "$bundle" "$bundle.sha256" "$bundle.sha256.sig" "$sca_evidence" "${sbom_assets[@]}" --notes-file "$notes_dir/notes.md" "${release_flags[@]}"
# Nothing is recorded here: a draft is not a publication. --promote writes the ledger once the
# release is public (see the promotion path above).
printf '%s is a draft, not a publication. After the smoke drill, scripts/publish-images.sh %s --promote <smoke-result.txt> publishes it and records it in selfhost/published-migrations.json.\n' "$release" "$release"
if [[ -n "$dry_run" ]]; then
  run rm -rf -- "$notes_dir"
fi
stamp 'done'
