#!/usr/bin/env bash
# Prerequisites: authenticated gh, Docker/BuildKit with a running daemon, git, python3,
# trivy, syft, gitleaks, rg, jq, initialized source submodules, a public root remote named public, and GHCR_TOKEN:
# a dedicated token with only write:packages (never the operator's general gh token). Run from the
# main session under CAP_MEM=12G cap: CAP_MEM=12G cap scripts/publish-images.sh <release>
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
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
release_verify_key=${CHRONICLE_RELEASE_VERIFY_KEY:-$root/selfhost/release-signing.pub}
if [[ "$dry_run" == --promote ]]; then
  public_repo=$(git -C "$root" remote get-url public)
  [[ $(gh release view "$release" --repo "$public_repo" --json isDraft -q .isDraft) == true ]] || {
    echo 'error: promotion requires a draft release' >&2
    exit 1
  }
  candidate_dir=$(mktemp -d)
  trap 'rm -rf -- "$candidate_dir"' EXIT
  name="chronicle-selfhost-${release#v}.tar.gz"
  gh release download "$release" --repo "$public_repo" --dir "$candidate_dir" \
    --pattern "$name" --pattern "$name.sha256" --pattern "$name.sha256.sig"
  python3 - "$root" "$candidate_dir/$name" "$3" "$release_verify_key" "$public_repo" "$release" <<'PY_PROMOTE'
from pathlib import Path
import os
import runpy
import sys
import tarfile
root, archive, result, verify_key = map(Path, sys.argv[1:5])
public_repo, release = sys.argv[5:]
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
builder['require_public_release_tag'](public_repo, release, manifest.get('public_revision', ''))
PY_PROMOTE
  catalog_repo=$(gh repo view "$public_repo" --json nameWithOwner -q .nameWithOwner)
  catalog=$(gh api --paginate --slurp "repos/$catalog_repo/releases")
  latest=$(PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="$root/selfhost" python3 -c '
import json,sys
from chronicle_ops.update import is_stable_release, latest_stable_release, version_key
candidate = sys.argv[1]
releases = [release for page in json.load(sys.stdin) for release in page]
stable = [release for release in releases if not release.get("draft") and not release.get("prerelease")]
print(str(is_stable_release(candidate) and (not stable or version_key(candidate) >= version_key(latest_stable_release(stable)["tag_name"]))).lower())
' "$release" <<<"$catalog")
  gh release edit "$release" --repo "$public_repo" --draft=false --latest="$latest"
  exit
fi
release_signing_key=${CHRONICLE_RELEASE_SIGNING_KEY:-$HOME/.config/chronicle/release-signing-key}
# capture assigns these variables by name, including symbolic values in dry runs.
login='' revision='' epoch='' backend_digest='' frontend_digest='' caddy_digest='' backup_digest='' postgres_digest='' grafana_digest='' fluentbit_digest=''
public_repo='' notes_dir='' public_revision='' sbom_output='' release_key_fingerprint=''
inputs_tree='' inputs_tree_label=''

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

scan_publication_source() (
  local evidence="$1" snapshot reports
  if [[ -n "$dry_run" ]]; then
    run bash "$root/scripts/local-ci.sh" bun-audit osv
    return
  fi
  snapshot=$(mktemp -d "${TMPDIR:-$root/build/releases}/chronicle-release-sca.XXXXXX")
  trap 'rm -rf -- "$snapshot"' EXIT
  PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="$root/selfhost" python3 -c \
    'from chronicle_ops.images import archive_source; import sys; archive_source(*sys.argv[1:4], sys.stdout.buffer)' \
    "$root" "$revision" . | tar -xf - -C "$snapshot"
  reports="$root/build/releases/sca-${release#v}"
  CHRONICLE_LOCAL_BIN_DIR="${CHRONICLE_LOCAL_BIN_DIR:-$root/.local/bin}" \
    CHRONICLE_LOCAL_CI_REPORT_DIR="$reports" bash "$snapshot/scripts/local-ci.sh" bun-audit osv
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

run cd "$root"
capture revision git rev-parse HEAD
capture inputs_tree_label env PYTHONPATH="$root/selfhost" python3 -c 'from chronicle_ops.images import INPUTS_TREE_LABEL; print(INPUTS_TREE_LABEL)'
capture inputs_tree env PYTHONPATH="$root/selfhost" python3 -c 'from chronicle_ops.images import source_inputs_tree; import sys; print(source_inputs_tree(*sys.argv[1:]))' "$root" "$revision"
if [[ -z "$dry_run" ]]; then
  [[ -n "${GHCR_TOKEN:-}" ]] || {
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
  command -v ssh-keygen >/dev/null || { echo 'error: missing tool: ssh-keygen' >&2; exit 1; }
  for tool in docker gh git python3 trivy syft jq rg; do
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
# Verify all filtered source trees, including submodules, before registry side effects.
release_signer=$(PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="$root/selfhost" python3 -c \
  'from chronicle_ops.release import RELEASE_SIGNER; print(RELEASE_SIGNER)')
capture public_revision bash "$root/scripts/publish.sh" verify-source
capture public_repo git remote get-url public
run python3 -c '
import runpy, sys
runpy.run_path(sys.argv[1])["require_public_release_tag"](*sys.argv[2:])
' "$root/scripts/build-selfhost-release.py" "$public_repo" "$release" "$public_revision"
# Fetch the vulnerability DBs first so a slow or failed download shows up before any build.
stamp 'trivy db download'
run trivy image --quiet --download-db-only
run trivy image --quiet --download-java-db-only
capture login gh api user -q .login
if [[ -n "$dry_run" ]]; then
  # shellcheck disable=SC2016 # The dry-run login is intentionally literal.
  printf '%s\n' 'printf %s "$GHCR_TOKEN" | docker login ghcr.io --username "${login}" --password-stdin'
else
  printf %s "$GHCR_TOKEN" | docker login ghcr.io --username "$login" --password-stdin
  login=${login,,}
fi
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
build_image() { # build_image <component> <context dir> <dockerfile in context> <tag> [docker build args...]
  local component=$1 ctx=$2 dockerfile=$3 tag=$4
  shift 4
  if [[ -n "$dry_run" ]]; then
    # shellcheck disable=SC2016 # The plan intentionally prints the revision variable literally.
    printf '(cd %q && git archive --format=tar "$revision") | ' "$ctx"
    printf '%q ' docker build -f "$dockerfile" -t "$tag" --label "org.opencontainers.image.revision=$revision" --label "$inputs_tree_label=$inputs_tree" "$@" -
    printf '\n'
  else
    PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="$root/selfhost" python3 -c 'from chronicle_ops.images import SOURCE_IMAGES; import sys
next(image for image in SOURCE_IMAGES if image.component == sys.argv[3]).archive(sys.argv[1], sys.argv[2], sys.stdout.buffer)' "$root" "$revision" "$component" |
      docker build -f "$dockerfile" -t "$tag" --label "org.opencontainers.image.revision=$revision" --label "$inputs_tree_label=$inputs_tree" "$@" -
  fi
}
# Nothing reaches the registry with a fixable HIGH or CRITICAL finding. Each image is scanned
# right after its build, smallest first, so a finding fails the run before the next build.
scan_image() {
  stamp "scan $1"
  run bash "$root/scripts/scan-selfhost-release-images.sh" "$1"
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
  scan_image "$tag"
}
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
run bash "$root/scripts/scan-selfhost-release-images.sh"
run require_unchanged_source
stamp 'frontend lockfile vulnerability evidence'
run mkdir -p "$root/build/releases"
sca_evidence="$root/build/releases/chronicle-frontend-vulnerabilities-${release#v}.json"
run scan_publication_source "$sca_evidence"
run require_unchanged_source
stamp push
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
  --backup-image "$backup_digest" --grafana-image "$grafana_digest" --postgres-image "$postgres_digest" --fluentbit-image "$fluentbit_digest"
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
run env PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="$root/selfhost" python3 -m chronicle_ops.migrations \
  "$root" "${bundle%.tar.gz}/release-manifest.json"
printf 'Commit selfhost/published-migrations.json before building another release.\n'
if [[ -n "$dry_run" ]]; then
  run rm -rf -- "$notes_dir"
fi
stamp 'done'
