#!/usr/bin/env bash
# Endorse a new self-host release signing key with the current one (CI-U7).
#
# Usage: scripts/endorse-release-key.sh OLD_PRIVATE_KEY NEW_PUBLIC_KEY OUTPUT_DIRECTORY
#
# Writes OUTPUT_DIRECTORY/release-signing.pub (the new key) and release-signing.pub.sig, the old
# key's signature over it in the chronicle-release-key namespace. Upload both as assets of every
# release signed by the new key, and commit the new key as selfhost/release-signing.pub so the
# bundle ships it. `./chronicle update` (2026.11.6 and later) then accepts the release with no
# operator step. Updaters older than 2026.11.6 cannot rotate: keep the old key until no server
# runs one. The old key is only read here; the namespace keeps a checksum signature from ever
# serving as an endorsement.
set -euo pipefail

[[ $# -eq 3 ]] || { echo "usage: $0 OLD_PRIVATE_KEY NEW_PUBLIC_KEY OUTPUT_DIRECTORY" >&2; exit 2; }
old_key="$1"
new_public="$2"
output="$3"
namespace="chronicle-release-key"

read -r key_type _ <"$new_public"
[[ "$key_type" == ssh-ed25519 ]] || { echo "error: the new key must be ssh-ed25519" >&2; exit 1; }
mkdir -p "$output"
[[ ! -e "$output/release-signing.pub" && ! -e "$output/release-signing.pub.sig" ]] \
  || { echo "error: $output already holds an endorsement; choose an empty directory" >&2; exit 1; }
cp "$new_public" "$output/release-signing.pub"
ssh-keygen -Y sign -q -n "$namespace" -f "$old_key" "$output/release-signing.pub"

# Verify against the old public key exactly as the updater does before reporting success.
old_public="$(ssh-keygen -y -f "$old_key")"
allowed="$(mktemp "$output/.allowed_signers.XXXXXX")"
trap 'unlink "$allowed"' EXIT
printf 'chronicle-release namespaces="%s" %s\n' "$namespace" "$old_public" >"$allowed"
ssh-keygen -Y verify -f "$allowed" -I chronicle-release -n "$namespace" \
  -s "$output/release-signing.pub.sig" <"$output/release-signing.pub" >/dev/null
echo "Endorsed $(ssh-keygen -lf "$output/release-signing.pub" -E sha256)"
echo "Upload $output/release-signing.pub and $output/release-signing.pub.sig with each release the new key signs."
