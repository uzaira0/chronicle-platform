#!/usr/bin/env bash
# Create the cosign key pair that signs Chronicle's release images. Run once, by the maintainer.
#
#   scripts/create-image-signing-key.sh [--key-dir DIR] [--public-key PATH]
#
# The private key goes beside the release-signing key (default ~/.config/chronicle/image-signing.key,
# mode 0600, encrypted with the password cosign asks for, or COSIGN_PASSWORD). The public key is written
# to selfhost/image-signing.pub, which must be committed: every release bundle ships it, and
# `./chronicle update` checks each image signature against it (selfhost/chronicle_ops/image_signatures.py).
# scripts/publish-images.sh reads the private key from CHRONICLE_IMAGE_SIGNING_KEY or the default path.
# Never replaces an existing key: rotating it is a separate, announced change of the pinned key.
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
key_dir="$HOME/.config/chronicle"
public_key="$root/selfhost/image-signing.pub"
while (($#)); do
  case "$1" in
    --key-dir) key_dir=${2:?--key-dir needs a directory}; shift 2 ;;
    --public-key) public_key=${2:?--public-key needs a path}; shift 2 ;;
    *) echo 'usage: scripts/create-image-signing-key.sh [--key-dir DIR] [--public-key PATH]' >&2; exit 2 ;;
  esac
done
command -v cosign >/dev/null || { echo 'error: cosign is required (brew install cosign)' >&2; exit 127; }
for existing in "$key_dir/image-signing.key" "$key_dir/image-signing.pub" "$public_key"; do
  if [[ -e "$existing" || -L "$existing" ]]; then
    echo "error: $existing already exists; this script never replaces a signing key" >&2
    exit 1
  fi
done
mkdir -p "$key_dir"
chmod 0700 "$key_dir"
(
  umask 077
  cd "$key_dir"
  cosign generate-key-pair --output-key-prefix image-signing >&2
)
chmod 0600 "$key_dir/image-signing.key"
cp "$key_dir/image-signing.pub" "$public_key"
chmod 0644 "$public_key"
printf 'Private key: %s\nPublic key:  %s (commit it)\n' "$key_dir/image-signing.key" "$public_key"
printf 'Public key SHA-256: '
openssl pkey -pubin -in "$public_key" -outform DER | openssl dgst -sha256 -r | cut -d' ' -f1
