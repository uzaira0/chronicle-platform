#!/usr/bin/env bash
# Scan explicit image references, or the self-host release and optional overlay inventory.
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
command -v trivy >/dev/null 2>&1 || { echo 'error: trivy is required to scan release runtime images' >&2; exit 127; }

if [[ $# -gt 0 ]]; then
  for image in "$@"; do
    [[ -n "$image" && "$image" != -* && "$image" != *[[:space:]]* ]] || {
      echo 'error: expected an image reference without whitespace or a leading hyphen' >&2
      exit 2
    }
  done
  images=$(printf '%s\n' "$@")
else
  command -v python3 >/dev/null 2>&1 || { echo 'error: python3 is required for the image inventory' >&2; exit 127; }
  images=$(PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="$root/selfhost" python3 - "$root/selfhost" <<'PY_IMAGE_INVENTORY'
import re
import sys
from chronicle_ops.images import SOURCE_IMAGES, bundle_images
placeholders = {image.placeholder for image in SOURCE_IMAGES}
for image in sorted(bundle_images(sys.argv[1]) - placeholders):
    if not re.fullmatch(r"[^\s@]+@sha256:[0-9a-f]{64}", image):
        raise SystemExit("error: runtime image inventory contains a mutable image")
    print(image)
PY_IMAGE_INVENTORY
  )
  [[ -n "$images" ]] || { echo 'error: no release runtime images were found' >&2; exit 2; }
fi

while IFS= read -r image; do
  [[ -n "$image" ]] || continue
  printf 'Scanning release runtime image %s\n' "$image" >&2
  trivy image --quiet --scanners vuln --severity HIGH,CRITICAL --exit-code 1 \
    --skip-db-update --skip-java-db-update --ignorefile "$root/.trivyignore.yaml" "$image"
done <<< "$images"
