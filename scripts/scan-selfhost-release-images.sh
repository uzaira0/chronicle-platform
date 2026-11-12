#!/usr/bin/env bash
# Scan explicit image references, or the self-host release and optional overlay inventory.
#
#   scripts/scan-selfhost-release-images.sh IMAGE...
#   scripts/scan-selfhost-release-images.sh [--inventory SELFHOST_DIR]
#
# Each image is scanned for HIGH and CRITICAL vulnerabilities and for secrets in any layer (container-infra
# checklist I8: a key copied in and deleted later still sits in the earlier layer).
# CHRONICLE_TRIVY_REPORT_DIR=DIR also writes one JSON report per image, with the waived findings
# (--show-suppressed), for tests/security/check-trivy-waivers.py --reports DIR: Trivy itself never
# reports an ignore entry that matched nothing.
# --inventory reads the compose inventory of another checkout's selfhost/ (the dependency gate
# runner's candidate) with this checkout's parser and ignore file.
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
inventory="$root/selfhost"
if [[ "${1:-}" == --inventory ]]; then
  [[ -d "${2:-}" ]] || { echo 'error: --inventory takes a selfhost directory' >&2; exit 2; }
  inventory=$2
  shift 2
fi
command -v trivy >/dev/null 2>&1 || { echo 'error: trivy is required to scan release runtime images' >&2; exit 127; }

if [[ $# -gt 0 ]]; then
  for image in "$@"; do
    [[ -n "$image" && "$image" != -* && "$image" != *[[:space:]]* ]] || {
      echo 'error: expected an image reference without whitespace or a leading hyphen' >&2
      exit 2
    }
  done
  images=$(printf '%s\n' "$@")
  image_source=()
else
  # Third-party runtime images are pulled from their registries by digest: trivy's docker source would scan
  # whatever platform the local daemon already holds (an arm64 copy on an arm64 host), ignoring --platform.
  image_source=(--image-src remote)
  command -v python3 >/dev/null 2>&1 || { echo 'error: python3 is required for the image inventory' >&2; exit 127; }
  images=$(PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="$root/selfhost" python3 - "$inventory" <<'PY_IMAGE_INVENTORY'
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

# Same platform as publish-images.sh release_platform: purls in the ignore file carry the architecture.
# Every image is scanned and, with a report directory, gets its report, also after a finding: the run
# fails at the end and names each image that failed. Trivy exits 1 for a finding and for its own
# errors alike, so the line says both.
scanned=0
failed=()
while IFS= read -r image; do
  [[ -n "$image" ]] || continue
  scanned=$((scanned + 1))
  printf 'Scanning release runtime image %s\n' "$image" >&2
  trivy image --quiet --platform linux/amd64 ${image_source[@]+"${image_source[@]}"} --scanners vuln,secret --severity HIGH,CRITICAL --exit-code 1 \
    --skip-db-update --skip-java-db-update --ignorefile "$root/.trivyignore.yaml" "$image" ||
    failed+=("$image (finding, secret or scanner error)")
  if [[ -n "${CHRONICLE_TRIVY_REPORT_DIR:-}" ]]; then
    mkdir -p "$CHRONICLE_TRIVY_REPORT_DIR"
    trivy image --quiet --platform linux/amd64 ${image_source[@]+"${image_source[@]}"} --scanners vuln --severity HIGH,CRITICAL \
      --skip-db-update --skip-java-db-update --ignorefile "$root/.trivyignore.yaml" --show-suppressed --format json \
      --output "$CHRONICLE_TRIVY_REPORT_DIR/$(printf %s "$image" | tr -c 'A-Za-z0-9._-' _).json" "$image" ||
      failed+=("$image (report not written)")
  fi
done <<< "$images"
if [[ ${#failed[@]} -gt 0 ]]; then
  printf 'error: %s of %s images failed the release scan:\n' \
    "$(printf '%s\n' "${failed[@]%% (*}" | sort -u | wc -l | tr -d ' ')" "$scanned" >&2
  printf '  %s\n' "${failed[@]}" >&2
  exit 1
fi
