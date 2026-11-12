#!/usr/bin/env bash
set -euo pipefail

echo "=== Dockerfile Linting ==="

cd /opt/chronicle

if ! command -v hadolint &> /dev/null; then
  echo "hadolint not found. Install: brew install hadolint or download from https://github.com/hadolint/hadolint"
  echo "Falling back to basic checks..."

  # Basic checks without hadolint
  for df in docker/Dockerfile.*; do
    echo ""
    echo "--- $df ---"

    # Check for latest tag usage
    if grep -n "FROM.*:latest" "$df" 2>/dev/null; then
      echo "WARN: Uses :latest tag (pin versions for reproducibility)"
    fi

    # Check for ADD instead of COPY
    if grep -n "^ADD " "$df" 2>/dev/null; then
      echo "WARN: Uses ADD instead of COPY"
    fi

    # Check for apt-get without --no-install-recommends
    if grep "apt-get install" "$df" | grep -v "no-install-recommends" 2>/dev/null; then
      echo "WARN: apt-get install without --no-install-recommends"
    fi

    # Check for missing cleanup
    if grep "apt-get" "$df" | grep -v "rm -rf" 2>/dev/null | sed -n 1p; then
      echo "WARN: May be missing apt cache cleanup"
    fi

    echo "Basic checks passed"
  done
  exit 0
fi

# With hadolint
for df in docker/Dockerfile.*; do
  echo ""
  echo "--- $df ---"
  hadolint "$df" --ignore DL3008 --ignore DL3013
done

echo ""
echo "Dockerfile linting complete"
