#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WEB_DIR="$ROOT_DIR/chronicle-web"

have_cmd() {
  command -v "$1" >/dev/null 2>&1
}

if ! have_cmd bun; then
  printf '[fail] bun not found\n' >&2
  exit 1
fi


printf 'Chronicle web Bun smoke\n'
printf 'web: %s\n' "$WEB_DIR"

if [[ "${CHRONICLE_WEB_SKIP_INSTALL:-0}" != "1" ]]; then
  printf '\n== bun-install ==\n'
  (cd "$WEB_DIR" && bun install --frozen-lockfile --ignore-scripts)
fi

printf '\n== bun-check ==\n'
(cd "$WEB_DIR" && bun run check)

printf '\n== bun-tests ==\n'
(cd "$WEB_DIR" && bun run test)

printf '\n== bun-e2e ==\n'
(cd "$WEB_DIR" && bun run e2e)

printf '\n== bun-build ==\n'
(cd "$WEB_DIR" && bun run build)

printf '\n[ok] chronicle-web Bun smoke complete\n'
