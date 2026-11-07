#!/usr/bin/env bash
# Read credentials from the files secrets-init writes, so no container's Compose configuration
# carries one (docs/NETWORK-EGRESS.md). Sourced by the bash one-shot jobs: config-guard, db-init
# and restore. The backend and migrate load theirs in backend-entrypoint.sh.
#
#   load_secret_files DIRECTORY VARIABLE:file [VARIABLE:file ...]
#
# Each file becomes the exported variable. A variable that is already set is kept, so a job
# started with it in its environment behaves as before. A missing file is fatal: secrets-init
# writes every file, so a missing one means it has not run.
load_secret_files() {
  local directory="$1" pair variable file
  shift
  for pair in "$@"; do
    variable="${pair%%:*}" file="${directory}/${pair#*:}"
    [[ -z "${!variable:-}" ]] || continue
    if [[ ! -r "$file" ]]; then
      printf 'FATAL: %s is missing; secrets-init writes it before this job starts\n' "$file" >&2
      exit 1
    fi
    printf -v "$variable" '%s' "$(<"$file")"
    export "${variable?}"
  done
}
