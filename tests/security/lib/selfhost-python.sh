#!/usr/bin/env bash
# Python operator tests must not execute user-site startup hooks.
# Shipped shell scripts can launch Python children without inheriting the parent's -s flag.
export PYTHONNOUSERSITE=1

selfhost_python() {
  PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="${SELFHOST_PYTHON_PACKAGE:-$ROOT_DIR/selfhost}:$ROOT_DIR/tests/selfhost-py" \
    python3 -s "$@"
}

run_selfhost_python_suite() {
  selfhost_python "${BASH_SOURCE[0]%/*}/../../selfhost-py/run_suite.py" "$@"
}

# Remove a disposable Compose project for good: `docker compose down --volumes --remove-orphans`
# (containers, networks, its named volumes), then the anonymous volumes its containers mounted.
# `down --volumes` alone leaves the anonymous volumes of every container `up` recreated, because
# Compose mounts those by name. The operator code leaves them too, because it cannot tell them from
# an operator's own volume; a harness owns what its project made and takes them
# (tests/selfhost-py/selfhost_fixture.py disposable_project_volumes). The arguments after the
# project are Compose's own options (--env-file FILE, -f FILE), then `--` and options for `down`.
#   remove_compose_project PROJECT [COMPOSE_OPTION...] [-- DOWN_OPTION...]
remove_compose_project() {
  local project="$1" anonymous status=0
  local -a compose_options=() down_options=()
  shift
  while (($#)); do
    if [[ "$1" == -- ]]; then shift; down_options=("$@"); break; fi
    compose_options+=("$1"); shift
  done
  anonymous="$(selfhost_python -c 'import sys; from selfhost_fixture import disposable_project_volumes; print(*disposable_project_volumes(sys.argv[1]))' "$project")" || anonymous=""
  docker compose -p "$project" ${compose_options[@]+"${compose_options[@]}"} down --volumes --remove-orphans \
    ${down_options[@]+"${down_options[@]}"} || status=$?
  if [[ -n "$anonymous" ]]; then
    # shellcheck disable=SC2086 # one volume name per word
    selfhost_python -c 'import sys; from chronicle_ops.common import DOCKER_QUERY_TIMEOUT_SECONDS, after_compose; after_compose(sys.argv[1], sys.argv[2:], seconds=DOCKER_QUERY_TIMEOUT_SECONDS)' "$project" $anonymous || status=$?
  fi
  return "$status"
}
