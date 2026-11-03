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
