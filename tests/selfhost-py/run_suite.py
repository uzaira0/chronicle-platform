"""Run the operator suite with its selected package and fail on skipped checks."""
import importlib
import os
import sys
import tempfile
import unittest
from pathlib import Path


def canonical_temporary_directory():
    """Point TMPDIR at its real path, for this process and every child.

    On macOS the default TMPDIR is under /var, a symlink to /private/var. The operator code
    resolves paths (Path.cwd(), Path.resolve()) when it records and compares release, state
    and recovery directories, so a fixture built under the unresolved name never equals what
    the code records, and the comparison fails for a reason no deployment has."""
    real = os.path.realpath(tempfile.gettempdir())
    os.environ["TMPDIR"] = real
    tempfile.tempdir = real


ROOT = Path(__file__).resolve().parents[2]
# Inputs the suite reads from submodules: migrations (forward update, restore schemas) and the API
# sources (topology). Without them dozens of tests failed on missing files (RD-N2).
REQUIRED_SUBMODULE_INPUTS = {
    "chronicle-server": ("src/main/resources/db/migration",),
    "chronicle-api": ("src/main/kotlin",),
}


def missing_inputs(root):
    """(submodule, path) for every required submodule input that is not checked out under root."""
    return [(name, relative) for name, inputs in REQUIRED_SUBMODULE_INPUTS.items() for relative in inputs
            if not (Path(root) / name / relative).is_dir()]


def preflight_message(missing):
    names = ", ".join(sorted({name for name, _ in missing}))
    return (f"The operator suite reads files from the {names} submodule(s), which are not checked out "
            f"here. Run: git submodule update --init --recursive")


if __name__ == "__main__":
    missing = missing_inputs(ROOT)
    if missing:
        print(preflight_message(missing), file=sys.stderr)
        sys.exit(2)
    canonical_temporary_directory()
    # Bundle checks select a package through PYTHONPATH before tests can alter sys.path.
    importlib.import_module("chronicle_ops")
    result = unittest.main(module=None, exit=False).result
    if result.skipped:
        print("Required operator checks were skipped; install their declared tools.", file=sys.stderr)
    sys.exit(not result.wasSuccessful() or bool(result.skipped))
