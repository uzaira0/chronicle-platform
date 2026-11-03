"""Run the operator suite with its selected package and fail on skipped checks."""
import importlib
import sys
import unittest


if __name__ == "__main__":
    # Bundle checks select a package through PYTHONPATH before tests can alter sys.path.
    importlib.import_module("chronicle_ops")
    result = unittest.main(module=None, exit=False).result
    if result.skipped:
        print("Required operator checks were skipped; install their declared tools.", file=sys.stderr)
    sys.exit(not result.wasSuccessful() or bool(result.skipped))
