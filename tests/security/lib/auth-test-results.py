"""Require passing server auth behavior tests; this layer never builds the JVM.

Usage: auth-test-results.py RESULTS_DIR INPUT... where each INPUT is a file or directory the
server tests depend on (sources, build files, lockfiles, sibling libraries)."""

import os
from pathlib import Path
import sys
import xml.etree.ElementTree as ET

REQUIRED_CLASSES = (
    "MobileApiSignatureFilterTest", "SecurityRouteAuthorizationTest", "RateLimitFilterTest",
    "ExceptionLoggingTest", "HardeningLiveChainTest",
)


# Generated output and prose cannot change a test's outcome; every other file under an input can.
NOT_INPUTS = {"build", ".gradle", "docs", "node_modules", ".git"}


def newest_input(inputs):
    def walk_error(error):
        raise error

    def input_files(root):
        if NOT_INPUTS.intersection(root.parts):
            return
        if root.is_file():
            yield root
            return
        if root.is_symlink() or not root.is_dir():
            return
        for directory, directories, names in os.walk(
                root, topdown=True, followlinks=False, onerror=walk_error):
            directory = Path(directory)
            directories[:] = [name for name in directories if name not in NOT_INPUTS
                              and not (directory == root and name == "logging")
                              and not (directory / name).is_symlink()]
            for name in names:
                yield directory / name

    files = (path for root in inputs for path in input_files(root))
    return max((path.stat().st_mtime_ns for path in files if path.is_file() and path.suffix != ".md"
                and not NOT_INPUTS.intersection(path.parts)), default=0)


def verify(results, inputs):
    newest_source = newest_input(inputs)
    suites = [(path, ET.parse(path).getroot()) for path in sorted(results.glob("TEST-*.xml"))]
    for name in REQUIRED_CLASSES:
        matches = [(path, suite) for path, suite in suites if suite.get("name", "").rsplit(".", 1)[-1] == name]
        if len(matches) != 1:
            raise ValueError(f"Missing server test results for {name}; rerun jvm-smoke")
        path, suite = matches[0]
        if path.stat().st_mtime_ns <= newest_source:
            raise ValueError(f"Stale server test results for {name}; rerun jvm-smoke")
        cases = suite.findall("testcase")
        if (not cases or int(suite.get("tests", "0")) != len(cases)
                or any(int(suite.get(key, "0")) for key in ("failures", "errors", "skipped"))
                or any(case.find(tag) is not None for case in cases for tag in ("failure", "error", "skipped"))):
            raise ValueError(f"Server auth behavior tests did not pass: {name}")
        print(f"Server auth evidence: {name}: {len(cases)} tests; 0 failures; 0 errors; 0 skipped")


if __name__ == "__main__":
    try:
        verify(Path(sys.argv[1]), [Path(argument) for argument in sys.argv[2:]])
    except (OSError, ValueError, ET.ParseError) as error:
        sys.exit(str(error))
