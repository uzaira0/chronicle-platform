#!/usr/bin/env python3
"""Run the Python and shell checks that found defects over all tracked runnable source."""
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def check(root, run=subprocess.run):
    files = {".py": [], ".sh": []}
    repositories = [root] + [path for path in root.iterdir() if path.is_dir() and (path / ".git").exists()]
    for repository in repositories:
        listed = subprocess.run(["git", "-C", str(repository), "ls-files", "-z", "--", "*.py", "*.sh"],
                                capture_output=True, text=True, check=True).stdout
        for name in sorted(filter(None, listed.split("\0"))):
            # These are deliberately broken scanner specimens, not scripts anyone executes.
            if name.startswith(("tests/security/fixtures/", "tests/security/semgrep-tests/")):
                continue
            path = repository / name
            if path.is_file():
                files[path.suffix].append(str(path))
    failed = False
    for command, suffix in ((["ruff", "check", "--select", "F"], ".py"), (["shellcheck", "-S", "warning"], ".sh")):
        if files[suffix]:
            failed = run(command + files[suffix]).returncode != 0 or failed
    return int(failed)


if __name__ == "__main__":
    raise SystemExit(check(ROOT))
