#!/usr/bin/env python3
"""Refuse cached filesystem paths tied to one workstation; private records stay private."""
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
# A path literal starts at its quote. A diagnostic sentence containing a path is test data,
# such as ErrorSanitizationConfigTest's input, rather than a path used for filesystem access.
QUOTED_PATH = r'''["'`]/(Users|home)/[[:alnum:]_.-]+/'''
SHELL_PATH = r'''(^|[[:space:]=])/(Users|home)/[[:alnum:]_.-]+/'''


def scan(root):
    exclusions = [":(exclude,glob)**/.env*", ":(exclude,glob)**/signing.properties",
                  ":(exclude,glob)**/*.keystore", ":(exclude,glob)**/*.jks", ":(exclude,glob)**/*.pem"]
    policy = ROOT / ".publishignore"
    if (root / ".publishignore").is_file():
        policy = root / ".publishignore"
    ignored = subprocess.run(["git", "-C", str(root), "ls-files", "-z", "--cached", "-i", "--exclude-from=" + str(policy)],
                             capture_output=True, text=True, check=True).stdout
    exclusions += [":(exclude,literal)" + name for name in ignored.split("\0") if name]
    found = set()
    for expression, files in ((QUOTED_PATH, ["."]), (SHELL_PATH, ["*.sh"])):
        result = subprocess.run(["git", "-C", str(root), "grep", "--cached", "-I", "-l", "-z", "-E",
                                 expression, "--", *files, *exclusions], capture_output=True, text=True)
        if result.returncode not in (0, 1):
            raise ValueError(result.stderr.strip() or "cached path scan failed")
        found.update(name for name in result.stdout.split("\0") if name)
    return sorted(found)


if __name__ == "__main__":
    repositories = [ROOT] + [path for path in ROOT.iterdir() if path.is_dir() and (path / ".git").exists()]
    failures = [(repository.relative_to(ROOT) / name).as_posix()
                for repository in repositories for name in scan(repository)]
    for name in failures:
        print("[fail] cached workstation filesystem path: " + name, file=sys.stderr)
    raise SystemExit(bool(failures))
