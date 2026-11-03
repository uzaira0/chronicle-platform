#!/usr/bin/env python3
"""Require a removal condition and a dated review for every dependency override."""
import datetime
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def inventory(root):
    found = {}
    versions = dict(re.findall(r"ext\.(\w+)\s*=\s*['\"]([^'\"]+)['\"]",
                               (root / "gradles/chronicle.gradle").read_text()))
    repositories = [root] + [path for path in root.iterdir() if path.is_dir() and (path / ".git").exists()]
    gradle_files = set()
    for repository in repositories:
        listed = subprocess.run(["git", "-C", str(repository), "ls-files", "-z", "--", "*.gradle", "*.gradle.kts"],
                                capture_output=True, text=True, check=True).stdout
        gradle_files.update((repository / name).relative_to(root).as_posix() for name in listed.split("\0") if name)
    for name in sorted(gradle_files):
        source = (root / name).read_text()
        coordinates = re.findall(r'\bforce\s+[\'"]([^\'"\n]+:[^\'"\n]+:[^\'"\n]+)[\'"]', source)
        blocks = re.findall(r'\bforce\((.*?)\)', source, re.DOTALL)
        for variable in re.findall(r'(\w+)\.each\s*\{\s*(?:force|classpath)\s+it\s*}', source):
            match = re.search(r'\b' + re.escape(variable) + r'\s*=\s*\[(.*?)]', source, re.DOTALL)
            if match is None:
                raise ValueError(name + ": cannot inventory force list " + variable)
            blocks.append(match[1])
        for variable in re.findall(r'(\w+)\.forEach\s*\{\s*classpath\(it\)\s*}', source):
            match = re.search(r'\b' + re.escape(variable) + r'\s*=\s*listOf\((.*?)\)', source, re.DOTALL)
            if match is None:
                raise ValueError(name + ": cannot inventory classpath list " + variable)
            blocks.append(match[1])
        for block in blocks:
            coordinates.extend(re.findall(r'[\'"]([^\'"\n]+:[^\'"\n]+:[^\'"\n]+)[\'"]', block))
        for coordinate in coordinates:
            artifact, version = coordinate.rsplit(":", 1)
            version = re.sub(r'\$\{(\w+)\}', lambda match: versions[match[1]], version)
            found[name + "::" + artifact] = version
    package = json.loads((root / "chronicle-web/package.json").read_text())
    found.update({"chronicle-web/package.json::" + name: pin for name, pin in package.get("overrides", {}).items()})
    web = root / "chronicle-web"
    for name, declared_path in package.get("patchedDependencies", {}).items():
        if not isinstance(declared_path, str) or "\\" in declared_path:
            raise ValueError("dependency patch must use a relative .patch path inside chronicle-web")
        relative = Path(declared_path)
        if (relative.is_absolute() or ".." in relative.parts or relative.suffix != ".patch"
                or any(part.startswith(".env") or part in {".git", ".ssh", ".aws", "keys", "keystores"}
                       for part in relative.parts)):
            raise ValueError("dependency patch must use a relative .patch path inside chronicle-web")
        patch = web / relative
        if (any(parent.is_symlink() for parent in (patch, *patch.parents) if parent.is_relative_to(web))
                or not patch.is_file()):
            raise ValueError("dependency patch must be a regular file without symlinks: " + declared_path)
        found["chronicle-web/package.json::patch:" + name] = "sha256:" + hashlib.sha256(patch.read_bytes()).hexdigest()
    caddy = (root / "selfhost/Dockerfile.caddy").read_text()
    for module, pin in re.findall(r'--replace\s+(\S+)=\S+@(\S+)', caddy):
        found["selfhost/Dockerfile.caddy::" + module] = pin
    for patch in re.findall(r'^COPY\s+(selfhost/caddy/\S+\.patch)\s', caddy, re.MULTILINE):
        found["selfhost/Dockerfile.caddy::patch:" + patch] = "sha256:" + hashlib.sha256((root / patch).read_bytes()).hexdigest()
    grafana = (root / "selfhost/Dockerfile.grafana").read_text()
    for module, pin in re.findall(r'go\s+work\s+edit\s+-replace=(\S+)=\S+@(\S+)', grafana):
        found["selfhost/Dockerfile.grafana::" + module] = pin
    backup = (root / "selfhost/Dockerfile.backup").read_text()
    for package in re.findall(r'\bdnf\s+-y\s+upgrade\s+(\S+)', backup):
        found["selfhost/Dockerfile.backup::" + package.split("-1.")[0]] = package
    found["selfhost/backup-image::fork"] = re.search(r'^# Commit: ([0-9a-f]{40})', backup, re.MULTILINE).group(1)
    return found


def review_problems(pins, records, today):
    failures = []
    for name in sorted(pins.keys() | records.keys()):
        record = records.get(name, {})
        if name not in pins or record.get("pin") != pins.get(name):
            failures.append(name + ": override missing or changed; update its removal review")
        if not all(record.get(field) for field in ("reason", "remove_when", "reviewed_on", "review_after")):
            failures.append(name + ": reason, removal condition and review dates are required")
            continue
        try:
            reviewed = datetime.date.fromisoformat(record["reviewed_on"])
            deadline = datetime.date.fromisoformat(record["review_after"])
            if not reviewed <= today < deadline:
                failures.append(name + ": removal review is due (" + record["review_after"] + ")")
        except ValueError:
            failures.append(name + ": invalid review date")
    return failures


def problems(root, today=None):
    records = json.loads((root / "config/dependency-overrides.json").read_text())
    return review_problems(inventory(root), records, today or datetime.date.today())


if __name__ == "__main__":
    failures = problems(ROOT)
    for failure in failures:
        print("[fail] " + failure, file=sys.stderr)
    if failures:
        raise SystemExit(1)
    print("[ok] every dependency override has an unchanged pin and a current removal review")
