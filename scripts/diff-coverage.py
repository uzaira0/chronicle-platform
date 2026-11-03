#!/usr/bin/env python3
import argparse
import fnmatch
import os
import re
import shutil
from pathlib import Path
import subprocess
import sys
import xml.etree.ElementTree as ET


def git(repo, *arguments, required=True):
    result = subprocess.run(["git", "-C", str(repo), *arguments], capture_output=True, text=True)
    if required and result.returncode:
        raise ValueError(result.stderr.strip() or "git " + " ".join(arguments) + " failed")
    return result.stdout.strip() if result.returncode == 0 else None


def default_base(repo, ref=None):
    if ref:
        return git(repo, "rev-parse", "--verify", ref + "^{commit}")
    base = git(repo, "merge-base", "HEAD", "origin/main", required=False)
    if base is None:
        base = git(repo, "rev-parse", "--verify", "HEAD~1^{commit}", required=False)
    if base is None:
        raise ValueError(f"{repo}: cannot resolve a base; supply --base <ref>")
    return base


def waivers(repo):
    result = []
    path = repo / ".diff-coverage-waivers"
    if path.is_file():
        for number, line in enumerate(path.read_text().splitlines(), 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            fields = line.split(None, 1)
            if len(fields) != 2 or not fields[1].lstrip("# \t").strip():
                raise ValueError(f"{path}:{number}: waiver requires a path glob and a reason")
            result.append(fields[0])
    return result


def children(repo, base, only=None):
    modules = repo / ".gitmodules"
    if not modules.is_file():
        return []
    paths = git(repo, "config", "--file", str(modules), "--get-regexp", r"^submodule\..*\.path$", required=False)
    result = []
    for entry in (paths or "").splitlines():
        relative = entry.split(None, 1)[1]
        child = repo / relative
        if only is not None and child != only:
            continue
        if not (child / ".git").exists():
            recorded = git(repo, "ls-tree", base, "--", relative)
            current = git(repo, "ls-tree", "HEAD", "--", relative)
            if recorded != current:
                raise ValueError(f"{child}: changed submodule is uninitialized; run git submodule update --init {relative}")
            continue
        recorded = git(repo, "ls-tree", base, "--", relative)
        child_base = recorded.split()[2] if recorded and recorded.startswith("160000 ") else None
        if child_base and git(child, "cat-file", "-e", child_base + "^{commit}", required=False) is None:
            raise ValueError(f"{child}: recorded base {child_base} is unavailable locally")
        result.append((child, child_base or default_base(child)))
    return result


def changed_files(repo, base):
    """Paths whose change adds lines, and untracked files; a deletion-only change leaves no line to measure."""
    tracked = git(repo, "diff", "--numstat", "--no-renames", "--diff-filter=ACMR", "-z", base, "--")
    added = {path for added, _, path in (record.split("\t", 2) for record in tracked.split("\0") if record)
             if added != "0"}
    untracked = git(repo, "ls-files", "--others", "--exclude-standard", "-z")
    return (added | set(untracked.split("\0"))) - {""}


def reports_and_roots(repo):
    xml, lcov, sources = [], [], ["."]
    for directory, dirs, files in os.walk(repo):
        here = Path(directory)
        dirs[:] = [d for d in dirs if d not in {".git", ".gradle", "node_modules", ".local", ".venv"}
                   and not (here / d / ".git").exists()]
        relative = here.relative_to(repo).as_posix()
        if re.search(r"(?:^|/)src/[^/]+/(?:java|kotlin)$", relative) and production_jvm(relative + "/Source.kt"):
            sources.append(relative)
        if any(directory in "/" + relative + "/" for directory in ("/build/reports/jacoco/", "/build/reports/coverage/")):
            xml.extend(str(here / f) for f in files if f.endswith(".xml"))
        xml.extend(str(here / f) for f in files if f == "coverage.xml"
                   or relative in {"coverage", "build/coverage"} and f.endswith(".xml"))
        if relative in {"coverage", "chronicle-web/coverage"} and "lcov.info" in files:
            lcov.append(str(here / "lcov.info"))
    return sorted(set(xml)), sorted(set(lcov)), sources


def production_jvm(path):
    source = re.search(r"(?:^|/)src/([^/]+)/(?:java|kotlin)/", path)
    # The root tests/ tree holds rule fixtures shaped like production sources; none of it ships.
    return bool(path.endswith((".kt", ".java")) and source and not path.startswith("tests/")
                and not source[1].lower().startswith(("test", "androidtest")))


def check(repo, base, required, inherited=()):
    relative = repo.relative_to(root).as_posix()
    prefix = "" if relative == "." else relative + "/"
    scoped = list(inherited) + [(prefix, glob) for glob in waivers(repo)]
    subs = children(repo, base)
    subpaths = {p for p, _ in subs}
    files = changed_files(repo, base)
    exclusions = [p for p in files if any((prefix + p).startswith(scope)
                  and fnmatch.fnmatchcase((prefix + p)[len(scope):], glob) for scope, glob in scoped)]
    changes = [p for p in files if repo / p not in subpaths and p not in exclusions]
    failed = False
    if changes:
        xml, lcov, sources = reports_and_roots(repo)
        # A report is required only where --require says a gate job produces it; other repositories
        # and languages (Bash) are measured against whatever reports exist, usually none.
        kinds = required.get(relative, set())
        # A report written before the newest change in its own module cannot measure it; it is not evidence.
        # A module's report is not made stale by a change in another module (Gradle leaves it untouched).
        dated = [("/" + p, (repo / p).stat().st_mtime) for p in changes
                 if p.endswith((".kt", ".java", ".ts", ".tsx", ".js", ".jsx", ".py")) and (repo / p).is_file()]

        def newest_in(report):
            module = ("/" + Path(report).relative_to(repo).as_posix()).split("/build/")[0].split("/coverage/")[0]
            return max((when for path, when in dated if path.startswith(module + "/")), default=0)

        stale = {r for r in xml + lcov if Path(r).stat().st_mtime < newest_in(r)}
        if stale:
            print(f"[diff-coverage] {repo}: ignoring reports that predate the changed sources: "
                  + ", ".join(sorted(str(Path(r).relative_to(repo)) for r in stale)), file=sys.stderr)
            xml, lcov = [r for r in xml if r not in stale], [r for r in lcov if r not in stale]
        missing = []
        if any(production_jvm(p) for p in changes) and "jacoco" in kinds and not xml:
            missing.append("changed JVM sources require JaCoCo XML")
        python_sources = [p for p in changes if p.startswith("selfhost/") and p.endswith(".py")]
        if python_sources and "cobertura" in kinds and not any(ET.parse(report).getroot().tag == "coverage" for report in xml):
            missing.append("changed selfhost Python sources require coverage.xml")
        if any(p.endswith((".ts", ".tsx", ".js", ".jsx")) for p in changes) and "lcov" in kinds and not lcov:
            missing.append("changed web sources require coverage/lcov.info")
        measured = set()
        for report in xml:
            document = ET.parse(report).getroot()
            for package in document.findall(".//package"):
                for source in package.findall("sourcefile"):
                    for directory in sources:
                        measured.add((repo / directory / package.get("name", "") / source.get("name", "")).resolve())
            for source in document.findall(".//class"):
                filename = source.get("filename")
                if filename:
                    roots = ["."] + [node.text for node in document.findall("./sources/source") if node.text]
                    measured.update((repo / directory / filename).resolve() for directory in roots)
        for report in lcov:
            for line in Path(report).read_text().splitlines():
                if line.startswith("SF:"):
                    measured.add((repo / line[3:]).resolve())
        for path in changes:
            production_web = path.endswith((".ts", ".tsx", ".js", ".jsx")) and not any(
                marker in "/" + path for marker in (".test.", ".spec.", "/tests/", "/__tests__/", "/e2e/"))
            if (production_jvm(path) and xml or production_web and lcov or path in python_sources and xml) and (repo / path).resolve() not in measured:
                missing.append(f"changed source {path} is absent from coverage reports")
        if missing:
            print(f"[diff-coverage] {repo}: {'; '.join(missing)}. Produce reports with "
                  "bash scripts/local-ci.sh jvm-smoke android-unit selfhost (JVM/Android/Python), or "
                  "(cd chronicle-web && bun test --coverage --coverage-reporter=lcov) (lcov).", file=sys.stderr)
            failed = True
        # diff-cover cannot mix lcov and XML in one invocation.
        for reports in (xml, lcov):
            if not reports:
                continue
            command = ["diff-cover", *reports, "--compare-branch", base, "--diff-range-notation", "..",
                       "--fail-under", "80", "--include-untracked", "--src-roots", *sources]
            if exclusions:
                # diff-cover matches --exclude against the basename or the absolute path only.
                command += ["--exclude", *(str(repo / p) for p in exclusions)]
            print(f"[diff-coverage] {repo}: base={base}, {len(reports)} report(s)", flush=True)
            failed = subprocess.run(command, cwd=repo).returncode != 0 or failed
    else:
        print(f"[diff-coverage] {repo}: no unwaived changes", flush=True)
    for child, child_base in subs:
        failed = check(child, child_base, required, scoped) or failed
    return failed


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Require 80% coverage of changed executable lines in each Git repository.")
    parser.add_argument("--base", help="root repository base (default: merge-base with origin/main, then HEAD~1)")
    parser.add_argument("--print-base", metavar="SUBMODULE",
                        help="print the base commit this gate uses for SUBMODULE, then exit")
    parser.add_argument("--require", action="append", default=[], metavar="REPO=KIND",
                        help="fail when REPO (path from the root, . for the root) has changed sources but no "
                             "KIND report (jacoco, lcov or cobertura); repeatable")
    args = parser.parse_args()
    required = {}
    for entry in args.require:
        repository, _, kind = entry.partition("=")
        if kind not in ("jacoco", "lcov", "cobertura"):
            parser.error(f"--require {entry}: KIND must be jacoco, lcov or cobertura")
        required.setdefault(repository, set()).add(kind)
    for command in ("git",) if args.print_base else ("git", "diff-cover"):
        if shutil.which(command) is None:
            print(f"[diff-coverage] missing required command: {command}", file=sys.stderr)
            sys.exit(127)
    try:
        root = Path(git(Path.cwd(), "rev-parse", "--show-toplevel"))
        base = default_base(root, args.base)
        if args.print_base:
            submodule = root / args.print_base
            print(dict(children(root, base, only=submodule)).get(submodule) or default_base(submodule))
            sys.exit(0)
        sys.exit(1 if check(root, base, required) else 0)
    except (ValueError, OSError, ET.ParseError) as error:
        print(f"[diff-coverage] {error}", file=sys.stderr)
        sys.exit(2)
