#!/usr/bin/env python3
"""Fail unless every OSV waiver is owned, rechecked, bounded, staggered and still resolved.

    check-osv-waivers.py [--root DIR] CONFIG...

osv-scanner refuses unknown keys in its config, so the owner and the recheck date live in the
reason text: "Owner: NAME." and "Rechecked YYYY-MM-DD".
A PackageOverrides entry must still name a version the repository resolves (a Gradle lockfile, a
Gradle verification-metadata catalog that OSV scans as a lockfile, a go.sum or a bun.lock under
--root, default the config's directory); an entry for a version nothing resolves is stale.
"""
import datetime
import os
from pathlib import Path
import re
import runpy
import sys
import tomllib

MAX_DAYS = 62
HERE = Path(__file__).resolve().parent
stagger_problems = runpy.run_path(str(HERE / 'check-trivy-waivers.py'))['stagger_problems']

# Each waiver table and the key holding its expiry.
WAIVERS = (("IgnoredVulns", "ignoreUntil"), ("PackageOverrides", "effectiveUntil"))
OWNER = re.compile(r'\bOwner: ?\S')
RECHECK = re.compile(r'\bRechecked (\d{4}-\d{2}-\d{2})\b')
SKIP = {'.git', 'node_modules', 'build', '.gradle', '.local', '.refs'}
RESOLVED_NAMES = {'gradle.lockfile', 'verification-metadata.xml', 'go.sum', 'bun.lock'}


def resolved_texts(root):
    """Contents of every dependency file OSV scans under root (pruned walk: no node_modules or build)."""
    texts = []
    for directory, subdirectories, files in os.walk(root):
        subdirectories[:] = [name for name in subdirectories if name not in SKIP]
        texts += [(Path(directory) / name).read_text(encoding='utf-8', errors='replace')
                  for name in files if name in RESOLVED_NAMES]
    return texts


def resolved(texts, name, version):
    """Whether any scanned dependency file under root resolves name at version."""
    group, _, artifact = name.rpartition(':')
    patterns = [re.compile(r'(?m)^' + re.escape(f'{name}:{version}') + r'=')]
    if group:
        patterns.append(re.compile(r'<component group="' + re.escape(group) + r'" name="' + re.escape(artifact)
                                   + r'" version="' + re.escape(version) + r'"'))
    patterns.append(re.compile(r'(?m)^' + re.escape(name) + r' v' + re.escape(version.removeprefix('v')) + r'[ /]'))
    patterns.append(re.compile(re.escape(f'"{name}@{version}"')))
    return any(pattern.search(text) for text in texts for pattern in patterns)


def problems(config: dict, now: datetime.datetime, root=None) -> list[str]:
    found, dates = [], []
    texts = resolved_texts(root) if root is not None else None
    for table, expiry in WAIVERS:
        for entry in config.get(table, []):
            waived = entry.get("id") or " ".join(filter(None, (entry.get("name"), entry.get("version")))) or "<unnamed>"
            until = entry.get(expiry)
            if isinstance(until, datetime.date) and not isinstance(until, datetime.datetime):
                until = datetime.datetime.combine(until, datetime.time(), datetime.timezone.utc)
            reason = str(entry.get("reason", "")).strip()
            if not reason:
                found.append(f"{waived}: missing reason")
            if not OWNER.search(reason):
                found.append(f"{waived}: the reason must name its owner (Owner: NAME.)")
            recheck = RECHECK.search(reason)
            if not recheck:
                found.append(f"{waived}: the reason must date its last recheck (Rechecked YYYY-MM-DD)")
            elif datetime.date.fromisoformat(recheck[1]) > now.date():
                found.append(f"{waived}: recheck date {recheck[1]} is in the future")
            if table == "PackageOverrides" and not entry.get("version"):
                found.append(f"{waived}: a package waiver must name one version")
            elif table == "PackageOverrides" and texts is not None and not resolved(texts, entry.get("name", ""), entry["version"]):
                found.append(f"{waived}: matches no resolved dependency; remove the stale waiver")
            if not isinstance(until, datetime.datetime):
                found.append(f"{waived}: missing {expiry}")
                continue
            dates.append(until.date())
            if not now < until <= now + datetime.timedelta(days=MAX_DAYS):
                found.append(f"{waived}: {expiry} {until.isoformat()} must be in the next {MAX_DAYS} days")
    return found + stagger_problems(dates, 'OSV waivers')


def self_test() -> None:
    now = datetime.datetime(2026, 10, 8, tzinfo=datetime.timezone.utc)
    soon = now + datetime.timedelta(days=30)
    reason = "unused. Owner: uzaira0. Rechecked 2026-10-08."
    assert not problems({"IgnoredVulns": [{"id": "A", "reason": reason, "ignoreUntil": soon}]}, now)
    assert problems({"IgnoredVulns": [{"id": "A", "ignoreUntil": soon}]}, now)
    assert problems({"IgnoredVulns": [{"id": "A", "reason": "unused. Rechecked 2026-10-08.", "ignoreUntil": soon}]}, now)
    assert problems({"IgnoredVulns": [{"id": "A", "reason": "unused. Owner: uzaira0.", "ignoreUntil": soon}]}, now)
    assert problems({"IgnoredVulns": [{"id": "A", "reason": reason}]}, now)
    assert problems({"IgnoredVulns": [{"id": "A", "reason": reason, "ignoreUntil": now}]}, now)
    assert problems({"IgnoredVulns": [{"id": "A", "reason": reason,
                                       "ignoreUntil": now + datetime.timedelta(days=MAX_DAYS + 1)}]}, now)
    package = {"name": "io.netty:netty-codec", "version": "4.1.93.Final", "reason": reason, "effectiveUntil": soon.date()}
    assert not problems({"PackageOverrides": [package]}, now)
    assert problems({"PackageOverrides": [dict(package, reason="")]}, now)
    assert problems({"PackageOverrides": [{k: v for k, v in package.items() if k != "effectiveUntil"}]}, now)
    assert problems({"PackageOverrides": [{k: v for k, v in package.items() if k != "version"}]}, now)
    assert problems({"PackageOverrides": [dict(package, effectiveUntil=(now + datetime.timedelta(days=MAX_DAYS + 1)).date())]}, now)
    assert problems({"PackageOverrides": [dict(package) for _ in range(4)]}, now)


if __name__ == "__main__":
    if sys.argv[1:] == ["--self-test"]:
        self_test()
        sys.exit(0)
    arguments = sys.argv[1:]
    root = None
    if arguments[:1] == ["--root"]:
        root, arguments = Path(arguments[1]), arguments[2:]
    now = datetime.datetime.now(datetime.timezone.utc)
    failures = []
    for path in arguments:
        with open(path, "rb") as handle:
            failures += [f"{path}: {problem}" for problem in
                         problems(tomllib.load(handle), now, root or Path(path).resolve().parent)]
    print("\n".join(failures))
    sys.exit(1 if failures else 0)
