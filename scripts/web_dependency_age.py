#!/usr/bin/env python3
"""Fail when a direct chronicle-web dependency looks unmaintained.

A direct dependency (dependencies or devDependencies; local file: packages excluded) whose newest
registry release is older than `freshness.web_max_release_age_days` fails, unless
`freshness.web_stale_accepted` in toolchain-manifest.yaml lists it with a reason and an unexpired
`expires` date. An acceptance that has expired, lacks a reason, or names a package that is no
longer a stale direct dependency also fails, so the list cannot rot. Run by scripts/deps-freshness.sh.

    web_dependency_age.py PACKAGE.json POLICY.json [--today YYYY-MM-DD]

Release dates come from deps.dev, with the npm registry as the second source. Every request has a
timeout and retries, IPv4 is tried before IPv6, and the whole run stops at a deadline.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import subprocess
import sys
import time
import urllib.parse
from pathlib import Path

DEADLINE_SECONDS = 600
CURL = ['curl', '-fsS', '--connect-timeout', '10', '--max-time', '60', '--retry', '2', '--retry-all-errors',
        '--retry-delay', '2', '--retry-max-time', '90']


class ReleaseLookupError(RuntimeError):
    pass


def direct_dependencies(package: dict) -> list[str]:
    names = set()
    for section in ('dependencies', 'devDependencies'):
        for name, spec in package.get(section, {}).items():
            if not str(spec).startswith(('file:', 'link:', 'workspace:')):
                names.add(name)
    return sorted(names)


def latest_from_deps_dev(document: dict) -> tuple[str, dt.date]:
    """The default (dist-tag latest) version and its publish date from a deps.dev package document."""
    defaults = [v for v in document.get('versions', []) if v.get('isDefault')]
    if len(defaults) != 1 or not defaults[0].get('publishedAt'):
        raise ReleaseLookupError('deps.dev names no single default version with a publish date')
    version = defaults[0]
    return version['versionKey']['version'], dt.date.fromisoformat(version['publishedAt'][:10])


def latest_from_npm(document: dict) -> tuple[str, dt.date]:
    """The dist-tag latest version and its publish date from an npm registry packument."""
    latest = document.get('dist-tags', {}).get('latest')
    published = document.get('time', {}).get(latest or '')
    if not latest or not published:
        raise ReleaseLookupError('npm packument has no dist-tags.latest publish time')
    return latest, dt.date.fromisoformat(published[:10])


def problems(releases: dict[str, tuple[str, dt.date]], policy: dict, today: dt.date) -> list[str]:
    max_age = int(policy['web_max_release_age_days'])
    accepted = {entry.get('name'): entry for entry in policy.get('web_stale_accepted') or []}
    found = []
    stale = set()
    for name, (version, published) in sorted(releases.items()):
        age = (today - published).days
        if age <= max_age:
            continue
        stale.add(name)
        entry = accepted.get(name)
        if entry is None:
            found.append(f'{name}: newest release {version} is {age} days old ({published}), over {max_age}; '
                         'replace it, or list it under freshness.web_stale_accepted with a reason and an expiry')
    for name, entry in sorted(accepted.items(), key=lambda item: str(item[0])):
        if not str(entry.get('reason') or '').strip():
            found.append(f'{name}: web_stale_accepted entry has no reason')
        try:
            expires = dt.date.fromisoformat(str(entry.get('expires')))
        except ValueError:
            found.append(f'{name}: web_stale_accepted entry has no valid expires date (YYYY-MM-DD)')
            continue
        if expires < today:
            found.append(f'{name}: web_stale_accepted entry expired on {expires}')
        if name not in stale:
            found.append(f'{name}: web_stale_accepted entry names no stale direct dependency; remove it')
    return found


def fetch_json(url: str, deadline: float) -> dict:
    for family in ('-4', '-6'):
        if time.monotonic() > deadline:
            break
        result = subprocess.run([*CURL, family, url], capture_output=True, timeout=120, check=False)
        if result.returncode == 0 and result.stdout:
            return json.loads(result.stdout)
    raise ReleaseLookupError(f'no answer from {url}')


def release(name: str, deadline: float) -> tuple[str, dt.date]:
    quoted = urllib.parse.quote(name, safe='')
    errors = []
    for url, parse in ((f'https://api.deps.dev/v3/systems/npm/packages/{quoted}', latest_from_deps_dev),
                       (f'https://registry.npmjs.org/{quoted.replace("%40", "@", 1)}', latest_from_npm)):
        try:
            return parse(fetch_json(url, deadline))
        except (ReleaseLookupError, ValueError, KeyError, subprocess.TimeoutExpired) as error:
            errors.append(f'{url}: {error}')
    raise ReleaseLookupError('; '.join(errors))


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('package', type=Path)
    parser.add_argument('policy', type=Path)
    parser.add_argument('--today', type=dt.date.fromisoformat, default=dt.date.today())
    args = parser.parse_args(argv)
    package = json.loads(args.package.read_text())
    policy = json.loads(args.policy.read_text())
    deadline = time.monotonic() + DEADLINE_SECONDS
    releases, failures = {}, []
    for name in direct_dependencies(package):
        try:
            releases[name] = release(name, deadline)
            print(f'{name:<40} {releases[name][0]:<14} {releases[name][1]}', flush=True)
        except ReleaseLookupError as error:
            failures.append(f'{name}: release lookup failed: {error}')
    found = failures + problems(releases, policy, args.today)
    for line in found:
        print(f'[fail] {line}', file=sys.stderr, flush=True)
    return 1 if found else 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
