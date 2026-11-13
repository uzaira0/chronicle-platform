#!/usr/bin/env python3
"""Fail when the database image trails a newer build of its vendor for too long.

The self-host database is Percona's build of PostgreSQL. PostgreSQL ships its security fixes in minor
releases, and Trivy has no advisories for Percona's packages, so the image gate says nothing when the
pinned image falls behind one. On 2026-11-13 the pin was 18.6.1-4, PostgreSQL 18.7 had been out for a day
with 38 advisories rated HIGH, and they showed up only against libpq5 in the fluent-bit image.
deps-freshness printed "minor-behind" and passed. This check puts a date on that lag.

The pinned tag (toolchain-manifest.yaml postgres.image) is compared with the repository's build tags
(MAJOR.MINOR.PATCH-BUILD) of the same PostgreSQL major. Once a newer one has been on Docker Hub for more
than `freshness.database_max_lag_days`, the check fails, unless `freshness.database_lag_accepted` holds a
reason and an unexpired `expires` date. The clock starts at the push of the oldest newer build, so a later
respin does not restart it. An acceptance that has expired, lacks a reason, or stands while nothing is over
the limit also fails, so it cannot rot. A newer build with no push time fails: the lag cannot be measured.
A newer major is deps-freshness.sh's own MAJOR-BEHIND row, not this check. Run by scripts/deps-freshness.sh.

    database_image_lag.py REPOSITORY PINNED_TAG POLICY.json [--today YYYY-MM-DD]

The tags come from Docker Hub, through the one curl call of scripts/web_dependency_age.py: every request
has a timeout and retries, IPv4 is tried before IPv6, and the whole run stops at a deadline. The list is
read page by page, and the address of a next page comes from Docker Hub's answer; it is fetched only when
it stays inside the repository's tag list.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import web_dependency_age  # scripts/web_dependency_age.py: fetch_json, the curl call both checks use

DEADLINE_SECONDS = 180
MAX_PAGES = 10
BUILD_TAG = re.compile(r'(\d+)\.(\d+)\.(\d+)-(\d+)')
# Docker Hub's NAMESPACE/NAME, and what may follow "tags?" in the address of a page of its tag list.
REPOSITORY = re.compile(r'[a-z0-9]+(?:[._-]+[a-z0-9]+)*/[a-z0-9]+(?:[._-]+[a-z0-9]+)*')
PAGE_QUERY = re.compile(r'[A-Za-z0-9._~%&=+-]+')


class TagLookupError(RuntimeError):
    pass


def build(tag: str) -> tuple[int, ...] | None:
    match = BUILD_TAG.fullmatch(tag)
    return tuple(int(part) for part in match.groups()) if match else None


def pushed_on(entry: dict) -> dt.date | None:
    try:
        return dt.date.fromisoformat(str(entry.get('tag_last_pushed') or '')[:10])
    except ValueError:
        return None


def problems(pinned: str, tags: list[dict], policy: dict, today: dt.date) -> tuple[list[str], str]:
    """(what fails, one line saying where the pin stands)."""
    limit = int(policy['database_max_lag_days'])
    accepted = policy.get('database_lag_accepted')
    current = build(pinned)
    if current is None:
        return [f'the pinned tag {pinned} is not MAJOR.MINOR.PATCH-BUILD; the lag cannot be measured'], ''
    builds = [(build(str(entry.get('name'))), entry) for entry in tags]
    newer = sorted(((key, entry) for key, entry in builds if key and key[0] == current[0] and key > current),
                   key=lambda item: item[0])
    found, note, over = [], f'{pinned} is the newest build of PostgreSQL {current[0]}', False
    if newer:
        newest = newer[-1][1]['name']
        undated = [entry['name'] for _, entry in newer if pushed_on(entry) is None]
        if undated:
            found.append(f'{undated[0]} is newer than {pinned} and Docker Hub gives no push time for it; the lag '
                         'cannot be measured')
        else:
            first = min(pushed_on(entry) for _, entry in newer)
            days = (today - first).days
            over = days > limit
            note = (f'{pinned} is behind {newest}, pushed {first} ({days} days ago); it has to move by '
                    f'{first + dt.timedelta(days=limit)}')
            if over and accepted is None:
                found.append(f'{pinned} has been behind {newest} for {days} days (pushed {first}), over {limit}: '
                             'PostgreSQL ships its security fixes in minor releases and the image scan does not see '
                             "them in Percona's packages. Move postgres.image, or record why not under "
                             'freshness.database_lag_accepted with a reason and an expiry')
    if accepted is not None:
        if not str(accepted.get('reason') or '').strip():
            found.append('database_lag_accepted has no reason')
        try:
            expires = dt.date.fromisoformat(str(accepted.get('expires')))
        except ValueError:
            found.append('database_lag_accepted has no valid expires date (YYYY-MM-DD)')
        else:
            if expires < today:
                found.append(f'database_lag_accepted expired on {expires}')
        if not over:
            found.append('database_lag_accepted stands while the image is not over the limit; remove it')
    return found, note


def fetch_json(url: str, deadline: float) -> dict:
    try:
        document = web_dependency_age.fetch_json(url, deadline)
    except ValueError as error:
        raise TagLookupError(f'{url} did not answer with JSON: {error}') from error
    except web_dependency_age.ReleaseLookupError as error:
        raise TagLookupError(str(error)) from error
    except subprocess.TimeoutExpired as error:
        raise TagLookupError(f'{url} did not answer in {error.timeout:g} seconds') from error
    if not isinstance(document, dict):
        raise TagLookupError(f'{url} did not answer with a JSON object')
    return document


def hub_tags(repository: str, major: int, deadline: float) -> list[dict]:
    """Every tag of the repository whose name contains "MAJOR." (Docker Hub's filter is a substring match)."""
    if not REPOSITORY.fullmatch(repository):
        raise TagLookupError(f'{repository!r} is not a Docker Hub repository (NAMESPACE/NAME)')
    tag_list = f'https://hub.docker.com/v2/repositories/{repository}/tags?'
    url = f'{tag_list}page_size=100&name={int(major)}.'
    tags: list[dict] = []
    for _ in range(MAX_PAGES):
        document = fetch_json(url, deadline)
        results = document.get('results')
        if not isinstance(results, list):
            raise TagLookupError(f'{url} has no results list')
        tags.extend(entry for entry in results if isinstance(entry, dict) and entry.get('name'))
        url = document.get('next')
        if not url:
            return tags
        # The address goes to curl as an argument: "-o..." would be an option, file:// a local file.
        if not (isinstance(url, str) and url.startswith(tag_list) and PAGE_QUERY.fullmatch(url[len(tag_list):])):
            raise TagLookupError(f'Docker Hub names a next page outside {tag_list}: {url!r}')
    raise TagLookupError(f'{repository} has more than {MAX_PAGES} pages of tags for {major}.')


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('repository')
    parser.add_argument('pinned')
    parser.add_argument('policy', type=Path)
    parser.add_argument('--today', type=dt.date.fromisoformat, default=dt.date.today())
    args = parser.parse_args(argv)
    policy = json.loads(args.policy.read_text())
    current = build(args.pinned)
    try:
        tags = hub_tags(args.repository, current[0], time.monotonic() + DEADLINE_SECONDS) if current else []
        found, note = problems(args.pinned, tags, policy, args.today)
    except TagLookupError as error:
        found, note = [f'tag lookup failed: {error}'], ''
    if note:
        print(f'database image: {note}', flush=True)
    for line in found:
        print(f'[fail] database image: {line}', file=sys.stderr, flush=True)
    return 1 if found else 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
