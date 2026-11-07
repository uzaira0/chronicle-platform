#!/usr/bin/env python3
"""Validate Dependency-Check suppressions against the resolved runtime Gradle coordinates.

    check-dependency-check-suppressions.py SUPPRESSIONS.xml REPOSITORY_ROOT

Dependency-Check scans runtimeClasspath only (build.gradle.kts scanConfigurations), so the locked
runtimeClasspath coordinates of every gradle.lockfile are what it can match. Every suppression:
  - expires (until=) within MAX_DAYS, and its notes name the owner ("Owner: NAME.") and the last
    recheck ("Rechecked YYYY-MM-DD");
  - selects its package by packageUrl or gav, pinned to versions: a selector that still matches the
    same artifact at any other version never stops matching after an upgrade;
  - still matches a locked runtime coordinate, or (for a library shaded inside another jar) its notes
    say "Carried by GROUP:ARTIFACT:VERSION" for a locked runtime coordinate; otherwise it is stale;
  - shares its expiry date with at most max(3, a quarter) of the suppressions;
  - if it waives every advisory (no cve/cpe/cwe/cvssBelow, or a vulnerabilityName matching anything),
    matches no resolved dependency at all: only shaded copies may be waived wholesale.
"""

import datetime
from pathlib import Path
import re
import runpy
import sys
import xml.etree.ElementTree as ET

stagger_problems = runpy.run_path(str(Path(__file__).resolve().parent / 'check-trivy-waivers.py'))['stagger_problems']

MAX_DAYS = 90
PROBE_VERSION = '0.0.0-chronicle-probe'
OWNER = re.compile(r'\bOwner: ?\S')
RECHECK = re.compile(r'\bRechecked (\d{4}-\d{2}-\d{2})\b')
CARRIER = re.compile(r'\bCarried by ([\w.-]+:[\w.-]+:[\w+-]+(?:\.[\w+-]+)*)')  # a sentence's full stop is not part of the version


def lock_entries(root):
    for lock in Path(root).rglob('gradle.lockfile'):
        for line in lock.read_text().splitlines():
            if line and not line.startswith(('#', 'empty=')):
                coordinate, _, configurations = line.partition('=')
                yield coordinate, set(configurations.split(','))


def locked_coordinates(root):
    return {coordinate for coordinate, _ in lock_entries(root)}


def runtime_coordinates(root):
    return {coordinate for coordinate, configurations in lock_entries(root) if 'runtimeClasspath' in configurations}


def matches(selector, value):
    text = selector.text or ''
    if selector.get('regex', 'false') == 'true':
        return re.fullmatch(text, value, re.IGNORECASE) is not None
    return text.lower() == value.lower()


def selector_values(coordinate):
    group, artifact, version = coordinate.split(':')
    return {'packageUrl': f'pkg:maven/{group}/{artifact}@{version}', 'gav': coordinate}


def selected(selectors, coordinate):
    values = selector_values(coordinate)
    return bool(selectors) and all(matches(selector, values[tag]) for tag, selector in selectors)


def problems(path, coordinates, today, runtime=None):
    """coordinates: every locked coordinate; runtime: the locked runtimeClasspath ones (default: all)."""
    runtime = coordinates if runtime is None else runtime
    found, dates = [], []
    for number, rule in enumerate(ET.parse(path).getroot().findall('{*}suppress'), 1):
        prefix = f'{path}: suppression {number}'
        notes = ''.join((rule.find('{*}notes').text or '') if rule.find('{*}notes') is not None else '')
        try:
            until = datetime.date.fromisoformat(rule.get('until', '').removesuffix('Z'))
            dates.append(until)
            if not today < until <= today + datetime.timedelta(days=MAX_DAYS):
                found.append(f'{prefix}: until must be in the next {MAX_DAYS} days')
        except ValueError:
            found.append(f'{prefix}: every suppression requires a valid until date')
        if not OWNER.search(notes):
            found.append(f'{prefix}: notes must name the owner (Owner: NAME.)')
        recheck = RECHECK.search(notes)
        if not recheck:
            found.append(f'{prefix}: notes must date the last recheck (Rechecked YYYY-MM-DD)')
        elif datetime.date.fromisoformat(recheck[1]) > today:
            found.append(f'{prefix}: recheck date {recheck[1]} is in the future')
        selectors = [(tag, selector) for tag in ('packageUrl', 'gav') for selector in rule.findall('{*}' + tag)]
        if not selectors:
            found.append(f'{prefix}: names no packageUrl or gav, so it would apply to every package')
        names = rule.findall('{*}vulnerabilityName')
        wide = any(all(matches(name, advisory) for advisory in
                       ('CVE-2099-12345', 'GHSA-test', 'arbitrary-advisory')) for name in names)
        wide = wide or not any(rule.find('{*}' + tag) is not None
                               for tag in ('cve', 'cpe', 'cwe', 'cvssBelow', 'vulnerabilityName'))
        if wide:
            for coordinate in sorted(coordinates):
                if not selectors or selected(selectors, coordinate):
                    found.append(f'{prefix}: package-wide suppression matches resolved dependency {coordinate}')
        if not selectors:
            continue
        carriers = CARRIER.findall(notes)
        hits = [coordinate for coordinate in runtime if selected(selectors, coordinate)]
        for coordinate in hits:
            group, artifact, _ = coordinate.split(':')
            if selected(selectors, f'{group}:{artifact}:{PROBE_VERSION}'):
                found.append(f'{prefix}: selector matches {group}:{artifact} at any version; pin the versions it waives')
                break
        if not wide and not hits and not any(carrier in runtime for carrier in carriers):
            found.append(f'{prefix}: matches no resolved runtime dependency; remove the stale suppression')
        if wide and not any(carrier in runtime for carrier in carriers):
            found.append(f'{prefix}: a package-wide suppression must name the resolved jar that carries the '
                         'shaded copy (Carried by GROUP:ARTIFACT:VERSION)')
    return found + [f'{path}: {problem}' for problem in stagger_problems(dates, 'Dependency-Check suppressions')]


if __name__ == '__main__':
    try:
        today = datetime.datetime.now(datetime.timezone.utc).date()
        root = Path(sys.argv[2])
        failures = problems(Path(sys.argv[1]), locked_coordinates(root), today, runtime_coordinates(root))
    except (ValueError, OSError, ET.ParseError) as error:
        sys.exit(str(error))
    print('\n'.join(failures))
    sys.exit(1 if failures else 0)
