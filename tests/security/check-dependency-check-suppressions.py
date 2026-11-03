#!/usr/bin/env python3
"""Validate package-wide Dependency-Check waivers against resolved Gradle coordinates."""

import datetime
from pathlib import Path
import re
import sys
import xml.etree.ElementTree as ET

MAX_DAYS = 90


def locked_coordinates(root):
    return {line.split('=', 1)[0] for lock in root.rglob('gradle.lockfile')
            for line in lock.read_text().splitlines()
            if line and not line.startswith(('#', 'empty='))}


def matches(selector, value):
    text = selector.text or ''
    if selector.get('regex', 'false') == 'true':
        return re.fullmatch(text, value, re.IGNORECASE) is not None
    return text.lower() == value.lower()


def problems(path, coordinates, today):
    found = []
    for number, rule in enumerate(ET.parse(path).getroot().findall('{*}suppress'), 1):
        names = rule.findall('{*}vulnerabilityName')
        wide = any(all(matches(name, advisory) for advisory in
                       ('CVE-2099-12345', 'GHSA-test', 'arbitrary-advisory')) for name in names)
        if not wide and any(rule.find('{*}' + tag) is not None
                            for tag in ('cve', 'cpe', 'cwe', 'cvssBelow', 'vulnerabilityName')):
            continue
        prefix = f'{path}: suppression {number}'
        try:
            until = datetime.date.fromisoformat(rule.get('until', '').removesuffix('Z'))
            if not today < until <= today + datetime.timedelta(days=MAX_DAYS):
                found.append(f'{prefix}: until must be in the next {MAX_DAYS} days')
        except ValueError:
            found.append(f'{prefix}: package-wide suppression requires a valid until date')
        selectors = [(tag, selector) for tag in ('packageUrl', 'gav') for selector in rule.findall('{*}' + tag)]
        for coordinate in sorted(coordinates):
            group, artifact, version = coordinate.split(':')
            values = {'packageUrl': f'pkg:maven/{group}/{artifact}@{version}', 'gav': coordinate}
            if all(matches(selector, values[tag]) for tag, selector in selectors):
                found.append(f'{prefix}: package-wide suppression matches resolved dependency {coordinate}')
    return found


if __name__ == '__main__':
    try:
        today = datetime.datetime.now(datetime.timezone.utc).date()
        failures = problems(Path(sys.argv[1]), locked_coordinates(Path(sys.argv[2])), today)
    except (ValueError, OSError, ET.ParseError) as error:
        sys.exit(str(error))
    print('\n'.join(failures))
    sys.exit(1 if failures else 0)
