#!/usr/bin/env python3
"""Check .trivyignore.yaml: every waiver is owned, rechecked, bounded, staggered and still in use.

    check-trivy-waivers.py IGNOREFILE [--reports DIR] [--today YYYY-MM-DD]

Static rules (container-infra checklist B8):
  - each entry has id, paths or purls, statement, owner, rechecked (a date) and expired_at (a date);
  - rechecked is not in the future, expired_at is after today and at most MAX_DAYS after rechecked;
  - no single expiry date holds more than max(3, a quarter) of the entries, so they never all lapse
    together and invite a bulk re-date without a recheck.
  - an entry expiring within WARN_DAYS is reported (not failed).

--reports DIR adds the stale rule: DIR holds the Trivy JSON reports (`--format json --show-suppressed`
with this ignore file) of every shipped image. Trivy does not report unused ignore entries, so an entry
that suppressed no finding in any report matches nothing shipped and must be removed.
"""
import argparse
import datetime
import json
import math
from pathlib import Path
import sys
from urllib.parse import unquote

MAX_DAYS = 62
WARN_DAYS = 14


def as_date(value):
    if isinstance(value, datetime.datetime):
        return value.date()
    if isinstance(value, datetime.date):
        return value
    if isinstance(value, str):
        try:
            return datetime.date.fromisoformat(value)
        except ValueError:
            return None
    return None


def stagger_problems(dates, what):
    """Expiry dates (one per waiver) where too many waivers lapse on the same day."""
    limit = max(3, math.ceil(len(dates) / 4))
    counts = {}
    for date in dates:
        counts[date] = counts.get(date, 0) + 1
    return [f'{count} of {len(dates)} {what} expire on {date}; at most {limit} may share a date '
            '(stagger the rechecks)' for date, count in sorted(counts.items()) if count > limit]


def label(entry, index):
    return f"entry {index} ({entry.get('id') or '<no id>'})"


def static_problems(entries, today):
    problems, notes, dates = [], [], []
    for index, entry in enumerate(entries, 1):
        name = label(entry, index)
        if not isinstance(entry, dict):
            problems.append(f'{name}: not a mapping')
            continue
        if not str(entry.get('id', '')).strip():
            problems.append(f'{name}: missing id')
        if not (entry.get('paths') or entry.get('purls')):
            problems.append(f'{name}: names no paths or purls, so it would waive the advisory everywhere')
        for field in ('statement', 'owner'):
            if not str(entry.get(field, '') or '').strip():
                problems.append(f'{name}: missing {field}')
        rechecked, expires = as_date(entry.get('rechecked')), as_date(entry.get('expired_at'))
        if rechecked is None:
            problems.append(f'{name}: missing rechecked date')
        elif rechecked > today:
            problems.append(f'{name}: rechecked {rechecked} is in the future')
        if expires is None:
            problems.append(f'{name}: missing expired_at date')
            continue
        dates.append(expires)
        if expires <= today:
            problems.append(f'{name}: has expired ({expires}); recheck it, then renew or remove it')
        elif (expires - today).days <= WARN_DAYS:
            notes.append(f'{name}: expires within {WARN_DAYS} days ({expires})')
        if rechecked is not None and (expires - rechecked).days > MAX_DAYS:
            problems.append(f'{name}: expired_at {expires} is {(expires - rechecked).days} days after its recheck '
                            f'(at most {MAX_DAYS})')
    return problems + stagger_problems(dates, 'Trivy waivers'), notes


def purl_matches(waived, found):
    """Trivy's rule: same type/namespace/name@version, and every qualifier the waiver names agrees."""
    waived, found = unquote(waived), unquote(found or '')
    base, _, qualifiers = waived.partition('?')
    found_base, _, found_qualifiers = found.partition('?')
    if base != found_base:
        return False
    have = dict(pair.partition('=')[::2] for pair in found_qualifiers.split('&') if pair)
    return all(have.get(key) == value for key, value in
               (pair.partition('=')[::2] for pair in qualifiers.split('&') if pair))


def suppressed_findings(directory):
    findings = []
    for report in sorted(Path(directory).glob('*.json')):
        document = json.loads(report.read_text(encoding='utf-8'))
        for result in document.get('Results') or []:
            for modified in result.get('ExperimentalModifiedFindings') or []:
                if modified.get('Type') == 'vulnerability':
                    # Go and Rust binaries carry no PkgPath; Trivy matches `paths` against the binary,
                    # which is the result's Target.
                    finding = dict(modified.get('Finding') or {})
                    finding.setdefault('PkgPath', None)
                    finding['PkgPath'] = finding['PkgPath'] or result.get('Target', '')
                    findings.append(finding)
    return findings


def stale_problems(entries, findings):
    problems = []
    for index, entry in enumerate(entries, 1):
        if not isinstance(entry, dict):
            continue
        used = False
        for finding in findings:
            if finding.get('VulnerabilityID') != entry.get('id'):
                continue
            purl = (finding.get('PkgIdentifier') or {}).get('PURL')
            path = finding.get('PkgPath') or ''
            if any(purl_matches(waived, purl) for waived in entry.get('purls') or []) or \
                    any(path == waived or path.endswith('/' + waived) for waived in entry.get('paths') or []):
                used = True
                break
        if not used:
            problems.append(f'{label(entry, index)}: suppresses nothing in the scanned images; remove it')
    return problems


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('ignorefile', type=Path)
    parser.add_argument('--reports', type=Path)
    parser.add_argument('--today', type=datetime.date.fromisoformat,
                        default=datetime.datetime.now(datetime.timezone.utc).date())
    args = parser.parse_args(argv)
    import yaml  # only the CLI parses YAML; the OSV and Dependency-Check checkers import stagger_problems
    entries = (yaml.safe_load(args.ignorefile.read_text(encoding='utf-8')) or {}).get('vulnerabilities') or []
    problems, notes = static_problems(entries, args.today)
    if args.reports is not None:
        if not any(args.reports.glob('*.json')):
            problems.append(f'{args.reports}: no Trivy JSON reports to check waivers against')
        else:
            problems += stale_problems(entries, suppressed_findings(args.reports))
    for line in notes:
        print(f'{args.ignorefile}: note: {line}')
    for line in problems:
        print(f'{args.ignorefile}: {line}')
    return 1 if problems else 0


if __name__ == '__main__':
    sys.exit(main())
