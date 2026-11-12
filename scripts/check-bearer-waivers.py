#!/usr/bin/env python3
"""Check that each bearer.ignore waiver still covers the statement that was reviewed for it.

Bearer names a finding <hash of rule and file>_<position among that rule's findings in the file>, and
bearer.ignore waives by that name. A flagged statement added above a waived one takes its position: that
waiver then covers the added statement, every waiver below it covers the flagged statement above its
own, and Bearer reports only the last statement of the file as new. On 2026-11-06 the waivers written
for selfhost/caddy/forward/main.go met a change that added a log.Fatal above them: six of the nine
covered the flagged statement above the one their comment described, and no comment described the
added one.

tests/security/bearer-waiver-sources.json records for each waiver the rule, the file, the flagged
statement and the two non-blank lines above it (identical statements such as log.Fatal(err) differ
there). This check reads a Bearer JSON report of the same tree made with an empty ignore file and fails
when a waiver's finding is gone, when waivers and records do not come in pairs, when a finding has no
waiver, or when a waiver covers another statement than the recorded one. Line numbers are not recorded:
a statement that only moved still passes.

--write records what the waivers cover now and prints every record it changed. Read each printed
statement at its place before committing the file: the record is the review.
"""

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
IGNORE = "bearer.ignore"
SOURCES = "tests/security/bearer-waiver-sources.json"
LINES_ABOVE = 2


def order(fingerprint):
    name, _, position = fingerprint.rpartition("_")
    return name, int(position) if position.isdigit() else -1


def findings(report):
    """Every finding of a Bearer JSON report ({severity: [finding, ...]}) by its fingerprint."""
    if not isinstance(report, dict) or not all(isinstance(items, list) for items in report.values()):
        raise ValueError("not a Bearer JSON report: expected lists of findings by severity")
    found = {}
    for items in report.values():
        for item in items:
            if item["fingerprint"] in found:
                raise ValueError("the report names two findings " + item["fingerprint"])
            found[item["fingerprint"]] = item
    return found


def record(root, finding):
    """What a waiver of this finding stands for: the rule, the file, the flagged statement and the lines above it."""
    path = (root / finding["filename"]).resolve()
    path.relative_to(root.resolve())
    lines = path.read_text().splitlines()
    first = finding["line_number"]
    last = max(first, finding["source"]["end"], finding["sink"]["end"])
    if not 1 <= first <= last <= len(lines):
        raise ValueError(f"{where(finding)}: the report does not belong to this tree")
    return {"rule": finding["id"], "file": finding["filename"],
            "above": [line.strip() for line in lines[:first - 1] if line.strip()][-LINES_ABOVE:],
            "statement": [line.strip() for line in lines[first - 1:last]]}


def where(finding):
    return f'{finding["filename"]}:{finding["line_number"]}'


def shown(entry):
    return "\n".join(["      " + line for line in entry["above"]] + ["    > " + line for line in entry["statement"]])


def compare(waivers, sources, found, current):
    """One message per waiver, record or finding that no longer matches the other two."""
    failures = [f'{name}: {where(found[name])} ({found[name]["id"]}) has no waiver\n{shown(current[name])}'
                for name in sorted(set(found) - set(waivers), key=order)]
    failures.extend(f"{name}: a recorded statement without a waiver in {IGNORE}"
                    for name in sorted(set(sources) - set(waivers), key=order))
    for name in sorted(waivers, key=order):
        if name not in found:
            failures.append(f"{name}: stale waiver, the scan has no finding with this name")
        elif name not in sources:
            failures.append(f"{name}: the waiver of {where(found[name])} has no recorded statement\n{shown(current[name])}")
        elif sources[name] != current[name]:
            moved = [f"{other} at {where(found[other])}" for other in sorted(current, key=order)
                     if current[other] == sources[name]]
            failures.append(
                f'{name}: the waiver now covers {where(found[name])} ({found[name]["id"]})\n{shown(current[name])}\n'
                f'  and was reviewed for {sources[name].get("file")} ({sources[name].get("rule")})\n'
                f'{shown({"above": sources[name].get("above", []), "statement": sources[name].get("statement", [])})}\n'
                + ("  which is now " + ", ".join(moved) if moved else "  which the scan no longer reports"))
    return failures


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0])
    parser.add_argument("--findings", type=Path, required=True,
                        help="Bearer JSON report of --root scanned with an empty ignore file")
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--ignore", type=Path, help=f"default: <root>/{IGNORE}")
    parser.add_argument("--sources", type=Path, help=f"default: <root>/{SOURCES}")
    parser.add_argument("--write", action="store_true",
                        help="record the statements the waivers cover now; read each printed one before committing")
    args = parser.parse_args()
    ignore, sources_path = args.ignore or args.root / IGNORE, args.sources or args.root / SOURCES
    waivers = json.loads(ignore.read_text())
    found = findings(json.loads(args.findings.read_text()))
    current = {name: record(args.root, finding) for name, finding in found.items()}
    sources = json.loads(sources_path.read_text()) if sources_path.is_file() else {}
    for path, entries in ((ignore, waivers), (sources_path, sources)):
        if not isinstance(entries, dict) or not all(isinstance(entry, dict) for entry in entries.values()):
            raise ValueError(f"{path}: expected one object per finding name")
    if args.write:
        recorded = {name: current[name] for name in sorted(waivers, key=order) if name in found}
        for name, entry in recorded.items():
            if sources.get(name) != entry:
                print(f"recorded {name} {where(found[name])}\n{shown(entry)}")
        sources_path.write_text(json.dumps(recorded, indent=1) + "\n")
        sources = recorded
    failures = compare(waivers, sources, found, current)
    if failures:
        raise ValueError("\n".join(failures) + f"\n{len(failures)} Bearer waiver(s) do not match the scan; after reading "
                         "each statement above, fix the code or the waiver and record it with --write")
    print(f"Bearer waivers: {len(waivers)} waivers, each covers the statement recorded for it")


if __name__ == "__main__":
    try:
        main()
    except (KeyError, TypeError, ValueError, OSError) as error:
        sys.exit(str(error))
