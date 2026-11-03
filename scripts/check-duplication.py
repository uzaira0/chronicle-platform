#!/usr/bin/env python3
import argparse
from collections import Counter
import csv
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parent.parent
BASELINE = ROOT / "tests/quality/duplication-baseline.jsonl"


def import_header_end(path):
    """Last line of the leading package/import section; clones inside it are not removable code."""
    end, open_brace = 0, False
    for number, line in enumerate(path.read_text().splitlines(), 1):
        text = line.strip()
        if open_brace:
            end, open_brace = number, not text.startswith("}")
        elif text.startswith(("import ", "package ")):
            end, open_brace = number, text.endswith("{")
        elif text and not text.startswith(("//", "/*", "*")):
            break
    return end


def scan():
    android = sorted((ROOT / "chronicle").glob("*/src/main"))
    sources = {
        "kotlin": ([ROOT / "chronicle-server/src/main", *android], {".kt"}),
        "java": (android, {".java"}),
        "typescript": ([ROOT / "chronicle-web/src"], {".ts", ".tsx"}),
        "python": ([ROOT / "selfhost", ROOT / "scripts"], {".py"}),
    }
    groups = Counter()
    locations = {}
    for language, (directories, extensions) in sources.items():
        files = sorted(
            path for directory in directories for path in directory.rglob("*")
            if path.is_file() and path.suffix in extensions
            and not (language == "typescript" and (
                {"test", "tests", "__tests__", "__mocks__"}.intersection(path.parts)
                or ".test." in path.name or ".spec." in path.name
                # Regenerated from the API spec; duplication there is not hand-maintained code.
                or ".generated." in path.name
            ))
        )
        if not directories or any(not directory.is_dir() for directory in directories):
            raise ValueError(f"missing production source directory for {language}")
        (ROOT / "build").mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=ROOT / "build") as mirror:
            # PMD 7.9.0 selects TypeScript files by the .ts extension only; its lexer reads TSX fine.
            scanned = {}
            for path in files:
                scanned[path] = path
                if path.suffix == ".tsx":
                    scanned[path] = Path(mirror, path.relative_to(ROOT)).with_suffix(".ts")
                    scanned[path].parent.mkdir(parents=True, exist_ok=True)
                    scanned[path].symlink_to(path)
            original = {str(alias): path for path, alias in scanned.items()}
            result = subprocess.run(
                ["pmd", "cpd", "--minimum-tokens", "75", "--language", language,
                 "--format", "csv", "--no-fail-on-violation", "--file-list", "/dev/stdin"],
                input="".join(f"{alias}\n" for alias in scanned.values()), capture_output=True, text=True,
            )
        if result.returncode:
            raise ValueError(f"CPD {language} failed ({result.returncode}): {result.stderr}")
        rows = csv.reader(io.StringIO(result.stdout))
        if next(rows, None) != ["lines", "tokens", "occurrences"]:
            raise ValueError(f"invalid CPD {language} report")
        for row in rows:
            starts = [int(line) for line in row[3::2]]
            if all(start + int(row[0]) - 1 <= import_header_end(original[path])
                   for start, path in zip(starts, row[4::2])):
                continue
            paths = [original[path].relative_to(ROOT).as_posix() for path in row[4::2]]
            # Preserve repeated paths and group multiplicity for clones within one file.
            key = (language, int(row[1]), tuple(sorted(paths)))
            groups[key] += 1
            locations.setdefault(key, []).append(
                ", ".join(f"{path}:{line}" for path, line in zip(paths, row[3::2]))
            )
        print(f"{language}: {sum(count for key, count in groups.items() if key[0] == language)} clone groups")
    return groups, locations


def main():
    parser = argparse.ArgumentParser(description="Gate production CPD clones against the checked-in baseline")
    parser.add_argument("--update-baseline", action="store_true",
                        help="drop baseline entries whose clones are gone; never adds a clone")
    args = parser.parse_args()
    current, locations = scan()
    baseline = Counter()
    for line in BASELINE.read_text().splitlines():
        language, tokens, paths = json.loads(line)
        baseline[(language, tokens, tuple(paths))] += 1
    if args.update_baseline:
        kept = baseline & current
        BASELINE.write_text("".join(json.dumps(key) + "\n" for key in sorted(kept) for _ in range(kept[key])))
        print(f"Updated {BASELINE.relative_to(ROOT)}: {sum(kept.values())} entries")
        return 0
    for key, count in sorted((current - baseline).items()):
        print(f"NEW clone ({key[0]}, {key[1]} tokens, {count} group(s)): " + "; ".join(locations[key]))
    # A stale entry would silently admit a new clone with the same key, so it fails too.
    for key, count in sorted((baseline - current).items()):
        print(f"STALE baseline entry ({key[0]}, {key[1]} tokens, {count} group(s)): {', '.join(key[2])}; "
              "remove it with CHRONICLE_DUPLICATION_UPDATE_BASELINE=1")
    return 1 if current != baseline else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError) as error:
        sys.exit(str(error))
