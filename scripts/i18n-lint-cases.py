#!/usr/bin/env python3
"""Table-driven proof that the hardcoded-English lint rules fire exactly where expected.

Every file under lint/i18n/cases is scanned with the repo's rules. A line carrying a
`FIRE: rule-id[, rule-id]` marker (inside any comment) must produce exactly those findings on
that line; every other line must produce none. Files without markers must be clean (they
exercise ignored paths, suppressions, allowed shapes, and documented holes). Every rule id
declared under lint/i18n must fire at least once, so a rule that stops matching, or a deleted
rule, fails the run.

Run from the surface repository (chronicle, chronicle-server, chronicle-web):
  python3 ../scripts/i18n-lint-cases.py [--tool ast-grep|semgrep] [--config PATH] [cases-dir]
"""

import glob
import json
import os
import re
import subprocess
import sys
from collections import Counter


def findings(tool, config, cases):
    """Scan the whole cases directory once (explicit file targets bypass path excludes) and
    return {relative path: sorted [(rule, line)]}."""
    by_file = {}
    if tool == "ast-grep":
        out = subprocess.run(
            ["ast-grep", "scan", "--json", cases], capture_output=True, text=True
        ).stdout
        for f in json.loads(out or "[]"):
            by_file.setdefault(os.path.normpath(f["file"]), []).append(
                (f["ruleId"], f["range"]["start"]["line"] + 1)
            )
    else:
        out = subprocess.run(
            [
                "semgrep",
                "--metrics=off",
                "--quiet",
                "--json",
                "--config",
                config,
                cases,
            ],
            capture_output=True,
            text=True,
        ).stdout
        for r in json.loads(out or '{"results": []}').get("results", []):
            by_file.setdefault(os.path.normpath(r["path"]), []).append(
                (r["check_id"].rsplit(".", 1)[-1], r["start"]["line"])
            )
    return {k: sorted(v) for k, v in by_file.items()}


def expected(path):
    exp = []
    with open(path, encoding="utf-8") as fh:
        for n, line in enumerate(fh, 1):
            m = re.search(r"FIRE:\s*([A-Za-z0-9_-]+(?:\s*,\s*[A-Za-z0-9_-]+)*)", line)
            if m:
                exp.extend((rule.strip(), n) for rule in m.group(1).split(","))
    return sorted(exp)


def declared_rules():
    ids = set()
    for yml in glob.glob("lint/i18n/*.yml"):
        with open(yml, encoding="utf-8") as fh:
            ids.update(
                re.findall(r"^\s*(?:- )?id:\s*([A-Za-z0-9_-]+)\s*$", fh.read(), re.M)
            )
    return ids


def main():
    args = sys.argv[1:]
    tool, config, cases = "ast-grep", None, "lint/i18n/cases"
    while args:
        a = args.pop(0)
        if a == "--tool":
            tool = args.pop(0)
        elif a == "--config":
            config = args.pop(0)
        else:
            cases = a
    files = sorted(
        os.path.join(d, f)
        for d, _, fs in os.walk(cases)
        for f in fs
        if not f.startswith(".")
    )
    if not files:
        print(f"no case files under {cases}")
        return 2
    failed, checked, fired = 0, 0, set()
    scanned = findings(tool, config, cases)
    for path in files:
        want, got = expected(path), scanned.get(os.path.normpath(path), [])
        checked += len(want)
        fired.update(rule for rule, _ in got)
        if want == got:
            print(f"PASS {path} ({len(want)} expected finding(s))")
        else:
            failed += 1
            print(f"FAIL {path}")
            for item, k in sorted((Counter(want) - Counter(got)).items()):
                print(f"     missing  {item[0]} @ line {item[1]} (x{k})")
            for item, k in sorted((Counter(got) - Counter(want)).items()):
                print(f"     unwanted {item[0]} @ line {item[1]} (x{k})")
    silent = declared_rules() - fired
    if silent:
        failed += 1
        print(
            f"FAIL rules declared but never fired in any case: {', '.join(sorted(silent))}"
        )
    print(
        f"{len(files) - failed}/{len(files)} case files pass, {checked} expected findings checked, "
        f"{len(fired)} rule id(s) exercised"
    )
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
