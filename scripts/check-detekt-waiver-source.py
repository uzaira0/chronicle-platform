#!/usr/bin/env python3
"""Verify SARIF-derived metadata for existing detekt allowances and suppression directives."""

import argparse
from collections import Counter
from functools import lru_cache
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
from urllib.parse import unquote, urlsplit
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
METADATA = ROOT / "detekt-baseline.sources.json"
BASELINE_BASE = "5dc62f05"
# Pin the reviewed Git blob so the first metadata commit cannot authorize its own refresh.
METADATA_REVISION = "b4419cdc4e2510b76259046d85316395711ce06d"
FUNCTION_RULES = {"LongMethod", "NestedBlockDepth", "CyclomaticComplexMethod", "ReturnCount", "ThrowsCount",
                  "FunctionOnlyReturningConstant"}
FUNCTION_KINDS = {"function_declaration", "getter", "setter", "secondary_constructor", "anonymous_function"}
CLASS_KINDS = {"class_declaration", "object_declaration", "companion_object", "object_literal"}


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def offset(source, line, column):
    lines = source.splitlines(keepends=True) + [""]
    if line < 1 or line > len(lines) or column < 1:
        raise ValueError("invalid source position")
    prefix = lines[line - 1].encode("utf-16-le")[:(column - 1) * 2].decode("utf-16-le")
    if len(prefix.encode("utf-16-le")) != (column - 1) * 2:
        raise ValueError("source column exceeds line")
    return sum(map(len, lines[:line - 1])) + len(prefix)


def region_text(source, region):
    start = offset(source, region["startLine"], region["startColumn"])
    end = offset(source, region["endLine"], region["endColumn"])
    if end < start:
        raise ValueError("reversed source region")
    return source[start:end]


@lru_cache(maxsize=256)
def ast_nodes(source):
    kinds = sorted(FUNCTION_KINDS | CLASS_KINDS | {"annotation", "file_annotation", "parenthesized_expression"})
    suppression_type = {"kind": "user_type", "has": {
        "kind": "type_identifier", "regex": "^`?Suppress`?$",
        "not": {"precedes": {"kind": "type_identifier", "stopBy": "end"}},
    }}
    definitions = [{"id": kind, "language": "Kotlin", "rule": {"kind": kind}} for kind in kinds]
    definitions.append({"id": "suppression", "language": "Kotlin", "rule": {"all": [
        {"any": [{"kind": "annotation"}, {"kind": "file_annotation"}]},
        {"any": [{"has": suppression_type},
                 {"has": {"kind": "constructor_invocation", "has": suppression_type}}]},
    ]}})
    rules = "\n---\n".join(map(encoded, definitions))
    # Diagnostic ignore comments cannot hide this source inventory; their byte offsets remain identical.
    parsed = source.replace("ast-grep-ignore", "ast-grep-search")
    result = subprocess.run(["ast-grep", "scan", "--inline-rules", rules, "--json=compact", "--stdin"],
                            input=parsed, text=True, capture_output=True, timeout=30)
    if result.returncode not in (0, 1):
        raise ValueError("cannot parse Kotlin source: " + result.stderr)
    nodes = json.loads(result.stdout)
    data = source.encode()
    for node in nodes:
        extent = node["range"]["byteOffset"]
        node["text"] = data[extent["start"]:extent["end"]].decode()
    return nodes


def position(source, byte_offset):
    before = source.encode()[:byte_offset].decode()
    return {"Line": before.count("\n") + 1,
            "Column": len(before.rsplit("\n", 1)[-1].encode("utf-16-le")) // 2 + 1}


def finding_records(root, document):
    if document.get("version") != "2.1.0" or not isinstance(document.get("runs"), list):
        raise ValueError("invalid detekt SARIF")
    records = []
    for run in document["runs"]:
        for finding in run.get("results", []):
            location = finding["locations"][0]["physicalLocation"]
            uri = urlsplit(location["artifactLocation"]["uri"])
            path = Path(unquote(uri.path))
            path = path if path.is_absolute() else root / path
            relative = path.resolve().relative_to(root.resolve()).as_posix()
            source, region = path.read_text(), location["region"]
            region_text(source, region)
            span = dict(region)
            rule = finding["ruleId"].rsplit(".", 1)[-1]
            kinds = FUNCTION_KINDS if rule in FUNCTION_RULES else CLASS_KINDS if rule in {"LargeClass", "TooManyFunctions"} else set()
            if kinds:
                at = len(source[:offset(source, region["startLine"], region["startColumn"])].encode())
                owners = [node for node in ast_nodes(source) if node["ruleId"] in kinds
                          and node["range"]["byteOffset"]["start"] <= at < node["range"]["byteOffset"]["end"]]
                if not owners:
                    raise ValueError(f"{relative}: no enclosing source unit for {rule}")
                node = min(owners, key=lambda owner: len(owner["text"]))
                span = {prefix + key: value for prefix, byte in node["range"]["byteOffset"].items()
                        for key, value in position(source, byte).items()}
            records.append({"rule": rule, "path": relative, "line": region["startLine"], "column": region["startColumn"],
                            "span": span, "sha256": hashlib.sha256(region_text(source, span).encode()).hexdigest()})
    return records


def waived_findings(root, all_results, filtered_results):
    all_records = Counter(encoded(record) for record in finding_records(root, all_results))
    filtered = Counter(encoded(record) for record in finding_records(root, filtered_results))
    if filtered - all_records:
        raise ValueError("filtered SARIF does not belong to the same source scan")
    return [json.loads(record) for record, count in sorted((all_records - filtered).items()) for _ in range(count)]


def source_files(root):
    repos = [repo for repo in [root, *root.iterdir()] if repo.is_dir() and (repo / ".git").exists()]
    if not repos:
        return sorted(root.rglob("*.kt"))
    files = set()
    for repo in repos:
        result = subprocess.run(["git", "-C", str(repo), "ls-files", "--cached", "--others", "--exclude-standard", "-z", "--", "*.kt"],
                                text=True, capture_output=True, check=True)
        files.update(repo / name for name in result.stdout.split("\0") if name and "/src/" in "/" + name
                     and not name.startswith("tests/security/fixtures/") and (repo / name).is_file())
    return sorted(files)


def suppression_records(path, source):
    if "Suppress" not in source:
        return []
    nodes, data = ast_nodes(source), source.encode()
    directives = [node for node in nodes if node["ruleId"] == "suppression"]
    complete = {node["range"]["byteOffset"]["start"] for node in directives
                if node["text"].rstrip().endswith(")")}
    seen, records = set(), []
    for node in directives:
        if node["text"].rstrip().endswith("]"):
            raise ValueError(path + ": grouped file suppression requires a standalone annotation")
        extent = node["range"]["byteOffset"]
        start, end = extent["start"], extent["end"]
        if not node["text"].rstrip().endswith(")"):
            if start in complete:
                continue
            # ast-grep 0.42.1 can put the argument expression beside a bare annotation name.
            # Join only an adjacent native AST extent; every other gap fails closed.
            following = data[end:].lstrip()
            if following.startswith(b"("):
                arguments = [candidate["range"]["byteOffset"] for candidate in nodes
                             if candidate["ruleId"] == "parenthesized_expression"
                             and candidate["range"]["byteOffset"]["start"] >= end
                             and not data[end:candidate["range"]["byteOffset"]["start"]].strip()]
                if not arguments:
                    raise ValueError(path + ": cannot capture complete suppression arguments")
                end = min(arguments, key=lambda value: value["end"])["end"]
            else:
                raise ValueError(path + ": cannot capture complete suppression arguments")
        key = start, end
        if key not in seen:
            records.append({"path": path, "line": node["range"]["start"]["line"] + 1, "text": data[start:end].decode()})
            seen.add(key)
    return records


def suppression_inventory(root):
    return sorted((entry for path in source_files(root)
                   for entry in suppression_records(path.relative_to(root).as_posix(), path.read_text())), key=encoded)


def historical_suppressions(root, repos):
    found = []
    for repo, revision in repos:
        result = subprocess.run(["git", "-C", str(repo), "grep", "-l", "-z", "Suppress", revision, "--", "*.kt"],
                                capture_output=True, text=True, timeout=30)
        if result.returncode not in (0, 1):
            raise ValueError("cannot read historical suppression inventory: " + result.stderr)
        for match in result.stdout.split("\0"):
            if not match:
                continue
            name = match.split(":", 1)[1]
            relative = (repo / name).relative_to(root).as_posix()
            if "/src/" not in "/" + relative or relative.startswith("tests/security/fixtures/"):
                continue
            content = subprocess.run(["git", "-C", str(repo), "show", revision + ":" + name],
                                     capture_output=True, text=True, timeout=30, check=True).stdout
            found.extend(suppression_records(relative, content))
    return sorted(found, key=encoded)


def suppression_rules(directive):
    payload = directive[directive.index("(") + 1:directive.rindex(")")]
    decoder, names, at = json.JSONDecoder(), set(), 0
    while at < len(payload):
        if payload[at].isspace() or payload[at] == ",":
            at += 1
        elif payload.startswith("//", at):
            end = payload.find("\n", at)
            at = len(payload) if end < 0 else end + 1
        elif payload.startswith("/*", at):
            depth, at = 1, at + 2
            while depth and at < len(payload):
                if payload.startswith("/*", at):
                    depth, at = depth + 1, at + 2
                elif payload.startswith("*/", at):
                    depth, at = depth - 1, at + 2
                else:
                    at += 1
            if depth:
                raise ValueError("unclosed suppression comment")
        else:
            value, end = decoder.raw_decode(payload, at)
            if not isinstance(value, str):
                raise ValueError("suppression rules must be literal names")
            names.add(value)
            at = end
    return names


def bootstrap_suppression_additions(current, historical):
    remaining, pending = list(historical), []
    # Preserve exact existing directives first, regardless of pre-pin location.
    for entry in current:
        exact = next((index for index, old in enumerate(remaining) if old["text"] == entry["text"]), None)
        if exact is None:
            pending.append(entry)
        else:
            remaining.pop(exact)
    old_rules = []
    for entry in remaining:
        try:
            old_rules.append(suppression_rules(entry["text"]))
        except ValueError:
            old_rules.append(None)
    options, failures = [], []
    for entry in pending:
        try:
            names = suppression_rules(entry["text"])
            options.append([index for index, rules in enumerate(old_rules) if rules is not None and names <= rules])
        except ValueError:
            options.append([])
    owners = {}

    def match(index, seen):
        for old in options[index]:
            if old in seen:
                continue
            seen.add(old)
            if old not in owners or match(owners[old], seen):
                owners[old] = index
                return True
        return False

    # A dated directive can cover one exact/narrowed current directive, never a split or merged allowance.
    for index in sorted(range(len(pending)), key=lambda index: len(options[index])):
        if not match(index, set()):
            entry = pending[index]
            failures.append(f'new suppression directive/rules/count during bootstrap: {entry["path"]}:{entry["line"]}: {entry["text"]}')
    return failures


def metadata_policy(metadata, accepted, base_ids, dated_suppressions=None):
    failures = []
    if set(metadata["baselineIds"]) - base_ids:
        failures.append("metadata grants new XML baseline IDs")
    if accepted is not None:
        if metadata.get("baselineBase") != accepted.get("baselineBase"):
            failures.append("the accepted XML baseline base is immutable")
        if (set(metadata["baselineIds"]) - set(accepted["baselineIds"])
                or Counter(map(encoded, metadata["findings"])) - Counter(map(encoded, accepted["findings"]))
                or Counter(map(encoded, metadata["suppressions"])) - Counter(map(encoded, accepted["suppressions"]))):
            failures.append("metadata may retire existing pins, never add, move or refresh them")
    else:
        # Bootstrap adopts the final candidate; a directive may relocate or lose rules, never gain scope.
        failures.extend(bootstrap_suppression_additions(metadata["suppressions"], dated_suppressions or []))
    return failures


def verify_metadata(root, metadata, ids, all_results=None, filtered_results=None):
    failures = ["new XML baseline ID: " + identity for identity in sorted(ids - set(metadata["baselineIds"]))]
    for entry in metadata["findings"]:
        try:
            digest = hashlib.sha256(region_text((root / entry["path"]).read_text(), entry["span"]).encode()).hexdigest()
            if digest != entry["sha256"]:
                failures.append(f'{entry["path"]}:{entry["line"]}:{entry["column"]}: edited source span for {entry["rule"]}')
        except (OSError, ValueError) as error:
            failures.append(f'{entry["path"]}: source span unavailable: {error}')
    actual = Counter(map(encoded, suppression_inventory(root)))
    pinned = Counter(map(encoded, metadata["suppressions"]))
    failures.extend("unknown or moved suppression: " + value for value in sorted((actual - pinned).elements()))
    failures.extend("stale suppression pin: " + value for value in sorted((pinned - actual).elements()))
    if all_results is not None:
        fresh = Counter(map(encoded, waived_findings(root, all_results, filtered_results)))
        known = Counter(map(encoded, metadata["findings"]))
        failures.extend("unknown or moved waived finding: " + value for value in sorted((fresh - known).elements()))
        failures.extend("stale waived finding pin: " + value for value in sorted((known - fresh).elements()))
    return failures


def diff_coverage():
    spec = importlib.util.spec_from_file_location("coverage", ROOT / "scripts/diff-coverage.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def accepted_metadata(root, revision):
    return json.loads(diff_coverage().git(root, "show", revision))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--metadata", type=Path, default=METADATA)
    parser.add_argument("--all-sarif", type=Path, required=True)
    parser.add_argument("--filtered-sarif", type=Path, required=True)
    parser.add_argument("--write", action="store_true", help="verify the metadata from these scans, then write it")
    args = parser.parse_args()
    coverage = diff_coverage()
    reports = [json.loads(path.read_text()) for path in (args.all_sarif, args.filtered_sarif)]
    ids = {node.text for node in ET.parse(ROOT / "detekt-baseline.xml").iter("ID")}
    accepted = accepted_metadata(ROOT, METADATA_REVISION)
    authorized = coverage.git(ROOT, "rev-parse", BASELINE_BASE)
    expected = accepted["baselineBase"]
    metadata = ({"baselineBase": expected, "baselineIds": sorted(ids),
                 "findings": waived_findings(ROOT, *reports), "suppressions": suppression_inventory(ROOT)}
                if args.write else json.loads(args.metadata.read_text()))
    if not expected or expected != authorized or metadata["baselineBase"] != expected:
        raise ValueError("metadata must preserve the authorized dated XML-ID base " + BASELINE_BASE)
    base_ids = {node.text for node in ET.fromstring(coverage.git(ROOT, "show", expected + ":detekt-baseline.xml")).iter("ID")}
    failures = metadata_policy(metadata, accepted, base_ids)
    failures.extend(verify_metadata(ROOT, metadata, ids, *reports))
    if failures:
        raise ValueError("\n".join(failures))
    if args.write:
        args.metadata.write_text(json.dumps(metadata, indent=1, sort_keys=True) + "\n")
    print(f'Detekt metadata: {len(metadata["findings"])} existing finding pins; full suppression inventory checked')


if __name__ == "__main__":
    try:
        main()
    except (KeyError, ValueError, OSError, ET.ParseError, subprocess.SubprocessError) as error:
        sys.exit(str(error))
