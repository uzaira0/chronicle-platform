#!/usr/bin/env python3
"""Fail on a JVM @Test that asserts nothing.

A test passes when it asserts something observable, or when it calls a test helper (any test source) that does.
"Asserts" is a default-deny allowlist: a call or reference whose name matches ASSERTION (JUnit/Kotlin
assert*/fail/check/require, kotest should*/forAll/checkAll, Mockito verify at a real boundary, a
waitUntil that fails on timeout), or `@Test(expected = ...)`. A test whose only check is that a mock
was called still needs a reviewer; this script catches the tests that check nothing at all
(e.g. a body that only calls an endpoint, or a comment saying "no exception").

Function bodies come from ast-grep (the Kotlin and Java grammars), so comments and strings never count.
Usage: check-tests-assert.py [ROOT]   (default: the repository root). Exit 1 lists every offender.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from collections.abc import Iterable
from pathlib import Path
from typing import NamedTuple

ROOT = Path(__file__).resolve().parents[1]
TEST_TREES = (
    'chronicle-server/src/test', 'chronicle-api/src/test', 'chronicle-models/src/test',
    'rhizome/src/test', 'rhizome-client/src/test', 'chronicle',
)
ASSERTION = re.compile(r'(?i)^(assert\w*|fail\w*|check\w*|require\w*|verify\w*|expect\w*|should\w*|'
                       r'forAll|checkAll|waitUntil\w*|await\w*Until\w*)$')
TYPE_ARGUMENTS = r'(?:<[\w\s.,?<>:[\]*&]+>)?'
CALL = re.compile(r'(?<![\w`])(`[^`]+`|[A-Za-z_]\w*)\s*(?=' + TYPE_ARGUMENTS +
                  r'\s*(?:\(|\{))|::(`[^`]+`|[A-Za-z_]\w*)')
# A helper call is a bare call (`helper(...)`, `helper { ... }`, `::helper`), never `client.api.createStudy(...)`:
# an endpoint or library method that happens to share a helper's name must not count as an assertion.
BARE_CALL = re.compile(r'(?<=::)(`[^`]+`|[A-Za-z_]\w*)|(?<![.\w`:])(`[^`]+`|[A-Za-z_]\w*)\s*' +
                       TYPE_ARGUMENTS + r'\s*(?:\(|\{)')
KOTLIN_NAME = re.compile(r'\bfun\s+(?:<[^>]*>\s*)?(?:[\w.]+\.)?(`[^`]+`|\w+)\s*\(')
JAVA_NAME = re.compile(r'(\w+)\s*\([^)]*\)\s*(?:throws[\w\s,.]+)?\{')
TEST_ANNOTATION = re.compile(r'@(?:org\.junit\.(?:jupiter\.api\.)?)?Test\b(\s*\(([^)]*)\))?')

RULES = {
    'kotlin': 'id: fn\nlanguage: Kotlin\nrule:\n  kind: function_declaration\n',
    'java': 'id: fn\nlanguage: Java\nrule:\n  kind: method_declaration\n',
}


def strip_comments_and_strings(text: str) -> str:
    text = re.sub(r'"""[\s\S]*?"""', '""', text)
    text = re.sub(r'"(?:\\.|[^"\\\n])*"', '""', text)
    text = re.sub(r'/\*[\s\S]*?\*/', ' ', text)
    return re.sub(r'//[^\n]*', ' ', text)


class Function(NamedTuple):
    file: str
    scope: str
    owner: str
    parents: tuple[str, ...]
    package: str
    imports: tuple[tuple[str, str], ...]
    name: str
    prefix: str
    body: str


def declarations(root: Path, trees: Iterable[str]) -> list[Function]:
    """Parse methods and their enclosing classes, including Android flavor test roots."""
    found = []
    paths = [str(root / tree) for tree in trees if (root / tree).exists()]
    if not paths:
        return found
    for language, rule in RULES.items():
        owner_rule = f'id: owner\nlanguage: {language}\nrule:\n  kind: class_declaration\n'
        rule += f'---\n{owner_rule}'
        if language == 'kotlin':
            rule += '---\nid: annotation\nlanguage: Kotlin\nrule:\n  kind: annotation\n'
        listed = subprocess.run(
            ['ast-grep', 'scan', '--inline-rules', rule, '--json=stream',
             '--globs', '**/src/test*/**', '--globs', '**/src/androidTest/**', '--globs', '!**/build/**', *paths],
            capture_output=True, text=True, check=False)
        if listed.returncode not in (0, 1):
            raise RuntimeError(f'ast-grep failed for {language}: {listed.stderr.strip()}')
        matches = [json.loads(line) for line in listed.stdout.splitlines()]
        owners = [match for match in matches if match['ruleId'] == 'owner']
        if language == 'kotlin':
            orphan_files = {row['file'] for row in matches if row['ruleId'] == 'fn' and not any(
                owner['file'] == row['file'] and owner['range']['byteOffset']['start'] <= row['range']['byteOffset']['start']
                and owner['range']['byteOffset']['end'] >= row['range']['byteOffset']['end'] for owner in owners)}
            for file in orphan_files:
                annotations = [row for row in matches if row['file'] == file and row['ruleId'] == 'annotation']
                if not annotations:
                    continue
                source = bytearray(Path(file).read_bytes())
                # Kotlin annotation class arrays can parse a whole class as a lambda; reparse owners only.
                for annotation in annotations:
                    # Recovery can split the annotation name from its arguments; keep those nodes intact.
                    if not annotation['text'].rstrip().endswith(')'):
                        continue
                    offsets = annotation['range']['byteOffset']
                    start, end = offsets['start'], offsets['end']
                    source[start:end] = re.sub(rb'[^\r\n]', b' ', source[start:end])
                reparsed = subprocess.run(
                    ['ast-grep', 'scan', '--inline-rules', owner_rule, '--json=stream', '--stdin'],
                    input=source.decode(), capture_output=True, text=True, check=False)
                if reparsed.returncode not in (0, 1):
                    raise RuntimeError(f'ast-grep failed to resolve classes in {file}: {reparsed.stderr.strip()}')
                owners.extend({**json.loads(line), 'file': file} for line in reparsed.stdout.splitlines())
        metadata = {}
        for file in {row['file'] for row in matches if row['ruleId'] == 'fn'}:
            source = strip_comments_and_strings(Path(file).read_text())
            package = re.search(r'(?m)^\s*package\s+([\w.]+)', source)
            imports = re.findall(r'(?m)^\s*import\s+(?:static\s+)?(\w+(?:\.\w+)*(?:\.\*)?)(?:\s+as\s+(\w+))?', source)
            metadata[file] = (package.group(1) if package else '', tuple(imports))
        for match in matches:
            if match['ruleId'] != 'fn' or not (parts := split(match['text'])):
                continue
            file = str(Path(match['file']).resolve().relative_to(root.resolve()))
            enclosing = [owner for owner in owners if owner['file'] == match['file'] and
                         owner['range']['byteOffset']['start'] <= match['range']['byteOffset']['start'] and
                         owner['range']['byteOffset']['end'] >= match['range']['byteOffset']['end']]
            if enclosing:
                owner = min(enclosing, key=lambda row: len(row['text']))
                owner_text = strip_comments_and_strings(owner['text'])
                owner_name = re.search(r'\b(?:class|object|interface)\s+(\w+)', owner_text)
                if owner_name is None:
                    raise RuntimeError(f'Cannot resolve the test class in {file}')
                name = owner_name.group(1)
                header = owner_text[owner_name.end():].split('{', 1)[0]
                while (cleaned := re.sub(r'\([^()]*\)|<[^<>]*>', '', header)) != header:
                    header = cleaned
                inheritance = re.split(r':|\bextends\b|\bimplements\b', header, maxsplit=1)
                parents = tuple(token.rsplit('.', 1)[-1] for token in
                                re.findall(r'[A-Za-z_]\w*(?:\.\w+)*', inheritance[1])) if len(inheritance) > 1 else ()
                scope = f"{file}:{owner['range']['byteOffset']['start']}"
            else:
                scope, name, parents = file, '', ()
            found.append(Function(file, scope, name, parents, *metadata[match['file']], *parts))
    return found


def bare_calls(body: str) -> set[str]:
    return {(reference or call).strip('`') for reference, call in BARE_CALL.findall(body)}


def split(text: str) -> tuple[str, str, str] | None:
    """(name, annotations and modifiers before the name, body after the signature) of one declaration."""
    cleaned = strip_comments_and_strings(text)
    signature = KOTLIN_NAME.search(cleaned) or JAVA_NAME.search(cleaned)
    if not signature:
        return None
    return signature.group(1).strip('`'), cleaned[:signature.start()], cleaned[signature.end():]


def offenders(functions: list[Function]) -> list[str]:
    """Resolve helpers through their class, ancestry, package and imports, never an unrelated class."""
    by_key = {}
    classes = {}
    top_level = {}
    for index, function in enumerate(functions):
        by_key.setdefault((function.scope, function.name), set()).add(index)
        if function.owner:
            classes.setdefault(function.owner, set()).add(function.scope)
        elif not re.search(r'\bprivate\b', function.prefix):
            top_level.setdefault((function.package, function.name), set()).add(index)

    def targets(function, name):
        pending, visited = [function.scope], set()
        while pending:
            scope = pending.pop()
            if scope in visited:
                continue
            visited.add(scope)
            if key := by_key.get((scope, name)):
                return key
            parent_names = next((row.parents for row in functions if row.scope == scope), ())
            for parent in parent_names:
                scopes = classes.get(parent, set())
                if len(scopes) == 1:
                    pending.extend(scopes)
        if local := by_key.get((function.file, name)):
            return local
        result = top_level.get((function.package, name), set()).copy()
        for qualified, alias in function.imports:
            package, _, imported = qualified.rpartition('.')
            if imported == '*':
                result.update(top_level.get((package, name), set()))
            elif (alias or imported) == name:
                result.update(top_level.get((package, imported), set()))
        return result

    direct = {index for index, function in enumerate(functions)
              if any(ASSERTION.fullmatch(call or reference) for call, reference in CALL.findall(function.body))}
    calls = [{tuple(sorted(targets(function, name))) for name in bare_calls(function.body)} for function in functions]
    asserting = set(direct)
    changed = True
    while changed:  # a helper that calls an asserting helper asserts too
        changed = False
        for index, candidates in enumerate(calls):
            if index not in asserting and any(target and set(target) <= asserting for target in candidates):
                asserting.add(index)
                changed = True
    bad: list[str] = []
    for index, function in sorted(enumerate(functions), key=lambda pair: (pair[1].file, pair[1].name)):
        annotation = TEST_ANNOTATION.search(function.prefix)
        if not annotation or (annotation.group(2) and 'expected' in annotation.group(2)):
            continue
        if index not in asserting:
            bad.append(f'{function.file}: @Test {function.name} asserts nothing (no assertion and no asserting helper)')
    return bad


def main() -> int:
    root = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else ROOT
    problems = offenders(declarations(root, TEST_TREES))
    for problem in problems:
        print(f'[fail] {problem}', file=sys.stderr)
    if problems:
        print(f'{len(problems)} test(s) assert nothing: assert the observable result.', file=sys.stderr)
        return 1
    print('[ok] every JVM @Test asserts something')
    return 0


if __name__ == '__main__':
    sys.exit(main())
