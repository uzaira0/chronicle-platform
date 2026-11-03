#!/usr/bin/env python3
"""Check the licenses of chronicle-web's installed production packages against the allowlist.

Input is a Syft JSON catalog of a `bun install --production` node_modules tree
(scripts/check-frontend-licenses.sh builds it), so bun decides which packages ship and Syft
reads each package's declared license. The check fails closed: a package with no declared
license, a production dependency missing from the catalog, or an empty catalog is refused.

    frontend_license_policy.py CATALOG.json PACKAGE.json ALLOWED   (ALLOWED: SPDX ids, ';'-separated)
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

TOKEN = re.compile(r'\(|\)|[^\s()]+')


class LicenseExpressionError(ValueError):
    pass


def permitted(expression: str, allowed: frozenset[str]) -> bool:
    """Evaluate an SPDX license expression: OR needs one allowed operand, AND needs all of them.

    `X WITH exception` is allowed only when the whole `X WITH exception` term is listed.
    """
    tokens = TOKEN.findall(expression)
    position = 0

    def peek() -> str | None:
        return tokens[position] if position < len(tokens) else None

    def take() -> str:
        nonlocal position
        if position >= len(tokens):
            raise LicenseExpressionError(f'incomplete license expression: {expression!r}')
        position += 1
        return tokens[position - 1]

    def term() -> bool:
        token = take()
        if token == '(':
            value = disjunction()
            if take() != ')':
                raise LicenseExpressionError(f'unbalanced license expression: {expression!r}')
            return value
        if token.upper() in ('AND', 'OR', 'WITH', ')'):
            raise LicenseExpressionError(f'malformed license expression: {expression!r}')
        if (peek() or '').upper() == 'WITH':
            take()
            exception = take()
            if exception.upper() in ('AND', 'OR', 'WITH', '(', ')'):
                raise LicenseExpressionError(f'malformed license exception: {expression!r}')
            token = f'{token} WITH {exception}'
        return token in allowed

    def conjunction() -> bool:
        value = term()
        while (peek() or '').upper() == 'AND':
            take()
            value = term() and value
        return value

    def disjunction() -> bool:
        value = conjunction()
        while (peek() or '').upper() == 'OR':
            take()
            value = conjunction() or value
        return value

    if not tokens:
        raise LicenseExpressionError('empty license expression')
    result = disjunction()
    if position != len(tokens):
        raise LicenseExpressionError(f'trailing tokens in license expression: {expression!r}')
    return result


def violations(catalog: dict, package: dict, allowed: frozenset[str]) -> list[str]:
    artifacts = [a for a in catalog.get('artifacts', []) if a.get('type') == 'npm']
    if not artifacts:
        return ['the catalog lists no installed npm package; the production install or the Syft scan failed']
    problems = []
    for artifact in sorted(artifacts, key=lambda a: (a['name'], a.get('version', ''))):
        ident = f"{artifact['name']}@{artifact.get('version', '?')}"
        licenses = artifact.get('licenses') or []
        if not licenses:
            problems.append(f'{ident}: declares no license')
            continue
        for entry in licenses:
            expression = entry.get('spdxExpression') or entry.get('value') or ''
            try:
                if not permitted(expression, allowed):
                    problems.append(f'{ident}: {expression}')
            except LicenseExpressionError as error:
                problems.append(f'{ident}: {error}')
    catalogued = {a['name'] for a in artifacts}
    for name in sorted(package.get('dependencies', {})):
        if name not in catalogued:
            problems.append(f'{name}: production dependency missing from the catalog')
    return problems


def main(argv: list[str]) -> int:
    if len(argv) != 4:
        print(__doc__, file=sys.stderr)
        return 2
    catalog = json.loads(Path(argv[1]).read_text())
    package = json.loads(Path(argv[2]).read_text())
    allowed = frozenset(item for item in argv[3].split(';') if item)
    problems = violations(catalog, package, allowed)
    for problem in problems:
        print(f'  {problem}')
    installed = sum(1 for a in catalog.get('artifacts', []) if a.get('type') == 'npm')
    print(f'{installed} installed production package(s) checked, {len(problems)} refused')
    return 1 if problems else 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
