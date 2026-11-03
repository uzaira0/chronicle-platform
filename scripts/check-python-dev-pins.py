#!/usr/bin/env python3
"""Hold the Python tooling to requirements-dev.txt.

scripts/ and tests/ import two third-party packages (PyYAML, openpyxl). Generated contracts and gate
results depend on their versions, so the lock pins each one with hashes and this check fails when:

- an entry in requirements-dev.txt is not `name==version` with at least one --hash;
- the python3 that runs the gate has a different version installed, or none;
- a tracked .py file imports a third-party module the lock does not pin.

Run by scripts/verify-toolchain.sh. Stdlib only, so it runs before the pins are installed.
"""

from __future__ import annotations

import ast
import pkgutil
import re
import subprocess
import sys
import sysconfig
from collections.abc import Callable, Iterable
from importlib import metadata
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LOCK_FILE = 'requirements-dev.txt'
INSTALL_HINT = ('uv pip install --system --break-system-packages --python "$(command -v python3)" '
                '--require-hashes -r requirements-dev.txt')
# Import name -> distribution name where they differ.
IMPORT_DISTRIBUTION = {'yaml': 'pyyaml'}
REQUIREMENT = re.compile(r'^([A-Za-z0-9][A-Za-z0-9._-]*)==([^\s\\;]+)')


def normalize(name: str) -> str:
    return re.sub(r'[-_.]+', '-', name).lower()


def parse_lock(text: str) -> dict[str, tuple[str, int]]:
    """{distribution: (version, hash count)}; every entry must be an exact pin with a hash."""
    entries: dict[str, tuple[str, int]] = {}
    current: str | None = None
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith('#'):
            continue
        if raw[0].isspace():
            if current is not None and line.startswith('--hash='):
                version, hashes = entries[current]
                entries[current] = (version, hashes + 1)
            continue
        requirement = line.rstrip('\\').strip()
        match = REQUIREMENT.match(requirement)
        if not match:
            raise ValueError(f'{LOCK_FILE}: {requirement} is not an exact name==version pin')
        current = normalize(match.group(1))
        entries[current] = (match.group(2), 0)
    unhashed = sorted(name for name, (_, hashes) in entries.items() if hashes == 0)
    if unhashed:
        raise ValueError(f'{LOCK_FILE}: {", ".join(unhashed)} has no --hash; regenerate with --generate-hashes')
    return entries


def installed_version(distribution: str) -> str | None:
    try:
        return metadata.version(distribution)
    except metadata.PackageNotFoundError:
        return None


def version_problems(lock: dict[str, tuple[str, int]],
                     installed: Callable[[str], str | None] = installed_version) -> list[str]:
    problems = []
    for name, (pinned, _) in sorted(lock.items()):
        actual = installed(name)
        if actual is None:
            problems.append(f'{name} is not installed; {LOCK_FILE} pins {pinned} ({INSTALL_HINT})')
        elif actual != pinned:
            problems.append(f'{name} {actual} is installed, {LOCK_FILE} pins {pinned} ({INSTALL_HINT})')
    return problems


def tracked_python_files(root: Path) -> list[str]:
    listed = subprocess.run(['git', '-C', str(root), 'ls-files', '-z', '--', '*.py'],
                            capture_output=True, text=True, check=True).stdout
    return sorted(name for name in listed.split('\0') if name)


def _imports(source: str) -> Iterable[str]:
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            yield from (alias.name.split('.')[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            yield node.module.split('.')[0]


def stdlib_modules() -> set[str]:
    names = getattr(sys, 'stdlib_module_names', None)
    if names is not None:
        return set(names)
    # Python 3.9 has no stdlib_module_names; inspect only its library directories, never site-packages.
    paths = {sysconfig.get_path('stdlib'), sysconfig.get_config_var('DESTSHARED')} - {None}
    return set(sys.builtin_module_names) | {module.name for module in pkgutil.iter_modules(sorted(paths))}


def unpinned_imports(root: Path, files: list[str], pinned: set[str]) -> dict[str, list[str]]:
    """{import name: files} for third-party imports whose distribution the lock does not pin."""
    local = {Path(name).stem for name in files} | {part for name in files for part in Path(name).parts[:-1]}
    stdlib = stdlib_modules() | {'__future__'}
    pinned = {normalize(name) for name in pinned}
    found: dict[str, set[str]] = {}
    for name in files:
        for module in _imports((root / name).read_text(encoding='utf-8')):
            if module in stdlib or module in local:
                continue
            if normalize(IMPORT_DISTRIBUTION.get(module, module)) not in pinned:
                found.setdefault(module, set()).add(name)
    return {module: sorted(names) for module, names in sorted(found.items())}


def main() -> int:
    try:
        lock = parse_lock((ROOT / LOCK_FILE).read_text(encoding='utf-8'))
    except (OSError, ValueError) as error:
        print(f'[fail] {error}', file=sys.stderr)
        return 1
    problems = version_problems(lock)
    for module, names in unpinned_imports(ROOT, tracked_python_files(ROOT), set(lock)).items():
        problems.append(f'{module} is imported by {", ".join(names)} but {LOCK_FILE} does not pin it')
    for problem in problems:
        print(f'[fail] {problem}', file=sys.stderr)
    if not problems:
        print(f'[ok] python tooling matches {LOCK_FILE}: '
              + ', '.join(f'{name} {version}' for name, (version, _) in sorted(lock.items())))
    return 1 if problems else 0


if __name__ == '__main__':
    sys.exit(main())
