"""Derive operator overrides from the shipped readers, excluding internally supplied values."""

import ast
from pathlib import Path
import re


# Compose variables the bundle supplies itself rather than reading from .env: ./chronicle and
# release_command export the first three on every Compose call (CHRONICLE_ALERT_EGRESS is derived
# from CHRONICLE_ALERT_WEBHOOK_URL by chronicle_ops/egress.py); the rest come from images or
# one-off commands. verify-config.sh exempts exactly these from the .env.example inventory.
COMPOSE_SUPPLIED = frozenset({'CHRONICLE_HOST_UID', 'CHRONICLE_HOST_GID', 'CHRONICLE_ALERT_EGRESS',
                              'CHRONICLE_SERVER_ARGS', 'HEALTHCHECK_PORT', 'RESTORE_FILE'})


def undocumented_runtime_settings(root, documented):
    root = Path(root)
    # The shell/runtime owns these process conventions, rather than deployment settings.
    supplied = {'PATH', 'HOME', 'TMPDIR', 'XDG_CACHE_HOME'}
    for path in [root / 'docker-compose.yml', *root.glob('overlays/*.yml')]:
        supplied.update(re.findall(r'^\s{6}([A-Z][A-Z0-9_]*):', path.read_text(), re.MULTILINE))
    shell_readers, python_readers, exported_values, python_assigned = set(), set(), set(), set()
    for path in [root / 'chronicle', *root.glob('*.sh'), *root.glob('monitoring/**/*.sh')]:
        text = '\n'.join(line for line in path.read_text().splitlines() if not line.lstrip().startswith('#'))
        fallbacks = list(re.finditer(r'\$\{([A-Z][A-Z0-9_]*):[-=+?]', text))
        first_read: dict[str, int] = {}
        for fallback in fallbacks:
            first_read.setdefault(fallback[1], fallback.start())
        local = set()
        for assignment in re.finditer(r'^\s*(export\s+)?([A-Z][A-Z0-9_]*)=(.*)$', text, re.MULTILINE):
            exported, key, expression = assignment.groups()
            if not re.search(r'\$(?:\{' + key + r'\b|' + key + r'\b)', expression):
                if assignment.start() < first_read.get(key, len(text)):
                    local.add(key)
                if exported:
                    exported_values.add(key)
        shell_readers.update({match[1] for match in fallbacks} - local - supplied - set(documented))
    trees = {path: ast.parse(path.read_text(), filename=str(path)) for path in root.glob('chronicle_ops/*.py')}
    def module_constants(tree):
        return {node.targets[0].id: node.value.value for node in tree.body
                if isinstance(node, ast.Assign) and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name) and isinstance(node.value, ast.Constant)
                and isinstance(node.value.value, str)}
    # A module may name another module's constant (from .verify import BASELINE_ENV).
    package_constants = {name: text for tree in trees.values() for name, text in module_constants(tree).items()}
    for path, tree in trees.items():
        constants = dict(package_constants, **module_constants(tree))
        for node in ast.walk(tree):
            argument = None
            if isinstance(node, ast.Call) and node.args and ast.unparse(node.func) in ('os.getenv', 'os.environ.get'):
                argument = node.args[0]
            elif isinstance(node, ast.Subscript) and isinstance(node.ctx, ast.Load) and ast.unparse(node.value) == 'os.environ':
                argument = node.slice
            if isinstance(argument, ast.Constant) and isinstance(argument.value, str):
                python_readers.add(argument.value)
            elif isinstance(argument, ast.Name) and argument.id in constants:
                python_readers.add(constants[argument.id])
            # A name the package itself assigns (os.environ[NAME] = ...) is handed from one of its
            # processes to another, like a shell export; it is not an operator setting.
            if (isinstance(node, ast.Subscript) and isinstance(node.ctx, ast.Store)
                    and ast.unparse(node.value) == 'os.environ'):
                if isinstance(node.slice, ast.Constant) and isinstance(node.slice.value, str):
                    python_assigned.add(node.slice.value)
                elif isinstance(node.slice, ast.Name) and node.slice.id in constants:
                    python_assigned.add(constants[node.slice.id])
    return sorted(shell_readers | (python_readers - supplied - exported_values - python_assigned - set(documented)))


RELEASE_FETCHER = 'chronicle_ops/update.py'
# Host-side connections off the host, which must take the operator's proxy as the release
# download does: the download itself and `update --check`'s probe of the host destinations.
PROXY_USERS = frozenset({RELEASE_FETCHER, 'chronicle_ops/egress.py'})


def proxy_violations(root):
    """Every curl the package builds must pass --noproxy (a proxy must never answer for this
    deployment), except the release fetcher in update.py and the destination probe in egress.py,
    which must honour HTTPS_PROXY."""
    root = Path(root)
    violations, fetches = [], 0
    for path in sorted(root.glob('chronicle_ops/*.py')):
        relative = path.relative_to(root).as_posix()
        for node in ast.walk(ast.parse(path.read_text(), filename=str(path))):
            if not (isinstance(node, ast.List) and node.elts and isinstance(node.elts[0], ast.Constant)
                    and node.elts[0].value == 'curl'):
                continue
            bypass = any(isinstance(item, ast.Constant) and item.value == '--noproxy' for item in node.elts)
            if relative in PROXY_USERS:
                fetches += relative == RELEASE_FETCHER
                if bypass:
                    violations.append(f'{relative}:{node.lineno} connections off the host ignore HTTPS_PROXY')
            elif not bypass:
                violations.append(f'{relative}:{node.lineno} probes the deployment through the proxy')
    if not fetches:
        violations.append(f'{RELEASE_FETCHER} has no release download')
    return violations
