"""Derive operator overrides from the shipped readers, excluding internally supplied values."""

import ast
from pathlib import Path
import re


def undocumented_runtime_settings(root, documented):
    root = Path(root)
    # The shell/runtime owns these process conventions, rather than deployment settings.
    supplied = {'PATH', 'HOME', 'TMPDIR'}
    for path in [root / 'docker-compose.yml', *root.glob('overlays/*.yml')]:
        supplied.update(re.findall(r'^\s{6}([A-Z][A-Z0-9_]*):', path.read_text(), re.MULTILINE))
    shell_readers, python_readers, exported_values = set(), set(), set()
    for path in [root / 'chronicle', *root.glob('*.sh'), *root.glob('monitoring/**/*.sh')]:
        text = '\n'.join(line for line in path.read_text().splitlines() if not line.lstrip().startswith('#'))
        fallbacks = list(re.finditer(r'\$\{([A-Z][A-Z0-9_]*):[-=+?]', text))
        first_read = {}
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
    for path in root.glob('chronicle_ops/*.py'):
        tree = ast.parse(path.read_text(), filename=str(path))
        constants = {node.targets[0].id: node.value.value for node in tree.body
                     if isinstance(node, ast.Assign) and len(node.targets) == 1
                     and isinstance(node.targets[0], ast.Name) and isinstance(node.value, ast.Constant)
                     and isinstance(node.value.value, str)}
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
    return sorted(shell_readers | (python_readers - supplied - exported_values - set(documented)))
