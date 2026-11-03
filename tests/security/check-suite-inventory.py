#!/usr/bin/env python3
"""Require every browser, load, parser and script test to have an executable gate owner."""

import fnmatch
import importlib
import json
from pathlib import Path
import re
import shlex
import sys
import subprocess

layers = importlib.import_module("check-security-layer-coverage")
ROOT = Path(__file__).resolve().parents[2]


def reachable_commands(path, entry_points, jobs):
    nodes = layers.shell_nodes(path)
    functions = layers.function_inventory(nodes)
    edges, _ = layers.call_graph(nodes, jobs)
    reached = layers.reachable_layers(edges, {name: {name} for name in edges}, entry_points)
    statements = layers.shell_nodes(path, ('command', 'for_statement'))
    return [node for node in statements if
            any(name in reached and layers.contains(function, node) for name, function in functions.items()) or
            None in reached and not any(layers.contains(function, node) for function in functions.values())]


def gate_commands(root):
    ci = root / 'scripts/local-ci.sh'
    nodes = layers.shell_nodes(ci)
    jobs = layers.dispatched_jobs(nodes, layers.function_inventory(nodes))
    selected = layers.gate_jobs(nodes)
    for node in nodes:
        match = re.fullmatch(r'all_jobs=\((.*?)\)', node['text'], re.S)
        if match:
            selected.update(job for job in shlex.split(match[1]) if job in jobs)
    release = root / 'tests/smoke/selfhost-release-smoke.sh'
    commands = reachable_commands(release, [None], {})
    for node in commands:
        if '/scripts/local-ci.sh' not in node['text']:
            continue
        args = shlex.split(node['text'].replace('\\\n', '').splitlines()[0])
        for index, arg in enumerate(args[:-1]):
            if arg.endswith('/scripts/local-ci.sh'):
                selected.add(args[index + 1])
    if selected - jobs.keys():
        raise ValueError(f'undispatched suite gates: {sorted(selected - jobs.keys())}')
    entries = {function for job in selected for function in jobs[job]}
    return commands + reachable_commands(ci, entries, jobs)


def script_invocations(root):
    pending, visited, commands = gate_commands(root), set(), []
    while pending:
        node = pending.pop()
        statement = node['text'].replace('\\\n', '')
        commands.append(node)
        invocation = statement.splitlines()[0]
        if '.sh' not in invocation or statement.startswith('for '):
            continue
        for arg in shlex.split(invocation):
            resolved = arg.replace('${ROOT_DIR}', str(root)).replace('$ROOT_DIR', str(root))
            path = Path(resolved)
            if path.suffix == '.sh' and path.is_file() and path not in visited:
                visited.add(path)
                pending.extend(reachable_commands(path, [None], {}))
    return commands


def listed_specs(root, selfhost):
    environment = {'CHRONICLE_E2E_SELFHOST': '1', 'CHRONICLE_PROXY_BASE_URL': 'https://127.0.0.1:1',
                   'CHRONICLE_E2E_PUBLIC_BASE_URL': 'https://127.0.0.1:2',
                   'CHRONICLE_E2E_DASHBOARD_PASSWORD': 'inventory-only'} if selfhost else {'CHRONICLE_E2E_SELFHOST': '0'}
    argv = ['env', *(f'{key}={value}' for key, value in environment.items()), 'bunx', 'playwright',
            'test', '--list', '--reporter=json', '--project=desktop-chromium']
    document = json.loads(subprocess.run(argv, cwd=root / 'chronicle-web', text=True,
                                        capture_output=True, timeout=300, check=True).stdout)
    def files(suites):
        return {suite['file'] for suite in suites if suite.get('file')} | {
            file for suite in suites for file in files(suite.get('suites', []))}
    return {root / 'chronicle-web/e2e' / file for file in files(document['suites'])}


def k6_modules(root):
    paths = {path.resolve() for directory in ('tests/load', 'tests/security')
             for path in (root / directory).rglob('*')
             if path.suffix in ('.js', '.mjs', '.cjs')}
    modules = json.loads(subprocess.run(['bun', str(Path(__file__).with_name('javascript-imports.ts')),
                                         *map(str, sorted(paths))], cwd=root, text=True,
                                        capture_output=True, timeout=300, check=True).stdout) if paths else []
    graph, direct = {path: set() for path in paths}, set()
    for module in modules:
        owner = Path(module['path']).resolve()
        for source in module['imports']:
            if source == 'k6' or source.startswith('k6/'):
                direct.add(owner)
            elif source.startswith('.'):
                dependency = (owner.parent / source).resolve()
                if dependency.suffix in ('.js', '.mjs', '.cjs'):
                    if dependency not in paths:
                        raise ValueError(f'Declare external suite module in the inventory: {dependency}')
                    graph[owner].add(dependency)
    return graph, direct


def k6_arguments(command):
    invocation = command.splitlines()[0]
    if not re.match(r'^(?:\w+=\S+\s+)*(?:k6|env|run_security_step)\b', invocation):
        return []
    args = shlex.split(invocation)
    if args[0] == 'run_security_step':
        args = args[args.index('--') + 1:] if '--' in args else []
    if args and args[0] == 'env':
        args.pop(0)
    while args and re.match(r'\w+=', args[0]):
        args.pop(0)
    return args


def load_loop_suites(root, nodes):
    owned = set()
    for loop in nodes:
        binding = re.match(r'for\s+(\w+)\s+in\s+(.*?)(?:;|\n)\s*do\b', loop['text'].replace('\\\n', ''), re.S)
        if not binding:
            continue
        for command in nodes:
            if command['file'] != loop['file'] or not layers.contains(loop, command):
                continue
            args = k6_arguments(command['text'].replace('\\\n', ''))
            if args[:2] == ['k6', 'run'] and args[-1] in ('$' + binding[1], '${' + binding[1] + '}'):
                for word in shlex.split(binding[2]):
                    pattern = Path(word.replace('${ROOT_DIR}', str(root)).replace('$ROOT_DIR', str(root)))
                    if pattern.is_absolute() and pattern.parent.resolve() == (root / 'tests/load').resolve():
                        owned.update(path.resolve() for path in pattern.parent.glob(pattern.name) if path.is_file())
    return owned


def k6_coverage(root, commands, load_suites):
    graph, direct = k6_modules(root)
    reverse = {path: {source for source, targets in graph.items() if path in targets} for path in graph}
    identities = {path: {path} for path in graph}
    candidates = layers.reachable_layers(reverse, identities, direct) | {
        path.resolve() for path in (root / 'tests/load').glob('*.js')}
    owned = set(load_suites)
    for command in commands:
        args = k6_arguments(command)
        if args[:2] == ['k6', 'run'] and not args[-1].startswith('$'):
            owned.add((root / args[-1]).resolve())
        elif args[:2] == ['k6', 'run'] and '/' in args[-1]:
            owned.add(Path(args[-1].replace('${ROOT_DIR}', str(root)).replace('$ROOT_DIR', str(root))).resolve())
    return candidates - layers.reachable_layers(graph, identities, owned)


def parser_corpora(root, commands):
    required = (
        ('chronicle-web/src/modern/lib/study-config-file.ts',
         'chronicle-web/src/modern/lib/study-config-file.property.test.ts', r'\bfc\.property\s*\('),
        ('selfhost/chronicle_ops/restore.py', 'tests/selfhost-py/test_restore.py',
         r'\bdef test_mutated_archive_metadata_is_refused_before_any_service_or_database_change\s*\('),
    )
    missing = {root / source for source, corpus, declaration in required
               if (root / source).is_file() and
               (not (root / corpus).is_file() or not re.search(declaration, (root / corpus).read_text()))}
    fuzz = root / 'chronicle-server/src/test/kotlin/com/openlattice/chronicle/fuzz'
    if not any(re.match(r'^JAZZER_FUZZ=1\s+gradle\s', command) for command in commands):
        missing.update(fuzz.glob('*FuzzTest.kt'))
    return missing


def script_test_coverage(root, nodes):
    candidates = {path for directory in ("tests", "scripts", "chronicle/scripts")
                  for path in (root / directory).rglob("test*.py")
                  if "fixtures" not in path.relative_to(root).parts}
    candidates.update(path for directory in ("tests", "scripts", "chronicle-web/src/modern", "chronicle-web/scripts")
                      for path in (root / directory).rglob("*")
                      if path.name.endswith((".test.ts", ".test.tsx")) and "fixtures" not in path.relative_to(root).parts)
    candidates.update((root / "chronicle/scripts").glob("test*.gradle"))
    owned, sources = set(), {}

    def expand(value, cwd):
        value = value.replace("${ROOT_DIR}", str(root)).replace("$ROOT_DIR", str(root))
        value = value.replace("${WEB_DIR}", str(root / "chronicle-web")).replace("$WEB_DIR", str(root / "chronicle-web"))
        return (cwd / value).resolve()

    def cwd_for(node):
        if "cwd" in node:
            return Path(node["cwd"])
        path = Path(node["file"])
        if not path.is_file() or "range" not in node:
            return root
        if path not in sources:
            sources[path] = (layers.shell_nodes(path, ("subshell", "compound_statement", "function_definition")),
                             layers.shell_nodes(path, ("command",)))
        scopes, commands = sources[path]

        def scope(command):
            parents = [outer for outer in scopes if layers.contains(outer, command)]
            return min(parents, key=lambda outer: len(outer["text"])) if parents else None

        owner = scope(node)
        cwd = root
        for command in commands:
            if command["range"]["byteOffset"]["start"] >= node["range"]["byteOffset"]["start"]:
                continue
            if scope(command) != owner:
                continue
            if not re.match(r'^cd\s', command["text"]):
                continue
            args = shlex.split(command["text"].replace("\\\n", ""), comments=True)
            if args[:1] == ["cd"] and len(args) == 2:
                cwd = expand(args[1], cwd)
        return cwd

    for node in nodes:
        statement = node["text"].replace("\\\n", "")
        if re.match(r'^for\s+\w+\s+in\b', statement):
            continue
        args = shlex.split(statement, comments=True)
        if args[:1] == ["run_security_step"]:
            args = args[args.index("--") + 1:] if "--" in args else []
        if args[:1] == ["env"]:
            args.pop(0)
        while args and re.match(r"\w+=", args[0]):
            args.pop(0)
        if args[:2] == ["uv", "run"]:
            args = args[2:]
            while args and args[0].startswith("-"):
                if args[0] == "--no-project":
                    args = args[1:]
                elif args[0] in {"--python", "--with-requirements"}:
                    args = args[2:]
                else:
                    args = []
        if not args:
            continue
        command, cwd = Path(args[0]).name, cwd_for(node)
        python = bool(re.fullmatch(r"python(?:\d+(?:\.\d+)?)?", command)) or command in {
            "selfhost_python", "run_selfhost_python_suite"
        }
        if python:
            owned.update(expand(arg, cwd) for arg in args[1:] if arg.endswith(".py"))
            if "discover" in args and "-k" not in args:
                start = args[args.index("-s") + 1] if "-s" in args else "."
                pattern = args[args.index("-p") + 1] if "-p" in args else "test*.py"
                directory = expand(start, cwd)
                owned.update(path for path in directory.rglob("*.py") if fnmatch.fnmatchcase(path.name, pattern)
                             and all((parent / "__init__.py").is_file() for parent in path.parents
                                     if directory in parent.parents))
            elif command == "run_selfhost_python_suite":
                owned.update(root / "tests/selfhost-py" / (arg.split(".")[0] + ".py")
                             for arg in args[1:] if not arg.startswith("-"))
        elif command == "bun" and args[1:2] == ["test"]:
            targets = [arg for arg in args[2:] if not arg.startswith("-")] or ["."]
            for target in targets:
                path = expand(target, cwd)
                owned.update(candidate for candidate in candidates if candidate == path or path in candidate.parents)
        elif command in {"gradle", "gradlew"}:
            for index, arg in enumerate(args[:-1]):
                if arg not in {"-I", "--init-script"}:
                    continue
                path = expand(args[index + 1], cwd)
                if path not in candidates:
                    continue
                tasks = set(re.findall(r'\btasks\.register\s*\(\s*["\']([^"\']+)["\']', path.read_text()))
                if tasks and tasks.issubset({argument.rsplit(":", 1)[-1] for argument in args}):
                    owned.add(path)
    return candidates - owned


def coverage(root):
    nodes = script_invocations(root)
    commands = [node['text'].replace('\\\n', '') for node in nodes]
    browser_commands = [command for command in commands if
                        re.match(r'^(?:\w+=\S+\s+)*bunx playwright test', command)]
    default = any(not re.search(r'\.spec\.ts|--grep', command) for command in browser_commands)
    deployed = any('selfhost-journey.spec.ts' in command for command in browser_commands)
    reached = (listed_specs(root, False) if default else set()) | (listed_specs(root, True) if deployed else set())
    specs = set((root / 'chronicle-web/e2e').rglob('*.spec.ts'))
    missing = specs - reached
    # Own the actual selected files and their imported modules, rather than crediting every JS file.
    missing.update(k6_coverage(root, commands, load_loop_suites(root, nodes)))
    missing.update(parser_corpora(root, commands))
    missing.update(script_test_coverage(root, nodes))
    return missing


if __name__ == '__main__':
    try:
        missing = coverage(ROOT)
        if missing:
            sys.exit('Suites without a gate: ' + ', '.join(str(path.relative_to(ROOT)) for path in sorted(missing)))
    except (ValueError, RuntimeError, OSError) as error:
        sys.exit(str(error))
    print('Every browser, load, parser and script test is owned by a runnable gate')
