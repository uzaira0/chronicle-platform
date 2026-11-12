#!/usr/bin/env python3
"""Require every browser, load, parser and script test, and every tests/security script, to have an executable gate owner."""

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


# Probes of a deployed host. Each needs the named services running on the machine it is started on,
# so no job in scripts/local-ci.sh can own it; a person runs it on that host. Every other script
# directly under tests/security needs a runner. An entry leaves this table when its probe gets a
# job (security_script_coverage reports an entry that has a runner) or is removed
# (tests/quality/test_test_entrypoints.py requires every entry's file).
HOST_PROBES = {
    'api-header-tests.sh': 'a deployed backend (BACKEND_URL) and its JWT signing key',
    'backup-dr-test.sh': 'the Traefik deployment: chronicle-postgres and /opt/chronicle/docker/backup-chronicle.sh',
    'database-security-tests.sh': 'the Traefik deployment: a running chronicle-postgres',
    'ir-drill-checklist.sh': 'an installed self-host stack',
    'test-fail2ban.sh': 'a host with the chronicle-fail2ban container',
    'test-falco.sh': 'a host with the chronicle-falco container',
    'test-vault.sh': 'the Traefik deployment: a running chronicle-vault',
}
RUNNER_ROOTS = ('scripts/local-ci.sh', 'lefthook.yml', 'tests/smoke/selfhost-release-smoke.sh')
SCRIPT_PATH = re.compile(r'[A-Za-z0-9_./*$\{}"-]*[A-Za-z0-9_*-]\.(?:sh|py|ts)\b')
LOOP = re.compile(r'\bfor\s+(\w+)\s+in\s+((?:[^;\n]|\\\n)*?)\s*(?:;|\n)\s*do\b')
IMPORTED = re.compile(r'''import_module\(\s*['"]([\w.-]+)['"]|^\s*(?:import|from)\s+([\w.]+)''', re.M)


def started_by(runner, root):
    """What a runner can start: repository paths and bare file names, and imported module names.

    Comment lines do not count. In a shell runner a `for ... in` list also counts: its words with
    the directory and suffix the loop body adds ("$ROOT_DIR/tests/security/$suite.sh"), and its
    path globs. A Python or TypeScript file counts as starting the scripts it names only when it
    starts processes at all (subprocess, spawn); a test that only reads a script's text does not."""
    text = '\n'.join(line for line in runner.read_text(errors='replace').splitlines()
                     if not line.lstrip().startswith(('#', '//')))

    def relative(word):
        word = word.replace('"', '').replace("'", '')
        for prefix in ('${ROOT_DIR}/', '$ROOT_DIR/', '${PROJECT_ROOT}/', '$PROJECT_ROOT/', str(root) + '/'):
            word = word.replace(prefix, '')
        return word.removeprefix('./')

    modules = {(first or second).rsplit('.', 1)[-1] for first, second in IMPORTED.findall(text)}
    if runner.suffix in ('.py', '.ts'):
        starts = re.search(r'\bsubprocess\b|\bspawn(?:Sync)?\b|\bexecFileSync\b', text)
        return ({relative(match[0]) for match in SCRIPT_PATH.finditer(text) if '*' not in match[0]} if starts else set()), modules
    paths = {relative(match[0]) for match in SCRIPT_PATH.finditer(text) if '*' not in match[0]}
    for variable, listed in LOOP.findall(text):
        words = listed.replace('\\\n', ' ').split()
        for directory, suffix in re.findall(r'([A-Za-z0-9_./$\{}"-]*/)\$\{?' + variable + r'\}?(\.(?:sh|py))', text):
            paths.update(relative(directory) + word.strip('"\'') + suffix for word in words if '/' not in word and '$' not in word)
        paths.update(relative(word) for word in words if '*' in word and '/' in word)
    return paths, modules


def security_script_coverage(root):
    """Scripts directly under tests/security that nothing a gate runs can start.

    A runner is scripts/local-ci.sh, lefthook.yml, the release smoke test or a test file (whose own
    gate script_test_coverage requires); a script a runner can start (started_by) is a runner of
    what it starts. A file named only by documentation, a Makefile or a deployment playbook has no
    gate. A bare file name counts for every file of that name."""
    directory = root / 'tests/security'
    candidates = {path for pattern in ('*.sh', '*.py') for path in directory.glob(pattern)
                  if not path.name.startswith('test_')}
    pool = {path for top in ('scripts', 'tests', 'selfhost') for path in (root / top).rglob('*')
            if path.suffix in ('.sh', '.py', '.ts') and path.is_file()
            and not {'fixtures', 'node_modules', '__pycache__'} & set(path.relative_to(root).parts)}
    runners = {root / name for name in RUNNER_ROOTS if (root / name).is_file()}
    runners |= {path for path in pool if (path.suffix == '.py' and path.name.startswith('test'))
                or path.name.endswith('.test.ts')}
    pending = list(runners)
    while pending:
        runner = pending.pop()
        paths, modules = started_by(runner, root)
        names = {Path(word).name for word in paths if '*' not in word}
        if runner.resolve() == Path(__file__).resolve():
            names -= set(HOST_PROBES)  # this file lists them; it does not start them
        globs = [word for word in paths if '*' in word]
        for path in pool - runners:
            name = path.relative_to(root).as_posix()
            if (path.name in names
                    or any(Path(glob).parent.as_posix() == Path(name).parent.as_posix()
                           and fnmatch.fnmatchcase(path.name, Path(glob).name) for glob in globs)
                    or (path.suffix == '.py' and (path.stem in modules or path.stem.replace('-', '_') in modules))):
                runners.add(path)
                pending.append(path)
    unowned = {path for path in candidates - runners if path.name not in HOST_PROBES}
    return unowned | {directory / name for name in HOST_PROBES if directory / name in runners}


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
    missing.update(security_script_coverage(root))
    return missing


if __name__ == '__main__':
    try:
        missing = coverage(ROOT)
        if missing:
            sys.exit('Suites without a gate: ' + ', '.join(str(path.relative_to(ROOT)) for path in sorted(missing)))
    except (ValueError, RuntimeError, OSError) as error:
        sys.exit(str(error))
    print('Every browser, load, parser and script test and every tests/security script is owned by a runnable gate')
