#!/usr/bin/env python3
"""Inventory Bash security layers reachable from CI groups or the release smoke."""

import json
from pathlib import Path
import re
import shlex
import subprocess
import sys

GATE_GROUPS = ('fast', 'security', 'containers')


def shell_nodes(path, kinds=('function_definition', 'command', 'for_statement',
                             'variable_assignment', 'case_item')):
    rule = {'id': 'inventory', 'language': 'Bash', 'rule': {'any': [
        {'kind': kind} for kind in kinds]}}
    result = subprocess.run(['ast-grep', 'scan', '--inline-rules', json.dumps(rule),
                             '--json=compact', str(path)], text=True, capture_output=True, timeout=30)
    if result.returncode not in (0, 1):
        raise ValueError(result.stderr)
    return json.loads(result.stdout)


def function_inventory(nodes):
    return {match[1]: node for node in nodes
            if (match := re.match(r'(\w+)\s*\(\)\s*[{(]', node['text']))}


def contains(function, node):
    outer, inner = function['range']['byteOffset'], node['range']['byteOffset']
    return outer['start'] < inner['start'] and inner['end'] < outer['end']


def gate_jobs(nodes):
    groups = {}
    for node in nodes:
        assignment = re.fullmatch(r'(\w+)_jobs=\((.*)\)', node['text'], re.S)
        if assignment and assignment[1] in GATE_GROUPS:
            groups[assignment[1]] = shlex.split(assignment[2].replace('\\\n', ''), comments=True)
    if set(groups) != set(GATE_GROUPS):
        raise ValueError('missing local CI gate group arrays')
    return {job for jobs in groups.values() for job in jobs}


def dispatched_jobs(nodes, functions):
    dispatch = functions.get('dispatch_job')
    if not dispatch:
        raise ValueError('missing local CI dispatch')
    jobs = {}
    for node in nodes:
        labels = re.match(r'([\w|_-]+)\)', node['text'])
        if labels and contains(dispatch, node):
            calls = {match[1] for member in nodes if contains(node, member)
                     if (match := re.match(r'(\w+)(?:\s|$)', member['text'])) and match[1] in functions}
            for label in labels[1].split('|'):
                jobs[label] = calls
    return jobs


def call_graph(nodes, jobs):
    functions = function_inventory(nodes)
    functions[None] = None  # Executed statements outside function definitions.
    edges = {name: set() for name in functions}
    owned = {name: set() for name in functions}
    for name, function in functions.items():
        members = [node for node in nodes if contains(function, node)] if function else [
            node for node in nodes if not any(outer and (outer == node or contains(outer, node))
                                             for outer in functions.values())]
        bindings = {}
        for node in members:
            loop = re.match(r'for\s+(\w+)\s+in\s+(.*?)\s*;?\s*do\b', node['text'], re.S)
            if loop:
                bindings[loop[1]] = shlex.split(loop[2].replace('\\\n', '').rstrip(';'))
        for node in members:
            statement = node['text'].replace('\\\n', '')
            command = re.match(r'(?:\w+=\S+\s+)*(\w+)(?:\s|$)', statement)
            if not command:
                continue
            called = command[1]
            if called == 'run_job':
                arguments = shlex.split(statement)
                if len(arguments) == 2 and '$' not in arguments[1]:
                    edges[name].update(jobs.get(arguments[1], set()))
            elif called in functions:
                edges[name].add(called)
            if called != 'bash' or 'run-all-security.sh' not in node['text']:
                continue
            arguments = shlex.split(statement)
            while re.match(r'\w+=', arguments[0]):
                arguments.pop(0)
            layer = arguments[2]
            if layer.startswith('$'):
                variable = layer.removeprefix('$').strip('{}')
                if variable not in bindings:
                    raise ValueError(f'{name}: cannot resolve security layer {layer}')
                owned[name].update(bindings[variable])
            else:
                owned[name].add(layer)
    return edges, owned


def reachable_layers(edges, owned, entry_points):
    pending, visited, reached = list(entry_points), set(), set()
    while pending:
        name = pending.pop()
        if name in visited:
            continue
        visited.add(name)
        reached.update(owned.get(name, set()))
        pending.extend(edges.get(name, set()))
    return reached


def coverage(runner, local_ci, release_smoke):
    layer_nodes, ci_nodes, smoke_nodes = shell_nodes(runner), shell_nodes(local_ci), shell_nodes(release_smoke)
    layers = {name.removeprefix('run_security_layer_').replace('_', '-')
              for name in function_inventory(layer_nodes) if name.startswith('run_security_layer_')}
    jobs = dispatched_jobs(ci_nodes, function_inventory(ci_nodes))
    entry_points = set()
    for job in gate_jobs(ci_nodes):
        if job not in jobs:
            raise ValueError(f'gate job is not dispatched: {job}')
        entry_points.update(jobs[job])
    reached = reachable_layers(*call_graph(ci_nodes, jobs), entry_points)
    reached.update(reachable_layers(*call_graph(smoke_nodes, {}), [None]))
    if not layers:
        raise ValueError('missing security layer definitions')
    return layers - reached, reached - layers


if __name__ == '__main__':
    root = Path(__file__).resolve().parents[2]
    paths = [Path(value) for value in sys.argv[1:]] or [
        root / 'tests/security/run-all-security.sh', root / 'scripts/local-ci.sh',
        root / 'tests/smoke/selfhost-release-smoke.sh']
    try:
        missing, unknown = coverage(*paths)
    except (ValueError, OSError) as error:
        sys.exit(str(error))
    if missing or unknown:
        sys.exit(f'unreachable security layers: {sorted(missing)}; unknown layers: {sorted(unknown)}')
    print('Every security layer is reachable from a local CI gate group or the release smoke')
