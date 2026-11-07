"""A fake `docker` executable for operator tests that start, wait on and inspect Compose services.

The shim records each invocation as one JSON line and answers the Compose subcommands the operator
uses: `config --services`, `up` (failing `--wait` while a listed service is unhealthy), `ps` with a
Go-style --format template, `run`, `stop` and `down`. Monitoring services appear in the
configuration only when overlays/monitoring.yml is among the selected files, and db-backup only
with overlays/backups.yml, as with real Compose. A `starting` service is still in its start period
(db-backup taking its first dump): `--wait` on it times out, and `ps` reports it running, starting.
Engine, containerd and runc versions answer `docker version --format` and `docker info --format`.
"""

import json
import os
from pathlib import Path
import sys

CORE = ['config-guard', 'cert-init', 'postgres', 'migrate', 'backend', 'web']
MONITORING = ['health-probe', 'monitoring-cert-init', 'monitoring-config', 'docker-socket-proxy', 'cadvisor',
              'operational-probe', 'metrics-exporter', 'victoriametrics', 'victorialogs', 'fluent-bit', 'grafana']
ONE_SHOT = {'config-guard', 'cert-init', 'migrate', 'health-probe', 'monitoring-cert-init', 'monitoring-config'}
MONITORING_OVERLAY = 'overlays/monitoring.yml'
BACKUPS = ['db-backup']
BACKUPS_OVERLAY = 'overlays/backups.yml'

SHIM = '''#!{python}
import sys
sys.path.insert(0, {tests!r})
from compose_shim import main
sys.exit(main(sys.argv[1:]))
'''


def install(directory, *, unhealthy=(), versions=None, starting=()):
    """Write `docker` into directory and return the environment entries that select it."""
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    docker = directory / 'docker'
    docker.write_text(SHIM.format(python=sys.executable, tests=str(Path(__file__).resolve().parent)))
    docker.chmod(0o755)
    scenario = directory / 'scenario.json'
    scenario.write_text(json.dumps({'unhealthy': list(unhealthy), 'versions': versions or {}, 'starting': list(starting)}))
    log = directory / 'docker.log'
    log.write_text('')
    return {'PATH': str(directory) + os.pathsep + os.environ['PATH'],
            'FAKE_DOCKER_SCENARIO': str(scenario), 'FAKE_DOCKER_LOG': str(log)}


def calls(environment):
    return [json.loads(line) for line in Path(environment['FAKE_DOCKER_LOG']).read_text().splitlines()]


def compose_calls(environment, verb):
    """Compose invocations of one subcommand, as (global options, subcommand arguments)."""
    found = []
    for args in calls(environment):
        if args[:1] != ['compose']:
            continue
        files, command = parse_compose(args[1:])
        if command[:1] == [verb]:
            found.append(command)
    return found


def parse_compose(args):
    files, index = [], 0
    while index < len(args):
        if args[index] in ('--env-file', '--project-name', '-p', '--profile', '--progress'):
            index += 2
        elif args[index] == '-f':
            files.append(args[index + 1])
            index += 2
        else:
            break
    return files, args[index:]


def selected_files(files):
    if files:
        return files
    selection = os.environ.get('COMPOSE_FILE')
    if selection is None and Path('.env').is_file():
        for line in Path('.env').read_text().splitlines():
            if line.startswith('COMPOSE_FILE='):
                selection = line.partition('=')[2].strip().strip("'\"")
    return [name for name in (selection or 'docker-compose.yml').split(':') if name]


def render(template, row):
    for key, text in row.items():
        template = template.replace('{{.' + key + '}}', text)
    return template.replace('\\t', '\t')


def main(args):
    scenario = json.loads(Path(os.environ['FAKE_DOCKER_SCENARIO']).read_text())
    with open(os.environ['FAKE_DOCKER_LOG'], 'a') as log:
        log.write(json.dumps(args) + '\n')
    versions = scenario['versions']
    if args[:1] in (['version'], ['info']) and '--format' in args:
        answer = versions.get(args[args.index('--format') + 1])
        if answer is None:
            return 1
        print(answer)
        return 0
    if args[:1] != ['compose']:
        return 0  # docker ps/inspect/rm for interrupted-recreate cleanup find nothing.
    files, command = parse_compose(args[1:])
    if command[:1] == ['version']:
        print(versions.get('compose', '2.30.0'))
        return 0
    selection = selected_files(files)
    monitoring = any(name == MONITORING_OVERLAY or name.endswith('/' + MONITORING_OVERLAY) for name in selection)
    backups = any(name == BACKUPS_OVERLAY or name.endswith('/' + BACKUPS_OVERLAY) for name in selection)
    configured = CORE + (BACKUPS if backups else []) + (MONITORING if monitoring else [])
    unhealthy = set(scenario['unhealthy'])
    starting = set(scenario.get('starting', ()))
    verb = command[0] if command else ''
    listed = [arg for arg in command[1:] if arg in configured]
    if verb == 'config':
        if '--services' in command:
            print('\n'.join(configured))
        else:
            print(json.dumps({'services': {name: {} for name in configured}}))
        return 0
    if verb == 'up':
        failed = [name for name in listed if name in unhealthy]
        if '--wait' in command and failed:
            print(f'container fixture-{failed[0]}-1 is unhealthy', file=sys.stderr)
            return 1
        slow = [name for name in listed if name in starting]
        if '--wait' in command and slow:
            print(f'container fixture-{slow[0]}-1 did not become healthy in time (timeout)', file=sys.stderr)
            return 1
        return 0
    if verb == 'ps':
        services = listed or configured
        if '--services' in command:
            print('\n'.join(name for name in services if name not in ONE_SHOT))
            return 0
        template = command[command.index('--format') + 1] if '--format' in command else '{{.Service}}'
        for name in services:
            if name in ONE_SHOT:
                row = dict(Service=name, State='exited', Health='', ExitCode='0', Status='Exited (0)')
            elif name in unhealthy:
                row = dict(Service=name, State='running', Health='unhealthy', ExitCode='0', Status='Up (unhealthy)')
            elif name in starting:
                row = {'Service': name, 'State': 'running', 'Health': 'starting', 'ExitCode': '0', 'Status': 'Up (health: starting)'}
            else:
                row = dict(Service=name, State='running', Health='healthy', ExitCode='0', Status='Up (healthy)')
            print(render(template, row))
        return 0
    return 0
