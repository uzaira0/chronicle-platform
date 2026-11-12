#!/usr/bin/env python3
"""Execute healthcheck programs against the images in a rendered Compose document."""
import argparse
from contextlib import contextmanager
import json
from pathlib import Path
import sys
import tempfile
import uuid

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'selfhost'))
from chronicle_ops.common import run


def pinned_image(reference):
    # Resolve local release tags too, then execute the exact image inspected here.
    if '$' in reference:
        raise ValueError('Healthcheck verification requires resolved image references')
    inspect = ['docker', 'image', 'inspect', '--format', '{{.Id}}', reference]
    image = run(inspect, cwd=ROOT, capture=True).stdout.strip()
    if not image:
        run(['docker', 'pull', reference], cwd=ROOT, check=True)
        image = run(inspect, cwd=ROOT, capture=True, check=True).stdout.strip()
    return image


@contextmanager
def temporary_container(arguments):
    name = 'chronicle-probe-check-' + uuid.uuid4().hex
    run(['docker', 'create', '--name', name, *arguments], cwd=ROOT, check=True)
    try:
        yield name
    finally:
        run(['docker', 'rm', '-fv', name], cwd=ROOT, check=True)


def copy_probe(installer, work):
    image = pinned_image(installer['image'])
    source, destination = installer['command']
    with temporary_container(['--network', 'none', image]) as name:
        target = work / 'busybox'
        run(['docker', 'cp', f'{name}:{source}', str(target)], cwd=ROOT, check=True)
        return target, destination


def verify_program(service, probe):
    image = pinned_image(service['image'])
    test = service['healthcheck']['test']
    if test[0] == 'CMD-SHELL':
        shell = json.loads(run(['docker', 'image', 'inspect', '--format', '{{json .Config.Shell}}', image], cwd=ROOT, capture=True, check=True).stdout)
        program, *arguments = shell or ['/bin/sh', '-c']
        arguments.append(test[1])
    elif test[0] == 'CMD':
        program, *arguments = test[1:]
    else:
        raise ValueError('Healthchecks must declare CMD or CMD-SHELL')
    argv = ['--network', 'none', '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges:true']
    limits = service.get('deploy', {}).get('resources', {}).get('limits', {})
    for option, value in (('--memory', service.get('mem_limit') or limits.get('memory')),
                          ('--pids-limit', service.get('pids_limit') or limits.get('pids'))):
        if value:
            argv += [option, str(value)]
    if service.get('user'):
        argv += ['--user', service['user']]
    if probe and program == probe[1]:
        argv += ['--mount', f'type=bind,source={probe[0]},target={probe[1]},readonly']
    argv += ['--entrypoint', program, image, *arguments]
    with temporary_container(argv) as name:
        run(['docker', 'start', '--attach', name], cwd=ROOT)
        state = json.loads(run(['docker', 'inspect', '--format', '{{json .State}}', name], cwd=ROOT, capture=True, check=True).stdout)
        if state['Status'] != 'exited' or state['Error'] or state['ExitCode'] in (126, 127):
            raise ValueError('The declared healthcheck program could not execute in its image')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--work-dir', type=Path)
    parser.add_argument('--self-test', action='store_true')
    args = parser.parse_args()
    if args.self_test:
        import unittest
        sys.path.insert(0, str(ROOT / 'tests/selfhost-py'))
        result = unittest.TextTestRunner().run(unittest.defaultTestLoader.loadTestsFromName('test_healthcheck_executables'))
        if not result.wasSuccessful():
            raise ValueError('Healthcheck executable regression failed')
        return
    if args.work_dir is None:
        parser.error('--work-dir is required')
    config = json.load(sys.stdin)
    services = config['services']
    args.work_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=args.work_dir) as directory:
        installer = services.get('health-probe')
        probe = copy_probe(installer, Path(directory)) if installer else None
        checked = 0
        for name, service in services.items():
            if 'healthcheck' not in service:
                continue
            try:
                verify_program(service, probe)
            except (ValueError, RuntimeError) as error:
                raise ValueError(f'{name}: healthcheck program verification failed') from error
            checked += 1
    if not checked:
        raise ValueError('No healthcheck programs were exercised')
    print(f'PASS {checked} healthcheck programs executed in their resolved images')


if __name__ == '__main__':
    main()
