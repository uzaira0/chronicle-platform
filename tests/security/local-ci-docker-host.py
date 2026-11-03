#!/usr/bin/env python3
"""local-ci points Docker API clients at the active docker context's engine on macOS.

Testcontainers and container-structure-test read DOCKER_HOST or /var/run/docker.sock and ignore
`docker context`. On a Mac whose engine socket exists only through the context (OrbStack at
~/.orbstack/run/docker.sock), 338 server tests failed with "Could not find a valid Docker
environment" while `docker ps` worked. Fake `uname` and `docker` binaries stand in for the host.
"""

import os
import socket
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PROBE = 'source "$1"; export_docker_host_from_context; printf "%s|%s" "${DOCKER_HOST:-}" "${TESTCONTAINERS_DOCKER_SOCKET_OVERRIDE:-}"'


def executable(path, text):
    path.write_text(text, encoding='utf-8')
    path.chmod(path.stat().st_mode | stat.S_IXUSR)


def probe(directory, system, environment=None):
    bin_dir = Path(directory) / f'bin-{system}'
    bin_dir.mkdir(exist_ok=True)
    engine = Path(directory) / 'engine.sock'
    executable(bin_dir / 'uname', f'#!/bin/sh\necho {system}\n')
    executable(bin_dir / 'docker', f'#!/bin/sh\n[ "$1 $2" = "context inspect" ] && echo unix://{engine}\n')
    env = {key: value for key, value in os.environ.items()
           if key not in ('DOCKER_HOST', 'TESTCONTAINERS_DOCKER_SOCKET_OVERRIDE')}
    env.update(environment or {})
    env['PATH'] = f'{bin_dir}{os.pathsep}{env["PATH"]}'
    completed = subprocess.run(['bash', '-c', PROBE, 'probe', str(ROOT / 'scripts/local-ci.sh')],
                               cwd=ROOT, env=env, capture_output=True, text=True, check=False)
    return completed.returncode, completed.stdout, completed.stderr, f'unix://{engine}'


def main():
    problems = []
    with tempfile.TemporaryDirectory() as directory:
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        # Bind relative to the fixture directory to respect macOS's short sockaddr_un limit.
        previous = Path.cwd()
        try:
            os.chdir(directory)
            listener.bind('engine.sock')
        finally:
            os.chdir(previous)
        try:
            status, out, err, engine = probe(directory, 'Darwin')
            if status != 0 or out != f'{engine}|/var/run/docker.sock':
                problems.append(f'macOS without DOCKER_HOST: expected {engine}|/var/run/docker.sock, got {status} {out!r} {err.strip()}')
            status, out, err, _ = probe(directory, 'Darwin', {'DOCKER_HOST': 'tcp://127.0.0.1:2375'})
            if status != 0 or out != 'tcp://127.0.0.1:2375|':
                problems.append(f'an explicit DOCKER_HOST was replaced: {status} {out!r} {err.strip()}')
            status, out, err, _ = probe(directory, 'Linux')
            if status != 0 or out != '|':
                problems.append(f'Linux environment was changed: {status} {out!r} {err.strip()}')
        finally:
            listener.close()
    if problems:
        print('\n'.join(problems), file=sys.stderr)
        return 1
    print('local-ci docker host: context engine exported on macOS only, explicit DOCKER_HOST kept')
    return 0


if __name__ == '__main__':
    sys.exit(main())
