#!/usr/bin/env python3
"""Fail an image that runs as root, has no HEALTHCHECK, carries a setuid/setgid file or a build tool,
unless config/image-policy.toml records why for that image (container-infra checklist I1 and I3).

    scripts/check-image-policy.py [--policy FILE] KEY=IMAGE [KEY=IMAGE ...]

KEY is the image's entry in the policy: the component name for an image built here (backend, caddy,
...), the repository for a third-party image (ghcr.io/google/cadvisor). The image filesystem is read
through `docker export` of a created (never started) container, so it works on distroless and scratch
images. An allowance the image no longer needs is reported as stale, so the policy cannot keep
excusing what was fixed.
"""
import argparse
import json
from pathlib import Path, PurePosixPath
import subprocess
import sys
import tarfile
import tomllib

ROOT = Path(__file__).resolve().parents[1]
BIN_DIRECTORIES = {'bin', 'sbin', 'usr/bin', 'usr/sbin', 'usr/local/bin', 'usr/local/sbin'}
# Build toolchains and debuggers: nothing a runtime image runs (checklist I1: no gcc, make, git).
BUILD_TOOLS = {'gcc', 'cc', 'c++', 'g++', 'clang', 'ld', 'as', 'make', 'gmake', 'cmake', 'git', 'go', 'javac',
               'cargo', 'rustc', 'gdb', 'strace', 'ltrace', 'tcpdump'}
ROOT_USERS = {'', '0', 'root'}


def docker(*arguments, **kwargs):
    return subprocess.run(['docker', *arguments], check=True, **kwargs)


def inspect(image):
    config = json.loads(docker('image', 'inspect', '--format', '{{json .Config}}', image,
                               capture_output=True, text=True).stdout)
    return config.get('User') or '', config.get('Healthcheck')


def filesystem(image):
    """(setid paths, build tools) in the image, read from a created container's export."""
    container = docker('create', image, '/chronicle-image-policy', capture_output=True, text=True).stdout.strip()
    setid, tools = set(), set()
    try:
        with subprocess.Popen(['docker', 'export', container], stdout=subprocess.PIPE) as export:
            with tarfile.open(fileobj=export.stdout, mode='r|') as archive:
                for member in archive:
                    path = PurePosixPath(member.name.lstrip('./'))
                    if member.isfile() and member.mode & 0o6000:
                        setid.add(str(path))
                    if (member.isfile() or member.issym() or member.islnk()) and \
                            str(path.parent) in BIN_DIRECTORIES and path.name in BUILD_TOOLS:
                        tools.add(str(path))
            if export.wait():
                raise subprocess.CalledProcessError(export.returncode, 'docker export')
    finally:
        subprocess.run(['docker', 'container', 'rm', '--volumes', container], capture_output=True, check=False)
    return setid, tools


def problems(key, image, entry):
    found = []
    user, healthcheck = inspect(image)
    root = user.split(':', 1)[0] in ROOT_USERS
    if root and not entry.get('root'):
        found.append(f'runs as root (USER {user or "unset"}); set a non-root USER or record why under root')
    if not root and entry.get('root'):
        found.append(f'stale root allowance: the image runs as {user}')
    absent = not healthcheck or (healthcheck.get('Test') or ['NONE'])[0] == 'NONE'
    if absent and not entry.get('healthcheck'):
        found.append('no HEALTHCHECK; add one or record what probes it under healthcheck')
    if not absent and entry.get('healthcheck'):
        found.append('stale healthcheck allowance: the image declares a HEALTHCHECK')
    setid, tools = filesystem(image)
    allowed_setid, allowed_tools = entry.get('setid', {}), entry.get('tools', {})
    found += [f'setuid/setgid file {path}; remove the bit or record why under setid'
              for path in sorted(setid - set(allowed_setid))]
    found += [f'stale setid allowance: {path} is gone or has no setuid/setgid bit'
              for path in sorted(set(allowed_setid) - setid)]
    found += [f'build tool {path} in a runtime image; remove it or record why under tools'
              for path in sorted(tools - set(allowed_tools))]
    found += [f'stale tools allowance: {path} is gone' for path in sorted(set(allowed_tools) - tools)]
    return found


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--policy', type=Path, default=ROOT / 'config' / 'image-policy.toml')
    parser.add_argument('pairs', nargs='+', metavar='KEY=IMAGE')
    args = parser.parse_args(argv)
    policy = tomllib.loads(args.policy.read_text(encoding='utf-8')).get('image', {})
    status = 0
    for pair in args.pairs:
        key, separator, image = pair.partition('=')
        if not separator or not key or not image or image.startswith('-') or any(c.isspace() for c in image):
            print(f'error: expected KEY=IMAGE, got {pair!r}', file=sys.stderr)
            return 2
        if key not in policy:
            print(f'error: {image}: {args.policy} has no entry [image."{key}"]', file=sys.stderr)
            status = 1
            continue
        found = problems(key, image, policy[key])
        for line in found:
            print(f'error: {image} ({key}): {line}', file=sys.stderr)
        if not found:
            print(f'image policy holds for {image} ({key})', file=sys.stderr)
        status = status or (1 if found else 0)
    return status


if __name__ == '__main__':
    sys.exit(main())
