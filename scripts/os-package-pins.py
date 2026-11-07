#!/usr/bin/env python3
"""Propose aged OS-package pins for every Dockerfile helper call (docs/SUPPLY-CHAIN.md, "OS packages").

    os-package-pins.py [--root DIR] [--dockerfile PATH]... [--write]

For each call of selfhost/os-packages/{apk-install-aged,apt-install-aged,dnf-upgrade-aged}.sh in a
tracked Dockerfile:

  apk  reads the stage's base image package database (docker create + docker cp of its linux/amd64
       variant; nothing in the image runs) and the branch's APK index, then pins every --add package
       and each dependency the base lacks (--pin), and upgrades each base package whose newer index
       version was built at least the wait ago (--upgrade). The branch is the base image's.
  apt  resolves the --add packages (or, with --download, the pinned names) inside the base image
       against the distribution's snapshot taken MAJOR_DAYS ago at midnight UTC, so nothing it pins
       can be younger than any wait; it never moves a pin back to an older version, and writes
       today's snapshot as the fallback source. The base image runs in this checkout's
       scripts/deps-sandbox.sh --base-image with --network registries: its only route out is the
       allowlisting egress proxy (HTTPS CONNECT to scripts/sandbox/egress-allowlist.txt), so apt
       reaches the snapshot over HTTPS (apt-install-aged.sh --https) with this host's CA bundle.
  dnf  moves each --upgrade pin to the UBI repository's current build of that package once that
       build is older than the wait.

The waits and the version-major rule come from scripts/check-dependency-age.py. Without --write it
prints what it would change. With --write it rewrites the calls in place and prints each changed
file's path relative to --root, one per line, on stdout; notes go to stderr.

Exit 0 when every call was refreshed (or needed nothing), 1 when a call cannot be satisfied by any
aged version (the build of that image will fail until one ages), 2 when a lookup could not be
answered (that call was left as it was).
"""
from __future__ import annotations

import argparse
import datetime as dt
import importlib.util
import io
import json
import os
import re
import ssl
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
SANDBOX = HERE / 'deps-sandbox.sh'
sys.path.insert(0, str(HERE))
import os_packages

spec = importlib.util.spec_from_file_location('check_dependency_age', HERE / 'check-dependency-age.py')
policy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(policy)


class Indeterminate(RuntimeError):
    pass


def note(message: str) -> None:
    print(f'os-package-pins: {message}', file=sys.stderr, flush=True)


def fetch(urls: list, min_bytes: int = 2, extra: list[str] | None = None) -> bytes:
    sys.path.insert(0, os.environ.get('ROBUST_FETCH_DIR', str(Path.home() / 'agent-skills' / 'lib')))
    import robust_fetch
    try:
        return robust_fetch.fetch(urls, deadline=240, min_bytes=min_bytes, extra=extra)[1]
    except robust_fetch.FetchError as error:
        raise Indeterminate(str(error)) from error


def wait_days(old: str | None, new: str) -> int:
    if old is not None and policy.major(old) != policy.major(new):
        return policy.MAJOR_DAYS
    return policy.ROUTINE_DAYS


def aged(now: dt.datetime, old: str | None, new: str, published: dt.datetime) -> bool:
    return (now - published).total_seconds() >= wait_days(old, new) * 86400


# ---------------------------------------------------------------- base images

def amd64_reference(reference: str) -> str:
    """repository@digest of the linux/amd64 image of a digest-pinned reference."""
    if '@sha256:' not in reference:
        raise Indeterminate(f'{reference} is not pinned by digest')
    named, digest = reference.split('@', 1)
    repository = named if ':' not in named.rsplit('/', 1)[-1] else named.rsplit(':', 1)[0]
    raw = subprocess.run(['docker', 'buildx', 'imagetools', 'inspect', '--raw', f'{repository}@{digest}'],
                         capture_output=True, text=True, check=False)
    if raw.returncode:
        raise Indeterminate(f'cannot read the manifest of {reference}: {raw.stderr.strip()}')
    manifest = json.loads(raw.stdout)
    for item in manifest.get('manifests', []):
        platform = item.get('platform', {})
        if platform.get('os') == 'linux' and platform.get('architecture') == 'amd64':
            return f'{repository}@{item["digest"]}'
    if manifest.get('manifests'):
        raise Indeterminate(f'{reference} has no linux/amd64 image')
    return f'{repository}@{digest}'


def image_files(reference: str, *paths: str) -> dict[str, str]:
    """Files from an image, copied out of a created (never started) container."""
    image = amd64_reference(reference)
    if subprocess.run(['docker', 'image', 'inspect', image], capture_output=True, check=False).returncode:
        pulled = subprocess.run(['docker', 'pull', '--quiet', image], capture_output=True, text=True, check=False)
        if pulled.returncode:
            raise Indeterminate(f'cannot pull {image}: {pulled.stderr.strip()}')
    container = subprocess.run(['docker', 'create', image, '/nonexistent'], capture_output=True, text=True,
                               check=False)
    if container.returncode:
        raise Indeterminate(f'cannot create a container of {image}: {container.stderr.strip()}')
    cid = container.stdout.strip()
    found = {}
    try:
        for path in paths:
            copied = subprocess.run(['docker', 'cp', '-L', f'{cid}:{path}', '-'], capture_output=True, check=False)
            if copied.returncode:
                continue
            with tarfile.open(fileobj=io.BytesIO(copied.stdout)) as archive:
                member = next((m for m in archive.getmembers() if m.isfile()), None)
                handle = archive.extractfile(member) if member else None
                if handle:
                    found[path] = handle.read().decode('utf-8', 'replace')
    finally:
        subprocess.run(['docker', 'rm', cid], capture_output=True, check=False)
    return found


# ---------------------------------------------------------------- proposals per helper

def propose_apk(call: os_packages.HelperCall, now: dt.datetime) -> tuple[list[str], dict[str, list[str]], list[str]]:
    files = image_files(call.stage_from or '', '/etc/alpine-release', '/lib/apk/db/installed')
    if '/lib/apk/db/installed' not in files or '/etc/alpine-release' not in files:
        raise Indeterminate(f'{call.stage_from} has no Alpine package database')
    branch = 'v' + '.'.join(files['/etc/alpine-release'].strip().split('.')[:2])
    base = os_packages.parse_apk_database(files['/lib/apk/db/installed'])
    index: dict[str, dict] = {}
    for repository in reversed(os_packages.APK_REPOSITORIES):  # main wins over community
        index.update(os_packages.parse_apkindex(fetch(
            [os_packages.apk_index_url(mirror, branch, repository) for mirror in os_packages.APK_MIRRORS],
            min_bytes=1000)))
    wanted = call.sections['add']
    previous = dict(os_packages.split_pin(word) for word in call.sections['pin'] + call.sections['upgrade'])

    def is_aged(name, old, new, built):
        old = old or previous.get(name)
        return bool(built) and aged(now, old, new, dt.datetime.fromtimestamp(int(built), dt.UTC))

    try:
        pins, upgrades, problems = os_packages.apk_proposal(wanted, base, index, is_aged)
    except LookupError as error:
        return [], {}, [str(error)]
    return [branch], {'add': wanted, 'pin': pins, 'upgrade': upgrades}, problems


def snapshot_now(now: dt.datetime) -> str:
    # The longest wait, so that no resolved version, major or not, can be younger than its own wait.
    moment = (now - dt.timedelta(days=policy.MAJOR_DAYS)).replace(hour=0, minute=0, second=0, microsecond=0)
    return moment.strftime('%Y%m%dT%H%M%SZ')


def ca_bundle() -> str:
    """This host's CA bundle, for apt's TLS to the snapshot (a slim base image may have none)."""
    paths = ssl.get_default_verify_paths()
    for candidate in (os.environ.get('SSL_CERT_FILE'), paths.cafile, paths.openssl_cafile,
                      '/etc/ssl/certs/ca-certificates.crt', '/etc/ssl/cert.pem'):
        if candidate and Path(candidate).is_file():
            return str(Path(candidate).resolve())
    raise Indeterminate('no CA bundle on this host for reaching the snapshot over HTTPS')


def propose_apt(call: os_packages.HelperCall, root: Path, now: dt.datetime) -> tuple[list[str], dict[str, list[str]], list[str]]:
    sections = call.sections
    distro = sections['positional'][0]
    download = '--download' in sections['flags']
    names = sections['add'] or [os_packages.split_pin(w)[0] for w in sections['pin'] + sections['upgrade']]
    snapshot = snapshot_now(now)
    helper = root / 'selfhost/os-packages/apt-install-aged.sh'
    image = amd64_reference(call.stage_from or '')
    with tempfile.TemporaryDirectory(prefix='os-package-pins-') as empty:  # the sandbox's /work: nothing
        command = ['bash', str(SANDBOX), '--base-image', image, '--platform', 'linux/amd64', '--network', 'registries',
                   '--mount', f'{helper}:/usr/local/sbin/apt-install-aged.sh:ro',
                   '--mount', f'{ca_bundle()}:/etc/ssl/certs/ca-certificates.crt:ro', empty, '--',
                   'sh', '/usr/local/sbin/apt-install-aged.sh', distro, snapshot, '--https',
                   *(['--download'] if download else []), '--resolve', *names]
        result = subprocess.run(command, capture_output=True, text=True, check=False, timeout=1800)
    lines = [line.split(' ', 1) for line in result.stdout.splitlines() if line.startswith(('pin ', 'upgrade '))]
    if result.returncode or not lines:
        raise Indeterminate(f'resolving {" ".join(names)} against the {distro} snapshot {snapshot} failed: '
                            f'{result.stderr.strip()[-400:]}')
    resolved = {'pin': sorted(w for kind, w in lines if kind == 'pin'),
                'upgrade': sorted(w for kind, w in lines if kind == 'upgrade')}
    missing = set(names) - {os_packages.split_pin(w)[0] for w in resolved['pin'] + resolved['upgrade']}
    problems = [f'the {distro} snapshot {snapshot} has no {name}' for name in sorted(missing)]
    # A pin is never moved back: a newer one already passed the age gate when it was committed (a
    # security build the snapshot of one wait ago predates, for instance), so it stays.
    previous = dict(os_packages.split_pin(w) for w in sections['pin'] + sections['upgrade'])
    for kind in ('pin', 'upgrade'):
        resolved[kind], kept = os_packages.never_back(resolved[kind], previous)
        for name in kept:
            note(f'{name}: keeping {previous[name]}; the {snapshot} snapshot has only an older build')
    # The snapshot written into the call is only where a pin is fetched from once the live mirror has
    # replaced it, so it must be no older than the newest pin: today at midnight UTC.
    fallback = now.replace(hour=0, minute=0, second=0, microsecond=0).strftime('%Y%m%dT%H%M%SZ')
    return [distro, fallback], {'add': sections['add'], **resolved}, problems


def propose_dnf(call: os_packages.HelperCall, now: dt.datetime) -> tuple[list[str], dict[str, list[str]], list[str]]:
    release = call.sections['positional'][0]
    current: dict[str, tuple[str, int]] = {}
    for base in os_packages.UBI_REPOSITORIES.get(release, ()):
        for (name, version, rel), times in os_packages.parse_primary(base, fetch).items():
            current.setdefault(name, (f'{version}-{rel}', max(times)))
    upgrades = []
    for word in call.sections['upgrade']:
        name, pinned = os_packages.split_pin(word)
        newest = current.get(name)
        if newest and newest[0] != pinned and aged(now, pinned, newest[0], dt.datetime.fromtimestamp(newest[1], dt.UTC)):
            upgrades.append(f'{name}={newest[0]}')
        else:
            upgrades.append(word)
    return [release], {'upgrade': upgrades}, []


# ---------------------------------------------------------------- rewrite

def rewrite(text: str, call: os_packages.HelperCall, positional: list[str], sections: dict[str, list[str]]) -> str:
    line_start = text.rfind('\n', 0, call.start) + 1
    indent = re.match(r'[ \t]*', text[line_start:]).group(0) + '  '
    rendered = os_packages.render_call(positional, call.sections['flags'], sections, indent)
    return text[:call.start] + rendered + text[call.end:]


def dockerfiles(root: Path, chosen: list[str]) -> list[Path]:
    if chosen:
        return [root / path for path in chosen]
    tracked = subprocess.run(['git', '-C', str(root), 'ls-files'], capture_output=True, text=True, check=True).stdout
    return [root / path for path in tracked.splitlines()
            if path.rsplit('/', 1)[-1].startswith('Dockerfile') and (root / path).is_file()]


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--root', type=Path, default=HERE.parent)
    parser.add_argument('--dockerfile', action='append', default=[], help='only this Dockerfile (relative to --root)')
    parser.add_argument('--write', action='store_true')
    args = parser.parse_args(argv)
    root = args.root.resolve()
    now = dt.datetime.now(dt.UTC)
    status = 0
    for path in dockerfiles(root, args.dockerfile):
        text = path.read_text()
        calls = os_packages.helper_calls(text)
        updated = text
        for call in reversed(calls):  # later offsets first, so earlier ones stay valid
            label = f'{path.relative_to(root)} ({call.helper} in FROM {call.stage_from})'
            try:
                if call.helper == 'apk-install-aged.sh':
                    positional, sections, problems = propose_apk(call, now)
                elif call.helper == 'apt-install-aged.sh':
                    positional, sections, problems = propose_apt(call, root, now)
                else:
                    positional, sections, problems = propose_dnf(call, now)
            except Indeterminate as error:
                note(f'{label}: left as it was: {error}')
                status = max(status, 2)
                continue
            if problems:
                for problem in problems:
                    note(f'{label}: {problem}')
                note(f'{label}: left as it was; the image build fails until an aged version exists')
                status = 1 if status != 2 else status
                continue
            updated = rewrite(updated, call, positional, sections)
        if updated != text:
            if args.write:
                path.write_text(updated)
                print(path.relative_to(root), flush=True)
            else:
                note(f'{path.relative_to(root)} would change')
    return status


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
