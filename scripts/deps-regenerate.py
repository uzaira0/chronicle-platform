#!/usr/bin/env python3
"""Carry a dependency bump into every file derived from it, the way scripts/verify-toolchain.sh checks.

Renovate changes the pins that are the source of truth (toolchain-manifest.yaml, Dockerfile FROM
lines, the root Gradle files and wrapper, chronicle-web's package.json, go.mod) and updates no
lockfile itself (renovate.json skipArtifactsUpdate: it holds the GitHub token, so it runs no package
manager). This script brings the derived pins and lockfiles in the root and the submodules into
line, so the candidate the gate runner tests is complete:

  - Bun: toolchain-manifest.yaml `bun` -> chronicle-web/package.json engines.bun and
    devDependencies.bun-types (tests/security/supply-chain-guardrails.sh reads the manifest);
  - Gradle wrapper: Renovate may only edit distributionUrl (running ./gradlew wrapper would execute the
    build with its token), so the distributionSha256Sum is set from services.gradle.org and
    `./gradlew wrapper` runs in the sandbox; then gradle/wrapper/* is copied to chronicle-server,
    chronicle-api, rhizome and rhizome-client (chronicle/'s Android wrapper is pinned separately);
  - Postgres: toolchain-manifest.yaml postgres.image/index_digest -> chronicle-server's pgTAP
    Dockerfile default and ChronicleContractTestSchema.PROD_POSTGRES_IMAGE;
  - chronicle-web/bun.lock: `bun install --ignore-scripts` when package.json and the lock disagree;
  - Gradle lockfiles and gradle/verification-metadata.xml: `--write-locks --write-verification-metadata
    sha256` over every included project, when a Gradle input changed against --base;
  - go.mod/go.sum of each Go module (GO_MODULES): `go mod tidy` when either changed against --base;
  - OS-package pins (selfhost/os-packages/ helper calls) of each Dockerfile whose FROM lines changed
    against --base: scripts/os-package-pins.py --write. It reads base image package databases with
    docker create/cp (nothing in the image runs) and resolves apt pins by running the base image's
    own apt against the distribution snapshot; no credentials reach either.

Every step that executes or fetches dependency code (Gradle, bun install, go) runs in
scripts/deps-sandbox.sh (no credentials, no host environment, registries only through the
allowlisting proxy) on a copy of the tree under --scratch, never on the tree itself, and only the
files that step may produce (its `outputs`) come back: regular files at their own paths, never a
symlink. Whatever else the dependency code writes stays in the scratch copy. The sandbox script is
this script's own (scripts/deps-sandbox.sh next to it), not the one in --root.

    deps-regenerate.py [--root DIR] [--base REF] [--scratch DIR] [--skip-gradle]

Prints each file it changed. Exit 0 when done, 1 when a step failed.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import stat
import subprocess
import sys
from pathlib import Path

SANDBOX = Path(__file__).resolve().parent / 'deps-sandbox.sh'
JVM_SUBMODULES = ('chronicle-server', 'chronicle-api', 'rhizome', 'rhizome-client')
GO_MODULES = ('selfhost/caddy/module', 'selfhost/backup-image/go-cron')
OS_PINS = Path(__file__).resolve().parent / 'os-package-pins.py'
# Relative to the tree copy the sandbox runs Gradle in.
POM_INIT = 'scripts/deps-regenerate-poms.init.gradle'
OS_HELPER = re.compile(r'os-packages/(?:apk-install-aged|apt-install-aged|dnf-upgrade-aged)\.sh')
FROM = re.compile(r'^FROM\s.*$', re.MULTILINE)
MAX_OUTPUT_BYTES = 256 * 1024 * 1024
GRADLE_PROJECTS = ('chronicle-models', 'chronicle-api', 'chronicle-server', 'rhizome', 'rhizome-client')
GRADLE_INPUTS = re.compile(r'^(build\.gradle\.kts|settings\.gradle\.kts|gradle\.properties|gradles/|gradle/wrapper/|'
                           r'(chronicle-server|chronicle-api|chronicle-models|rhizome|rhizome-client)(/|$))')


def manifest_value(root: Path, pattern: str) -> str:
    match = re.search(pattern, (root / 'toolchain-manifest.yaml').read_text(), re.MULTILINE)
    if not match:
        raise SystemExit(f'deps-regenerate: toolchain-manifest.yaml has no match for {pattern}')
    return match.group(1)


def rewrite(path: Path, pattern: str, replacement: str, changed: list[str], root: Path) -> None:
    if not path.is_file():
        return
    text = path.read_text()
    updated = re.sub(pattern, replacement, text, flags=re.MULTILINE)
    if updated != text:
        path.write_text(updated)
        changed.append(str(path.relative_to(root)))


def sync_bun(root: Path, changed: list[str]) -> bool:
    bun = manifest_value(root, r'^bun: "([^"]+)"')
    package_path = root / 'chronicle-web/package.json'
    if not package_path.is_file():
        return False
    text = package_path.read_text()
    package = json.loads(text)
    before = json.dumps(package, sort_keys=True)
    package.setdefault('engines', {})['bun'] = bun
    if 'bun-types' in package.get('devDependencies', {}):
        package['devDependencies']['bun-types'] = bun
    if json.dumps(package, sort_keys=True) == before:
        return False
    package_path.write_text(json.dumps(package, indent=2, ensure_ascii=False) + '\n')
    changed.append('chronicle-web/package.json')
    return True


def update_wrapper(root: Path, scratch: Path, changed: list[str]) -> bool:
    properties = root / 'gradle/wrapper/gradle-wrapper.properties'
    text = properties.read_text()
    version = re.search(r'gradle-([0-9][^-/]*)-bin\.zip', text).group(1)
    current = re.search(r'^distributionSha256Sum=([0-9a-f]{64})$', text, re.MULTILINE)
    sys.path.insert(0, os.environ.get('ROBUST_FETCH_DIR', str(Path.home() / 'agent-skills' / 'lib')))
    import robust_fetch
    url = f'https://services.gradle.org/distributions/gradle-{version}-bin.zip.sha256'
    try:
        expected = robust_fetch.fetch([url], deadline=120, min_bytes=64)[1].decode().strip()
    except robust_fetch.FetchError as error:
        print(f'deps-regenerate: cannot read {url}: {error}', file=sys.stderr)
        return False
    if not re.fullmatch(r'[0-9a-f]{64}', expected):
        print(f'deps-regenerate: {url} is not a sha256', file=sys.stderr)
        return False
    if current and current.group(1) == expected:
        return True
    return sandbox(root, scratch, '', ['./gradlew', '--no-daemon', '--console=plain', 'wrapper', '--gradle-version',
                                       version, '--distribution-type', 'bin', '--gradle-distribution-sha256-sum',
                                       expected],
                   ('gradle/wrapper/gradle-wrapper.properties', 'gradle/wrapper/gradle-wrapper.jar'), changed,
                   image='jdk')


def sync_wrapper(root: Path, changed: list[str]) -> None:
    for module in JVM_SUBMODULES:
        target = root / module / 'gradle/wrapper'
        if not target.is_dir():
            continue
        for name in ('gradle-wrapper.properties', 'gradle-wrapper.jar'):
            source = root / 'gradle/wrapper' / name
            if source.read_bytes() != (target / name).read_bytes():
                shutil.copyfile(source, target / name)
                changed.append(f'{module}/gradle/wrapper/{name}')


def sync_postgres(root: Path, changed: list[str]) -> None:
    image = manifest_value(root, r'^postgres:\n  image: "([^"]+)"')
    digest = manifest_value(root, r'^postgres:\n(?:  .*\n)*?  index_digest: "(sha256:[0-9a-f]{64})"')
    rewrite(root / 'chronicle-server/src/test/docker/pgtap/Dockerfile', r'^ARG PROD_POSTGRES_IMAGE=\S+',
            f'ARG PROD_POSTGRES_IMAGE={image}@{digest}', changed, root)
    rewrite(root / 'chronicle-server/src/test/kotlin/com/openlattice/chronicle/contract/ChronicleContractTestSchema.kt',
            r'PROD_POSTGRES_IMAGE = "[^"]+"', f'PROD_POSTGRES_IMAGE = "{image.split(":")[0]}@{digest}"', changed, root)


def copy_tree(source: Path, target: Path) -> None:
    """A copy of source at target (an APFS clone on macOS, so it costs no space)."""
    if target.exists():
        shutil.rmtree(target)
    target.parent.mkdir(parents=True, exist_ok=True)
    clone = ['cp', '-cR'] if sys.platform == 'darwin' else ['cp', '-a', '--reflink=auto']
    subprocess.run([*clone, str(source), str(target)], check=True)


def take_back(copy: Path, target: Path, outputs: tuple[str, ...], changed: list[str], root: Path) -> bool:
    """Copy each output that the sandbox step produced from copy back to target.

    Only regular files at exactly their own path count: a symlink (which would make this host process
    read a host file of the sandbox's choosing into the tree) or a symlinked directory on the way is
    refused, and so is anything over MAX_OUTPUT_BYTES."""
    ok = True
    for relative in outputs:
        source = copy / relative
        parent = copy
        for part in Path(relative).parts[:-1]:
            parent = parent / part
            if parent.is_symlink() or not parent.is_dir():
                print(f'deps-regenerate: refusing {relative}: {parent.relative_to(copy)} is not a directory',
                      file=sys.stderr)
                ok = False
                break
        else:
            try:
                mode = os.lstat(source).st_mode
            except FileNotFoundError:
                continue  # the step did not produce it
            if not stat.S_ISREG(mode):
                print(f'deps-regenerate: refusing {relative}: not a regular file', file=sys.stderr)
                ok = False
                continue
            descriptor = os.open(source, os.O_RDONLY | os.O_NOFOLLOW)
            with os.fdopen(descriptor, 'rb') as handle:
                data = handle.read(MAX_OUTPUT_BYTES + 1)
            if len(data) > MAX_OUTPUT_BYTES:
                print(f'deps-regenerate: refusing {relative}: larger than {MAX_OUTPUT_BYTES} bytes', file=sys.stderr)
                ok = False
                continue
            destination = target / relative
            if not destination.is_file() or destination.read_bytes() != data:
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(data)
                changed.append(str(destination.relative_to(root)))
    return ok


def sandbox(root: Path, scratch: Path, subdir: str, command: list[str], outputs: tuple[str, ...], changed: list[str],
            image: str = 'deps', network: str = 'registries') -> bool:
    """Run command in the sandbox over a copy of root/subdir and take back only outputs (relative to subdir)."""
    target = root / subdir if subdir else root
    copy = scratch / (subdir.replace('/', '_') or 'root')
    copy_tree(target, copy)
    args = ['bash', str(SANDBOX), '--image', image, '--network', network, str(copy), '--', *command]
    print('+ ' + ' '.join(args), flush=True)
    ok = subprocess.run(args, check=False).returncode == 0
    return take_back(copy, target, outputs, changed, root) and ok


def relock_web(root: Path, scratch: Path, changed: list[str]) -> bool:
    web = root / 'chronicle-web'
    if not (web / 'package.json').is_file():
        return True
    # Frozen first: when package.json and bun.lock agree there is nothing to do.
    if sandbox(root, scratch, 'chronicle-web', ['bun', 'install', '--frozen-lockfile', '--ignore-scripts', '--dry-run'],
               (), changed):
        return True
    return sandbox(root, scratch, 'chronicle-web', ['bun', 'install', '--ignore-scripts', '--lockfile-only'],
                   ('bun.lock',), changed)


def git(root: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(['git', '-c', 'core.fsmonitor=false', '-c', 'core.hooksPath=/dev/null', '-C', str(root),
                           *args], capture_output=True, text=True, check=False)


def changed_against(root: Path, base: str | None, pattern: re.Pattern) -> bool:
    if base is None:
        return True
    return any(pattern.match(path) for path in git(root, 'diff', '--name-only', base).stdout.splitlines())


def refresh_os_packages(root: Path, base: str | None, changed: list[str]) -> bool:
    """OS-package pins of each Dockerfile whose FROM lines changed against base (all of them without a
    base): a new base image carries its own package versions, so its pins are resolved again by this
    script's own scripts/os-package-pins.py, which also ages every version it picks."""
    paths = (git(root, 'diff', '--name-only', base).stdout if base else git(root, 'ls-files').stdout).splitlines()
    chosen = []
    for rel in paths:
        path = root / rel
        if 'Dockerfile' not in path.name or not path.is_file() or path.is_symlink():
            continue
        text = path.read_text()
        if not OS_HELPER.search(text):
            continue
        before = git(root, 'show', f'{base}:{rel}').stdout if base else ''
        if base and FROM.findall(before) == FROM.findall(text):
            continue
        chosen.append(rel)
    if not chosen:
        return True
    args = [sys.executable, '-I', str(OS_PINS), '--root', str(root)]
    for rel in chosen:
        args += ['--dockerfile', rel]
    print('+ ' + ' '.join(args + ['--write']), flush=True)
    result = subprocess.run([*args, '--write'], stdout=subprocess.PIPE, text=True, check=False)
    for line in result.stdout.splitlines():
        if line.strip() and line.strip() not in changed:
            changed.append(line.strip())
    return result.returncode == 0


def gradle_inputs_changed(root: Path, base: str | None) -> bool:
    return changed_against(root, base, GRADLE_INPUTS)


def regenerate_gradle(root: Path, scratch: Path, changed: list[str]) -> bool:
    outputs = ('gradle/verification-metadata.xml', *(f'{p}/gradle.lockfile' for p in GRADLE_PROJECTS))
    # resolveVerificationPoms (POM_INIT) records the POMs Dependency-Check and the CycloneDX BOM fetch.
    tasks = [task for project in GRADLE_PROJECTS
             for task in (f':{project}:dependencies', f':{project}:resolveVerificationPoms')]
    return sandbox(root, scratch, '', ['./gradlew', '--no-daemon', '--console=plain', '--init-script', POM_INIT,
                                       '--write-locks', '--write-verification-metadata', 'sha256',
                                       'buildEnvironment', *tasks],
                   outputs, changed, image='jdk')


def tidy_go(root: Path, scratch: Path, base: str | None, changed: list[str]) -> bool:
    """go mod tidy for each Go module whose go.mod or go.sum changed (Renovate edits go.mod only)."""
    ok = True
    for module in GO_MODULES:
        if not (root / module / 'go.mod').is_file():
            continue
        if not changed_against(root, base, re.compile(rf'^{re.escape(module)}/go\.(mod|sum)$')):
            continue
        ok = sandbox(root, scratch, module, ['go', 'mod', 'tidy'], ('go.mod', 'go.sum'), changed, image='go') and ok
    return ok


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument('--base', help='regenerate Gradle and Go state only when their inputs differ from this ref')
    parser.add_argument('--scratch', type=Path,
                        default=Path(os.environ.get('XDG_CACHE_HOME', Path.home() / '.cache')) / 'chronicle-deps-regenerate',
                        help='where the sandboxed steps get their copies of the tree')
    parser.add_argument('--skip-gradle', action='store_true')
    args = parser.parse_args(argv)
    root = args.root.resolve()
    scratch = args.scratch.resolve()
    changed: list[str] = []
    sync_bun(root, changed)
    ok = update_wrapper(root, scratch, changed)
    sync_wrapper(root, changed)
    sync_postgres(root, changed)
    ok = relock_web(root, scratch, changed) and ok
    ok = tidy_go(root, scratch, args.base, changed) and ok
    ok = refresh_os_packages(root, args.base, changed) and ok
    if not args.skip_gradle and gradle_inputs_changed(root, args.base):
        ok = regenerate_gradle(root, scratch, changed) and ok
    for path in changed:
        print(f'regenerated {path}')
    print(f'deps-regenerate: {len(changed)} file(s) changed, {"ok" if ok else "FAILED"}')
    return 0 if ok else 1


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
