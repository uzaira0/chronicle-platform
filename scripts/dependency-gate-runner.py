#!/usr/bin/env python3
"""Gate Renovate's branches and fast-forward deps/auto with the ones that pass (docs/SUPPLY-CHAIN.md).

    dependency-gate-runner.py [--root DIR] [--branch NAME] [--dry-run]
    dependency-gate-runner.py --candidate REF --base-ref REF
    dependency-gate-runner.py --init-base REF | --trust-base REF

Trust: everything that decides a gate comes from this checkout (--root, the runner's own), never
from the candidate. The age gate, the regeneration driver, the image gate and every script a
sandboxed gate runs (scripts/ and tests/, mounted read-only) are this checkout's files. The candidate is data:
it is cloned into a work directory, none of its code runs on the host, and a candidate that changes
a gate input (PROTECTED below: scripts/, tests/, the policy and scanner files, the toolchain's gate
tools, chronicle-web's bunfig.toml and the non-dependency fields of its package.json) fails before
anything of it runs. deps/auto is untrusted too, since Renovate's token can write it: the runner
gates against the last deps/auto it pushed itself (or one this checkout already contains), so
anything that reached deps/auto another way is gated together with the candidate.

For every renovate/* branch of the root repository and of chronicle-web-dev that has not passed
(failed ones are retried, see should_gate) and that contains the trusted deps/auto:

 1. clones the candidate into <work>/candidate (the root at the Renovate commit, or at deps/auto with
    chronicle-web moved to the Renovate commit; submodules at their gitlinks from this checkout's
    module repositories). Git runs with hooks and fsmonitor off;
 2. refuses changes to PROTECTED paths, then runs this checkout's scripts/check-dependency-age.py on
    the candidate before any dependency code runs (waits, unreviewed new names, OSV MAL-);
 3. completes the candidate with this checkout's scripts/deps-regenerate.py, which runs everything
    that executes dependency code in scripts/deps-sandbox.sh on a copy and takes back only the files
    each step may produce; commits what changed in each submodule, then in the root, and checks
    PROTECTED again;
 4. runs the gates on the complete candidate (gate_steps). On the host only this checkout's code runs:
    the age gate again, `local-ci.sh image-gate` (the builds run inside BuildKit; the host side has an
    empty HOME and a Docker configuration without credentials) and deps-freshness.sh --fetch-github
    (GitHub lookups of repositories named in that script, with the runner's gh login). Everything
    else runs in the gate sandbox, each step on a fresh APFS clone of the candidate with this
    checkout's scripts/ and tests/ mounted read-only: the candidate's requirements-dev.txt from
    hashes; local-ci's security tools (written only by that step); verify-toolchain.sh; the security
    jobs that query live databases (ONLINE_JOBS, through the allowlisting proxy); a Gradle download of
    every resolvable configuration; every other security job with no network, the ones that build or
    test last; the fuzz job as linux/amd64 with no network; when chronicle-web changed, `bun install`
    (registries only) then `local-ci.sh web` (no network);
 5. on success pushes deps/auto as a fast-forward (moved submodules first, then the root), records
    it as the trusted base, and posts chronicle/dependency-gate on the Renovate commit.

It pushes nothing but refs/heads/deps/auto, only to the uzaira0 *-dev repositories, never with
force; it never touches main, never tags and never publishes. Taking deps/auto further is the user's
decision. --dry-run gates the candidates but posts no status, pushes and records nothing.
--candidate gates one local commit of the root against --base-ref the same way, as a dry run.

--init-base REF creates deps/auto at REF in the root repository and at REF's chronicle-web gitlink in
chronicle-web-dev (an existing deps/auto is left alone) and trusts REF. --trust-base REF records REF
as the trusted deps/auto after a person has reviewed it.

Work directory: CHRONICLE_DEPENDENCY_GATE_WORK (default ~/Library/Caches/chronicle-dependency-gate);
gate logs go to <work>/logs/<branch>-<sha>/. State (trusted base, failed results):
CHRONICLE_DEPENDENCY_GATE_STATE (default ~/Library/Application Support/chronicle-dependency-gate/
state.json). One line per branch on stdout.
"""
from __future__ import annotations

import argparse
import dataclasses
import datetime as dt
import functools
import hashlib
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import time
from pathlib import Path

GATE_CONTEXT = 'chronicle/dependency-gate'
BASE = 'deps/auto'
ROOT_REPO = 'uzaira0/methodic-dev'
WEB_REPO = 'uzaira0/chronicle-web-dev'
WEB_PATH = 'chronicle-web'
SKIP_SUBMODULES = {'chronicle-ios'}  # nothing Renovate updates lives there and the module may be absent
ALLOWED_PUSH_URL = re.compile(r'^https://github\.com/uzaira0/[A-Za-z0-9_.-]+-dev\.git$')
RUNTIME_INVENTORY = re.compile(r'^(toolchain-manifest\.yaml|selfhost/docker-compose[^/]*\.ya?ml|selfhost/overlays/)')
# Gate inputs: what decides whether a candidate passes. A person changes them, never the bot. A
# directory ends with '/'. A change that only swaps one digest-pinned image reference for another
# (Renovate's Dockerfile and regex managers on scripts/sandbox/ and scripts/flyway-migrate.sh) is
# allowed: the age gate checks the new image.
PROTECTED = ('scripts/', 'tests/', '.github/', '.gitmodules', 'lefthook.yml', 'renovate.json',
             'dependency-exceptions.toml', 'dependency-additions.toml', '.trivyignore.yaml', '.grype.yaml',
             'osv-scanner.toml', 'bearer.yml', 'bearer.ignore', 'sgconfig.yml', 'detekt.yml', 'detekt-baseline.xml',
             'config/dependency-check-suppression.xml', f'{WEB_PATH}/bunfig.toml')
# package.json fields Renovate and deps-regenerate.py change; every other field (scripts,
# trustedDependencies, workspaces, ...) is a gate input.
PACKAGE_DEPENDENCY_FIELDS = {'dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies',
                             'overrides', 'resolutions', 'engines', 'packageManager'}
IMAGE_PIN = re.compile(r'(?:[a-z0-9.-]+(?::\d+)?/)?[a-z0-9._/-]+:[\w.-]+@sha256:[a-f0-9]{64}')
GATE_TOOLS_BLOCK = re.compile(r'^gate_tools:\n(?:(?:[ \t].*)?\n)*', re.MULTILINE)
# Every git command the runner runs: no hooks (lefthook would run the candidate's lefthook.yml on the
# host), no fsmonitor command, no ext:: transport.
GIT_SAFETY = (('core.hooksPath', '/dev/null'), ('core.fsmonitor', 'false'), ('protocol.ext.allow', 'never'))
# Failures that time or a retry clears: waits end, lookups come back. The age gate runs before
# anything else and is cheap, so these are retried on every run.
RETRY_ALWAYS = {'age', 'age-indeterminate'}
MAX_ATTEMPTS = 3


def with_git_safety(env: dict[str, str] | None) -> dict[str, str]:
    env = dict(os.environ if env is None else env)
    count = int(env.get('GIT_CONFIG_COUNT', '0') or 0)
    for index, (key, value) in enumerate(GIT_SAFETY, start=count):
        env[f'GIT_CONFIG_KEY_{index}'], env[f'GIT_CONFIG_VALUE_{index}'] = key, value
    env['GIT_CONFIG_COUNT'] = str(count + len(GIT_SAFETY))
    return env


def run(args: list[str], cwd: Path, log: Path | None = None, env: dict | None = None, check: bool = False) -> int:
    if args[0] == 'git':
        env = with_git_safety(env)
    if log is None:
        result = subprocess.run(args, cwd=cwd, env=env, check=False)
    else:
        with log.open('ab') as handle:
            handle.write(f'\n$ {shlex.join(args)}\n'.encode())
            handle.flush()
            result = subprocess.run(args, cwd=cwd, env=env, stdout=handle, stderr=subprocess.STDOUT, check=False)
    if check and result.returncode:
        raise SystemExit(f'dependency-gate: {shlex.join(args)} failed ({result.returncode})')
    return result.returncode


def out(args: list[str], cwd: Path, check: bool = True) -> str:
    env = with_git_safety(None) if args[0] == 'git' else None
    result = subprocess.run(args, cwd=cwd, env=env, capture_output=True, text=True, check=False)
    if check and result.returncode:
        raise SystemExit(f'dependency-gate: {shlex.join(args)} failed ({result.returncode}): {result.stderr.strip()}')
    return result.stdout.strip() if result.returncode == 0 else ''


# ---------------------------------------------------------------- push

def push_command(url: str, sha: str, git_dir: Path) -> list[str]:
    """The only remote write: one commit to deps/auto at one validated URL, no force, nothing else.

    The URL is given explicitly (never a remote name, whose configuration can carry extra pushurls),
    from a bare repository of the runner's own (no repository settings, no insteadOf), with tags and
    submodule recursion off whatever the configuration says.
    """
    if not ALLOWED_PUSH_URL.match(url):
        raise SystemExit(f'dependency-gate: refusing to push to {url} (only uzaira0 *-dev repositories)')
    if not re.fullmatch(r'[0-9a-f]{40}', sha):
        raise SystemExit(f'dependency-gate: refusing to push {sha!r} (a full commit id is required)')
    return ['git', f'--git-dir={git_dir}', '-c', 'push.followTags=false', '-c', 'push.recurseSubmodules=no',
            '-c', 'core.hooksPath=/dev/null', 'push', '--no-follow-tags', '--recurse-submodules=no', '--porcelain',
            url, f'{sha}:refs/heads/{BASE}']


def push_env(work: Path) -> dict[str, str]:
    """Git configuration for the push: no system config, a global config holding only gh's credential helper."""
    gh = shutil.which('gh')
    if not gh:
        raise SystemExit('dependency-gate: gh is not on PATH; it supplies the push credential')
    config = work / 'push-gitconfig'
    config.write_text('[credential "https://github.com"]\n\thelper =\n'
                      f'\thelper = !{shlex.quote(gh)} auth git-credential\n')
    env = {k: v for k, v in os.environ.items() if not k.startswith('GIT_')}
    env.update(GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL=str(config), GIT_TERMINAL_PROMPT='0')
    return env


def push_repository(repo_dir: Path, work: Path, env: dict[str, str]) -> Path:
    """A bare repository under work/push that borrows repo_dir's objects and none of its configuration."""
    objects = Path(out(['git', 'rev-parse', '--path-format=absolute', '--git-path', 'objects'], repo_dir))
    name = re.sub(r'[^A-Za-z0-9_.-]', '_', str(objects.parent.resolve()).strip('/'))
    git_dir = work / 'push' / f'{name}.git'
    if not (git_dir / 'HEAD').is_file():
        git_dir.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run(['git', 'init', '--bare', '--quiet', '--template=', str(git_dir)], env=env, check=True)
    (git_dir / 'objects' / 'info').mkdir(parents=True, exist_ok=True)
    (git_dir / 'objects' / 'info' / 'alternates').write_text(f'{objects}\n')
    return git_dir


def push(repo_dir: Path, sha: str, url: str, work: Path) -> None:
    env = push_env(work)
    run(push_command(url, sha, push_repository(repo_dir, work, env)), repo_dir, env=env, check=True)


def module_urls(root: Path) -> dict[str, str]:
    """Submodule path -> URL, from this checkout's .gitmodules (never the candidate's)."""
    urls = {}
    # --get-regexp exits 1 when nothing matches: a checkout without submodules.
    for line in out(['git', 'config', '-f', str(root / '.gitmodules'), '--get-regexp', r'^submodule\..*\.path$'],
                    root, check=False).splitlines():
        key, path = line.split(maxsplit=1)
        urls[path] = out(['git', 'config', '-f', str(root / '.gitmodules'), f'{key[:-len(".path")]}.url'], root)
    return urls


def push_url(root: Path, path: str) -> str:
    """Where deps/auto goes for the root ('') or a submodule path."""
    return f'https://github.com/{ROOT_REPO}.git' if not path else module_urls(root)[path]


# ---------------------------------------------------------------- remote state

def remote_heads(cwd: Path, remote: str) -> dict[str, str]:
    lines = out(['git', 'ls-remote', remote, 'refs/heads/renovate/*', f'refs/heads/{BASE}'], cwd).splitlines()
    return {ref.removeprefix('refs/heads/'): sha for sha, ref in (line.split('\t') for line in lines if line)}


def gate_status(repo: str, sha: str) -> str | None:
    result = subprocess.run(['gh', 'api', f'repos/{repo}/commits/{sha}/statuses'], capture_output=True, text=True,
                            check=False)
    if result.returncode:
        raise SystemExit(f'dependency-gate: cannot read statuses of {repo}@{sha}: {result.stderr.strip()}')
    return next((s.get('state') for s in json.loads(result.stdout) if s.get('context') == GATE_CONTEXT), None)


def post_status(repo: str, sha: str, state: str, description: str) -> None:
    run(['gh', 'api', '--silent', '-X', 'POST', f'repos/{repo}/statuses/{sha}', '-f', f'state={state}',
         '-f', f'context={GATE_CONTEXT}', '-f', f'description={description[:139]}'], Path.cwd(), check=True)


# ---------------------------------------------------------------- state

def state_file() -> Path:
    return Path(os.environ.get('CHRONICLE_DEPENDENCY_GATE_STATE',
                               Path.home() / 'Library/Application Support/chronicle-dependency-gate/state.json'))


def load_state() -> dict:
    path = state_file()
    state = json.loads(path.read_text()) if path.is_file() else {}
    state.setdefault('candidates', {})
    return state


def save_state(state: dict) -> None:
    path = state_file()
    path.parent.mkdir(parents=True, exist_ok=True)
    cutoff = (dt.datetime.now(dt.UTC) - dt.timedelta(days=60)).isoformat()
    state['candidates'] = {k: v for k, v in state['candidates'].items() if v.get('at', '') >= cutoff}
    part = path.with_name(path.name + '.part')
    part.write_text(json.dumps(state, indent=2, sort_keys=True) + '\n')
    os.replace(part, path)


def is_ancestor(cwd: Path, ancestor: str, descendant: str) -> bool:
    return run(['git', 'merge-base', '--is-ancestor', ancestor, descendant], cwd) == 0


def trusted_base(root: Path, state: dict, remote_tip: str) -> str:
    """The deps/auto this runner can vouch for.

    The remote tip is trusted when it is the one recorded (pushed by this runner or trusted by a
    person) or when this checkout already contains it. Otherwise the recorded base is used, so the
    candidate's diff also covers whatever moved deps/auto past it."""
    recorded = state.get('trusted_base')
    if remote_tip == recorded or is_ancestor(root, remote_tip, 'HEAD'):
        return remote_tip
    if recorded:
        print(f'dependency-gate: {BASE} is at {remote_tip[:12]}, which this runner did not push and this '
              f'checkout does not contain; gating against the trusted {recorded[:12]}', file=sys.stderr)
        return recorded
    raise SystemExit(f'dependency-gate: {BASE} ({remote_tip[:12]}) is neither recorded nor contained in this '
                     f'checkout; review it, then run --trust-base {remote_tip}')


def fingerprint(root: Path, base: str) -> str:
    """What a failed result depends on besides the candidate: the trusted base and this checkout's gates."""
    head = out(['git', 'rev-parse', 'HEAD'], root)
    dirty = out(['git', 'status', '--porcelain', '--untracked-files=no'], root)
    return hashlib.sha256(f'{base}\n{head}\n{dirty}'.encode()).hexdigest()[:24]


def should_gate(status: str | None, record: dict | None, current: str) -> bool:
    """Gate a candidate that has no result, or whose failure may not hold any more.

    A pass is final. A failure is retried when this checkout's gates or the trusted base changed,
    always when it was only a wait or an unanswered lookup, and otherwise up to MAX_ATTEMPTS times
    (a flaky download in a scan)."""
    if status == 'success':
        return False
    if status is None or record is None or record.get('fingerprint') != current:
        return True
    failed = set(record.get('failed', []))
    if failed and failed <= RETRY_ALWAYS:
        return True
    return record.get('attempts', 0) < MAX_ATTEMPTS


# ---------------------------------------------------------------- candidate checkout

def drop_refs(repo: Path, log: Path) -> None:
    """Delete every ref of a fresh clone except tags on the history under test, leaving HEAD detached at
    the commit under test. A clone copies the source's branches and tags, and the full-history scanners
    (gitleaks walks every ref) would otherwise judge the candidate by unrelated work on other branches of
    this checkout; tags on its own history stay for `git describe`, which the build's versioning reads."""
    drop = []
    for line in out(['git', 'for-each-ref', '--format=%(refname) %(*objectname) %(objectname)'], repo).splitlines():
        ref, *targets = line.split()
        if ref.startswith('refs/tags/') and run(['git', 'merge-base', '--is-ancestor', targets[0], 'HEAD'], repo) == 0:
            continue
        drop.append(ref)
    with log.open('ab') as handle:
        handle.write(f'\n$ git update-ref --no-deref --stdin  # delete {len(drop)} refs in {repo}\n'.encode())
        handle.flush()
        # --no-deref: origin/HEAD is a symbolic ref to a branch also on the list.
        subprocess.run(['git', 'update-ref', '--no-deref', '--stdin'], cwd=repo, env=with_git_safety(None),
                       check=True, stdout=handle, stderr=subprocess.STDOUT,
                       input=''.join(f'delete {ref}\n' for ref in drop).encode())


def prepare(root: Path, tree: Path, ref: str, web_sha: str | None, log: Path) -> None:
    """A clone of the root at ref under the work directory, submodules from the local module repositories.

    A clone, not a worktree: the candidate gets git directories of its own, so nothing done in it can
    reach this checkout's configuration or hooks."""
    if tree.exists():
        shutil.rmtree(tree)
    tree.parent.mkdir(parents=True, exist_ok=True)
    run(['git', 'clone', '--quiet', '--local', '--no-checkout', str(root), str(tree)], root, log, check=True)
    run(['git', 'checkout', '--quiet', '--detach', ref], tree, log, check=True)
    drop_refs(tree, log)
    modules = Path(out(['git', 'rev-parse', '--path-format=absolute', '--git-common-dir'], root)) / 'modules'
    urls = module_urls(root)
    for line in out(['git', 'config', '-f', '.gitmodules', '--get-regexp', r'^submodule\..*\.path$'], tree,
                    check=False).splitlines():
        key, path = line.split()
        name = key[len('submodule.'):-len('.path')]
        if name in SKIP_SUBMODULES or path not in urls:
            continue
        run(['git', 'submodule', 'init', '--', path], tree, log, check=True)
        run(['git', 'config', f'submodule.{name}.url', str(modules / name)], tree, log, check=True)
        cloned = run(['git', '-c', 'protocol.file.allow=always', 'submodule', 'update', '--', path], tree, log)
        run(['git', 'config', f'submodule.{name}.url', urls[path]], tree, log, check=True)
        run(['git', '-C', path, 'remote', 'set-url', 'origin', urls[path]], tree, log, check=True)
        if cloned:
            # The gitlink is a commit the local module repository lacks (a regeneration commit an earlier
            # gate pushed, or one made in another worktree): fetch exactly that commit from the remote.
            gitlink = out(['git', 'ls-tree', 'HEAD', '--', path], tree).split()[2]
            run(['git', '-C', path, 'fetch', '--quiet', 'origin', gitlink], tree, log, check=True)
            run(['git', '-C', path, 'checkout', '--quiet', '--detach', gitlink], tree, log, check=True)
        drop_refs(tree / path, log)
    if web_sha:
        run(['git', '-C', WEB_PATH, 'fetch', '--quiet', 'origin', '+refs/heads/renovate/*:refs/remotes/origin/renovate/*'],
            tree, log, check=True)
        run(['git', '-C', WEB_PATH, 'checkout', '--quiet', '--detach', web_sha], tree, log, check=True)
        drop_refs(tree / WEB_PATH, log)


def submodule_paths(tree: Path) -> list[str]:
    return [line.split()[1] for line in out(['git', 'submodule', 'status'], tree).splitlines()
            if not line.startswith('-')]


def commit_all(tree: Path, branch: str, log: Path) -> None:
    """Commit regenerated files in each changed submodule, then the root (files and gitlinks)."""
    for path in submodule_paths(tree):
        if out(['git', '-C', path, 'status', '--porcelain'], tree):
            run(['git', '-C', path, 'add', '-A'], tree, log, check=True)
            run(['git', '-C', path, 'commit', '-q', '-m', f'chore(deps): regenerate for {branch}'], tree, log,
                check=True)
    if out(['git', 'status', '--porcelain', '--ignore-submodules=none'], tree):
        run(['git', 'add', '-A'], tree, log, check=True)
        run(['git', 'commit', '-q', '-m', f'chore(deps): complete {branch} (derived pins, lockfiles, gitlinks)'],
            tree, log, check=True)


def moved_submodules(tree: Path, base: str) -> dict[str, str]:
    """Submodule path -> its commit at base, for every gitlink that differs between base and HEAD."""
    moved = {}
    for path in submodule_paths(tree):
        old = out(['git', 'ls-tree', base, '--', path], tree).split()
        new = out(['git', 'ls-tree', 'HEAD', '--', path], tree).split()
        if old != new:
            moved[path] = old[2] if len(old) >= 3 else ''
    return moved


def changed_paths(tree: Path, base: str) -> list[str]:
    """Paths changed between base and HEAD, with submodule contents expanded to <submodule>/<path>."""
    moved = moved_submodules(tree, base)
    paths = [p for p in out(['git', 'diff', '--name-only', base, 'HEAD'], tree).splitlines() if p not in moved]
    for path, old in moved.items():
        inner = out(['git', '-C', path, 'diff', '--name-only', old, 'HEAD'], tree) if old else ''
        paths += [f'{path}/{p}' for p in inner.splitlines()] or [path]
    return sorted(set(paths))


def uncommitted_paths(tree: Path) -> list[str]:
    """Working-tree changes of the root and every submodule, as root-relative paths."""
    paths = []
    for prefix in ['', *(p + '/' for p in submodule_paths(tree))]:
        status = out(['git', '-C', prefix or '.', 'status', '--porcelain', '--untracked-files=all',
                      '--ignore-submodules=all'], tree)
        paths += [prefix + line[3:].split(' -> ')[-1] for line in status.splitlines()]
    return paths


def text_at(tree: Path, base: str, path: str, moved: dict[str, str]) -> str | None:
    """A file's text at base (None when absent), reading a submodule file at the submodule's base commit."""
    top, _, rest = path.partition('/')
    if rest and top in moved:
        if not moved[top]:
            return None
        args = ['git', '-C', str(tree / top), 'show', f'{moved[top]}:{rest}']
    else:
        args = ['git', '-C', str(tree), 'show', f'{base}:{path}']
    result = subprocess.run(args, capture_output=True, text=True, env=with_git_safety(None), check=False)
    return result.stdout if result.returncode == 0 else None


def text_now(tree: Path, path: str) -> str | None:
    file = tree / path
    return file.read_text(errors='replace') if file.is_file() and not file.is_symlink() else None


def is_protected(path: str) -> bool:
    return any(path == p or (p.endswith('/') and path.startswith(p)) for p in PROTECTED)


def protected_changes(tree: Path, base: str) -> list[str]:
    """Changes between base and the candidate's working tree that touch a gate input."""
    moved = moved_submodules(tree, base)
    problems = []
    for path in sorted(set(changed_paths(tree, base) + uncommitted_paths(tree))):
        if path != 'toolchain-manifest.yaml' and path != f'{WEB_PATH}/package.json' and not is_protected(path):
            continue
        old, new = text_at(tree, base, path, moved), text_now(tree, path)
        if path == 'toolchain-manifest.yaml':
            if gate_tools(old) != gate_tools(new):
                problems.append(f'{path}: gate_tools changed (their digests are refreshed by a person)')
        elif path == f'{WEB_PATH}/package.json':
            if package_rest(old) != package_rest(new):
                problems.append(f'{path}: a field other than the dependency fields changed')
        elif old is None or new is None or IMAGE_PIN.sub('<image>', old) != IMAGE_PIN.sub('<image>', new):
            problems.append(f'{path}: gate input changed')
    return problems


def gate_tools(text: str | None) -> str:
    match = GATE_TOOLS_BLOCK.search(text or '')
    return match.group(0) if match else ''


def package_rest(text: str | None) -> dict | None:
    try:
        document = json.loads(text) if text else None
    except ValueError:
        return {'unparsable': text}
    return {k: v for k, v in document.items() if k not in PACKAGE_DEPENDENCY_FIELDS} if document else None


# ---------------------------------------------------------------- gates

def copy_sources(dockerfile: Path) -> list[str]:
    """Build-context sources of a Dockerfile's COPY/ADD lines ('.' when it copies the whole context) and
    of its RUN --mount=type=bind mounts from the context."""
    sources = []
    for line in re.sub(r'\\\n', ' ', dockerfile.read_text()).splitlines():
        words = line.split()
        if words and words[0].upper() == 'RUN':
            for word in words[1:]:
                if not word.startswith('--mount='):
                    break
                options = dict(part.partition('=')[::2] for part in word[len('--mount='):].split(','))
                if options.get('type') == 'bind' and 'from' not in options:
                    sources.append((options.get('source') or options.get('src') or '.').rstrip('/') or '.')
            continue
        if not words or words[0].upper() not in ('COPY', 'ADD'):
            continue
        if any(w.startswith('--from=') for w in words[1:]):
            continue
        args = [w for w in words[1:] if not w.startswith('--')]
        sources += [a.rstrip('/') or '.' for a in args[:-1]]
    return sources


def touched_images(root: Path, tree: Path, paths: list[str]) -> list[str]:
    """Release images whose Dockerfile or COPY sources changed: this checkout's image inventory
    (chronicle_ops.images.SOURCE_IMAGES, imported from root, never from the candidate), the
    candidate's Dockerfiles read as text."""
    sys.path.insert(0, str(root / 'selfhost'))
    try:
        from chronicle_ops.images import SOURCE_IMAGES
    finally:
        sys.path.pop(0)
    submodules = set(submodule_paths(tree))
    touched = []
    for image in SOURCE_IMAGES:
        context = os.path.normpath('selfhost/' + image.context)
        dockerfile = os.path.normpath('selfhost/' + image.dockerfile)
        prefix = '' if context == '.' else context + '/'
        sources = [os.path.normpath(prefix + s) for s in copy_sources(tree / dockerfile)]
        for path in paths:
            top = path.split('/', 1)[0]
            archived = top not in submodules or top in image.submodules  # what archive_source puts in the context
            if path == dockerfile or (archived and any(
                    s == '.' or path == s or path.startswith(s + '/') for s in sources)):
                touched.append(image.component)
                break
    if 'frontend' in touched and 'caddy' not in touched:
        touched.append('caddy')  # caddy serves the frontend's build output
    return touched


# local-ci security jobs that query a live database (npm audit, OSV, GitHub releases, Bearer's rules) and
# run only checksum-pinned tools and this checkout's scripts: the only ones with a network. Every other
# job runs with none, the ones that build or test (dependency code) after all the scanners.
ONLINE_JOBS = ('bun-audit', 'deps-freshness', 'bearer', 'osv')
DEPENDENCY_CODE_JOBS = ('engineering', 'gradle-depcheck')
FUZZ_JOB = 'fuzz'


def security_jobs(root: Path) -> list[str]:
    match = re.search(r'^security_jobs=\(([^)]*)\)', (root / 'scripts/local-ci.sh').read_text(), re.MULTILINE)
    if not match:
        raise SystemExit('dependency-gate: scripts/local-ci.sh has no security_jobs')
    return [job for job in match.group(1).split() if job != 'dependency-age']  # the age gate runs on its own


@functools.cache
def docker_host() -> str:
    if os.environ.get('DOCKER_HOST'):
        return os.environ['DOCKER_HOST']
    host = out(['docker', 'context', 'inspect', '--format', '{{.Endpoints.docker.Host}}'], Path.cwd())
    if not host:
        raise SystemExit('dependency-gate: cannot resolve the Docker endpoint (docker context inspect)')
    return host


def gate_docker_config(work: Path) -> Path:
    """A Docker client configuration with the CLI plugin directories (buildx) and nothing else: no auths,
    no credsStore, no credHelpers. Without a docker CLI on PATH (the sandbox that runs this checkout's tests)
    there is no plugin directory to list; a gate run still fails at its first sandboxed step."""
    plugins = '' if shutil.which('docker') is None else out(
        ['docker', 'info', '--format', '{{range .ClientInfo.Plugins}}{{.Path}}{{"\\n"}}{{end}}'],
        Path.cwd(), check=False)
    directories = sorted({str(Path(p).resolve().parent) for p in plugins.splitlines() if p.strip()})
    config = work / 'docker-config'
    config.mkdir(parents=True, exist_ok=True)
    (config / 'config.json').write_text(json.dumps({'cliPluginsExtraDirs': directories}, indent=2) + '\n')
    return config


def robust_fetch_dir() -> str:
    library = Path(os.environ.get('ROBUST_FETCH_DIR', Path.home() / 'agent-skills' / 'lib'))
    if not (library / 'robust_fetch.py').is_file():
        raise SystemExit(f'dependency-gate: robust_fetch.py not found in {library} (set ROBUST_FETCH_DIR)')
    return str(library)


def host_env(work: Path, base: str) -> dict[str, str]:
    """The whole environment of a host gate step, built from nothing: no credential, an empty home.

    Only this checkout's code runs with it (the age gate, the regeneration driver, the image gate).
    It reaches the Docker daemon with a client configuration that holds no registry credential."""
    home = work / 'home'
    for directory in (home, work / 'tmp', work / 'cache', work / 'bin'):
        directory.mkdir(parents=True, exist_ok=True)
    return {
        'PATH': os.environ.get('PATH', '/usr/bin:/bin'),
        'HOME': str(home),
        'TMPDIR': str(work / 'tmp'),
        'XDG_CACHE_HOME': str(work / 'cache'),
        'LANG': os.environ.get('LANG', 'C.UTF-8'),
        'DOCKER_HOST': docker_host(),
        'DOCKER_CONFIG': str(gate_docker_config(work)),
        'ROBUST_FETCH_DIR': robust_fetch_dir(),
        'CHRONICLE_DEPENDENCY_BASE': base,
        'CHRONICLE_LOCAL_BIN_DIR': str(work / 'bin'),
        'CHRONICLE_LOCAL_CI_KEEP_GOING': '1',
        'TRIVY_CACHE_DIR': str(work / 'cache' / 'trivy'),
    }


@dataclasses.dataclass
class Step:
    name: str
    commands: list[list[str]]
    env: dict[str, str]
    cwd: Path | None = None  # default: the candidate tree

    @property
    def sandboxed(self) -> bool:
        return all(len(c) > 1 and c[1].endswith('/deps-sandbox.sh') for c in self.commands)


def sandbox(root: Path, source: Path, command: list[str], network: str, env: dict[str, str] | None = None,
            mounts: tuple[str, ...] = (), platform: str | None = None) -> list[str]:
    """A command for the gate sandbox over source, with this checkout's scripts/ and tests/ (gate inputs, the
    candidate may not change them) in place of the candidate's, so the jobs and the tests of the scripts
    they run agree."""
    args = ['bash', str(root / 'scripts/deps-sandbox.sh'), '--image', 'gate', '--network', network,
            '--mount', f'{root / "scripts"}:/work/scripts:ro', '--mount', f'{root / "tests"}:/work/tests:ro']
    if platform:
        args += ['--platform', platform]
    for mount in mounts:
        args += ['--mount', mount]
    for key, value in (env or {}).items():
        args += ['--env', f'{key}={value}']
    return args + [str(source), '--', *command]


def snapshot(source: Path, target: Path) -> None:
    """A copy for the sandbox (an APFS clone, so it costs no space). The sandbox never sees the
    candidate itself, whose git directories the runner commits and pushes from."""
    if target.exists():
        shutil.rmtree(target)
    target.parent.mkdir(parents=True, exist_ok=True)
    clone = ['cp', '-cR'] if sys.platform == 'darwin' else ['cp', '-a', '--reflink=auto']
    subprocess.run([*clone, str(source), str(target)], check=True)


def nvd_data(work: Path) -> Path | None:
    """A private copy of the workstation's NVD database for gradle-depcheck (SKIP_NVD_UPDATE=1): the
    sandbox has no NVD key and must not write into the shared copy."""
    shared = Path(os.environ.get('CHRONICLE_DEPCHECK_DATA_DIR', Path.home() / '.cache/chronicle/dependency-check-data'))
    if not shared.is_dir():
        return None
    snapshot(shared, work / 'sandbox-nvd')
    return work / 'sandbox-nvd'


def fresh_dir(path: Path) -> Path:
    if path.exists():
        shutil.rmtree(path)
    path.mkdir(parents=True)
    return path


def gate_steps(root: Path, tree: Path, paths: list[str], logs: Path, work: Path, base: str) -> list[Step]:
    """The gates for a complete candidate. Each sandboxed step gets a fresh copy of the candidate (run_steps),
    so nothing one step's dependency code writes reaches another step."""
    env = host_env(work, base)
    snap = work / 'sandbox'
    reports = logs / 'reports'
    reports.mkdir(parents=True, exist_ok=True)
    nvd = nvd_data(work)
    # The candidate's requirements-dev.txt (scripts/ and tests/ need it), installed from hashes into a fresh
    # directory that Dockerfile.gate puts first on PATH: written by the python step, read-only after it.
    python = fresh_dir(work / 'gate-python')
    python_ro = f'{python}:/gate-python:ro'
    # The security tools local-ci downloads (checksum-pinned) and grype's database. Kept between runs and
    # written only by the tools step, which runs local-ci's downloads and nothing of the candidate's.
    tools = work / 'gate-tools'
    tools.mkdir(parents=True, exist_ok=True)
    tools_ro = f'{tools}:/gate-tools:ro'
    # GitHub release lookups for deps-freshness, made by this checkout's script with the runner's gh login
    # (the repositories are named in that script, nothing comes from the candidate); the sandbox reads them.
    github = fresh_dir(work / 'github-api')
    # check-python-dev-pins.py (verify-toolchain, engineering) requires the workstation's robust_fetch.py.
    fetch_ro = f'{Path(robust_fetch_dir()) / "robust_fetch.py"}:/robust-fetch/robust_fetch.py:ro'
    tool_env = {'CHRONICLE_LOCAL_BIN_DIR': '/gate-tools', 'ROBUST_FETCH_DIR': '/robust-fetch', 'GRYPE_DB_CACHE_DIR': '/gate-tools/grype-db',
                'GRYPE_DB_AUTO_UPDATE': 'false', 'GRYPE_CHECK_FOR_APP_UPDATE': 'false',
                'SYFT_CHECK_FOR_APP_UPDATE': 'false'}
    job_env = dict(tool_env, CHRONICLE_LOCAL_CI_KEEP_GOING='1', CHRONICLE_LOCAL_CI_REPORT_DIR='/reports',
                   CHRONICLE_DEPENDENCY_BASE=base)
    jobs = security_jobs(root)
    scan = [job for job in jobs if job in ONLINE_JOBS]
    offline = ([job for job in jobs if job not in ONLINE_JOBS + DEPENDENCY_CODE_JOBS + (FUZZ_JOB,)]
               + [job for job in jobs if job in DEPENDENCY_CODE_JOBS])
    fuzz = [job for job in jobs if job == FUZZ_JOB]
    local_ci = ['bash', 'scripts/local-ci.sh']
    steps = [Step('age', [['python3', str(root / 'scripts/check-dependency-age.py'), '--root', str(tree), '--base', base,
                           '--cache', str(work / 'age-cache.json'), '--report', str(logs / 'age-report.txt')]], env),
             Step('python', [
                 sandbox(root, snap, ['uv', 'venv', '--quiet', '--python', '/usr/bin/python3', '/gate-python'], 'none',
                         mounts=(f'{python}:/gate-python',)),
                 sandbox(root, snap, ['uv', 'pip', 'install', '--quiet', '--python', '/gate-python/bin/python',
                                      '--require-hashes', '--only-binary', ':all:', '-r', 'requirements-dev.txt'],
                         'registries', {'UV_CACHE_DIR': '/cache/uv'}, (f'{python}:/gate-python',))], env),
             Step('tools', [sandbox(root, snap, [*local_ci, 'gate-tools'], 'registries',
                                    dict(tool_env, GRYPE_DB_AUTO_UPDATE='true'), (f'{tools}:/gate-tools',))], env),
             Step('github', [['bash', str(root / 'scripts/deps-freshness.sh'), '--fetch-github', str(github)]],
                  dict(os.environ), cwd=root),
             Step('toolchain', [sandbox(root, snap, ['bash', 'scripts/verify-toolchain.sh'], 'none',
                                        {'ROBUST_FETCH_DIR': '/robust-fetch'}, (python_ro, fetch_ro))], env),
             Step('scan', [sandbox(root, snap, [*local_ci, *scan], 'registries',
                                   dict(job_env, CHRONICLE_GITHUB_API_CACHE='/github-api',
                                        BEARER_DISABLE_VERSION_CHECK='true'),
                                   (f'{reports}:/reports', tools_ro, python_ro, fetch_ro,
                                    f'{github}:/github-api:ro'))], env),
             # Downloads what the offline builds resolve: every resolvable configuration, as dependency
             # verification would record them (--dry-run writes only a .dryrun.xml in this step's copy). The
             # offline steps verify each artifact against the candidate's verification-metadata.xml.
             Step('gradle', [sandbox(root, snap, ['./gradlew', '--no-daemon', '--console=plain',
                                                  '--write-verification-metadata', 'sha256', '--dry-run', 'help'],
                                     'registries')], env),
             Step('security', [sandbox(root, snap, [*local_ci, *offline], 'none',
                                       dict(job_env, SKIP_NVD_UPDATE='1', CHRONICLE_DEPCHECK_DATA_DIR='/nvd'),
                                       (f'{reports}:/reports', tools_ro, python_ro, fetch_ro)
                                       + ((f'{nvd}:/nvd',) if nvd else ()))], env)]
    if fuzz:
        # Jazzer ships no linux/aarch64 native library.
        steps.append(Step('fuzz', [sandbox(root, snap, [*local_ci, *fuzz], 'none', platform='linux/amd64')], env))
    if any(p.startswith(WEB_PATH + '/') for p in paths):
        steps.append(Step('web', [
            sandbox(root, snap, ['bun', 'install', '--cwd', WEB_PATH, '--frozen-lockfile', '--ignore-scripts'],
                    'registries'),
            sandbox(root, snap, [*local_ci, 'web'], 'none',
                    dict(tool_env, CHRONICLE_WEB_AUDIT='0', CHRONICLE_LOCAL_CI_REPORT_DIR='/reports'),
                    (f'{reports}:/reports', tools_ro, python_ro, fetch_ro))],
            env))
    images = touched_images(root, tree, paths)
    runtime = any(RUNTIME_INVENTORY.match(p) for p in paths)
    if images or runtime:
        steps.append(Step('images', [['bash', str(root / 'scripts/local-ci.sh'), 'image-gate']],
                          dict(env, CHRONICLE_IMAGE_GATE_SOURCE=str(tree),
                               CHRONICLE_IMAGE_GATE_COMPONENTS=' '.join(images) or 'none',
                               CHRONICLE_IMAGE_GATE_RUNTIME='1' if runtime else '0')))
    return steps


def run_steps(steps: list[Step], tree: Path, work: Path, logs: Path) -> list[str]:
    """Run each step's commands in order (a step stops at its first failing command); the failed step names."""
    failed = []
    for step in steps:
        if step.sandboxed:
            snapshot(tree, work / 'sandbox')
        for command in step.commands:
            code = run(command, step.cwd or tree, logs / f'{step.name}.log', step.env)
            if code:
                failed.append('age-indeterminate' if step.name == 'age' and code == 2 else step.name)
                break
    return failed


def gate_branch(root: Path, work: Path, repo: str, branch: str, sha: str, base: str, dry_run: bool,
                local: bool = False) -> list[str] | None:
    """Gate one candidate against the trusted base: the failed gates, [] when it passed (and was pushed
    unless dry_run), None when it was skipped. local: sha and base are already in this checkout."""
    logs = work / 'logs' / f'{branch.replace("/", "_")}-{sha[:12]}'
    logs.mkdir(parents=True, exist_ok=True)
    log = logs / 'git.log'
    tree = work / 'candidate'
    if repo == ROOT_REPO:
        if not local:
            run(['git', 'fetch', '--quiet', 'origin', f'refs/heads/{branch}'], root, log, check=True)
        if not is_ancestor(root, base, sha):
            print(f'{repo} {branch} {sha[:12]}: skipped, does not contain the trusted {BASE} (Renovate rebases it)')
            return None
        prepare(root, tree, sha, None, log)
    else:
        prepare(root, tree, base, sha, log)
        web_base = out(['git', 'ls-tree', base, '--', WEB_PATH], tree).split()[2]
        if not is_ancestor(tree / WEB_PATH, web_base, sha):
            print(f'{repo} {branch} {sha[:12]}: skipped, does not contain the trusted {BASE} (Renovate rebases it)')
            return None
    env = host_env(work, base)
    failed = []
    problems = protected_changes(tree, base)
    if problems:
        (logs / 'protected.txt').write_text('\n'.join(problems) + '\n')
        failed.append('protected')
    else:
        # Nothing from the update runs before the age gate has passed on Renovate's own change.
        code = run(['python3', str(root / 'scripts/check-dependency-age.py'), '--root', str(tree), '--base', base,
                    '--cache', str(work / 'age-cache.json'), '--report', str(logs / 'age-renovate.txt')],
                   tree, logs / 'age-renovate.log', env)
        if code:
            failed.append('age-indeterminate' if code == 2 else 'age')
        else:
            if run(['python3', str(root / 'scripts/deps-regenerate.py'), '--root', str(tree), '--base', base,
                    '--scratch', str(work / 'regenerate')], tree, logs / 'regenerate.log', env):
                failed.append('regenerate')
            commit_all(tree, branch, log)
            problems = protected_changes(tree, base)
            if problems:
                (logs / 'protected.txt').write_text('\n'.join(problems) + '\n')
                failed.append('protected')
            else:
                paths = changed_paths(tree, base)
                (logs / 'changed-paths.txt').write_text('\n'.join(paths) + '\n')
                failed += run_steps(gate_steps(root, tree, paths, logs, work, base), tree, work, logs)
    state = 'error' if failed and set(failed) <= {'age-indeterminate'} else 'failure' if failed else 'success'
    description = (f'failed: {", ".join(failed)}' if failed
                   else 'passed: protected, age, MAL-, toolchain, security, web, images')
    print(f'{repo} {branch} {sha[:12]}: {state}, {description} (logs {logs})', flush=True)
    if not dry_run:
        if not failed:
            for path in moved_submodules(tree, base):
                push(tree / path, out(['git', '-C', path, 'rev-parse', 'HEAD'], tree), push_url(root, path), work)
            head = out(['git', 'rev-parse', 'HEAD'], tree)
            push(tree, head, push_url(root, ''), work)
            recorded = load_state()
            recorded['trusted_base'] = head
            save_state(recorded)
        post_status(repo, sha, state, description)
    return failed


def init_base(root: Path, ref: str) -> int:
    commit = out(['git', 'rev-parse', f'{ref}^{{commit}}'], root)
    work = work_dir()
    if BASE in remote_heads(root, 'origin'):
        print(f'{ROOT_REPO} already has {BASE}')
    else:
        push(root, commit, push_url(root, ''), work)
    web = root / WEB_PATH
    web_sha = out(['git', 'ls-tree', commit, '--', WEB_PATH], root).split()[2]
    if BASE in remote_heads(web, 'origin'):
        print(f'{WEB_REPO} already has {BASE}')
    else:
        push(web, web_sha, push_url(root, WEB_PATH), work)
    return trust_base(root, commit)


def trust_base(root: Path, ref: str) -> int:
    commit = out(['git', 'rev-parse', f'{ref}^{{commit}}'], root)
    state = load_state()
    state['trusted_base'] = commit
    save_state(state)
    print(f'dependency-gate: trusted {BASE} is {commit}')
    return 0


def work_dir() -> Path:
    work = Path(os.environ.get('CHRONICLE_DEPENDENCY_GATE_WORK',
                               Path.home() / 'Library/Caches/chronicle-dependency-gate')).resolve()
    work.mkdir(parents=True, exist_ok=True)
    return work


def cleanup(work: Path) -> None:
    for name in ('candidate', 'sandbox', 'sandbox-nvd', 'regenerate', 'gate-python', 'github-api'):
        if (work / name).exists():
            shutil.rmtree(work / name)


def record_result(key: str, failed: list[str], current: str) -> dict:
    state = load_state()
    previous = state['candidates'].get(key, {})
    attempts = previous.get('attempts', 0) + 1 if previous.get('fingerprint') == current else 1
    state['candidates'][key] = {'failed': failed, 'fingerprint': current, 'attempts': attempts,
                                'at': dt.datetime.now(dt.UTC).isoformat()}
    save_state(state)
    return state


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument('--branch', help='gate only this renovate/* branch')
    parser.add_argument('--dry-run', action='store_true', help='gate, but post no status, push or record nothing')
    parser.add_argument('--init-base', metavar='REF', help=f'create {BASE} at REF, trust it and exit')
    parser.add_argument('--trust-base', metavar='REF', help=f'record REF as the trusted {BASE} and exit')
    parser.add_argument('--candidate', metavar='REF',
                        help='gate this local root commit against --base-ref instead of the remote branches '
                             '(implies --dry-run)')
    parser.add_argument('--base-ref', metavar='REF', help='base for --candidate')
    args = parser.parse_args(argv)
    root = args.root.resolve()
    if args.init_base:
        return init_base(root, args.init_base)
    if args.trust_base:
        return trust_base(root, args.trust_base)
    work = work_dir()
    started = time.monotonic()
    if args.candidate:
        if not args.base_ref:
            parser.error('--candidate needs --base-ref')
        sha = out(['git', 'rev-parse', f'{args.candidate}^{{commit}}'], root)
        base = out(['git', 'rev-parse', f'{args.base_ref}^{{commit}}'], root)
        try:
            failed = gate_branch(root, work, ROOT_REPO, args.candidate, sha, base, True, local=True)
        finally:
            cleanup(work)
        print(f'dependency-gate: candidate {"passed" if failed == [] else "failed"}, '
              f'{time.monotonic() - started:.0f}s')
        return 0 if failed == [] else 1
    heads = {repo: remote_heads(cwd, 'origin') for repo, cwd in ((ROOT_REPO, root), (WEB_REPO, root / WEB_PATH))}
    for repo, branches in heads.items():
        if BASE not in branches:
            print(f'dependency-gate: {repo} has no {BASE}; create it with --init-base REF', file=sys.stderr)
            return 1
    run(['git', 'fetch', '--quiet', 'origin', f'+refs/heads/{BASE}:refs/remotes/origin/{BASE}'], root, check=True)
    state = load_state()
    base = trusted_base(root, state, heads[ROOT_REPO][BASE])
    current = fingerprint(root, base)
    results = []
    for repo, branches in heads.items():
        for branch, sha in sorted(branches.items()):
            if branch == BASE or (args.branch and branch != args.branch):
                continue
            key = f'{repo}@{sha}'
            if not should_gate(gate_status(repo, sha), state['candidates'].get(key), current):
                continue
            try:
                failed = gate_branch(root, work, repo, branch, sha, base, args.dry_run)
            finally:
                cleanup(work)
            if failed is None:
                continue
            results.append(not failed)
            if not args.dry_run:
                state = record_result(key, failed, current)
                if not failed:
                    base = state['trusted_base']
                    current = fingerprint(root, base)
    print(f'dependency-gate: {sum(results)} passed, {len(results) - sum(results)} failed, '
          f'{time.monotonic() - started:.0f}s')
    return 0 if all(results) else 1


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
