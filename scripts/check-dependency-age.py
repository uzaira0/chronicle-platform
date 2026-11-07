#!/usr/bin/env python3
"""Refuse dependency versions that are too new, newly added without review, or known malicious.

Supply-chain policy (docs/SUPPLY-CHAIN.md). Compares every lockfile and pin file in the root
repository and its initialised submodules (working tree, so uncommitted edits count) with the same
files at a base ref, and for every entry that is new or changed:

  - its registry publish time must be older than the wait for that update:
      7 days routine, 14 days for a major version change, 3 days when the old version has an OSV
      advisory the new one does not (a security fix);
    unless dependency-exceptions.toml lists that exact version with a reviewer, a note and an
    expiry no more than 30 days ahead;
  - a package name the base did not have needs an entry in dependency-additions.toml (a lockfile
    approval admits only the names that file held at the reviewed `revision`);
  - an npm package from anywhere but the npm registry (git, github, tarball URL, another registry,
    link:, a path outside the repository) has no registry publish time: it needs a reviewed
    dependency-additions.toml row naming that exact source (ecosystem "npm-source");
  - a publish time that only the publisher asserts (an OCI image's own `created`) does not count:
    such an entry needs an exception.

Every current npm, Maven, Go and PyPI entry, changed or not, is also checked against OSV (every
result page), and any MAL- (malicious package) advisory on a version the candidate holds fails. No
exception can admit a MAL- hit. A malicious version being removed does not block its replacement.

    check-dependency-age.py [--root DIR] [--base REF] [--today YYYY-MM-DD]
                            [--lookup-fixture FILE] [--cache FILE] [--report FILE]
    check-dependency-age.py --print-policy     # the waits as JSON; every other copy is tested against it

Files read: bun.lock, gradle.lockfile, gradle/verification-metadata.xml, go.sum, requirements*.txt,
gradle-wrapper.properties, Dockerfile* FROM lines and OS-package pins (scripts/os_packages.py: Alpine,
Debian/Ubuntu and RPM packages installed through selfhost/os-packages/), compose `image:` lines and
toolchain-manifest.yaml.
A changed toolchain-manifest key with no known publish-time source fails closed.

Publish times come from the registries themselves (npm `time`, Maven Central's index timestamp or
the repository's Last-Modified, PyPI upload time, Docker Hub tag_last_pushed while the tag holds the
pinned digest, Quay start_ts for that digest, GitHub release published_at, services.gradle.org).
A Go version is dated by index.golang.org's Timestamp, the time proxy.golang.org first cached it, because
the module proxy's own .info Time is the commit time. Fetches go
through ~/agent-skills/lib/robust_fetch.py (retries, IPv4/IPv6, deadline); a lookup that fails is
indeterminate and fails the run (exit 2). --lookup-fixture replaces every network lookup with a JSON
file of the same answers, for tests.

Exit 0 when every entry passes, 1 on a policy failure, 2 when a lookup could not be answered.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import dataclasses
import datetime as dt
import json
import os
import re
import subprocess
import sys
import threading
import time
import tomllib
import urllib.parse
import xml.etree.ElementTree as ET
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import os_packages  # scripts/os_packages.py: OS-package pins in Dockerfiles

# The policy numbers. This file owns them: renovate.json, chronicle-web/bunfig.toml, docs/SUPPLY-CHAIN.md
# and the scripts that quote them are checked against `--print-policy` by
# tests/quality/test_check_dependency_age.py (PolicyNumberTests), so a change here fails until they agree.
ROUTINE_DAYS = 7
MAJOR_DAYS = 14
SECURITY_DAYS = 3
MAX_EXCEPTION_DAYS = 30
# Go dating (Lookups._time_go). The search narrows to GO_LOCATE_WINDOW in at most GO_SEARCH_PROBES probes,
# then reads index.golang.org pages (2000 versions each, about an hour of the feed in 2026) from
# GO_INDEX_LEAD before the window, at most GO_INDEX_PAGES of them. The lead covers versions the checksum
# log and the proxy took in a slightly different order.
GO_LOCATE_WINDOW = dt.timedelta(minutes=10)
GO_INDEX_LEAD = dt.timedelta(minutes=10)
GO_INDEX_PAGES = 4
GO_SEARCH_PROBES = 60
GO_INDEX_START = '2019-04-10T19:08:52Z'  # the feed's first row
GO_WORKERS = 4
# index.golang.org answers HTTP 429 to several parallel clients (measured 2026-11-06); the threads share
# one spacing between index requests, doubled (to GO_INDEX_MAX_INTERVAL) by each 429 and eased back by each
# answer, and a 429 that outlasts robust_fetch's retries waits GO_INDEX_COOLDOWN seconds.
GO_INDEX_INTERVAL = 0.25
GO_INDEX_MAX_INTERVAL = 4.0
GO_INDEX_COOLDOWN = (10.0, 30.0, 60.0)
# The only cache sources still trusted for an ecosystem whose dating changed: older cache rows for Go hold
# the commit time ('proxy.golang.org') or a witness time ('sum.golang.org, first witnessed').
CACHE_SOURCES = {'go': {'index.golang.org first cached'}}


def policy_numbers() -> dict[str, int]:
    return {'routine_days': ROUTINE_DAYS, 'major_days': MAJOR_DAYS, 'security_days': SECURITY_DAYS,
            'exception_days': MAX_EXCEPTION_DAYS}
DEADLINE_SECONDS = 900
OSV_ECOSYSTEMS = {'npm': 'npm', 'maven': 'Maven', 'go': 'Go', 'pypi': 'PyPI'}
OSV_MAX_PAGES = 50
# Images this project builds and publishes itself; their age is the release's, not a dependency's.
OWN_IMAGE_PREFIXES = ('ghcr.io/uzaira0/',)
# Gate tools in toolchain-manifest.yaml: GitHub repository and release tag for a version.
GATE_TOOL_RELEASES = {
    'container-structure-test': ('GoogleContainerTools/container-structure-test', '{v}'),
    'hadolint': ('hadolint/hadolint', '{v}'),
    'ast-grep': ('ast-grep/ast-grep', '{v}'),
    'pmd': ('pmd/pmd', 'pmd_releases/{v}'),
    'bearer': ('Bearer/bearer', 'v{v}'),
    'osv-scanner': ('google/osv-scanner', '{v}'),
    'grype': ('anchore/grype', 'v{v}'),
    'syft': ('anchore/syft', 'v{v}'),
    'detekt-cli': ('detekt/detekt', 'v{v}'),
}
# toolchain-manifest.yaml keys that are not dependency pins (floors, policy, platform).
MANIFEST_NON_PINS = re.compile(r'^(jdk\.|python$|release_platform$|freshness\.)')


class LookupError_(RuntimeError):
    """A registry or OSV question that could not be answered: indeterminate, never a pass."""


@dataclasses.dataclass(frozen=True, order=True)
class Entry:
    ecosystem: str  # npm, npm-source, maven, go, pypi, oci, gradle-dist, github-release, asset-digest, apk, deb, rpm
    name: str
    version: str
    path: str = dataclasses.field(compare=False, default='')

    @property
    def key(self) -> str:
        return f'{self.ecosystem}:{self.name}@{self.version}'


# ---------------------------------------------------------------- parsers

GRADLE_LOCK = re.compile(r'^([^#=\s:]+):([^#=\s:]+):([^#=\s:]+)=', re.MULTILINE)
GO_SUM = re.compile(r'^(\S+) (v[^\s/]+)(?:/go\.mod)? h1:', re.MULTILINE)
REQUIREMENT = re.compile(r'^([A-Za-z0-9][A-Za-z0-9_.-]*)(?:\[[^\]]*\])?==([^\s;\\]+)', re.MULTILINE)
FROM_LINE = re.compile(r'^\s*FROM\s+(?:--platform=\S+\s+)?(\S+)', re.MULTILINE | re.IGNORECASE)
IMAGE_LINE = re.compile(r'^\s*image:\s*["\']?([^\s"\'#]+)', re.MULTILINE)
WRAPPER_URL = re.compile(r'^distributionUrl=.*gradle-([0-9][^-/]*)-(?:bin|all)\.zip', re.MULTILINE)


def parse_bun_lock(text: str, path: str) -> set[Entry]:
    """npm registry entries, and every other source as an `npm-source` entry that needs a review.

    bun.lock is JSON with trailing commas. A package entry is [name@spec, registry, {..}, integrity]
    for the npm registry (registry "" is the default one) and [name@spec, {..}, ...] for git, github,
    tarball, file, link and workspace specs. Only workspace: and file: paths that stay inside the
    repository are local code; a non-default registry, git, github, tarball URL, link: or a path
    leaving the repository is a remote source with no registry publish time, so it is never aged
    and never dropped: it fails until dependency-additions.toml names that exact source.
    """
    try:
        packages = json.loads(re.sub(r',(\s*[}\]])', r'\1', text)).get('packages', {})
    except ValueError as error:
        raise SystemExit(f'error: {path} is not a readable bun.lock ({error}); nothing in it can be checked')
    found = set()
    base = path.rsplit('/', 1)[0] if '/' in path else ''
    for value in packages.values():
        if not isinstance(value, list) or not value or not isinstance(value[0], str) or '@' not in value[0][1:]:
            raise SystemExit(f'error: {path} has a package entry this gate cannot read: {value!r:.120}')
        name, _, spec = value[0].rpartition('@')
        registry = value[1] if len(value) > 1 and isinstance(value[1], str) else None
        if registry is not None and not re.match(r'[a-z+]+:', spec):
            if registry:
                found.add(Entry('npm-source', name, f'{spec} {registry}', path))
            else:
                found.add(Entry('npm', name, spec, path))
            continue
        local = re.match(r'(workspace|file):(.*)$', spec)
        if local and not local.group(2).startswith('/'):
            inside = os.path.normpath(os.path.join(base, local.group(2)))
            if inside != '..' and not inside.startswith('../'):
                continue  # code in this repository, reviewed as code
        found.add(Entry('npm-source', name, spec, path))
    return found


def parse_gradle_lockfile(text: str, path: str) -> set[Entry]:
    return {Entry('maven', f'{g}:{a}', v, path) for g, a, v in GRADLE_LOCK.findall(text)}


def parse_verification_metadata(text: str, path: str) -> set[Entry]:
    root = ET.fromstring(text)
    found = set()
    for node in root.iter():
        if node.tag.endswith('}component') or node.tag == 'component':
            group, name, version = node.get('group'), node.get('name'), node.get('version')
            if group and name and version:
                found.add(Entry('maven', f'{group}:{name}', version, path))
    return found


def parse_go_sum(text: str, path: str) -> set[Entry]:
    return {Entry('go', module, version, path) for module, version in GO_SUM.findall(text)}


def parse_requirements(text: str, path: str) -> set[Entry]:
    return {Entry('pypi', name.lower().replace('_', '-'), version, path) for name, version in REQUIREMENT.findall(text)}


def parse_wrapper(text: str, path: str) -> set[Entry]:
    return {Entry('gradle-dist', 'gradle', version, path) for version in WRAPPER_URL.findall(text)}


def image_entry(reference: str, path: str) -> Entry | None:
    """An OCI reference pinned by digest, as Entry(oci, repository, tag@digest)."""
    if '${' in reference or '@sha256:' not in reference:
        return None
    named, digest = reference.split('@', 1)
    repository, tag = named, ''
    if ':' in named.rsplit('/', 1)[-1]:
        repository, tag = named.rsplit(':', 1)
    return Entry('oci', normalise_repository(repository), f'{tag}@{digest}', path)


def normalise_repository(repository: str) -> str:
    first = repository.split('/', 1)[0]
    if '.' not in first and ':' not in first and first != 'localhost':
        repository = 'docker.io/' + repository
    if repository.count('/') == 1 and repository.startswith('docker.io/'):
        repository = 'docker.io/library/' + repository.split('/', 1)[1]
    return repository


def parse_dockerfile(text: str, path: str) -> set[Entry]:
    images = {entry for ref in FROM_LINE.findall(text) if (entry := image_entry(ref, path))}
    return images | os_packages.parse_dockerfile(text, path, Entry)


SHELL_IMAGE = re.compile(r'''["'=\s]((?:[a-z0-9.-]+(?::\d+)?/)?[a-z0-9._/-]+:[\w.-]+@sha256:[a-f0-9]{64})''')


def parse_shell(text: str, path: str) -> set[Entry]:
    """Digest-pinned images that scripts run (scripts/flyway-migrate.sh, scripts/renovate-run.sh)."""
    return {entry for ref in SHELL_IMAGE.findall(text) if (entry := image_entry(ref, path))}


def parse_compose(text: str, path: str) -> set[Entry]:
    return {entry for ref in IMAGE_LINE.findall(text) if (entry := image_entry(ref, path))}


def flatten_simple_yaml(text: str) -> dict[str, str]:
    """Dotted keys to scalar values for the block-mapping subset toolchain-manifest.yaml uses."""
    flat: dict[str, str] = {}
    stack: list[tuple[int, str]] = []
    for raw in text.splitlines():
        line = re.sub(r'\s+#.*$', '', raw) if not raw.lstrip().startswith('#') else ''
        if not line.strip() or line.lstrip().startswith('- '):
            continue
        indent = len(line) - len(line.lstrip())
        match = re.match(r'^\s*([A-Za-z0-9_.-]+):\s*(.*)$', line)
        if not match:
            continue
        while stack and stack[-1][0] >= indent:
            stack.pop()
        key, value = match.groups()
        dotted = '.'.join([part for _, part in stack] + [key])
        if value.strip():
            flat[dotted] = value.strip().strip('"\'')
        else:
            stack.append((indent, key))
    return flat


def manifest_entries(flat: dict[str, str], path: str) -> tuple[set[Entry], set[str]]:
    """Dependency entries from toolchain-manifest.yaml, and `key=value` for pins of nothing known."""
    found, unknown = set(), set()
    for key, value in flat.items():
        if MANIFEST_NON_PINS.match(key):
            continue
        if key == 'bun':
            found.add(Entry('npm', 'bun', value, path))
        elif key == 'semgrep':
            found.add(Entry('pypi', 'semgrep', value, path))
        elif key == 'kotlin':
            found.add(Entry('maven', 'org.jetbrains.kotlin:kotlin-stdlib', value, path))
        elif key == 'flyway.version':
            found.add(Entry('maven', 'org.flywaydb:flyway-core', value, path))
        elif key in ('gradle.wrapper', 'gradle.android_wrapper'):
            found.add(Entry('gradle-dist', 'gradle', value, path))
        elif key.endswith('.image') and f'{key[:-6]}.index_digest' in flat:
            entry = image_entry(f'{value}@{flat[key[:-6] + ".index_digest"]}', path)
            found.add(entry) if entry else unknown.add(f'{key}={value}')
        elif key.endswith('.index_digest'):
            continue  # paired with .image above
        elif key.startswith('selfhost_images.'):
            entry = image_entry(value, path)
            found.add(entry) if entry else unknown.add(f'{key}={value}')
        elif key.startswith('gate_tools.') and key.endswith('.version'):
            tool = key.split('.')[1]
            if tool in GATE_TOOL_RELEASES:
                repository, tag = GATE_TOOL_RELEASES[tool]
                found.add(Entry('github-release', repository, tag.format(v=value), path))
            else:
                unknown.add(f'{key}={value}')
        elif key.startswith('gate_tools.') and '.sha256.' in key:
            found.add(Entry('asset-digest', key, value, path))
        else:
            unknown.add(f'{key}={value}')
    return found, unknown


def parse_file(name: str, text: str, path: str) -> tuple[set[Entry], set[str]]:
    if name == 'bun.lock':
        return parse_bun_lock(text, path), set()
    if name == 'gradle.lockfile':
        return parse_gradle_lockfile(text, path), set()
    if name == 'verification-metadata.xml':
        return parse_verification_metadata(text, path), set()
    if name == 'go.sum':
        return parse_go_sum(text, path), set()
    if name.startswith('requirements') and name.endswith('.txt'):
        return parse_requirements(text, path), set()
    if name == 'gradle-wrapper.properties':
        return parse_wrapper(text, path), set()
    if name == 'toolchain-manifest.yaml':
        return manifest_entries(flatten_simple_yaml(text), path)
    if name.startswith('Dockerfile'):
        return parse_dockerfile(text, path), set()
    if re.match(r'.*\.ya?ml$', name):
        return parse_compose(text, path), set()
    if name.endswith('.sh'):
        return parse_shell(text, path), set()
    return set(), set()


def is_pin_file(path: str) -> bool:
    name = path.rsplit('/', 1)[-1]
    if '/node_modules/' in f'/{path}' or path.startswith(('build/', 'docs/')) or '/build/' in path:
        return False
    if name in ('bun.lock', 'gradle.lockfile', 'verification-metadata.xml', 'go.sum',
                'gradle-wrapper.properties', 'toolchain-manifest.yaml') or name.startswith('Dockerfile'):
        return True
    if name.startswith('requirements') and name.endswith('.txt'):
        return True
    if re.match(r'^scripts/[^/]+\.sh$', path):
        return True
    return bool(re.search(r'(^|/)(docker-compose[^/]*|compose)\.ya?ml$', path)
                or re.search(r'(^|/)selfhost/overlays/[^/]+\.ya?ml$', path))


# ---------------------------------------------------------------- git

def git(cwd: Path, *args: str, check: bool = True) -> str:
    result = subprocess.run(['git', '-C', str(cwd), *args], capture_output=True, text=True, check=False)
    if check and result.returncode:
        raise SystemExit(f'error: git {" ".join(args)} in {cwd}: {result.stderr.strip()}')
    return result.stdout if result.returncode == 0 else ''


def repositories(root: Path, base: str) -> list[tuple[str, Path, str | None]]:
    """(prefix, checkout, base commit) for the root and every initialised submodule."""
    found = [('', root, git(root, 'rev-parse', '--verify', f'{base}^{{commit}}').strip())]
    for line in git(root, 'submodule', 'status').splitlines():
        status, _sha, path = line[0], *line[1:].split()[:2]
        if status == '-':
            continue
        tree = git(root, 'ls-tree', base, '--', path, check=False).split()
        found.append((path + '/', root / path, tree[2] if len(tree) >= 3 and tree[1] == 'commit' else None))
    return found


def collect(root: Path, base: str, adopted: str | None = None) -> tuple[set[Entry], set[Entry], set[str], list[str]]:
    """(current entries, base entries, unknown manifest keys changed, files read).

    `adopted` is the revision at which this policy was adopted (dependency-additions.toml
    [policy] adopted_at): pins present there were accepted under the earlier review and count as base.
    """
    if adopted:
        _, before_adoption, _, _ = collect(root, adopted)
        current, before, unknown, files = collect(root, base)
        return current, before | before_adoption, unknown, files
    current, before, unknown_now, unknown_before, files = set(), set(), set(), set(), []
    for prefix, checkout, base_commit in repositories(root, base):
        tracked = git(checkout, 'ls-files', '--cached', '--others', '--exclude-standard').splitlines()
        base_files = git(checkout, 'ls-tree', '-r', '--name-only', base_commit).splitlines() if base_commit else []
        for relative in sorted({p for p in tracked + base_files if is_pin_file(p)}):
            label, name = prefix + relative, relative.rsplit('/', 1)[-1]
            disk = checkout / relative
            if disk.is_file():
                entries, unknown = parse_file(name, disk.read_text(encoding='utf-8', errors='replace'), label)
                current |= entries
                unknown_now |= unknown
                files.append(label)
            if base_commit and relative in base_files:
                text = git(checkout, 'show', f'{base_commit}:{relative}', check=False)
                entries, unknown = parse_file(name, text, label)
                before |= entries
                unknown_before |= unknown
    return current, before, {item.split('=', 1)[0] for item in unknown_now - unknown_before}, files


# ---------------------------------------------------------------- lookups

class Lookups:
    """Publish times and OSV advisories, from the network (robust_fetch) or from a fixture file."""

    def __init__(self, fixture: Path | None, cache: Path | None, deadline: float):
        self.fixture = json.loads(fixture.read_text()) if fixture else None
        self.cache_path = cache
        self.cache: dict[str, list] = {}
        if cache and cache.is_file():
            try:
                self.cache = json.loads(cache.read_text())
            except ValueError:
                self.cache = {}
        self.deadline = deadline
        self.packuments: dict[str, dict] = {}
        self._fetch = None
        self._go_probes: list[tuple[dt.datetime, float]] = []  # (index time queried, record of its first row)
        self._go_failed: dict[str, LookupError_] = {}
        self._lock = threading.Lock()
        self._index_lock = threading.Lock()
        self._index_next = 0.0
        self._index_interval: float | None = None
        self._go_size: int | None = None

    def save(self) -> None:
        if self.cache_path and self.fixture is None:
            self.cache_path.parent.mkdir(parents=True, exist_ok=True)
            part = self.cache_path.with_name(self.cache_path.name + '.part')
            part.write_text(json.dumps(self.cache, indent=0, sort_keys=True))
            os.replace(part, self.cache_path)

    # -- network
    def _robust(self):
        if self._fetch is None:
            library = Path(os.environ.get('ROBUST_FETCH_DIR', Path.home() / 'agent-skills' / 'lib'))
            sys.path.insert(0, str(library))
            try:
                import robust_fetch
            except ImportError as error:
                raise LookupError_(f'robust_fetch not importable from {library} (set ROBUST_FETCH_DIR): {error}') from error
            robust_fetch.log = lambda message: print(f'  fetch {message}', file=sys.stderr, flush=True)
            self._fetch = robust_fetch
        return self._fetch

    def get(self, urls: list, min_bytes: int = 2, extra: list[str] | None = None) -> bytes:
        robust = self._robust()
        left = self.deadline - time.monotonic()
        if left <= 0:
            raise LookupError_('overall lookup deadline reached')
        try:
            return robust.fetch(urls, deadline=min(left, 180), min_bytes=min_bytes, extra=extra)[1]
        except robust.FetchError as error:
            raise LookupError_(str(error)) from error

    def get_json(self, urls: list, **kwargs) -> dict:
        try:
            return json.loads(self.get(urls, **kwargs))
        except ValueError as error:
            raise LookupError_(f'{urls[0]}: not JSON: {error}') from error

    # -- publish time
    def published(self, entry: Entry) -> tuple[dt.datetime, str]:
        """(publish time, source) where source names who asserts the time; 'publisher' is untrusted."""
        if self.fixture is not None:
            value = self.fixture.get('times', {}).get(entry.key)
            if value is None:
                raise LookupError_(f'no fixture time for {entry.key}')
            stamp, _, source = value.partition(' ')
            return parse_time(stamp), source or 'registry'
        if entry.key in self._go_failed:
            raise self._go_failed[entry.key]
        cached = self.cache.get(entry.key)
        if cached and cached[1] not in CACHE_SOURCES.get(entry.ecosystem, {cached[1]}):
            cached = None
        if cached:
            return parse_time(cached[0]), cached[1]
        stamp, source = getattr(self, f'_time_{entry.ecosystem.replace("-", "_")}')(entry)
        if source != 'publisher':
            self.cache[entry.key] = [stamp.isoformat(), source]
        return stamp, source

    def _time_npm(self, entry: Entry) -> tuple[dt.datetime, str]:
        name = entry.name.replace('/', '%2F')
        if entry.name not in self.packuments:
            self.packuments[entry.name] = self.get_json(
                [f'https://registry.npmjs.org/{name}', f'https://registry.npmmirror.com/{name}'], min_bytes=50)
        stamp = self.packuments[entry.name].get('time', {}).get(entry.version)
        if not stamp:
            raise LookupError_(f'npm has no publish time for {entry.name}@{entry.version}')
        return parse_time(stamp), 'npm registry'

    def _time_maven(self, entry: Entry) -> tuple[dt.datetime, str]:
        group, artifact = entry.name.split(':', 1)
        query = urllib.parse.quote(f'g:"{group}" AND a:"{artifact}" AND v:"{entry.version}"')
        try:
            document = self.get_json([f'https://search.maven.org/solrsearch/select?q={query}&core=gav&rows=1&wt=json'],
                                     min_bytes=20)
            docs = document.get('response', {}).get('docs', [])
            if docs and docs[0].get('timestamp'):
                return dt.datetime.fromtimestamp(docs[0]['timestamp'] / 1000, dt.UTC), 'Maven Central index'
        except LookupError_:
            pass
        path = f'{group.replace(".", "/")}/{artifact}/{entry.version}/{artifact}-{entry.version}.pom'
        for base in ('https://repo1.maven.org/maven2', 'https://plugins.gradle.org/m2',
                     'https://dl.google.com/dl/android/maven2', 'https://repo.maven.apache.org/maven2'):
            try:
                headers = self.get([f'{base}/{path}'], min_bytes=10, extra=['-I'])
            except LookupError_:
                continue
            stamp = last_modified(headers)
            if stamp:
                return stamp, f'{base.split("/")[2]} Last-Modified'
        raise LookupError_(f'no Maven repository answered for {entry.name}:{entry.version}')

    def prefetch_go(self, entries: list[Entry]) -> None:
        """Date Go versions on GO_WORKERS threads; published() then answers from the cache or the failure."""
        todo = list({e.key: e for e in entries if e.ecosystem == 'go'}.values())
        if self.fixture is not None or len(todo) < 2:
            return

        def one(entry: Entry) -> None:
            try:
                self.published(entry)
            except LookupError_ as error:
                self._go_failed[entry.key] = error

        with concurrent.futures.ThreadPoolExecutor(GO_WORKERS) as pool:
            list(pool.map(one, todo))

    def _time_go(self, entry: Entry) -> tuple[dt.datetime, str]:
        """When proxy.golang.org first cached the version: its Timestamp in index.golang.org.

        The proxy's .info Time is the commit time (go.dev/ref/mod#version-info), which a tag pushed
        today on an old commit backdates; deps.dev's publishedAt is the same value (equal to .info Time
        for caddy v2.11.2, x/net v0.47.0, yaml.v2 v2.2.2 and go-cron v0.0.11). index.golang.org is a
        feed ordered by "the time it was first cached by proxy.golang.org", read with `since`; it cannot
        be asked for one version. sum.golang.org/lookup gives the version's record number in the checksum
        log, which grows as the proxy takes in new versions, so the gate searches the feed by time
        (interpolation, with bisection where the numbers grow unevenly) on the record number of the first
        row at each probe, from the commit time to now, then reads the pages
        around that point for the version's own row. Only that row's Timestamp is returned; a version
        whose row is not found there is indeterminate.
        """
        info = self.get_json([f'https://proxy.golang.org/{go_escape(entry.name)}/@v/{entry.version}.info'])
        try:
            commit = parse_time(info['Time'])
        except (KeyError, TypeError, ValueError) as error:
            raise LookupError_(f'proxy.golang.org .info for {entry.name}@{entry.version} has no Time') from error
        record = self._go_record(entry.name, entry.version)
        low = max(commit - GO_INDEX_LEAD, parse_time(GO_INDEX_START))
        high = dt.datetime.now(dt.UTC)
        low_record, high_record = None, float(self._go_tree_size())
        with self._lock:
            for when, seen in self._go_probes:
                if seen < record and low <= when < high:
                    low, low_record = when, seen
                elif seen >= record and low < when < high:
                    high, high_record = when, seen
        probes = 0

        def probe(when: dt.datetime) -> None:
            nonlocal low, high, low_record, high_record, probes
            probes += 1
            if probes > GO_SEARCH_PROBES:
                raise LookupError_(f'index.golang.org: {entry.name}@{entry.version} not located in {GO_SEARCH_PROBES} probes')
            seen = self._go_probe(when)
            with self._lock:
                self._go_probes.append((when, seen))
            if seen < record:
                low, low_record = when, seen
            else:
                high, high_record = when, seen

        if low_record is None:
            probe(low)
            if high == low:  # the checksum log took the version before its commit time: the commit time is wrong
                low, low_record = parse_time(GO_INDEX_START), 0.0
        bisections = 0  # owed after an interpolation that missed
        while high - low > GO_LOCATE_WINDOW:
            span = high - low
            if not bisections and low_record is not None and high_record != float('inf') and high_record > low_record:
                # Record numbers grow almost linearly over a short span: aim at the version and one window past it.
                guess = low + span * min(max((record - low_record) / (high_record - low_record), 0.0), 1.0)
                for when in (guess - GO_LOCATE_WINDOW / 2, guess + GO_LOCATE_WINDOW / 2):
                    if low < when < high:
                        probe(when)
                # Where growth is uneven (the 2019 backfill), bisect three times before aiming again.
                bisections = 0 if high - low <= span / 4 else 3
            else:
                probe(low + (high - low) / 2)
                bisections = max(0, bisections - 1)
        cursor, stop = low - GO_INDEX_LEAD, high + GO_INDEX_LEAD
        for _ in range(GO_INDEX_PAGES):
            rows = self._go_index(cursor, 2000)
            for row in rows:
                if row['Path'] == entry.name and row['Version'] == entry.version:
                    return parse_time(row['Timestamp']), 'index.golang.org first cached'
            if len(rows) < 2000 or parse_time(rows[-1]['Timestamp']) > stop:
                break
            cursor = parse_time(rows[-1]['Timestamp'])
        raise LookupError_(f'index.golang.org has no row for {entry.name}@{entry.version} (checksum record {record}) '
                           f'between {low - GO_INDEX_LEAD:%Y-%m-%dT%H:%MZ} and {stop:%Y-%m-%dT%H:%MZ}')

    def _go_tree_size(self) -> int:
        """The checksum log's current size (sum.golang.org/latest), read once a run."""
        with self._lock:
            if self._go_size is None:
                latest = self.get(['https://sum.golang.org/latest'], min_bytes=20).decode(errors='replace').splitlines()
                if len(latest) < 2 or latest[0] != 'go.sum database tree' or not latest[1].strip().isdigit():
                    raise LookupError_('sum.golang.org/latest is not a checksum database checkpoint')
                self._go_size = int(latest[1])
            return self._go_size

    def _go_record(self, name: str, version: str) -> int:
        body = self.get([f'https://sum.golang.org/lookup/{go_escape(name)}@{version}'], min_bytes=10)
        first = body.split(b'\n', 1)[0].strip()
        if not first.isdigit():
            raise LookupError_(f'sum.golang.org lookup of {name}@{version} has no record number')
        return int(first)

    def _go_index(self, since: dt.datetime, limit: int) -> list[dict]:
        cursor = since.astimezone(dt.UTC).strftime('%Y-%m-%dT%H:%M:%S.%fZ')
        url = f'https://index.golang.org/index?since={cursor}&limit={limit}'
        for cooldown in (*GO_INDEX_COOLDOWN, None):
            with self._index_lock:
                interval = self._index_interval or GO_INDEX_INTERVAL
                wait = self._index_next - time.monotonic()
                if wait > 0:
                    time.sleep(wait)
                self._index_next = time.monotonic() + interval
            try:
                body = self.get([url])
            except LookupError_ as error:
                if 'HTTP 429' not in str(error):
                    raise
                with self._index_lock:
                    self._index_interval = min(GO_INDEX_MAX_INTERVAL, 2 * (self._index_interval or GO_INDEX_INTERVAL))
                if cooldown is None:
                    raise
                time.sleep(cooldown)
                continue
            with self._index_lock:
                self._index_interval = max(GO_INDEX_INTERVAL, 0.95 * (self._index_interval or GO_INDEX_INTERVAL))
            break
        try:
            rows = [json.loads(line) for line in body.decode().splitlines() if line.strip()]
            for row in rows:
                if not isinstance(row, dict) or not all(isinstance(row.get(k), str) for k in ('Path', 'Version', 'Timestamp')):
                    raise ValueError(f'row without Path, Version and Timestamp: {row!r:.80}')
        except ValueError as error:
            raise LookupError_(f'index.golang.org since={cursor}: unreadable page: {error}') from error
        return rows

    def _go_probe(self, when: dt.datetime) -> float:
        """The checksum record number of the first version the proxy cached at or after `when` (inf past the end)."""
        rows = self._go_index(when, 5)
        if not rows:
            return float('inf')
        for row in rows:
            try:
                return self._go_record(row['Path'], row['Version'])
            except LookupError_:
                continue
        raise LookupError_(f'sum.golang.org has none of the first index.golang.org rows after {when:%Y-%m-%dT%H:%MZ}')

    def _time_pypi(self, entry: Entry) -> tuple[dt.datetime, str]:
        document = self.get_json([f'https://pypi.org/pypi/{entry.name}/{entry.version}/json'], min_bytes=50)
        times = [f['upload_time_iso_8601'] for f in document.get('urls', []) if f.get('upload_time_iso_8601')]
        if not times:
            raise LookupError_(f'PyPI has no upload time for {entry.name}=={entry.version}')
        return min(parse_time(t) for t in times), 'PyPI'

    def _time_gradle_dist(self, entry: Entry) -> tuple[dt.datetime, str]:
        versions = self.get_json(['https://services.gradle.org/versions/all'], min_bytes=100)
        for item in versions:
            if item.get('version') == entry.version and item.get('buildTime'):
                return dt.datetime.strptime(item['buildTime'], '%Y%m%d%H%M%S%z'), 'services.gradle.org'
        raise LookupError_(f'services.gradle.org does not list Gradle {entry.version}')

    def _time_github_release(self, entry: Entry) -> tuple[dt.datetime, str]:
        tag = urllib.parse.quote(entry.version, safe='')
        release = self.get_json([f'https://api.github.com/repos/{entry.name}/releases/tags/{tag}'], min_bytes=50,
                                extra=['-H', 'Accept: application/vnd.github+json'])
        if not release.get('published_at'):
            raise LookupError_(f'GitHub release {entry.name} {entry.version} has no published_at')
        return parse_time(release['published_at']), 'GitHub release'

    def _time_apk(self, entry: Entry) -> tuple[dt.datetime, str]:
        try:
            return os_packages.apk_time(entry, self.get, self.__dict__.setdefault('os_indexes', {}))
        except LookupError as error:
            raise LookupError_(str(error)) from error

    def _time_deb(self, entry: Entry) -> tuple[dt.datetime, str]:
        try:
            return os_packages.deb_time(entry, self.get_json)
        except LookupError as error:
            raise LookupError_(str(error)) from error

    def _time_rpm(self, entry: Entry) -> tuple[dt.datetime, str]:
        try:
            return os_packages.rpm_time(entry, self.get, self.__dict__.setdefault('os_indexes', {}))
        except LookupError as error:
            raise LookupError_(str(error)) from error

    def _time_oci(self, entry: Entry) -> tuple[dt.datetime, str]:
        tag, digest = entry.version.split('@', 1)
        registry, repository = entry.name.split('/', 1)
        if registry == 'docker.io' and tag:
            namespace, name = repository.split('/', 1)
            document = self.get_json([f'https://hub.docker.com/v2/namespaces/{namespace}/repositories/{name}/tags/{tag}'],
                                     min_bytes=50)
            # tag_last_pushed is when the tag last moved. It dates the pinned digest only while the tag
            # holds that digest (as its index digest or one platform's): the digest existed by then, so
            # the age is never overstated. A tag that has moved to another digest says nothing about ours.
            held = {document.get('digest')} | {image.get('digest') for image in document.get('images') or []}
            if document.get('tag_last_pushed') and digest in held:
                return parse_time(document['tag_last_pushed']), 'Docker Hub tag_last_pushed'
        if registry == 'quay.io' and tag:
            url = (f'https://quay.io/api/v1/repository/{repository}/tag/'
                   f'?specificTag={urllib.parse.quote(tag)}&onlyActiveTags=false')
            document = self.get_json([url], min_bytes=20)
            starts = [t['start_ts'] for t in document.get('tags', []) if t.get('manifest_digest') == digest]
            if starts:
                return dt.datetime.fromtimestamp(min(starts), dt.UTC), 'Quay start_ts'
        created = self._oci_created(registry, repository, digest)
        return created, 'publisher'

    def _oci_created(self, registry: str, repository: str, digest: str) -> dt.datetime:
        """The image config's `created`, which the publisher writes; reported as untrusted."""
        host = 'registry-1.docker.io' if registry == 'docker.io' else registry
        token_urls = {'docker.io': f'https://auth.docker.io/token?service=registry.docker.io&scope=repository:{repository}:pull',
                      'ghcr.io': f'https://ghcr.io/token?scope=repository:{repository}:pull',
                      'quay.io': f'https://quay.io/v2/auth?service=quay.io&scope=repository:{repository}:pull'}
        auth = []
        if registry in token_urls:
            token = self.get_json([token_urls[registry]], min_bytes=10).get('token')
            if token:
                auth = ['-H', f'Authorization: Bearer {token}']
        accept = ['-H', ('Accept: application/vnd.oci.image.index.v1+json, application/vnd.oci.image.manifest.v1+json, '
                         'application/vnd.docker.distribution.manifest.list.v2+json, '
                         'application/vnd.docker.distribution.manifest.v2+json')]
        manifest = self.get_json([f'https://{host}/v2/{repository}/manifests/{digest}'], min_bytes=50, extra=auth + accept)
        if manifest.get('manifests'):
            amd64 = [m for m in manifest['manifests'] if m.get('platform', {}).get('architecture') == 'amd64'] or manifest['manifests']
            manifest = self.get_json([f'https://{host}/v2/{repository}/manifests/{amd64[0]["digest"]}'], min_bytes=50,
                                     extra=auth + accept)
        annotation = manifest.get('annotations', {}).get('org.opencontainers.image.created')
        if annotation:
            return parse_time(annotation)
        config = self.get_json([f'https://{host}/v2/{repository}/blobs/{manifest["config"]["digest"]}'], min_bytes=50,
                               extra=auth)
        if not config.get('created'):
            raise LookupError_(f'{registry}/{repository}@{digest} has no created time')
        return parse_time(config['created'])

    # -- OSV
    def advisories(self, entries: list[Entry]) -> dict[str, list[str]]:
        """OSV advisory ids per entry key, for every entry in an ecosystem OSV covers."""
        queryable = [e for e in entries if e.ecosystem in OSV_ECOSYSTEMS]
        if self.fixture is not None:
            known = self.fixture.get('osv', {})
            return {e.key: list(known.get(e.key, [])) for e in queryable}
        found: dict[str, list[str]] = {e.key: [] for e in queryable}
        scratch = self.cache_path.parent if self.cache_path else Path.cwd()
        scratch.mkdir(parents=True, exist_ok=True)
        # A result with next_page_token has more advisories: that query is sent again with page_token
        # until no token comes back (docs/api/post-v1-querybatch.md in google/osv.dev).
        pending = [(e, {'package': {'ecosystem': OSV_ECOSYSTEMS[e.ecosystem], 'name': e.name}, 'version': e.version})
                   for e in queryable]
        for _round in range(OSV_MAX_PAGES):
            if not pending:
                return found
            following = []
            for start in range(0, len(pending), 1000):
                chunk = pending[start:start + 1000]
                request = scratch / 'osv-querybatch.json'
                request.write_text(json.dumps({'queries': [query for _, query in chunk]}))
                answer = self.get_json([('https://api.osv.dev/v1/querybatch',
                                         ['-H', 'Content-Type: application/json', '--data-binary', f'@{request}'])],
                                       min_bytes=10)
                results = answer.get('results')
                if not isinstance(results, list) or len(results) != len(chunk):
                    raise LookupError_('OSV querybatch returned a different number of results than queries')
                for (entry, query), result in zip(chunk, results, strict=True):
                    found[entry.key] += [v['id'] for v in (result or {}).get('vulns', [])]
                    token = (result or {}).get('next_page_token')
                    if token:
                        following.append((entry, {**query, 'page_token': token}))
            pending = following
        raise LookupError_(f'OSV still had more result pages after {OSV_MAX_PAGES} rounds')


def go_escape(path: str) -> str:
    """A module path as the proxy and checksum database spell it: each capital becomes '!' and the lower case."""
    return re.sub(r'[A-Z]', lambda m: '!' + m.group(0).lower(), path)


def parse_time(value: str) -> dt.datetime:
    value = value.strip().replace('Z', '+00:00')
    value = re.sub(r'(\.\d{6})\d+', r'\1', value)
    stamp = dt.datetime.fromisoformat(value)
    return stamp if stamp.tzinfo else stamp.replace(tzinfo=dt.UTC)


def last_modified(headers: bytes) -> dt.datetime | None:
    import email.utils
    values = re.findall(rb'(?im)^last-modified:\s*(.+?)\s*$', headers)
    return email.utils.parsedate_to_datetime(values[-1].decode()) if values else None


# ---------------------------------------------------------------- policy

def major(version: str) -> str:
    version = version.split('@', 1)[0].lstrip('vV')
    match = re.match(r'(\d+)(?:\.(\d+))?', version)
    if not match:
        return version
    first, second = match.groups()
    return f'0.{second}' if first == '0' and second is not None else first


def load_toml(path: Path, table: str) -> list[dict]:
    if not path.is_file():
        return []
    with path.open('rb') as handle:
        document = tomllib.load(handle)
    rows = document.get(table, [])
    return rows if isinstance(rows, list) else []


def exception_problems(rows: list[dict], today: dt.date) -> list[str]:
    problems = []
    for row in rows:
        label = f'{row.get("ecosystem")}:{row.get("name")}@{row.get("version")}'
        for field in ('ecosystem', 'name', 'version', 'reviewer', 'note'):
            if not str(row.get(field) or '').strip():
                problems.append(f'dependency-exceptions.toml {label}: missing {field}')
        expires = row.get('expires')
        if not isinstance(expires, dt.date):
            problems.append(f'dependency-exceptions.toml {label}: expires must be a TOML date (YYYY-MM-DD)')
        elif expires < today:
            problems.append(f'dependency-exceptions.toml {label}: expired on {expires}; remove it')
        elif (expires - today).days > MAX_EXCEPTION_DAYS:
            problems.append(f'dependency-exceptions.toml {label}: expires more than {MAX_EXCEPTION_DAYS} days ahead')
    return problems


def addition_problems(rows: list[dict]) -> list[str]:
    """An addition names one package, one remote npm source, or the reviewed content of one lockfile."""
    problems = []
    for row in rows:
        label = f'{row.get("ecosystem")}:{row.get("name") or row.get("lockfile")}'
        if bool(row.get('name')) == bool(row.get('lockfile')):
            problems.append(f'dependency-additions.toml {label}: give exactly one of name or lockfile')
        required = ['ecosystem', 'reviewer', 'reason'] + (['source'] if row.get('ecosystem') == 'npm-source' else [])
        problems += [f'dependency-additions.toml {label}: missing {field}'
                     for field in required if not str(row.get(field) or '').strip()]
    return problems


def approved_lockfiles(root: Path, base: str, additions: list[dict]) -> tuple[dict[tuple[str, str], set[str]], list[str]]:
    """((ecosystem, lockfile) -> names the reviewed revision of that lockfile held, problems).

    A lockfile approval admits the names that file held at the revision a person reviewed, not
    whatever it holds later: a name added afterwards is a new name like any other.
    """
    approved: dict[tuple[str, str], set[str]] = {}
    problems: list[str] = []
    checkouts = sorted(((prefix, checkout) for prefix, checkout, _ in repositories(root, base)),
                       key=lambda item: -len(item[0]))
    for row in additions:
        lockfile = str(row.get('lockfile') or '')
        if not lockfile:
            continue
        ecosystem, revision = row.get('ecosystem'), str(row.get('revision') or '').strip()
        label = f'dependency-additions.toml {ecosystem}:{lockfile}'
        if not re.fullmatch(r'[0-9a-f]{40}', revision):
            problems.append(f'{label}: a lockfile approval needs the reviewed revision (revision = full commit id); '
                            'without one it would admit every name added to the file later')
            continue
        prefix, checkout = next((p, c) for p, c in checkouts if lockfile.startswith(p))
        relative = lockfile[len(prefix):]
        shown = subprocess.run(['git', '-C', str(checkout), 'show', f'{revision}:{relative}'], capture_output=True,
                               text=True, check=False)
        if shown.returncode:
            problems.append(f'{label}: cannot read {lockfile} at {revision}: {shown.stderr.strip()}')
            continue
        entries, _ = parse_file(relative.rsplit('/', 1)[-1], shown.stdout, lockfile)
        approved.setdefault((ecosystem, lockfile), set()).update(e.name for e in entries if e.ecosystem == ecosystem)
    return approved, problems


def evaluate(current: set[Entry], before: set[Entry], unknown_keys: set[str], lookups: Lookups,
             exceptions: list[dict], additions: list[dict], today: dt.date,
             now: dt.datetime, approved_files: dict[tuple[str, str], set[str]] | None = None,
             ) -> tuple[list[str], list[str], list[str]]:
    """(report lines, policy failures, indeterminate lookups).

    approved_files: names each reviewed lockfile approval admits (approved_lockfiles()).
    """
    report, failures, unknown = [], [], []
    failures += exception_problems(exceptions, today) + addition_problems(additions)
    failures += [f'toolchain-manifest.yaml {key}: changed pin with no publish-time source; '
                 'add a mapping in scripts/check-dependency-age.py or an exception' for key in sorted(unknown_keys)]
    excepted = {(r.get('ecosystem'), r.get('name'), str(r.get('version'))) for r in exceptions}
    added = {(r.get('ecosystem'), r.get('name')) for r in additions if r.get('name')}
    approved_files = approved_files or {}
    reviewed_sources = {(r.get('ecosystem'), r.get('name'), str(r.get('source'))) for r in additions
                        if r.get('ecosystem') == 'npm-source'}
    base_by_name: dict[tuple[str, str], set[str]] = {}
    for entry in before:
        base_by_name.setdefault((entry.ecosystem, entry.name), set()).add(entry.version)
    base_keys = {(e.ecosystem, e.name, e.version) for e in before}
    changed = sorted({e for e in current if (e.ecosystem, e.name, e.version) not in base_keys})

    # Every current entry OSV covers, changed or not; plus the old versions of changed ones.
    unique_current = list({(e.ecosystem, e.name, e.version): e for e in current}.values())
    old_versions = [Entry(e.ecosystem, e.name, v) for e in changed for v in base_by_name.get((e.ecosystem, e.name), ())]
    try:
        osv = lookups.advisories(unique_current + old_versions)
    except LookupError_ as error:
        unknown.append(f'OSV: {error}')
        osv = {}
    # MAL- fails what the candidate holds; a malicious version it removes only classifies its replacement.
    for key in sorted({e.key for e in unique_current} & osv.keys()):
        for advisory in osv[key]:
            if advisory.startswith('MAL-'):
                failures.append(f'{key}: OSV {advisory} marks this version malicious; no exception can admit it')

    lookups.prefetch_go(changed)
    for entry in changed:
        if entry.ecosystem == 'asset-digest':
            version_key = entry.name.rsplit('.sha256.', 1)[0] + '.version'
            if not any(e.ecosystem == 'github-release' and e.path == entry.path for e in changed):
                failures.append(f'{entry.path} {entry.name}: asset digest changed without a version change ({version_key})')
            continue
        if entry.ecosystem == 'npm-source':
            if (entry.ecosystem, entry.name, entry.version) in reviewed_sources:
                report.append(f'{entry.key:<70} reviewed remote source')
            else:
                failures.append(f'{entry.key} ({entry.path}): remote source outside the npm registry, with no registry '
                                'publish time; read it, then add a dependency-additions.toml row (ecosystem '
                                f'"npm-source", name "{entry.name}", source "{entry.version}")')
            continue
        olds = base_by_name.get((entry.ecosystem, entry.name), set())
        is_new = not olds
        if is_new and (entry.ecosystem, entry.name) not in added and \
                entry.name not in approved_files.get((entry.ecosystem, entry.path), set()):
            failures.append(f'{entry.key} ({entry.path}): new package name; add it to dependency-additions.toml '
                            'with a reviewer and a reason')
        if entry.name.startswith(OWN_IMAGE_PREFIXES):
            report.append(f'{entry.key:<70} own image, not aged')
            continue
        if is_new:
            days, kind = ROUTINE_DAYS, 'new'
        elif any(major(old) != major(entry.version) for old in olds):
            days, kind = MAJOR_DAYS, 'major'
        else:
            days, kind = ROUTINE_DAYS, 'routine'
        old_ids = {i for old in olds for i in osv.get(Entry(entry.ecosystem, entry.name, old).key, [])}
        if kind != 'major' and old_ids - set(osv.get(entry.key, [])):
            days, kind = SECURITY_DAYS, 'security'
        try:
            stamp, source = lookups.published(entry)
        except LookupError_ as error:
            if (entry.ecosystem, entry.name, entry.version) in excepted:
                report.append(f'{entry.key:<70} lookup failed, excepted: {error}')
            else:
                unknown.append(f'{entry.key} ({entry.path}): {error}')
            continue
        age_days = max(0.0, (now - stamp).total_seconds() / 86400)  # a time after now (clock skew) is age 0
        line = f'{entry.key:<70} {kind:<8} {age_days:6.1f}d of {days}d  {stamp:%Y-%m-%d} ({source})'
        if (entry.ecosystem, entry.name, entry.version) in excepted:
            report.append(line + '  EXCEPTED')
            continue
        if source == 'publisher':
            failures.append(f'{entry.key} ({entry.path}): only the publisher asserts its time ({stamp:%Y-%m-%d}); '
                            'no registry timestamp exists, so it needs a dependency-exceptions.toml entry')
        elif age_days < days:
            failures.append(f'{entry.key} ({entry.path}): published {stamp:%Y-%m-%d %H:%M}Z, {age_days:.1f} days ago; '
                            f'{kind} updates wait {days} days')
        report.append(line)
    return report, failures, unknown


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument('--base', default=os.environ.get('CHRONICLE_DEPENDENCY_BASE', 'origin/main'))
    parser.add_argument('--today', type=dt.date.fromisoformat)
    parser.add_argument('--lookup-fixture', type=Path)
    parser.add_argument('--cache', type=Path,
                        default=Path(os.environ.get('XDG_CACHE_HOME', Path.home() / '.cache')) / 'chronicle' / 'dependency-age.json')
    parser.add_argument('--report', type=Path)
    parser.add_argument('--print-policy', action='store_true', help='print the waits as JSON and exit')
    args = parser.parse_args(argv)
    if args.print_policy:
        print(json.dumps(policy_numbers(), sort_keys=True))
        return 0
    now = (dt.datetime.combine(args.today, dt.time(12), dt.UTC) if args.today else dt.datetime.now(dt.UTC))
    today = now.date()
    root = args.root.resolve()
    policy = {}
    if (root / 'dependency-additions.toml').is_file():
        with (root / 'dependency-additions.toml').open('rb') as handle:
            policy = tomllib.load(handle).get('policy', {})
    current, before, unknown_keys, files = collect(root, args.base, policy.get('adopted_at'))
    before |= os_packages.implied_base(current, major, Entry)  # an OS --upgrade changes a base-image package
    lookups = Lookups(args.lookup_fixture, args.cache, time.monotonic() + DEADLINE_SECONDS)
    exceptions = load_toml(root / 'dependency-exceptions.toml', 'exception')
    additions = load_toml(root / 'dependency-additions.toml', 'addition')
    approved_files, approval_problems = approved_lockfiles(root, args.base, additions)
    report, failures, unknown = evaluate(current, before, unknown_keys, lookups, exceptions, additions, today, now,
                                         approved_files)
    failures = approval_problems + failures
    lookups.save()
    header = (f'dependency age gate: base {args.base}, {len(files)} pin files, {len(current)} current entries, '
              f'{len(report)} new or changed')
    lines = [header, *report]
    lines += [f'[fail] {line}' for line in failures] + [f'[indeterminate] {line}' for line in unknown]
    lines.append(f'result: {len(failures)} failure(s), {len(unknown)} indeterminate')
    text = '\n'.join(lines) + '\n'
    print(text, end='', flush=True)
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(text)
    if failures:
        return 1
    return 2 if unknown else 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
