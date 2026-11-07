"""OS packages installed by Dockerfiles: pins, their registry publish times, and pin proposals.

Release Dockerfiles install distribution packages only through the helpers in selfhost/os-packages/
(docs/SUPPLY-CHAIN.md, "OS packages"):

    apk-install-aged.sh BRANCH [--add NAME...] [--pin NAME=VERSION...] [--upgrade NAME=VERSION...]
    apt-install-aged.sh DISTRO SNAPSHOT [--download] [--add NAME...] [--pin NAME=VERSION...] [--upgrade NAME=VERSION...]
    dnf-upgrade-aged.sh RELEASE --upgrade NAME=VERSION-RELEASE...

scripts/check-dependency-age.py reads their pins as entries (Entry(ecosystem, name, version)):

    apk  v3.24/<package>          Alpine APK index build time `t:` (main, then community, x86_64)
    deb  debian/<package>         snapshot.debian.org first_seen of the amd64 or all binary
    deb  ubuntu/<package>         Launchpad date_published of the amd64 or all binary
    rpm  el9/<package>            UBI 9 repository metadata (primary.xml): the later of the file
                                  time (when the repository received it) and the build time

An --upgrade replaces a version the base image already has, so it is a changed version of a known
name, not a new name; implied_base() supplies that base side. scripts/os-package-pins.py proposes
the pins.
"""
from __future__ import annotations

import datetime as dt
import gzip
import io
import re
import shlex
import tarfile
import urllib.parse
import xml.etree.ElementTree as ET

HELPERS = ('apk-install-aged.sh', 'apt-install-aged.sh', 'dnf-upgrade-aged.sh')
ECOSYSTEMS = ('apk', 'deb', 'rpm')
APK_MIRRORS = ('https://dl-cdn.alpinelinux.org/alpine', 'https://mirror.leaseweb.com/alpine',
               'https://uk.alpinelinux.org/alpine')
APK_REPOSITORIES = ('main', 'community')
UBI_REPOSITORIES = {'el9': ('https://cdn-ubi.redhat.com/content/public/ubi/dist/ubi9/9/x86_64/baseos/os',
                            'https://cdn-ubi.redhat.com/content/public/ubi/dist/ubi9/9/x86_64/appstream/os',
                            'https://cdn-ubi.redhat.com/content/public/ubi/dist/ubi9/9/x86_64/codeready-builder/os')}
ARCHITECTURES = ('amd64', 'all')  # release images are linux/amd64
TOKEN_SEPARATOR = re.compile(r'(?:[ \t]|\\\n)+')


# ---------------------------------------------------------------- Dockerfile calls

class HelperCall:
    """One helper invocation in a Dockerfile: its arguments and where they sit in the text."""

    def __init__(self, helper: str, words: list[str], start: int, end: int, stage_from: str | None):
        self.helper = helper
        self.words = words
        self.start = start  # offset of the first argument
        self.end = end  # offset after the last argument
        self.stage_from = stage_from  # the FROM reference of the stage the call is in

    @property
    def sections(self) -> dict[str, list[str]]:
        found: dict[str, list[str]] = {'positional': [], 'add': [], 'pin': [], 'upgrade': [], 'flags': []}
        section = 'positional'
        for word in self.words:
            if word in ('--add', '--pin', '--upgrade'):
                section = word[2:]
            elif word.startswith('--'):
                found['flags'].append(word)
            else:
                found[section].append(word)
        return found


def helper_calls(text: str) -> list[HelperCall]:
    """Every helper call, with its arguments up to `&&`, `;`, `|` or the end of the instruction."""
    calls = []
    for match in re.finditer(r'/(' + '|'.join(re.escape(h) for h in HELPERS) + r')(?=[ \t\\])', text):
        position, words, end = match.end(), [], match.end()
        while True:
            separator = TOKEN_SEPARATOR.match(text, position)
            if not separator:
                break
            token = re.match(r'[^\s\\]+', text[separator.end():])
            if not token or token.group(0) in ('&&', '||', ';', '|') or token.group(0).startswith(('&', ';', '|')):
                break
            words.append(token.group(0))
            position = end = separator.end() + token.end()
        if match.start() > 0 and re.search(r'target=[^\s,]*$', text[max(0, match.start() - 200):match.start()]):
            continue  # the --mount target, not the call
        start_line = text.rfind('\n', 0, match.start()) + 1
        if text[start_line:match.start()].lstrip().startswith('#'):
            continue
        stage = None
        for line in re.finditer(r'^\s*FROM\s+(?:--platform=\S+\s+)?(\S+)', text[:match.start()], re.MULTILINE | re.IGNORECASE):
            stage = line.group(1)
        calls.append(HelperCall(match.group(1), words, match.end(), end, arg_default(text, stage)))
    return calls


def arg_default(text: str, reference: str | None) -> str | None:
    """A `FROM ${NAME}` (or `$NAME`) reference as the default of the `ARG NAME=...` before the first FROM,
    None when there is no such default; any other reference as it is."""
    variable = re.fullmatch(r'\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?', reference or '')
    if not variable:
        return reference
    first_from = re.search(r'^\s*FROM\s', text, re.MULTILINE | re.IGNORECASE)
    head = text[:first_from.start()] if first_from else text
    default = re.search(rf'^\s*ARG\s+{variable.group(1)}=(\S+)\s*$', head, re.MULTILINE)
    return default.group(1) if default else None


def split_pin(word: str) -> tuple[str, str]:
    name, _, version = word.partition('=')
    if not name or not version:
        raise ValueError(f'not NAME=VERSION: {word}')
    return name, version


def pins(call: HelperCall) -> list[tuple[str, str, str, bool]]:
    """(ecosystem, entry name, version, is_upgrade) for every pin of a call."""
    sections = call.sections
    positional = sections['positional']
    if call.helper == 'apk-install-aged.sh':
        ecosystem, prefix = 'apk', positional[0] if positional else '?'
    elif call.helper == 'apt-install-aged.sh':
        ecosystem, prefix = 'deb', positional[0] if positional else '?'
    else:
        ecosystem, prefix = 'rpm', positional[0] if positional else '?'
    found = []
    for section, upgrade in (('pin', False), ('upgrade', True)):
        for word in sections[section]:
            name, version = split_pin(word)
            found.append((ecosystem, f'{prefix}/{name}', version, upgrade))
    return found


def parse_dockerfile(text: str, path: str, entry_cls) -> set:
    """Entries for every OS-package pin in a Dockerfile (check-dependency-age.py's Entry)."""
    found = set()
    for call in helper_calls(text):
        for ecosystem, name, version, upgrade in pins(call):
            found.add(entry_cls(ecosystem, name, version, path + (' (upgrade)' if upgrade else '')))
    return found


def implied_base(current: set, major, entry_cls) -> set:
    """For each --upgrade pin, a base-side entry of the same name and major version.

    An upgrade replaces a package the base image already has (the helpers refuse an --upgrade of a
    name the base lacks, at build time), so it is a routine change of a known name: never a new
    name, and a major change only when the version's major moves, which the base side cannot show.
    """
    implied = set()
    for entry in current:
        if entry.ecosystem in ECOSYSTEMS and entry.path.endswith(' (upgrade)'):
            implied.add(entry_cls(entry.ecosystem, entry.name, f'{major(entry.version)}.base-image', entry.path))
    return implied


# ---------------------------------------------------------------- publish times

def apk_index_url(base: str, branch: str, repository: str) -> str:
    return f'{base}/{branch}/{repository}/x86_64/APKINDEX.tar.gz'


def parse_apkindex(data: bytes) -> dict[str, dict]:
    """Package name -> {V, t, D, p, k} from an APKINDEX.tar.gz (or a plain APKINDEX text)."""
    if data[:2] == b'\x1f\x8b':
        with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as archive:
            member = archive.extractfile('APKINDEX')
            text = member.read().decode('utf-8', 'replace') if member else ''
    else:
        text = data.decode('utf-8', 'replace')
    return parse_apk_database(text)


def parse_apk_database(text: str) -> dict[str, dict]:
    """APKINDEX or /lib/apk/db/installed text -> package name -> fields."""
    packages = {}
    for block in text.split('\n\n'):
        fields: dict[str, str] = {}
        for line in block.splitlines():
            if len(line) > 2 and line[1] == ':' and line[0] not in fields:
                fields[line[0]] = line[2:]
        if 'P' in fields and 'V' in fields:
            packages[fields['P']] = {'V': fields['V'], 't': fields.get('t'), 'k': int(fields.get('k') or 0),
                                     'D': fields.get('D', '').split(), 'p': fields.get('p', '').split()}
    return packages


def apk_time(entry, get, cache: dict) -> tuple[dt.datetime, str]:
    branch, name = entry.name.split('/', 1)
    for repository in APK_REPOSITORIES:
        key = f'apkindex:{branch}/{repository}'
        if key not in cache:
            cache[key] = parse_apkindex(get([apk_index_url(base, branch, repository) for base in APK_MIRRORS],
                                            min_bytes=1000))
        package = cache[key].get(name)
        if package and package['V'] == entry.version and package['t']:
            return dt.datetime.fromtimestamp(int(package['t']), dt.UTC), f'Alpine {branch}/{repository} APKINDEX t:'
    raise LookupError(f'Alpine {branch} index has no {name} {entry.version} (the index keeps only the current version)')


def deb_time(entry, get_json) -> tuple[dt.datetime, str]:
    distro, name = entry.name.split('/', 1)
    if distro == 'debian':
        url = (f'https://snapshot.debian.org/mr/binary/{urllib.parse.quote(name)}/'
               f'{urllib.parse.quote(entry.version, safe="")}/binfiles?fileinfo=1')
        document = get_json([url], min_bytes=20)
        hashes = {item['hash'] for item in document.get('result', []) if item.get('architecture') in ARCHITECTURES}
        seen = [info['first_seen'] for digest, infos in document.get('fileinfo', {}).items() if digest in hashes
                for info in infos if info.get('first_seen')]
        if not seen:
            raise LookupError(f'snapshot.debian.org has no amd64 binary of {name} {entry.version}')
        return min(parse_compact_time(value) for value in seen), 'snapshot.debian.org first_seen'
    if distro == 'ubuntu':
        query = urllib.parse.urlencode({'ws.op': 'getPublishedBinaries', 'binary_name': name, 'version': entry.version,
                                        'exact_match': 'true', 'ws.size': '300'})
        document = get_json([f'https://api.launchpad.net/1.0/ubuntu/+archive/primary?{query}'], min_bytes=20)
        published = [item['date_published'] for item in document.get('entries', [])
                     if item.get('date_published') and item.get('binary_package_version') == entry.version
                     and ((item.get('distro_arch_series_link') or '').endswith('/amd64')
                          or item.get('architecture_specific') is False)]
        if not published:
            raise LookupError(f'Launchpad has no published amd64 binary of {name} {entry.version}')
        return min(parse_compact_time(value) for value in published), 'Launchpad date_published'
    raise LookupError(f'no publish-time source for {distro} packages')


def rpm_time(entry, get, cache: dict) -> tuple[dt.datetime, str]:
    release, name = entry.name.split('/', 1)
    if release not in UBI_REPOSITORIES:
        raise LookupError(f'no repository metadata source for {release} packages')
    version, _, rel = entry.version.rpartition('-')
    for base in UBI_REPOSITORIES[release]:
        key = f'primary:{base}'
        if key not in cache:
            cache[key] = parse_primary(base, get)
        times = cache[key].get((name, version, rel))
        if times:
            # `file` is when the repository received the package and `build` the builder's own
            # header time; the later one never overstates the age.
            return dt.datetime.fromtimestamp(max(times), dt.UTC), f'{base.split("/")[-2]} primary.xml'
    raise LookupError(f'UBI {release} repositories list no {name}-{entry.version} (they keep only the current build)')


def parse_primary(base: str, get) -> dict[tuple[str, str, str], tuple[int, int]]:
    repomd = ET.fromstring(get([f'{base}/repodata/repomd.xml'], min_bytes=200))
    namespace = {'r': 'http://linux.duke.edu/metadata/repo', 'c': 'http://linux.duke.edu/metadata/common'}
    location = next(data.find('r:location', namespace).get('href') for data in repomd.findall('r:data', namespace)
                    if data.get('type') == 'primary')
    primary = ET.fromstring(gzip.decompress(get([f'{base}/{location}'], min_bytes=1000)))
    found = {}
    for package in primary.findall('c:package', namespace):
        arch = package.find('c:arch', namespace).text
        if arch not in ('x86_64', 'noarch'):
            continue
        version = package.find('c:version', namespace)
        stamp = package.find('c:time', namespace)
        found[(package.find('c:name', namespace).text, version.get('ver'), version.get('rel'))] = (
            int(stamp.get('file')), int(stamp.get('build')))
    return found


def parse_compact_time(value: str) -> dt.datetime:
    """snapshot.debian.org's 20261029T000000Z and Launchpad's ISO 8601 times."""
    if re.fullmatch(r'\d{8}T\d{6}Z', value):
        return dt.datetime.strptime(value, '%Y%m%dT%H%M%SZ').replace(tzinfo=dt.UTC)
    stamp = dt.datetime.fromisoformat(value)
    return stamp if stamp.tzinfo else stamp.replace(tzinfo=dt.UTC)


# ---------------------------------------------------------------- pin proposals (os-package-pins.py)

def apk_dependency_name(token: str) -> str | None:
    if token.startswith('!'):
        return None
    return re.split(r'[<>=~]', token, maxsplit=1)[0]


def apk_providers(packages: dict[str, dict]) -> dict[str, list[str]]:
    providers: dict[str, list[str]] = {}
    for name, fields in packages.items():
        providers.setdefault(name, []).append(name)
        for provided in fields['p']:
            providers.setdefault(apk_dependency_name(provided) or provided, []).append(name)
    return providers


def apk_closure(wanted: list[str], base: dict[str, dict], index: dict[str, dict]) -> dict[str, str]:
    """Package -> index version for `wanted` and every dependency the base does not provide."""
    base_provides = set(apk_providers(base))
    index_providers = apk_providers(index)
    chosen: dict[str, str] = {}
    queue = list(wanted)
    while queue:
        name = queue.pop(0)
        if name in chosen or (name in base and name not in wanted):
            continue
        if name not in index:
            raise LookupError(f'the Alpine index has no package {name}')
        chosen[name] = index[name]['V']
        for token in index[name]['D']:
            dependency = apk_dependency_name(token)
            if not dependency or dependency in base_provides:
                continue
            candidates = index_providers.get(dependency, [])
            if not candidates:
                raise LookupError(f'nothing in the Alpine index provides {dependency} (needed by {name})')
            if any(candidate in chosen for candidate in candidates):
                continue
            queue.append(dependency if dependency in index else max(candidates, key=lambda c: index[c]['k']))
    return chosen


def apk_proposal(wanted: list[str], base: dict[str, dict], index: dict[str, dict], aged) -> tuple[list[str], list[str], list[str]]:
    """(pins, upgrades, problems). aged(name, old_version, new_version, build_time) -> bool."""
    problems = []
    pins = []
    for name, version in sorted(apk_closure(wanted, base, index).items()):
        if not aged(name, None, version, index[name]['t']):
            problems.append(f'{name}={version} has not aged; the base lacks it, so nothing older can be installed')
        pins.append(f'{name}={version}')
    upgrades = []
    for name, fields in sorted(base.items()):
        newer = index.get(name)
        if newer and newer['V'] != fields['V'] and aged(name, fields['V'], newer['V'], newer['t']):
            upgrades.append(f'{name}={newer["V"]}')
    return pins, upgrades, problems


def never_back(resolved: list[str], previous: dict[str, str]) -> tuple[list[str], list[str]]:
    """Resolved Debian pins with any that would move an existing pin to an older version put back.

    Returns (pins, names kept at their previous version)."""
    pins, kept = [], []
    for word in resolved:
        name, version = split_pin(word)
        if name in previous and debian_compare(version, previous[name]) < 0:
            word = f'{name}={previous[name]}'
            kept.append(name)
        pins.append(word)
    return pins, kept


def render_call(positional: list[str], flags: list[str], sections: dict[str, list[str]], indent: str,
                width: int = 110) -> str:
    """The argument text for a call: one section per continuation line, wrapped at `width`."""
    lines = [' '.join(shlex.quote(word) for word in positional + flags)]
    for section in ('add', 'pin', 'upgrade'):
        words = sections.get(section) or []
        if not words:
            continue
        line = f'--{section}'
        for word in words:
            if len(indent) + len(line) + 1 + len(word) > width and line != f'--{section}':
                lines.append(line)
                line = '  ' + word
            else:
                line += ' ' + word
        lines.append(line)
    return ' ' + f' \\\n{indent}'.join(lines)


def _debian_order(character: str) -> int:
    if character == '~':
        return -1
    if character.isalpha():
        return ord(character)
    return ord(character) + 256 if character else 0


def _debian_part(left: str, right: str) -> int:
    """dpkg's comparison of an upstream version or revision string."""
    while left or right:
        left_text = re.match(r'[^0-9]*', left).group(0)
        right_text = re.match(r'[^0-9]*', right).group(0)
        for index in range(max(len(left_text), len(right_text))):
            a = _debian_order(left_text[index] if index < len(left_text) else '')
            b = _debian_order(right_text[index] if index < len(right_text) else '')
            if a != b:
                return -1 if a < b else 1
        left, right = left[len(left_text):], right[len(right_text):]
        left_digits = re.match(r'[0-9]*', left).group(0)
        right_digits = re.match(r'[0-9]*', right).group(0)
        if int(left_digits or 0) != int(right_digits or 0):
            return -1 if int(left_digits or 0) < int(right_digits or 0) else 1
        left, right = left[len(left_digits):], right[len(right_digits):]
    return 0


def debian_compare(left: str, right: str) -> int:
    """-1, 0 or 1 as `dpkg --compare-versions left lt|eq|gt right`."""
    def split(version: str) -> tuple[int, str, str]:
        epoch, _, rest = version.rpartition(':') if ':' in version else ('0', '', version)
        upstream, _, revision = rest.rpartition('-') if '-' in rest else (rest, '', '0')
        return int(epoch or 0), upstream, revision
    (le, lu, lr), (re_, ru, rr) = split(left), split(right)
    if le != re_:
        return -1 if le < re_ else 1
    return _debian_part(lu, ru) or _debian_part(lr, rr)
