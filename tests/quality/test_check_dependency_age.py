#!/usr/bin/env python3
"""scripts/check-dependency-age.py: too-new, unreviewed-new and malicious dependency versions fail.

Each case builds a throwaway git repository whose base commit holds a lockfile, edits the working
tree, and runs the gate against the base with a lookup fixture in place of the registries and OSV.
"""
import bisect
import contextlib
import importlib.util
import io
import json
import re
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]


def escape(path: str) -> str:
    """Module path escaping (go.dev/ref/mod#goproxy-protocol): each capital becomes '!' and its lower case."""
    return re.sub(r'[A-Z]', lambda m: '!' + m.group(0).lower(), path)

spec = importlib.util.spec_from_file_location('check_dependency_age', ROOT / 'scripts/check-dependency-age.py')
gate = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = gate  # dataclasses look their module up here (3.12/3.13)
spec.loader.exec_module(gate)

TODAY = '2026-11-06'
BUN_LOCK = '''{{
  "lockfileVersion": 1,
  "workspaces": {{ "": {{ "name": "web", "dependencies": {{}} }} }},
  "packages": {{
{entries}
  }}
}}
'''


def bun_entry(name: str, version: str) -> str:
    return f'    "{name}": ["{name}@{version}", "", {{}}, "sha512-x"],\n'


class Repo:
    def __init__(self, directory: Path):
        self.root = directory
        self.run('init', '-q', '-b', 'main')
        self.run('config', 'user.email', 'gate@example.invalid')
        self.run('config', 'user.name', 'gate test')

    def run(self, *args: str) -> None:
        subprocess.run(['git', '-C', str(self.root), *args], check=True, capture_output=True)

    def write(self, path: str, text: str) -> None:
        target = self.root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text)

    def commit(self) -> None:
        self.run('add', '-A')
        self.run('commit', '-q', '-m', 'base')


def lock(*packages: tuple[str, str]) -> str:
    return BUN_LOCK.format(entries=''.join(bun_entry(n, v) for n, v in packages))


class DependencyAgeGateTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = Repo(Path(self.tmp.name))
        self.repo.write('web/bun.lock', lock(('left-pad', '1.3.0')))
        self.repo.commit()
        self.fixture = {'times': {'npm:left-pad@1.3.0': '2018-04-08T00:00:00Z'}, 'osv': {}}

    def tearDown(self):
        self.tmp.cleanup()

    def gate(self, base: str = 'HEAD') -> tuple[int, str]:
        fixture = Path(self.tmp.name) / 'fixture.json'
        fixture.write_text(json.dumps(self.fixture))
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = gate.main(['--root', str(self.repo.root), '--base', base, '--today', TODAY,
                              '--lookup-fixture', str(fixture), '--cache', str(Path(self.tmp.name) / 'cache.json')])
        return code, output.getvalue()

    def test_a_version_published_yesterday_fails(self):
        self.repo.write('web/bun.lock', lock(('left-pad', '1.3.1')))
        self.fixture['times']['npm:left-pad@1.3.1'] = '2026-11-05T12:00:00Z'
        code, out = self.gate()
        self.assertEqual(1, code, out)
        self.assertIn('npm:left-pad@1.3.1 (web/bun.lock): published 2026-11-05 12:00Z, 1.0 days ago; routine updates wait 7 days', out)

    def test_a_version_past_its_wait_passes(self):
        self.repo.write('web/bun.lock', lock(('left-pad', '1.3.1')))
        self.fixture['times']['npm:left-pad@1.3.1'] = '2026-10-20T00:00:00Z'
        code, out = self.gate()
        self.assertEqual(0, code, out)
        self.assertIn('result: 0 failure(s), 0 indeterminate', out)

    def test_a_major_update_waits_fourteen_days(self):
        self.repo.write('web/bun.lock', lock(('left-pad', '2.0.0')))
        self.fixture['times']['npm:left-pad@2.0.0'] = '2026-10-27T00:00:00Z'
        code, out = self.gate()
        self.assertEqual(1, code, out)
        self.assertIn('major updates wait 14 days', out)

    def test_a_security_fix_waits_three_days(self):
        self.repo.write('web/bun.lock', lock(('left-pad', '1.3.1')))
        self.fixture['times']['npm:left-pad@1.3.1'] = '2026-11-02T00:00:00Z'
        self.fixture['osv']['npm:left-pad@1.3.0'] = ['GHSA-aaaa-bbbb-cccc']
        code, out = self.gate()
        self.assertEqual(0, code, out)
        self.assertRegex(out, r'npm:left-pad@1\.3\.1\s+security\s+4\.5d of 3d')

    def test_an_osv_malicious_advisory_fails_even_with_an_exception(self):
        self.repo.write('web/bun.lock', lock(('left-pad', '1.3.1')))
        self.fixture['times']['npm:left-pad@1.3.1'] = '2026-10-01T00:00:00Z'
        self.fixture['osv']['npm:left-pad@1.3.1'] = ['MAL-2026-1234']
        self.repo.write('dependency-exceptions.toml', textwrap.dedent('''\
            [[exception]]
            ecosystem = "npm"
            name = "left-pad"
            version = "1.3.1"
            reviewer = "maintainer"
            note = "tested"
            expires = 2026-11-20
            '''))
        code, out = self.gate()
        self.assertEqual(1, code, out)
        self.assertIn('npm:left-pad@1.3.1: OSV MAL-2026-1234 marks this version malicious', out)

    def test_an_unchanged_package_flagged_malicious_later_still_fails(self):
        self.fixture['osv']['npm:left-pad@1.3.0'] = ['MAL-2026-9999']
        code, out = self.gate()
        self.assertEqual(1, code, out)
        self.assertIn('MAL-2026-9999', out)

    def test_a_new_package_without_an_additions_entry_fails(self):
        self.repo.write('web/bun.lock', lock(('left-pad', '1.3.0'), ('right-pad', '1.0.0')))
        self.fixture['times']['npm:right-pad@1.0.0'] = '2020-01-01T00:00:00Z'
        code, out = self.gate()
        self.assertEqual(1, code, out)
        self.assertIn('npm:right-pad@1.0.0 (web/bun.lock): new package name; add it to dependency-additions.toml', out)
        self.repo.write('dependency-additions.toml', textwrap.dedent('''\
            [[addition]]
            ecosystem = "npm"
            name = "right-pad"
            reviewer = "maintainer"
            reason = "pads on the right"
            '''))
        code, out = self.gate()
        self.assertEqual(0, code, out)

    def test_an_exception_admits_one_exact_version_and_must_expire(self):
        self.repo.write('web/bun.lock', lock(('left-pad', '1.3.1')))
        self.fixture['times']['npm:left-pad@1.3.1'] = '2026-11-05T12:00:00Z'
        entry = '[[exception]]\necosystem = "npm"\nname = "left-pad"\nversion = "1.3.1"\nreviewer = "maintainer"\n' \
                'note = "exploited CVE, reachable; reviewed diff"\nexpires = {expires}\n'
        self.repo.write('dependency-exceptions.toml', entry.format(expires='2026-11-20'))
        code, out = self.gate()
        self.assertEqual(0, code, out)
        self.assertIn('EXCEPTED', out)
        self.repo.write('dependency-exceptions.toml', entry.format(expires='2026-11-01'))
        code, out = self.gate()
        self.assertEqual(1, code, out)
        self.assertIn('expired on 2026-11-01', out)
        self.repo.write('dependency-exceptions.toml', entry.format(expires='2027-01-01'))
        self.assertEqual(1, self.gate()[0])

    def test_a_lookup_that_cannot_be_answered_is_indeterminate_not_a_pass(self):
        self.repo.write('web/bun.lock', lock(('left-pad', '1.3.1')))
        code, out = self.gate()
        self.assertEqual(2, code, out)
        self.assertIn('[indeterminate] npm:left-pad@1.3.1', out)

    def test_an_image_with_only_a_publisher_timestamp_needs_an_exception(self):
        digest = 'sha256:' + 'a' * 64
        self.repo.write('Dockerfile.app', f'FROM ghcr.io/example/app:1.0@{digest}\n')
        self.repo.write('dependency-additions.toml', '[[addition]]\necosystem = "oci"\nname = "ghcr.io/example/app"\n'
                        'reviewer = "maintainer"\nreason = "app base"\n')
        self.fixture['times'][f'oci:ghcr.io/example/app@1.0@{digest}'] = '2025-01-01T00:00:00Z publisher'
        code, out = self.gate()
        self.assertEqual(1, code, out)
        self.assertIn('only the publisher asserts its time', out)

    def test_a_manifest_pin_with_no_known_source_fails_closed(self):
        self.repo.write('toolchain-manifest.yaml', 'mystery_tool: "1.0"\n')
        self.repo.commit()
        self.repo.write('toolchain-manifest.yaml', 'mystery_tool: "2.0"\n')
        code, out = self.gate()
        self.assertEqual(1, code, out)
        self.assertIn('toolchain-manifest.yaml mystery_tool: changed pin with no publish-time source', out)

    def test_pins_present_when_the_policy_was_adopted_are_not_aged_again(self):
        adopted = subprocess.run(['git', '-C', str(self.repo.root), 'rev-parse', 'HEAD'], capture_output=True,
                                 text=True, check=True).stdout.strip()
        self.repo.run('checkout', '-q', '--orphan', 'older')
        self.repo.run('rm', '-rq', '--cached', '.')
        self.repo.write('web/bun.lock', lock())
        self.repo.commit()
        self.repo.write('web/bun.lock', lock(('left-pad', '1.3.0')))
        code, out = self.gate()
        self.assertEqual(1, code, out)  # left-pad is new against this base
        self.repo.write('dependency-additions.toml', f'[policy]\nadopted_at = "{adopted}"\n')
        code, out = self.gate()
        self.assertEqual(0, code, out)

    def test_a_newly_committed_lockfile_is_admitted_only_as_reviewed(self):
        base = self.head()
        self.repo.write('tool/go.sum', 'example.com/a v1.0.0 h1:x=\nexample.com/b v1.0.0/go.mod h1:y=\n')
        self.fixture['times'].update({'go:example.com/a@v1.0.0': '2024-01-01T00:00:00Z',
                                      'go:example.com/b@v1.0.0': '2024-01-01T00:00:00Z',
                                      'go:example.com/c@v1.0.0': '2024-01-01T00:00:00Z'})
        self.assertEqual(1, self.gate(base)[0])
        self.repo.commit()
        reviewed = self.head()
        # A lockfile approval without the reviewed revision would admit whatever the file holds later.
        row = ('[[addition]]\necosystem = "go"\nlockfile = "tool/go.sum"\n{revision}'
               'reviewer = "maintainer"\nreason = "pins what the build resolved before"\n')
        self.repo.write('dependency-additions.toml', row.format(revision=''))
        code, out = self.gate(base)
        self.assertEqual(1, code, out)
        self.assertIn('dependency-additions.toml go:tool/go.sum: a lockfile approval needs the reviewed revision', out)
        self.repo.write('dependency-additions.toml', row.format(revision=f'revision = "{reviewed}"\n'))
        code, out = self.gate(base)
        self.assertEqual(0, code, out)
        # A name added to the approved lockfile after the reviewed revision is a new, unreviewed name.
        self.repo.write('tool/go.sum', 'example.com/a v1.0.0 h1:x=\nexample.com/b v1.0.0/go.mod h1:y=\n'
                        'example.com/c v1.0.0 h1:z=\n')
        code, out = self.gate(base)
        self.assertEqual(1, code, out)
        self.assertIn('go:example.com/c@v1.0.0 (tool/go.sum): new package name', out)
        self.assertNotIn('go:example.com/a@v1.0.0 (tool/go.sum): new package name', out)
        self.repo.write('dependency-additions.toml', row.format(revision='revision = "0123456789abcdef0123456789abcdef01234567"\n'))
        code, out = self.gate(base)
        self.assertEqual(1, code, out)
        self.assertIn('cannot read tool/go.sum at 0123456789abcdef0123456789abcdef01234567', out)

    def head(self) -> str:
        return subprocess.run(['git', '-C', str(self.repo.root), 'rev-parse', 'HEAD'], capture_output=True, text=True,
                              check=True).stdout.strip()

    def test_a_malicious_version_being_removed_does_not_block_its_replacement(self):
        self.repo.write('web/bun.lock', lock(('left-pad', '1.3.1')))
        self.fixture['times']['npm:left-pad@1.3.1'] = '2026-10-01T00:00:00Z'
        self.fixture['osv']['npm:left-pad@1.3.0'] = ['MAL-2026-0001']
        code, out = self.gate()
        self.assertEqual(0, code, out)
        self.assertNotIn('[fail]', out)

    def test_remote_npm_sources_fail_closed_until_reviewed(self):
        lockfile = lock(('left-pad', '1.3.0')).replace('  }\n}', (
            '    "gh-pkg": ["gh-pkg@github:owner/repo#0123abcd", {}, "owner-repo-0123abcd"],\n'
            '    "reg-pkg": ["reg-pkg@1.0.0", "https://npm.example.invalid/reg-pkg/-/reg-pkg-1.0.0.tgz", {}, "sha512-y"],\n'
            '    "tar-pkg": ["tar-pkg@https://example.invalid/tar-pkg-1.0.0.tgz", {}],\n'
            '    "local": ["local@file:vendor/local", {}],\n'
            '  }\n}'))
        self.repo.write('web/bun.lock', lockfile)
        self.repo.write('web/vendor/local/package.json', '{}\n')
        code, out = self.gate()
        self.assertEqual(1, code, out)
        for name in ('gh-pkg', 'reg-pkg', 'tar-pkg'):
            self.assertIn(f'npm-source:{name}@', out)
        self.assertRegex(out, r'npm-source:gh-pkg@github:owner/repo#0123abcd \(web/bun\.lock\): remote source outside '
                              r'the npm registry')
        self.assertNotIn('local@', out)
        rows = ''.join(
            f'[[addition]]\necosystem = "npm-source"\nname = "{name}"\nsource = "{source}"\nreviewer = "maintainer"\n'
            f'reason = "read the source"\n'
            for name, source in (('gh-pkg', 'github:owner/repo#0123abcd'),
                                 ('reg-pkg', '1.0.0 https://npm.example.invalid/reg-pkg/-/reg-pkg-1.0.0.tgz'),
                                 ('tar-pkg', 'https://example.invalid/tar-pkg-1.0.0.tgz')))
        self.repo.write('dependency-additions.toml', rows)
        code, out = self.gate()
        self.assertEqual(0, code, out)
        # The review covers that exact source, not the next commit of the same repository.
        self.repo.write('web/bun.lock', lockfile.replace('#0123abcd', '#4567cdef'))
        code, out = self.gate()
        self.assertEqual(1, code, out)
        self.assertIn('npm-source:gh-pkg@github:owner/repo#4567cdef', out)

    def test_a_local_source_outside_the_repository_is_not_local(self):
        lockfile = lock(('left-pad', '1.3.0')).replace('  }\n}', (
            '    "outside": ["outside@file:../../elsewhere", {}],\n'
            '    "linked": ["linked@link:linked", {}],\n  }\n}'))
        self.repo.write('web/bun.lock', lockfile)
        code, out = self.gate()
        self.assertEqual(1, code, out)
        self.assertIn('npm-source:outside@file:../../elsewhere', out)
        self.assertIn('npm-source:linked@link:linked', out)


class LookupTests(unittest.TestCase):
    """Network lookups with the HTTP seam (Lookups.get) replaced by recorded registry answers."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.cache = Path(self.tmp.name) / 'cache.json'
        self.lookups = gate.Lookups(None, self.cache, float('inf'))
        self.requests: list[tuple[str, list]] = []
        self.answers: list = []
        self.lookups.get = self.fake_get
        pacing = mock.patch.object(gate, 'GO_INDEX_INTERVAL', 0.0)  # the real spacing is for index.golang.org
        pacing.start()
        self.addCleanup(pacing.stop)

    def tearDown(self):
        self.tmp.cleanup()

    def fake_get(self, urls, min_bytes=2, extra=None):
        url = urls[0][0] if isinstance(urls[0], tuple) else urls[0]
        args = urls[0][1] if isinstance(urls[0], tuple) else (extra or [])
        body = None
        if '--data-binary' in args:
            body = json.loads(Path(args[args.index('--data-binary') + 1].lstrip('@')).read_text())
        self.requests.append((url, body))
        answer = self.answers.pop(0)
        if isinstance(answer, Exception):
            raise answer
        return answer if isinstance(answer, bytes) else json.dumps(answer).encode()

    # -- OSV pagination
    def test_osv_pages_are_followed_until_every_query_is_exhausted(self):
        first, second = gate.Entry('npm', 'a', '1.0.0'), gate.Entry('npm', 'b', '1.0.0')
        self.answers = [
            {'results': [{'vulns': [{'id': 'GHSA-1'}], 'next_page_token': 'more-a'}, {'vulns': [{'id': 'GHSA-2'}]}]},
            {'results': [{'vulns': [{'id': 'MAL-2026-7'}]}]},
        ]
        found = self.lookups.advisories([first, second])
        self.assertEqual({'npm:a@1.0.0': ['GHSA-1', 'MAL-2026-7'], 'npm:b@1.0.0': ['GHSA-2']}, found)
        self.assertEqual([{'package': {'ecosystem': 'npm', 'name': 'a'}, 'version': '1.0.0', 'page_token': 'more-a'}],
                         self.requests[1][1]['queries'])

    def test_an_osv_page_that_cannot_be_fetched_is_indeterminate(self):
        self.answers = [{'results': [{'vulns': [], 'next_page_token': 'more'}]}, gate.LookupError_('timeout')]
        with self.assertRaises(gate.LookupError_):
            self.lookups.advisories([gate.Entry('npm', 'a', '1.0.0')])

    def test_osv_pagination_that_never_ends_is_indeterminate(self):
        self.answers = [{'results': [{'vulns': [], 'next_page_token': 'again'}]}] * 200
        with self.assertRaises(gate.LookupError_):
            self.lookups.advisories([gate.Entry('npm', 'a', '1.0.0')])

    # -- Docker Hub: a tag's push time is evidence only for the digest the tag holds
    def hub_tag(self, digest: str, platform_digest: str) -> dict:
        return {'digest': digest, 'images': [{'digest': platform_digest, 'architecture': 'amd64'}],
                'tag_last_pushed': '2025-01-01T00:00:00Z'}

    def test_hub_tag_time_counts_for_the_digest_the_tag_holds(self):
        pinned = 'sha256:' + 'a' * 64
        for document in (self.hub_tag(pinned, 'sha256:' + 'b' * 64), self.hub_tag('sha256:' + 'c' * 64, pinned)):
            with self.subTest(document=document):
                self.answers = [document]
                stamp, source = self.lookups._time_oci(gate.Entry('oci', 'docker.io/library/alpine', f'3.24@{pinned}'))
                self.assertEqual('Docker Hub tag_last_pushed', source)
                self.assertEqual(2025, stamp.year)

    def test_hub_tag_time_is_not_borrowed_for_another_digest(self):
        pinned = 'sha256:' + 'a' * 64
        self.answers = [self.hub_tag('sha256:' + 'c' * 64, 'sha256:' + 'd' * 64)]
        self.lookups._oci_created = lambda registry, repository, digest: gate.parse_time('2026-11-05T00:00:00Z')
        _stamp, source = self.lookups._time_oci(gate.Entry('oci', 'docker.io/library/alpine', f'3.24@{pinned}'))
        self.assertEqual('publisher', source)

    # -- Go: the module proxy's Time is the commit time; the first-cache time comes from index.golang.org
    class FakeGo:
        """proxy.golang.org .info, sum.golang.org/lookup and index.golang.org over one synthetic feed."""

        def __init__(self, rows: list[tuple[str, str, str]], commit: dict[str, str], unlogged: set[str] = frozenset()):
            self.rows = sorted(rows, key=lambda row: gate.parse_time(row[2]))
            self.times = [gate.parse_time(row[2]) for row in self.rows]
            keys = [f'{escape(p)}@{v}' for p, v, _ in self.rows]
            self.record = {key: 1000 + i for i, key in enumerate(keys) if key not in unlogged}
            self.commit, self.requests = commit, []

        def get(self, urls, min_bytes=2, extra=None):
            url = urls[0]
            self.requests.append(url)
            parsed = gate.urllib.parse.urlparse(url)
            if parsed.netloc == 'proxy.golang.org':
                key = parsed.path[1:].replace('/@v/', '@').removesuffix('.info')
                if key not in self.commit:
                    raise gate.LookupError_('HTTP 404')
                return json.dumps({'Version': key.split('@')[1], 'Time': self.commit[key]}).encode()
            if parsed.netloc == 'sum.golang.org' and parsed.path == '/latest':
                return f'go.sum database tree\n{1000 + len(self.rows)}\nhash=\n\n- sum.golang.org sig\n'.encode()
            if parsed.netloc == 'sum.golang.org':
                key = parsed.path.removeprefix('/lookup/')
                if key not in self.record:
                    raise gate.LookupError_('HTTP 404')
                return f'{self.record[key]}\n{key} h1:x=\n'.encode()
            query = gate.urllib.parse.parse_qs(parsed.query)
            since, limit = gate.parse_time(query['since'][0]), int(query['limit'][0])
            first = bisect.bisect_left(self.times, since)
            rows = self.rows[first:first + limit]
            return ''.join(json.dumps({'Path': p, 'Version': v, 'Timestamp': t}) + '\n' for p, v, t in rows).encode()

    def feed(self, target_at: int, commit: str, unlogged=frozenset(), count=20000, step=180):
        """count versions one every step seconds from 2026-08-01; the version under test is row target_at."""
        start = gate.parse_time('2026-08-01T00:00:00Z')
        rows = [(f'example.com/x{i}', 'v1.0.0', (start + gate.dt.timedelta(seconds=step * i)).strftime('%Y-%m-%dT%H:%M:%S.%fZ'))
                for i in range(count)]
        if target_at is not None:
            rows[target_at] = ('example.com/M', 'v1.0.0', rows[target_at][2])
        fake = self.FakeGo(rows, {'example.com/!m@v1.0.0': commit}, unlogged)
        self.lookups.get = fake.get
        return fake, rows

    def test_go_age_is_when_the_module_proxy_first_cached_the_version(self):
        fake, rows = self.feed(12345, '2026-08-20T00:00:00Z')
        stamp, source = self.lookups._time_go(gate.Entry('go', 'example.com/M', 'v1.0.0'))
        self.assertEqual(gate.parse_time(rows[12345][2]), stamp)
        self.assertEqual('index.golang.org first cached', source)
        self.assertLess(len(fake.requests), 60)  # a search, not a scan of the feed

    def test_a_backdated_go_tag_is_dated_by_its_first_cache_not_its_commit(self):
        _fake, rows = self.feed(19000, '2019-01-01T00:00:00Z')
        stamp, _ = self.lookups._time_go(gate.Entry('go', 'example.com/M', 'v1.0.0'))
        self.assertEqual(gate.parse_time(rows[19000][2]), stamp)

    def test_a_go_version_first_cached_long_after_its_commit_is_found_without_reading_the_feed_between(self):
        # 400000 versions over 46 days (the 2026 feed carries about 2000 an hour); first cached 45 days after its commit.
        fake, rows = self.feed(390000, '2026-07-31T00:00:00Z', count=400000, step=10)
        stamp, _ = self.lookups._time_go(gate.Entry('go', 'example.com/M', 'v1.0.0'))
        self.assertEqual(gate.parse_time(rows[390000][2]), stamp)
        self.assertLess(len(fake.requests), 30)

    def test_a_commit_time_after_the_first_cache_does_not_hide_the_version(self):
        _fake, rows = self.feed(5000, '2026-08-30T00:00:00Z')  # row 5000 is 2026-08-11
        stamp, _ = self.lookups._time_go(gate.Entry('go', 'example.com/M', 'v1.0.0'))
        self.assertEqual(gate.parse_time(rows[5000][2]), stamp)

    def test_an_index_rate_limit_is_waited_out(self):
        fake, rows = self.feed(12345, '2026-08-20T00:00:00Z')
        answer, limited = fake.get, [3]

        def get(urls, min_bytes=2, extra=None):
            if 'index.golang.org' in urls[0] and limited[0]:
                limited[0] -= 1
                raise gate.LookupError_(f'{urls[0]}: HTTP 429')
            return answer(urls, min_bytes, extra)
        self.lookups.get = get
        with mock.patch.object(gate, 'GO_INDEX_COOLDOWN', (0.0, 0.0, 0.0)):
            stamp, _ = self.lookups._time_go(gate.Entry('go', 'example.com/M', 'v1.0.0'))
        self.assertEqual(gate.parse_time(rows[12345][2]), stamp)

    def test_a_go_version_the_index_does_not_hold_is_indeterminate(self):
        fake, _ = self.feed(None, '2026-08-20T00:00:00Z')
        fake.record['example.com/!m@v1.0.0'] = 1000 + 12345
        with self.assertRaisesRegex(gate.LookupError_, 'index.golang.org has no row'):
            self.lookups._time_go(gate.Entry('go', 'example.com/M', 'v1.0.0'))

    def test_a_go_version_missing_from_the_checksum_database_is_indeterminate(self):
        self.feed(12345, '2026-08-20T00:00:00Z', unlogged={'example.com/!m@v1.0.0'})
        with self.assertRaises(gate.LookupError_):
            self.lookups._time_go(gate.Entry('go', 'example.com/M', 'v1.0.0'))

    def test_a_go_version_unknown_to_the_proxy_is_indeterminate(self):
        self.feed(12345, '2026-08-20T00:00:00Z')
        with self.assertRaises(gate.LookupError_):
            self.lookups._time_go(gate.Entry('go', 'example.com/other', 'v1.0.0'))

    def test_a_cached_go_time_from_a_retired_source_is_looked_up_again(self):
        for retired in ('proxy.golang.org', 'sum.golang.org, first witnessed'):
            with self.subTest(retired=retired):
                self.cache.write_text(json.dumps({'go:example.com/M@v1.0.0': ['2018-01-01T00:00:00+00:00', retired]}))
                self.lookups = gate.Lookups(None, self.cache, float('inf'))
                _fake, rows = self.feed(500, '2026-08-01T00:00:00Z')
                stamp, source = self.lookups.published(gate.Entry('go', 'example.com/M', 'v1.0.0'))
                self.assertEqual((gate.parse_time(rows[500][2]), 'index.golang.org first cached'), (stamp, source))

    def test_go_index_time_is_cached(self):
        fake, _ = self.feed(500, '2026-08-01T00:00:00Z')
        entry = gate.Entry('go', 'example.com/M', 'v1.0.0')
        self.lookups.published(entry)
        asked = len(fake.requests)
        self.lookups.published(entry)
        self.assertEqual(asked, len(fake.requests))

    def test_prefetch_dates_go_versions_and_keeps_each_failure_for_published(self):
        fake, rows = self.feed(12345, '2026-08-20T00:00:00Z')
        fake.commit['example.com/x7@v1.0.0'] = '2026-08-01T00:00:00Z'
        found, other = gate.Entry('go', 'example.com/M', 'v1.0.0'), gate.Entry('go', 'example.com/gone', 'v1.0.0')
        self.lookups.prefetch_go([found, other, gate.Entry('go', 'example.com/x7', 'v1.0.0')])
        asked = len(fake.requests)
        self.assertEqual(gate.parse_time(rows[12345][2]), self.lookups.published(found)[0])
        with self.assertRaises(gate.LookupError_):
            self.lookups.published(other)
        self.assertEqual(asked, len(fake.requests))


class ParserTests(unittest.TestCase):
    def test_parsers_read_each_pin_format(self):
        self.assertEqual({('maven', 'com.a:b', '1.2')},
                         {(e.ecosystem, e.name, e.version) for e in gate.parse_gradle_lockfile('com.a:b:1.2=runtimeClasspath\n', 'x')})
        self.assertEqual({('go', 'github.com/x/y', 'v1.0.0')},
                         {(e.ecosystem, e.name, e.version) for e in gate.parse_go_sum(
                             'github.com/x/y v1.0.0 h1:abc=\ngithub.com/x/y v1.0.0/go.mod h1:def=\n', 'go.sum')})
        image = gate.image_entry('percona/pg:18@sha256:' + 'b' * 64, 'Dockerfile')
        self.assertEqual(('oci', 'docker.io/percona/pg', '18@sha256:' + 'b' * 64), (image.ecosystem, image.name, image.version))
        self.assertEqual('docker.io/library/alpine', gate.image_entry('alpine:3@sha256:' + 'c' * 64, 'x').name)
        shell = gate.parse_shell('IMAGE="renovate/renovate:44.1.0@sha256:' + 'd' * 64 + '"\n', 'scripts/run.sh')
        self.assertEqual({('docker.io/renovate/renovate', '44.1.0@sha256:' + 'd' * 64)}, {(e.name, e.version) for e in shell})
        flat = gate.flatten_simple_yaml('bun: "1.4.4"  # pin\ngate_tools:\n  grype:\n    version: "0.1.0"\n')
        self.assertEqual({'bun': '1.4.4', 'gate_tools.grype.version': '0.1.0'}, flat)
        entries, unknown = gate.manifest_entries(flat, 'toolchain-manifest.yaml')
        self.assertEqual(set(), unknown)
        self.assertIn(('github-release', 'anchore/grype', 'v0.1.0'), {(e.ecosystem, e.name, e.version) for e in entries})


class PolicyNumberTests(unittest.TestCase):
    """check-dependency-age.py owns the waits; every other copy of a number must say the same."""

    # (file, pattern): every named group that matches is a number of days (or seconds, `_seconds`).
    COPIES = (
        ('renovate.json', r'"Waits: (?P<routine>\d+) days routine, (?P<major>\d+) days major, (?P<security>\d+) days security'),
        ('renovate.json', r'"Major updates wait (?P<major>\d+) days'),
        ('chronicle-web/bunfig.toml', r'^minimumReleaseAge = (?P<routine_seconds>\d+)$'),
        ('chronicle-web/bunfig.toml', r'younger than (?P<routine>\d+) days'),
        ('chronicle-web/bunfig.toml', r'waits the same (?P<routine>\d+) days'),
        ('docs/SUPPLY-CHAIN.md', r'^\| Routine [^|]*\| (?P<routine>\d+) days \|'),
        ('docs/SUPPLY-CHAIN.md', r'minimumReleaseAge = (?P<routine_seconds>\d+)'),
        ('docs/SUPPLY-CHAIN.md', r'^\| Major \| (?P<major>\d+) days \|'),
        ('docs/SUPPLY-CHAIN.md', r'^\| Security fix [^|]*\| (?P<security>\d+) days \|'),
        ('docs/SUPPLY-CHAIN.md', r'# at most (?P<exception>\d+) days ahead'),
        ('scripts/dependency-intake.sh', r'\((?P<routine>\d+) days routine, (?P<major>\d+) major, (?P<security>\d+) security\)'),
        ('scripts/publish-images.sh', r'(?P<routine>\d+) days routine, (?P<major>\d+) major, (?P<security>\d+) security'),
        ('scripts/local-ci.sh', r'younger than the wait \((?P<routine>\d+)/(?P<major>\d+)/(?P<security>\d+) days\)'),
        ('dependency-exceptions.toml', (r'The waits are (?P<routine>\d+) days routine, (?P<major>\d+) days major, '
                                        r'(?P<security>\d+) days security')),
        ('dependency-exceptions.toml', r'no more than (?P<exception>\d+) days ahead'),
        ('scripts/check-dependency-age.py', (r'(?P<routine>\d+) days routine, (?P<major>\d+) days for a major '
                                             r'version change, (?P<security>\d+) days when')),
        ('scripts/check-dependency-age.py', r'no more than (?P<exception>\d+) days ahead'),
        ('tests/security/supply-chain-guardrails.sh', r'age < (?P<routine_seconds>\d+):'),
        ('tests/security/supply-chain-guardrails.sh', r'at least (?P<routine_seconds>\d+) seconds'),
        ('tests/security/supply-chain-guardrails.sh', r'younger than (?P<routine>\d+) days'),
    )

    @classmethod
    def setUpClass(cls):
        result = subprocess.run(['python3', str(ROOT / 'scripts/check-dependency-age.py'), '--print-policy'],
                                capture_output=True, text=True, check=True)
        cls.policy = json.loads(result.stdout)

    def expected(self, group: str) -> int:
        days = self.policy[group.removesuffix('_seconds') + '_days']
        return days * 86400 if group.endswith('_seconds') else days

    def test_the_owner_prints_the_policy(self):
        self.assertEqual({'routine_days': gate.ROUTINE_DAYS, 'major_days': gate.MAJOR_DAYS,
                          'security_days': gate.SECURITY_DAYS, 'exception_days': gate.MAX_EXCEPTION_DAYS}, self.policy)

    def test_every_copy_of_a_wait_matches_the_owner(self):
        for relative, pattern in self.COPIES:
            path = ROOT / relative
            if relative.startswith('chronicle-web/') and not path.exists():
                continue  # submodule not initialised in this checkout
            with self.subTest(file=relative, pattern=pattern):
                matches = list(re.finditer(pattern, path.read_text(), re.MULTILINE))
                self.assertTrue(matches, f'{relative} no longer states this number; update COPIES with the file')
                for match in matches:
                    for group, value in match.groupdict().items():
                        self.assertEqual(self.expected(group), int(value), f'{relative}: {match.group(0)!r}')

    def test_renovate_waits_match_the_owner(self):
        config = json.loads((ROOT / 'renovate.json').read_text())
        self.assertEqual(f'{self.policy["routine_days"]} days', config['minimumReleaseAge'])
        majors = [rule for rule in config['packageRules']
                  if rule.get('matchUpdateTypes') == ['major'] and 'matchPackageNames' not in rule]
        self.assertEqual([f'{self.policy["major_days"]} days'], [rule.get('minimumReleaseAge') for rule in majors])
        self.assertEqual(f'{self.policy["security_days"]} days', config['vulnerabilityAlerts']['minimumReleaseAge'])

    def test_a_changed_number_is_caught(self):
        relative, pattern = self.COPIES[0]
        text = (ROOT / relative).read_text().replace(f'"Waits: {self.policy["routine_days"]} days routine',
                                                      f'"Waits: {self.policy["routine_days"] + 1} days routine')
        match = re.search(pattern, text, re.MULTILINE)
        self.assertNotEqual(self.expected('routine'), int(match.group('routine')))


if __name__ == '__main__':
    unittest.main()
