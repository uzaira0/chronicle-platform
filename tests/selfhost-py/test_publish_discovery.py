"""A release about to be published must be found by every installed release that can update to it.

An installed server discovers releases with its own, older chronicle_ops/update.py. This test
builds the catalog row GitHub serves once the publisher's draft is published (the assets that
scripts/publish-images.sh uploads) and runs discovery with the code of every published release
at or above the upgrade floor, read from its git tag, and with the code in this tree."""

import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'selfhost'))

from chronicle_ops.release import UPGRADE_FROM_MINIMUM, parse_version  # noqa: E402

DISCOVER = '''
import json, sys
from chronicle_ops.update import release_assets, select_release
catalog, version = json.load(sys.stdin), sys.argv[3]  # argv: -c, package root, this code, version
chosen = select_release(catalog)
assets = release_assets(chosen, f"chronicle-selfhost-{version}.tar.gz")
print(json.dumps([chosen["tag_name"], [asset.url for asset in assets.all()]]))
'''


def next_release():
    """The version this tree will publish: the newest CHANGELOG section."""
    match = re.search(r'^## \[(\d{4}\.\d+\.\d+)\]', (ROOT / 'CHANGELOG.md').read_text(), re.MULTILINE)
    return match[1]


def uploaded_assets(version):
    """The asset names scripts/publish-images.sh uploads with `gh release create`."""
    script = (ROOT / 'scripts/publish-images.sh').read_text()
    assert 'bundle="build/releases/chronicle-selfhost-${release#v}.tar.gz"' in script
    # The command itself: comments and messages in the script also name `gh release create`.
    create = next(line for line in script.splitlines() if line.startswith('run gh release create '))
    following = script[script.index(create):].split('\n', 2)[1]
    assert '"$bundle" "$bundle.sha256" "$bundle.sha256.sig"' in following, following
    archive = f'chronicle-selfhost-{version}.tar.gz'
    return [archive, archive + '.sha256', archive + '.sha256.sig', 'sca-evidence.json']


def published_catalog(version):
    def row(tag, names):
        return dict(tag_name=tag, draft=False, prerelease=False, assets=[
            dict(name=name, browser_download_url=f'https://github.com/uzaira0/chronicle-platform/releases/download/{tag}/{name}')
            for name in names])
    previous = f'chronicle-selfhost-{UPGRADE_FROM_MINIMUM}.tar.gz'
    return [row(version, uploaded_assets(version)),
            row(UPGRADE_FROM_MINIMUM, [previous, previous + '.sha256', previous + '.sha256.sig'])]


def supported_tags(version):
    tags = subprocess.run(['git', '-C', str(ROOT), 'tag', '--list'], capture_output=True, text=True, check=True).stdout.split()
    floor, target = parse_version(UPGRADE_FROM_MINIMUM, 'floor'), parse_version(version, 'release')
    supported = []
    for tag in tags:
        try:
            key = parse_version(tag.removeprefix('v'), 'tag')
        except ValueError:
            continue
        if floor <= key < target and key[3][0] == 1:  # stable releases at or above the floor
            supported.append(tag)
    return supported


class PublishDiscoveryTests(unittest.TestCase):
    def discover(self, package_root, catalog, version):
        result = subprocess.run([sys.executable, '-I', '-c', 'import sys; sys.path.insert(0, sys.argv[1]); exec(sys.argv[2])',
                                 str(package_root), DISCOVER, version],
                                input=json.dumps(catalog), capture_output=True, text=True, timeout=30)
        self.assertEqual(0, result.returncode, result.stderr)
        return json.loads(result.stdout)

    def test_every_supported_release_discovers_the_release_being_published(self):
        version = next_release()
        catalog = published_catalog(version)
        expected = [version, [f'https://github.com/uzaira0/chronicle-platform/releases/download/{version}/chronicle-selfhost-{version}.tar.gz{suffix}'
                              for suffix in ('', '.sha256', '.sha256.sig')]]
        self.assertEqual(expected, self.discover(ROOT / 'selfhost', catalog, version))
        tags = supported_tags(version)
        self.assertIn('2026.11.2', tags, 'run `git fetch --tags`: discovery must be checked against every supported release')
        for tag in tags:
            with self.subTest(installed=tag), tempfile.TemporaryDirectory() as folder:
                archive = subprocess.run(['git', '-C', str(ROOT), 'archive', '--format=tar', tag, 'selfhost/chronicle_ops'],
                                         capture_output=True, check=True).stdout
                with tarfile.open(fileobj=io.BytesIO(archive)) as members:
                    members.extractall(folder, **({'filter': 'data'} if hasattr(tarfile, 'data_filter') else {}))
                self.assertEqual(expected, self.discover(Path(folder) / 'selfhost', catalog, version))


def load_checker():
    import importlib.util
    spec = importlib.util.spec_from_file_location('check_release_discovery', ROOT / 'scripts/check-release-discovery.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def promotion_catalog(version):
    """What `gh api --paginate --slurp repos/<public>/releases` returns at promotion: the real
    catalog recorded from the GitHub API on 2026-11-06 (github_releases_api.json, bodies emptied)
    with the publisher's draft of `version` on top, in the API's own row shape. The recording
    named the repository uzaira0/methodic; the rename of 2026-11-10 replaced that name in the
    file's URLs, which is what the API serves since (on 2026-11-11 the same 14 rows, ids and
    URLs under the old and the new name)."""
    import copy
    recorded = json.loads((Path(__file__).with_name('github_releases_api.json')).read_text())
    draft = copy.deepcopy(recorded[0])
    old = draft['tag_name']
    draft.update(tag_name=version, name=version, draft=True, prerelease=False, published_at=None,
                 html_url=draft['html_url'].replace('/tag/' + old, '/untagged-0123456789abcdef'))
    template = draft['assets'][0]
    draft['assets'] = []
    for name in uploaded_assets(version):
        asset = copy.deepcopy(template)
        asset.update(name=name, browser_download_url=f'https://github.com/uzaira0/chronicle-platform/releases/download/{version}/{name}')
        draft['assets'].append(asset)
    return [[draft, *recorded]]  # --slurp: one list per page


def recorded_list():
    """What GitHub answers the release-list request of an installed release with: the recorded
    catalog, which holds published releases only."""
    return Path(__file__).with_name('github_releases_api.json').read_bytes()


def recorded_feed():
    """The releases feed GitHub returned on 2026-11-11 for the repository's old name, after the
    rename (github_releases_feed.atom, release notes cut): every link carries the new name."""
    return Path(__file__).with_name('github_releases_feed.atom').read_bytes()


# Where 2026.11.2's updater looks for releases (update.py:228 at the tag).
OLD_NAME_LIST = 'https://api.github.com/repos/uzaira0/methodic/releases?per_page=100'

# update.py's feed pattern in the candidate bundle built before the rename, with its repository name.
AS_BUILT_REPOSITORY = 'RELEASES_REPOSITORY = "uzaira0/methodic"'
AS_BUILT_FEED_TAG = ("FEED_TAG = re.compile(r'href=\"https://github\\.com/' + re.escape(RELEASES_REPOSITORY)"
                     " + r'/releases/tag/([^\"/?#]+)\"')")


def bundle_of(folder, version, as_built=False):
    """A release bundle with the one part the check reads, its chronicle_ops: this tree's, or this
    tree's with the feed pattern of the bundle built before the rename."""
    package = Path(folder) / 'chronicle_ops'
    shutil.copytree(ROOT / 'selfhost/chronicle_ops', package, ignore=shutil.ignore_patterns('__pycache__'))
    if as_built:
        source = (package / 'update.py').read_text()
        changed, names = re.subn(r'(?m)^RELEASES_REPOSITORY = .*$', lambda _: AS_BUILT_REPOSITORY, source)
        changed, patterns = re.subn(r'(?m)^FEED_TAG = .*$', lambda _: AS_BUILT_FEED_TAG, changed)
        assert (names, patterns) == (1, 1), (names, patterns)
        (package / 'update.py').write_text(changed)
    archive = Path(folder) / f'chronicle-selfhost-{version}.tar.gz'
    with tarfile.open(archive, 'w:gz') as bundle:
        bundle.add(package, f'chronicle-selfhost-{version}/selfhost/chronicle_ops')
    return archive


FAKE_CURL = '''#!{python}
import json, sys
with open({log!r}, "a") as log:
    log.write(json.dumps(sys.argv[1:]) + "\\n")
if not {status}:
    with open({feed!r}, "rb") as feed:
        sys.stdout.buffer.write(feed.read())
sys.stderr.write({said!r})
sys.exit({status})
'''


class PromotionCatalogTests(unittest.TestCase):
    """UPD-N2: the first update from 2026.11.2 runs 2026.11.2's own discovery, which refuses the whole
    catalog for one row it cannot parse (update.py:216-219 at the tag). Promotion runs
    scripts/check-release-discovery.py on the catalog it is about to publish: every supported
    installed release's own fetch_published_releases, select_release and release_assets, from its
    git tag, over HTTP with GitHub's paging, must select the release being published.

    The release being promoted must also find releases through its second source, GitHub's
    releases feed, as GitHub serves it on the day: a candidate bundle built before the repository
    was renamed looked for the old name in the feed's links and listed no release."""

    def test_the_catalog_after_promotion_is_discovered_by_every_supported_release(self):
        checker = load_checker()
        version = next_release()
        catalog = checker.anonymous_catalog(checker.catalog_rows(promotion_catalog(version)), version)
        self.assertEqual(version, catalog[0]['tag_name'])
        self.assertFalse(catalog[0]['draft'])
        results = checker.check(ROOT, catalog, version, recorded_feed(), listing=recorded_list())
        self.assertIn('2026.11.2', [installed for installed, _ in results])
        self.assertIn(f'2026.11.2 release list ({OLD_NAME_LIST})', [installed for installed, _ in results])
        self.assertEqual(['this tree', 'this tree (releases feed)'], [installed for installed, _ in results][-2:])
        self.assertEqual([], [(installed, problem) for installed, problem in results if problem])

    def test_a_row_2026_11_2_would_reject_stops_the_promotion(self):
        checker = load_checker()
        version = next_release()
        rows = checker.catalog_rows(promotion_catalog(version))
        for name, change in (('non-version tag', {'tag_name': 'published-2026-11-06'}),
                             ('missing prerelease flag', {'prerelease': None})):
            with self.subTest(name):
                broken = json.loads(json.dumps(rows))
                broken[3].update(change)
                broken[3] = {key: item for key, item in broken[3].items() if item is not None}
                results = dict(checker.check(ROOT, checker.anonymous_catalog(broken, version), version, recorded_feed(),
                                             published=checker.published_now(rows), listing=recorded_list()))
                self.assertTrue(results['2026.11.2'], results)

    def test_other_drafts_are_invisible_to_an_installed_server(self):
        checker = load_checker()
        version = next_release()
        pages = promotion_catalog(version)
        other = dict(pages[0][1], tag_name='not-a-version', draft=True)
        catalog = checker.anonymous_catalog(checker.catalog_rows([[*pages[0], other]]), version)
        self.assertNotIn('not-a-version', [row['tag_name'] for row in catalog])

    def test_the_documented_mirror_path_works_with_2026_11_2s_own_discovery(self):
        """UPGRADE-ROLLBACK.md's one-time path for a proxy-only 2026.11.2 host: its releases.json,
        served without a proxy, is what 2026.11.2's code reads from CHRONICLE_RELEASES_URL, and it
        selects the release and downloads every asset from the mirror."""
        checker = load_checker()
        guide = (ROOT / 'selfhost/docs/UPGRADE-ROLLBACK.md').read_text()
        section = guide[guide.index('### The first update from 2026.11.2'):]
        catalog = json.loads(re.search(r'```json\n(.*?)```', section, re.DOTALL)[1])
        self.assertIn('CHRONICLE_RELEASES_URL=https://mirror.example.internal/chronicle/releases.json ./chronicle update', section)
        version = catalog[0]['tag_name']
        server = checker.serve(catalog)
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        url = f'http://127.0.0.1:{server.server_address[1]}/chronicle/releases.json'
        with tempfile.TemporaryDirectory() as folder:
            archive = subprocess.run(['git', '-C', str(ROOT), 'archive', '--format=tar', '2026.11.2', 'selfhost/chronicle_ops'],
                                     capture_output=True, check=True).stdout
            with tarfile.open(fileobj=io.BytesIO(archive)) as members:
                members.extractall(folder, filter='data')
            for installed, package in (('2026.11.2', Path(folder) / 'selfhost'), ('this tree', ROOT / 'selfhost')):
                with self.subTest(installed=installed):
                    tag, urls = checker.discovered(package, url, version)
                    self.assertEqual(version, tag)
                    self.assertEqual([f'https://mirror.example.internal/chronicle/chronicle-selfhost-{version}.tar.gz{suffix}'
                                      for suffix in ('', '.sha256', '.sha256.sig')], urls)

    def test_promotion_runs_the_check_before_publishing_the_draft(self):
        script = (ROOT / 'scripts/publish-images.sh').read_text()
        check = script.index('scripts/check-release-discovery.py')
        self.assertLess(script.index('catalog=$(gh api --paginate --slurp'), check)
        self.assertLess(check, script.index('gh release edit "$release"'))

    def test_promotion_checks_the_bundle_it_downloaded_against_the_live_feed(self):
        """The bundle that is about to be published is the code servers will run, so its own
        updater is checked, not this tree's; and no saved feed is passed, so the feed is read
        from GitHub at promotion."""
        script = (ROOT / 'scripts/publish-images.sh').read_text()
        self.assertIn('name="chronicle-selfhost-${release#v}.tar.gz"', script)
        self.assertIn('gh release download "$release" --repo "$public_repo" --dir "$candidate_dir"', script)
        invocation = next(line for line in script.splitlines() if 'scripts/check-release-discovery.py' in line)
        self.assertIn(' --bundle "$candidate_dir/$name" ', invocation)
        self.assertNotIn('--feed', invocation)

    def test_the_feed_after_promotion_lists_this_release_first_in_the_feeds_own_form(self):
        checker = load_checker()
        version = next_release()
        served, tags = checker.published_feed(recorded_feed(), version)
        self.assertEqual([version, '2026.11.2', '2026.10.9'], tags[:3])
        self.assertEqual(11, len(tags))
        self.assertEqual(11, served.count(b'<entry>'))
        link = f'<link rel="alternate" type="text/html" href="https://github.com/uzaira0/chronicle-platform/releases/tag/{version}"/>'
        self.assertLess(served.index(link.encode()), served.index(b'/releases/tag/2026.11.2"'))
        # Already published (a rerun after promotion): nothing is added.
        again, same = checker.published_feed(served, version)
        self.assertEqual((served, tags), (again, same))
        for name, broken in (('an HTML page', b'<html><body>Just a moment...</body></html>'),
                             ('no entries', recorded_feed().split(b'<entry>')[0] + b'</feed>'),
                             ('an entry without a release link', recorded_feed().replace(b'/releases/tag/2026.10.9"', b'/commits/main"'))):
            with self.subTest(name), self.assertRaises(ValueError):
                checker.published_feed(broken, version)

    def test_a_bundle_that_cannot_read_the_feed_stops_the_promotion(self):
        """The promotion command line, on the catalog and feed as recorded: a bundle of this tree
        passes; the same bundle with the pre-rename feed pattern still selects the release from
        the API catalog, lists nothing from the feed, and is refused."""
        version = next_release()
        with tempfile.TemporaryDirectory() as folder:
            folder = Path(folder)
            (folder / 'catalog.json').write_text(json.dumps(promotion_catalog(version)))
            (folder / 'feed.atom').write_bytes(recorded_feed())
            for name, as_built in (('this tree', False), ('built before the rename', True)):
                with self.subTest(name):
                    (folder / name).mkdir()
                    bundle = bundle_of(folder / name, version, as_built)
                    result = subprocess.run([sys.executable, str(ROOT / 'scripts/check-release-discovery.py'), version,
                                             '--catalog', str(folder / 'catalog.json'), '--feed', str(folder / 'feed.atom'),
                                             '--release-list', str(Path(__file__).with_name('github_releases_api.json')),
                                             '--bundle', str(bundle)], capture_output=True, text=True, timeout=300)
                    lines = result.stdout.splitlines()
                    self.assertIn(f'2026.11.2: selects {version}', lines, result.stdout + result.stderr)
                    self.assertIn(f"2026.11.2 release list ({OLD_NAME_LIST}): answers with this repository's published releases", lines)
                    self.assertIn(f'the bundle: selects {version}', lines, result.stdout + result.stderr)
                    self.assertNotIn('this tree', result.stdout)
                    if as_built:
                        self.assertEqual(1, result.returncode, result.stdout + result.stderr)
                        self.assertIn('the bundle (releases feed): FAILS: ValueError: release feed lists no releases', lines)
                        self.assertIn('rebuild', result.stderr)
                    else:
                        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
                        self.assertIn(f'the bundle (releases feed): selects {version}', lines)

    def test_an_installed_releases_own_release_list_must_be_this_repositorys_published_releases(self):
        """2026.11.2 asks https://api.github.com/repos/uzaira0/methodic/releases, the repository's
        name before 2026-11-10, and nothing else. The address is read from its own code (it is
        built inside fetch_published_releases there) and its answer is compared, by release id and
        tag, with the published rows of the catalog promotion fetched. Here the answer is a saved
        one; test_publish_promotion asks a loopback server through a real redirect."""
        checker = load_checker()
        version = next_release()
        rows = checker.catalog_rows(promotion_catalog(version))
        published = checker.published_now(rows)
        self.assertEqual(14, len(published))
        self.assertNotIn(version, [row['tag_name'] for row in published])  # the draft is not published yet
        label = f'2026.11.2 release list ({OLD_NAME_LIST})'

        def problem(listing):
            results = dict(checker.check(ROOT, checker.anonymous_catalog(rows, version), version, recorded_feed(),
                                         published=published, listing=listing))
            return results[label]
        self.assertIsNone(problem(recorded_list()))
        other = [dict(row, id=row['id'] + 1) for row in published]  # the same tags in another repository
        for name, listing, reason in (
                ('another repository with the same tags', json.dumps(other).encode(), "does not return this repository's published releases: it lists 14 (0 of"),
                ('a repository without releases', b'[]', "does not return this repository's published releases: it lists 0 (0 of"),
                ('this repository and releases the catalog does not hold', json.dumps([*published, dict(id=7, tag_name='2027.1.1')]).encode(),
                 "it lists 15 (14 of this repository's 14; others: 2027.1.1)"),
                ('an error document', b'{"message": "Not Found"}', 'did not answer with a list of releases'),
                ('a page that is not JSON', b'<html>Just a moment...</html>', 'did not answer with JSON')):
            with self.subTest(name):
                self.assertIn(OLD_NAME_LIST + ' ', problem(listing))
                self.assertIn(reason, problem(listing))
        # Some of this repository's releases and nothing else: an earlier state of its list, which
        # GitHub's cache for requests without credentials serves for a while after a publish.
        self.assertIsNone(problem(json.dumps(published[1:]).encode()))

    def test_one_page_of_a_long_release_list_is_enough_when_every_row_is_this_repositorys(self):
        checker = load_checker()
        rows = [dict(id=number, tag_name=f'2026.1.{number}', draft=False) for number in range(1, 131)]
        url = 'https://api.github.com/repos/o/n/releases?per_page=100'
        self.assertIsNone(checker.list_problem(url, json.dumps(rows[:100]), rows))
        notes = []
        self.assertIsNone(checker.list_problem(url, json.dumps(rows[:99]), rows, notes.append))
        self.assertIn("99 of this repository's 130 published releases", notes[0])
        self.assertIn('others: 2027.1.1', checker.list_problem(url, json.dumps([*rows[:99], dict(id=999, tag_name='2027.1.1')]), rows))

    def test_a_feed_reader_that_misses_entries_is_reported(self):
        checker = load_checker()
        version = next_release()
        served, tags = checker.published_feed(recorded_feed(), version)
        server = checker.serve([], served)
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        url = f'http://127.0.0.1:{server.server_address[1]}/fixture/releases.atom'
        self.assertIsNone(checker.discover_feed(ROOT / 'selfhost', url, version, tags))
        self.assertEqual(f"lists 11 of the feed's 12 releases ({', '.join(tags)})",
                         checker.discover_feed(ROOT / 'selfhost', url, version, [*tags, '2026.9.22']))

    def live_feed(self, folder, status, said='', checker=None, **environment):
        checker = checker or load_checker()
        folder = Path(folder)
        (folder / 'feed.atom').write_bytes(recorded_feed())
        curl = folder / 'curl'
        curl.write_text(FAKE_CURL.format(python=sys.executable, log=str(folder / 'curl.log'),
                                         feed=str(folder / 'feed.atom'), status=status, said=said))
        curl.chmod(0o755)
        with patch.dict(os.environ, {'PATH': str(folder) + os.pathsep + os.environ['PATH'],
                                     'GH_TOKEN': 'not-sent', 'GITHUB_TOKEN': 'not-sent', **environment}):
            try:
                answer = checker.live_feed(ROOT / 'selfhost')
            except ValueError as error:
                answer = error
        return answer, [json.loads(line) for line in (folder / 'curl.log').read_text().splitlines()]

    def test_the_live_feed_is_one_get_by_the_releases_own_updater_without_credentials(self):
        """With no saved feed the check asks GitHub, as an installed server does when the API
        refuses it: the release's own curl call on the release's own feed URL, redirects followed,
        no token. A recorded copy would still show the names of the day it was recorded."""
        from chronicle_ops.update import FEED_RELEASES_URL
        with tempfile.TemporaryDirectory() as folder:
            feed, calls = self.live_feed(folder, 0)
        self.assertEqual(recorded_feed(), feed)
        self.assertEqual(1, len(calls))
        self.assertEqual(FEED_RELEASES_URL, calls[0][-1])
        self.assertIn('--location', calls[0])
        self.assertFalse([argument for argument in calls[0] if 'not-sent' in argument or argument in ('-H', '--header', '-u', '--user')])

    def test_a_feed_that_cannot_be_fetched_stops_the_check(self):
        with tempfile.TemporaryDirectory() as folder:
            answer, calls = self.live_feed(folder, 47)  # too many redirects: curl does not retry it
        self.assertIsInstance(answer, ValueError)
        self.assertIn('releases feed', str(answer))
        self.assertEqual(1, len(calls))

    def test_a_feed_that_was_not_reached_or_was_refused_for_now_is_not_a_verdict_on_the_release(self):
        """A connection that fails, and an answer that refuses the request for now (429, a server
        error), say nothing about what the feed holds. They are named as what they are, as
        Unread, which promotion reports as a check that could not be completed. The release's
        own curl call has already retried inside its deadline."""
        checker = load_checker()
        for status, said, named in ((7, "curl: (7) Failed to connect to github.com port 443 after 12 ms: Couldn't connect to server\n",
                                     'the releases feed was not read: curl: (7) Failed to connect to github.com port 443'),
                                    (22, 'curl: (22) The requested URL returned error: 429\n',
                                     'the releases feed was not read: curl: (22) The requested URL returned error: 429'),
                                    (22, 'curl: (22) The requested URL returned error: 503\n',
                                     'the releases feed was not read: curl: (22) The requested URL returned error: 503')):
            with self.subTest(said=said), tempfile.TemporaryDirectory() as folder:
                answer, calls = self.live_feed(folder, status, said, checker, CHRONICLE_TRANSFER_TIMEOUT_SECONDS='4')
                self.assertIsInstance(answer, checker.Unread)
                self.assertIn(named, str(answer))
                self.assertGreaterEqual(len(calls), 2)

    def test_a_feed_address_that_is_gone_is_a_verdict_on_the_release(self):
        """404 from the feed address the promoted release reads: its second source is dead, and
        asking again does not change that."""
        checker = load_checker()
        with tempfile.TemporaryDirectory() as folder:
            answer, _ = self.live_feed(folder, 22, 'curl: (22) The requested URL returned error: 404\n', checker,
                                       CHRONICLE_TRANSFER_TIMEOUT_SECONDS='4')
        self.assertIsInstance(answer, ValueError)
        self.assertNotIsInstance(answer, checker.Unread)
        self.assertIn('answers 404', str(answer))

    def test_a_check_that_could_not_ask_github_exits_75_and_says_it_can_be_run_again(self):
        """The checker's exit status tells promotion which sentence to print: 1 when a check
        failed, 75 (EX_TEMPFAIL) when GitHub could not be asked and nothing is known."""
        version = '9999.1.1'
        with tempfile.TemporaryDirectory() as folder:
            folder = Path(folder)
            (folder / 'catalog.json').write_text(json.dumps(promotion_catalog(version)))
            (folder / 'list.json').write_bytes(recorded_list())
            curl = folder / 'curl'
            curl.write_text(FAKE_CURL.format(python=sys.executable, log=str(folder / 'curl.log'), feed=str(folder / 'none'), status=6,
                                             said='curl: (6) Could not resolve host: github.com\n'))
            curl.chmod(0o755)
            result = subprocess.run(
                [sys.executable, str(ROOT / 'scripts/check-release-discovery.py'), version, '--catalog', str(folder / 'catalog.json'),
                 '--release-list', str(folder / 'list.json')],
                env=dict(os.environ, PATH=str(folder) + os.pathsep + os.environ['PATH'], CHRONICLE_TRANSFER_TIMEOUT_SECONDS='2',
                         PYTHONDONTWRITEBYTECODE='1'),
                capture_output=True, text=True, timeout=120, check=False)
        self.assertEqual(75, result.returncode, result.stdout + result.stderr)
        self.assertIn('error: the releases feed was not read: curl: (6) Could not resolve host: github.com', result.stderr)
        self.assertIn('nothing was published, and the promotion can be run again', result.stderr)


if __name__ == '__main__':
    unittest.main()
