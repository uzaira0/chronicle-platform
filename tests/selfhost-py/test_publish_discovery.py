"""A release about to be published must be found by every installed release that can update to it.

An installed server discovers releases with its own, older chronicle_ops/update.py. This test
builds the catalog row GitHub serves once the publisher's draft is published (the assets that
scripts/publish-images.sh uploads) and runs discovery with the code of every published release
at or above the upgrade floor, read from its git tag, and with the code in this tree."""

import io
import json
from pathlib import Path
import re
import subprocess
import sys
import tarfile
import tempfile
import unittest

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
    create = next(line for line in script.splitlines() if 'gh release create' in line)
    following = script[script.index(create):].split('\n', 2)[1]
    assert '"$bundle" "$bundle.sha256" "$bundle.sha256.sig"' in following, following
    archive = f'chronicle-selfhost-{version}.tar.gz'
    return [archive, archive + '.sha256', archive + '.sha256.sig', 'sca-evidence.json']


def published_catalog(version):
    def row(tag, names):
        return dict(tag_name=tag, draft=False, prerelease=False, assets=[
            dict(name=name, browser_download_url=f'https://github.com/uzaira0/methodic/releases/download/{tag}/{name}')
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
        expected = [version, [f'https://github.com/uzaira0/methodic/releases/download/{version}/chronicle-selfhost-{version}.tar.gz{suffix}'
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
    with the publisher's draft of `version` on top, in the API's own row shape."""
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
        asset.update(name=name, browser_download_url=f'https://github.com/uzaira0/methodic/releases/download/{version}/{name}')
        draft['assets'].append(asset)
    return [[draft, *recorded]]  # --slurp: one list per page


class PromotionCatalogTests(unittest.TestCase):
    """UPD-N2: the first update from 2026.11.2 runs 2026.11.2's own discovery, which refuses the whole
    catalog for one row it cannot parse (update.py:216-219 at the tag). Promotion runs
    scripts/check-release-discovery.py on the catalog it is about to publish: every supported
    installed release's own fetch_published_releases, select_release and release_assets, from its
    git tag, over HTTP with GitHub's paging, must select the release being published."""

    def test_the_catalog_after_promotion_is_discovered_by_every_supported_release(self):
        checker = load_checker()
        version = next_release()
        catalog = checker.anonymous_catalog(checker.catalog_rows(promotion_catalog(version)), version)
        self.assertEqual(version, catalog[0]['tag_name'])
        self.assertFalse(catalog[0]['draft'])
        results = checker.check(ROOT, catalog, version)
        self.assertIn('2026.11.2', [installed for installed, _ in results])
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
                results = dict(checker.check(ROOT, checker.anonymous_catalog(broken, version), version))
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


if __name__ == '__main__':
    unittest.main()
