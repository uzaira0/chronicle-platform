"""Promotion of a draft release, end to end, in a publisher checkout made for the test.

`scripts/publish-images.sh <release> --promote` runs from a copy of this tree's scripts and operator
package in a temporary git repository whose `public` remote is a local bare repository holding the
release tag, as GitHub holds it once a draft is published. git, curl, ssh-keygen and bash are the
real ones. gh and docker are fixtures. curl is wrapped only to send the two GitHub addresses an
installed server asks (api.github.com and the releases feed) to a loopback server and to the
recorded feed, so the release-list request of 2026.11.2's own updater follows a real HTTP redirect.

The release is 9999.1.1, above every real release, so the supported installed releases are the
real ones: 2026.11.2's updater comes from its git tag in this repository."""

import datetime
import http.server
import io
import json
import os
from pathlib import Path
import runpy
import shutil
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
from urllib.parse import urlsplit

from host_tools import modern_bash
import test_publish_discovery

ROOT = Path(__file__).resolve().parents[2]
VERSION = '9999.1.1'
INSTALLED = '2026.11.2'
# Where 2026.11.2 looks for releases (update.py:228 at the tag): the repository's name before
# the rename of 2026-11-10. GitHub answers it with a redirect to the repository by its id.
OLD_LIST = '/repos/uzaira0/methodic/releases'
BY_ID_LIST = '/repositories/1355605219/releases'
LAYOUT = ('selfhost/Dockerfile.postgres', 'selfhost/docker-compose.yml')

CURL = '''#!{python}
import os, sys
arguments = sys.argv[1:]
for index, argument in enumerate(arguments):
    if argument.startswith("https://github.com/") and argument.endswith("/releases.atom"):
        with open({feed!r}, "rb") as feed:
            sys.stdout.buffer.write(feed.read())
        sys.exit(0)
    if argument.startswith("https://api.github.com/"):
        with open({asked!r}, "a") as asked:
            asked.write(argument + "\\n")
        arguments[index] = {api!r} + argument[len("https://api.github.com"):]
os.execv({curl!r}, [{curl!r}, *arguments])
'''
DOCKER = '#!/bin/sh\n[ "$1 $2" = "manifest inspect" ] && [ -d "$DOCKER_CONFIG" ] && [ ! -f "$DOCKER_CONFIG/config.json" ]\n'
# For a cut: every docker call is a line of $ASSETS/docker-calls, and none of them succeeds.
DOCKER_LOG = '#!/bin/sh\nprintf "%s\\n" "$*" >>"$ASSETS/docker-calls"\nexit 1\n'
# scripts/publish.sh in the fixture checkout. A cut calls `publish.sh verify-source` right after
# its gate on GitHub's release list, so this line on stderr says that the gate let the cut through.
PUBLISH_STUB = '#!/usr/bin/env bash\necho "fixture: publish.sh $*" >&2\nexit 3\n'
VERIFY_SOURCE_REACHED = 'fixture: publish.sh verify-source'
CHANGELOG = f'# Changelog\n\n## [{VERSION}]\n\n- fixture\n\n## [{INSTALLED}]\n\n- fixture\n'


def git(directory, *arguments):
    """git in a fixture repository, apart from the user's configuration (signing, hooks)."""
    environment = dict(os.environ, GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM='1')
    return subprocess.run(['git', '-C', str(directory), '-c', 'user.name=fixture', '-c', 'user.email=fixture@example.invalid',
                           '-c', 'init.defaultBranch=main', '-c', 'protocol.file.allow=always', *arguments],
                          env=environment, check=True, capture_output=True, text=True, timeout=60).stdout.strip()


class GitHubApi:
    """What api.github.com answers for the old release-list address, by mode:

    intact              a redirect to the repository's own list: this repository's published releases
    cached              the same redirect, to the list as it was before the newest release was published
    gone                404
    another repository  the old name itself answers, with releases that are not this repository's
    empty repository    the old name itself answers, with no release
    rate limited        403, x-ratelimit-remaining 0: what the 61st request of an hour without
                        credentials gets (docs.github.com, "Rate limits for the REST API")
    secondary limit     429 with retry-after
    unavailable         503
    unreachable         the connection is closed without an answer
    recovers            unreachable for the first request, intact after it"""

    # x-ratelimit-reset of the rate-limited answer, in UTC epoch seconds.
    RESET = int(datetime.datetime(2036, 1, 1, tzinfo=datetime.timezone.utc).timestamp())
    RATE_LIMIT = {'x-ratelimit-limit': '60', 'x-ratelimit-remaining': '0', 'x-ratelimit-used': '60',
                  'x-ratelimit-reset': str(RESET), 'x-ratelimit-resource': 'core'}
    REFUSALS = {
        'rate limited': (403, RATE_LIMIT, "API rate limit exceeded for 203.0.113.7. (But here's the good news: Authenticated "
                         'requests get a higher rate limit. Check out the documentation for more details.)'),
        'secondary limit': (429, {'retry-after': '60'}, 'You have exceeded a secondary rate limit. Please wait a few minutes '
                            'before you try again.'),
        'unavailable': (503, {}, 'No server is currently available to service your request.'),
    }

    def __init__(self, published):
        self.mode, self.requests = 'intact', []
        api = self
        foreign = [dict(row, id=row['id'] + 1, tag_name='0.' + str(index)) for index, row in enumerate(published[:3])]

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                path = urlsplit(self.path).path
                api.requests.append(self.path)
                mode = api.mode
                if mode == 'recovers':
                    mode = 'unreachable' if len(api.requests) == 1 else 'intact'
                if mode == 'unreachable':
                    self.close_connection = True
                    return
                if mode in ('intact', 'cached') and path == OLD_LIST:
                    self.send_response(301)
                    self.send_header('Location', BY_ID_LIST + '?' + urlsplit(self.path).query)
                    self.send_header('Content-Length', '0')
                    self.end_headers()
                    return
                headers = {}
                if mode in ('intact', 'cached') and path == BY_ID_LIST:
                    status, body = 200, json.dumps(published if mode == 'intact' else published[1:]).encode()
                elif mode == 'another repository' and path == OLD_LIST:
                    status, body = 200, json.dumps(foreign).encode()
                elif mode == 'empty repository' and path == OLD_LIST:
                    status, body = 200, b'[]'
                elif mode in api.REFUSALS:
                    status, headers, message = api.REFUSALS[mode]
                    body = json.dumps(dict(message=message, documentation_url='https://docs.github.com/rest')).encode()
                else:
                    status, body = 404, b'{"message": "Not Found", "status": "404"}'
                self.send_response(status)
                self.send_header('Content-Type', 'application/json')
                for name, value in headers.items():
                    self.send_header(name, value)
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *_arguments):
                pass

        self.server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.base = f'http://127.0.0.1:{self.server.server_address[1]}'

    def close(self):
        self.server.shutdown()
        self.server.server_close()


class Promotion:
    """The publisher checkout, the signed candidate the draft holds, and the fixture tools."""

    def __init__(self, root, migrations=None, release=VERSION):
        self.root, self.release = Path(root), release
        self.builder = runpy.run_path(str(ROOT / 'scripts/build-selfhost-release.py'))
        self.checkout, self.public = self.root / 'checkout', self.root / 'public.git'
        self.ledger = self.checkout / 'selfhost/published-migrations.json'
        self.revision = self.make_checkout()
        published = json.loads(self.ledger.read_text())
        self.migrations = migrations or dict(published[INSTALLED], **{'V2__fixture.sql': 'b' * 64})
        self.catalog = test_publish_discovery.promotion_catalog(VERSION)
        draft = self.catalog[0][0]
        assert draft['draft'] is True and draft['tag_name'] == VERSION
        draft.update(tag_name=self.release, name=self.release)  # the tag as the draft was cut; its assets drop a leading v
        self.api = GitHubApi([row for row in self.catalog[0] if row['draft'] is False])
        self.environment = self.make_candidate()

    def make_checkout(self):
        """A repository with the installed release's tag, then this tree's scripts and operator
        package as its HEAD; `public` holds HEAD as the release tag and the checkout does not."""
        self.checkout.mkdir()
        git(self.checkout, 'init', '-q')
        installed = subprocess.run(['git', '-C', str(ROOT), 'archive', '--format=tar', INSTALLED, 'selfhost/chronicle_ops', *LAYOUT],
                                   capture_output=True, check=True, timeout=60).stdout
        with tarfile.open(fileobj=io.BytesIO(installed)) as members:
            members.extractall(self.checkout, filter='data')
        git(self.checkout, 'add', '-A')
        git(self.checkout, 'commit', '-q', '-m', 'fixture: ' + INSTALLED)
        git(self.checkout, 'tag', INSTALLED)
        shutil.rmtree(self.checkout / 'selfhost')
        ignore = shutil.ignore_patterns('__pycache__')
        shutil.copytree(ROOT / 'selfhost/chronicle_ops', self.checkout / 'selfhost/chronicle_ops', ignore=ignore)
        shutil.copytree(ROOT / 'scripts', self.checkout / 'scripts', ignore=ignore)
        for name in (*LAYOUT, 'selfhost/published-migrations.json', 'selfhost/image-signing.pub'):
            shutil.copy2(ROOT / name, self.checkout / name)
        # What a cut needs from its checkout before it asks GitHub anything: a changelog entry for
        # the release and the committed image-signing public key. publish.sh is the stub above.
        (self.checkout / 'CHANGELOG.md').write_text(CHANGELOG)
        (self.checkout / 'scripts/publish.sh').write_text(PUBLISH_STUB)
        (self.checkout / '.gitignore').write_text('build/\n__pycache__/\n')
        git(self.checkout, 'add', '-A')
        git(self.checkout, 'commit', '-q', '-m', 'fixture: source of ' + VERSION)
        revision = git(self.checkout, 'rev-parse', 'HEAD')
        git(self.root, 'init', '-q', '--bare', str(self.public))
        git(self.checkout, 'push', '-q', str(self.public), f'HEAD:refs/tags/{self.release}')
        git(self.checkout, 'remote', 'add', 'public', str(self.public))
        return revision

    def make_candidate(self):
        builder, root = self.builder, self.root
        key = root / 'release-key'
        subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(key)], check=True, capture_output=True, timeout=10)
        images = {name: f'ghcr.io/example/{name}@sha256:' + 'a' * 64 for name in builder['PLACEHOLDERS'].values()}
        cli = root / 'chronicle'
        cli.write_text('#!/bin/sh\nexit 0\n')
        cli.chmod(0o755)
        self.manifest = {builder['UPGRADE_FLOOR_KEY']: builder['UPGRADE_FROM_MINIMUM'], builder['MIGRATIONS_KEY']: self.migrations,
                         'release_version': VERSION, 'source_revision': 'b' * 40, 'public_revision': self.revision, 'images': images}
        manifest = root / 'manifest.json'
        manifest.write_text(json.dumps(self.manifest))
        archive = root / f'chronicle-selfhost-{VERSION}.tar.gz'
        bundle = archive.name.removesuffix('.tar.gz')
        with tarfile.open(archive, 'w:gz') as source:
            builder['add_to_tar'](source, manifest, f'{bundle}/release-manifest.json', 0)
            builder['add_to_tar'](source, Path(str(key) + '.pub'), f'{bundle}/selfhost/release-signing.pub', 0)
            builder['add_to_tar'](source, cli, f'{bundle}/selfhost/chronicle', 0)
            source.add(ROOT / 'selfhost/chronicle_ops', f'{bundle}/selfhost/chronicle_ops',
                       filter=lambda member: None if '__pycache__' in member.name else member)
        Path(str(archive) + '.sha256').write_text(f'{builder["sha256"](archive)}  {archive.name}\n')
        subprocess.run(['ssh-keygen', '-Y', 'sign', '-n', builder['RELEASE_SIGNER'], '-f', str(key), str(archive) + '.sha256'],
                       check=True, capture_output=True, timeout=10)
        evidence = dict(status='passed', **{builder['SMOKE_ARCHIVE_HASH_FIELD']: builder['sha256'](archive)},
                        **builder['SMOKE_REQUIRED_EVIDENCE'])
        (root / 'result.txt').write_text(''.join(f'{name}={value}\n' for name, value in evidence.items()))
        tools = root / 'bin'
        tools.mkdir()
        shutil.copy2(ROOT / 'tests/security/fixtures/selfhost-promotion/gh', tools / 'gh')
        (tools / 'docker').write_text(DOCKER)
        for scanner in ('trivy', 'syft', 'cosign'):  # a cut requires them on PATH; none runs before its gate
            (tools / scanner).write_text('#!/bin/sh\nexit 1\n')
        shutil.copy2(ROOT / 'tests/selfhost-py/github_releases_feed.atom', root / 'releases.atom')
        (tools / 'curl').write_text(CURL.format(python=sys.executable, feed=str(root / 'releases.atom'),
                                                asked=str(root / 'api-requests'), api=self.api.base, curl=shutil.which('curl')))
        for tool in tools.iterdir():
            tool.chmod(0o755)
        return dict(os.environ, ASSETS=str(root), RELEASE_CATALOG=json.dumps(self.catalog), GH_CALLS=str(root / 'gh-calls'),
                    PROMOTED=str(root / 'promoted'), CHRONICLE_RELEASE_VERIFY_KEY=str(key) + '.pub',
                    PATH=str(tools) + os.pathsep + os.environ['PATH'])

    def promote(self, mode='intact', **environment):
        self.api.mode = mode
        return subprocess.run([modern_bash(), str(self.checkout / 'scripts/publish-images.sh'), self.release, '--promote',
                               str(self.root / 'result.txt')], env=dict(self.environment, **environment),
                              capture_output=True, text=True, timeout=300)

    def cut(self, rows, token='fixture-value-never-sent'):
        """`publish-images.sh <release>` in the checkout, with `rows` as GitHub's release list and
        every local prerequisite of a cut in place (registry token, keys, tools, a clean tree, a
        changelog entry). A cut that its gate lets through stops at the publish.sh stub."""
        environment = dict(self.environment, RELEASE_CATALOG=json.dumps([rows]),
                           CHRONICLE_RELEASE_SIGNING_KEY=str(self.root / 'release-key'),
                           CHRONICLE_IMAGE_SIGNING_KEY=str(self.root / 'release-key'))
        environment.pop('GHCR_TOKEN', None)
        if token:
            environment['GHCR_TOKEN'] = token
        docker = self.root / 'bin/docker'
        docker.write_text(DOCKER_LOG)
        try:
            return subprocess.run([modern_bash(), str(self.checkout / 'scripts/publish-images.sh'), self.release],
                                  env=environment, capture_output=True, text=True, timeout=300)
        finally:
            docker.write_text(DOCKER)

    def gh_calls(self):
        calls = self.root / 'gh-calls'
        return [line.split('\t') for line in calls.read_text().splitlines()] if calls.exists() else []

    def docker_calls(self):
        calls = self.root / 'docker-calls'
        return calls.read_text().splitlines() if calls.exists() else []

    @property
    def published_rows(self):
        """GitHub's release list without the draft being promoted."""
        return [row for row in self.catalog[0] if row['draft'] is False]

    def another_release(self, version, draft=False):
        """A row of GitHub's release list for one more release of this repository."""
        row = json.loads(json.dumps(self.published_rows[0]))
        row.update(id=row['id'] + 1000, tag_name=version, name=version, draft=draft,
                   html_url=f'https://github.com/example/chronicle/releases/tag/{version}')
        return row

    @property
    def promoted(self):
        return (self.root / 'promoted').exists()

    def asked(self):
        requests = self.root / 'api-requests'
        return requests.read_text().splitlines() if requests.exists() else []


class PromotionFixture(unittest.TestCase):
    def promotion(self, **options):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        promotion = Promotion(Path(folder.name).resolve(), **options)
        self.addCleanup(promotion.api.close)
        return promotion


class InstalledReleaseListTests(PromotionFixture):
    """Servers on 2026.11.2 find releases only at https://api.github.com/repos/uzaira0/methodic/releases.
    The repository has had another name since 2026-11-10 and GitHub redirects the old one, for as
    long as no repository takes it. Promotion asks that address once, as 2026.11.2's own updater
    asks it, and publishes only when the answer is this repository's published releases."""

    LIST_URL = f'https://api.github.com{OLD_LIST}?per_page=100'

    def test_an_intact_redirect_publishes(self):
        promotion = self.promotion()
        result = promotion.promote('intact')
        output = result.stdout + result.stderr
        self.assertEqual(0, result.returncode, output)
        self.assertIn(f"{INSTALLED} release list ({self.LIST_URL}): answers with this repository's published releases",
                      result.stdout.splitlines())
        self.assertIn(f'{INSTALLED}: selects {VERSION}', result.stdout.splitlines())
        self.assertTrue(promotion.promoted)
        # One request to the address 2026.11.2's own code builds, redirected and followed for real.
        self.assertEqual([self.LIST_URL], promotion.asked())
        self.assertEqual([OLD_LIST + '?per_page=100', BY_ID_LIST + '?per_page=100'], promotion.api.requests)

    def test_an_address_that_no_longer_answers_or_answers_with_another_repository_publishes_nothing(self):
        promotion = self.promotion()
        for mode, reason in (('gone', "answers 404; it does not return this repository's published releases"),
                             ('another repository', "does not return this repository's published releases: it lists 3 ")):
            with self.subTest(mode):
                result = promotion.promote(mode)
                output = result.stdout + result.stderr
                self.assertNotEqual(0, result.returncode, output)
                row = next(line for line in result.stdout.splitlines() if line.startswith(f'{INSTALLED} release list ('))
                self.assertIn(f'FAILS: {self.LIST_URL} {reason}', row)
                self.assertIn('nothing was published', result.stderr)
                self.assertIn("The public repository's former name", result.stderr)
                self.assertFalse(promotion.promoted)
                calls = [line.split('\t') for line in (promotion.root / 'gh-calls').read_text().splitlines()]
                self.assertFalse([call for call in calls if call[:2] == ['release', 'edit']])


class ReleaseListAnswerTests(unittest.TestCase):
    """What the one request to an installed release's own release-list address can come back with,
    and what promotion is told for each. Only an answer that is another repository's list, or a
    404, means the address no longer reaches this repository. A refusal by GitHub's rate limit, a
    connection that fails and a server error say nothing about the address: they are named as
    what they are, with the advice to run the promotion again, and a failure without an HTTP
    answer is asked again with backoff inside one deadline. 2026.11.2's own curl command makes
    every request, through a wrapper that only sends api.github.com to the loopback server."""

    @classmethod
    def setUpClass(cls):
        cls.checker = test_publish_discovery.load_checker()
        cls.folder = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.folder.cleanup)
        root = Path(cls.folder.name).resolve()
        installed = subprocess.run(['git', '-C', str(ROOT), 'archive', '--format=tar', INSTALLED, 'selfhost/chronicle_ops'],
                                   capture_output=True, check=True, timeout=60).stdout
        with tarfile.open(fileobj=io.BytesIO(installed)) as members:
            members.extractall(root / INSTALLED, filter='data')
        cls.package = root / INSTALLED / 'selfhost'
        rows = cls.checker.catalog_rows(test_publish_discovery.promotion_catalog(VERSION))
        cls.published = cls.checker.published_now(rows)
        cls.api = GitHubApi(cls.published)
        cls.addClassCleanup(cls.api.close)
        tools = root / 'bin'
        tools.mkdir()
        (tools / 'curl').write_text(CURL.format(python=sys.executable, feed=str(root / 'no-feed'), asked=str(root / 'api-requests'),
                                                api=cls.api.base, curl=shutil.which('curl')))
        (tools / 'curl').chmod(0o755)
        cls.path = str(tools) + os.pathsep + os.environ['PATH']
        cls.url = f'https://api.github.com{OLD_LIST}?per_page=100'

    def answer(self, mode, deadline=6):
        """(problem or None, note or None, requests the server saw, seconds) for one check in `mode`."""
        self.api.mode = mode
        self.api.requests.clear()
        notes, started = {}, time.monotonic()
        with patch.dict(os.environ, PATH=self.path):
            label, problem = self.checker.installed_list_result(INSTALLED, self.package, self.published, {},
                                                                notes=notes, deadline=deadline)
        self.assertEqual(f'{INSTALLED} release list ({self.url})', label)
        return problem, notes.get(label), list(self.api.requests), time.monotonic() - started

    def test_this_repositorys_list_passes_through_the_redirect(self):
        problem, note, requests, _ = self.answer('intact')
        self.assertIsNone(problem)
        self.assertIsNone(note)
        self.assertEqual([OLD_LIST + '?per_page=100', BY_ID_LIST + '?per_page=100'], requests)

    def test_a_list_from_before_a_release_was_published_is_still_this_repositorys(self):
        """GitHub caches answers to requests without credentials, so the list can lack a release
        published a moment ago. Its rows carry this repository's release ids, which no other
        repository has: the address reaches this repository, and that is what is being checked."""
        problem, note, _, _ = self.answer('cached')
        self.assertIsNone(problem)
        newest = self.published[0]['tag_name']
        self.assertIn(f"13 of this repository's 14 published releases (not listed: {newest})", note)

    def test_only_a_404_or_another_repositorys_list_means_the_address_is_lost(self):
        for mode, reason in (('gone', "answers 404; it does not return this repository's published releases"),
                             ('another repository', "does not return this repository's published releases: it lists 3 (0 of"),
                             ('empty repository', "does not return this repository's published releases: it lists 0 (0 of")):
            with self.subTest(mode):
                problem, _, requests, _ = self.answer(mode)
                self.assertIn(self.url + ' ' + reason, problem)
                self.assertEqual(self.checker.REDIRECT_ADVICE, problem.advice)
                self.assertEqual(1, len(requests), 'an answer from GitHub is not asked for again')

    def test_a_rate_limit_refusal_names_the_limit_and_when_it_resets(self):
        problem, _, requests, _ = self.answer('rate limited')
        self.assertIn(self.url + " was refused by GitHub's rate limit for requests without credentials (HTTP 403)", problem)
        self.assertIn('all 60 requests an hour from this address are used', problem)
        self.assertIn('it resets at 2036-01-01 00:00:00 UTC', problem)
        self.assertNotIn("does not return this repository's published releases", problem)
        self.assertEqual(self.checker.RERUN_ADVICE, problem.advice)
        self.assertEqual(1, len(requests), 'a refused request is not repeated against the limit')

    def test_a_reset_within_two_hours_is_also_given_in_minutes(self):
        answer = dict(status=429, body=b'{"message": "API rate limit exceeded"}',
                      headers={'x-ratelimit-limit': '60', 'x-ratelimit-remaining': '0', 'x-ratelimit-reset': str(GitHubApi.RESET)})
        problem = self.checker.answer_problem(self.url, answer, self.published, now=GitHubApi.RESET - 1790)
        self.assertIn('(HTTP 429): all 60 requests an hour from this address are used, and it resets at '
                      '2036-01-01 00:00:00 UTC, 30 minutes from now', problem)

    def test_a_refusal_that_is_no_rate_limit_is_reported_with_its_status_and_message(self):
        """403 with requests left is not the rate limit, and nothing in it says whose list the
        address returns: it is printed as GitHub sent it and the promotion can be run again."""
        answer = dict(status=403, body=b'{"message": "Repository access blocked"}', attempts=1, deadline=120,
                      headers={'x-ratelimit-limit': '60', 'x-ratelimit-remaining': '41'})
        problem = self.checker.answer_problem(self.url, answer, self.published)
        self.assertEqual(f'{self.url} was answered with HTTP 403 by GitHub (1 attempt inside the deadline of 120 seconds): '
                         'Repository access blocked', problem)
        self.assertEqual(self.checker.RERUN_ADVICE, problem.advice)

    def test_a_secondary_rate_limit_names_the_wait_github_asked_for(self):
        problem, _, requests, _ = self.answer('secondary limit')
        self.assertIn("was refused by GitHub's secondary rate limit (HTTP 429, retry-after 60 seconds)", problem)
        self.assertIn('You have exceeded a secondary rate limit', problem)
        self.assertEqual(self.checker.RERUN_ADVICE, problem.advice)
        self.assertEqual(1, len(requests))

    def test_a_connection_that_fails_is_asked_again_with_backoff_and_then_named(self):
        problem, _, requests, seconds = self.answer('unreachable', deadline=6)
        self.assertIn(self.url + ' was not reached: curl: (52) Empty reply from server', problem)
        self.assertRegex(problem, r'\(curl exit 52; [2-9] attempts inside the deadline of 6 seconds\)')
        self.assertNotIn("does not return this repository's published releases", problem)
        self.assertEqual(self.checker.RERUN_ADVICE, problem.advice)
        self.assertGreaterEqual(len(requests), 2)
        self.assertLess(seconds, 12)

    def test_a_connection_that_comes_back_inside_the_deadline_passes(self):
        problem, note, requests, _ = self.answer('recovers', deadline=20)
        self.assertIsNone(problem)
        self.assertIsNone(note)
        self.assertEqual([OLD_LIST + '?per_page=100'] * 2 + [BY_ID_LIST + '?per_page=100'], requests)

    def test_a_server_error_is_asked_again_and_named_as_githubs(self):
        problem, _, requests, _ = self.answer('unavailable', deadline=6)
        self.assertIn(self.url + ' was answered with HTTP 503 by GitHub', problem)
        self.assertIn('No server is currently available', problem)
        self.assertEqual(self.checker.RERUN_ADVICE, problem.advice)
        self.assertGreaterEqual(len(requests), 2)


class UnansweredReleaseListTests(PromotionFixture):
    """The same through `publish-images.sh --promote`: an unanswered release list publishes
    nothing, and promotion says that the check could not be completed and can be run again,
    not that the address is lost."""

    LIST_URL = f'https://api.github.com{OLD_LIST}?per_page=100'

    def refused(self, mode, **environment):
        promotion = self.promotion()
        promotion.environment.update(environment)
        result = promotion.promote(mode)
        output = result.stdout + result.stderr
        self.assertNotEqual(0, result.returncode, output)
        self.assertFalse(promotion.promoted, output)
        calls = [line.split('\t') for line in (promotion.root / 'gh-calls').read_text().splitlines()]
        self.assertFalse([call for call in calls if call[:2] == ['release', 'edit']])
        self.assertNotIn(VERSION, json.loads(promotion.ledger.read_text()))
        row = next(line for line in result.stdout.splitlines() if line.startswith(f'{INSTALLED} release list ('))
        self.assertIn('the discovery check could not be completed; nothing was published, and the promotion can be run again',
                      result.stderr)
        self.assertNotIn("The public repository's former name", result.stderr)
        self.assertNotIn('would not discover this release', result.stderr)
        return promotion, row

    def test_a_rate_limited_machine_is_told_the_limit_and_its_reset_and_publishes_nothing(self):
        _, row = self.refused('rate limited')
        self.assertIn(f"FAILS: {self.LIST_URL} was refused by GitHub's rate limit for requests without credentials (HTTP 403)", row)
        self.assertIn('it resets at 2036-01-01 00:00:00 UTC', row)

    def test_a_failed_connection_is_retried_inside_the_deadline_then_named_and_publishes_nothing(self):
        promotion, row = self.refused('unreachable', CHRONICLE_TRANSFER_TIMEOUT_SECONDS='6')
        self.assertIn(f'FAILS: {self.LIST_URL} was not reached: curl: (52) Empty reply from server', row)
        self.assertGreaterEqual(len(promotion.api.requests), 2)

    def test_a_list_cached_before_another_publish_does_not_stop_the_promotion(self):
        promotion = self.promotion()
        result = promotion.promote('cached')
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertTrue(promotion.promoted)
        row = next(line for line in result.stdout.splitlines() if line.startswith(f'{INSTALLED} release list ('))
        self.assertIn("answers with 13 of this repository's 14 published releases", row)


class PublicationLedgerTests(PromotionFixture):
    """selfhost/published-migrations.json records publications, and a draft is not one: it can be
    replaced or deleted, and GitHub creates its tag only when it publishes it. The release builder
    reads Dockerfile.postgres and docker-compose.yml of every recorded release from refs/tags/<version>
    (chronicle_ops.migrations.require_database_volume_continuity), so an entry written when the draft
    was cut made every bundle build fail until promotion, and a replaced draft left a stale entry.
    --promote writes the entry, once `gh release edit --draft=false` has succeeded, from the manifest
    of the bundle it promoted, after fetching that one tag from the public repository."""

    def recorded(self, promotion):
        return json.loads(promotion.ledger.read_text())

    def tag(self, promotion):
        shown = subprocess.run(['git', '-C', str(promotion.checkout), 'rev-parse', '--verify', '--quiet', f'refs/tags/{VERSION}^{{commit}}'],
                               capture_output=True, text=True, timeout=60)
        return shown.stdout.strip() or None

    def require_continuity(self, promotion):
        """What scripts/build-selfhost-release.py runs before it builds any bundle."""
        from chronicle_ops.migrations import require_database_volume_continuity
        require_database_volume_continuity(promotion.checkout, promotion.checkout)

    def test_cutting_a_draft_runs_nothing_that_writes_the_ledger(self):
        ledger = ROOT / 'selfhost/published-migrations.json'
        before = ledger.read_bytes()
        plan = subprocess.run([modern_bash(), str(ROOT / 'scripts/publish-images.sh'), VERSION, '--dry-run'],
                              capture_output=True, text=True, timeout=120)
        self.assertEqual(0, plan.returncode, plan.stderr)
        lines = plan.stdout.splitlines()
        created = next(index for index, line in enumerate(lines) if line.startswith('gh release create '))
        self.assertIn(' --draft ', lines[created] + ' ')
        # Every process a draft cut starts is a line of the plan; none of them is the ledger's writer.
        self.assertEqual([], [line for line in lines if 'chronicle_ops.migrations' in line])
        closing = [line for line in lines[created + 1:] if 'published-migrations.json' in line]
        self.assertEqual(1, len(closing), lines[created + 1:])
        self.assertIn(f'{VERSION} is a draft, not a publication', closing[0])
        self.assertIn(f'scripts/publish-images.sh {VERSION} --promote <smoke-result.txt>', closing[0])
        self.assertNotIn('Commit selfhost/published-migrations.json', plan.stdout)
        self.assertEqual(before, ledger.read_bytes())

    def test_a_recorded_release_without_its_tag_fails_the_continuity_check_and_names_the_fetch(self):
        """The state a draft cut used to leave: the entry, and no tag to read the release from."""
        promotion = self.promotion()
        promotion.ledger.write_text(json.dumps(dict(self.recorded(promotion), **{VERSION: promotion.migrations})))
        fetch = f'git fetch --no-tags public refs/tags/{VERSION}:refs/tags/{VERSION}'
        with self.assertRaisesRegex(ValueError, f'published release {VERSION} has no git tag here .*{fetch}'):
            self.require_continuity(promotion)

    def test_promotion_records_the_release_and_fetches_its_tag_so_the_continuity_check_passes(self):
        promotion = self.promotion()
        before = self.recorded(promotion)
        self.assertNotIn(VERSION, before)
        self.assertIsNone(self.tag(promotion))
        result = promotion.promote()
        output = result.stdout + result.stderr
        self.assertEqual(0, result.returncode, output)
        self.assertTrue(promotion.promoted)
        # The entry is the inventory of the bundle that was promoted, added to what was there.
        self.assertEqual(dict(before, **{VERSION: promotion.migrations}), self.recorded(promotion))
        self.assertEqual(promotion.revision, self.tag(promotion))
        self.require_continuity(promotion)
        self.assertIn(f'{VERSION} is published. Commit selfhost/published-migrations.json', result.stdout.splitlines()[-1])
        # No other tracked file changed: the ledger is the one file to commit.
        self.assertEqual('M selfhost/published-migrations.json',
                         git(promotion.checkout, 'status', '--porcelain', '--untracked-files=no'))

    def test_a_v_prefixed_release_is_fetched_as_the_tag_the_continuity_check_reads(self):
        """The ledger records 9999.1.1 for a release tagged v9999.1.1, and the continuity check reads
        refs/tags/9999.1.1."""
        promotion = self.promotion(release='v' + VERSION)
        result = promotion.promote()
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertEqual(promotion.migrations, self.recorded(promotion)[VERSION])
        self.assertEqual(promotion.revision, self.tag(promotion))
        self.require_continuity(promotion)

    def test_a_promotion_that_is_refused_leaves_the_ledger_and_the_tags_alone(self):
        promotion = self.promotion()
        before = promotion.ledger.read_bytes()
        result = promotion.promote('gone')
        self.assertNotEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertFalse(promotion.promoted)
        self.assertEqual(before, promotion.ledger.read_bytes())
        self.assertIsNone(self.tag(promotion))

    def test_a_release_the_ledger_cannot_take_is_refused_before_it_is_published(self):
        """A bundle without a migration that a published release shipped: found while the release
        is still a draft, not when the ledger is written after publication."""
        promotion = self.promotion(migrations={'V2__fixture.sql': 'b' * 64})
        before = promotion.ledger.read_bytes()
        dropped = next(iter(json.loads(before)[INSTALLED]))
        result = promotion.promote()
        output = result.stdout + result.stderr
        self.assertNotEqual(0, result.returncode, output)
        self.assertIn(f'published migration changed or removed: {dropped}', result.stderr)
        self.assertIn('selfhost/published-migrations.json cannot record this release; nothing was published', result.stderr)
        self.assertFalse(promotion.promoted)
        self.assertEqual(before, promotion.ledger.read_bytes())
        self.assertIsNone(self.tag(promotion))

    def assert_published_and_not_recorded(self, promotion, result):
        output = result.stdout + result.stderr
        self.assertNotEqual(0, result.returncode, output)
        self.assertTrue(promotion.promoted, output)
        self.assertNotIn(VERSION, self.recorded(promotion))
        self.assertIn(f'error: {VERSION} is published on example/chronicle, but this checkout has not recorded it', result.stderr)
        self.assertIn('run the same promotion again', result.stderr)
        self.assertIn('commit selfhost/published-migrations.json', result.stderr)
        self.assertNotIn('nothing was published', result.stderr)

    def finish_by_hand(self, promotion, result):
        """Run the commands the failed promotion printed, exactly as printed."""
        message = result.stderr[result.stderr.index(f'error: {VERSION} is published on '):].splitlines()
        commands = [line[2:] for line in message if line.startswith('  ')]
        self.assertEqual(2, len(commands), result.stderr)
        self.assertEqual(message[-2:], ['  ' + command for command in commands])
        script = promotion.root / 'finish-by-hand.sh'
        script.write_text('set -e\n' + '\n'.join(commands) + '\n')
        finished = subprocess.run([modern_bash(), str(script)], env=promotion.environment, capture_output=True, text=True, timeout=120)
        self.assertEqual(0, finished.returncode, finished.stdout + finished.stderr)
        self.assertEqual(promotion.migrations, self.recorded(promotion)[VERSION])
        self.assertEqual(promotion.revision, self.tag(promotion))
        self.require_continuity(promotion)

    @unittest.skipIf(os.geteuid() == 0, 'root writes into a read-only directory')
    def test_a_ledger_that_cannot_be_written_after_publication_says_what_to_run(self):
        promotion = self.promotion()
        folder = promotion.ledger.parent
        folder.chmod(0o555)
        self.addCleanup(folder.chmod, 0o755)
        result = promotion.promote()
        self.assert_published_and_not_recorded(promotion, result)
        self.assertIn('PermissionError', result.stderr)
        folder.chmod(0o755)
        self.finish_by_hand(promotion, result)

    def test_a_tag_that_cannot_be_fetched_after_publication_says_what_to_run(self):
        promotion = self.promotion()
        # GitHub creates the tag when it publishes the draft; here the fetch that follows finds none,
        # as when the network fails between the two.
        git(promotion.public, 'update-ref', '-d', f'refs/tags/{VERSION}')
        result = promotion.promote()
        self.assert_published_and_not_recorded(promotion, result)
        self.assertIsNone(self.tag(promotion))
        git(promotion.checkout, 'push', '-q', str(promotion.public), f'HEAD:refs/tags/{VERSION}')
        self.finish_by_hand(promotion, result)


class PromotionRecoveryTests(PromotionFixture):
    """`gh release edit --draft=false` can fail after GitHub has applied it: the connection is lost
    once the request was accepted. The release is then public and the ledger has no entry. The
    script asks GitHub what the release is now and goes on from there, and a later --promote of a
    release that is already public verifies the downloaded bundle as usual and records it."""

    def recorded(self, promotion):
        return json.loads(promotion.ledger.read_text())

    def tag(self, promotion):
        shown = subprocess.run(['git', '-C', str(promotion.checkout), 'rev-parse', '--verify', '--quiet', f'refs/tags/{VERSION}^{{commit}}'],
                               capture_output=True, text=True, timeout=60)
        return shown.stdout.strip() or None

    def edits(self, promotion):
        return [call for call in promotion.gh_calls() if call[:2] == ['release', 'edit']]

    def test_an_edit_that_github_applied_while_gh_reported_a_failure_is_recorded(self):
        promotion = self.promotion()
        result = promotion.promote(GH_EDIT_FAILS='applied')
        output = result.stdout + result.stderr
        self.assertEqual(0, result.returncode, output)
        self.assertIn(f'gh release edit reported a failure, but {VERSION} is public on example/chronicle', result.stderr)
        self.assertEqual(promotion.migrations, self.recorded(promotion)[VERSION])
        self.assertEqual(promotion.revision, self.tag(promotion))
        self.assertIn(f'{VERSION} is published. Commit selfhost/published-migrations.json', result.stdout.splitlines()[-1])
        self.assertEqual(1, len(self.edits(promotion)))

    def test_an_edit_that_github_refused_publishes_and_records_nothing(self):
        promotion = self.promotion()
        before = promotion.ledger.read_bytes()
        result = promotion.promote(GH_EDIT_FAILS='refused')
        output = result.stdout + result.stderr
        self.assertNotEqual(0, result.returncode, output)
        self.assertIn(f'error: gh release edit failed and {VERSION} is still a draft on example/chronicle; nothing was published, '
                      'and the promotion can be run again', result.stderr)
        self.assertFalse(promotion.promoted)
        self.assertEqual(before, promotion.ledger.read_bytes())
        self.assertIsNone(self.tag(promotion))

    def test_an_edit_with_an_unknown_outcome_says_to_run_the_promotion_again_and_that_run_records_it(self):
        promotion = self.promotion()
        result = promotion.promote(GH_EDIT_FAILS='unknown')
        output = result.stdout + result.stderr
        self.assertNotEqual(0, result.returncode, output)
        self.assertIn(f'error: gh release edit failed, and GitHub did not say whether {VERSION} is public now', result.stderr)
        self.assertIn(f'scripts/publish-images.sh {VERSION} --promote {promotion.root / "result.txt"}', result.stderr)
        self.assertNotIn('nothing was published', result.stderr)
        self.assertNotIn(VERSION, self.recorded(promotion))
        # The network is back. The same command finds the release public, publishes nothing and records it.
        (promotion.root / 'gh-offline').unlink()
        promotion.api.requests.clear()
        again = promotion.promote()
        self.assertEqual(0, again.returncode, again.stdout + again.stderr)
        self.assertEqual(promotion.migrations, self.recorded(promotion)[VERSION])
        self.assertEqual(promotion.revision, self.tag(promotion))
        self.assertEqual(1, len(self.edits(promotion)), 'the second run edits nothing')
        self.assertEqual([], promotion.api.requests, 'a release that is public is not asked about again')
        self.assertIn(f'{VERSION} was already public on example/chronicle. Commit selfhost/published-migrations.json',
                      again.stdout.splitlines()[-1])

    def public_and_unrecorded(self, **options):
        """A release GitHub has published that this checkout has no entry and no tag for."""
        promotion = self.promotion(**options)
        (promotion.root / 'promoted').write_text('published by a run that did not record it\n')
        return promotion

    def test_a_public_release_missing_from_the_ledger_is_verified_and_recorded(self):
        promotion = self.public_and_unrecorded()
        before = self.recorded(promotion)
        result = promotion.promote()
        output = result.stdout + result.stderr
        self.assertEqual(0, result.returncode, output)
        self.assertNotIn('promotion requires a draft release', output)
        self.assertEqual(dict(before, **{VERSION: promotion.migrations}), self.recorded(promotion))
        self.assertEqual(promotion.revision, self.tag(promotion))
        self.assertEqual([], self.edits(promotion))
        self.assertEqual({'view', 'download'}, {call[1] for call in promotion.gh_calls() if call[0] == 'release'})
        self.assertIn(f'{VERSION} was already public on example/chronicle. Commit selfhost/published-migrations.json, which now records it',
                      result.stdout.splitlines()[-1])

    def test_a_public_release_is_verified_before_it_is_recorded(self):
        """The same checks as for a draft: here the signature under a key that did not sign it,
        then a smoke result for another archive."""
        promotion = self.public_and_unrecorded()
        before = promotion.ledger.read_bytes()
        other = promotion.root / 'other-key'
        subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(other)], check=True, capture_output=True, timeout=10)
        result = promotion.promote(CHRONICLE_RELEASE_VERIFY_KEY=str(other) + '.pub')
        self.assertNotEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertEqual(before, promotion.ledger.read_bytes())
        self.assertIsNone(self.tag(promotion))
        smoke = promotion.root / 'result.txt'
        field = promotion.builder['SMOKE_ARCHIVE_HASH_FIELD']
        smoke.write_text(''.join(f'{field}={"0" * 64}\n' if line.startswith(field + '=') else line
                                 for line in smoke.read_text().splitlines(keepends=True)))
        result = promotion.promote()
        self.assertNotEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertEqual(before, promotion.ledger.read_bytes())

    def test_a_public_release_the_ledger_cannot_take_is_named_as_public(self):
        promotion = self.public_and_unrecorded(migrations={'V2__fixture.sql': 'b' * 64})
        before = promotion.ledger.read_bytes()
        result = promotion.promote()
        self.assertNotEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertIn('published migration changed or removed', result.stderr)
        self.assertIn(f'error: {VERSION} is public on example/chronicle and selfhost/published-migrations.json cannot record it',
                      result.stderr)
        self.assertNotIn('nothing was published', result.stderr)
        self.assertEqual(before, promotion.ledger.read_bytes())

    def test_promoting_a_recorded_public_release_again_changes_nothing(self):
        promotion = self.promotion()
        self.assertEqual(0, promotion.promote().returncode)
        recorded = promotion.ledger.read_bytes()
        again = promotion.promote()
        self.assertEqual(0, again.returncode, again.stdout + again.stderr)
        self.assertEqual(recorded, promotion.ledger.read_bytes())
        self.assertEqual(1, len(self.edits(promotion)))
        self.assertIn(f'{VERSION} is public on example/chronicle and selfhost/published-migrations.json already records it',
                      again.stdout.splitlines()[-1])

    def test_the_first_release_a_checkout_records_makes_the_ledger_without_a_complaint(self):
        """No ledger yet (a new publisher checkout, a repository with no published release): the
        promotion writes it, and says nothing about the file that was not there before."""
        promotion = self.promotion()
        promotion.ledger.unlink()
        result = promotion.promote('empty repository', RELEASE_CATALOG=json.dumps([[promotion.catalog[0][0]]]))
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertEqual({VERSION: promotion.migrations}, self.recorded(promotion))
        self.assertNotIn('No such file', result.stderr)
        self.assertIn(f'{VERSION} is published. Commit selfhost/published-migrations.json, which now records it',
                      result.stdout.splitlines()[-1])

    def test_a_release_that_gh_cannot_read_is_not_called_a_missing_draft(self):
        promotion = self.promotion()
        (promotion.root / 'gh-offline').write_text('')
        result = promotion.promote()
        self.assertNotEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertIn(f'error: gh could not read release {VERSION} on example/chronicle', result.stderr)
        self.assertNotIn('promotion requires a draft release', result.stderr)
        self.assertEqual([], [call for call in promotion.gh_calls() if call[:2] == ['release', 'download']])


class UnrecordedPublicationTests(PromotionFixture):
    """selfhost/published-migrations.json is what stops a release from changing or dropping a
    migration that a published release shipped, and it only knows the releases recorded in it.
    A release that is public and has no entry (its promotion failed after publication and nobody
    finished the record) is invisible to that check. So a cut starts, and a draft is published,
    only when every published release at or above the upgrade floor has its entry."""

    UNRECORDED = '9999.0.9'

    def record_command(self, version):
        return f'  scripts/publish-images.sh {version} --promote <smoke-result.txt>'

    def test_a_cut_stops_before_any_build_while_a_published_release_is_unrecorded(self):
        promotion = self.promotion()
        result = promotion.cut([promotion.another_release(self.UNRECORDED), *promotion.published_rows])
        output = result.stdout + result.stderr
        self.assertNotEqual(0, result.returncode, output)
        self.assertIn(f'error: example/chronicle has published {self.UNRECORDED}, and selfhost/published-migrations.json does not record it',
                      result.stderr)
        self.assertIn(self.record_command(self.UNRECORDED), result.stderr.splitlines())
        # Releases below the upgrade floor (2026.10.9 and older) need no entry and are not named.
        self.assertNotIn('2026.10.9', result.stderr)
        self.assertNotIn(self.record_command(INSTALLED), result.stderr)
        # Nothing was built, pushed or created: the cut stopped at the gate, before its next step.
        self.assertEqual([], promotion.docker_calls())
        self.assertEqual([['repo', 'view'], ['api', '--paginate']], [call[:2] for call in promotion.gh_calls()])
        self.assertNotIn(VERIFY_SOURCE_REACHED, result.stderr)

    def test_a_cut_with_every_published_release_recorded_passes_the_gate(self):
        promotion = self.promotion()
        result = promotion.cut(promotion.published_rows)
        output = result.stdout + result.stderr
        self.assertNotIn('does not record', output)
        self.assertIn(VERIFY_SOURCE_REACHED, result.stderr, output)
        self.assertEqual([], promotion.docker_calls())

    def test_a_cut_that_lacks_a_local_prerequisite_asks_github_nothing(self):
        """The registry token, the keys, the tools, a clean tree and the changelog entry are
        checked first: a run that cannot go on makes no request. tests/security runs the real
        script without its token and without its signing key and relies on that."""
        promotion = self.promotion()
        result = promotion.cut(promotion.catalog[0], token=None)
        self.assertNotEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertIn('error: GHCR_TOKEN is unset', result.stderr)
        self.assertEqual([], promotion.gh_calls())
        (promotion.ledger.parent / 'untracked.txt').write_text('left behind\n')
        result = promotion.cut(promotion.catalog[0])
        self.assertIn('error: working tree is dirty', result.stderr)
        self.assertEqual([], promotion.gh_calls())

    def test_a_ledger_that_cannot_be_read_stops_the_cut_and_is_named(self):
        promotion = self.promotion()
        promotion.ledger.write_text('{"2026.11.2": ')
        git(promotion.checkout, 'commit', '-q', '-am', 'fixture: a ledger that is no JSON')
        result = promotion.cut(promotion.published_rows)
        self.assertNotEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertIn("error: GitHub's release list could not be compared with selfhost/published-migrations.json "
                      '(the reason is above); nothing was built or pushed', result.stderr)
        self.assertNotIn(VERIFY_SOURCE_REACHED, result.stderr)

    def test_an_unrecorded_draft_or_prerelease_is_told_apart(self):
        """A draft of another version is no publication. A published prerelease is one."""
        promotion = self.promotion()
        rows = [promotion.another_release('9999.0.8', draft=True), promotion.another_release('v9999.0.7-rc.1'),
                *promotion.published_rows]
        result = promotion.cut(rows)
        self.assertNotEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertIn(self.record_command('v9999.0.7-rc.1'), result.stderr.splitlines())
        self.assertNotIn('9999.0.8', result.stderr)

    def test_what_counts_as_a_publication_that_needs_an_entry(self):
        from chronicle_ops.migrations import unrecorded_publications
        from chronicle_ops.release import UPGRADE_FROM_MINIMUM
        promotion = self.promotion()
        rows = [
            dict(tag_name=UPGRADE_FROM_MINIMUM, draft=False),            # the floor itself
            dict(tag_name=UPGRADE_FROM_MINIMUM + '-rc.1', draft=False),  # sorts below the floor
            dict(tag_name='v' + INSTALLED, draft=False),                 # recorded as 2026.11.2
            dict(tag_name='published-2026-11-08', draft=False),          # no release version
            dict(tag_name='9999.0.1', draft=True),                       # a draft
            dict(tag_name='9999.0.2'),                                   # GitHub did not say it is published
            'not a row',
            dict(tag_name='v9999.0.3', draft=False, prerelease=True),
        ]
        self.assertEqual([UPGRADE_FROM_MINIMUM, 'v9999.0.3'], unrecorded_publications(promotion.checkout, rows))
        promotion.ledger.unlink()  # no ledger: nothing is recorded
        self.assertEqual([UPGRADE_FROM_MINIMUM, 'v' + INSTALLED, 'v9999.0.3'], unrecorded_publications(promotion.checkout, rows))

    def test_a_draft_is_not_published_while_another_published_release_is_unrecorded(self):
        promotion = self.promotion()
        before = promotion.ledger.read_bytes()
        rows = [promotion.catalog[0][0], promotion.another_release(self.UNRECORDED), *promotion.published_rows]
        result = promotion.promote(RELEASE_CATALOG=json.dumps([rows]))
        output = result.stdout + result.stderr
        self.assertNotEqual(0, result.returncode, output)
        self.assertIn(f'error: example/chronicle has published {self.UNRECORDED}, and selfhost/published-migrations.json does not record it',
                      result.stderr)
        self.assertIn(self.record_command(self.UNRECORDED), result.stderr.splitlines())
        self.assertIn('nothing was published', result.stderr)
        self.assertFalse(promotion.promoted)
        self.assertEqual(before, promotion.ledger.read_bytes())
        self.assertEqual([], promotion.api.requests, 'refused before GitHub is asked anything without credentials')

    def test_the_plan_of_a_cut_runs_the_gate_before_anything_is_built(self):
        plan = subprocess.run([modern_bash(), str(ROOT / 'scripts/publish-images.sh'), VERSION, '--dry-run'],
                              capture_output=True, text=True, timeout=120)
        self.assertEqual(0, plan.returncode, plan.stderr)
        lines = plan.stdout.splitlines()
        gate = next(index for index, line in enumerate(lines) if line.startswith('require_cut_allowed '))
        listed = next(index for index, line in enumerate(lines) if line.startswith('release_list=$(gh api --paginate --slurp '))
        first_docker = next(index for index, line in enumerate(lines) if line.startswith('docker ') or ' docker ' in line)
        self.assertLess(listed, gate)
        self.assertLess(gate, first_docker)
        self.assertLess(gate, next(index for index, line in enumerate(lines) if 'verify-source' in line))


class ExistingReleaseTagTests(PromotionFixture):
    """`gh release create --draft` does not look for a release that already has the tag: gh 2.103.0
    makes that lookup only for a release that is not a draft (pkg/cmd/release/create/create.go,
    `if hasAssets && !opts.Draft`), and a draft holds no git tag for GitHub to refuse. A second cut
    of the same version therefore leaves two drafts under one tag, and `gh release view`,
    `download` and `edit` act on "the first draft release that has tagName as its pending tag"
    (pkg/cmd/release/shared/fetch.go), one GraphQL lookup whose choice among several drafts no
    GitHub document states. Promotion could then verify one bundle and publish another. So a cut
    refuses, before any build or push, when GitHub's release list already holds the tag, draft
    or public. A stale draft is removed by the person running the cut; the script deletes nothing."""

    def refused(self, promotion, rows):
        result = promotion.cut(rows)
        self.assertNotEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertIn('Nothing was built or pushed', result.stderr)
        self.assertEqual([], promotion.docker_calls())
        # GitHub was asked for the repository's name and its release list. Nothing was created or deleted.
        self.assertEqual([['repo', 'view'], ['api', '--paginate']], [call[:2] for call in promotion.gh_calls()])
        self.assertNotIn(VERIFY_SOURCE_REACHED, result.stderr)
        return result

    def test_a_cut_is_refused_while_a_draft_with_the_tag_exists(self):
        promotion = self.promotion()
        draft = promotion.catalog[0][0]
        result = self.refused(promotion, promotion.catalog[0])
        self.assertIn(f'error: example/chronicle already has a draft release tagged {VERSION} ({draft["html_url"]})', result.stderr)
        self.assertIn(f'  gh release delete {VERSION} --repo example/chronicle', result.stderr.splitlines())
        self.assertIn('this script deletes no release', result.stderr)

    def test_every_draft_with_the_tag_is_named(self):
        promotion = self.promotion()
        draft = promotion.catalog[0][0]
        second = dict(draft, id=draft['id'] + 1, html_url=draft['html_url'].replace('untagged-0123', 'untagged-9876'))
        result = self.refused(promotion, [second, *promotion.catalog[0]])
        self.assertIn(f'error: example/chronicle already has 2 draft releases tagged {VERSION} ({second["html_url"]}, {draft["html_url"]})',
                      result.stderr)
        self.assertIn('once for each draft', result.stderr)

    def test_a_leading_v_does_not_hide_the_existing_draft(self):
        promotion = self.promotion(release='v' + VERSION)
        rows = [dict(promotion.catalog[0][0], tag_name=VERSION), *promotion.published_rows]
        result = self.refused(promotion, rows)
        self.assertIn(f'already has a draft release tagged {VERSION} ', result.stderr)
        # The command names the tag the draft has, not the one being cut.
        self.assertIn(f'  gh release delete {VERSION} --repo example/chronicle', result.stderr.splitlines())

    def test_a_cut_is_refused_when_the_version_is_already_public(self):
        promotion = self.promotion()
        promotion.ledger.write_text(json.dumps(dict(json.loads(promotion.ledger.read_text()), **{VERSION: promotion.migrations})))
        git(promotion.checkout, 'commit', '-q', '-am', 'fixture: record ' + VERSION)
        public = promotion.another_release(VERSION)
        result = self.refused(promotion, [public, *promotion.published_rows])
        self.assertIn(f'error: example/chronicle has already published {VERSION} ({public["html_url"]})', result.stderr)
        self.assertIn('A published release is never cut again or replaced', result.stderr)
        self.assertNotIn('gh release delete', result.stderr)

    def test_a_tag_no_release_has_passes(self):
        promotion = self.promotion()
        result = promotion.cut([promotion.another_release('9999.1.10', draft=True), *promotion.published_rows])
        self.assertNotIn('already', result.stderr)
        self.assertIn(VERIFY_SOURCE_REACHED, result.stderr, result.stdout + result.stderr)


if __name__ == '__main__':
    unittest.main()
