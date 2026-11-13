"""scripts/database_image_lag.py: the database image may trail a newer vendor build only for a set time.

On 2026-11-13 the pinned image was percona-distribution-postgresql 18.6.1-4, PostgreSQL had released 18.7
the day before with 38 advisories rated HIGH, and the image gate reported none of them for the database:
Trivy has no advisories for Percona's packages. deps-freshness printed "minor-behind" and passed."""
import datetime as dt
import importlib.util
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('database_image_lag', ROOT / 'scripts/database_image_lag.py')
lag = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lag)

TODAY = dt.date(2026, 11, 13)
POLICY = {'database_max_lag_days': 10}
PINNED = '18.6.1-4'


def tag(name: str, pushed: str | None) -> dict:
    return {'name': name, 'tag_last_pushed': pushed}


# Docker Hub's answer of 2026-11-13 for name=18., cut to the tags that matter here.
HUB = [tag('18', '2026-11-13T05:10:27.1Z'), tag('18.7', '2026-11-13T05:10:24.6Z'), tag('18.7.1-1', '2026-11-13T05:09:29.5Z'),
       tag('18.7.1-1-ubi8', '2026-11-13T05:07:24.0Z'), tag('18.6.1-4', '2026-10-20T11:00:00.0Z'),
       tag('18.6.1-3', '2026-09-30T11:00:00.0Z'), tag('17.18.1-1', '2026-11-13T04:00:00.0Z')]


class LagRuleTests(unittest.TestCase):
    def test_the_case_of_13_november_passes_on_the_day_and_fails_after_the_limit(self):
        found, note = lag.problems(PINNED, HUB, POLICY, TODAY)
        self.assertEqual([], found)
        self.assertEqual('18.6.1-4 is behind 18.7.1-1, pushed 2026-11-13 (0 days ago); it has to move by 2026-11-23', note)
        self.assertEqual([], lag.problems(PINNED, HUB, POLICY, dt.date(2026, 11, 23))[0])
        found, _ = lag.problems(PINNED, HUB, POLICY, dt.date(2026, 11, 24))
        self.assertEqual(1, len(found))
        self.assertTrue(found[0].startswith('18.6.1-4 has been behind 18.7.1-1 for 11 days (pushed 2026-11-13), over 10'),
                        found[0])

    def test_a_current_pin_passes_and_other_majors_and_variants_do_not_count(self):
        self.assertEqual(([], '18.7.1-1 is the newest build of PostgreSQL 18'), lag.problems('18.7.1-1', HUB, POLICY, TODAY))
        # 17.18.1-1 is newer than nothing here, and 19.x is deps-freshness.sh's MAJOR-BEHIND row.
        tags = [tag('17.18.1-1', '2026-01-01T00:00:00Z'), tag('19.0.1-1', '2026-01-01T00:00:00Z'), tag(PINNED, None)]
        self.assertEqual([], lag.problems(PINNED, tags, POLICY, TODAY)[0])

    def test_the_clock_starts_at_the_oldest_newer_build(self):
        # A respin on day 11 must not restart the wait that began with 18.7.1-1.
        tags = [tag('18.7.1-1', '2026-11-02T05:00:00Z'), tag('18.7.1-2', '2026-11-12T05:00:00Z'), tag(PINNED, None)]
        found, _ = lag.problems(PINNED, tags, POLICY, TODAY)
        self.assertEqual(1, len(found))
        self.assertIn('behind 18.7.1-2 for 11 days (pushed 2026-11-02)', found[0])

    def test_a_newer_build_without_a_push_time_fails(self):
        for pushed in (None, '', 'yesterday'):
            with self.subTest(pushed=pushed):
                found, _ = lag.problems(PINNED, [tag('18.7.1-1', pushed)], POLICY, TODAY)
                self.assertEqual([('18.7.1-1 is newer than 18.6.1-4 and Docker Hub gives no push time for it; the lag '
                                   'cannot be measured')], found)

    def test_a_pin_that_is_not_a_build_tag_fails(self):
        found, _ = lag.problems('18', HUB, POLICY, TODAY)
        self.assertEqual(['the pinned tag 18 is not MAJOR.MINOR.PATCH-BUILD; the lag cannot be measured'], found)

    def test_an_acceptance_with_a_reason_and_a_future_expiry_passes(self):
        policy = dict(POLICY, database_lag_accepted={'reason': '18.7.1-1 fails the pg_tde upgrade drill', 'expires': '2026-12-01'})
        self.assertEqual([], lag.problems(PINNED, HUB, policy, dt.date(2026, 11, 30))[0])

    def test_an_acceptance_cannot_rot(self):
        late = dt.date(2026, 11, 30)
        cases = {
            'expired': ({'reason': 'drill', 'expires': '2026-11-29'}, late, 'database_lag_accepted expired on 2026-11-29'),
            'no reason': ({'reason': ' ', 'expires': '2026-12-01'}, late, 'database_lag_accepted has no reason'),
            'no date': ({'reason': 'drill', 'expires': 'soon'}, late,
                        'database_lag_accepted has no valid expires date (YYYY-MM-DD)'),
            'nothing over the limit': ({'reason': 'drill', 'expires': '2026-12-01'}, TODAY,
                                       'database_lag_accepted stands while the image is not over the limit; remove it'),
        }
        for name, (entry, today, message) in cases.items():
            with self.subTest(name):
                found, _ = lag.problems(PINNED, HUB, dict(POLICY, database_lag_accepted=entry), today)
                self.assertIn(message, found)

    def test_the_limit_is_a_positive_number_in_the_manifest(self):
        import yaml
        freshness = yaml.safe_load((ROOT / 'toolchain-manifest.yaml').read_text())['freshness']
        self.assertGreaterEqual(int(freshness['database_max_lag_days']), 7, 'shorter than the dependency wait')
        self.assertLessEqual(int(freshness['database_max_lag_days']), 14)

    def test_deps_freshness_runs_the_check_on_the_pinned_database_image(self):
        script = (ROOT / 'scripts/deps-freshness.sh').read_text()
        self.assertIn('scripts/database_image_lag.py" percona/percona-distribution-postgresql "${pg##*:}"', script)


REPOSITORY = 'percona/percona-distribution-postgresql'
TAG_LIST = f'https://hub.docker.com/v2/repositories/{REPOSITORY}/tags?'


class TagListTests(unittest.TestCase):
    """The tag list is read page by page, and the address of each next page comes from Docker Hub's answer.

    That address is the last argument of a curl command. The first version of the script handed it over
    as it came: "-o/some/file" would have been read by curl as an option and file:///... as a local file.
    Bearer reported the call (python_lang_os_command_injection) on 2026-11-13."""

    def pages(self, *documents):
        asked = []

        def fetch(url, deadline):
            asked.append(url)
            return documents[len(asked) - 1]
        original = lag.web_dependency_age.fetch_json
        lag.web_dependency_age.fetch_json = fetch
        self.addCleanup(setattr, lag.web_dependency_age, 'fetch_json', original)
        return asked

    def test_a_next_page_inside_the_tag_list_is_read(self):
        # The form Docker Hub gave on 2026-11-13 for page_size=2 (99 tags matched name=18. that day).
        second = TAG_LIST + 'name=18.&page=2&page_size=100'
        asked = self.pages({'results': [tag('18.7.1-1', '2026-11-13T05:09:29.5Z')], 'next': second},
                           {'results': [tag(PINNED, '2026-10-20T11:00:00.0Z')], 'next': None})
        self.assertEqual(['18.7.1-1', PINNED], [entry['name'] for entry in lag.hub_tags(REPOSITORY, 18, 0.0)])
        self.assertEqual([TAG_LIST + 'page_size=100&name=18.', second], asked)

    def test_a_next_page_anywhere_else_is_refused_before_it_is_fetched(self):
        for link in ('-o/etc/cron.d/job', '--config=/dev/stdin', 'file:///etc/passwd',
                     'http://hub.docker.com/v2/repositories/' + REPOSITORY + '/tags?page=2',
                     'https://hub.docker.com.example.net/v2/repositories/' + REPOSITORY + '/tags?page=2',
                     'https://hub.docker.com/v2/repositories/other/image/tags?page=2',
                     'https://hub.docker.com/v2/repositories/' + REPOSITORY + '/tags/../../../users?page=2',
                     ' ' + TAG_LIST + 'page=2', TAG_LIST + 'page=2 -o /dev/null', TAG_LIST + 'page=2\n-K-', 7, ['x']):
            with self.subTest(link=link):
                asked = self.pages({'results': [tag('18.7.1-1', '2026-11-13T05:09:29.5Z')], 'next': link},
                                   {'results': [], 'next': None})
                with self.assertRaises(lag.TagLookupError) as raised:
                    lag.hub_tags(REPOSITORY, 18, 0.0)
                self.assertIn('next page', str(raised.exception))
                self.assertEqual(1, len(asked), asked)

    def test_a_repository_name_outside_docker_hubs_grammar_is_refused_before_any_fetch(self):
        for name in ('percona', '-o/dev/null', 'percona/../users', 'percona/image?x=', 'Percona/Image', 'a/b/c', 'a/b c', ''):
            with self.subTest(name=name):
                asked = self.pages({'results': [], 'next': None})
                with self.assertRaises(lag.TagLookupError):
                    lag.hub_tags(name, 18, 0.0)
                self.assertEqual([], asked)

    def test_a_failed_or_malformed_answer_is_a_lookup_failure(self):
        def no_answer(url, deadline):
            raise lag.web_dependency_age.ReleaseLookupError(f'no answer from {url}')

        def not_json(url, deadline):
            raise ValueError('Expecting value: line 1 column 1 (char 0)')

        def too_slow(url, deadline):
            raise subprocess.TimeoutExpired(['curl'], 120)

        def a_list(url, deadline):
            return [{'results': [], 'next': None}]
        for fetch, message in ((no_answer, 'no answer from ' + TAG_LIST), (not_json, 'did not answer with JSON'),
                               (too_slow, 'did not answer in 120 seconds'), (a_list, 'did not answer with a JSON object')):
            with self.subTest(message):
                original = lag.web_dependency_age.fetch_json
                lag.web_dependency_age.fetch_json = fetch
                self.addCleanup(setattr, lag.web_dependency_age, 'fetch_json', original)
                with self.assertRaises(lag.TagLookupError) as raised:
                    lag.hub_tags(REPOSITORY, 18, 0.0)
                self.assertIn(message, str(raised.exception))

    def test_the_script_starts_no_process_of_its_own(self):
        # One curl call, in scripts/web_dependency_age.py, with one reviewed waiver (bearer.ignore). A second
        # call here would need a second review of the same statement.
        source = (ROOT / 'scripts/database_image_lag.py').read_text()
        for word in ('subprocess.run', 'subprocess.Popen', 'os.system', 'os.popen', 'check_output'):
            self.assertNotIn(word, source)


if __name__ == '__main__':
    unittest.main()
