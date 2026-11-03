"""BACKUP_SCHEDULE is read with go-cron's own grammar, and "overdue" follows its longest gap between runs."""
import datetime
import json
import os
from pathlib import Path
import random
import re
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import uuid

from chronicle_ops import cron, dump

ROOT = Path(__file__).resolve().parents[2]
HOUR, DAY = 60 * 60, 24 * 60 * 60
MARGIN = 36 * HOUR - DAY  # today's 36 h window for the default daily schedule


def brute_force_longest_gap(spec, start, days):
    """Step every minute of the window and measure the gaps between the minutes the schedule runs in."""
    runs, moment = [], datetime.datetime.combine(start, datetime.time())
    end = moment + datetime.timedelta(days=days)
    while moment < end:
        if moment.minute in spec.minute and moment.hour in spec.hour and spec.runs_on(moment.date()):
            runs.append(moment)
        moment += datetime.timedelta(minutes=1)
    gaps = [int((later - earlier).total_seconds()) for earlier, later in zip(runs, runs[1:])]
    return max(gaps, default=None)


def brute_force_zone_gap(spec, start, days):
    """Step every UTC minute, read the sidecar's wall clock in spec.zone and keep the minutes whose
    local fields match: a skipped wall time never matches and a repeated one matches twice."""
    zone, runs = spec.zone, []
    first = int(datetime.datetime.combine(start, datetime.time(), zone).timestamp()) - 3 * HOUR
    last = first + days * DAY + 6 * HOUR
    for instant in range(first - first % 60, last, 60):
        local = datetime.datetime.fromtimestamp(instant, zone)
        if (start <= local.date() < start + datetime.timedelta(days=days) and local.minute in spec.minute
                and local.hour in spec.hour and spec.runs_on(local.date())):
            runs.append(instant)
    return max((later - earlier for earlier, later in zip(runs, runs[1:])), default=None)


class BackupScheduleTests(unittest.TestCase):
    def test_a_time_zone_prefix_measures_gaps_across_daylight_saving_changes(self):
        # Santiago skips 00:00 on 2026-09-06 (robfig finds no midnight that day) and repeats 23:00-24:00
        # on 2026-04-04 (a run in that hour happens twice, an hour apart).
        for schedule, gap in (('TZ=America/Santiago 0 0 * * *', 47 * HOUR), ('CRON_TZ=America/Santiago @daily', 47 * HOUR),
                              ('TZ=America/Santiago 0 3 * * *', 25 * HOUR), ('TZ=America/Santiago 30 23 * * *', DAY),
                              ('TZ=Europe/Berlin 30 2 * * *', 47 * HOUR), ('TZ=UTC 0 0 * * *', DAY),
                              ('TZ=Local 0 0 * * *', DAY), ('0 0 * * *', DAY)):
            with self.subTest(schedule=schedule):
                self.assertEqual(gap + MARGIN, dump.backup_max_age_seconds(schedule))

    def test_zone_gaps_match_minute_stepping_around_transitions(self):
        choices = random.Random(20261028)
        for zone, start in (('America/Santiago', datetime.date(2026, 8, 25)), ('America/Santiago', datetime.date(2027, 3, 25)),
                            ('Europe/Berlin', datetime.date(2026, 3, 20)), ('Europe/Berlin', datetime.date(2026, 10, 15))):
            for _ in range(6):
                minute = choices.choice(('0', '30', '*/20', '15,45'))
                hour = choices.choice(('0', '23', '2', '3', '1-3', '*/6', '22-23'))
                pattern = f'TZ={zone} {minute} {hour} * * {choices.choice(("*", "0", "6", "0,6"))}'
                spec = cron.parse(pattern)
                with self.subTest(pattern=pattern, start=start):
                    self.assertEqual(brute_force_zone_gap(spec, start, 21), cron.longest_gap(spec, start, 21))


    def test_overdue_is_the_longest_gap_between_runs_plus_the_daily_margin(self):
        for schedule, gap in (
                ('', DAY), ('@daily', DAY), ('@midnight', DAY), ('@hourly', HOUR), ('@weekly', 7 * DAY),
                ('@monthly', 31 * DAY), ('@yearly', 366 * DAY), ('@annually', 366 * DAY),
                ('0 3 * * *', DAY), ('0 3 * * 1-5', 3 * DAY), ('0 */6 * * *', 6 * HOUR),
                ('30 0 3 * * *', DAY), ('*/20 * * * * *', 20), ('0 3 * * mon', 7 * DAY),
                ('0 0 3 * * MON-FRI', 3 * DAY), ('0 3 1 jan,jul *', 184 * DAY), ('15,45 2-4 * * *', 21 * HOUR + 30 * 60),
                ('0 3 29 2 *', 1461 * DAY), ('0 3 31 * *', 61 * DAY), ('CRON_TZ=UTC 0 3 * * *', DAY),
                ('TZ=UTC @weekly', 7 * DAY),
                # robfig's day rule: a restricted day of month OR a restricted weekday; a * on either side means AND.
                ('0 3 1 * 1', 7 * DAY), ('0 3 1-31 * 1', DAY), ('0 3 * * 1', 7 * DAY), ('0 3 */1 * 1', 7 * DAY),
                ('@every 1h30m', 90 * 60), ('@every 1.5h', 90 * 60), ('@every 6h', 6 * HOUR),
                ('@every 90m', 90 * 60), ('@every 1h0.5m', HOUR + 30), ('@every 2500ms', 2),
                ('@every 500ms', 1), ('@every 0', 1), ('@every 0s', 1), ('@every 36µs', 1)):
            with self.subTest(schedule=schedule):
                self.assertEqual(gap + MARGIN, dump.backup_max_age_seconds(schedule))

    def test_values_go_cron_cannot_run_are_refused_with_the_setting_name(self):
        for schedule in ('0 3 * *', '0 0 3 * * * *', '61 * * * *', '0 24 * * *', '0 3 0 * *', '0 3 * 13 *',
                         '0 3 * * 7', '0 3 * * sunday', '5-1 * * * *', '*/0 * * * *', '1-2-3 * * * *',
                         '1/2/3 * * * *', 'x * * * *', '@fortnightly', '@DAILY', ' @daily', '@every',
                         '@every 1d', '@every 5 minutes', '@every h', '@every .h', 'TZ=UTC',
                         'TZ=Not/A_Zone 0 3 * * *',
                         # Valid syntax that never runs: robfig returns no next run and go-cron stays idle.
                         '0 3 30 2 *', '0 3 31 4,6,9,11 *', ', * * * *'):
            with self.subTest(schedule=schedule), self.assertRaisesRegex(ValueError, 'BACKUP_SCHEDULE'):
                dump.backup_max_age_seconds(schedule)

    def test_every_parses_like_go_time_parse_duration(self):
        for text, nanoseconds in (('1h30m', 5400 * 10**9), ('1.5h', 5400 * 10**9), ('+2m', 120 * 10**9),
                                  ('-1s', -10**9), ('1.s', 10**9), ('.5s', 5 * 10**8), ('1h1m1s1ms1us1ns', 3661001001001),
                                  ('3μs', 3000), ('3µs', 3000), ('0', 0), ('0.000000001s', 1)):
            with self.subTest(text=text):
                self.assertEqual(nanoseconds, cron.parse_duration(text))
        for text in ('', '+', '1', '.s', '1x', '1h 30m', '9223372036854775808ns', '2562048h'):
            with self.subTest(text=text), self.assertRaises(ValueError):
                cron.parse_duration(text)

    def test_out_of_range_every_values_fail_with_go_s_reason(self):
        # Go's leadingInt overflow, a sum past int64 on a negative delay, and fraction digits past int64 that Go reads and drops.
        for text, reason in (('99999999999999999999', 'invalid duration'), ('-9223372036854775807ns2ns', 'invalid duration')):
            with self.subTest(text=text), self.assertRaisesRegex(ValueError, reason):
                cron.parse_duration(text)
        self.assertEqual(-(1 << 63), cron.parse_duration('-9223372036854775808ns'))
        self.assertEqual(1555555555, cron.parse_duration('1.' + '5' * 400 + 's'))
        with self.assertRaisesRegex(ValueError, 'BACKUP_SCHEDULE.*negative number -5 is not allowed'):
            dump.backup_max_age_seconds('*/-5 * * * *')

    def test_a_host_without_a_zone_database_measures_the_zone_on_the_sidecar_wall_clock(self):
        def missing(name):
            raise cron.zoneinfo.ZoneInfoNotFoundError(name)
        with patch.object(cron.zoneinfo, 'ZoneInfo', side_effect=missing), \
             patch.object(cron.zoneinfo, 'available_timezones', return_value=set()), \
             patch.object(cron.datetime, 'date', wraps=cron.datetime.date) as date:
            date.today.return_value = date(2026, 10, 31)
            self.assertIsNone(cron.parse('TZ=America/Santiago 0 3 * * *').zone)
            self.assertEqual(DAY + MARGIN, dump.backup_max_age_seconds('TZ=America/Santiago 0 0 * * *'))
        with patch.object(cron.zoneinfo, 'ZoneInfo', side_effect=missing), self.assertRaisesRegex(ValueError, 'unknown time zone'):
            cron.parse('TZ=America/Santiago 0 3 * * *')

    def test_enumerated_gap_matches_minute_stepping_on_random_patterns(self):
        choices = random.Random(20261027)
        start = datetime.date(2028, 1, 20)  # spans a leap February

        def field(low, high, names=()):
            a, b = sorted(choices.sample(range(low, high + 1), 2))
            step = choices.randint(1, max(1, (high - low) // 2))
            value = choices.choice(names) if names else str(a)
            return choices.choice(('*', f'*/{step}', f'{a}-{b}', f'{a},{b}', str(a), f'{a}-{b}/{step}', f'{a}/{step}', value))

        for _ in range(30):
            pattern = ' '.join((choices.choice(('0', '*/15', '5,35')), choices.choice(('3', '*/5', '1-2', '22')),
                                field(1, 31), field(1, 12, ('jan', 'feb', 'mar')), field(0, 6, ('mon', 'SAT', 'sun'))))
            spec = cron.parse(pattern)
            with self.subTest(pattern=pattern):
                self.assertEqual(brute_force_longest_gap(spec, start, 45), cron.longest_gap(spec, start, 45))


ORACLE_BUILD = '''
go mod init oracle >/dev/null 2>&1
go get "github.com/prodrigestivill/go-cron@$GOCRON_VERSION"
go mod tidy
go build -trimpath -o /work/oracle .
cp "$(go env GOMODCACHE)/github.com/prodrigestivill/go-cron@$GOCRON_VERSION/gocron/go-cron.go" /work/go-cron.go
'''


class GoCronOracleTests(unittest.TestCase):
    """Compares the overdue window with the sidecar's own scheduler, not with a model of it: robfig/cron at the
    version go-cron pins, compiled in the builder image Dockerfile.backup pins and run in its runtime base."""

    @classmethod
    def setUpClass(cls):
        dockerfile = (ROOT / 'selfhost/Dockerfile.backup').read_text()
        builder, runtime = re.findall(r'^FROM (\S+)', dockerfile, re.MULTILINE)
        version = re.search(r'github\.com/prodrigestivill/go-cron@(v[0-9.]+)', dockerfile)[1]
        folder = tempfile.TemporaryDirectory(prefix='gocron-oracle-')
        cls.addClassCleanup(folder.cleanup)
        cls.work, cls.runtime = Path(folder.name), runtime
        source = cls.work / 'source'
        source.mkdir()
        (source / 'main.go').write_text((Path(__file__).with_name('gocron_oracle.go')).read_text())
        user = f'{os.getuid()}:{os.getgid()}'
        cls.docker_run('-u', user, '-e', 'HOME=/work', '-e', 'GOCRON_VERSION=' + version,
                        '-e', 'GOMODCACHE=/work/gomod', '-e', 'GOCACHE=/work/gocache', '-e', 'GOFLAGS=-modcacherw',
                        '-e', 'CGO_ENABLED=0', '-e', 'GOTOOLCHAIN=local', '-v', f'{cls.work}:/work', '-w', '/work/source',
                        '--entrypoint', 'sh', builder, '-ec', ORACLE_BUILD)
        cls.gocron_source = (cls.work / 'go-cron.go').read_text()

    @classmethod
    def docker_run(cls, *arguments, **kwargs):
        name = 'chronicle-gocron-oracle-' + uuid.uuid4().hex
        try:
            return subprocess.run(['docker', 'run', '--rm', '--name', name, *arguments],
                                  check=True, capture_output=True, timeout=600, **kwargs)
        finally:
            subprocess.run(['docker', 'rm', '-fv', name], capture_output=True, timeout=30)

    def oracle(self, requests):
        """Runs in the sidecar's runtime base, so a schedule with no TZ= prefix reads its Local clock."""
        result = self.docker_run('-i', '--network', 'none', '-v', f'{self.work}:/work:ro',
                                 '--entrypoint', '/work/oracle', self.runtime,
                                input=''.join(json.dumps(request) + '\n' for request in requests),
                                text=True)
        answers = [json.loads(line) for line in result.stdout.splitlines()]
        self.assertEqual(len(requests), len(answers), 'the scheduler oracle omitted answers')
        return answers

    def test_oracle_reads_schedules_with_the_sidecars_parser(self):
        self.assertIn('cron.NewParser(\n\t\t\t\tcron.SecondOptional | cron.Minute | cron.Hour | cron.Dom | cron.Month | '
                      'cron.Dow | cron.Descriptor,', self.gocron_source)
        self.assertIn('c.AddFunc(schedule,', self.gocron_source)

    def test_measured_gaps_match_go_cron_across_santiago_daylight_saving(self):
        # Four years from 2026: Santiago skips 00:00-01:00 each September and repeats 23:00-24:00 each April,
        # 2028 is a leap year, and Berlin's changes fall at 02:00-03:00.
        start, days = datetime.date(2026, 1, 1), 4 * 365 + 1
        schedules = ('@daily', '0 0 * * *', '30 0 3 * * *', '0 3 * * 1-5', '15,45 2-4 * * *', '0 3 31 * *',
                     'TZ=America/Santiago 0 0 * * *', 'CRON_TZ=America/Santiago @daily', 'TZ=America/Santiago 30 23 * * *',
                     'TZ=America/Santiago 0 3 * * *', 'TZ=America/Santiago 0 */6 * * *', 'TZ=America/Santiago 0 0 1 * *',
                     'TZ=America/Santiago 0 30 0 * * sun', 'TZ=America/Santiago 0,30 23 * * sat', 'TZ=Europe/Berlin 30 2 * * *',
                     'TZ=UTC @weekly', 'TZ=Local 0 0 * * *')
        answers = self.oracle([dict(schedule=schedule, start=start.isoformat(), days=days) for schedule in schedules])
        for schedule, answer in zip(schedules, answers):
            with self.subTest(schedule=schedule):
                self.assertNotIn('error', answer)
                self.assertGreater(answer['runs'], 1)
                self.assertEqual(answer['gap'], cron.longest_gap(cron.parse(schedule), start, days))
                self.assertLessEqual(answer['gap'] + MARGIN, dump.backup_max_age_seconds(schedule))

    def test_every_delays_match_go_cron(self):
        schedules = ('@every 6h', '@every 1h30m', '@every 1.5h', '@every 90m', '@every 2500ms', '@every 500ms',
                     'TZ=America/Santiago @every 6h')
        answers = self.oracle([dict(schedule=schedule, start='2026-09-05', days=3) for schedule in schedules])
        for schedule, answer in zip(schedules, answers):
            with self.subTest(schedule=schedule):
                self.assertNotIn('error', answer)
                self.assertEqual(answer['gap'] + MARGIN, dump.backup_max_age_seconds(schedule))

    def test_schedules_go_cron_refuses_or_never_runs_are_refused(self):
        schedules = ('0 3 * *', '0 0 3 * * * *', '61 * * * *', '0 24 * * *', '0 3 0 * *', '0 3 * 13 *', '0 3 * * 7',
                     '0 3 * * sunday', '5-1 * * * *', '*/0 * * * *', '1-2-3 * * * *', '1/2/3 * * * *', 'x * * * *',
                     '@fortnightly', '@DAILY', '@every', '@every 1d', '@every 5 minutes', '@every h', '@every .h',
                     'TZ=UTC', 'TZ=Not/A_Zone 0 3 * * *', '0 3 30 2 *', '0 3 31 4,6,9,11 *', ', * * * *')
        answers = self.oracle([dict(schedule=schedule, start='2026-01-01', days=6 * 366) for schedule in schedules])
        for schedule, answer in zip(schedules, answers):
            with self.subTest(schedule=schedule):
                self.assertIn('error', answer)
                with self.assertRaisesRegex(ValueError, 'BACKUP_SCHEDULE'):
                    dump.backup_max_age_seconds(schedule)


if __name__ == '__main__':
    unittest.main()
