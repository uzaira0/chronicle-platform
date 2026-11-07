"""Verification right after a start waits for the services to settle before a failure counts.

The 2026.11.6 drill's rollback ran 2026.11.2's ./chronicle verify seconds after restarting the
stack; its edge rate-limit probe sent 400 requests to a cold backend, which answered too slowly
for 200 of them to land in one rate-limit window, so the check failed, the rollback stopped and
its journal stayed. The previous release's verifier cannot change, so verify_release reruns a
failing verification until VERIFY_SETTLE_SECONDS pass; and this release's probe keeps sending
bursts within its own deadline before it reports that nothing was rate limited.
"""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from chronicle_ops import upgrade, verify


def launcher(folder, outcomes):
    """A ./chronicle whose `verify` prints the next outcome's FAIL lines and exits accordingly."""
    script = Path(folder) / 'chronicle'
    counter = Path(folder) / 'count'
    lines = ['#!/usr/bin/env bash', f'n=$(cat {counter} 2>/dev/null || echo 0); echo $((n + 1)) >{counter}', 'case "$n" in']
    for index, failures in enumerate(outcomes):
        body = ''.join(f'echo "  FAIL   {failure}"; ' for failure in failures)
        lines.append(f'  {index}) {body}exit {1 if failures else 0} ;;')
    lines += ['  *) exit 0 ;;', 'esac']
    script.write_text('\n'.join(lines) + '\n')
    script.chmod(0o755)
    return script, counter


class VerifyReleaseSettleTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.mkdtemp(prefix='settle-')
        self.sleeps = []
        patcher = patch('chronicle_ops.upgrade.time.sleep', side_effect=self.sleeps.append)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_a_check_that_fails_only_right_after_the_start_does_not_roll_back(self):
        script, counter = launcher(self.folder, [['400 requests to mobile enrollment were never rate limited'], []])
        upgrade.verify_release(script, [])
        self.assertEqual('2', counter.read_text().strip())
        self.assertEqual([upgrade.VERIFY_RETRY_DELAYS[0]], self.sleeps)

    def test_a_failure_that_persists_past_the_deadline_still_fails(self):
        failing = ['web is down']
        script, counter = launcher(self.folder, [failing] * 50)
        with self.assertRaisesRegex(ValueError, 'verification failed: web is down'):
            upgrade.verify_release(script, [])
        self.assertLessEqual(sum(self.sleeps), upgrade.VERIFY_SETTLE_SECONDS)
        self.assertGreater(int(counter.read_text()), 1)

    def test_a_failure_present_before_the_update_is_not_retried(self):
        script, counter = launcher(self.folder, [['backups is 0755']])
        upgrade.verify_release(script, ['backups is 0755'])
        self.assertEqual('1', counter.read_text().strip())
        self.assertEqual([], self.sleeps)


class RateLimitProbeTests(unittest.TestCase):
    def run_probe(self, answers):
        """answers: one list of status codes per burst."""
        bursts = iter(answers)
        current = {'codes': iter(())}
        results = []

        def curl(*_args, **_kwargs):
            try:
                return 0, next(current['codes'])
            except StopIteration:
                current['codes'] = iter(next(bursts))
                return 0, next(current['codes'])

        with patch('chronicle_ops.verify.curl', side_effect=curl), \
             patch('chronicle_ops.verify.time.sleep'), \
             patch('chronicle_ops.verify.RATE_LIMIT_PROBE_MAX_REQUESTS', 4):
            verify.verify_mobile_rate_limit({'RATE_LIMIT_MOBILE_ABUSE_EVENTS': '2'}, 'https://fixture', lambda ok, message: results.append((ok, message)))
        return results

    def test_a_cold_first_burst_is_followed_by_another_within_the_deadline(self):
        [(ok, message)] = self.run_probe([['404'] * 4, ['404', '404', '429', '429']])
        self.assertTrue(ok, message)

    def test_no_429_after_every_burst_still_fails(self):
        [(ok, message)] = self.run_probe([['404'] * 4] * verify.RATE_LIMIT_PROBE_BURSTS)
        self.assertFalse(ok)
        self.assertIn('never rate limited', message)


if __name__ == '__main__':
    unittest.main()
