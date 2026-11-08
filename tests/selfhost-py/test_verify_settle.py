"""Verification right after a start waits for the services to settle before a failure counts.

The 2026.11.6 drill's rollback ran 2026.11.2's ./chronicle verify seconds after restarting the
stack; its edge rate-limit probe sent 400 requests to a cold backend, which answered too slowly
for 200 of them to land in one rate-limit window, so the check failed, the rollback stopped and
its journal stayed. The previous release's verifier cannot change, so verify_release reruns a
failing verification until VERIFY_SETTLE_SECONDS pass; and this release's probe keeps sending
bursts within its own deadline before it reports that nothing was rate limited.
"""
import os
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
    """A missing 429 fails verification only when a burst was fast enough that the edge had to refuse part of
    it. The 2026.11.6 release smoke on a busy host sent 1200 requests too slowly to exceed 200 per second and
    failed although the same Caddy limited the matrix rows' bursts; that is unproven, not broken."""

    def run_probe(self, bursts, settings=None):
        """bursts: one (status codes, seconds elapsed) per burst."""
        results = []
        answers = iter(bursts)
        with patch('chronicle_ops.verify.send_burst', side_effect=lambda *_: next(answers)), \
             patch('chronicle_ops.verify.time.sleep'), \
             patch('chronicle_ops.verify.RATE_LIMIT_PROBE_MAX_REQUESTS', 4):
            verify.verify_mobile_rate_limit(settings or {'RATE_LIMIT_MOBILE_ABUSE_EVENTS': '2'}, 'https://fixture',
                                            lambda ok, message, warning=False: results.append((ok, warning, message)))
        return results

    def test_a_cold_first_burst_is_followed_by_another_within_the_deadline(self):
        [(ok, _, message)] = self.run_probe([(['404'] * 4, 0.1), (['404', '404', '429', '429'], 0.1)])
        self.assertTrue(ok, message)

    def test_a_burst_fast_enough_to_exceed_the_limit_without_a_429_fails(self):
        # 4 answered requests in 0.5 s: one 1 s window held 4 > 2 events, so the edge had to refuse some.
        [(ok, warning, message)] = self.run_probe([(['404'] * 4, 0.5)] * verify.RATE_LIMIT_PROBE_BURSTS)
        self.assertEqual((False, False), (ok, warning))
        self.assertIn('never rate limited', message)

    def test_a_host_too_slow_to_exceed_the_limit_is_unproven_not_failed(self):
        # 4 requests over 2.5 s spread across 3 windows: at most 2 per window is within the limit of 2.
        [(ok, warning, message)] = self.run_probe([(['404'] * 4, 2.5)] * verify.RATE_LIMIT_PROBE_BURSTS)
        self.assertEqual((False, True), (ok, warning))
        self.assertIn('unproven', message)
        self.assertIn('2 per 1s', message)

    def test_unanswered_requests_do_not_count_towards_the_limit(self):
        [(ok, warning, _)] = self.run_probe([(['000', '000', '404', '404'], 0.1)] * verify.RATE_LIMIT_PROBE_BURSTS)
        self.assertEqual((False, True), (ok, warning))

    def test_the_configured_window_decides(self):
        # The same 4 requests in 2.5 s overflow a 1m window of 2 events.
        [(ok, warning, _)] = self.run_probe([(['404'] * 4, 2.5)] * verify.RATE_LIMIT_PROBE_BURSTS,
                                            {'RATE_LIMIT_MOBILE_ABUSE_EVENTS': '2', 'RATE_LIMIT_MOBILE_WINDOW': '1m'})
        self.assertEqual((False, False), (ok, warning))

    def test_an_unreadable_window_keeps_the_failure(self):
        [(ok, warning, _)] = self.run_probe([(['404'] * 4, 2.5)] * verify.RATE_LIMIT_PROBE_BURSTS,
                                            {'RATE_LIMIT_MOBILE_ABUSE_EVENTS': '2', 'RATE_LIMIT_MOBILE_WINDOW': 'soon'})
        self.assertEqual((False, False), (ok, warning))


class SendBurstTests(unittest.TestCase):
    """send_burst with the real curl against a local HTTP/1.1 server: every request answered, and each worker
    reuses one connection instead of a new process and handshake per request."""

    def test_every_request_is_answered_over_one_connection_per_worker(self):
        import http.server
        import threading
        connections = []

        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = 'HTTP/1.1'

            def setup(self):
                super().setup()
                connections.append(self.client_address)

            def do_GET(self):
                self.send_response(404)
                self.send_header('Content-Length', '0')
                self.end_headers()

            def log_message(self, *_):
                pass

        server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(thread.join, 10)
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        with tempfile.TemporaryDirectory() as folder, patch.dict('os.environ', {'CHRONICLE_OPS_STATE': folder}):
            origin = Path.cwd()
            self.addCleanup(os.chdir, origin)
            os.chdir(folder)
            codes, elapsed = verify.send_burst(f'http://127.0.0.1:{server.server_port}/probe', 40, 4)
        self.assertEqual(['404'] * 40, codes)
        self.assertGreater(elapsed, 0)
        self.assertEqual(4, len(connections))

if __name__ == '__main__':
    unittest.main()
