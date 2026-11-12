"""A harness that takes the backend down stops what restore stops.

The 2026.11.12 release smoke stopped only backend, db-backup and postgres to prove the TDE volume is
unreadable without its keyring. web kept running against the stopped backend, failed its health check
more often than its retries allow, and the following `docker compose up --wait` refused the unhealthy web
although the backend had recovered. Restore stops every service but postgres
(chronicle_ops.common.application_services); harnesses that stop the backend must do the same."""
import re
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
STOP = re.compile(r'docker compose stop ([^\n>|&;]*)')


def partial_stops(text):
    """`docker compose stop` calls that stop backend (by name) without the full application list."""
    return [arguments.strip() for arguments in STOP.findall(text)
            if re.search(r'\bbackend\b', arguments) and 'offline_services' not in arguments]


class SmokeOfflineServiceTests(unittest.TestCase):
    def test_no_harness_stops_the_backend_alone(self):
        tracked = subprocess.run(['git', '-C', str(ROOT), 'ls-files', '-z', '--', 'tests/*.sh'],
                                 capture_output=True, text=True, check=True).stdout.split('\0')
        offenders = {name: partial_stops((ROOT / name).read_text(errors='replace'))
                     for name in filter(None, tracked) if (ROOT / name).is_file()}
        self.assertEqual({}, {name: stops for name, stops in offenders.items() if stops})

    def test_the_release_smoke_stops_the_application_services_of_restore(self):
        smoke = (ROOT / 'tests/smoke/selfhost-release-smoke.sh').read_text()
        self.assertIn('from chronicle_ops.common import application_services', smoke)
        self.assertIn('docker compose stop "${offline_services[@]}" postgres', smoke)

    def test_the_check_catches_the_2026_11_6_line(self):
        self.assertEqual(['backend db-backup postgres'],
                         partial_stops('docker compose stop backend db-backup postgres >/dev/null\n'))
        self.assertEqual([], partial_stops('docker compose stop postgres\n'))


if __name__ == '__main__':
    unittest.main()
