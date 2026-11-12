"""Every bundle path the release smoke names must exist in the bundle.

In tests/smoke/selfhost-release-smoke.sh, BUNDLE is the extracted release's selfhost/ directory, whose
shipped files come from this repository's selfhost/. The monitoring check joined
BUNDLE / "selfhost/monitoring/grafana-dashboards", found nothing, and failed the 2026.11.12 smoke with
"the bundle ships 0 Grafana dashboards" although the bundle ships six. Paths the installation creates at
run time (.env, backups/, tls/, the restore lock) are not in the source tree and are listed here."""
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SMOKE = ROOT / 'tests/smoke/selfhost-release-smoke.sh'
CREATED_AT_RUN_TIME = ('.env', '.chronicle-restore.lock', 'backups/', 'tls/')
PATTERN = re.compile(r'Path\(os\.environ\["BUNDLE"\]\) / "([^"]+)"|\$\{?BUNDLE\}?/([A-Za-z0-9_./-]+)')


def bundle_paths(text):
    return sorted({first or second for first, second in PATTERN.findall(text)})


class SmokeBundlePathTests(unittest.TestCase):
    def test_every_bundle_path_in_the_smoke_ships_or_is_created_at_run_time(self):
        paths = bundle_paths(SMOKE.read_text())
        self.assertIn('monitoring/grafana-dashboards', paths)
        missing = [path for path in paths if not path.startswith(CREATED_AT_RUN_TIME)
                   and not (ROOT / 'selfhost' / path).exists()]
        self.assertEqual([], missing, 'the smoke names bundle paths that the bundle does not ship')

    def test_the_check_catches_the_doubled_selfhost_component(self):
        # Negative control: the 2026.11.12 line is reported.
        line = 'shipped = sorted((Path(os.environ["BUNDLE"]) / "selfhost/monitoring/grafana-dashboards").glob("*.json"))'
        [path] = bundle_paths(line)
        self.assertFalse((ROOT / 'selfhost' / path).exists())


if __name__ == '__main__':
    unittest.main()
