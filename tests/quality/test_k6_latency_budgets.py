"""Latency budgets gate only on a backend that runs on the host's own CPU architecture.

The release images are linux/amd64. The 2026.11.12 release smoke ran them on an arm64 Mac, where they are
emulated, and failed only the DoS concurrent latency budget (p95 9.0 s and 7.8 s) with the backend using
about 1.2 of its 4 CPUs. The same backend jars ran a 50-task burst 6x slower cold and 50x slower warm under
emulation than on a native JRE (tests/load/README.md). Every k6 script now splits its thresholds with
tests/load/latency-budgets.js; the smoke reads the backend container's platform with
tests/load/latency-budget-mode.sh and records latency as unqualified when it differs from the host's.

These tests run k6 itself (k6 inspect evaluates each script's init code and prints its thresholds), the
real local-ci job with k6 replaced on PATH, and Docker for the platform read."""
import json
import os
import re
import shutil
import stat
import subprocess
import tempfile
import unittest
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = sorted([ROOT / 'tests/load/chronicle-load-test.js', *ROOT.glob('tests/load/k6-*.js'),
                  *(ROOT / 'tests/performance' / name for name in ('load.js', 'smoke.js', 'stress.js'))])
# k6's built-in time metrics; scripts add their own with new Trend(name, true).
BUILTIN_TIME_METRICS = {'http_req_duration', 'http_req_blocked', 'http_req_connecting', 'http_req_tls_handshaking',
                        'http_req_sending', 'http_req_waiting', 'http_req_receiving', 'iteration_duration',
                        'group_duration'}
IMAGE = re.search(r'AUDIT_HELPER_IMAGE="([^"]+)"', (ROOT / 'docker/restore-chronicle.sh').read_text()).group(1)


def time_metrics(script):
    """Built-in time metrics plus every time Trend the script or its local imports declare."""
    names, seen, pending = set(BUILTIN_TIME_METRICS), set(), [script]
    while pending:
        path = pending.pop()
        if path in seen:
            continue
        seen.add(path)
        text = path.read_text()
        names |= set(re.findall(r"new Trend\('([^']+)',\s*true\)", text))
        pending += [(path.parent / spec).resolve() for spec in re.findall(r"from '(\.{1,2}/[^']+)'", text)]
    return names


class K6Inspect:
    def __init__(self, folder):
        self.devices = Path(folder) / 'devices.json'
        self.devices.write_text(json.dumps([{'participant_id': 'p', 'random_device_id': 'd', 'api_key': 'k'}]))

    def thresholds(self, script, mode):
        env = dict(os.environ, AUTH_TOKEN='synthetic', JWT_TOKEN='synthetic', API_KEY='synthetic',
                   STUDY_ID='00000000-0000-0000-0000-000000000001', PARTICIPANT_ID='synthetic',
                   TEST_RANDOM_DEVICE_ID='synthetic', MOBILE_SIGNING_SECRET='synthetic',
                   DEVICE_FIXTURES_FILE=str(self.devices), BASE_URL='http://127.0.0.1:9')
        env.pop('K6_LATENCY_BUDGETS', None)
        if mode is not None:
            env['K6_LATENCY_BUDGETS'] = mode
        result = subprocess.run(['k6', 'inspect', '--include-system-env-vars', '--execution-requirements', str(script)],
                                check=False, cwd=ROOT, env=env, capture_output=True, text=True, timeout=120)
        return result.returncode, (json.loads(result.stdout)['thresholds'] if result.returncode == 0 else result.stderr)


@unittest.skipUnless(shutil.which('k6'), 'k6 is required')
class ThresholdModeTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.k6 = K6Inspect(self.folder.name)

    def tearDown(self):
        self.folder.cleanup()

    def test_record_mode_drops_exactly_the_latency_thresholds_of_every_script(self):
        self.assertGreaterEqual(len(SCRIPTS), 9)
        latency_scripts = []
        for script in SCRIPTS:
            with self.subTest(script=script.relative_to(ROOT)):
                code, default = self.k6.thresholds(script, None)
                self.assertEqual(code, 0, default)
                _, gate = self.k6.thresholds(script, 'gate')
                _, record = self.k6.thresholds(script, 'record')
                self.assertEqual(default, gate)
                timed = time_metrics(script)
                latency = {key for key in gate if key.split('{', 1)[0] in timed}
                self.assertEqual({key: value for key, value in gate.items() if key not in latency}, record)
                self.assertFalse([key for key in record if key.split('{', 1)[0] in timed])
                if latency:
                    latency_scripts.append(script.name)
        # The DoS and study-list budgets that the 2026.11.12 smoke measured are among them.
        self.assertIn('k6-dos-patterns.js', latency_scripts)
        self.assertIn('k6-study-api.js', latency_scripts)

    def test_dos_patterns_keeps_its_every_response_bounds_as_latency_thresholds(self):
        _, gate = self.k6.thresholds(ROOT / 'tests/load/k6-dos-patterns.js', 'gate')
        # The removed checks ("responds within 5s/10s", rate==1) required every response under the bound.
        self.assertEqual(gate['concurrent_p95'], ['p(95)<5000', 'max<5000'])
        self.assertEqual(gate['pagination_duration'], ['max<10000'])
        self.assertEqual(gate['slowloris_duration'], ['max<5000'])
        self.assertEqual(gate['checks'], ['rate==1'])

    def test_an_unknown_mode_stops_the_script(self):
        code, error = self.k6.thresholds(ROOT / 'tests/load/k6-study-api.js', 'off')
        self.assertNotEqual(code, 0)
        self.assertIn('K6_LATENCY_BUDGETS must be gate or record', error)


@unittest.skipUnless(shutil.which('ast-grep'), 'ast-grep is required')
class LatencyOutsideChecksTests(unittest.TestCase):
    RULE = ROOT / 'tests/security/ast-grep/k6-latency-outside-checks.yml'

    def scan(self, folder):
        result = subprocess.run(['ast-grep', 'scan', '--rule', str(self.RULE), '--json=compact', '.'], check=False,
                                cwd=folder, capture_output=True, text=True, timeout=120)
        self.assertIn(result.returncode, (0, 1), result.stderr)
        return json.loads(result.stdout or '[]')

    def test_no_script_puts_latency_in_a_check(self):
        self.assertEqual(self.scan(ROOT), [])

    def test_the_rule_catches_the_2026_11_6_dos_checks(self):
        old = subprocess.run(['git', 'show', '044da1bd:tests/load/k6-dos-patterns.js'], cwd=ROOT,
                             capture_output=True, text=True, check=True).stdout
        with tempfile.TemporaryDirectory() as folder:
            target = Path(folder) / 'tests/load/k6-dos-patterns.js'
            target.parent.mkdir(parents=True)
            target.write_text(old)
            self.assertEqual(len(self.scan(folder)), 3)


class LocalCiJobTests(unittest.TestCase):
    def test_every_script_runs_after_one_fails_and_the_job_still_fails(self):
        with tempfile.TemporaryDirectory() as folder:
            calls = Path(folder) / 'calls'
            k6 = Path(folder) / 'k6'
            # External seam: k6 itself. The job, its loop and its exit status are the real ones.
            k6.write_text('#!/usr/bin/env bash\nprintf "%s %s\\n" "${K6_LATENCY_BUDGETS:-unset}" "${!#}" >>"$K6_CALLS"\n'
                          'case "${!#}" in *k6-dos-patterns.js) exit 99 ;; esac\n')
            k6.chmod(k6.stat().st_mode | stat.S_IXUSR)
            env = dict(os.environ, PATH=f'{folder}:{os.environ["PATH"]}', K6_CALLS=str(calls),
                       K6_LATENCY_BUDGETS='record', BASE_URL='http://127.0.0.1:9', AUTH_TOKEN='synthetic',
                       TEST_STUDY_ID='synthetic', TEST_PARTICIPANT_ID='synthetic', TEST_RANDOM_DEVICE_ID='synthetic',
                       API_KEY='synthetic', DEVICE_FIXTURES_FILE='synthetic')
            result = subprocess.run(['bash', str(ROOT / 'scripts/local-ci.sh'), 'k6-benchmarks'], check=False, cwd=ROOT,
                                    env=env, capture_output=True, text=True, timeout=300)
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            ran = [Path(line.split(' ', 1)[1]).name for line in calls.read_text().splitlines()]
            expected = ['chronicle-load-test.js'] + sorted(path.name for path in ROOT.glob('tests/load/k6-*.js'))
            self.assertEqual(ran, expected)
            self.assertTrue(all(line.startswith('record ') for line in calls.read_text().splitlines()))
            self.assertIn('k6 benchmarks failed: k6-dos-patterns.js', result.stdout + result.stderr)


@unittest.skipUnless(shutil.which('docker') and subprocess.run(['docker', 'info'], check=False, capture_output=True,
                                                                timeout=60).returncode == 0, 'Docker is required')
class PlatformModeTests(unittest.TestCase):
    def mode(self, image):
        name = f'chronicle-latency-mode-{uuid.uuid4().hex[:12]}'
        subprocess.run(['docker', 'create', '--name', name, image, 'true'], check=True, capture_output=True, timeout=300)
        try:
            script = f'source {ROOT}/tests/load/latency-budget-mode.sh && k6_latency_budget_mode {name}'
            return subprocess.run(['bash', '-c', script], check=True, capture_output=True, text=True,
                                  timeout=60).stdout.strip()
        finally:
            subprocess.run(['docker', 'rm', '--volumes', name], check=False, capture_output=True, timeout=60)

    def test_native_image_gates_and_foreign_image_records(self):
        host = subprocess.run(['docker', 'version', '--format', '{{.Server.Os}}/{{.Server.Arch}}'], check=True,
                              capture_output=True, text=True).stdout.strip()
        foreign = 'linux/arm64' if host == 'linux/amd64' else 'linux/amd64'
        # The pin is a multi-platform index; the classic image store keeps one platform per digest, so the
        # foreign platform is created from its own manifest digest.
        index = json.loads(subprocess.run(['docker', 'manifest', 'inspect', IMAGE], check=True, capture_output=True,
                                          text=True, timeout=120).stdout)
        digest = next(entry['digest'] for entry in index['manifests']
                      if f"{entry['platform']['os']}/{entry['platform']['architecture']}" == foreign)
        self.assertEqual(self.mode(IMAGE), 'gate')
        self.assertEqual(self.mode(IMAGE.split('@')[0].rsplit(':', 1)[0] + '@' + digest), f'record {foreign} {host}')

    def test_an_unreadable_container_fails(self):
        script = (f'source {ROOT}/tests/load/latency-budget-mode.sh && '
                  f'k6_latency_budget_mode chronicle-no-such-{uuid.uuid4().hex}')
        result = subprocess.run(['bash', '-c', script], check=False, capture_output=True, timeout=60)
        self.assertNotEqual(result.returncode, 0)


class SmokeWiringTests(unittest.TestCase):
    def test_the_smoke_passes_the_backend_mode_to_the_k6_job_and_records_it(self):
        text = (ROOT / 'tests/smoke/selfhost-release-smoke.sh').read_text()
        mode = text.index('k6_latency_budget_mode "$(docker compose -p "$PROJECT" ps -q backend)"')
        export = text.index('export K6_LATENCY_BUDGETS="$BENCHMARK_LATENCY_BUDGETS"')
        job = text.index('bash "$ROOT_DIR/scripts/local-ci.sh" k6-benchmarks')
        self.assertLess(mode, export)
        self.assertLess(export, job)
        self.assertIn('echo "k6_latency_budgets=${k6_latency_budgets}"', text)


if __name__ == '__main__':
    unittest.main()
