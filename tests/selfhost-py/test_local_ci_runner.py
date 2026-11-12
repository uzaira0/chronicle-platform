"""Exercise the shipped local runner with a synthetic engineering toolchain."""

import json
import os
import subprocess
import sys
from pathlib import Path
import tempfile
import unittest

from chronicle_ops.common import run
from host_tools import modern_bash

ROOT = Path(__file__).resolve().parents[2]
TIMEOUT_RUNNER = ROOT / 'scripts/local-ci-timeout.py'


class LocalCiRunnerTests(unittest.TestCase):
    def fake_toolchain(self, fixture, names):
        calls = fixture / 'calls'
        semgrep_pin = subprocess.run(['yq', '-r', '.semgrep', str(ROOT / 'toolchain-manifest.yaml')],
                                    capture_output=True, text=True, check=True).stdout.strip() if 'semgrep' in names else ''
        ast_grep_pin = subprocess.run(['yq', '-r', '.gate_tools."ast-grep".version', str(ROOT / 'toolchain-manifest.yaml')],
                                    capture_output=True, text=True, check=True).stdout.strip() if 'ast-grep' in names else ''
        for name in names:
            tool = fixture / name
            tool.write_text('''#!/bin/bash
printf '%s %s\\n' "${0##*/}" "$*" >>"$FIXTURE_CALLS"
if [[ "${0##*/}" == semgrep && "${1:-}" == --version ]]; then
  printf '%s\\n' '__SEMGREP_PIN__'
  exit 0
fi
if [[ "${0##*/}" == ast-grep && "${1:-}" == --version ]]; then
  printf 'ast-grep %s\\n' '__AST_GREP_PIN__'
  exit 0
fi
if [[ "${0##*/}" == curl ]]; then
  printf '%s\\n' 'unexpected fixture download' >&2
  exit 91
fi
if [[ "${0##*/}" == python3 && "$*" == *test_caddy_body_limit.py ]]; then
  printf '%s\\n' "$SELFHOST_CADDY_TEST_IMAGE" "$CADDY_BODY_TEST_LOG_DIR" >"$FIXTURE_CADDY_ENV"
  exit "${CADDY_TEST_STATUS:-0}"
fi
'''.replace('__SEMGREP_PIN__', semgrep_pin).replace('__AST_GREP_PIN__', ast_grep_pin))
            tool.chmod(0o755)
        return calls

    def fake_engineering_toolchain(self, fixture):
        calls = self.fake_toolchain(fixture, ('python3', 'ast-grep', 'semgrep', 'bun', 'ruff', 'shellcheck', 'curl'))
        # Replace the external JVM boundary, not the mandatory engineering/Detekt job.
        (fixture / 'detekt-cli-1.23.7-all.jar').touch(mode=0o755)
        settings = fixture / 'detekt-fixture.json'
        settings.write_text('{}')
        java = fixture / 'java'
        java.write_text('#!' + sys.executable + '\n' + '''import json, os, shutil, sys
from pathlib import Path
args = sys.argv[1:]
assert args[:1] == ['-jar'] and Path(args[1]).name == 'detekt-cli-1.23.7-all.jar'
phase = 'fresh' if '--create-baseline' in args else 'filtered' if '--baseline' in args else 'all'
with open(os.environ['FIXTURE_CALLS'], 'a') as handle:
    handle.write('java detekt ' + phase + '\\n')
settings = json.loads(Path(__file__).with_name('detekt-fixture.json').read_text())
status = settings.get(phase, 0)
if status not in (0, 2):
    sys.exit(status)
if phase == 'fresh':
    target = Path(args[args.index('--baseline') + 1])
    source = Path(args[args.index('--config') + 1]).with_name('detekt-baseline.xml')
    shutil.copyfile(source, target)
else:
    for index, argument in enumerate(args[:-1]):
        if argument != '--report':
            continue
        kind, path = args[index + 1].split(':', 1)
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps({'version': '2.1.0', 'runs': [{'results': [], 'properties': {'fixturePhase': phase}}]})
                          if kind == 'sarif' else '<html>synthetic report</html>')
sys.exit(status)
''')
        java.chmod(0o755)
        python = fixture / 'python3'
        python.write_text('#!' + sys.executable + '\n' + '''import json, os, sys
from pathlib import Path
args = sys.argv[1:]
inline = args[:1] == ['-']
with open(os.environ['FIXTURE_CALLS'], 'a') as handle:
    handle.write('python3 - <stale-baseline-comparison>\\n' if inline else 'python3 ' + ' '.join(args) + '\\n')
if args and Path(args[0]).name == 'check-detekt-waiver-source.py':
    assert '--base' not in args
    reports = {label: Path(args[args.index('--' + label + '-sarif') + 1]) for label in ('all', 'filtered')}
    assert reports['all'] != reports['filtered']
    for label, path in reports.items():
        document = json.loads(path.read_text())
        assert document['version'] == '2.1.0'
        assert document['runs'][0]['properties']['fixturePhase'] == label
    Path(__file__).with_name('metadata-evidence.json').write_text(json.dumps({label: str(path) for label, path in reports.items()}))
    settings = json.loads(Path(__file__).with_name('detekt-fixture.json').read_text())
    sys.exit(settings.get('metadata', 0))
if inline:
    # Run the shipped stale-ID comparison against the synthetic scanner's fresh XML.
    executable = __REAL_PYTHON__
    os.execv(executable, [executable, *args])
'''.replace('__REAL_PYTHON__', repr(sys.executable)))
        python.chmod(0o755)
        (fixture / 'tmp').mkdir()
        environment = dict(os.environ, CHRONICLE_LOCAL_BIN_DIR=str(fixture), FIXTURE_CALLS=str(calls),
                           CHRONICLE_LOCAL_CI_REPORT_DIR=str(fixture / 'reports'),
                           CHRONICLE_LOCAL_CI_KEEP_GOING='0', TMPDIR=str(fixture / 'tmp'))
        return calls, environment

    def fake_k6_toolchain(self, fixture):
        calls = fixture / 'calls'
        tool = fixture / 'k6'
        tool.write_text('#!' + sys.executable + '\n' + '''import json, os, sys
from pathlib import Path
args = sys.argv[1:]
with open(os.environ['FIXTURE_CALLS'], 'a') as handle:
    handle.write(json.dumps(args) + '\\n')
assert args[:2] == ['run', '--include-system-env-vars']
assert os.environ['JWT_TOKEN'] == os.environ['AUTH_TOKEN']
assert os.environ['STUDY_ID'] == os.environ['TEST_STUDY_ID']
assert os.environ['PARTICIPANT_ID'] == os.environ['TEST_PARTICIPANT_ID']
failed = Path(__file__).with_name('fail-suite')
sys.exit(7 if failed.is_file() and args[-1] == failed.read_text() else 0)
''')
        tool.chmod(0o755)
        environment = dict(os.environ, CHRONICLE_LOCAL_BIN_DIR=str(fixture), FIXTURE_CALLS=str(calls),
                           BASE_URL='http://fixture.invalid', AUTH_TOKEN='synthetic-token',
                           TEST_STUDY_ID='synthetic-study', TEST_PARTICIPANT_ID='synthetic-participant',
                           TEST_RANDOM_DEVICE_ID='synthetic-device', API_KEY='synthetic-key',
                           DEVICE_FIXTURES_FILE=str(fixture / 'enrolled.json'))
        suites = [*(ROOT / 'tests/load').glob('chronicle-load-test.js'), *sorted((ROOT / 'tests/load').glob('k6-*.js'))]
        return calls, environment, suites

    def test_k6_requires_single_device_credentials_before_starting_any_suite(self):
        required = ('BASE_URL', 'AUTH_TOKEN', 'TEST_STUDY_ID', 'TEST_PARTICIPANT_ID',
                    'TEST_RANDOM_DEVICE_ID', 'API_KEY', 'DEVICE_FIXTURES_FILE')
        with tempfile.TemporaryDirectory() as folder:
            calls, environment, suites = self.fake_k6_toolchain(Path(folder))
            self.assertTrue(suites)
            for keep_going in ('0', '1'):
                for missing in (*required, None):
                    with self.subTest(keep_going=keep_going, missing=missing):
                        calls.write_text('')
                        current = dict(environment, CHRONICLE_LOCAL_CI_KEEP_GOING=keep_going)
                        if missing:
                            current.pop(missing)
                        result = run([modern_bash(), str(ROOT / 'scripts/local-ci.sh'), 'k6-benchmarks'],
                                     env=current, capture=True, stderr=subprocess.PIPE, timeout=10)
                        if missing:
                            self.assertNotEqual(0, result.returncode, result.stderr)
                            self.assertEqual('', calls.read_text())
                        else:
                            self.assertEqual(0, result.returncode, result.stderr)
                            recorded = [json.loads(line) for line in calls.read_text().splitlines()]
                            self.assertEqual(suites, [Path(args[-1]) for args in recorded])

    def test_k6_failure_fails_the_job_after_every_suite_has_run(self):
        """A failing script fails the job and is named, and the scripts after it still run. The job
        stopped at the first failure until fc0f9010, so four scripts had never run in the release
        smoke; this test still held it to stopping, with k6's own exit status."""
        with tempfile.TemporaryDirectory() as folder:
            fixture = Path(folder)
            calls, environment, suites = self.fake_k6_toolchain(fixture)
            self.assertGreater(len(suites), 2)
            failed = suites[1]
            (fixture / 'fail-suite').write_text(str(failed))
            for keep_going in ('0', '1'):
                with self.subTest(keep_going=keep_going):
                    calls.write_text('')
                    result = run([modern_bash(), str(ROOT / 'scripts/local-ci.sh'), 'k6-benchmarks'],
                                 env=dict(environment, CHRONICLE_LOCAL_CI_KEEP_GOING=keep_going),
                                 capture=True, stderr=subprocess.PIPE, timeout=10)
                    self.assertEqual(1, result.returncode, result.stdout + result.stderr)
                    self.assertIn('k6 benchmarks failed: ' + failed.name, result.stdout + result.stderr)
                    recorded = [json.loads(line) for line in calls.read_text().splitlines()]
                    self.assertEqual(suites, [Path(args[-1]) for args in recorded])

    def test_fuzz_job_executes_every_bounded_target_and_fails_when_it_finds_none(self):
        import shutil
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            for name in ('scripts/local-ci.sh', 'tests/security/lib/selfhost-python.sh'):
                (root / name).parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(ROOT / name, root / name)
            calls = root / 'calls'
            (root / 'gradlew').write_text('#!/bin/bash\nprintf \'%s %s\\n\' "$JAZZER_FUZZ" "$*" >>"$FIXTURE_CALLS"\n')
            (root / 'jdk/bin').mkdir(parents=True)
            (root / 'jdk/bin/java').write_text('#!/bin/sh\necho \'openjdk version "21.0.5"\' >&2\n')
            for tool in (root / 'gradlew', root / 'jdk/bin/java'):
                tool.chmod(0o755)
            sources = root / 'chronicle-server/src/test/kotlin/fixture'
            sources.mkdir(parents=True)
            environment = dict(os.environ, JAVA_HOME=str(root / 'jdk'), FIXTURE_CALLS=str(calls))
            empty = run(['bash', str(root / 'scripts/local-ci.sh'), 'fuzz'], env=environment,
                        capture=True, stderr=subprocess.PIPE, timeout=30)
            self.assertNotEqual(0, empty.returncode)
            self.assertIn('no bounded fuzz targets found', empty.stdout + empty.stderr)
            self.assertFalse(calls.exists())
            (sources / 'ParserFuzzTest.kt').write_text(
                'package fixture\n\nclass ParserFuzzTest {\n    @FuzzTest(maxDuration = "30s")\n    fun parses(data: FuzzedDataProvider) {}\n\n'
                '    @FuzzTest(maxDuration = "1m")\n    fun rejects(data: FuzzedDataProvider) {}\n}\n')
            result = run(['bash', str(root / 'scripts/local-ci.sh'), 'fuzz'], env=environment,
                         capture=True, stderr=subprocess.PIPE, timeout=30)
            self.assertEqual(0, result.returncode, result.stdout + result.stderr)
            # One fuzzing invocation per target: JAZZER_FUZZ=1 and that target's --tests filter.
            lines = calls.read_text().splitlines()
            self.assertEqual(2, len(lines))
            for line, method in zip(lines, ('parses', 'rejects')):
                self.assertTrue(line.startswith('1 '), line)
                self.assertIn(f' --tests fixture.ParserFuzzTest.{method} ', line + ' ')
            # The shipped tree has targets, and the job runs each of them.
            calls.unlink()
            shutil.rmtree(root / 'chronicle-server/src/test')
            (root / 'chronicle-server/src/test').symlink_to(ROOT / 'chronicle-server/src/test')
            shipped = sum(path.read_text().count('@FuzzTest') for path in (ROOT / 'chronicle-server/src/test').rglob('*FuzzTest.kt'))
            result = run(['bash', str(root / 'scripts/local-ci.sh'), 'fuzz'], env=environment,
                         capture=True, stderr=subprocess.PIPE, timeout=60)
            self.assertEqual(0, result.returncode, result.stdout + result.stderr)
            self.assertGreater(shipped, 0)
            self.assertEqual(shipped, len(calls.read_text().splitlines()))

    def test_jvm_smoke_executes_documentation_archive_and_propagates_failure(self):
        import shutil
        with tempfile.TemporaryDirectory() as folder:
            fixture = Path(folder)
            for name in ('scripts/local-ci.sh', 'tests/security/lib/selfhost-python.sh'):
                target = fixture / name
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(ROOT / name, target)
            calls = fixture / 'gradle-calls.jsonl'
            wrapper = fixture / 'gradlew'
            wrapper.write_text('#!' + sys.executable + '\n' + """import json, os, sys
with open(os.environ['FIXTURE_CALLS'], 'a') as handle:
    handle.write(json.dumps(sys.argv[1:]) + '\\n')
sys.exit(int(os.environ['DOCS_FIXTURE_STATUS']) if ':rhizome:javadocJar' in sys.argv else 0)
""")
            java = fixture / 'jdk/bin/java'
            java.parent.mkdir(parents=True)
            java.write_text('#!/bin/sh\nprintf \'%s\\n\' \'openjdk version "25.0.5"\' >&2\n')
            for executable in (wrapper, java):
                executable.chmod(0o755)
            environment = dict(os.environ, JAVA_HOME=str(fixture / 'jdk'), FIXTURE_CALLS=str(calls),
                               DOCKER_HOST='unix:///fixture-engine.sock', CHRONICLE_TEST_HTTP_PORT='12345',
                               CHRONICLE_LOCAL_CI_KEEP_GOING='0')
            for status in (0, 73):
                with self.subTest(documentation_exit=status):
                    calls.write_text('')
                    result = run([modern_bash(), str(fixture / 'scripts/local-ci.sh'), 'jvm-smoke'],
                                 env=dict(environment, DOCS_FIXTURE_STATUS=str(status)),
                                 capture=True, stderr=subprocess.PIPE, timeout=15)
                    recorded = [json.loads(line) for line in calls.read_text().splitlines()]
                    documentation = [args for args in recorded if ':rhizome:javadocJar' in args]
                    self.assertEqual([['--no-daemon', ':rhizome:javadocJar', '--build-cache']], documentation)
                    self.assertEqual(status, result.returncode, result.stdout + result.stderr)
                    if status:
                        self.assertEqual(documentation[0], recorded[-1])
                    else:
                        self.assertIn(['--no-daemon', ':chronicle-server:pitest'], recorded)

    def test_tool_installer_leaves_stdout_to_the_caller(self):
        # Callers capture `ensure_<tool>; command -v <tool>` and scripts such as write-image-sboms.sh promise
        # their own stdout, so a first install must report checksum verification on stderr only.
        import hashlib
        import json
        import tarfile
        with tempfile.TemporaryDirectory() as folder:
            fixture = Path(folder)
            fake_bin, tools = fixture / 'fake-bin', fixture / 'tools'
            fake_bin.mkdir()
            payload = fixture / 'syft'
            payload.write_text('#!/bin/sh\nexit 0\n')
            payload.chmod(0o755)
            archive = fixture / 'syft.tar.gz'
            with tarfile.open(archive, 'w:gz') as bundle:
                bundle.add(payload, arcname='syft')
            digest = hashlib.sha256(archive.read_bytes()).hexdigest()
            version = subprocess.run(['yq', '-r', '.gate_tools.syft.version', str(ROOT / 'toolchain-manifest.yaml')],
                                     capture_output=True, text=True, check=True).stdout.strip()
            (fixture / 'toolchain-manifest.yaml').write_text(json.dumps({'gate_tools': {'syft': {
                'version': version, 'sha256': {platform: digest for platform in
                    ('darwin-amd64', 'darwin-arm64', 'linux-amd64', 'linux-arm64')},
            }}}))
            curl = fake_bin / 'curl'
            curl.write_text('#!/usr/bin/env bash\nwhile [[ $# -gt 0 ]]; do\n'
                            '  case "$1" in -o) output=$2 ;; https://*) url=$1 ;; esac\n  shift\ndone\n'
                            'case "$url" in *checksums.txt) printf "%s  %s\\n" "$FIXTURE_SHA" "$(cat "$FIXTURE_ASSET_NAME")" > "$output" ;;\n'
                            '  *) printf "%s" "${url##*/}" > "$FIXTURE_ASSET_NAME"; cp "$FIXTURE_ARCHIVE" "$output" ;; esac\n')
            curl.chmod(0o755)
            result = run([modern_bash(), '-c', 'source "$1"; ROOT_DIR="$2"; ensure_syft; command -v syft', 'fixture',
                          str(ROOT / 'scripts/local-ci.sh'), str(fixture)],
                         env=dict(os.environ, CHRONICLE_LOCAL_BIN_DIR=str(tools), FIXTURE_ARCHIVE=str(archive),
                                  FIXTURE_SHA=digest, FIXTURE_ASSET_NAME=str(fixture / 'asset-name'),
                                  PATH=f'{fake_bin}{os.pathsep}{os.environ["PATH"]}'),
                         capture=True, stderr=subprocess.PIPE, timeout=30)
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertEqual(f'{tools / "syft"}\n', result.stdout)
            self.assertIn('OK', result.stderr)

    def test_operation_writer_jobs_require_flock_before_running_anything(self):
        # selfhost-monitoring.py and the selfhost-py suite run the shipped flock writers on this host.
        bash = modern_bash()
        with tempfile.TemporaryDirectory() as folder:
            fixture = Path(folder)
            calls = self.fake_toolchain(fixture, ('python3', 'docker', 'uvx'))
            system = fixture / 'system-without-flock'
            system.mkdir()
            for directory in ('/usr/bin', '/bin'):
                for tool in Path(directory).iterdir():
                    target = system / tool.name
                    if tool.name != 'flock' and not target.exists() and not target.is_symlink():
                        target.symlink_to(tool)
            for job in ('architecture', 'selfhost'):
                with self.subTest(job=job):
                    calls.write_text('')
                    result = run([bash, str(ROOT / 'scripts/local-ci.sh'), job],
                                 env=dict(os.environ, CHRONICLE_LOCAL_BIN_DIR=str(fixture), FIXTURE_CALLS=str(calls),
                                          DOCKER_HOST='unix:///fixture-engine.sock', PATH=str(system)),
                                 capture=True, stderr=subprocess.PIPE, timeout=30)
                    self.assertNotEqual(0, result.returncode)
                    self.assertIn('missing required command: flock', result.stderr)
                    self.assertEqual('', calls.read_text())

    def test_selfhost_job_fails_when_the_nested_selfhost_python_suite_fails(self):
        # job_selfhost calls `run_job selfhost-python || return $?`; errexit is off there, so run_job must return the status.
        import shutil
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            for name in ('scripts/local-ci.sh', 'tests/security/lib/selfhost-python.sh'):
                (root / name).parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(ROOT / name, root / name)
            fixture = root / 'bin'
            fixture.mkdir()
            calls = self.fake_toolchain(fixture, ('python3', 'docker', 'flock'))
            (fixture / 'uvx').write_text('#!/bin/bash\nprintf \'uvx %s\\n\' "$*" >>"$FIXTURE_CALLS"\n'
                                         '[[ "$*" != *"coverage run"* ]] || exit 5\n')
            (fixture / 'uvx').chmod(0o755)
            for keep_going in ('0', '1'):
                with self.subTest(keep_going=keep_going):
                    calls.write_text('')
                    result = run([modern_bash(), str(root / 'scripts/local-ci.sh'), 'selfhost'],
                                 env=dict(os.environ, CHRONICLE_LOCAL_BIN_DIR=str(fixture), FIXTURE_CALLS=str(calls),
                                          DOCKER_HOST='unix:///fixture-engine.sock', CHRONICLE_LOCAL_CI_KEEP_GOING=keep_going),
                                 capture=True, stderr=subprocess.PIPE, timeout=30)
                    self.assertEqual(1 if keep_going == '1' else 5, result.returncode, result.stdout + result.stderr)
                    self.assertIn('coverage run', calls.read_text().splitlines()[-1])

    def test_gitleaks_refuses_a_repository_that_is_not_its_own_checkout(self):
        # An uninitialized submodule is an empty directory: git walks up to the root repository,
        # so a scan there reads the root history with the submodule's ignore file.
        import shutil
        repos = ('chronicle', 'chronicle-api', 'chronicle-ios', 'chronicle-models', 'chronicle-server',
                 'chronicle-web', 'rhizome', 'rhizome-client')
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder).resolve()
            for name in ('scripts/local-ci.sh', 'tests/security/lib/selfhost-python.sh'):
                (root / name).parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(ROOT / name, root / name)
            fixture = root / 'bin'
            fixture.mkdir()
            calls = fixture / 'calls'
            (fixture / 'gitleaks').write_text('#!/bin/bash\nprintf \'%s\\n\' "$(pwd -P)" >>"$FIXTURE_CALLS"\n')
            (fixture / 'gitleaks').chmod(0o755)
            run(['git', 'init', '--quiet', str(root)], capture=True, timeout=10)
            for repo in repos:
                (root / repo).mkdir()
                if repo not in ('chronicle-ios', 'chronicle-api'):
                    run(['git', 'init', '--quiet', str(root / repo)], capture=True, timeout=10)
            (root / '.gitmodules').write_text('[submodule \"chronicle-ios\"]\n\tupdate = none\n')
            environment = dict(os.environ, CHRONICLE_LOCAL_BIN_DIR=str(fixture), FIXTURE_CALLS=str(calls))
            calls.write_text('')
            result = run(['bash', str(root / 'scripts/local-ci.sh'), 'gitleaks'], env=environment,
                         capture=True, stderr=subprocess.PIPE, timeout=30)
            self.assertNotEqual(0, result.returncode, result.stdout + result.stderr)
            self.assertIn('chronicle-api is not a git checkout', result.stdout + result.stderr)
            self.assertIn('gitleaks could not scan: chronicle-api', result.stderr)
            self.assertNotIn('found leaks', result.stderr)
            scanned = calls.read_text().splitlines()
            self.assertNotIn(str(root / 'chronicle-ios'), scanned)
            self.assertEqual(7, len(scanned))
            run(['git', 'init', '--quiet', str(root / 'chronicle-api')], capture=True, timeout=10)
            calls.write_text('')
            result = run(['bash', str(root / 'scripts/local-ci.sh'), 'gitleaks'], env=environment,
                         capture=True, stderr=subprocess.PIPE, timeout=30)
            self.assertEqual(0, result.returncode, result.stdout + result.stderr)
            self.assertEqual(sorted([str(root)] + [str(root / repo) for repo in repos if repo != 'chronicle-ios']),
                             sorted(calls.read_text().splitlines()))

    def test_help_lists_every_fast_group_member(self):
        result = run(['bash', str(ROOT / 'scripts/local-ci.sh'), '--help'],
                     capture=True, stderr=subprocess.PIPE, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        group = next(line.split() for line in result.stdout.splitlines() if line.startswith('  fast '))
        self.assertIn('architecture', group)
        self.assertIn('web-a11y', group)

    def test_local_ci_runs_a_repeated_job_once_including_keep_going(self):
        with tempfile.TemporaryDirectory() as folder:
            fixture = Path(folder)
            calls, environment = self.fake_engineering_toolchain(fixture)
            for keep_going in ('0', '1'):
                with self.subTest(keep_going=keep_going):
                    calls.write_text('')
                    result = run(['bash', str(ROOT / 'scripts/local-ci.sh'), 'engineering', 'engineering'],
                        env=dict(environment, CHRONICLE_LOCAL_CI_KEEP_GOING=keep_going),
                        capture=True, stderr=subprocess.PIPE, timeout=10)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    recorded = calls.read_text().splitlines()
                    self.assertTrue(recorded)
                    self.assertEqual(['java detekt filtered', 'java detekt all', 'java detekt fresh'],
                                     [line for line in recorded if line.startswith('java ')])
                    version_check = recorded.index('ast-grep --version')
                    metadata_check = next(index for index, line in enumerate(recorded) if 'check-detekt-waiver-source.py' in line)
                    self.assertLess(version_check, recorded.index('java detekt filtered'))
                    self.assertLess(version_check, metadata_check)
                    self.assertFalse(any(line.startswith('curl ') for line in recorded), recorded)
                    self.assertTrue((fixture / 'metadata-evidence.json').is_file())
                    calls.write_text('')
                    once = run(['bash', str(ROOT / 'scripts/local-ci.sh'), 'engineering'],
                        env=dict(environment, CHRONICLE_LOCAL_CI_KEEP_GOING=keep_going),
                        capture=True, stderr=subprocess.PIPE, timeout=10)
                    self.assertEqual(0, once.returncode, once.stderr)
                    self.assertEqual(calls.read_text().splitlines(), recorded)

    def test_detekt_reports_findings_and_scanner_errors_without_masking_them(self):
        cases = (({}, 0, ['filtered', 'all', 'fresh']),
                 ({'filtered': 2, 'all': 2}, 2, ['filtered', 'all', 'fresh']),
                 ({'all': 2}, 0, ['filtered', 'all', 'fresh']),
                 ({'filtered': 3}, 3, ['filtered']),
                 ({'all': 3}, 3, ['filtered', 'all']),
                 ({'metadata': 7}, 1, ['filtered', 'all', 'fresh']),
                 ({'fresh': 3}, 1, ['filtered', 'all', 'fresh']))
        with tempfile.TemporaryDirectory() as folder:
            fixture = Path(folder)
            calls, environment = self.fake_engineering_toolchain(fixture)
            for settings, status, phases in cases:
                with self.subTest(settings=settings):
                    (fixture / 'detekt-fixture.json').write_text(json.dumps(settings))
                    calls.write_text('')
                    result = run(['bash', str(ROOT / 'scripts/local-ci.sh'), 'detekt'], env=environment,
                                 capture=True, stderr=subprocess.PIPE, timeout=10)
                    self.assertEqual(status, result.returncode, result.stdout + result.stderr)
                    recorded = calls.read_text().splitlines()
                    self.assertEqual(['java detekt ' + phase for phase in phases],
                                     [line for line in recorded if line.startswith('java ')])
                    self.assertEqual('fresh' in phases, any('check-detekt-waiver-source.py' in line for line in recorded))

    def test_repo_automation_reuses_architecture_within_each_process(self):
        with tempfile.TemporaryDirectory() as folder:
            fixture = Path(folder)
            calls = self.fake_toolchain(fixture, ('python3', 'uvx', 'flock', 'bash'))
            for keep_going in ('0', '1'):
                for jobs in (('architecture', 'repo-automation'), ('repo-automation',)):
                    with self.subTest(keep_going=keep_going, jobs=jobs):
                        calls.write_text('')
                        result = run([modern_bash(), str(ROOT / 'scripts/local-ci.sh'), *jobs],
                                     env=dict(os.environ, CHRONICLE_LOCAL_BIN_DIR=str(fixture), FIXTURE_CALLS=str(calls),
                                              CHRONICLE_LOCAL_CI_KEEP_GOING=keep_going),
                                     capture=True, stderr=subprocess.PIPE, timeout=10)
                        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
                        recorded = calls.read_text().splitlines()
                        self.assertEqual(1, sum(line.endswith('/check-architecture-boundaries.py --self-test')
                                                for line in recorded), recorded)
                        self.assertEqual(1, sum(line.endswith('/verify-toolchain.sh') for line in recorded), recorded)

    def test_repo_automation_propagates_nested_architecture_failure(self):
        with tempfile.TemporaryDirectory() as folder:
            fixture = Path(folder)
            calls = self.fake_toolchain(fixture, ('python3', 'uvx', 'flock', 'bash'))
            python = fixture / 'python3'
            python.write_text(python.read_text() +
                              '\nif [[ "$*" == *check-architecture-boundaries.py* && "$*" == *--self-test* ]]; then exit 9; fi\n')
            for keep_going in ('0', '1'):
                with self.subTest(keep_going=keep_going):
                    calls.write_text('')
                    result = run([modern_bash(), str(ROOT / 'scripts/local-ci.sh'), 'repo-automation'],
                                 env=dict(os.environ, CHRONICLE_LOCAL_BIN_DIR=str(fixture), FIXTURE_CALLS=str(calls),
                                          CHRONICLE_LOCAL_CI_KEEP_GOING=keep_going),
                                 capture=True, stderr=subprocess.PIPE, timeout=10)
                    self.assertEqual(1 if keep_going == '1' else 9, result.returncode, result.stdout + result.stderr)
                    recorded = calls.read_text().splitlines()
                    self.assertEqual(1, len(recorded), recorded)
                    self.assertTrue(recorded[0].endswith('/check-architecture-boundaries.py --self-test'), recorded)

    def test_container_structure_runs_caddy_behavior_and_propagates_failure(self):
        with tempfile.TemporaryDirectory() as folder:
            fixture = Path(folder)
            calls = self.fake_toolchain(fixture, ('docker', 'container-structure-test', 'python3'))
            evidence = fixture / 'caddy-env'
            reports = fixture / 'reports'
            for status in (0, 7):
                for keep_going in ('0', '1'):
                    with self.subTest(status=status, keep_going=keep_going):
                        calls.write_text('')
                        result = run(['bash', str(ROOT / 'scripts/local-ci.sh'), 'container-structure'],
                            env=dict(os.environ, CHRONICLE_LOCAL_BIN_DIR=str(fixture), FIXTURE_CALLS=str(calls),
                                     FIXTURE_CADDY_ENV=str(evidence), CADDY_TEST_STATUS=str(status),
                                     CHRONICLE_LOCAL_CI_REPORT_DIR=str(reports),
                                     CHRONICLE_LOCAL_CI_KEEP_GOING=keep_going),
                            capture=True, stderr=subprocess.PIPE, timeout=10)
                        self.assertEqual(result.returncode, (1 if keep_going == '1' else status) if status else 0,
                                         result.stderr)
                        commands = calls.read_text().splitlines()
                        build = (f'docker build -f {ROOT / "selfhost/Dockerfile.caddy"} --build-context '
                                 f'chronicle-selfhost-frontend:release=docker-image://chronicle-selfhost-frontend:test -t chronicle-selfhost-caddy:test {ROOT}')
                        index = commands.index(build)
                        self.assertEqual(commands[index + 1],
                                         f'python3 -s {ROOT / "tests/deployment/test_caddy_body_limit.py"}')
                        self.assertEqual(evidence.read_text().splitlines(),
                                         ['chronicle-selfhost-caddy:test', str(reports / 'caddy-body-limit')])
                        if status:
                            self.assertEqual(commands[-1], commands[index + 1])
                        else:
                            tagged = next(line for line in commands if line.startswith('docker tag chronicle-selfhost-backup:test '))
                            self.assertIn(f'container-structure-test test --save --image {tagged.split()[-1]} '
                                          f'--config {ROOT / "tests/container/selfhost-backup.yaml"}', commands)

    def structure_test_fixture(self, fixture):
        """A Docker that lists three containers for any ancestor filter: two made from the tag asked
        for and one made from another tag of the same image (another checkout's run of the job).
        container-structure-test exits STRUCTURE_TEST_STATUS for the image named in STRUCTURE_TEST_FAILS."""
        calls = self.fake_toolchain(fixture, ('docker', 'container-structure-test', 'python3'))
        docker = fixture / 'docker'
        docker.write_text(docker.read_text() + '''
if [[ "${1:-}" == ps ]]; then
  for argument in "$@"; do
    [[ "$argument" != ancestor=* ]] || tag="${argument#ancestor=}"
  done
  printf '%s\\n' "aaaa $tag" "bbbb chronicle-selfhost-backup:test" "cccc $tag"
fi
''')
        tool = fixture / 'container-structure-test'
        tool.write_text(tool.read_text() + '''
tag="$(awk -v image="$STRUCTURE_TEST_FAILS" '$1 == "docker" && $2 == "tag" && $3 == image { tag = $4 } END { print tag }' "$FIXTURE_CALLS")"
if [[ -n "$tag" && " $* " == *" --image $tag "* ]]; then exit "${STRUCTURE_TEST_STATUS:-0}"; fi
''')
        return calls

    def test_structure_tests_remove_their_containers_with_the_anonymous_volumes(self):
        """container-structure-test removes its containers and leaves their anonymous volumes: one run
        of container-structure left 56 on chronicle-selfhost-backup:test (8 test containers, 7 VOLUME
        paths; 2026-11-11). The job keeps the containers (--save) under a tag only that call has and
        removes exactly those with their volumes, also when a structure test fails."""
        with tempfile.TemporaryDirectory() as folder:
            fixture = Path(folder)
            calls = self.structure_test_fixture(fixture)
            images =('chronicle-backend:test', 'chronicle-selfhost-frontend:test', 'chronicle-selfhost-caddy:test',
                      'chronicle-selfhost-backup:test')
            for failing, status in (('', 0), ('chronicle-selfhost-backup:test', 5), ('chronicle-backend:test', 5)):
                with self.subTest(failing=failing):
                    calls.write_text('')
                    result = run(['bash', str(ROOT / 'scripts/local-ci.sh'), 'container-structure'],
                                 env=dict(os.environ, CHRONICLE_LOCAL_BIN_DIR=str(fixture), FIXTURE_CALLS=str(calls),
                                          FIXTURE_CADDY_ENV=str(fixture / 'caddy-env'),
                                          CHRONICLE_LOCAL_CI_REPORT_DIR=str(fixture / 'reports'),
                                          STRUCTURE_TEST_FAILS=failing, STRUCTURE_TEST_STATUS=str(status)),
                                 capture=True, stderr=subprocess.PIPE, timeout=10)
                    self.assertEqual(status, result.returncode, result.stderr)
                    commands = calls.read_text().splitlines()
                    tested = images[:images.index(failing) + 1] if failing else images
                    self.assertEqual([line.split()[2] for line in commands if line.startswith('docker tag ')], list(tested))
                    for image in tested:
                        start = next(index for index, line in enumerate(commands) if line.startswith(f'docker tag {image} '))
                        tag = commands[start].split()[-1]
                        self.assertRegex(tag, r'^chronicle-structure-test:[0-9]+-[0-9]+-[0-9]+$')
                        config = 'backend' if image == 'chronicle-backend:test' else image.split(':')[0].removeprefix('chronicle-')
                        self.assertEqual(commands[start + 1:start + 5], [
                            f'container-structure-test test --save --image {tag} --config {ROOT / "tests/container"}/{config}.yaml',
                            f'docker ps -a --no-trunc --filter ancestor={tag} --format {{{{.ID}}}} {{{{.Image}}}}',
                            'docker rm --force --volumes aaaa cccc',
                            f'docker image rm {tag}'])
                    self.assertFalse([line for line in commands if 'bbbb' in line], commands)
        self.assertEqual(1, (ROOT / 'scripts/local-ci.sh').read_text().count('container-structure-test test '),
                         'every structure test goes through structure_test, which removes the containers and volumes')

    def test_image_gate_structure_test_passes_its_platform_and_removes_the_same_way(self):
        """image-gate tests the linux/amd64 release images through the same function."""
        with tempfile.TemporaryDirectory() as folder:
            fixture = Path(folder)
            calls = self.structure_test_fixture(fixture)
            for failing, status in (('', 0), ('chronicle-image-gate-backup:fixture', 5)):
                with self.subTest(failing=failing):
                    calls.write_text('')
                    result = run(['bash', '-c', 'source "$1"; shift; structure_test "$@"', 'gate', str(ROOT / 'scripts/local-ci.sh'),
                                  'chronicle-image-gate-backup:fixture', 'backup.yaml', '--platform', 'linux/amd64'],
                                 env=dict(os.environ, CHRONICLE_LOCAL_BIN_DIR=str(fixture), FIXTURE_CALLS=str(calls),
                                          STRUCTURE_TEST_FAILS=failing, STRUCTURE_TEST_STATUS=str(status)),
                                 capture=True, stderr=subprocess.PIPE, timeout=10)
                    self.assertEqual(status, result.returncode, result.stderr)
                    commands = calls.read_text().splitlines()
                    tag = commands[0].split()[-1]
                    self.assertEqual(commands, [
                        f'docker tag chronicle-image-gate-backup:fixture {tag}',
                        f'container-structure-test test --save --platform linux/amd64 --image {tag} --config backup.yaml',
                        f'docker ps -a --no-trunc --filter ancestor={tag} --format {{{{.ID}}}} {{{{.Image}}}}',
                        'docker rm --force --volumes aaaa cccc',
                        f'docker image rm {tag}'])
        self.assertIn('structure_test "$tag" "$config" --platform linux/amd64 || image_failed=1',
                      (ROOT / 'scripts/local-ci.sh').read_text())

    def test_timeout_runner_rejects_non_finite_and_missing_commands(self):
        with tempfile.TemporaryDirectory() as folder:
            log = Path(folder) / 'output.log'
            for seconds in ('nan', 'inf', '-1', '1'):
                with self.subTest(seconds=seconds):
                    result = run([sys.executable, str(TIMEOUT_RUNNER), seconds, str(log)],
                                 capture=True, stderr=subprocess.PIPE, timeout=5)
                    self.assertEqual(result.returncode, 2)
                    self.assertFalse(log.exists())

    def test_timeout_runner_redacts_streams_and_preserves_failure(self):
        with tempfile.TemporaryDirectory() as folder:
            log = Path(folder) / 'output.log'
            runner = TIMEOUT_RUNNER
            result = run([sys.executable, str(runner), '0', str(log)], input='apiKey=synthetic-private-key\n',
                         capture=True, stderr=subprocess.PIPE, timeout=5)
            self.assertEqual(result.returncode, 0)
            self.assertEqual(result.stdout, 'apiKey=[redacted]\n')
            self.assertEqual(log.read_text(), result.stdout)
            result = run([sys.executable, str(runner), '5', str(log), sys.executable, '-c',
                          'import sys; print("failure"); sys.exit(7)'],
                         capture=True, stderr=subprocess.PIPE, timeout=10)
            self.assertEqual(result.returncode, 7)
            self.assertEqual(result.stdout, 'failure\n')
            result = run([sys.executable, str(runner), '0.1', str(log), sys.executable, '-c',
                          'import time; time.sleep(10)'], capture=True, stderr=subprocess.PIPE, timeout=5)
            self.assertEqual(result.returncode, 124)
            self.assertIn('command timed out', result.stderr)
