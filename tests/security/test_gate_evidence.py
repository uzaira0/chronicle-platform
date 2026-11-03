"""Exercise local gate ownership and freshness without invoking a build."""

import contextlib
import json
import os
from pathlib import Path
import runpy
import shutil
import socket
import subprocess
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]


def run_web_bun_audit(directory, audit_json='{}', audit_status=0):
    """Run the gate's web + bun-audit jobs against a stub bun whose audit prints [audit_json] and exits [audit_status]."""
    fixture = Path(directory)
    security = fixture / 'tests/security'
    (security / 'lib').mkdir(parents=True)
    for relative in ('run-all-security.sh', 'security-runner-lib.sh', 'lib/selfhost-python.sh'):
        shutil.copyfile(ROOT / 'tests/security' / relative, security / relative)
    guardrail = security / 'supply-chain-guardrails.sh'
    guardrail.write_text('#!/bin/bash\necho guardrails >>"$SCA_CALLS"\n')
    guardrail.chmod(0o755)
    (fixture / 'chronicle-web').mkdir()
    (fixture / 'chronicle-web/package.json').write_text('{}')
    (fixture / 'audit.json').write_text(audit_json)
    bun = fixture / 'bun'
    bun.write_text('#!/bin/bash\necho "bun $*" >>"$SCA_CALLS"\n[ "$1" = audit ] || { printf "{}\\n"; exit 0; }\n'
                   f'cat "{fixture / "audit.json"}"\nexit {audit_status}\n')
    bun.chmod(0o755)
    script = ('source "$1"\nROOT_DIR="$2"\nWEB_DIR="$2/chronicle-web"\n'
              'ensure_ast_grep() { :; }\nlocal_ci_main web bun-audit\n')
    return subprocess.run(['bash', '-eu', '-s', '--', str(ROOT / 'scripts/local-ci.sh'), directory],
                          input=script, text=True, capture_output=True, timeout=20,
                          env=dict(os.environ, CHRONICLE_LOCAL_BIN_DIR=directory, SCA_CALLS=str(fixture / 'calls.log'),
                                   CHRONICLE_LOCAL_CI_REPORT_DIR=str(fixture / 'reports')))


class GateEvidenceTests(unittest.TestCase):
    def test_bun_audit_fails_on_high_or_critical_only(self):
        # bun 1.3 --json exits 1 for any advisory whatever --audit-level says.
        advisory = '{"minimatch":[{"severity":"%s","url":"https://github.com/advisories/GHSA-g3hv-75wg-m249"}]}'
        for audit_json, audit_status, expected in (
                (advisory % 'info', 1, 0), (advisory % 'low', 1, 0), (advisory % 'moderate', 1, 0),
                (advisory % 'high', 1, 1), (advisory % 'critical', 1, 1), (advisory % 'high', 0, 1),
                ('{}', 0, 0), ('{}', 1, 2), ('{"minimatch":[]}', 0, 0), ('{"minimatch":[]}', 1, 2),
                ('not json', 0, 2), ('[]', 0, 2), ('{"minimatch":null}', 0, 2),
                ('{"minimatch":[null]}', 0, 2), ('{"minimatch":[{}]}', 0, 2),
                ('{"minimatch":[{"severity":"unknown"}]}', 0, 2)):
            with self.subTest(audit_json=audit_json, audit_status=audit_status), \
                    tempfile.TemporaryDirectory() as directory:
                result = run_web_bun_audit(directory, audit_json, audit_status)
                manifest = json.loads((Path(directory) / 'reports/sca/security-manifest-sca.json').read_text())
                audit = next(step for step in manifest['steps'] if step['id'] == 'sca.bun-audit')
                self.assertEqual(expected, audit['exitCode'], result.stdout + result.stderr)
                self.assertEqual(expected == 0, result.returncode == 0, result.stdout + result.stderr)

    def test_web_and_bun_audit_share_one_sca_install_and_audit(self):
        with tempfile.TemporaryDirectory() as directory:
            result = run_web_bun_audit(directory)
            self.assertEqual(0, result.returncode, result.stdout + result.stderr)
            events = (Path(directory) / 'calls.log').read_text().splitlines()
            self.assertIn('bun test --coverage --coverage-reporter=text --coverage-reporter=lcov src/modern scripts', events)
            self.assertIn('bun test src/modern/state/contract-drift.test.ts', events)
            self.assertEqual(['guardrails', 'bun install --frozen-lockfile', 'bun audit --audit-level=high --json'],
                             [event for event in events if event == 'guardrails' or event.startswith(('bun install', 'bun audit'))])

    def test_supply_chain_leaves_gate_evidence_to_engineering(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = Path(directory)
            calls = fixture / 'calls.log'
            python = fixture / 'python3'
            python.write_text('#!/bin/bash\nprintf "%s\\n" "$*" >>"$POLICY_CALLS"\nexec "$POLICY_PYTHON" "$@"\n')
            python.chmod(0o755)
            result = subprocess.run(['bash', str(ROOT / 'tests/security/supply-chain-guardrails.sh'),
                                     str(fixture / 'reports')], text=True, capture_output=True, timeout=30,
                                    env=dict(os.environ, PATH=directory + os.pathsep + os.environ['PATH'],
                                             POLICY_CALLS=str(calls), POLICY_PYTHON=sys.executable))
            self.assertEqual(0, result.returncode, result.stdout + result.stderr)
            events = calls.read_text()
            self.assertIn('test_supply_chain_policy.py', events)
            self.assertNotIn('test_gate_evidence', events)

    def test_every_security_layer_has_a_gate_entry_point(self):
        checker = ROOT / 'tests/security/check-security-layer-coverage.py'
        result = subprocess.run(['python3', '-s', str(checker)], text=True, capture_output=True, timeout=30)
        self.assertEqual(0, result.returncode, result.stderr)

    def assert_layer_coverage(self, runner, ci, smoke, expected):
        result = subprocess.run(['python3', '-s', str(ROOT / 'tests/security/check-security-layer-coverage.py'),
                                 str(runner), str(ci), str(smoke)], text=True, capture_output=True, timeout=30)
        self.assertEqual(expected, result.returncode, result.stderr)
        if expected:
            self.assertIn('unreachable security layers:', result.stderr)

    def test_layer_inventory_rejects_unwired_dead_and_unknown_layers(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = Path(directory)
            runner, ci, smoke = (fixture / name for name in ('runner.sh', 'ci.sh', 'smoke.sh'))
            smoke.write_text('')
            runner.write_text('run_security_layer_first() { :; }\nrun_security_layer_second() { :; }\n')
            for layers, dispatched, grouped, expected in (
                    ('first second', True, True, 0), ('first', True, True, 1),
                    ('first second', False, True, 1), ('first second missing', True, True, 1),
                    ('first second', True, False, 1)):
                with self.subTest(layers=layers, dispatched=dispatched, grouped=grouped):
                    ci.write_text('fast_jobs=()\nsecurity_jobs=()\ncontainers_jobs=(entry)\n'
                                  'run_job() { dispatch_job "$1"; }\n'
                                  'job_empty() { :; }\njob_entry() { run_job '
                                  + ('layer-scan' if grouped else 'empty') + '; }\n'
                                  'job_layers() {\nfor layer in ' + layers + '; do\n'
                                  'bash "$ROOT_DIR/tests/security/run-all-security.sh" "$layer" reports\ndone\n}\n'
                                  'dispatch_job() { case "$1" in\nentry) job_entry ;;\nempty) job_empty ;;\nlayer-scan) '
                                  + ('job_layers' if dispatched else ':') + ' ;;\nesac\n}\n')
                    self.assert_layer_coverage(runner, ci, smoke, expected)

    def test_release_smoke_owns_live_layers_and_rejects_dead_or_unknown_calls(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = Path(directory)
            runner, ci, smoke = (fixture / name for name in ('runner.sh', 'ci.sh', 'smoke.sh'))
            runner.write_text('run_security_layer_upload() { :; }\nrun_security_layer_selfhost_topology() { :; }\n')
            ci.write_text('fast_jobs=()\nsecurity_jobs=()\ncontainers_jobs=()\n'
                          'job_dead() { bash run-all-security.sh upload reports; }\n'
                          'dispatch_job() { case "$1" in\ndead) job_dead ;;\nesac\n}\n')
            for topology, upload, called, expected in (
                    ('selfhost-topology', 'upload', True, 0),
                    ('selfhost-topology', '', True, 1), ('', 'upload', True, 1),
                    ('selfhost-topology', 'upload', False, 1),
                    ('unknown', 'upload', True, 1)):
                with self.subTest(topology=topology, upload=upload, called=called):
                    smoke.write_text('run_live() {\n' + ''.join(
                        'TOPOLOGY_SUBNET=10.253.54.0/24 bash "$ROOT/tests/security/run-all-security.sh" '
                        + layer + ' reports\n' for layer in (topology, upload) if layer)
                        + '}\n' + ('run_live\n' if called else ''))
                    self.assert_layer_coverage(runner, ci, smoke, expected)

    def test_iac_checkov_propagates_failures(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = Path(directory)
            (fixture / 'Dockerfile').touch()
            tool = fixture / 'checkov'
            tool.write_text('#!/bin/bash\nprintf "%s\\n" "$*" >>"$IAC_CALLS"\n'
                            '[[ "$*" != *--soft-fail* ]] || exit 91\n'
                            '[[ "$*" != *dockerfile* ]] || exit "$DOCKERFILE_STATUS"\n')
            tool.chmod(0o755)
            script = ('source "$1"\nROOT_DIR="$2"\n'
                      'deployment_files() { printf "%s\\n" "$ROOT_DIR/Dockerfile"; }\n'
                      'shellcheck() { :; }; conftest() { :; }; docker() { return 91; }\n'
                      'local_ci_main iac-scan\n')
            calls = fixture / 'calls.log'
            for dockerfile in (0, 7):
                for keep_going in ('0', '1'):
                    with self.subTest(dockerfile=dockerfile, keep_going=keep_going):
                        calls.write_text('')
                        result = subprocess.run(['bash', '-eu', '-s', '--', str(ROOT / 'scripts/local-ci.sh'), directory],
                            input=script, text=True, capture_output=True, timeout=10,
                            env=dict(os.environ, CHRONICLE_LOCAL_BIN_DIR=directory, IAC_CALLS=str(calls),
                                     DOCKERFILE_STATUS=str(dockerfile), CHRONICLE_LOCAL_CI_KEEP_GOING=keep_going))
                        # A failed target never passes; the job reports every failed target, then exits 1.
                        self.assertEqual(1 if dockerfile else 0, result.returncode, result.stdout + result.stderr)
                        scans = calls.read_text().splitlines()
                        self.assertIn('--framework dockerfile --quiet --skip-download', scans[1])

    def test_server_secret_exception_allows_only_the_exact_fixture(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "src/test/kotlin/com/openlattice/chronicle/security/MfaSecureDefaultTest.kt"
            source.parent.mkdir(parents=True)
            for prefix, expected in (("", 0), ("unexpected-", 1)):
                source.write_text(f'val jwtSecret = "{prefix}mfa-default-test-signing-secret-0123456789"\n')
                result = subprocess.run(["gitleaks", "dir", ".", "--config", str(ROOT / "chronicle-server/.gitleaks.toml"),
                                         "--no-banner", "--redact"], cwd=root, text=True, capture_output=True, timeout=20)
                self.assertEqual(expected, result.returncode, result.stderr)

    def test_every_gradle_job_gets_a_free_or_explicit_port(self):
        """A fixed default port fails the whole gate when anything else holds it."""
        with tempfile.TemporaryDirectory() as directory, socket.socket() as held:
            with contextlib.suppress(OSError):  # already held by someone else: busy either way
                held.bind(('', 41320))
                held.listen()
            root = Path(directory)
            (root / "gradlew").write_text('#!/bin/sh\n[ "$1" = --no-daemon ] || exit 23\nprintf "%s\\n" "$CHRONICLE_TEST_HTTP_PORT"\n')
            (root / "gradlew").chmod(0o755)
            script = 'source "$1"\nROOT_DIR="$2"\ngradle :chronicle-server:pitest\n'
            for supplied in (None, "41400"):
                environment = dict(os.environ)
                environment.pop("CHRONICLE_TEST_HTTP_PORT", None)
                if supplied:
                    environment["CHRONICLE_TEST_HTTP_PORT"] = supplied
                result = subprocess.run(["bash", "-s", "--", str(ROOT / "scripts/local-ci.sh"), directory],
                                        input=script, env=environment, text=True, capture_output=True, timeout=10)
                self.assertEqual(0, result.returncode, result.stderr)
                if supplied:
                    self.assertEqual(supplied, result.stdout.strip())
                    continue
                with socket.socket() as probe:
                    probe.bind(('', int(result.stdout.strip())))

    def test_auth_freshness_prunes_excluded_and_linked_directories_before_inspection(self):
        checker = runpy.run_path(str(ROOT / "tests/security/lib/auth-test-results.py"))
        with tempfile.TemporaryDirectory(prefix="auth-evidence-", dir=ROOT) as directory:
            fixture = Path(directory)
            server = fixture / "chronicle-server"
            source = server / "src/main/Policy.kt"
            source.parent.mkdir(parents=True)
            source.write_text("fixture policy\n")
            excluded = [server / name for name in checker["NOT_INPUTS"] | {"logging"}]
            for path in excluded:
                (path / "poison").mkdir(parents=True)
            outside = fixture / "outside"
            outside.mkdir()
            linked = server / "linked-cache"
            linked.symlink_to(outside, target_is_directory=True)
            newest = source.stat().st_mtime_ns
            real_stat, real_scandir = Path.stat, os.scandir

            def blocked(path, roots):
                return any(path == root or root in path.parents for root in roots)

            def guarded_stat(path, *args, **kwargs):
                if blocked(path, excluded):
                    raise AssertionError("Excluded input tree was inspected")
                return real_stat(path, *args, **kwargs)

            def guarded_scandir(path):
                if not isinstance(path, int) and blocked(Path(path), excluded + [linked, outside]):
                    raise AssertionError("Excluded or linked input tree was traversed")
                return real_scandir(path)

            with patch.object(Path, "stat", guarded_stat), patch.object(os, "scandir", guarded_scandir):
                self.assertEqual(newest, checker["newest_input"]([server]))
                self.assertEqual(0, checker["newest_input"]([server / "build"]))
                self.assertEqual(0, checker["newest_input"]([linked]))

    def test_auth_freshness_keeps_source_inputs_and_metadata_errors(self):
        checker = runpy.run_path(str(ROOT / "tests/security/lib/auth-test-results.py"))
        with tempfile.TemporaryDirectory(prefix="auth-evidence-", dir=ROOT) as directory:
            fixture = Path(directory)
            server, models = fixture / "chronicle-server", fixture / "chronicle-models"
            inputs = (server / "src/main/Policy.kt", server / "src/main/logging/Policy.kt",
                      server / "build.gradle", server / "gradle.lockfile", models / "src/main/Model.kt")
            prose = server / "POLICY.md"
            for path in inputs + (prose,):
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("fixture\n")
            real_stat = Path.stat
            for selected in inputs:
                with self.subTest(source=selected.relative_to(fixture)):
                    def source_stat(path, *args, **kwargs):
                        actual = real_stat(path, *args, **kwargs)
                        if path in inputs or path == prose:
                            stamp = 999 if path == prose else 200 if path == selected else 100
                            return SimpleNamespace(st_mode=actual.st_mode, st_mtime_ns=stamp)
                        return actual
                    with patch.object(Path, "stat", source_stat):
                        self.assertEqual(200, checker["newest_input"]([server, models]))
                        self.assertEqual(200, checker["newest_input"]([selected]))

            def unreadable_source(path, *args, **kwargs):
                if path == inputs[0]:
                    raise PermissionError("Real source metadata is unavailable")
                return real_stat(path, *args, **kwargs)

            with patch.object(Path, "stat", unreadable_source):
                with self.assertRaisesRegex(PermissionError, "Real source metadata"):
                    checker["newest_input"]([inputs[0]])
            real_scandir = os.scandir

            def unreadable_directory(path):
                if not isinstance(path, int) and Path(path) == server / "src":
                    raise PermissionError("Real source directory is unavailable")
                return real_scandir(path)

            with patch.object(os, "scandir", unreadable_directory):
                with self.assertRaisesRegex(PermissionError, "Real source directory"):
                    checker["newest_input"]([server])
            self.assertEqual(0, checker["newest_input"]([]))
            self.assertEqual(0, checker["newest_input"]([fixture / "missing"]))

    def test_auth_evidence_rejects_missing_and_stale_results(self):
        checker = runpy.run_path(str(ROOT / "tests/security/lib/auth-test-results.py"))
        with tempfile.TemporaryDirectory() as directory:
            server = Path(directory) / "chronicle-server"
            results = server / "build/test-results/test"
            results.mkdir(parents=True)
            source = server / "src/main/Policy.kt"
            build_file, lockfile = server / "build.gradle", server / "gradle.lockfile"
            dependency = Path(directory) / "chronicle-models/src/main/Model.kt"
            source_inputs = (source, build_file, lockfile, dependency, server / "src/main/logging/Policy.kt")
            outputs = (Path(directory) / "chronicle-models/build/libs/models.jar", server / "docs/NOTES.md",
                       server / "logging/chronicleServer.log")
            for path in source_inputs + outputs:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("fixture\n")
            inputs = [server, Path(directory) / "chronicle-models"]
            stamp = source.stat().st_mtime_ns
            for path in source_inputs:
                os.utime(path, ns=(stamp, stamp))
            with self.assertRaisesRegex(ValueError, "rerun jvm-smoke"):
                checker["verify"](results, inputs)
            for name in checker["REQUIRED_CLASSES"]:
                path = results / f"TEST-{name}.xml"
                path.write_text(f'<testsuite name="{name}" tests="1"><testcase name="policy"/></testsuite>')
                os.utime(path, ns=(stamp + 10, stamp + 10))
            # Build outputs, runtime logs and prose cannot change the tests' outcome.
            for path in outputs:
                os.utime(path, ns=(stamp + 20, stamp + 20))
            checker["verify"](results, inputs)
            for changed in source_inputs:
                with self.subTest(changed=changed.name):
                    os.utime(changed, ns=(stamp + 20, stamp + 20))
                    with self.assertRaisesRegex(ValueError, "rerun jvm-smoke"):
                        checker["verify"](results, inputs)
                    os.utime(changed, ns=(stamp, stamp))

    def test_shared_python_runner_isolates_repository_imports(self):
        with tempfile.TemporaryDirectory() as directory:
            environment = dict(os.environ, PYTHONUSERBASE=directory)
            environment.pop("PYTHONNOUSERSITE", None)
            script = ('source "$1"\nROOT_DIR="$2"\nselfhost_python - <<\'PY\'\n'
                      'import site, chronicle_ops, subprocess, sys\nassert not site.ENABLE_USER_SITE\n'
                      'subprocess.run([sys.executable, "-c", "import site; assert not site.ENABLE_USER_SITE"], check=True)\nPY\n')
            result = subprocess.run(["bash", "-eu", "-s", "--", str(ROOT / "tests/security/lib/selfhost-python.sh"), str(ROOT)],
                                    input=script, env=environment, text=True, capture_output=True, timeout=10)
            self.assertEqual(0, result.returncode, result.stderr)


if __name__ == "__main__":
    unittest.main()
