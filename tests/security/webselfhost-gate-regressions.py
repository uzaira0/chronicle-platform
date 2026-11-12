#!/usr/bin/env python3
"""Offline gate regressions with synthetic CLI responses only."""
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest
import yaml

ROOT = Path(__file__).resolve().parents[2]
RUNS = Path(os.environ.get('TMPDIR', ROOT / 'build/operator-test-runs/webselfhost-gates'))
RUNS.mkdir(parents=True, exist_ok=True)
os.environ['TMPDIR'] = str(RUNS)
tempfile.tempdir = str(RUNS)

def function(path, name):
    source = (ROOT / path).read_text()
    match = re.search(r'^' + name + r'\(\) \{.*?^\}', source, re.M | re.S)
    if not match:
        raise AssertionError('missing function ' + name)
    return match.group()

class GateRegressions(unittest.TestCase):
    def test_W64_only_audited_fixture_fingerprints_are_baselined(self):
        approved={
            'chronicle-web': [f'7ceef73c4d9c24ff985e59645d94e0e992222a61:src/modern/generated/chronicle-payload-contracts.generated.ts:generic-api-key:{line}' for line in (1031,1041,1051)],
            'chronicle-platform-root': [f'{commit}:tests/security/selfhost-deletion-status.sh:generic-api-key:{line}'
                for commit,lines in [('1837e1075e90470a5e8fd0bb2643a96312918ee2',(49,50,55)),('53fd926e60a7b6343d64bc8a91a6d3b3cfe9f051',(47,48,53)),('42f716cd59dda05f05f1372fb2ca24dc734acd14',(47,48,53))] for line in lines],
            'chronicle': ['167ff8340f8e4d0ccd3a34d1157fca2ed81fde55:app/src/test/java/com/openlattice/chronicle/collection/upload/UploadTelemetryRedactionTest.kt:generic-api-key:29']+
                [f'{commit}:collection-base/src/androidTest/java/com/openlattice/chronicle/storage/EnrollmentReplayDaoTest.kt:generic-api-key:{line}' for commit in ('167ff8340f8e4d0ccd3a34d1157fca2ed81fde55','ce2e9f5a90e4502d99fb93df7e88e717ba6d19d8','f2658a1ce187803d1ddf0aa8fdcc9fcb20bff461') for line in (124,227)],
        }
        combined=[]
        for name,rows in approved.items():
            contents=(ROOT/f'tests/security/gitleaks-ignore/{name}.gitleaksignore').read_text()
            entries={line.strip() for line in contents.splitlines() if line.strip() and not line.startswith('#')}
            self.assertTrue(set(rows).issubset(entries),name)
            combined.extend(entries)
        with tempfile.TemporaryDirectory() as d:
            import secrets
            fixture=Path(d)/'fresh.txt';fixture.write_text('api_key = "'+secrets.token_hex(32)+'"\n')
            ignore=Path(d)/'accepted-fingerprints';ignore.write_text('\n'.join(combined)+'\n')
            report=Path(d)/'redacted-findings.json'
            scan=subprocess.run(['gitleaks','dir','--no-banner','--redact=100','--gitleaks-ignore-path',str(ignore),
                '--report-format','json','--report-path',str(report),str(fixture)],capture_output=True)
            self.assertEqual(scan.returncode,1,scan.stderr.decode())
            self.assertIn('generic-api-key',{r['RuleID'] for r in json.loads(report.read_text())})

    def test_W69_always_recorded_inventory_matches_schema(self):
        doc=(ROOT/'selfhost/docs/UNINSTALL-DATA-DELETION.md').read_text()
        schema=(ROOT/'chronicle-server/src/main/resources/db/migration/V1__fresh_schema.sql').read_text()
        for field in ('study_id','participant_id','random_device_id','platform','app_version','model',
                      'participant_form_submission_receipts','form_kind','idempotency_key','request_hash',
                      'audit','user_agent','deletion_tombstones'):
            self.assertIn('`'+field+'`',doc)
        for field in ('form_kind','idempotency_key','request_hash'):
            self.assertIn(field,schema)
        self.assertIn('ClientIpRecord',doc)
        self.assertIn('withheld',doc)
        self.assertIn('authorized',doc.lower())
        self.assertIn('optional collection modules',doc)

    def test_W58_policy_units_and_gate_failure(self):
        result = subprocess.run(['conftest','verify','--policy',str(ROOT/'tests/security/policies')],capture_output=True)
        self.assertEqual(result.returncode,0,result.stdout.decode()+result.stderr.decode())
        gate = function('tests/security/run-all-security.sh','run_compliance_scan')
        with tempfile.TemporaryDirectory() as d:
            shell = 'set -euo pipefail\nconftest() { echo "$1" >>"$CALLS"; [[ "$1" != verify ]]; }\n'+gate+'\nrun_compliance_scan\n'
            result = subprocess.run(['bash','-c',shell],env={**os.environ,'ROOT_DIR':str(ROOT),'REPORT_DIR':d,'CALLS':d+'/calls'},capture_output=True)
            self.assertNotEqual(result.returncode,0)
            self.assertEqual(Path(d+'/calls').read_text().splitlines(),['verify'])

    def test_W59_shipped_gate_coverage(self):
        methods = '\n'.join(function('scripts/local-ci.sh',n) for n in ('deployment_files','job_dockerfile_lint','job_iac_scan'))
        with tempfile.TemporaryDirectory() as d:
            fixture = Path(d)
            for name in ('docker/Dockerfile.backend','docker/Dockerfile.frozen','selfhost/Dockerfile.caddy','selfhost/overlays/sample.yml','selfhost/entrypoint.sh'):
                p=fixture/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_text('clean')
            stub = '''set -euo pipefail
ensure_hadolint() { :; }; prepare_checkov_runtime() { :; }; require_cmd() { :; }
report_path() { printf '%s/%s' "$ROOT_DIR" "$2"; }
scanner() { for a in "$@"; do [[ ! -f "$a" ]] || ! rg -q VIOLATION "$a" || return 1; done; }
hadolint() { scanner "$@"; }; shellcheck() { scanner "$@"; }
conftest() { scanner "$@"; }; checkov() { scanner "$@"; }
'''
            env={**os.environ,'ROOT_DIR':d}
            def run():
                return subprocess.run(['bash','-c',stub+methods+'\njob_dockerfile_lint\njob_iac_scan'],env=env,capture_output=True)
            self.assertEqual(run().returncode,0)
            # Every docker/ input is frozen; selfhost inputs remain enforced.
            for name in ('docker/Dockerfile.backend','docker/Dockerfile.frozen'):
                (fixture/name).write_text('VIOLATION')
                self.assertEqual(run().returncode,0,name)
            for name in ('selfhost/Dockerfile.caddy','selfhost/overlays/sample.yml','selfhost/entrypoint.sh'):
                p=fixture/name;p.write_text('VIOLATION')
                self.assertNotEqual(run().returncode,0,name)
                p.write_text('clean')

    def test_hadolint_gates_name_the_repository_configuration(self):
        # Hadolint reads .hadolint.yaml from the working directory only. Started from any other directory, both
        # gates ran it with its default threshold and reported the note-level DL3066 and SC2015 in
        # selfhost/Dockerfile.caddy and selfhost/Dockerfile.grafana as findings.
        gates = '\n'.join([function('tests/security/run-all-security.sh', 'run_hadolint_scan')] +
                          [function('scripts/local-ci.sh', name) for name in ('deployment_files', 'job_dockerfile_lint')])
        with tempfile.TemporaryDirectory() as d:
            fixture, elsewhere = Path(d) / 'repository', Path(d) / 'elsewhere'
            (fixture / 'selfhost').mkdir(parents=True)
            elsewhere.mkdir()
            (fixture / 'selfhost/Dockerfile.caddy').write_text('FROM scratch\n')
            stub = '''set -euo pipefail
ensure_hadolint() { :; }; validate_sarif() { :; }
hadolint() { printf '%s\\n' "$*" >>"$CALLS"; }
'''
            calls = Path(d) / 'calls'
            result = subprocess.run(
                ['bash', '-c', stub + gates + '\nrun_hadolint_scan "$ROOT_DIR/selfhost/Dockerfile.caddy" "$CALLS.sarif"\njob_dockerfile_lint\n'],
                env={**os.environ, 'ROOT_DIR': str(fixture), 'CALLS': str(calls)}, cwd=elsewhere, capture_output=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            seen = calls.read_text().splitlines()
            self.assertEqual(len(seen), 2, seen)
            for call in seen:
                self.assertIn(f'--config {fixture}/.hadolint.yaml ', call)
                self.assertTrue(call.endswith(f'{fixture}/selfhost/Dockerfile.caddy'), call)

    def test_W63_local_requests_have_absolute_deadlines(self):
        source=(ROOT/'scripts/local-ci.sh').read_text()
        # Every actual curl call must bound the transfer as well as the connection.
        calls=re.findall(r'^[ \t]*[^#\n]*?\bcurl[ \t]+((?:[^\n]*\\\n)*[^\n]*)',source,re.M)
        self.assertGreaterEqual(len(calls),5)
        for call in calls:
            self.assertRegex(call,r'--max-time\s+[1-9][0-9]*')
            self.assertRegex(call,r'--connect-timeout\s+[1-9][0-9]*')
        with tempfile.TemporaryDirectory() as d:
            stub='set -euo pipefail\nrequire_cmd() { :; }; curl() { [[ "$*" == *"--max-time"* && "$*" == *"--connect-timeout"* ]] || return 99; return 28; }\n'
            result=subprocess.run(['bash','-c',stub+function('scripts/local-ci.sh','download_asset')+'\ndownload_asset https://fixture.invalid artifact'],env={**os.environ,'TMPDIR':d},capture_output=True,timeout=2)
            self.assertEqual(result.returncode,28)

    def test_W65_android_sast_modules_and_candidate_license(self):
        sast=function('tests/security/run-all-security.sh','run_sast_semgrep')
        modules=function('tests/security/run-all-security.sh','android_source_roots')
        modular=function('tests/security/run-all-security.sh','run_collection_semgrep_modularization')
        self.assertIn('android_source_roots',sast)
        self.assertIn('android_source_roots',modular)
        self.assertIn('find',modules)
        job=function('scripts/local-ci.sh','job_android_unit')
        self.assertIn(':app:checkLicense',job)
        self.assertIn('run-all-security.sh',job)
        rule=(ROOT/'tests/security/collection-rules/collection-modularization.yaml').read_text()
        self.assertIn('override val privacyClass: CollectionPrivacyClass = $ID.privacyClass',rule)
        with tempfile.TemporaryDirectory() as d:
            shell='''set -euo pipefail
require_jdk21() { :; }; require_cmd() { :; }; log() { :; }
'''+job.replace('bash "$ROOT_DIR/tests/security/run-all-security.sh" sast','printf sast >>"$CALLS"')+'\njob_android_unit'
            root=Path(d);(root/'chronicle').mkdir()
            gradle=root/'chronicle/gradlew'
            gradle.write_text('#!/bin/bash\nprintf "%s\\n" "$*" >>"$CALLS"\n[[ "$*" != *":app:checkLicense"* ]]\n');gradle.chmod(0o755)
            result=subprocess.run(['bash','-c',shell],env={**os.environ,'ROOT_DIR':d,'CALLS':d+'/calls'},capture_output=True)
            self.assertNotEqual(result.returncode,0)
            self.assertIn(':app:checkLicense',(root/'calls').read_text())
            selected=[]
            for path in ('tests/security/rules/cwe-comprehensive.yaml','tests/security/collection-rules/collection-modularization.yaml'):
                rules=yaml.safe_load((ROOT/path).read_text())['rules']
                selected.extend(r for r in rules if r['id'] in ('chronicle-android-log-raw-participant-id','chronicle-collection-module-must-assert-privacy-invariant','chronicle-hardcoded-password-kotlin'))
            config=root/'rules.yaml';config.write_text(yaml.safe_dump({'rules':selected}))
            scan_parent=ROOT/'audit-regression-runs';scan_parent.mkdir(exist_ok=True)
            with tempfile.TemporaryDirectory(dir=scan_parent) as scan_dir:
                fixture=Path(scan_dir)/'chronicle/collection-activity/src/main/java/fixture';fixture.mkdir(parents=True)
                valid=fixture/'Valid.kt';valid.write_text('class Valid : DataCollectionModule { override val privacyClass: CollectionPrivacyClass = id.privacyClass; val LIST_API_KEYS_SQL = "$SELECT_API_KEYS_SQL ORDER BY created_at"; val passwordHeader = "X-Password" }')
                invalid=fixture/'Invalid.kt';invalid.write_text('class Invalid : DataCollectionModule { val apiKey = "synthetic-fixture-credential"; val apiKeySql = "synthetic-fixture-credential"; fun log(participantId: String) { Log.i("tag", "$participantId") } }')
                scan=subprocess.run(['semgrep','scan','--config',str(config),'--metrics','off','--disable-version-check','--no-git-ignore','--json','.'],cwd=fixture,env={**os.environ,'SEMGREP_SEND_METRICS':'off'},capture_output=True)
                self.assertEqual(scan.returncode,0,scan.stderr.decode())
                findings=json.loads(scan.stdout)['results']
                self.assertEqual({Path(r['path']).name for r in findings},{'Invalid.kt'},scan.stderr.decode()+scan.stdout.decode())
                self.assertEqual(len(findings),4,scan.stderr.decode()+scan.stdout.decode())

    def test_W75_observed_secure_v3_cookie_required(self):
        import sys
        sys.path.insert(0, str(ROOT / 'tests/selfhost-py'))
        from session_probe_fixture import run_session_probe
        for mode in ('unreachable', '404', 'no-cookie', 'insecure', 'secure', 'rotation-current-rejected',
                     'rotation-old-accepted', 'rotation-forbidden', 'rotation-throttled'):
            result = run_session_probe(mode)
            self.assertEqual(result.returncode == 0, mode == 'secure', result.stdout + result.stderr)
            if mode.startswith('rotation-'):
                self.assertNotIn('[PASS]  Test 2:', re.sub(r'\x1b\[[0-9;]*m', '', result.stdout))

if __name__ == '__main__':
    unittest.main()
