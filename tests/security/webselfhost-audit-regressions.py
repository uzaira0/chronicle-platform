#!/usr/bin/env -S python3 -s
"""Isolated web self-host regressions; never contacts a deployment."""
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "selfhost"))
from chronicle_ops.route_surface import RETIRED_PREFIXES

RUNS = Path(os.environ.get('TMPDIR') or ROOT / 'build/operator-test-runs/webselfhost-audit')
RUNS.mkdir(parents=True, exist_ok=True)
os.environ['TMPDIR'] = str(RUNS)
tempfile.tempdir = str(RUNS)

class AuditRegressions(unittest.TestCase):
    def test_cross_S03_contract2_refused_before_drop(self):
        source = (ROOT / 'selfhost/restore.sh').read_text()
        branch = source.split('else\n  checkpoint_rows=', 1)[1].split('\nfi\n\n# Treat a resumed', 1)[0]
        initialization = source[source.index('RESTORE_CONTINUITY_CONTRACT_VERSION=$(cat '):
                                source.index('\nreadonly RESTORE_CONTINUITY_CONTRACT_VERSION')]
        current_contract = (ROOT / 'selfhost/restore-continuity.version').read_text().strip()
        shell = '''set -euo pipefail
psql_q() { if [[ "$*" == *contract_version* ]]; then printf '%s' "$CONTRACT"; else printf 1; fi; }
''' + initialization + '\ncheckpoint_rows=' + branch + '\nprintf accepted > "$MARKER"\n'
        with tempfile.TemporaryDirectory() as d:
            for contract in ('2', '3', '4', current_contract, 'unknown'):
                marker = Path(d) / contract
                result = subprocess.run(['bash', '-c', shell], env={**os.environ,
                    'CONTRACT': contract, 'MARKER': str(marker),
                    'RESTORE_SQL_DIR': str(ROOT / 'selfhost')}, capture_output=True)
                self.assertEqual(result.returncode == 0, contract == current_contract, result.stderr.decode())
                self.assertEqual(marker.exists(), contract == current_contract)
                if contract != current_contract:
                    self.assertIn(f'unsupported contract {contract}', result.stderr.decode())

    def test_W14_only_reviewed_restricted_dumps_restore(self):
        import gzip, hashlib
        sys.path.insert(0, str(ROOT / 'selfhost'))
        from chronicle_ops.dump import DumpError, validate_dump
        # The container script delegates to the same validator before any database mutation.
        container = (ROOT / 'selfhost/restore.sh').read_text()
        self.assertIn('python3 -m chronicle_ops.dump', container)
        self.assertLess(container.index('verify_restore_dump "$RESTORE_FILE"'), container.index('DROP SCHEMA'))
        complete = b'-- PostgreSQL database dump complete\n'
        with tempfile.TemporaryDirectory() as d:
            for payload, accepted in [(b'-- PostgreSQL database dump\n\\restrict token123\nSET statement_timeout = 0;\n' + complete + b'\\unrestrict token123\n',True),
                (b'-- PostgreSQL database dump\n\\restrict token123\nCOPY public.x (id) FROM stdin;\n\\! this-is-copy-data\n\\.\n' + complete + b'\\unrestrict token123\n',True),
                (b'-- PostgreSQL database dump\n\\restrict token123\n\\! touch owned\n' + complete + b'\\unrestrict token123\n',False),
                (b"-- PostgreSQL database dump\n\\restrict token123\nCOPY x FROM PROGRAM 'touch owned';\n" + complete + b'\\unrestrict token123\n',False),
                (b'-- PostgreSQL database dump\n\\restrict token123\nSELECT 1; \\unrestrict token123\nSELECT 1; \\! touch owned\n' + complete + b'\\unrestrict token123\n',False),
                (b'SELECT 1;\n',False)]:
                dump = Path(d) / 'dump.gz'; dump.write_bytes(gzip.compress(payload))
                for trusted in (True,False):
                    digest = hashlib.sha256(dump.read_bytes()).hexdigest() if trusted else '0'*64
                    try:
                        validate_dump(dump, digest); valid = True
                    except DumpError:
                        valid = False
                    self.assertEqual(valid, accepted and trusted, payload)

    def test_W31_independent_monitoring_guard(self):
        source = (ROOT / 'selfhost/monitoring/render-config.sh').read_text()
        compose = (ROOT / 'selfhost/overlays/monitoring.yml').read_text()
        service = compose[compose.index('  monitoring-config:'):compose.index('  # Read-only Docker API')]
        self.assertIn('GRAFANA_BIND:',service)
        self.assertIn('GRAFANA_ADMIN_PASSWORD:',service)
        preflight = source[:source.index('mkdir -p /monitoring-secrets')]
        with tempfile.TemporaryDirectory() as d:
            script = Path(d) / 'render.sh'
            script.write_text(preflight.replace('$(dirname \"${BASH_SOURCE[0]}\")/../network-policy.sh', str(ROOT / 'selfhost/network-policy.sh')) + '\nprintf accepted\n')
            for bind,password,accepted in [('0.0.0.0','short',False),('::0','x'*32,False),
                ('127.0.0.1','x'*32,True),('10.1.2.3','x'*32,True)]:
                result = subprocess.run(['bash',str(script)],env={**os.environ,
                    'METRICS_PASSWORD':'x'*32,'GRAFANA_ADMIN_PASSWORD':password,'GRAFANA_BIND':bind,
                    'CHRONICLE_HOST_UID':'1000','CHRONICLE_HOST_GID':'1000'},capture_output=True)
                self.assertEqual(result.returncode==0,accepted,result.stderr.decode())

    def test_W53_public_researcher_bearer_separation(self):
        from urllib.parse import unquote
        snippets = (ROOT / 'selfhost/caddy/snippets.caddy').read_text()
        block = snippets[snippets.index('(chronicle_strip_researcher_bearer)'):snippets.index('(chronicle_mobile)')]
        pattern = re.search(r'path_regexp (.+)',block).group(1)
        self.assertIn('request_header @publicResearcherSurface -Authorization',block)
        retired = snippets.split("(chronicle_mobile) {", 1)[1].split("\n}", 1)[0]
        deny_pattern = re.search(r"path_regexp (.+)", retired).group(1)
        for prefix in RETIRED_PREFIXES:
            assert re.search(deny_pattern, prefix + "/x")
        assert "respond @chronicle_retired_api 404" in retired
        for path in ('/chronicle/v3/study/abc','/chronicle/v3/study/abc/participants',
                     '/chronicle/v3/%73tudy/abc','/chronicle%2fv3%2fstudy%2fabc',
                     '/chronicle/v3/permissions','/chronicle/v3/admin/abc',
                     '/chronicle/v4/study/abc',
                     '/chronicle/v3/time-use-diary/abc/submit',
                     '/chronicle/v3/time-use-diary/abc/participant/p1',
                     '/chronicle/v3/time-use-diary/abc/settings'):
            self.assertTrue(re.search(pattern,unquote(path)))
        # The public boundary strips researcher cookies while retaining participant sessions.
        cookie_rewrites = re.findall(r'^\s*request_header Cookie `([^`]+)` "([^"\n]*)"\s*$',block,re.M)
        self.assertTrue(cookie_rewrites, 'Researcher cookies must be removed before proxying')
        for cookie,expected in (
                ('chronicle_auth=jwt; ol_csrf_token=x','ol_csrf_token=x'),
                ('__Host-chronicle-form=session; authorization=Bearer%20jwt','__Host-chronicle-form=session'),
                ('__Host-chronicle-form=session','__Host-chronicle-form=session'),
                ('chronicle_auth=jwt; authorization=Bearer%20jwt',''),
                ('authorization=jwt; __Host-chronicle-form=session; chronicle_auth=jwt; ol_csrf_token=x',
                 '__Host-chronicle-form=session; ol_csrf_token=x'),
                ('other_chronicle_auth=value; __Host-chronicle-form=session',
                 'other_chronicle_auth=value; __Host-chronicle-form=session'),
                ('\tchronicle_auth =jwt;\tauthorization =jwt; __Host-chronicle-form=session',
                 '__Host-chronicle-form=session')):
            stripped = cookie
            for cookie_pattern,replacement in cookie_rewrites:
                stripped = re.sub(cookie_pattern,replacement,stripped)
            self.assertEqual(stripped,expected,cookie)
        for header in ('Cookie','X-Api-Key','X-Chronicle-Form-CSRF','Idempotency-Key'):
            self.assertNotIn(f'-{header}',block)
        for name in ('Caddyfile.split','Caddyfile.split.local','Caddyfile.split.tls'):
            source = (ROOT / 'selfhost' / name).read_text()
            public, internal = source.split(':8081 {',1)
            self.assertIn('import chronicle_strip_researcher_bearer',public)
            self.assertNotIn('import chronicle_strip_researcher_bearer',internal)
            self.assertLess(public.index('import chronicle_strip_researcher_bearer'),public.index('import chronicle_mobile'))

    def test_W56_canonical_bind_and_cidr_union(self):
        guard = (ROOT / 'selfhost/guard-config.sh').read_text()
        self.assertIn('specific_private_bind "$INTERNAL_BIND"',guard)
        self.assertIn('validate_dashboard_networks "$DASHBOARD_ALLOWED_IPS"',guard)
        policy = ROOT / 'selfhost/network-policy.sh'
        for bind,accepted in [('0.0.0.0',False),('0.00.0.00',False),('::',False),('::0',False),
            ('[0:0:0:0:0:0:0:0]',False),('::ffff:0.0.0.0',False),('127.0.0.1',True),
            ('10.1.2.3',True),('192.168.5.6',True),('::1',True),('0:0:0:0:0:0:0:1',True),('fd12::1234',True)]:
            result = subprocess.run(['bash','-c','source "$1"; specific_private_bind "$2"','policy',str(policy),bind],capture_output=True)
            self.assertEqual(result.returncode==0,accepted,bind)
        for networks,accepted in [('0.0.0.0/1 128.0.0.0/1',False),('::/1 8000::/1',False),
            ('0.0.0.0/2 64.0.0.0/2 128.0.0.0/2 192.0.0.0/2',False),
            ('192.168.0.0/16 ::1/128',True),('10.0.0.0/8',True),('invalid/3',False)]:
            result = subprocess.run(['bash','-c','source "$1"; validate_dashboard_networks "$2"','policy',str(policy),networks],capture_output=True)
            self.assertEqual(result.returncode==0,accepted,networks)

    def test_W06_exiting_ca_is_not_health_waited(self):
        source = (ROOT / 'selfhost/rotate-secret.sh').read_text()
        function = source[source.index('apply_configuration() {'):source.index('wait_for_metrics_target() {')]
        stub = """set -euo pipefail
fail() { exit 1; }
dc() {
  if [[ "$*" == 'config --services' ]]; then printf '%s\n' postgres backend ca-export; return; fi
  if [[ "$1" == up ]]; then
    [[ "$*" == *'--wait'* && "$*" != *'ca-export'* && "$*" == *'postgres backend'* ]] || return 91
    printf 'wait\n'
  else
    [[ "$*" == 'run --rm --no-deps ca-export' ]] || return 92
    printf 'export\n'
  fi
}
service_roles() {
  if [[ "$*" == 'compose-services core' ]]; then printf '%s\n' postgres backend ca-export; return; fi
  [[ "$*" == 'start-monitoring' ]] || return 93
}
APPLY_MODE=full
SECRET_ROTATION_WAIT_TIMEOUT_SECONDS=30
"""
        result = subprocess.run(['bash','-c',stub+function+'\napply_configuration\napply_configuration\napply_configuration\n'],capture_output=True)
        self.assertEqual(result.returncode,0,result.stderr.decode())
        self.assertEqual(result.stdout.decode(),'wait\nexport\n'*3)

if __name__ == '__main__':
    unittest.main()
