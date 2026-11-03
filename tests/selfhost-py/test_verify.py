from dataclasses import dataclass, field
from functools import partial
import gzip
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from types import SimpleNamespace
import io
import re
from pathlib import Path
import shutil
import ssl
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "selfhost"))
from chronicle_ops.verify import verify_backup, curl_config
from test_restore import DUMP
from selfhost_fixture import MobileCanaryFixture, run_cert_init


class VerifyBackupTests(unittest.TestCase):
    def test_restored_privileges_report_preserved_violated_and_unavailable(self):
        from types import SimpleNamespace
        from chronicle_ops.verify import DATABASE_PRIVILEGES_SQL, DATABASE_PRIVILEGES_VIOLATION, DATABASE_PRIVILEGES_UNAVAILABLE, verify_database_privileges
        for answer, expected, message in (('t', 0, 'retain'), ('f', DATABASE_PRIVILEGES_VIOLATION, 'least privilege'),
                                          ('', DATABASE_PRIVILEGES_UNAVAILABLE, 'Could not check'),
                                          ('malformed', DATABASE_PRIVILEGES_UNAVAILABLE, 'Could not check')):
            with patch('chronicle_ops.verify.compose', return_value=SimpleNamespace(stdout='postgres-id')), \
                 patch('chronicle_ops.verify.postgres_sql', return_value=answer) as query:
                status, shown = verify_database_privileges()
                self.assertEqual(status, expected)
                self.assertIn(message, shown)
                self.assertEqual('preserves ACLs' in shown, answer == 'f')
                query.assert_called_once_with('postgres-id', DATABASE_PRIVILEGES_SQL)

    def check(self, contents):
        files = {Path(f"/backups/last/{i}.sql.gz"): data for i, data in enumerate(contents)}
        opened = []
        def stream(path, _mode):
            opened.append(path)
            return gzip.GzipFile(fileobj=io.BytesIO(files[path]))
        output = io.StringIO()
        with patch.object(Path, "glob", return_value=reversed(list(files))), \
             patch("chronicle_ops.dump.gzip.open", stream), patch("sys.stdout", output):
            status = verify_backup("/backups")
        return status, output.getvalue(), opened

    def test_no_backup_retains_exact_message(self):
        status, output, opened = self.check([])
        self.assertEqual(status, 1)
        self.assertEqual(output, "  \033[31mFAIL\033[0m no SQL dump yet — nothing recoverable if the keyring is lost\n")
        self.assertEqual(opened, [])

    def test_complete_dump_directs_operator_to_guarded_restore(self):
        status, output, _ = self.check([gzip.compress(DUMP)])
        self.assertEqual(status, 0)
        self.assertEqual(output, "  \033[32mok\033[0m   a key-free SQL dump exists; recover with ./chronicle restore\n")

    def test_normal_pg_dump_footer_needs_no_rewriting(self):
        dump = DUMP.replace(b"\\unrestrict fixture\n-- PostgreSQL database dump complete\n",
                            b"-- PostgreSQL database dump complete\n\n--\n\n\\unrestrict fixture\n")
        self.assertEqual(self.check([gzip.compress(dump)])[0], 0)

    def test_b5_rejects_invalid_gzip_and_truncated_crc(self):
        for content in (b"fixture-dump\n", gzip.compress(DUMP)[:-3]):
            with self.subTest(content=content):
                status, output, _ = self.check([content])
                self.assertEqual(status, 1)
                self.assertIn("SQL dump failed gzip integrity verification", output)

    def test_b5_rejects_incomplete_empty_or_nonfinal_marker(self):
        for content in (DUMP.replace(b"-- PostgreSQL database dump complete\n", b""), b"", DUMP + b"SELECT 2;\n",
                        DUMP.replace(b"-- PostgreSQL database dump complete\n", b"-- PostgreSQL database dump complete\r\n")):
            with self.subTest(content=content):
                status, output, _ = self.check([gzip.compress(content)])
                self.assertEqual(status, 1)
                self.assertIn("lacks the final PostgreSQL database dump complete marker", output)

    def test_read_failure_is_indeterminate(self):
        with patch.object(Path, "glob", return_value=[Path("unreadable.sql.gz")]), \
             patch("chronicle_ops.dump.gzip.open", side_effect=PermissionError()), patch("sys.stdout", io.StringIO()):
            self.assertEqual(verify_backup("/backups"), 1)

    def test_all_candidates_are_checked_in_stable_order(self):
        complete = gzip.compress(DUMP)
        status, _, opened = self.check([complete, complete])
        self.assertEqual(status, 0)
        self.assertEqual(opened, [Path("/backups/last/0.sql.gz"), Path("/backups/last/1.sql.gz")])
        status, output, _ = self.check([complete, b"bad"])
        self.assertEqual(status, 1)
        self.assertIn("/backups/last/1.sql.gz", output)

    def test_credentials_are_curl_config_escaped_and_line_breaks_rejected(self):
        self.assertEqual(curl_config("user", 'researcher:one"two\\three'),
                         'user = "researcher:one\\"two\\\\three"\n')
        for value in ("one\ntwo", "one\rtwo"):
            with self.assertRaises(ValueError):
                curl_config("user", value)


@dataclass
class VerifyCommandState:
    password: str
    postgres: str
    reviewer: str
    canary: MobileCanaryFixture
    capacity: int
    bind: str = ''
    denied: bool = False
    uploads: int = 0
    calls: list = field(default_factory=list)


class VerifyCredentialsTests(unittest.TestCase):
    def test_backup_restore_verification_uses_the_configured_database(self):
        import os
        from chronicle_ops.verify import verify_configured_backups
        settings = {'COMPOSE_FILE': 'overlays/backups.yml', 'POSTGRES_DB': 'custom', 'BACKUP_SCHEDULE': '@weekly'}
        results = []
        with patch.dict(os.environ, {'CHRONICLE_OPS_BACKUPS': '/fixture/absent-backups'}, clear=True), \
             patch('chronicle_ops.verify.verify_backup_storage', return_value=0), \
             patch('chronicle_ops.verify.verify_backup', return_value=1) as check:
            verify_configured_backups(settings, lambda ok, message, warning=False: results.append((ok, message)))
        check.assert_called_once_with(Path('/fixture/absent-backups'), 'custom', '@weekly')
        self.assertIn((False, 'Backup restore verification'), results)

    def test_backup_directory_failures_survive_successful_dump_check(self):
        import os
        import tempfile
        from contextlib import ExitStack
        from chronicle_ops.verify import verify
        from chronicle_ops.dump import publish_backup
        with tempfile.TemporaryDirectory() as folder:
            backups = Path(folder)
            child = backups / 'last'
            child.mkdir()
            with gzip.open(child / 'chronicle-dump.sql.gz', 'wb') as output:
                output.write(DUMP)
            publish_backup(child / 'chronicle-dump.sql.gz', 'chronicle', {})
            settings = dict(COMPOSE_FILE='overlays/backups.yml', ENABLE_ENCRYPTION='false', RATE_LIMIT_RETRY_SLEEP='0')
            for mode, writable, expected in ((0o700, True, 0), (0o755, True, 1), (0o700, False, 1)):
                backups.chmod(mode)
                child.chmod(0o700 if writable else 0o500)
                with self.subTest(mode=mode, writable=writable), ExitStack() as stack:
                    stack.enter_context(patch.dict(os.environ, {'CHRONICLE_OPS_BACKUPS': folder}, clear=True))
                    stack.enter_context(patch('chronicle_ops.verify.read_env', return_value=settings))
                    for name in ('verify_public_surface', 'verify_mobile_bootstrap', 'verify_mobile_rate_limit'):
                        stack.enter_context(patch('chronicle_ops.verify.' + name))
                    stack.enter_context(patch('chronicle_ops.verify.verify_database_privileges', return_value=(0, 'ok')))
                    stack.enter_context(patch('chronicle_ops.verify.verify_backup_storage', return_value=0))
                    stack.enter_context(patch('chronicle_ops.verify.verify_database_storage', return_value=0))
                    stack.enter_context(patch('chronicle_ops.verify.os.access', side_effect=lambda directory, _: writable or directory != child))
                    output = stack.enter_context(patch('sys.stdout', io.StringIO()))
                    self.assertEqual(expected, verify([]), output.getvalue())

    def test_verify_rejects_changed_lock_identity_before_probing(self):
        import os
        from chronicle_ops.verify import verify
        environment = {"CHRONICLE_OPS_STATE": "/state", "CHRONICLE_OPS_PROJECT": "pilot"}
        for settings in ({"CHRONICLE_STATE_DIR": "/other", "COMPOSE_PROJECT_NAME": "pilot"},
                         {"CHRONICLE_STATE_DIR": "/state", "COMPOSE_PROJECT_NAME": "other"}):
            with self.subTest(settings=settings), patch.dict(os.environ, environment, clear=True), \
                 patch("chronicle_ops.verify.read_env", return_value=settings), \
                 patch("chronicle_ops.verify.curl") as curl, self.assertRaisesRegex(ValueError, "changed"):
                verify([])
            curl.assert_not_called()

    def test_rate_limit_guardrail_and_documented_settings_match_caddy(self):
        import os
        import subprocess
        import tempfile
        from chronicle_ops.envfile import read_env, value
        root = Path(__file__).resolve().parents[2]
        settings = read_env(root / "selfhost/.env.example")
        readme = (root / "selfhost/README.md").read_text()
        zones = re.findall(r"events \{\$(RATE_LIMIT_(?:MOBILE|WEB)_ABUSE_EVENTS):(\d+)\}",
                           (root / "selfhost/caddy/snippets.caddy").read_text())
        self.assertEqual(len(zones), 2)
        from fnmatch import fnmatchcase
        from chronicle_ops.verify import MOBILE_RATE_PROBE
        snippets = (root / "selfhost/caddy/snippets.caddy").read_text()
        quota_paths = re.search(r"\(chronicle_mobile_rate_match\) \{\s*path ([^\n]+)", snippets).group(1).split()
        self.assertTrue(any(fnmatchcase(MOBILE_RATE_PROBE, path) for path in quota_paths), quota_paths)
        for key, default in zones:
            self.assertEqual(value(settings, key), default)
            self.assertIn(key, readme)
        compose = (root / "selfhost/docker-compose.yml").read_text()
        self.assertIsNone(re.search(r"RATE_LIMIT_(?:MOBILE|WEB)_EVENTS", readme + str(settings) + compose))
        source = (root / "tests/security/selfhost-verify-secrets.sh").read_text()
        guard = source.split('/bin/chmod 0755 "${FIXTURE_SELFHOST}/chronicle"\n', 1)[1].split('\nPASSWORD=', 1)[0]
        result = subprocess.run(["bash", "-eu", "-c", 'fail() { echo "$*" >&2; exit 1; };\n' + guard],
                                env=dict(os.environ, ROOT_DIR=str(root)), capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        with tempfile.TemporaryDirectory() as folder:
            result = subprocess.run(["bash", str(root / "tests/security/selfhost-verify-secrets.sh")],
                env=dict(os.environ, SELFHOST_VERIFY_TEST_ROOT=str(Path(folder) / "runs")),
                capture_output=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)

    def credential_command(self, state: VerifyCommandState, args, **kwargs):
        self.assertTrue(all(secret not in " ".join(args) for secret in (state.password, state.postgres, state.reviewer)))
        for key in ("DASHBOARD_PASSWORD", "POSTGRES_PASSWORD", "CHRONICLE_REVIEWER_ACCESS_SECRET"):
            self.assertNotIn(key, os.environ)
        state.calls.append((args, kwargs))
        url = args[-1]
        for name, request in state.canary.requests.items():
            if url == request['url']:
                response = {'apiKey': state.canary.credential} if name == 'enrollment' else len(request['body'])
                return SimpleNamespace(returncode=0, stdout=json.dumps(response) + '\n200')
        code = "404"
        if url.endswith("/health"):
            code = "204"
        if url.endswith(("/chronicle", "/chronicle/", "/chronicle/survey")):
            code = "200"
        if url.startswith("https://" + state.bind + ":") and url.endswith("/chronicle/api/web/study"):
            code = "403" if state.denied else "401"
        if "participant/reviewer/enroll" in url:
            code = "401"
        if url.endswith("/chronicle/v4/mobile/reviewer-enrollment"):
            code = "200" if state.reviewer in (kwargs.get("input") or "") else "401"
        if url.endswith("/chronicle/v4/study/x/participant/x/enrollment-preview"):
            state.uploads += 1
            code = "401" if state.uploads <= state.capacity else "429"
        if url.endswith("/chronicle/v3/auth/dashboard-login"):
            self.assertIn('data-binary = ', kwargs["input"])
            code = "200" if state.password in kwargs["input"] else "401"
        if url.endswith("/chronicle/v3/auth/session") and "--cookie" in args:
            code = "200"
        output = code
        if "-sI" in args:
            output = "WWW-Authenticate: Basic realm=chronicle\r\n"
        if "--cookie" in args or "--cookie-jar" in args:
            # Like the backend, each answer sets a fresh CSRF cookie and returns that token.
            csrf = "fixture-" + url.rsplit("/", 1)[1]
            if "--cookie-jar" in args:
                Path(args[args.index("--cookie-jar") + 1]).write_text(
                    "# Netscape HTTP Cookie File\n127.0.0.1\tFALSE\t/chronicle\tTRUE\t0\tol_csrf_token\t" + csrf + "\n")
            output = '{"authenticated": ' + str(code == '200').lower() + ', "csrfToken": "' + csrf + '"}\n' + code
        elif "-w" in args:
            fmt = args[args.index("-w") + 1]
            if "url_effective" in fmt:
                output = f"200|{url.rsplit('/', 1)[0]}/chronicle/reviewer|128"
            elif "size_download" in fmt:
                output = code + " 128"
        if url == "http://example.test/health":
            output = "HTTP/1.1 308\r\nLocation: https://example.test/health\r\n\r\n\n308"
        return SimpleNamespace(returncode=0, stdout=output)

    def test_real_verify_keeps_credentials_in_stdin_and_proves_session(self):
        import os
        from types import SimpleNamespace
        from chronicle_ops.verify import verify
        password, postgres, reviewer = "dashboard-sentinel", "postgres-sentinel", "reviewer-sentinel"
        settings = {"DOMAIN": "example.test", "POSTGRES_PASSWORD": postgres,
                    "CHRONICLE_INTERNAL_WEB_SECRET": "synthetic-update-verifier",
                    "HTTP_BIND": "10.0.0.5", "CADDY_TRUSTED_PROXIES": "127.0.0.1/32",
                    "CHRONICLE_REVIEWER_ACCESS_ENABLED": "true", "CHRONICLE_REVIEWER_ACCESS_SECRET": reviewer,
                    "RATE_LIMIT_RETRY_SLEEP": "0"}
        # F5 SNAT admits this whole probe at the edge. The backend's bucket for failed
        # unauthenticated attempts must be exhausted instead; derive it from the shipped configuration.
        config = (Path(__file__).resolve().parents[2] / "chronicle-server/src/main/resources/rate-limit.yaml").read_text()
        capacity = int(int(re.search(r"^auth-requests-per-minute: (\d+)$", config, re.M)[1]) *
                       float(re.search(r"^burst-capacity-multiplier: ([\d.]+)$", config, re.M)[1]))
        import tempfile
        from selfhost_fixture import mobile_canary_fixture
        from chronicle_ops.mobile_canary import CANARY_FILE_SETTING
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        canary = mobile_canary_fixture(folder.name, 'https://example.test')
        settings[CANARY_FILE_SETTING] = str(canary.path)
        original_stat = Path.stat
        state = VerifyCommandState(password=password, postgres=postgres, reviewer=reviewer, canary=canary, capacity=capacity)
        calls = state.calls
        def database(*args, **kwargs):
            if "postgres" in args:
                self.assertTrue(kwargs["input"].startswith(postgres + "\0"))
                return SimpleNamespace(returncode=0, stdout="0" if "<>" in kwargs["input"] else "7")
            return SimpleNamespace(returncode=0, stdout="")
        environment = {"DASHBOARD_PASSWORD": password,
                       "CHRONICLE_OPS_TLS_MODE": "own-tls", "CHRONICLE_OPS_EXPOSURE": "internal",
                       "CHRONICLE_OPS_BACKUPS": "/backups", "DOMAIN": "stale.test",
                       "CHRONICLE_PUBLIC_BASE_URL": "https://stale.test", "ENABLE_ENCRYPTION": "false",
                       "COMPOSE_FILE": "docker-compose.yml"}
        for mode, bind, denied, expected in (("own-tls", "127.0.0.1", False, 0),
                                           ("behind-proxy", "127.0.0.1", False, 0),
                                           ("own-tls", "127.0.0.1", True, 1),
                                           ("own-tls", "10.0.0.5", True, 0)):
            environment["CHRONICLE_OPS_TLS_MODE"] = mode
            settings["INTERNAL_BIND"] = bind
            settings["COMPOSE_FILE"] = f"docker-compose.yml:overlays/mode-{mode}-internal.yml:overlays/backups.yml"
            calls.clear()
            state.uploads = 0
            state.bind, state.denied = bind, denied
            with self.subTest(mode=mode), patch.dict(os.environ, environment, clear=True), \
                 patch("chronicle_ops.verify.read_env", return_value=settings), \
                 patch("chronicle_ops.verify.dashboard_ca", return_value=Path("/tls/internal-cert.pem")), \
                 patch("chronicle_ops.verify.run", side_effect=partial(self.credential_command, state)), patch("chronicle_ops.verify.compose", side_effect=database), \
                 patch("chronicle_ops.verify.verify_backup", return_value=0), \
                 patch("chronicle_ops.verify.verify_database_privileges", return_value=(0, "Privileges verified")), \
                 patch("chronicle_ops.verify.verify_backup_storage", return_value=0), patch("chronicle_ops.verify.time.sleep"), \
                 patch("chronicle_ops.verify.verify_database_storage", return_value=0), \
                 patch.object(Path, "is_dir", return_value=True), patch.object(Path, "is_file", return_value=True), \
                 patch.object(Path, "iterdir", return_value=[]), patch("chronicle_ops.verify.os.access", return_value=True), patch.object(Path, "stat", lambda path, *a, **kw: original_stat(path, *a, **kw) if path == canary.path else SimpleNamespace(st_mode=0o700, st_size=1)), \
                 patch("sys.stdout", new_callable=io.StringIO) as output:
                self.assertEqual(verify([]), expected, output.getvalue())
                self.assertGreater(state.uploads, capacity)
                self.assertIn("Encryption at rest", output.getvalue())
                self.assertEqual(os.environ["COMPOSE_FILE"], settings["COMPOSE_FILE"])
                self.assertNotIn(password, output.getvalue())
                # Upgrade acceptance runs verify after the rollback dump: a minted invitation would outlive it.
                self.assertEqual([], [args for args, kwargs in calls if reviewer in (kwargs.get("input") or "")])
                if not denied:
                    self.assertIn("backend issued an authenticated dashboard session", output.getvalue())
                if denied and bind == "127.0.0.1":
                    # This host's own request was refused at the source allowlist: nothing was answered.
                    self.assertNotIn("answered without an app session", output.getvalue())
                    self.assertIn("dashboard API was refused by the source allowlist before the app session check (403)",
                                  output.getvalue())
                authenticated = [kwargs["input"] for _, kwargs in calls if password in (kwargs.get("input") or "")]
                self.assertEqual(len(authenticated), 0 if denied and bind != "127.0.0.1" else 1)
                self.assertNotIn("tests/deployment/", output.getvalue())
                if mode == "behind-proxy":
                    self.assertIn("Public HTTPS passed from this host", output.getvalue())
                    self.assertTrue(any(args[-1] == "https://example.test/health" for args, _ in calls))

    def test_real_verify_runs_every_probe_while_update_ingress_is_closed(self):
        from chronicle_ops.ingress import VERIFY_HEADER, VERIFY_SCHEME
        original = self.credential_command
        def checked(state, args, **kwargs):
            self.assertIn(VERIFY_HEADER + ': ' + VERIFY_SCHEME + ' synthetic-update-verifier', kwargs.get('input') or '')
            self.assertNotIn('synthetic-update-verifier', str(args))
            return original(state, args, **kwargs)
        with patch('chronicle_ops.ingress.fence_path', return_value=SimpleNamespace(exists=lambda: True)), \
             patch.object(self, 'credential_command', checked):
            self.test_real_verify_keeps_credentials_in_stdin_and_proves_session()



class VerifyMessagesTests(unittest.TestCase):
    def test_probe_classification_names_a_forbidden_answer_apart_from_acceptance(self):
        from chronicle_ops.verify import ProbeStatus, probe_status, report_refusal
        for code, refused, expected in (("401", ("401",), ProbeStatus.REFUSED), ("403", ("401", "403"), ProbeStatus.REFUSED),
                                        ("403", ("401",), ProbeStatus.FORBIDDEN), ("429", ("401",), ProbeStatus.RATE_LIMITED),
                                        ("000", ("401",), ProbeStatus.UNREACHABLE), ("502", ("401",), ProbeStatus.SERVER_ERROR),
                                        ("200", ("401",), ProbeStatus.ACCEPTED)):
            with self.subTest(code=code, refused=refused):
                self.assertIs(expected, probe_status(code, refused))
        reports = []
        report_refusal(lambda ok, text: reports.append((ok, text)), "dashboard API", "403", None, ("401",),
                       "requires an app session", "answered without an app session")
        self.assertEqual([(False, "dashboard API was refused by the source allowlist before the app session check (403)")], reports)

    def test_operator_verification_never_replays_a_mutating_mobile_canary(self):
        from chronicle_ops.mobile_canary import CANARY_FILE_SETTING
        from chronicle_ops.verify import verify_mobile_bootstrap
        for recipe in ('', '/private/fixture-recipe'):
            with self.subTest(recipe=recipe), patch('chronicle_ops.verify.curl', return_value=(0, '403')), \
                 patch('chronicle_ops.verify.send_canary') as replay, patch('sys.stdout', io.StringIO()) as output:
                verify_mobile_bootstrap({CANARY_FILE_SETTING: recipe}, 'https://fixture.invalid', lambda *_args: None)
                replay.assert_not_called()
                self.assertIn('release smoke', output.getvalue())

    def test_rate_limited_anonymous_probes_are_inconclusive_with_the_servers_retry_action(self):
        from chronicle_ops.verify import verify_mobile_bootstrap
        for retry_after, action in (('37', 'after 37 s'), ('0', 'after 0 s'),
                                    ('Sun, 01 Nov 2026 12:00:00 GMT', 'after 2026-11-01T12:00:00+00:00'),
                                    (None, 'wait for the rate-limit window'), ('garbage', 'wait for the rate-limit window')):
            def curl(url, *args, **kwargs):
                # Answers like curl itself: -D - prints the response headers, then the -w format.
                limited = url.endswith(('/settings/type/DataCollection', '/participant/reviewer/enroll', '/mobile/reviewer-enrollment'))
                code = '429' if limited else '404'
                headers = f'HTTP/1.1 {code}\r\n' + (f'Retry-After: {retry_after}\r\n' if limited and retry_after else '') + '\r\n'
                fmt = args[args.index('-w') + 1] if '-w' in args else ''
                if 'url_effective' in fmt:
                    return 0, '200|https://fixture.invalid/chronicle/reviewer|128'
                dumped = '-D' in args and args[args.index('-D') + 1] == '-'
                return 0, ((headers if dumped else '') + fmt.replace('%{http_code}', code).replace('%{size_download}', '128')).rstrip('\n')
            reports = []
            with self.subTest(retry_after=retry_after), patch('chronicle_ops.verify.curl', curl), patch('sys.stdout', io.StringIO()):
                verify_mobile_bootstrap({}, 'https://fixture.invalid', lambda ok, message, **_: reports.append((ok, message)))
                probes = [(ok, message) for ok, message in reports
                          if any(subject in message for subject in ('collection settings', 'one-time code', 'reviewer route'))]
                self.assertEqual(3, len(probes), reports)
                for ok, message in probes:
                    self.assertFalse(ok, message)
                    self.assertIn('rate limited', message)
                    self.assertIn(action, message)
                    self.assertNotIn('accepted', message)
                    self.assertNotIn('not refused', message)

    def test_database_privileges_cli_distinguishes_unavailable_from_violation(self):
        import subprocess
        from types import SimpleNamespace
        from chronicle_ops.__main__ import main
        from chronicle_ops.verify import DATABASE_PRIVILEGES_UNAVAILABLE, DATABASE_PRIVILEGES_VIOLATION
        for container, answer, error, expected in (
            ('postgres-id', 't', None, 0),
            ('postgres-id', 'f', None, DATABASE_PRIVILEGES_VIOLATION),
            ('', 't', None, DATABASE_PRIVILEGES_UNAVAILABLE),
            ('postgres-id', '', None, DATABASE_PRIVILEGES_UNAVAILABLE),
            ('postgres-id', 'malformed', None, DATABASE_PRIVILEGES_UNAVAILABLE),
            ('postgres-id', '', subprocess.CalledProcessError(1, 'psql'), DATABASE_PRIVILEGES_UNAVAILABLE),
            ('postgres-id', '', subprocess.TimeoutExpired('psql', 10), DATABASE_PRIVILEGES_UNAVAILABLE),
            ('postgres-id', '', PermissionError('query unavailable'), DATABASE_PRIVILEGES_UNAVAILABLE),
        ):
            with self.subTest(container=container, answer=answer, error=error), \
                 patch('chronicle_ops.__main__.signal.signal'), \
                 patch('chronicle_ops.verify.compose', return_value=SimpleNamespace(stdout=container)), \
                 patch('chronicle_ops.verify.postgres_sql', return_value=answer, side_effect=error) as query, \
                 patch('sys.stdout', new_callable=io.StringIO) as output:
                self.assertEqual(main(['database-privileges']), expected)
                shown = output.getvalue()
                self.assertEqual('preserves ACLs' in shown, expected == DATABASE_PRIVILEGES_VIOLATION)
                if expected == DATABASE_PRIVILEGES_UNAVAILABLE:
                    self.assertIn('Could not check database privileges', shown)
                    self.assertIn('Restore database connectivity and rerun doctor', shown)
                if not container:
                    query.assert_not_called()
        with patch('chronicle_ops.verify.compose', side_effect=subprocess.CalledProcessError(1, 'docker')), \
             patch('chronicle_ops.__main__.signal.signal'), patch('sys.stdout', io.StringIO()) as output:
            self.assertEqual(main(['database-privileges']), DATABASE_PRIVILEGES_UNAVAILABLE)
            self.assertIn('Could not check database privileges', output.getvalue())

    def test_public_acceptance_distinguishes_readiness_transport_and_http_response(self):
        from chronicle_ops.verify import verify_public_origin
        for replies, expected, message in (
            ([(0, '204'), (0, '200')], 0, ''),
            ([(0, '503')], 1, 'HTTPS responded, but Chronicle is not ready (503)'),
            ([(60, '000')], 1, 'check DNS, LB routing and released-client TLS trust'),
            ([(28, '503')], 1, 'Could not complete public HTTPS /health (curl exit 28)'),
            ([(0, '401')], 1, 'responded with HTTP 401 (expected 204)'),
            ([(0, '204'), (0, '500')], 1, 'responded with HTTP 500 (expected 200)'),
        ):
            with self.subTest(replies=replies), patch('chronicle_ops.verify.curl', side_effect=replies), \
                 patch('sys.stderr', new_callable=io.StringIO) as output:
                self.assertEqual(verify_public_origin('https://example.test'), expected)
                self.assertIn(message, output.getvalue())
                if replies == [(0, '503')]:
                    self.assertIn('Inspect backend, database and encryption health', output.getvalue())
                    self.assertNotIn('DNS', output.getvalue())

    def check_storage(self, queries, keyring=True, keyring_size=1, backup_status=0, privileges=(0, 'Privileges verified'),
                      backup_storage_status=0, database_storage_status=0):
        import os
        from types import SimpleNamespace
        from chronicle_ops.verify import verify
        settings = {'DOMAIN': 'example.test', 'COMPOSE_FILE': 'docker-compose.yml:overlays/backups.yml',
                    'RATE_LIMIT_MOBILE_ABUSE_EVENTS': '1', 'RATE_LIMIT_RETRY_SLEEP': '0'}
        uploads = 0
        def curl(url, *args, **kwargs):
            nonlocal uploads
            if url.endswith('/health'):
                code = '204'
            elif url.endswith('/chronicle/v4/study/x/participant/x/enrollment-preview'):
                uploads += 1
                code = '401' if uploads == 1 else '429'
            elif url.endswith(('/enroll', '/reviewer-enrollment')):
                code = '401'
            elif url.endswith('/reviewer'):
                return 0, '200|https://example.test/chronicle/reviewer|128'
            elif url.endswith(('/chronicle', '/chronicle/', '/chronicle/survey', '/DataCollection')):
                code = '200'
            else:
                code = '404'
            return 0, code + (' 128' if '%{http_code} %{size_download}' in args else '')
        replies = [query if isinstance(query, BaseException) else SimpleNamespace(returncode=query[0], stdout=query[1])
                   for query in queries]
        with patch.dict(os.environ, {'CHRONICLE_OPS_BACKUPS': '/backups'}, clear=True), \
             patch('chronicle_ops.verify.read_env', return_value=settings), patch('chronicle_ops.verify.curl', curl), \
             patch('chronicle_ops.verify.compose', side_effect=replies), \
             patch('chronicle_ops.verify.verify_database_privileges', return_value=privileges), \
             patch('chronicle_ops.verify.verify_backup', return_value=backup_status), \
             patch('chronicle_ops.verify.verify_mobile_bootstrap'), \
             patch('chronicle_ops.verify.verify_backup_storage', return_value=backup_storage_status), \
             patch('chronicle_ops.verify.verify_database_storage', return_value=database_storage_status), \
             patch.object(Path, 'is_dir', return_value=False), patch.object(Path, 'is_file', return_value=keyring), \
             patch.object(Path, 'stat', return_value=SimpleNamespace(st_size=keyring_size)), \
             patch('sys.stdout', new_callable=io.StringIO) as output:
            status = verify([])
        return status, output.getvalue()

    def test_encryption_reports_only_successful_query_counts(self):
        import subprocess
        for queries in ([(1, '')], [(0, '7'), (1, '')], [(0, '')], [(0, '7'), (0, 'garbled')],
                        [PermissionError('query unavailable')], [subprocess.TimeoutExpired('psql', 10)]):
            with self.subTest(queries=queries):
                status, output = self.check_storage(queries)
                self.assertEqual(status, 1)
                self.assertIn('Could not verify table encryption. Check the PostgreSQL query failure.', output)
                self.assertNotIn('table(s) still on plain heap', output)
                self.assertNotIn('tables are encrypted', output)
        for enc, plain, expected, message in (('7', '0', 0, 'all 7 tables are encrypted'),
                                              ('7', '3', 1, '3 table(s) still on plain heap'),
                                              ('0', '0', 1, 'No encrypted public tables were found')):
            with self.subTest(enc=enc, plain=plain):
                status, output = self.check_storage([(0, enc), (0, plain)])
                self.assertEqual(status, expected)
                self.assertIn(message, output)

    def test_missing_or_empty_backup_keyring_does_not_claim_a_remount_failure(self):
        for present, size in ((False, 1), (True, 0)):
            with self.subTest(present=present, size=size):
                status, output = self.check_storage([(0, '7'), (0, '0')], keyring=present, keyring_size=size)
                self.assertEqual(status, 1)
                self.assertIn('The backup keyring copy is missing or empty. Check keyring backup creation', output)
                self.assertNotIn('remounted', output)

    def test_final_verdict_covers_storage_privilege_and_backup_failures(self):
        from chronicle_ops.verify import DATABASE_PRIVILEGES_VIOLATION
        for overrides in ({'backup_status': 1}, {'privileges': (DATABASE_PRIVILEGES_VIOLATION, 'Privilege violation')},
                          {'keyring': False}, {'backup_storage_status': 1}, {'database_storage_status': 1}):
            with self.subTest(overrides=overrides):
                status, output = self.check_storage([(0, '7'), (0, '0')], **overrides)
                self.assertEqual(status, 1)
                self.assertIn('Resolve the failed checks listed above.', output)
                self.assertNotIn('not exposed as configured', output)


class RedirectTests(unittest.TestCase):
    def test_exact_redirect_target_status_and_deadlines(self):
        from types import SimpleNamespace
        from chronicle_ops.verify import check_proxy_http_redirect
        expected = "https://example.test/health"
        for code, location, result in (("308", expected, "308"), ("301", "https://other.test/health", None), ("200", expected, None)):
            with self.subTest(code=code, location=location), \
                 patch("chronicle_ops.verify.run", return_value=SimpleNamespace(returncode=0, stdout=f"HTTP/1.1 {code}\r\nLocation: {location}\r\n\r\n\n{code}")) as call:
                self.assertEqual(check_proxy_http_redirect("http://example.test/health", expected), result)
                args = call.call_args.args[0]
                self.assertEqual(args[args.index("--connect-timeout") + 1], "5")
                self.assertEqual(args[args.index("--max-time") + 1], "10")
                self.assertNotIn("-L", args)
                self.assertNotIn("--location", args)
        with patch("chronicle_ops.verify.run", return_value=SimpleNamespace(returncode=28, stdout=f"Location: {expected}\n308")):
            self.assertIsNone(check_proxy_http_redirect("http://example.test/health", expected))


class BackupFootprintTests(unittest.TestCase):
    RETENTION = dict(BACKUP_KEEP_DAYS='1', BACKUP_KEEP_WEEKS='1', BACKUP_KEEP_MONTHS='1', MIN_FREE_DISK_GIB='1')

    def footprint(self, settings, free, dump=b'x' * 1000, dump_size=None):
        import tempfile
        from chronicle_ops.verify import backup_footprint
        with tempfile.TemporaryDirectory() as folder:
            if dump is not None:
                (Path(folder) / 'last').mkdir()
                (Path(folder) / 'last/chronicle-20260101-000000.sql.gz').write_bytes(dump)
            disk = SimpleNamespace(f_bavail=free, f_frsize=1)
            with patch('chronicle_ops.verify.os.statvfs', return_value=disk):
                return backup_footprint(settings, folder, dump_size)

    def test_finite_retention_must_fit_above_the_free_space_floor(self):
        gib = 1024 ** 3
        # Four dumps (three tiers plus the newest) of 1000 bytes; one already exists.
        _, status, message, _ = self.footprint(self.RETENTION, gib + 3000)
        self.assertEqual('ok', status, message)
        self.assertIn('4 dumps', message)
        _, status, message, action = self.footprint(self.RETENTION, gib + 2999)
        self.assertEqual('warn', status, message)
        self.assertIn('./chronicle setup', action)

    def test_keep_all_warns_only_when_the_next_dump_would_cross_the_floor(self):
        gib = 1024 ** 3
        settings = dict(self.RETENTION, BACKUP_KEEP_WEEKS='all')
        _, status, message, _ = self.footprint(settings, gib + 1000)
        self.assertEqual('ok', status, message)
        self.assertIn('keeps every', message)
        _, status, message, _ = self.footprint(settings, gib + 999)
        self.assertEqual('warn', status, message)

    def test_no_dump_yet_and_unchosen_retention_are_reported(self):
        _, status, message, _ = self.footprint(self.RETENTION, 10 ** 12, dump=None)
        self.assertEqual(('ok', True), (status, 'first backup' in message), message)
        _, status, message, action = self.footprint({'MIN_FREE_DISK_GIB': '1'}, 10 ** 12)
        self.assertEqual('warn', status, message)
        self.assertIn('./chronicle setup', action)

    def test_the_database_estimate_stands_in_for_a_missing_dump(self):
        gib = 1024 ** 3
        _, status, message, _ = self.footprint(self.RETENTION, gib + 4000, dump=None, dump_size=1000)
        self.assertEqual('ok', status, message)
        _, status, message, _ = self.footprint(self.RETENTION, gib + 3999, dump=None, dump_size=1000)
        self.assertEqual('warn', status, message)


class VerifyTransportTests(unittest.TestCase):
    """verify probes the local listener itself: an inherited proxy must not answer, and the
    dashboard listener must prove the identity cert-init issued it."""

    def dashboard_chain(self, folder):
        tls = Path(folder) / 'tls'
        tls.mkdir(parents=True)
        result = run_cert_init(tls, timeout=30)
        self.assertEqual(0, result.returncode, result.stderr)
        return tls

    def listener(self, handler, tls=None):
        server = ThreadingHTTPServer(('127.0.0.1', 0), handler)
        self.addCleanup(server.server_close)
        if tls is not None:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(tls / 'internal-cert.pem', tls / 'internal-key.pem')
            server.socket = context.wrap_socket(server.socket, server_side=True)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.shutdown)
        return server

    def test_dashboard_probe_bypasses_an_inherited_proxy_and_rejects_a_foreign_certificate(self):
        from chronicle_ops.verify import curl
        proxied = []

        class Health(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(204 if self.path == '/health' else 404)
                self.end_headers()

            def log_message(self, *args):
                pass

        class HostileProxy(Health):
            def do_GET(self):
                proxied.append(self.path)
                self.send_response(204)
                self.end_headers()

            do_CONNECT = do_GET

        with tempfile.TemporaryDirectory() as folder:
            deployed = self.dashboard_chain(Path(folder) / 'deployed')
            foreign = self.dashboard_chain(Path(folder) / 'foreign')
            server = self.listener(Health, deployed)
            proxy = 'http://127.0.0.1:%d' % self.listener(HostileProxy).server_address[1]
            state = Path(folder) / 'state'
            state.mkdir()
            (state / '.env').write_text('INTERNAL_BIND=127.0.0.1\nINTERNAL_PORT=%d\n' % server.server_address[1])
            origin = 'https://127.0.0.1:%d' % server.server_address[1]
            environment = {name: proxy for name in ('HTTP_PROXY', 'http_proxy', 'HTTPS_PROXY', 'https_proxy', 'ALL_PROXY', 'all_proxy')}
            # An empty home: real curl must not read the account's .curlrc (noproxy or insecure would mask the checks).
            home = Path(folder) / 'home'
            home.mkdir()
            environment.update(PATH=os.environ['PATH'], CHRONICLE_OPS_STATE=str(state), HOME=str(home),
                               CURL_HOME=str(home), XDG_CONFIG_HOME=str(home))
            for trusted, expected in ((deployed, (0, '204')), (foreign, None)):
                (state / 'tls').mkdir(exist_ok=True)
                for name in ('internal-ca.crt', 'internal-cert.pem'):
                    shutil.copyfile(trusted / name, state / 'tls' / name)
                with self.subTest(trusted=trusted.parent.name), patch.dict(os.environ, environment, clear=True), \
                        patch('chronicle_ops.verify.Path.cwd', return_value=state):
                    status, code = curl(origin + '/health', '-o', '/dev/null', '-w', '%{http_code}')
                    if expected is None:
                        # curl 60: the listener's certificate does not chain to the recorded dashboard CA.
                        self.assertEqual(60, status, code)
                    else:
                        self.assertEqual(expected, (status, code))
                    self.assertEqual([], proxied)


class OperatorProbeTests(unittest.TestCase):
    """Doctor and verify probes against fake Compose/curl answers, one real failure each."""

    def test_dashboard_password_comes_from_one_stdin_line_or_the_terminal(self):
        from chronicle_ops.verify import verification_password
        environment = patch.dict(os.environ)
        environment.start()
        self.addCleanup(environment.stop)
        def ask(stdin, environment=None, tty=False):
            stream = io.StringIO(stdin)
            stream.isatty = lambda: tty
            with patch.dict(os.environ, environment or {}), patch('sys.stdin', stream), \
                 patch('chronicle_ops.verify.getpass.getpass', return_value='typed at the prompt') as prompt:
                try:
                    return verification_password(['--dashboard-password']), prompt.called, 'DASHBOARD_PASSWORD' in os.environ
                except ValueError as error:
                    return str(error), prompt.called, 'DASHBOARD_PASSWORD' in os.environ
        os.environ.pop('DASHBOARD_PASSWORD', None)
        self.assertEqual(('fixture-🔐', False, False), ask('fixture-🔐\nsecond line\n'))
        self.assertEqual(('typed at the prompt', True, False), ask('', tty=True))
        self.assertEqual(('--dashboard-password expected one password line on stdin', False, False), ask(''))
        self.assertEqual(('dashboard password must not be empty', False, False), ask('\n'))
        self.assertEqual(('use either --dashboard-password or DASHBOARD_PASSWORD, not both', False, False),
                         ask('piped\n', {'DASHBOARD_PASSWORD': 'from environment'}))
        with patch.dict(os.environ, DASHBOARD_PASSWORD='from environment'):
            self.assertEqual('from environment', verification_password([]))
            self.assertNotIn('DASHBOARD_PASSWORD', os.environ)

    def test_rate_limited_surface_probe_retries_before_reporting(self):
        from chronicle_ops.verify import surface_probe
        for answers, expected in ((['429', '429', '404'], (True, '404 /chronicle/v3/auth/session ')),
                                  (['429'] * 4, (False, '429 /chronicle/v3/auth/session was rate limited, so the answer is '
                                                        'unproven; wait for the rate-limit window to pass, then rerun ./chronicle verify '))):
            reports, replies = [], iter(answers)
            with self.subTest(answers=answers), patch('chronicle_ops.verify.curl', side_effect=lambda *_a, **_k: (0, next(replies))), \
                 patch('chronicle_ops.verify.time.sleep') as wait:
                surface_probe('https://estudio.example.cl', 7, lambda ok, message: reports.append((ok, message)))(
                    '/chronicle/v3/auth/session', ('404',))
                self.assertEqual([expected], reports)
                self.assertEqual([7] * (len(answers) - (answers[-1] != '429')), [call.args[0] for call in wait.call_args_list])

    def test_correct_dashboard_password_is_retried_through_a_login_rate_limit(self):
        from chronicle_ops.verify import verify_internal_surface
        reports = []
        sessions = iter([(False, '401'), (False, '429'), (True, '200')])
        clock = iter([0, 10, 20])
        with patch('chronicle_ops.verify.curl', return_value=(0, '')), \
             patch('chronicle_ops.verify.anonymous_request', return_value=('401', None)), \
             patch('chronicle_ops.verify.dashboard_session', side_effect=lambda *_: next(sessions)), \
             patch('chronicle_ops.verify.compose', return_value=SimpleNamespace(returncode=0)), \
             patch('chronicle_ops.verify.time.monotonic', side_effect=lambda: next(clock)), \
             patch('chronicle_ops.verify.time.sleep') as wait, patch('sys.stdout', io.StringIO()):
            verify_internal_surface({'INTERNAL_BIND': '127.0.0.1'}, 'correct password', lambda ok, message: reports.append((ok, message)),
                                    lambda *_args, **_kwargs: None)
        self.assertEqual((True, 'backend issued an authenticated dashboard session and accepted its cookie'), reports[-1])
        self.assertIn((True, 'wrong dashboard password is rejected (401)'), reports)
        wait.assert_called_once_with(15)

    def test_settings_server_error_is_reported_as_such(self):
        from chronicle_ops.verify import verify_mobile_bootstrap
        def curl(url, *args, **_kwargs):
            fmt = args[args.index('-w') + 1] if '-w' in args else ''
            if 'url_effective' in fmt:
                return 0, '200|https://estudio.example.cl/chronicle/reviewer|128'
            return 0, '502' if url.endswith('/settings/type/DataCollection') else '401'
        reports = []
        with patch('chronicle_ops.verify.curl', curl), patch('sys.stdout', io.StringIO()):
            verify_mobile_bootstrap({}, 'https://estudio.example.cl', lambda ok, message, **_: reports.append((ok, message)))
        self.assertIn((False, 'public collection settings returned a server error (502)'), reports)

    def test_behind_proxy_http_must_redirect_to_the_canonical_https_health_url(self):
        from chronicle_ops.env_migration import DeploymentMode
        from chronicle_ops.verify import verify_proxy_surface
        for external, location, http, expected in (
                ('https://estudio.example.cl/', 'https://estudio.example.cl/health', 'http://estudio.example.cl/health',
                 (True, '308 redirects to the canonical HTTPS health URL (https://estudio.example.cl/health)')),
                ('https://[2001:db8::7]', 'https://[2001:db8::7]/health', 'http://[2001:db8::7]/health',
                 (True, '308 redirects to the canonical HTTPS health URL (https://[2001:db8::7]/health)')),
                ('https://estudio.example.cl', 'https://other.example.cl/health', 'http://estudio.example.cl/health',
                 (False, 'HTTP /health must redirect with 301, 302, 307 or 308 to exactly https://estudio.example.cl/health'))):
            reports, asked = [], []
            def run(args, **_kwargs):
                asked.append(args[-1])
                return SimpleNamespace(returncode=0, stdout=f'HTTP/1.1 308\r\nLocation: {location}\r\n\r\n\n308')
            with self.subTest(external=external, location=location), patch('chronicle_ops.verify.run', side_effect=run), \
                 patch('sys.stdout', io.StringIO()):
                verify_proxy_surface({'PUBLIC_HTTP_ENABLED': 'true'}, DeploymentMode.BEHIND_PROXY, external,
                                     lambda *_args, **_kwargs: None, lambda ok, message: reports.append((ok, message)))
                self.assertEqual([expected], reports)
                self.assertEqual([http], asked)
        reports = []
        with patch('chronicle_ops.verify.run', side_effect=AssertionError('probed plain HTTP')):
            verify_proxy_surface({'PUBLIC_HTTP_ENABLED': 'false'}, DeploymentMode.BEHIND_PROXY, 'https://estudio.example.cl',
                                 lambda *_args, **_kwargs: None, lambda ok, message: reports.append((ok, message)))
        self.assertEqual([], reports)

    def test_doctor_reads_the_active_tde_key_creation_date(self):
        from datetime import datetime, timezone
        from chronicle_ops.verify import tde_key_generated_at
        for container, answer, expected in (('postgres-1', '2026-09-01T12:30:00Z', datetime(2026, 9, 1, 12, 30, tzinfo=timezone.utc)),
                                            ('postgres-1', '', None)):
            with self.subTest(answer=answer), patch('chronicle_ops.verify.compose', return_value=SimpleNamespace(stdout=container + '\n')), \
                 patch('chronicle_ops.verify.postgres_sql', return_value=answer) as query:
                self.assertEqual(expected, tde_key_generated_at())
                self.assertIn('WHERE key_name = (SELECT key_name FROM pg_tde_key_info())', query.call_args.args[1])
        with patch('chronicle_ops.verify.compose', return_value=SimpleNamespace(stdout='\n')), \
             self.assertRaisesRegex(ValueError, 'PostgreSQL container is unavailable'):
            tde_key_generated_at()

    def test_metrics_ignore_foreign_jobs_and_refuse_targets_without_a_scrape_time(self):
        from datetime import datetime, timezone
        from chronicle_ops.verify import MONITORING_JOBS, healthy_targets
        now = datetime(2026, 10, 31, 12, tzinfo=timezone.utc).timestamp()
        fresh = datetime.fromtimestamp(now, timezone.utc).isoformat()
        targets = [{'labels': {'job': job}, 'health': 'up', 'lastScrape': fresh} for job in sorted(MONITORING_JOBS)]
        stray = {'labels': {'job': 'institutional-node-exporter'}, 'health': 'down'}
        self.assertTrue(healthy_targets({'data': {'activeTargets': targets + [stray]}}, now))
        del targets[0]['lastScrape']
        self.assertFalse(healthy_targets({'data': {'activeTargets': targets}}, now))

    def test_doctor_monitoring_rows_follow_targets_daemons_and_the_log_canary(self):
        from datetime import datetime, timezone
        from chronicle_ops.verify import MONITORING_JOBS, monitoring_checks
        now = datetime(2026, 10, 31, 12, tzinfo=timezone.utc).timestamp()
        payload = json.dumps({'data': {'activeTargets': [
            {'labels': {'job': job}, 'health': 'up', 'lastScrape': datetime.fromtimestamp(now, timezone.utc).isoformat()}
            for job in MONITORING_JOBS]}})
        for daemons_up, delivered_on, expected in ((True, 2, ('ok', 'ok')), (False, 1, ('fail', 'ok')), (True, None, ('ok', 'fail'))):
            polls, recorded = [], []
            def compose(*args, **_kwargs):
                if args[2] == 'operational-probe':
                    recorded.append(args[-1])
                    return SimpleNamespace(returncode=0, stdout='')
                url = next(arg for arg in args if arg.startswith('http'))
                if url.endswith('/api/v1/targets'):
                    return SimpleNamespace(returncode=0, stdout=payload)
                if 'logsql' in url:
                    polls.append(url)
                    found = delivered_on is not None and len(polls) >= delivered_on
                    return SimpleNamespace(returncode=0, stdout=f'{{"failure_category":"{recorded[0]}"}}' if found else '')
                return SimpleNamespace(returncode=0 if daemons_up or 'fluent-bit' not in url else 1, stdout='')
            clock = iter(range(0, 1000, 5))
            with self.subTest(daemons_up=daemons_up, delivered_on=delivered_on), \
                 patch('chronicle_ops.verify.compose', side_effect=compose), \
                 patch('chronicle_ops.verify.time.time', return_value=now), \
                 patch('chronicle_ops.verify.time.monotonic', side_effect=lambda: next(clock)), \
                 patch('chronicle_ops.verify.time.sleep'):
                rows = monitoring_checks()
            self.assertEqual(expected, tuple(row[1] for row in rows))
            self.assertEqual(['metrics-pipeline', 'logs-pipeline'], [row[0] for row in rows])
            self.assertRegex(recorded[0], r'^doctor_[0-9a-f]{16}$')
            self.assertEqual(delivered_on or 5, len(polls))  # a 30 s window polled on a 5 s fake clock

    def test_storage_encryption_is_read_from_the_nearest_existing_directory_and_on_macos(self):
        import plistlib
        from chronicle_ops.verify import verify_backup_storage
        tree = json.dumps({'blockdevices': [{'type': 'crypt', 'children': [{'type': 'disk'}]}]})
        with tempfile.TemporaryDirectory() as folder:
            existing = Path(folder).resolve()
            def linux(args, **_kwargs):
                if args[0] == 'findmnt':
                    return SimpleNamespace(returncode=0 if args[-1] == str(existing) else 1, stdout='/dev/mapper/backups\n')
                return SimpleNamespace(returncode=0, stdout=tree)
            with patch('chronicle_ops.verify.sys.platform', 'linux'), \
                 patch('chronicle_ops.verify.run', side_effect=linux), patch('sys.stdout', io.StringIO()) as output:
                self.assertEqual(0, verify_backup_storage(existing / 'backups/not-created-yet'))
            self.assertIn('backup backing device is encrypted', output.getvalue())
            for answer, expected in (({'FileVault': True}, 0), ({'Encrypted': True}, 0), ({'FileVault': False}, 1)):
                def macos(args, **_kwargs):
                    if args[0] == 'df':
                        return SimpleNamespace(returncode=0, stdout='Filesystem 512-blocks Used Available Capacity Mounted on\n'
                                                                   '/dev/disk3s5 100 1 99 1% /System/Volumes/Data\n')
                    self.assertEqual(['diskutil', 'info', '-plist', '/dev/disk3s5'], args)
                    return SimpleNamespace(returncode=0, stdout=plistlib.dumps(answer).decode())
                with self.subTest(answer=answer), patch('chronicle_ops.verify.sys.platform', 'darwin'), \
                     patch('chronicle_ops.verify.run', side_effect=macos), patch('sys.stdout', io.StringIO()):
                    self.assertEqual(expected, verify_backup_storage(existing))
