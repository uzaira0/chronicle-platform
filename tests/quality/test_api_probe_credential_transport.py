"""Synthetic loopback requests keep probe credentials out of real curl arguments."""

import base64
import contextlib
import http.server
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import tempfile
import threading
import unittest

ROOT = Path(__file__).resolve().parents[2]


class ApiProbeCredentialTransportTest(unittest.TestCase):
    @contextlib.contextmanager
    def fixture(self):
        scratch = ROOT / "build/operator-test-runs"
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as directory:
            folder = Path(directory)
            secret, bearer = 'synthetic-internal-"quoted"\\value', 'synthetic-bearer-"quoted"\\value'
            metrics_password = 'synthetic-metrics-"quoted"\\value'
            captures = []
            class Handler(http.server.BaseHTTPRequestHandler):
                def do_GET(self):
                    body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
                    captures.append({"path": self.path, "headers": dict(self.headers), "body": body})
                    if self.path.endswith("/auth/testing-login"):
                        status, payload = (200, b'{"authToken":"synthetic-issued-token"}') if self.headers.get("X-Chronicle-Internal-Web") == secret else (401, b"{}")
                    elif self.path == "/chronicle/v3/":
                        status, payload = 200, b"{}"
                    elif self.path == "/chronicle/internal/health/ready":
                        status, payload = 204, b""
                    elif self.path == "/health":
                        status, payload = 200, b"healthy"
                    elif self.path == "/prometheus/":
                        expected = "Basic " + base64.b64encode(("chronicle-metrics:" + metrics_password).encode()).decode()
                        status, payload = (200, b"metrics") if self.headers.get("Authorization") == expected else (401, b"{}")
                    elif self.path.startswith("http://remote-proxy-fixture.invalid:"):
                        status, payload = 204, b""
                    elif self.headers.get("Authorization") != "Bearer " + bearer:
                        status, payload = 401, b"{}"
                    else:
                        status, payload = (200 if self.path.endswith("/study/study-a/participants") else 403), b"{}"
                    self.send_response(status)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(payload)))
                    self.send_header("Connection", "close")
                    self.end_headers()
                    self.wfile.write(payload)
                do_POST = do_GET
                def log_message(self, *_args):
                    pass
            server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
            thread = threading.Thread(target=lambda: server.serve_forever(poll_interval=0.05), daemon=True)
            thread.start()
            real_curl = shutil.which("curl")
            self.assertIsNotNone(real_curl, "curl is a required probe tool")
            wrapper = folder / "curl"
            wrapper.write_text(
                '#!/usr/bin/env python3\nimport json,os,sys\n'
                'args=sys.argv[1:]\n'
                'safe=all(not os.environ.get(name) or os.environ[name] not in " ".join(args) for name in '
                '("AUTH_TOKEN","CHRONICLE_INTERNAL_WEB_SECRET","METRICS_FIXTURE_PASSWORD"))\n'
                'if os.environ.get("CURL_OBSERVE_ONLY")!="true":\n'
                ' assert safe, "credential leaked in curl argv"\n'
                ' assert "--noproxy" in args and args[args.index("--noproxy")+1]=="*"\n'
                ' assert "--max-time" in args and "--connect-timeout" in args\n'
                'with open(os.environ["CURL_ARGV_PROOF"],"a") as h: h.write(json.dumps({"safe":safe})+"\\n")\n'
                'if os.environ.get("CURL_TEST_RESOLVE"):\n'
                ' prefix=1 if args and args[0]=="-q" else 0\n'
                ' args[prefix:prefix]=["--resolve",os.environ["CURL_TEST_RESOLVE"]]\n'
                'os.execv(' + repr(real_curl) + ', [' + repr(real_curl) + '] + args)\n'
            )
            wrapper.chmod(0o700)
            environment = {**os.environ, "PATH": str(folder) + os.pathsep + os.environ["PATH"],
                           "BASE_URL": f"http://127.0.0.1:{server.server_port}", "AUTH_TOKEN": bearer,
                           "CHRONICLE_INTERNAL_WEB_SECRET": secret, "STUDY_A": "study-a", "STUDY_B": "study-b",
                           "METRICS_FIXTURE_PASSWORD": metrics_password,
                           "CURL_OBSERVE_ONLY": "false", "CURL_TEST_RESOLVE": "",
                           "PARTICIPANT_ID": "participant-b", "CURL_ARGV_PROOF": str(folder / "argv.jsonl")}
            try:
                yield folder, environment, captures
            finally:
                server.shutdown()
                server.server_close()
                thread.join()

    @contextlib.contextmanager
    def inherited_proxy(self):
        with self.fixture() as (folder, environment, captures), self.fixture() as (
            _proxy_folder, proxy_environment, proxy_captures
        ):
            commands, home, work = (folder / name for name in ("commands", "home", "work"))
            for path in (commands, home, work):
                path.mkdir()
            (home / ".curlrc").write_text('header = "X-Fixture-Curlrc: ambient"\n')
            proxy, target = proxy_environment["BASE_URL"], environment["BASE_URL"]
            environment.update(
                PATH=str(commands) + os.pathsep + environment["PATH"], CURL_OBSERVE_ONLY="true",
                HOME=str(home), CURL_HOME=str(home), XDG_CONFIG_HOME=str(home), TMPDIR=str(work),
                http_proxy=proxy, https_proxy=proxy, all_proxy=proxy,
                HTTP_PROXY=proxy, HTTPS_PROXY=proxy, ALL_PROXY=proxy, NO_PROXY="", no_proxy="",
            )
            real_curl = shutil.which("curl")
            self.assertIsNotNone(real_curl, "curl is required by the readiness probe")
            control = subprocess.run(
                [real_curl, "-q", "--proxy", proxy, "--noproxy", "", "--silent", "--show-error",
                 "--max-time", "5", "-o", os.devnull, "-w", "%{http_code}", target + "/chronicle/internal/health/ready"],
                env=environment, capture_output=True, text=True, check=True, timeout=10,
            )
            self.assertEqual("401", control.stdout)
            self.assertEqual(1, len(proxy_captures))
            self.assertEqual([], captures)
            proxy_captures.clear()
            yield folder, environment, captures, proxy_captures

    def function_source(self, owner, name):
        source = (ROOT / owner).read_text()
        start = source.index(name + "() {\n")
        return source[start:source.index("\n}\n", start) + 3]

    def request_command(self, source, identifier):
        lines = [line.strip() for line in source.splitlines() if identifier in line and line.strip().startswith("if ")]
        self.assertEqual(1, len(lines))
        command = lines[0].removeprefix("if ! ").removeprefix("if ").removesuffix("; then")
        self.assertTrue(command.startswith("curl "))
        return command

    def run_fragment(self, folder, environment, body, setup=""):
        script = folder / "fragment.sh"
        script.write_text('set -euo pipefail\nlog() { :; }\ndocker() { :; }\n' + setup +
                          '\nprobe() {\n' + body + '\n}\nprobe\n')
        return subprocess.run(["bash", str(script)], env=environment, capture_output=True, text=True, timeout=15)

    def assert_local_transport(self, result, captures, proxy_captures):
        self.assertEqual(0, result.returncode, result.stdout + result.stderr +
                         f"direct requests={len(captures)}; proxy requests={len(proxy_captures)}")
        self.assertEqual(1, len(captures))
        self.assertNotIn("X-Fixture-Curlrc", captures[0]["headers"])
        self.assertEqual([], proxy_captures)

    def token_script(self, folder):
        source = (ROOT / "tests/security/backend-api-probes.sh").read_text()
        start = source.index("token_for() {\n")
        end = source.index("\n}\n", start) + 3
        script = folder / "token.sh"
        script.write_text('set -euo pipefail\nbackend="$BASE_URL"\n' + source[start:end] +
                          '\ntoken_for test_user1 > "$TOKEN_OUTPUT"\n')
        return script

    def test_testing_login_internal_header_uses_stdin_config(self):
        with self.fixture() as (folder, environment, captures):
            token = folder / "token.txt"
            result = subprocess.run(["bash", str(self.token_script(folder))],
                                    env={**environment, "TOKEN_OUTPUT": str(token)}, capture_output=True, text=True, timeout=20)
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertEqual("synthetic-issued-token", token.read_text().strip())
            self.assertEqual(1, len(captures))
            self.assertEqual(environment["CHRONICLE_INTERNAL_WEB_SECRET"], captures[0]["headers"]["X-Chronicle-Internal-Web"])
            self.assertNotIn(environment["CHRONICLE_INTERNAL_WEB_SECRET"], result.stdout + result.stderr)

    def test_business_probes_authenticate_without_bearer_in_curl_argv(self):
        with self.fixture() as (_folder, environment, captures):
            result = subprocess.run(["bash", str(ROOT / "tests/security/business-logic-tests.sh")],
                                    env=environment, capture_output=True, text=True, timeout=30)
            self.assertEqual(0, result.returncode, result.stdout + result.stderr)
            self.assertEqual(9, len(captures))
            self.assertEqual(6, sum(row["headers"].get("Authorization") == "Bearer " + environment["AUTH_TOKEN"] for row in captures))
            self.assertNotIn(environment["AUTH_TOKEN"], result.stdout + result.stderr)

    def test_internal_header_rejects_line_break_before_curl(self):
        with self.fixture() as (folder, environment, captures):
            result = subprocess.run(["bash", str(self.token_script(folder))],
                                    env={**environment, "TOKEN_OUTPUT": str(folder / "token.txt"),
                                         "CHRONICLE_INTERNAL_WEB_SECRET": "synthetic\r\nInjected: value"},
                                    capture_output=True, text=True, timeout=20)
            self.assertNotEqual(0, result.returncode)
            self.assertEqual([], captures)

    def test_web_e2e_readiness_ignores_inherited_proxy_and_curl_config(self):
        with self.inherited_proxy() as (folder, environment, captures, proxy_captures):
            project = folder / "project"
            (project / "scripts").mkdir(parents=True)
            (project / "chronicle-web").mkdir()
            script = project / "scripts/run-web-e2e.sh"
            shutil.copy2(ROOT / "scripts/run-web-e2e.sh", script)
            commands = folder / "commands"
            gradle = project / "gradlew"
            gradle.write_text(
                '#!/usr/bin/env python3\nfrom pathlib import Path\nimport os,sys,time\n'
                'assert ":chronicle-server:test" in sys.argv\n'
                'done=Path(next(arg.split("=",1)[1] for arg in sys.argv if arg.startswith("-Dchronicle.playwright.backend.doneFile=")))\n'
                'deadline=time.monotonic()+5\n'
                'while not done.exists() and time.monotonic()<deadline: time.sleep(0.01)\n'
                'Path(os.environ["BACKEND_EXIT_PROOF"]).write_text(str(done.exists()))\n'
                'sys.exit(0 if done.exists() else 7)\n'
            )
            gradle.chmod(0o700)
            browser = commands / "bunx"
            browser.write_text(
                '#!/usr/bin/env python3\nfrom pathlib import Path\nimport os,sys\n'
                'assert sys.argv[1:3]==["playwright","test"]\n'
                'Path(os.environ["BROWSER_PROBE_MARKER"]).write_text("fake browser invoked")\n'
            )
            browser.chmod(0o700)
            work = folder / "work"
            target = environment["BASE_URL"]
            environment.update(
                GRADLE_USER_HOME=str(folder / "gradle"),
                CHRONICLE_TEST_HTTP_PORT=target.rsplit(":", 1)[1],
                BACKEND_EXIT_PROOF=str(folder / "backend-exit"), BROWSER_PROBE_MARKER=str(folder / "browser-invoked"),
            )
            result = subprocess.run(["bash", str(script)], env=environment, capture_output=True, text=True, timeout=15)
            if result.returncode:
                self.assertGreater(len(proxy_captures), 0, "readiness failure did not exercise the inherited proxy")
                self.assertEqual([], captures)
            self.assertEqual(0, result.returncode, result.stdout + result.stderr +
                             f"direct requests={len(captures)}; proxy requests={len(proxy_captures)}")
            self.assertTrue((folder / "browser-invoked").is_file())
            self.assertEqual("True", (folder / "backend-exit").read_text())
            self.assertEqual(["/chronicle/internal/health/ready"], [row["path"] for row in captures])
            self.assertNotIn("X-Fixture-Curlrc", captures[0]["headers"])
            self.assertEqual([], proxy_captures)
            self.assertEqual([], list(work.iterdir()))

    def test_deploy_local_readiness_ignores_inherited_proxy_and_curl_config(self):
        wait = self.function_source("scripts/deploy.sh", "wait_for_healthy")
        verify = self.function_source("scripts/deploy.sh", "verify_deployment")
        calls = (
            (self.request_command(wait, '"${url}"'), 'url="$BASE_URL/chronicle/internal/health/ready"'),
            (self.request_command(verify, "http://127.0.0.1:40320/").replace(
                "http://127.0.0.1:40320", '"$BASE_URL"'), ""),
            (self.request_command(verify, "http://127.0.0.1:8080/").replace(
                "http://127.0.0.1:8080", '"$BASE_URL"'), ""),
        )
        for command, setup in calls:
            with self.subTest(command=command), self.inherited_proxy() as (folder, environment, captures, proxy_captures):
                result = self.run_fragment(folder, environment, command, setup)
                self.assert_local_transport(result, captures, proxy_captures)

    def test_ci_local_readiness_ignores_inherited_proxy_and_curl_config(self):
        source = self.function_source("scripts/local-ci.sh", "run_ci_smoke_stack")
        for identifier in ('"${backend_url}/chronicle/internal/health/ready"', '"${frontend_url}/health"'):
            with self.subTest(listener=identifier), self.inherited_proxy() as (folder, environment, captures, proxy_captures):
                result = self.run_fragment(folder, environment, self.request_command(source, identifier),
                                           'backend_url="$BASE_URL"\nfrontend_url="$BASE_URL"')
                self.assert_local_transport(result, captures, proxy_captures)

    def metrics_fragment(self):
        source = self.function_source("scripts/local-ci.sh", "run_ci_smoke_stack")
        start = source.index('  metrics_password=')
        return source[start:source.index('\n  log "waiting for frontend"', start)]

    def test_ci_metrics_password_stays_out_of_curl_argv(self):
        with self.inherited_proxy() as (folder, environment, captures, proxy_captures):
            secrets = folder / "secrets"
            secrets.mkdir(mode=0o700)
            password = environment["METRICS_FIXTURE_PASSWORD"]
            secret = secrets / "chronicle_security_metrics_password"
            secret.write_text(password)
            secret.chmod(0o600)
            environment.update(NO_PROXY="*", no_proxy="*")
            result = self.run_fragment(folder, environment, self.metrics_fragment(),
                                       'backend_url="$BASE_URL"\nsecrets_dir=' + shlex.quote(str(secrets)))
            self.assertEqual(0, result.returncode, result.stdout + result.stderr)
            records = [json.loads(line) for line in Path(environment["CURL_ARGV_PROOF"]).read_text().splitlines()]
            self.assertTrue(records and all(row["safe"] for row in records), "metrics password reached curl argv")
            self.assertFalse(password in result.stdout + result.stderr, "metrics password reached probe logs")
            self.assert_local_transport(result, captures, proxy_captures)
            expected = "Basic " + base64.b64encode(("chronicle-metrics:" + password).encode()).decode()
            self.assertTrue(captures[0]["headers"].get("Authorization") == expected, "Basic authentication changed")

    def test_ci_metrics_rejects_line_break_before_curl(self):
        with self.inherited_proxy() as (folder, environment, captures, proxy_captures):
            secrets = folder / "secrets"
            secrets.mkdir(mode=0o700)
            secret = secrets / "chronicle_security_metrics_password"
            secret.write_text(environment["METRICS_FIXTURE_PASSWORD"] + "\nInjected: value")
            secret.chmod(0o600)
            environment.update(NO_PROXY="*", no_proxy="*")
            result = self.run_fragment(folder, environment, self.metrics_fragment(),
                                       'backend_url="$BASE_URL"\nsecrets_dir=' + shlex.quote(str(secrets)))
            self.assertNotEqual(0, result.returncode)
            self.assertEqual(0, len(captures), "invalid credential reached the HTTP endpoint")
            self.assertEqual([], proxy_captures)
            self.assertFalse(Path(environment["CURL_ARGV_PROOF"]).exists(), "invalid credential reached curl")

    def smoke_fragment(self, target, function):
        codes = "204" if function == "check_http" else "500,502,503"
        source = (ROOT / "scripts/smoke-test.sh").read_text()
        return (source[:source.index("\n#  Main\n")] +
                '\n' + function + ' fixture "' + target + '" "' + codes + '"\n((FAIL == 0))')

    def test_smoke_loopback_readiness_ignores_inherited_proxy_and_curl_config(self):
        for function in ("check_http", "check_not_status"):
            with self.subTest(function=function), self.inherited_proxy() as (folder, environment, captures, proxy_captures):
                result = self.run_fragment(folder, environment,
                                           self.smoke_fragment('$BASE_URL/chronicle/internal/health/ready', function),
                                           "PASS=0 FAIL=0 TOTAL=0 GREEN='' RED='' NC=''")
                if function == "check_not_status":
                    self.assertEqual(0, result.returncode, result.stdout + result.stderr)
                    self.assertEqual(1, len(captures), "status-exclusion probe passed without reaching the requested listener")
                self.assert_local_transport(result, captures, proxy_captures)

    def test_smoke_remote_url_retains_configured_proxy_transport(self):
        for function in ("check_http", "check_not_status"):
            with self.subTest(function=function), self.inherited_proxy() as (folder, environment, captures, proxy_captures):
                port = environment["BASE_URL"].rsplit(":", 1)[1]
                remote = f"http://remote-proxy-fixture.invalid:{port}/chronicle/internal/health/ready"
                environment['CURL_TEST_RESOLVE'] = f"remote-proxy-fixture.invalid:{port}:127.0.0.1"
                result = self.run_fragment(folder, environment, self.smoke_fragment(remote, function),
                                           "PASS=0 FAIL=0 TOTAL=0 GREEN='' RED='' NC=''")
                self.assertEqual(0, result.returncode, result.stdout + result.stderr)
                self.assertEqual([], captures, "remote URL bypassed its configured proxy")
                self.assertEqual([remote], [row["path"] for row in proxy_captures])
                self.assertNotIn("X-Fixture-Curlrc", proxy_captures[0]["headers"])

    def test_smoke_remote_no_proxy_matches_curl_wildcard_and_case_precedence(self):
        cases = (
            ("uppercase wildcard", None, "*", True),
            ("lowercase wildcard", "*", "unrelated.invalid", True),
            ("empty lowercase falls back", "", "*", True),
            ("lowercase list takes precedence", "unrelated.invalid", "*", False),
            ("lowercase host list", "remote-proxy-fixture.invalid", "unrelated.invalid", True),
            ("uppercase host list", None, "remote-proxy-fixture.invalid", True),
        )
        for function in ("check_http", "check_not_status"):
            for name, lowercase, uppercase, bypass in cases:
                with self.subTest(function=function, case=name), self.inherited_proxy() as (
                    folder, environment, captures, proxy_captures
                ):
                    port = environment["BASE_URL"].rsplit(":", 1)[1]
                    remote = f"http://remote-proxy-fixture.invalid:{port}/chronicle/internal/health/ready"
                    resolve = f"remote-proxy-fixture.invalid:{port}:127.0.0.1"
                    environment.update(NO_PROXY=uppercase, CURL_TEST_RESOLVE=resolve)
                    if lowercase is None:
                        environment.pop("no_proxy")
                    else:
                        environment["no_proxy"] = lowercase
                    control = subprocess.run(
                        [shutil.which("curl"), "-q", "--resolve", resolve, "--silent", "--show-error",
                         "--connect-timeout", "3", "--max-time", "5", "-o", os.devnull,
                         "-w", "%{http_code}", remote],
                        env=environment, capture_output=True, text=True, check=True, timeout=10,
                    )
                    self.assertEqual("204", control.stdout)
                    self.assertEqual(int(bypass), len(captures), "raw curl direct route changed")
                    self.assertEqual(int(not bypass), len(proxy_captures), "raw curl proxy route changed")
                    captures.clear()
                    proxy_captures.clear()
                    result = self.run_fragment(folder, environment, self.smoke_fragment(remote, function),
                                               "PASS=0 FAIL=0 TOTAL=0 GREEN='' RED='' NC=''")
                    self.assertEqual(0, result.returncode, result.stdout + result.stderr)
                    self.assertEqual(int(bypass), len(captures), "smoke changed curl's remote NO_PROXY bypass")
                    self.assertEqual(int(not bypass), len(proxy_captures), "smoke changed curl's remote proxy selection")
                    self.assertNotIn("X-Fixture-Curlrc", (captures or proxy_captures)[0]["headers"])


if __name__ == "__main__":
    unittest.main()
