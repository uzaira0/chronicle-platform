"""Exercise the inventory sweep against a real disposable HTTP listener."""

import contextlib
import http.server
import importlib.util
import json
import os
import subprocess
import tempfile
import threading
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("route_probes", ROOT / "tests/security/route-authorization-probes.py")
PROBES = importlib.util.module_from_spec(SPEC)
if Path(SPEC.origin).is_file():
    SPEC.loader.exec_module(PROBES)


class RouteAuthorizationProbesTest(unittest.TestCase):
    def setUp(self):
        self.assertTrue(Path(SPEC.origin).is_file(), "route inventory sweep is missing")

    @contextlib.contextmanager
    def backend(self, leak=False, captures=None, responder=None):
        seen = []

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
                seen.append((self.path, bool(self.headers.get("Authorization"))))
                if captures is not None:
                    captures.append({"method": self.command, "path": self.path, "body": body, "headers": dict(self.headers)})
                status = 200 if self.path == "/public" or leak else (
                    403 if self.headers.get("Authorization") else 401
                )
                payload = b"fixture"
                headers = {}
                if responder is not None:
                    status, payload, *extra = responder(self.path, self.headers, body)
                    headers = extra[0] if extra else {}
                self.send_response(status)
                for name, value in headers.items():
                    self.send_header(name, value)
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, *_args):
                pass

            do_POST = do_GET
            do_PUT = do_GET
            do_PATCH = do_GET
            do_DELETE = do_GET

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=lambda: server.serve_forever(poll_interval=0.05), daemon=True)
        thread.start()
        try:
            yield f"http://127.0.0.1:{server.server_port}", seen
        finally:
            server.shutdown()
            server.server_close()
            thread.join()

    def test_every_route_is_probed_and_scoped_and_admin_routes_get_extra_checks(self):
        routes = [
            {"method": "GET", "path": "/public", "auth": "PUBLIC"},
            {"method": "GET", "path": "/study/{studyId}/participant/{participantId}", "auth": "AUTHENTICATED"},
            {"method": "GET", "path": "/admin/settings", "auth": "AUTHENTICATED",
             "operation": "AdminController.getControllerSettings"},
        ]
        with self.backend() as (base, seen):
            self.assertEqual(5, PROBES.sweep(base, routes, "fixture-token", "study-b", "participant-b"))
        self.assertEqual(5, len(seen))
        self.assertIn(("/study/study-b/participant/participant-b", True), seen)
        self.assertIn(("/admin/settings", True), seen)

    def test_foreign_organization_and_user_ids_also_receive_researcher_probes(self):
        routes = [{"method": "GET", "path": "/organization/{organizationId}", "auth": "AUTHENTICATED",
                   "operation": "OrganizationController.getOrganization"},
                  {"method": "GET", "path": "/study/organization/{organizationId}", "auth": "AUTHENTICATED",
                   "operation": "StudyController.getOrgStudies"},
                  {"method": "DELETE", "path": "/principal/users/{userId}", "auth": "AUTHENTICATED",
                   "operation": "PrincipalDirectoryController.deleteUserAccount"}]
        with self.backend() as (base, seen):
            self.assertEqual(6, PROBES.sweep(base, routes, "fixture-token", "study-b", "participant-b",
                                           {"organizationId": "org-b", "userId": "user-b"}))
        self.assertEqual(3, sum(authenticated for _path, authenticated in seen))

    def test_mutating_methods_are_not_omitted(self):
        routes = [{"method": method, "path": "/study/{studyId}", "auth": "AUTHENTICATED"}
                  for method in ("POST", "PUT", "PATCH", "DELETE")]
        with self.backend() as (base, seen):
            self.assertEqual(8, PROBES.sweep(base, routes, "fixture-token", "study-b", "participant-b"))
        self.assertEqual(8, len(seen))

    def test_a_successful_unauthorized_route_fails(self):
        with self.backend(leak=True) as (base, _seen):
            with self.assertRaisesRegex(ValueError, "anonymous.*HTTP 200"):
                PROBES.sweep(base, [{"method": "GET", "path": "/private", "auth": "AUTHENTICATED"}],
                             "fixture-token", "study-b", "participant-b")

    def test_setting_reads_probe_a_setting_that_is_not_public(self):
        routes = [{"method": method, "path": "/study/{studyId}/settings/type/{settingType}", "auth": "AUTHENTICATED",
                   "operation": "StudyController.setting"} for method in ("GET", "PATCH")]
        paths = [probe["path"] for probe in PROBES.cases(routes, "study-b", "participant-b", {"settingType": "DataCollection"})]
        self.assertEqual(["/study/study-b/settings/type/Notifications"] * 2 +
                         ["/study/study-b/settings/type/DataCollection"] * 2, paths)

    def test_only_an_anonymous_form_download_may_be_redirected(self):
        routes = [{"method": "POST", "path": "/study/{studyId}/data", "auth": "AUTHENTICATED", "operation": "StudyController.download"}]
        form = lambda _method, _path: {"headers": {}, "query": [], "form": {"dataType": "UsageEvents"}}
        json_body = lambda _method, _path: {"headers": {}, "query": [], "json": {}}
        for target, request, accepted in (("/chronicle/login", form, True), ("/login", form, True),
                                          ("/chronicle/v3/study/study-b/data", form, False), ("/chronicle/login", json_body, False)):
            with self.subTest(target=target, form=request is form):
                with self.backend(responder=lambda _path, headers, _body: (403, b"") if headers.get("Authorization")
                                  else (303, b"", {"Location": target})) as (base, _seen):
                    sweep = lambda: PROBES.sweep(base, routes, "fixture-token", "study-b", "participant-b",
                                                 request_builder=request, reauthentication_path="/login")
                    if accepted:
                        self.assertEqual(2, sweep())
                    else:
                        with self.assertRaisesRegex(ValueError, "anonymous POST /study/study-b/data: HTTP 303"):
                            sweep()

    def test_new_route_without_auth_or_path_fixture_fails(self):
        for route in (
            {"method": "GET", "path": "/new", "auth": "UNDECLARED"},
            {"method": "GET", "path": "/new/{unexpectedId}", "auth": "AUTHENTICATED"},
        ):
            with self.subTest(route=route), self.assertRaises(ValueError):
                PROBES.cases([route], "study-b", "participant-b")

    def test_live_or_remote_targets_are_rejected(self):
        for base in ("http://example.org", "http://127.0.0.1/path", "https://127.0.0.1"):
            with self.subTest(base=base), self.assertRaisesRegex(ValueError, "disposable loopback"):
                PROBES.sweep(base, [], "fixture-token", "study-b", "participant-b")

    def test_schema_inputs_reach_the_request_without_changing_the_researcher(self):
        captures = []
        routes = [{"method": "POST", "path": "/study/{studyId}", "auth": "AUTHENTICATED"}]
        inputs = {"json": {"participantId": "participant-b"}, "query": [("limit", "1")],
                  "headers": {"If-Match": '"1"', "Idempotency-Key": "fixture-request"}}
        with self.backend(captures=captures) as (base, _seen):
            self.assertEqual(2, PROBES.sweep(base, routes, "fixture-token", "study-b", "participant-b",
                                           request_builder=lambda _method, _path: inputs))
        request = captures[1]
        self.assertEqual("/study/study-b?limit=1", request["path"])
        self.assertEqual({"participantId": "participant-b"}, json.loads(request["body"]))
        self.assertEqual('"1"', request["headers"]["If-Match"])
        self.assertEqual("Bearer fixture-token", request["headers"]["Authorization"])
        inputs["headers"]["Authorization"] = "Bearer another-principal"
        with self.backend() as (base, _seen), self.assertRaisesRegex(ValueError, "cannot change"):
            PROBES.sweep(base, routes, "fixture-token", "study-b", "participant-b",
                         request_builder=lambda _method, _path: inputs)

    def test_nested_resource_ids_require_real_fixture_bindings(self):
        routes = [{"method": "GET", "path": "/study/{studyId}/keys/{keyId}", "auth": "AUTHENTICATED"}]
        with self.assertRaisesRegex(ValueError, "Missing path fixtures"):
            PROBES.cases(routes, "study-b", "participant-b")
        self.assertEqual(2, len(PROBES.cases(routes, "study-b", "participant-b", {"keyId": "real-key"})))

    def test_self_principals_uses_the_reflected_owner_and_exact_actor_set(self):
        routes = [{"method": "GET", "path": "/admin/principals", "auth": "AUTHENTICATED",
                   "operation": "AdminController.getCurrentUserPrincipals"},
                  {"method": "GET", "path": "/admin/principals/{id}", "auth": "AUTHENTICATED",
                   "operation": "AdminController.getUserPrincipals"}]
        actor = {"principals": [{"id": "actor-a", "type": "USER"}, {"id": "group-a", "type": "GROUP"}]}
        def respond(path, headers, _body):
            if not headers.get("Authorization"):
                return 401, b"denied"
            if path == "/admin/principals":
                return 200, json.dumps(list(reversed(actor["principals"]))).encode()
            return 403, b"denied"
        with self.backend(responder=respond) as (base, _seen):
            self.assertEqual(4, PROBES.sweep(base, routes, "fixture-token", "study-b", "participant-b",
                                           {"id": "actor-b"}, actor_fixtures=actor))
        for bad in ([{"id": "actor-b", "type": "USER"}], actor["principals"] + [{"id": "extra", "type": "GROUP"}]):
            with self.backend(responder=lambda _p, h, _b: (200, json.dumps(bad).encode()) if h.get("Authorization")
                              else (401, b"denied")) as (base, _seen), self.assertRaisesRegex(ValueError, "principal set"):
                PROBES.sweep(base, routes[:1], "fixture-token", "study-b", "participant-b", actor_fixtures=actor)
        with self.backend(responder=lambda _p, h, _b: (200, json.dumps(actor["principals"]).encode()) if h.get("Authorization")
                          else (403, b"denied")) as (base, _seen), self.assertRaisesRegex(ValueError, "anonymous.*HTTP 403"):
            PROBES.sweep(base, routes[:1], "fixture-token", "study-b", "participant-b", actor_fixtures=actor)
        denied = [{**routes[0], "auth": "DENY"}]
        self.assertEqual(["anonymous", "denied"], [p["label"] for p in PROBES.cases(denied, "study-b", "participant-b")])

    def test_native_cross_denial_requires_actor_own_success_first(self):
        routes = [{"method": "POST", "path": "/study/{studyId}/participant/{participantId}/usage", "auth": "AUTHENTICATED"},
                  {"method": "GET", "path": "/study/{studyId}/participant/{participantId}/status", "auth": "AUTHENTICATED",
                   "operation": "MobileReminderController.getParticipationStatus"}]
        actor = {"studyId": "study-a", "participantId": "participant-a", "nativeHeaders": {"X-Api-Key": "actor-key"}}
        def inputs(participant, method):
            return {"query": [], "headers": {"X-Api-Key": "actor-key"},
                    **({"json": {"participantId": participant}} if method == "POST" else {})}
        def respond(path, headers, body):
            self.assertIsNone(headers.get("Authorization"), "native requests must never mix bearer and API key")
            if not headers.get("X-Api-Key"):
                return 401, b"denied"
            self.assertEqual("actor-key", headers["X-Api-Key"])
            own = path.startswith("/study/study-a/")
            if not path.endswith("/status"):
                self.assertEqual("participant-a" if own else "participant-b", json.loads(body)["participantId"])
            return (204 if own else 403), b""
        captures = []
        with self.backend(responder=respond, captures=captures) as (base, seen):
            self.assertEqual(6, PROBES.sweep(base, routes, "fixture-token", "study-b", "participant-b",
                request_builder=lambda m, _p: inputs("participant-b", m), actor_fixtures=actor,
                actor_request_builder=lambda m, _p: inputs("participant-a", m)))
        self.assertTrue(all(not authenticated for _path, authenticated in seen))
        self.assertEqual("GET", captures[1]["method"])
        self.assertTrue(captures[1]["path"].endswith("/status"), "native own control must be the nonmutating status read")
        self.assertFalse(any(c["method"] != "GET" and "/study/study-a/" in c["path"] for c in captures))
        self.assertIn("study-a", seen[1][0])
        self.assertIn("study-b", seen[2][0])
        with self.backend(responder=lambda _p, _h, _b: (401, b"bad credentials")) as (base, seen):
            with self.assertRaisesRegex(ValueError, "own-resource control.*HTTP 401"):
                PROBES.sweep(base, routes, "fixture-token", "study-b", "participant-b",
                    request_builder=lambda m, _p: inputs("participant-b", m), actor_fixtures=actor,
                    actor_request_builder=lambda m, _p: inputs("participant-a", m))
        self.assertEqual(2, len(seen), "a refused own control cannot count a foreign-resource refusal")
        for bad in (400, 401):
            with self.backend(responder=lambda p, h, _b: (204 if p.startswith("/study/study-a/") else bad,
                              b"") if h.get("X-Api-Key") else (401, b"denied")) as (base, _seen):
                with self.assertRaisesRegex(ValueError, f"cross-study.*HTTP {bad}"):
                    PROBES.sweep(base, routes, "fixture-token", "study-b", "participant-b",
                        request_builder=lambda m, _p: inputs("participant-b", m), actor_fixtures=actor,
                        actor_request_builder=lambda m, _p: inputs("participant-a", m))

    def test_anonymous_scoped_requests_have_valid_inputs_without_any_native_credentials(self):
        routes = [{"method": "POST", "path": "/study/{studyId}/participant/{participantId}/usage", "auth": "AUTHENTICATED"},
                  {"method": "GET", "path": "/study/{studyId}/participant/{participantId}/status", "auth": "AUTHENTICATED",
                   "operation": "MobileReminderController.getParticipationStatus"}]
        actor = {"studyId": "study-a", "participantId": "participant-a", "nativeHeaders": {"X-Api-Key": "actor-key"}}
        inputs = lambda _m, _p: {"json": {"required": "valid"}, "query": [("required", "valid")],
                                 "headers": {"X-Api-Key": "actor-key", "If-Match": "revision"}}
        captures = []
        def respond(path, headers, _body):
            return (204 if path.startswith("/study/study-a/") else 403, b"") if headers.get("X-Api-Key") else (401, b"")
        with self.backend(responder=respond, captures=captures) as (base, _seen):
            PROBES.sweep(base, routes, "fixture-token", "study-b", "participant-b", request_builder=inputs,
                         actor_fixtures=actor, actor_request_builder=inputs)
        self.assertEqual({"required": "valid"}, json.loads(captures[0]["body"]))
        self.assertIn("?required=valid", captures[0]["path"])
        self.assertNotIn("X-Api-Key", captures[0]["headers"])
        self.assertEqual("revision", captures[0]["headers"]["If-Match"])

    def test_request_context_merges_operation_state_but_uses_only_actor_native_credentials(self):
        target = {"studyId": "study-b", "nativeHeaders": {"X-Api-Key": "target-key"},
                  "headers": {"if-match": "old", "X-API-KEY": "target-key"}, "query": {"global": 1},
                  "operations": {"POST /study/{studyId}": {"headers": {"If-Match": "revision-b"},
                                                          "query": {"operation": 2}, "body": {"studyId": "study-b"}}}}
        actor = {"nativeHeaders": {"X-Api-Key": "actor-key", "X-Source-Device": "actor-device"}}
        context = PROBES.request_context(target, actor, "POST", "/study/{studyId}")
        self.assertEqual({"if-match": "revision-b", "x-api-key": "actor-key", "x-source-device": "actor-device"},
                         {name.lower(): value for name, value in context["headers"].items()})
        self.assertEqual({"global": 1, "operation": 2}, context["query"])
        self.assertEqual({"studyId": "study-b"}, context["body"])
        self.assertNotIn("nativeHeaders", context)
        self.assertEqual("target-key", target["headers"]["X-API-KEY"])

    def test_schemathesis_runs_the_researcher_get_surface_privately(self):
        scratch = ROOT / "build/operator-test-runs"
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as directory:
            folder = Path(directory)
            command = folder / "schemathesis"
            command.write_text(
                '#!/usr/bin/env python3\nimport json, os, sys\n'
                'from pathlib import Path\n'
                'args = sys.argv[1:]\n'
                'assert "SCHEMATHESIS_HOOKS" not in os.environ, "inherited authentication hook"\n'
                'assert not Path(os.environ["NETRC"]).read_text(), "inherited netrc authentication"\n'
                'assert os.environ["CHRONICLE_AUTH_TOKEN"] not in " ".join(args), "credential leaked in argv"\n'
                'config = open(args[args.index("--config-file") + 1]).read()\n'
                'authenticated = "Authorization" in config\n'
                'if authenticated: assert "${CHRONICLE_AUTH_TOKEN}" in config\n'
                'with open(os.environ["SCHEMA_CALLS"], "a") as handle:\n'
                '    handle.write(json.dumps({"authenticated": authenticated, '
                '"method_filter": "--include-method" in args, "proxy": os.environ.get("NO_PROXY")}) + "\\n")\n'
                'report = Path(args[args.index("--report-dir") + 1])\n'
                'report.mkdir(parents=True, exist_ok=True)\n'
                '(report / "fixture.xml").write_text("synthetic-body-secret")\n'
                'print("synthetic-body-secret")\n'
                'sys.exit(1 if authenticated else 0)\n'
            )
            command.chmod(0o755)
            calls = folder / "calls.jsonl"
            result = subprocess.run(
                ["bash", str(ROOT / "tests/api-contract/run-schemathesis.sh")],
                env={**os.environ, "PATH": str(folder) + os.pathsep + os.environ["PATH"],
                     "CHRONICLE_BASE_URL": "http://127.0.0.1:1", "CHRONICLE_AUTH_TOKEN": "fixture-token",
                     "SCHEMA_CALLS": str(calls), "CHRONICLE_SCHEMATHESIS_REPORT_DIR": str(folder / "reports"),
                     "SCHEMATHESIS_HOOKS": "ambient_auth_fixture", "NETRC": str(folder / "ambient.netrc")}, capture_output=True, text=True, check=False,
            )
            self.assertEqual(1, result.returncode, result.stderr)
            self.assertTrue(calls.exists(), result.stderr)
            self.assertNotIn("synthetic-body-secret", result.stdout + result.stderr)
            reports = folder / "reports"
            self.assertEqual(0o700, reports.stat().st_mode & 0o777)
            for artifact in reports.rglob("*"):
                self.assertEqual(0o700 if artifact.is_dir() else 0o600, artifact.stat().st_mode & 0o777)
            self.assertEqual(1, len(list(reports.rglob("cli.log"))))
            self.assertEqual([{"authenticated": True, "method_filter": True, "proxy": "*"}],
                             [json.loads(line) for line in calls.read_text().splitlines()])


if __name__ == "__main__":
    unittest.main()
