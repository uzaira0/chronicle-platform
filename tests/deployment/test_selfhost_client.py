"""Real HTTP controls for the generated upload ceiling and public mobile canary."""
import http.server
import importlib.util
import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch
import uuid

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('selfhost_client', Path(__file__).with_name('selfhost-client.py'))
client = importlib.util.module_from_spec(spec)
spec.loader.exec_module(client)
from chronicle_ops.mobile_canary import CANARY_ROUTES, verify_canary
from chronicle_ops.route_surface import ProbeKind, RouteProbe
from chronicle_ops.verify import send_canary


class MobileEdge(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        size = int(self.headers['Content-Length'])
        status = 413 if size > client.MAX_REQUEST_SIZE_BYTES else 403 if self.server.block_posts else 200
        if status == 200:
            body = self.rfile.read(size)
            self.server.body_sizes.append(len(body))
            response = {'apiKey': self.server.credential} if self.path.endswith(CANARY_ROUTES['enrollment']) else len(json.loads(body))
        else:
            response = None
        data = json.dumps(response).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(data)))
        self.end_headers(); self.wfile.write(data)

    def log_message(self, *args):
        pass


class ResearcherApi(http.server.BaseHTTPRequestHandler):
    """Answers like CreateReceiptFilter and the settings preconditions: 428 without the key or revision."""
    def reply(self, status, body=None, etag=None):
        data = json.dumps(body).encode() if body is not None else b''
        self.send_response(status)
        if etag is not None:
            self.send_header('Etag', f'"{etag}"')
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(data)))
        self.end_headers(); self.wfile.write(data)

    def do_POST(self):
        self.rfile.read(int(self.headers['Content-Length']))
        self.server.keys.append(self.headers.get('Idempotency-Key'))
        if self.path == '/api/study' and not self.headers.get('Idempotency-Key'):
            return self.reply(428)
        self.reply(200, str(uuid.uuid4()))

    def do_GET(self):
        self.reply(200, {}, self.server.revision)

    def do_PATCH(self):
        self.rfile.read(int(self.headers['Content-Length']))
        precondition = self.headers.get('If-Match')
        if precondition is None:
            return self.reply(428)
        if precondition != f'"{self.server.revision}"':
            return self.reply(412)
        self.server.revision += 1
        self.reply(200, {}, self.server.revision)

    def log_message(self, *args):
        pass


class ResearcherClientTests(unittest.TestCase):
    def test_creates_carry_a_fresh_key_and_settings_edits_chain_the_revision(self):
        server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), ResearcherApi)
        server.keys, server.revision = [], 7
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        api = f'http://127.0.0.1:{server.server_port}/api'
        opener, now = client.client(), client.datetime.now(client.timezone.utc)
        study = client.create_study(opener, {}, api, now)
        client.create_study(opener, {}, api, now)
        client.configure_study(opener, {}, api, study, 'https://public.example.org', now)
        self.assertEqual(9, server.revision)
        self.assertEqual(2, len(set(server.keys)))
        with self.assertRaises(ValueError):
            client.request(opener, api + '/study/' + study + '/settings/type/DataCollection', 'PATCH', {})


class ProbeFixtureApi(ResearcherApi):
    """Disposable HTTP resources with parent ownership and independent entity revisions."""
    def body(self):
        return json.loads(self.rfile.read(int(self.headers.get('Content-Length', 0))) or b'null')

    def do_POST(self):
        body = self.body()
        if not self.headers.get('Idempotency-Key'):
            return self.reply(428)
        self.server.keys.append(self.headers['Idempotency-Key'])
        path = self.path
        if path == '/chronicle/v3/organization':
            self.server.organization = str(uuid.uuid4())
            return self.reply(200, self.server.organization)
        if path == '/chronicle/v3/study':
            self.server.study = str(uuid.uuid4())
            self.server.study_body = {**body, 'id': self.server.study}
            return self.reply(200, self.server.study)
        study = self.server.study
        if path == f'/chronicle/v3/study/{study}/webhooks':
            if self.server.enrolled:
                return self.reply(409)
            self.server.webhook = str(uuid.uuid4())
            self.server.webhook_body = body
            return self.reply(200, {'webhookId': self.server.webhook, 'studyId': study, **body})
        if path == f'/chronicle/v3/survey/{study}/questionnaire':
            self.server.questionnaire = str(uuid.uuid4())
            self.server.questionnaire_body = {**body, 'id': self.server.questionnaire}
            return self.reply(200, self.server.questionnaire)
        if path == f'/chronicle/v3/study/{study}/api-keys':
            self.server.key = str(uuid.uuid4())
            return self.reply(200, {'keyId': self.server.key, 'rawKey': self.server.credential,
                                    'info': {'keyId': self.server.key, 'studyId': study, **body}})
        if path == f'/chronicle/v3/study/{study}/participant':
            self.server.participants.add(body['participantId'])
            return self.reply(200, {})
        if path.endswith('/form-access-codes'):
            participant = path.split('/')[-2]
            if participant not in self.server.participants:
                return self.reply(404)
            return self.reply(200, {'accessCode': self.server.enrollment_code})
        if path.endswith('/enroll'):
            if (self.headers.get(client.ENROLLMENT_CODE_HEADER) != self.server.enrollment_code
                    or self.headers.get(client.MANIFEST_HEADER) != self.server.digest):
                return self.reply(403)
            self.server.source_device = body['randomDeviceId']
            self.server.enrolled = True
            return self.reply(200, {'chronicleId': self.server.device, 'apiKey': self.server.credential})
        if path.endswith('/collection-ack'):
            if self.headers.get(client.API_KEY_HEADER) != self.server.credential:
                return self.reply(403)
            return self.reply(200, {})
        if path.endswith('/participants/purge'):
            participant = body['participantId']
            if participant not in self.server.participants or body['confirmationToken'] != 'confirm-' + participant:
                return self.reply(400)
            self.server.quarantined.add(participant)
            self.server.operation = str(uuid.uuid4())
            return self.reply(200, [self.server.operation])
        self.reply(404)

    def do_GET(self):
        path, study = self.path, self.server.study
        if path == '/chronicle/v3/admin/principals':
            return self.reply(200, [{'type': 'USER', 'id': 'test_user2'}] + getattr(self.server, 'extra_principals', []))
        if path == f'/chronicle/v3/study/{study}':
            return self.reply(200, self.server.study_body, self.server.revision)
        if path == f'/chronicle/v3/study/{study}/settings/type/DataCollection':
            return self.reply(200, self.server.collection, self.server.revision)
        if path == f'/chronicle/v3/study/{study}/participants':
            return self.reply(200, [{'participantId': participant, 'statusRevision': 13}
                                    for participant in self.server.participants])
        if path.endswith('/deliveries'):
            return self.reply(200, getattr(self.server, 'deliveries', []))
        if path.endswith('/annotations'):
            return self.reply(200, {'participantNotes': '', 'participantTags': []}, 'annotations-revision')
        if '/questionnaire/' in path:
            return self.reply(200, self.server.questionnaire_body, 'questionnaire-revision')
        if path.endswith('/purge/preview'):
            participant = path.split('/')[-3]
            if participant not in self.server.participants:
                return self.reply(404)
            return self.reply(200, {'confirmationToken': 'confirm-' + participant})
        if path.endswith('/enrollment-preview'):
            return self.reply(200, {'manifestDigest': self.server.digest,
                                    'manifest': {'serverOrigin': 'https://probe.example.org', 'settingsVersion': 2}})
        if '/participants/data?' in path:
            data = b'applicationLabel\n'
            self.send_response(200)
            self.send_header('Content-Type', 'text/csv')
            self.send_header('Content-Length', str(len(data)))
            self.end_headers(); self.wfile.write(data)
            return
        self.reply(404)

    def do_PATCH(self):
        body = self.body()
        if self.headers.get('If-Match') != f'"{self.server.revision}"':
            return self.reply(412)
        self.server.revision += 1
        if self.path.endswith('/DataCollection'):
            self.server.collection = body
        self.reply(200, {}, self.server.revision)


class BenchmarkFixtureApi(ProbeFixtureApi):
    def do_POST(self):
        self.path = self.path.replace(client.DASHBOARD_API, '/chronicle/v3', 1)
        if self.path.endswith('/enroll') and not getattr(self.server, 'duplicate_keys', False):
            self.server.credential = self.headers['X-Chronicle-Proposed-Api-Key']
        if self.headers[client.API_KEY_HEADER] and self.headers['Cookie']:
            # The server refuses a device key sent with a person credential (mixed credentials).
            self.send_error(400)
            return
        if self.path.endswith('/collection-ack'):
            self.server.acknowledged.add(self.headers[client.API_KEY_HEADER])
        super().do_POST()

    def do_GET(self):
        self.path = self.path.replace(client.DASHBOARD_API, '/chronicle/v3', 1)
        super().do_GET()


class ProbeFixtureTests(unittest.TestCase):
    def fixture_token(self):
        claims = client.base64.urlsafe_b64encode(json.dumps({'sub': 'test_user2'}).encode()).decode().rstrip('=')
        return 'fixture.' + claims + '.signature'

    def fixture_server(self, extra_principals=(), handler=ProbeFixtureApi):
        server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), handler)
        server.keys, server.revision, server.study = [], 7, None
        server.enrolled, server.participants, server.quarantined = False, set(), set()
        server.acknowledged = set()
        server.credential, server.enrollment_code, server.digest = 'private-fixture-key', 'private-code', 'a' * 64
        server.device = str(uuid.uuid4())
        server.extra_principals = list(extra_principals)
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        return server

    def test_benchmark_inventory_enrolls_distinct_acknowledged_devices_and_keeps_them_private(self):
        server = self.fixture_server(handler=BenchmarkFixtureApi)
        management = f'http://127.0.0.1:{server.server_port}'
        scratch = ROOT / 'build/operator-test-runs'
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix='benchmark-records-', dir=scratch) as folder:
            path = Path(folder) / 'devices.json'
            browser = client.client()
            browser.addheaders = [('Cookie', 'chronicle_session=fixture')]  # the dashboard session cookie
            with patch.object(client, 'dashboard_client', return_value=(browser, {})):
                credentials = client.benchmark_device_inventory('https://probe.example.org', management,
                                                                 None, 'fixture-password', 2, path)
            records = json.loads(path.read_text())
            self.assertEqual(0o600, path.stat().st_mode & 0o777)
            self.assertEqual(2, len(records))
            self.assertEqual(2, len({record['api_key'] for record in records}))
            self.assertEqual(2, len({record['random_device_id'] for record in records}))
            self.assertEqual(server.acknowledged, {record['api_key'] for record in records})
            self.assertEqual(server.participants, {record['participant_id'] for record in records})
            self.assertEqual(records[0]['api_key'], credentials['API_KEY'])
            self.assertEqual(records[0]['participant_id'], credentials['TEST_PARTICIPANT_ID'])
            self.assertEqual(server.study, credentials['TEST_STUDY_ID'])
            self.assertEqual(records[-1]['api_key'], server.credential)
        for count in (0, -1):
            with self.subTest(count=count), self.assertRaisesRegex(ValueError, 'positive'):
                client.benchmark_device_inventory('https://probe.example.org', management,
                                                  None, 'fixture-password', count, path)

    def test_benchmark_inventory_rejects_duplicate_enrollment_keys_without_writing_inventory(self):
        server = self.fixture_server(handler=BenchmarkFixtureApi)
        server.duplicate_keys = True
        management = f'http://127.0.0.1:{server.server_port}'
        scratch = ROOT / 'build/operator-test-runs'
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix='benchmark-duplicates-', dir=scratch) as folder:
            path = Path(folder) / 'devices.json'
            with patch.object(client, 'dashboard_client', return_value=(client.client(), {})):
                with self.assertRaisesRegex(RuntimeError, 'duplicate device credentials'):
                    client.benchmark_device_inventory('https://probe.example.org', management,
                                                      None, 'fixture-password', 2, path)
            self.assertFalse(path.exists())

    def test_seed_returns_owned_nested_resources_and_revisions_without_bearer_or_invitation(self):
        server = self.fixture_server()
        api = f'http://127.0.0.1:{server.server_port}/chronicle/v3'
        token = self.fixture_token()
        context = client.api_fixture_study(api, token, 'https://probe.example.org', 'probe-b')
        self.assertIn('questionnaireId', context, 'authorization probes require a persisted nested questionnaire')
        for name, expected in (('study', server.study), ('participant', 'probe-b'), ('id', 'test_user2'),
                               ('organizationId', server.organization), ('questionnaireId', server.questionnaire),
                               ('webhookId', server.webhook), ('keyId', server.key), ('operationId', server.operation),
                               ('randomDeviceId', server.device)):
            self.assertEqual(expected, context[name])
        self.assertIn(server.organization, server.study_body['organizationIds'])
        self.assertNotIn('probe-b', server.quarantined)
        self.assertEqual(1, len(server.quarantined))
        serialized = json.dumps(context)
        for secret in (server.enrollment_code, token):
            self.assertNotIn(secret, serialized)
        self.assertEqual(server.credential, context['nativeHeaders'][client.API_KEY_HEADER])
        self.assertNotIn(client.API_KEY_HEADER, context.get('headers', {}))
        self.assertTrue(all(client.API_KEY_HEADER not in entry.get('headers', {})
                            for entry in context['operations'].values()))
        capability = context['operations'][
            'POST /chronicle/v4/study/{studyId}/participant/{participantId}/form-access-codes']['body']
        self.assertEqual(server.questionnaire, capability.get('resourceId'),
                         'QUESTIONNAIRE capability requests bind the real questionnaire as resourceId')
        revision_headers = [entry['headers']['If-Match'] for entry in context['operations'].values()
                            if 'If-Match' in entry.get('headers', {})]
        self.assertIn('"annotations-revision"', revision_headers)
        self.assertIn('"questionnaire-revision"', revision_headers)
        self.assertIn('"9"', revision_headers)
        self.assertEqual(len(server.keys), len(set(server.keys)))
        # Every actual scoped route must have typed inputs before the authorization sweep can interpret a denial.
        import sys
        import yaml
        sys.path.insert(0, str(ROOT / 'tests/security'))
        from route_probe_inputs import request_inputs
        document = yaml.safe_load((ROOT / 'chronicle-api/chronicle.yaml').read_text())
        inventory = json.loads((ROOT / 'chronicle-server/src/test/resources/route-inventory.json').read_text())
        for route in inventory:
            if route['auth'] != 'AUTHENTICATED' or not ('{studyId}' in route['path'] or '/admin/' in route['path']):
                continue
            with self.subTest(method=route['method'], path=route['path']):
                operation = context['operations'][route['method'] + ' ' + route['path']]
                inputs = {**context, **operation, 'headers': {**operation['headers'], **context['nativeHeaders']}}
                sampled = request_inputs(document, route['path'], route['method'], inputs)
                if 'json' in sampled:
                    self.assertNotEqual('test_user2', sampled['json'].get('id') if isinstance(sampled['json'], dict) else None)

    def test_foreign_principal_or_role_cannot_be_recorded_as_the_expected_own_response(self):
        for unexpected in ({'type': 'USER', 'id': 'test_user1'}, {'type': 'ROLE', 'id': 'admin'}):
            with self.subTest(unexpected=unexpected):
                server = self.fixture_server((unexpected,))
                api = f'http://127.0.0.1:{server.server_port}/chronicle/v3'
                with self.assertRaisesRegex(ValueError, 'own principal'):
                    client.api_fixture_study(api, self.fixture_token(), 'https://probe.example.org', 'probe-b')

    def test_seed_refuses_to_bless_a_registration_that_created_a_delivery(self):
        server = self.fixture_server()
        server.deliveries = [{'eventType': 'STUDY_STATUS_CHANGED'}]
        api = f'http://127.0.0.1:{server.server_port}/chronicle/v3'
        with self.assertRaisesRegex(RuntimeError, 'webhook delivery'):
            client.api_fixture_study(api, self.fixture_token(), 'https://probe.example.org', 'probe-b')

    def test_private_fixture_writer_creates_mode_0600_without_replacing_existing_path(self):
        scratch = ROOT / 'build/operator-test-runs'
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix='probe-records-', dir=scratch) as folder:
            path = Path(folder) / 'records.json'
            client.write_private_fixture(path, {'confirmationToken': 'private-fixture-token'})
            self.assertEqual(0o600, path.stat().st_mode & 0o777)
            self.assertEqual({'confirmationToken': 'private-fixture-token'}, json.loads(path.read_text()))
            with self.assertRaises(FileExistsError):
                client.write_private_fixture(path, {})
            self.assertEqual({'confirmationToken': 'private-fixture-token'}, json.loads(path.read_text()))


class DashboardSessions(http.server.BaseHTTPRequestHandler):
    """Cookie sessions like the backend's: login mints one, a revoked token reads nothing."""
    def reply(self, status, body=None, cookie=None):
        data = json.dumps(body).encode() if body is not None else b''
        self.send_response(status)
        if cookie:
            self.send_header('Set-Cookie', f'chronicle_session={cookie}; Path=/; HttpOnly')
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(data)))
        self.end_headers(); self.wfile.write(data)

    def token(self):
        cookies = dict(part.strip().split('=', 1) for part in (self.headers.get('Cookie') or '').split(';') if '=' in part)
        return cookies.get('chronicle_session') if cookies.get('chronicle_session') in self.server.live else None

    def do_POST(self):
        if self.path != '/chronicle/v3/auth/dashboard-login':
            return self.reply(404)
        body = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
        if body.get('password') != self.server.password:
            return self.reply(401)
        token = uuid.uuid4().hex
        self.server.live.add(token)
        self.reply(200, {'authenticated': True, 'csrfToken': 'csrf-' + token}, token)

    def do_GET(self):
        token = self.token()
        if token is None:
            return self.reply(401)
        if self.path == '/chronicle/v3/auth/session':
            return self.reply(200, {'authenticated': True, 'csrfToken': 'csrf-' + token})
        if not self.path.startswith('/chronicle/api/web/study/'):
            return self.reply(404)
        if (self.headers.get('X-CSRF-Token') != 'csrf-' + token
                or self.headers.get('Origin') != f'http://127.0.0.1:{self.server.server_port}'):
            return self.reply(403)
        self.reply(200, {'id': self.path.rsplit('/', 1)[1]})

    def log_message(self, *args):
        pass


class DashboardSessionTests(unittest.TestCase):
    def test_saved_session_replays_until_the_server_revokes_it(self):
        server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), DashboardSessions)
        server.password, server.live = 'synthetic-password-' + uuid.uuid4().hex, set()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        management, records = f'http://127.0.0.1:{server.server_port}', {'study': str(uuid.uuid4())}
        with tempfile.TemporaryDirectory() as folder:
            saved = Path(folder) / 'session.json'
            client.save_session(management, None, server.password, saved)
            self.assertEqual(0o600, saved.stat().st_mode & 0o777)
            self.assertEqual('valid', client.session_state(management, None, saved, records))
            server.live.clear()
            self.assertEqual('refused', client.session_state(management, None, saved, records))
        self.assertTrue(client.login_refused(management, None, 'retired-' + server.password))
        self.assertFalse(client.login_refused(management, None, server.password))


class MobileEdgeTests(unittest.TestCase):
    def setUp(self):
        self.server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), MobileEdge)
        self.server.block_posts = False
        self.server.body_sizes = []
        self.server.credential = 'synthetic-' + uuid.uuid4().hex
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.public = 'http://127.0.0.1:' + str(self.server.server_port)

    def test_ceiling_minus_generated_headroom_is_accepted_and_ceiling_plus_one_is_413(self):
        payload = [{'synthetic': True}]
        acknowledged = client.request(client.client(), self.public + '/upload', 'POST', payload,
                                      padding_bytes=client.NEAR_LIMIT_BYTES)
        self.assertEqual(len(payload), acknowledged)
        self.assertEqual(client.MAX_REQUEST_SIZE_BYTES - client.UPLOAD_LIMITS['REQUEST_HEADER_HEADROOM_BYTES'],
                         self.server.body_sizes[-1])
        client.assert_oversize_rejected(self.public + '/upload', {})

    def test_positive_canary_requires_enrollment_and_upload_acknowledgments(self):
        base = self.public + '/chronicle/v4/study/' + str(uuid.uuid4()) + '/participant/smoke-' + uuid.uuid4().hex
        recipe = {name: dict(url=base + suffix, body=[{'synthetic': True}],
                             headers={client.API_KEY_HEADER: self.server.credential}) for name, suffix in CANARY_ROUTES.items()}
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'canary'; path.write_text(json.dumps(recipe)); path.chmod(0o600)
            with patch.object(Path, 'cwd', return_value=Path(folder)):
                verify_canary(path, self.public, send_canary)
                self.assertEqual(len(CANARY_ROUTES), len(self.server.body_sizes))
                self.server.block_posts = True
                with self.assertRaises(ValueError):
                    verify_canary(path, self.public, send_canary)

    def test_reachable_probe_cannot_count_any_refusal_as_success(self):
        for status in ('401', '403', '404', '429', '500'):
            with self.subTest(status=status), self.assertRaises(ValueError):
                RouteProbe('/fixture', (status,), 'reachable')
            RouteProbe('/fixture', (status,), 'refused', kind=ProbeKind.DENIED)
