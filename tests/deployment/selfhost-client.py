#!/usr/bin/env python3
"""Real dashboard session, Android enrollment, uploads and PostgreSQL receipts."""
import argparse
import base64
import csv
from datetime import datetime, timedelta, timezone
import http.cookiejar
import io
import json
import os
import http.client
import secrets
import shlex
from pathlib import Path
import ssl
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from urllib.parse import urlencode, urlsplit
import uuid

REQUEST_TIMEOUT_SECONDS = 300
UPLOAD_LIMITS_OWNER = Path(__file__).resolve().parents[2] / 'generated/upload-limits.json'
UPLOAD_LIMITS = json.loads(UPLOAD_LIMITS_OWNER.read_text())
MAX_REQUEST_SIZE_BYTES = UPLOAD_LIMITS['MAX_REQUEST_SIZE_BYTES']
NEAR_LIMIT_BYTES = MAX_REQUEST_SIZE_BYTES - UPLOAD_LIMITS['REQUEST_HEADER_HEADROOM_BYTES']
LARGE_EXPORT_BYTES = 6 * 1024 * 1024
# The server discards usage events whose index-key text exceeds 2048 bytes, so the large export is
# many rows of a label that fits beside the fixture's other key fields.
LARGE_EXPORT_LABEL_BYTES = 1800
LARGE_EXPORT_ROWS = LARGE_EXPORT_BYTES // LARGE_EXPORT_LABEL_BYTES + 1
TRANSFER_CHUNK_BYTES = 64 * 1024
SLOW_TRANSFER_INTERVAL_SECONDS = 0.1
IDLE_GAP_SECONDS = 3
IDLE_FAILURE_DEADLINE_SECONDS = 10
BODY_PROBE_CONTROL_TIMEOUT_SECONDS = 5
BODY_DEADLINE_MIN_ELAPSED_FRACTION = 0.8
BROWSER_BURST_REQUESTS = 12
# Usage events reach chronicle_usage_events through the upload buffer, which the backend's
# MOVE_TO_EVENT_STORAGE task drains 5 minutes after start and every 5 minutes after that.
PERSIST_WAIT_SECONDS = 420
EXPORT_RETRY_SECONDS = 30
UPLOAD_RETRY_INTERVAL_SECONDS = 0.12
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'selfhost'))
from chronicle_ops.mobile_canary import API_KEY_HEADER, CANARY_ROUTES
DEVICE_HEADER = 'X-Chronicle-Random-Device-Id'
# Caddy serves the researcher API (/chronicle/v3) at this prefix on the management origin.
DASHBOARD_API = '/chronicle/api/web'
ENROLLMENT_CODE_HEADER = 'X-Chronicle-Enrollment-Code'
MANIFEST_HEADER = 'X-Chronicle-Manifest-Digest'
TABLES = {'usage': 'chronicle_usage_events', 'sensors': 'android_sensor_data',
          'battery': 'battery_telemetry', 'connectivity-state': 'connectivity_state_events',
          'app-network-usage': 'app_network_usage', 'device-settings': 'device_settings',
          'upload-diagnostics': 'upload_diagnostics', 'availability': 'android_device_sensor_availability',
          'interaction': 'interaction_events', 'audio-activity': 'app_audio_activity',
          'audio-content': 'app_audio_content', 'notification-activity': 'notification_activity',
          'sleep': 'sleep_events', 'activity-recognition': 'activity_recognition_events', 'health-connect': 'health_metrics'}
# Every active Android module that is on by default must be listed: enrollment acknowledges
# exactly the effective enabled set, and unlisted defaults (device_lifecycle, questionnaire) count.
# Sensor modules cover every sensor tests/load/mobile-client.js generates; the server refuses a batch naming an
# unconsented sensor.
MODULES = ('usage_events', 'device_lifecycle', 'questionnaire', 'sensor_accelerometer', 'sensor_gyroscope', 'sensor_light',
           'sensor_proximity', 'battery_telemetry', 'connectivity_state',
           'app_network_usage', 'device_settings', 'upload_telemetry', 'sensor_availability',
           'interaction_events', 'audio_activity', 'audio_content', 'notification_activity',
           'sleep', 'activity_recognition', 'health_connect')


def tls_context(ca):
    context = ssl.create_default_context(cafile=ca)
    context.verify_flags |= ssl.VERIFY_X509_STRICT
    return context


def client(ca=None):
    jar = http.cookiejar.CookieJar()
    return urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPCookieProcessor(jar),
                                      urllib.request.HTTPSHandler(context=tls_context(ca)))


def configure_fixture_address(public, resolve_public):
    endpoint, origin = urlsplit('//' + resolve_public), urlsplit(public)
    if not endpoint.hostname or not endpoint.port:
        raise ValueError('fixture endpoint requires host:port')
    resolve = socket.getaddrinfo
    def fixture_address(host, port, *arguments, **keywords):
        if host == origin.hostname and int(port) == (origin.port or 443):
            host, port = endpoint.hostname, endpoint.port
        return resolve(host, port, *arguments, **keywords)
    socket.getaddrinfo = fixture_address


def request(opener, url, method='GET', body=None, headers=None, expected=(200, 201, 204), padding_bytes=0, body_interval=0,
            upload_progress=None, response_headers=None):
    """Every client call goes through here: POST carries a fresh Idempotency-Key (researcher creates answer 428
    without one) and PATCH must carry the If-Match ETag of the read it is based on (conditional edits answer 428)."""
    headers = dict(headers or {})
    if method == 'POST':
        headers.setdefault('Idempotency-Key', str(uuid.uuid4()))
    if method == 'PATCH' and 'If-Match' not in headers:
        raise ValueError(f'PATCH {url.split("?")[0]} needs If-Match with the ETag of the read it is based on')
    if body is not None:
        headers['Content-Type'] = 'application/json'
    data = json.dumps(body).encode() if body is not None else None
    if padding_bytes:
        data += b" " * max(0, padding_bytes - len(data))
    if body_interval:
        headers['Content-Length'] = str(len(data))
        payload = data
        def chunks():
            for offset in range(0, len(payload), TRANSFER_CHUNK_BYTES):
                yield payload[offset:offset + TRANSFER_CHUNK_BYTES]
                if upload_progress is not None:
                    upload_progress['bytes_sent'] += len(payload[offset:offset + TRANSFER_CHUNK_BYTES])
                time.sleep(body_interval)
        data = chunks()
    try:
        response = opener.open(urllib.request.Request(url, data, headers, method=method), timeout=REQUEST_TIMEOUT_SECONDS)
    except urllib.error.HTTPError as error:
        # Name the route and the server's reason; the body is an ApiError envelope, never a credential.
        error.msg = f'{error.msg} from {method} {url.split("?")[0]}: {error.read(2048).decode("utf-8", "replace")}'
        raise
    with response:
        if response.status not in expected:
            raise RuntimeError(f'{method} {url.split("?")[0]} returned {response.status}')
        if response_headers is not None:
            response_headers.update((name.lower(), value) for name, value in response.headers.items())
        raw = response.read()
        if not raw:
            return None
        if 'application/json' not in response.headers.get('Content-Type', ''):
            raise RuntimeError('API success did not contain JSON')
        return json.loads(raw)


def probe_body_deadline(origin, ca, deadline_seconds):
    """Trickle an incomplete body with an invalid key: the body is read before key authentication."""
    endpoint = urlsplit(origin)
    connection = socket.create_connection((endpoint.hostname, endpoint.port or (443 if endpoint.scheme == 'https' else 80)), timeout=BODY_PROBE_CONTROL_TIMEOUT_SECONDS)
    if endpoint.scheme == 'https':
        connection = tls_context(ca).wrap_socket(connection, server_hostname=endpoint.hostname)
    connection.settimeout(SLOW_TRANSFER_INTERVAL_SECONDS)
    started = time.monotonic()
    with connection:
        path = '/chronicle/v4/study/00000000-0000-0000-0000-000000000001/participant/deadline-probe/android'
        connection.sendall((f'POST {path} HTTP/1.1\r\nHost: {endpoint.netloc}\r\nContent-Type: application/json\r\n'
                            f'{API_KEY_HEADER}: invalid-deadline-fixture\r\nContent-Length: {NEAR_LIMIT_BYTES}\r\n\r\n[').encode())
        checked_health = False
        while time.monotonic() - started < deadline_seconds + IDLE_FAILURE_DEADLINE_SECONDS:
            try:
                connection.sendall(b' ')
                response = connection.recv(4096)
            except socket.timeout:
                if not checked_health:
                    with client(ca).open(origin.rstrip('/') + '/health', timeout=BODY_PROBE_CONTROL_TIMEOUT_SECONDS) as health:
                        if health.status not in (200, 204):
                            raise RuntimeError('health failed during the partial upload')
                    checked_health = True
                continue
            except (BrokenPipeError, ConnectionResetError, ssl.SSLEOFError):
                response = b''
            elapsed = time.monotonic() - started
            if elapsed < deadline_seconds * BODY_DEADLINE_MIN_ELAPSED_FRACTION:
                raise RuntimeError('upload was rejected before the body deadline; probe did not exercise the body reader')
            if response.startswith(b'HTTP/') and response.split(b' ', 2)[1] == b'401':
                raise RuntimeError('incomplete body reached key authentication')
            print('PASS incomplete trickled body ended at the read deadline; health remained responsive')
            return
    raise RuntimeError('incomplete trickled body exceeded the listener read deadline')


def batches(study, participant, now):
    sample = {'id': str(uuid.uuid4()), 'timestamp': now, 'timezone': 'America/Santiago'}
    return {
        'usage': [{'@class': 'com.openlattice.chronicle.android.ChronicleUsageEvent', 'clientEventId': sample['id'], 'studyId': study,
                   'participantId': participant, 'appPackageName': 'org.chronicle.smoke', 'interactionType': 'Activity Resumed',
                   'timestamp': now, 'timezone': sample['timezone'], 'user': 'synthetic', 'applicationLabel': 'Smoke'}],
        'sensors': [dict(sample, sensor='accelerometer', x=1.0, y=2.0, z=3.0, accuracy=3)],
        'battery': [dict(sample, levelPercent=80, chargingState='DISCHARGING', plugType='UNPLUGGED',
                         temperatureDeciC=250, voltageMillivolts=4000, health='GOOD')],
        'connectivity-state': [dict(sample, eventType='SNAPSHOT', transport='WIFI', connected=True, metered=False, validated=True)],
        'app-network-usage': [dict(sample, packageName='org.chronicle.smoke', networkType='WIFI', rxBytes=100, txBytes=50,
                                   bucketStartMillis=1, bucketEndMillis=2)],
        'device-settings': [dict(sample, fontScale=1.0, batterySaver=False)],
        'interaction': [dict(sample, eventType='CLICK', gridRows=1, gridCols=1, gridRow=0, gridCol=0,
                             elementRole='android.widget.Button', foregroundPackage='org.chronicle.smoke')],
        'audio-activity': [dict(sample, eventType='SNAPSHOT', audioActive=False)],
        'audio-content': [dict(sample, audioPackage='org.chronicle.smoke', title='Synthetic fixture')],
        'notification-activity': [dict(sample, eventType='POSTED', packageName='org.chronicle.smoke')],
        'sleep': [dict(sample, eventType='CLASSIFY', confidence=80)],
        'activity-recognition': [dict(sample, activityType='STILL', confidence=80)],
        'health-connect': [dict(sample, metricType='STEPS', value=1.0, unit='count', startMillis=1, endMillis=2)],
        'upload-diagnostics': [{'id': sample['id'], 'day': now[:10], 'moduleFamily': 'CONNECTIVITY', 'issueCode': 'TIMEOUT',
                                'count': 1, 'firstOccurredAt': now, 'lastOccurredAt': now}],
    }


def dashboard_client(management, ca, password):
    browser = client(ca)
    browser_headers = {'Origin': management}
    login_url = management + '/chronicle/v3/auth/dashboard-login'
    try:
        login = request(browser, login_url, 'POST', {'password': password}, browser_headers)
    except urllib.error.HTTPError as error:
        # The release drill also seeds a supported predecessor that still has Caddy Basic.
        if error.code != 401 or not error.headers.get('WWW-Authenticate', '').lower().startswith('basic '):
            raise
        error.close()
        basic = base64.b64encode(('researcher:' + password).encode()).decode()
        browser_headers['Authorization'] = 'Basic ' + basic
        login = request(browser, login_url, 'POST', {'password': password}, browser_headers)
    if not login.get('authenticated') or not login.get('csrfToken'):
        raise RuntimeError('dashboard login did not issue an authenticated CSRF session')
    session = request(browser, management + '/chronicle/v3/auth/session', headers=browser_headers)
    if not session.get('authenticated') or not session.get('csrfToken'):
        raise RuntimeError('cookie-backed authenticated follow-up failed')
    # Session bootstrap reissues the CSRF cookie; like the dashboard, send the current token.
    browser_headers['X-CSRF-Token'] = session['csrfToken']
    return browser, browser_headers


def assert_study(records, management, ca, password):
    browser, headers = dashboard_client(management, ca, password)
    study = str(uuid.UUID(records['study']))
    response = request(browser, management + DASHBOARD_API + '/study/' + study, headers=headers)
    if response.get('id') != study:
        raise RuntimeError('persisted study was not readable with its researcher permissions')


def save_session(management, ca, password, destination):
    """Keep one dashboard session's cookies and CSRF header so a later probe can replay it after a rotation."""
    browser, headers = dashboard_client(management, ca, password)
    jar = next(handler.cookiejar for handler in browser.handlers if isinstance(handler, urllib.request.HTTPCookieProcessor))
    cookies = [dict(name=cookie.name, value=cookie.value, domain=cookie.domain, path=cookie.path, secure=cookie.secure)
               for cookie in jar]
    with open(destination, 'x', opener=lambda path, flags: os.open(path, flags, 0o600)) as output:
        json.dump({'cookies': cookies, 'headers': headers}, output)


def session_state(management, ca, saved, records):
    """'valid' when the saved session still reads the persisted study through the live backend, else 'refused'."""
    state = json.loads(Path(saved).read_text())
    browser = client(ca)
    jar = next(handler.cookiejar for handler in browser.handlers if isinstance(handler, urllib.request.HTTPCookieProcessor))
    for cookie in state['cookies']:
        jar.set_cookie(http.cookiejar.Cookie(0, cookie['name'], cookie['value'], None, False, cookie['domain'], True,
                                             cookie['domain'].startswith('.'), cookie['path'], True, cookie['secure'],
                                             None, False, None, None, {}))
    study = str(uuid.UUID(records['study']))
    try:
        response = request(browser, management + DASHBOARD_API + '/study/' + study, headers=state['headers'])
    except urllib.error.HTTPError as error:
        if error.code in (401, 403):
            error.close()
            return 'refused'
        raise
    if response.get('id') != study:
        raise RuntimeError('saved session read a different study')
    return 'valid'


def login_refused(management, ca, password):
    try:
        dashboard_client(management, ca, password)
    except urllib.error.HTTPError as error:
        if error.code == 401:
            error.close()
            return True
        raise
    return False


def create_study(browser, browser_headers, api, now, organization_ids=()):
    study = request(browser, api + '/study', 'POST',
                    {'title': 'Topology synthetic study', 'contact': 'synthetic@example.org',
                     'organizationIds': list(organization_ids),
                     'modules': {'CHRONICLE_DATA_COLLECTION': {}}, 'startedAt': (now - timedelta(days=1)).isoformat(), 'endedAt': (now + timedelta(days=2)).isoformat()}, browser_headers)
    return str(uuid.UUID(study))


def configure_study(browser, browser_headers, api, study, public, now):
    """Enable every listed module and publish the participant policy, each edit conditional on the last revision."""
    base = api + '/study/' + study
    revision = {}
    request(browser, base, headers=browser_headers, response_headers=revision)
    setting = {'@class': 'com.openlattice.chronicle.collection.AndroidDataCollectionSetting', 'version': 2,
               'modules': {module: {'enabled': True, 'required': False} for module in MODULES}}
    setting['modules']['health_connect']['healthConnectRecordTypes'] = ['steps']
    request(browser, base + '/settings/type/DataCollection', 'PATCH', setting,
            {**browser_headers, 'If-Match': revision['etag']}, response_headers=revision)
    fields = ('responsibleInstitution', 'serverOperator', 'researchContact', 'purpose', 'expectedDuration', 'procedures',
              'foreseeableRisks', 'expectedBenefits', 'dataUseAndSharing', 'retentionAndDeletion')
    policy = dict.fromkeys(fields, 'Synthetic release qualification only')
    policy.update({'@class': 'com.openlattice.chronicle.study.StudyParticipantPolicy', 'version': 'smoke-1',
                   'effectiveAt': now.isoformat(), 'privacyPolicyUrl': public + '/chronicle/privacy',
                   'withdrawalUrl': public + '/chronicle/withdraw'})
    request(browser, base + '/settings/type/ParticipantPolicy', 'PATCH', policy,
            {**browser_headers, 'If-Match': revision['etag']})
    return policy


def add_participant(browser, browser_headers, base, participant):
    request(browser, base + '/participant', 'POST', {'participantId': participant, 'candidate': {},
                                                   'participationStatus': 'ENROLLED'}, browser_headers)


def api_fixture_study(api, token, public, participant):
    """Seed real related resources; the returned context belongs only in a private fixture file."""
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    headers = {'Authorization': 'Bearer ' + token}
    now = datetime.now(timezone.utc)
    principals = request(opener, api + '/admin/principals', headers=headers)
    # The disposable backend seeds these researcher actors with only their USER principal, and this seed
    # creates ownership ACLs, not group grants. The server has authenticated the token for the read above;
    # its subject supplies the independent expected identity, never the returned response itself.
    try:
        encoded_claims = token.split('.')[1]
        user_id = json.loads(base64.urlsafe_b64decode(encoded_claims + '=' * (-len(encoded_claims) % 4)))['sub']
        if not isinstance(user_id, str) or not user_id:
            raise ValueError('Missing subject')
    except (IndexError, KeyError, ValueError) as error:
        raise ValueError('Fixture token needs a valid own principal subject') from error
    expected_principals = [{'type': 'USER', 'id': user_id}]
    if principals != expected_principals:
        raise ValueError('Self-introspection must return exactly the fixture actor own principal')
    organization = str(uuid.UUID(request(opener, api + '/organization', 'POST',
                                        {'title': 'Authorization probe organization', 'description': 'Synthetic fixture'}, headers)))
    study = create_study(opener, headers, api, now, (organization,))
    policy = configure_study(opener, headers, api, study, public, now)
    base = api + '/study/' + study
    # Recipient configuration is locked once anyone enrolls. This event is not emitted by the participant seed.
    webhook_body = {'url': 'https://example.org/chronicle-probe', 'secret': secrets.token_urlsafe(32),
                    'eventTypes': ['STUDY_STATUS_CHANGED'], 'description': 'Synthetic authorization probe'}
    webhook = request(opener, base + '/webhooks', 'POST', webhook_body, headers)
    questionnaire_body = {'id': None, 'title': 'Authorization probe questionnaire', 'dateCreated': None,
                          'description': 'Synthetic fixture', 'active': True,
                          'questions': [{'title': 'Synthetic answer', 'choices': ['Yes', 'No']}], 'recurrenceRule': None}
    survey = api + '/survey/' + study
    questionnaire = str(uuid.UUID(request(opener, survey + '/questionnaire', 'POST', questionnaire_body, headers)))
    key_body = {'name': 'Authorization probe key', 'scope': 'READ_ONLY', 'expiresInDays': 1}
    key = request(opener, base + '/api-keys', 'POST', key_body, headers)
    add_participant(opener, headers, base, participant)
    native_headers, device, acknowledgment = enroll_probe_device(opener, opener, headers, api, study, participant, policy, now)
    # A separate participant supplies a real deletion-ledger ID without quarantining the target's enrolled device.
    deletion_participant = 'probe-deletion-' + uuid.uuid4().hex
    add_participant(opener, headers, base, deletion_participant)
    deletion_preview = request(opener, base + '/participants/' + deletion_participant + '/purge/preview', headers=headers)
    operation = request(opener, base + '/participants/purge', 'POST',
                        {'participantId': deletion_participant, 'confirmationToken': deletion_preview['confirmationToken']}, headers)[0]
    preview = request(opener, base + '/participants/' + participant + '/purge/preview', headers=headers)
    study_headers, annotation_headers, questionnaire_headers = {}, {}, {}
    snapshot = request(opener, base, headers=headers, response_headers=study_headers)
    collection = request(opener, base + '/settings/type/DataCollection', headers=headers)
    request(opener, base + '/participant/' + participant + '/annotations', headers=headers, response_headers=annotation_headers)
    request(opener, survey + '/questionnaire/' + questionnaire, headers=headers, response_headers=questionnaire_headers)
    participants = request(opener, base + '/participants', headers=headers)
    status_revision = next(row['statusRevision'] for row in participants if row['participantId'] == participant)
    # The owner's export succeeds, so a probe refused on this route is refused by authorization.
    usage_export(opener, base, headers, participant)
    if request(opener, api + '/admin/principals', headers=headers) != expected_principals:
        raise ValueError('Resource creation changed the fixture actor own principal set')
    if request(opener, base + '/webhooks/' + webhook['webhookId'] + '/deliveries', headers=headers):
        raise RuntimeError('Registration-only seed unexpectedly created a webhook delivery')
    context = {'study': study, 'participant': participant, 'studyId': study, 'participantId': participant,
               'id': user_id, 'userId': user_id, 'name': 'STUDIES', 'settingType': 'DataCollection',
               'organizationId': organization, 'questionnaireId': questionnaire, 'webhookId': webhook['webhookId'],
               'keyId': key['keyId'], 'operationId': str(uuid.UUID(operation)), 'randomDeviceId': device,
               # The caller reads actor A's separate record; target B's key must never change the probe's actor.
               'nativeHeaders': native_headers, 'principals': expected_principals, 'operations': {}}
    payloads = batches(study, participant, now.isoformat())
    body_by_operation = {
        'StudyController.updateStudy': {'title': snapshot['title']},
        'StudyController.registerParticipant': {'participantId': participant, 'candidate': {'id': str(uuid.uuid4())}, 'participationStatus': 'ENROLLED'},
        'StudyController.updateStudySettings': collection,
        'StudyController.updateParticipantAnnotations': {'participantNotes': 'Synthetic fixture', 'participantTags': ['probe']},
        'StudyController.deleteStudyParticipants': [participant],
        'SurveyController.createQuestionnaire': questionnaire_body,
        'SurveyController.updateQuestionnaire': {'title': questionnaire_body['title'], 'description': 'Synthetic fixture',
                                               'active': True, 'questions': questionnaire_body['questions']},
        'SurveyController.setAppsFilteredForStudyAppUsageSurvey': ['org.chronicle.probe'],
        'SurveyController.filterAppForStudyAppUsageSurvey': ['org.chronicle.probe'],
        'SurveyController.allowAppForStudyAppUsageSurvey': ['org.chronicle.probe'],
        'ParticipantPurgeController.executeParticipantPurge': {'participantId': participant, 'confirmationToken': preview['confirmationToken']},
        'ParticipantFormAccessController.createAccessCode': {'formKind': 'QUESTIONNAIRE', 'resourceId': questionnaire},
        'WebhookController.createWebhook': webhook_body,
        'ApiKeyController.createApiKey': key_body,
        'StudyV4Controller.uploadAndroidUsageEventDataV4': payloads['usage'],
        'StudyV4Controller.uploadBatteryTelemetryV4': payloads['battery'],
        'StudyV4Controller.uploadIosBatteryTelemetry': payloads['battery'],
        'StudyV4Controller.uploadConnectivityStateEventsV4': payloads['connectivity-state'],
        'StudyV4Controller.uploadIosConnectivityStateEvents': payloads['connectivity-state'],
        'StudyV4Controller.uploadAppNetworkUsageV4': payloads['app-network-usage'],
        'StudyV4Controller.uploadDeviceSettingsV4': payloads['device-settings'],
        'StudyV4Controller.uploadInteractionEventsV4': payloads['interaction'],
        'StudyV4Controller.uploadAudioActivityV4': payloads['audio-activity'],
        'StudyV4Controller.uploadAudioContentV4': payloads['audio-content'],
        'StudyV4Controller.uploadNotificationActivityV4': payloads['notification-activity'],
        'StudyV4Controller.uploadSleepEventsV4': payloads['sleep'],
        'StudyV4Controller.uploadActivityRecognitionEventsV4': payloads['activity-recognition'],
        'StudyV4Controller.uploadHealthMetricsV4': payloads['health-connect'],
        'StudyV4Controller.uploadIosHealthMetrics': payloads['health-connect'],
        'StudyV4Controller.reportAndroidSensorAvailabilityV4': {'availableSensors': ['accelerometer']},
        'StudyV4Controller.uploadAndroidSensorDataV4': payloads['sensors'],
        'StudyV4Controller.uploadAndroidSensorDataReceiptV4': payloads['sensors'],
        'StudyV4Controller.uploadDiagnosticsV4': payloads['upload-diagnostics'],
        'StudyV4Controller.reportCollectionAcknowledgmentV4': acknowledgment,
        'StudyV4Controller.uploadScreenTimeDataV4': {
            'schemaVersion': 1, 'randomDeviceId': native_headers[DEVICE_HEADER], 'studyId': study, 'participantId': participant,
            'generatedAt': now.isoformat(), 'records': [{'id': str(uuid.uuid4()), 'rowKind': 'application',
                'capturedAt': now.isoformat(), 'observationStart': (now - timedelta(minutes=1)).isoformat(),
                'observationEnd': now.isoformat(), 'timezoneIdentifier': 'UTC',
                'bundleIdentifier': 'org.chronicle.probe', 'durationSeconds': 30}]},
    }
    inventory = json.loads((Path(__file__).resolve().parents[2] / 'chronicle-server/src/test/resources/route-inventory.json').read_text())
    for route in inventory:
        operation_name, method, path = (route[name] for name in ('operation', 'method', 'path'))
        entry = {'headers': {}}
        if method == 'POST':
            entry['headers']['Idempotency-Key'] = str(uuid.uuid4())
        if method in {'PATCH', 'PUT', 'POST', 'DELETE'}:
            revision = (annotation_headers['etag'] if operation_name == 'StudyController.updateParticipantAnnotations'
                        else questionnaire_headers['etag'] if operation_name == 'SurveyController.updateQuestionnaire'
                        else f'"{status_revision}"' if operation_name == 'StudyController.updateParticipationStatus'
                        or operation_name.startswith('ParticipantProcessingController.')
                        else study_headers['etag'])
            entry['headers']['If-Match'] = revision
        if operation_name in body_by_operation:
            entry['body'] = body_by_operation[operation_name]
        if operation_name == 'StudyController.getParticipantsData':
            entry['query'] = {'dataType': 'UsageEvents', 'participantId': [participant]}
        if operation_name == 'StudyController.postParticipantsData':
            entry['body'] = {'dataType': 'UsageEvents', 'participantId': [participant], 'responseType': 'csv'}
        context['operations'][method + ' ' + path] = entry
    return context


def enroll_probe_device(opener, device_opener, researcher_headers, api, study, participant, policy, now):
    """opener issues the researcher's invitation; device_opener carries no person credential, because the server
    refuses an API key sent with an auth cookie or bearer token (ApiKeyAuthenticationFilter, mixed credentials)."""
    invitation = request(opener, api + '/study/' + study + '/participant/' + participant + '/form-access-codes',
                         'POST', {'formKind': 'ENROLLMENT'}, researcher_headers)
    # The seed uses the disposable API transport; --public is the policy's canonical HTTPS origin.
    endpoint = urlsplit(api)
    enrollment = f'{endpoint.scheme}://{endpoint.netloc}/chronicle/v4/study/{study}/participant/{participant}'
    source_device = str(uuid.uuid4())
    headers = {DEVICE_HEADER: source_device, ENROLLMENT_CODE_HEADER: invitation['accessCode']}
    preview = request(device_opener, enrollment + '/enrollment-preview', headers=headers)
    proposed = uuid.uuid4().hex
    headers.update({MANIFEST_HEADER: preview['manifestDigest'], 'X-Chronicle-Enrollment-Attempt-Id': str(uuid.uuid4()),
                    'X-Chronicle-Proposed-Api-Key': 'ck_' + proposed[:8] + '_' + proposed})
    android = {'@class': 'com.openlattice.chronicle.sources.AndroidDevice', 'randomDeviceId': source_device,
               'sdkVersion': '36', 'osVersion': '16', **dict.fromkeys(('device', 'model', 'codename', 'brand', 'product'), 'synthetic')}
    enrolled = request(device_opener, enrollment + '/enroll', 'POST', android, headers)
    replay = request(device_opener, enrollment + '/enroll', 'POST', android, headers)
    if enrolled != replay or not enrolled.get('apiKey'):
        raise RuntimeError('fixture enrollment did not replay the same device credential')
    native_headers = {DEVICE_HEADER: source_device, API_KEY_HEADER: enrolled['apiKey']}
    acknowledgment = {'acknowledgedModules': list(MODULES), 'acknowledgedAt': now.isoformat(),
                      'settingsVersion': preview['manifest']['settingsVersion'], 'disclosureVersion': policy['version'],
                      'manifestDigest': preview['manifestDigest']}
    request(device_opener, enrollment + '/android/collection-ack', 'POST', acknowledgment, native_headers)
    return native_headers, str(uuid.UUID(enrolled['chronicleId'])), acknowledgment


def write_private_fixture(path, records):
    """Create the private probe context with its permissions in force before any bytes are written."""
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, 'w') as output:
        json.dump(records, output)


def benchmark_device_inventory(public, management, ca, password, count, destination):
    """Enroll each benchmark VU through the existing researcher/invitation/consent flow."""
    if count <= 0:
        raise ValueError('benchmark device count must be positive')
    if Path(destination).exists():
        raise FileExistsError(destination)
    browser, headers = dashboard_client(management, ca, password)
    now = datetime.now(timezone.utc)
    api = management + DASHBOARD_API
    study = create_study(browser, headers, api, now)
    policy = configure_study(browser, headers, api, study, public, now)
    records = []
    for _ in range(count):
        participant = 'benchmark-' + uuid.uuid4().hex
        add_participant(browser, headers, api + '/study/' + study, participant)
        native, _, _ = enroll_probe_device(browser, client(ca), headers, api, study, participant, policy, now)
        records.append({'participant_id': participant, 'random_device_id': native[DEVICE_HEADER],
                        'api_key': native[API_KEY_HEADER]})
    if len({record['api_key'] for record in records}) != count:
        raise RuntimeError('benchmark enrollment returned duplicate device credentials')
    write_private_fixture(destination, records)
    first = records[0]
    return {'API_KEY': first['api_key'], 'TEST_STUDY_ID': study,
            'TEST_PARTICIPANT_ID': first['participant_id'], 'TEST_RANDOM_DEVICE_ID': first['random_device_id']}


def exercise(public, management, ca, password, *, transport_recipe=None, enrollment_credentials=None, seed_only=False,
             mobile_canary=None):
    browser, browser_headers = dashboard_client(management, ca, password)
    phone = client(ca)
    now = datetime.now(timezone.utc)
    api = management + DASHBOARD_API
    study = create_study(browser, browser_headers, api, now)
    base = api + '/study/' + study
    policy = configure_study(browser, browser_headers, api, study, public, now)
    participant = 'smoke-' + uuid.uuid4().hex
    add_participant(browser, browser_headers, base, participant)
    invitation = request(browser, base + '/participant/' + participant + '/form-access-codes', 'POST',
                         {'formKind': 'ENROLLMENT'}, browser_headers)
    device = str(uuid.uuid4())
    enrollment = public + '/chronicle/v4/study/' + study + '/participant/' + participant
    headers = {DEVICE_HEADER: device, ENROLLMENT_CODE_HEADER: invitation['accessCode']}
    preview = request(phone, enrollment + '/enrollment-preview', headers=headers)
    if preview['manifest']['serverOrigin'].rstrip('/') != public:
        raise RuntimeError('manifest used the wrong canonical origin')
    proposed = uuid.uuid4().hex
    headers.update({MANIFEST_HEADER: preview['manifestDigest'], 'X-Chronicle-Enrollment-Attempt-Id': str(uuid.uuid4()),
                    'X-Chronicle-Proposed-Api-Key': 'ck_' + proposed[:8] + '_' + proposed})
    android = {'@class': 'com.openlattice.chronicle.sources.AndroidDevice', 'randomDeviceId': device, 'sdkVersion': '36', 'osVersion': '16'}
    android.update(dict.fromkeys(('device', 'model', 'codename', 'brand', 'product'), 'synthetic'))
    enrollment_recipe = {'url': enrollment + CANARY_ROUTES['enrollment'], 'body': android, 'headers': dict(headers)}
    enrolled = request(phone, enrollment_recipe['url'], 'POST', android, headers)
    replay = request(phone, enrollment_recipe['url'], 'POST', android, headers)
    if enrolled != replay or not enrolled.get('apiKey'):
        raise RuntimeError('lost enrollment acknowledgement did not replay the same device credential')
    headers = {DEVICE_HEADER: device, API_KEY_HEADER: enrolled['apiKey']}
    if enrollment_credentials:
        credentials_path = Path(enrollment_credentials)
        with credentials_path.open('x') as output:
            credentials_path.chmod(0o600)
            json.dump({'API_KEY': enrolled['apiKey'], 'TEST_STUDY_ID': study,
                       'TEST_PARTICIPANT_ID': participant, 'TEST_RANDOM_DEVICE_ID': device}, output)
    manifest = preview['manifest']
    acknowledgment = {'acknowledgedModules': list(MODULES), 'acknowledgedAt': now.isoformat(),
                      'settingsVersion': manifest['settingsVersion'], 'disclosureVersion': policy['version'],
                      'manifestDigest': preview['manifestDigest']}
    acknowledgment_recipe = {'url': enrollment + CANARY_ROUTES['collection_ack'], 'body': acknowledgment, 'headers': dict(headers)}
    request(phone, acknowledgment_recipe['url'], 'POST', acknowledgment, headers)
    assert_oversize_rejected(enrollment + "/android/sensors", headers, ca)
    sensor_batch = upload_batches(phone, enrollment, headers, study, participant, now.isoformat(), bool(transport_recipe))
    if mobile_canary:
        path = Path(mobile_canary)
        with path.open('x') as output:
            path.chmod(0o600)
            json.dump({'enrollment': enrollment_recipe, 'collection_ack': acknowledgment_recipe,
                       'upload': {'url': enrollment + CANARY_ROUTES['upload'], 'body': sensor_batch,
                                  'headers': headers}}, output)
    if not seed_only:
        download = export_download(browser, base, browser_headers, participant, LARGE_EXPORT_ROWS if transport_recipe else 1)
        if transport_recipe:
            Path(transport_recipe).write_text(json.dumps({'enrollment': enrollment_recipe, 'collection_ack': acknowledgment_recipe,
                                                         'upload': {'url': enrollment + CANARY_ROUTES['upload'], 'body': sensor_batch,
                                                                   'headers': headers}, 'download': download,
                                                         'browser': {'url': base + '/settings/type/DataCollection', 'headers': download['headers']}}))
            Path(transport_recipe).chmod(0o600)
    records = {'study': study, 'participant': participant, 'tables': list(TABLES.values())}
    if transport_recipe:
        records['counts'] = dict(dict.fromkeys(TABLES.values(), 1), **{TABLES['usage']: LARGE_EXPORT_ROWS})
    return records


def assert_oversize_rejected(url, headers, ca=None):
    origin = urlsplit(url)
    connection = http.client.HTTPSConnection(origin.hostname, origin.port, timeout=REQUEST_TIMEOUT_SECONDS,
                                              context=tls_context(ca)) if origin.scheme == 'https' else http.client.HTTPConnection(origin.hostname, origin.port, timeout=REQUEST_TIMEOUT_SECONDS)
    try:
        connection.putrequest('POST', origin.path)
        for key, value in dict(headers, **{'Content-Type': 'application/json',
                                          'Content-Length': str(MAX_REQUEST_SIZE_BYTES + 1)}).items():
            connection.putheader(key, value)
        connection.endheaders()
        # A declared oversize must be rejected before the edge waits for an upload body.
        if connection.getresponse().status != 413:
            raise RuntimeError('ceiling+1 upload was not rejected with 413')
    finally:
        connection.close()


def upload_batches(phone, enrollment, headers, study, participant, now, large_export=False):
    payloads = batches(study, participant, now)
    if large_export:
        # Random-looking printable text avoids turning the streaming test into a tiny gzip.
        payloads['usage'] = [dict(payloads['usage'][0], clientEventId=str(uuid.uuid4()),
                                  applicationLabel=secrets.token_hex(LARGE_EXPORT_LABEL_BYTES // 2))
                             for _ in range(LARGE_EXPORT_ROWS)]
    payloads['availability'] = {'availableSensors': ['accelerometer']}
    for kind, batch in payloads.items():
        path = '/android' + ('' if kind == 'usage' else '/sensors/availability' if kind == 'availability' else '/' + kind)
        first = request(phone, enrollment + path, 'POST', batch, headers, padding_bytes=NEAR_LIMIT_BYTES if kind == 'sensors' else 0)
        request(phone, enrollment + path, 'POST', batch, headers)
        if kind in ('upload-diagnostics', 'battery'):
            if first.get('acceptedIds') != [batch[0]['id']] or first.get('discardedIds') or first.get('heldIds'):
                raise RuntimeError(f'{kind} upload receipt mismatch')
        elif kind == 'usage':
            if sorted(first.get('acceptedIds') or []) != sorted(event['clientEventId'] for event in batch):
                raise RuntimeError(f"usage upload receipt accepted {len(first.get('acceptedIds') or [])} of {len(batch)} rows")
        elif first != 1:
            raise RuntimeError(f'{kind} upload did not acknowledge one row')
        time.sleep(UPLOAD_RETRY_INTERVAL_SECONDS)
    return payloads['sensors']


def usage_export(opener, base, headers, participant):
    """The synchronous streamed CSV export of one participant's usage events: (request, body, data rows)."""
    download = urllib.request.Request(base + '/participants/data?' + urlencode(
        {'dataType': 'UsageEvents', 'participantId': participant, 'responseType': 'csv'}), headers=headers)
    with opener.open(download, timeout=REQUEST_TIMEOUT_SECONDS) as response:
        if response.status != 200 or not response.headers.get('Content-Type', '').startswith('text/csv'):
            raise RuntimeError('participant export did not answer a CSV download')
        body = response.read()
    return download, body, max(len(list(csv.reader(io.StringIO(body.decode())))) - 1, 0)


def export_download(browser, base, browser_headers, participant, rows):
    deadline = time.monotonic() + PERSIST_WAIT_SECONDS
    while True:
        download, body, count = usage_export(browser, base, browser_headers, participant)
        if count == rows:
            break
        # Zero rows until the upload buffer drains; any other count is wrong outright.
        if count != 0 or time.monotonic() >= deadline:
            raise RuntimeError('export omitted the uploaded usage row')
        time.sleep(min(EXPORT_RETRY_SECONDS, deadline - time.monotonic()))
    if b'org.chronicle.smoke' not in body:
        raise RuntimeError('authenticated streamed export omitted uploaded data')
    return {'url': download.full_url, 'headers': dict(download.header_items())}


def transport_replay(recipe, ca, idle_failure=False):
    opener = client(ca)
    upload = recipe['upload']
    if idle_failure and request(opener, upload['url'], 'POST', upload['body'], upload['headers']) != len(upload['body']):
        raise RuntimeError('short-idle control upload was not acknowledged')
    progress = {'bytes_sent': 0}
    started = time.monotonic()
    try:
        acknowledged = request(opener, upload['url'], 'POST', upload['body'], upload['headers'],
                               padding_bytes=NEAR_LIMIT_BYTES,
                               body_interval=IDLE_GAP_SECONDS if idle_failure else SLOW_TRANSFER_INTERVAL_SECONDS,
                               upload_progress=progress)
    except (urllib.error.URLError, OSError) as error:
        reason = error.reason if isinstance(error, urllib.error.URLError) else error
        timeout_or_reset = (isinstance(error, urllib.error.HTTPError) and error.code in (408, 504)
                            or isinstance(reason, (TimeoutError, ConnectionResetError, BrokenPipeError, ssl.SSLEOFError))
                            # OpenSSL 3 reports a peer reset during a TLS write as a SYS-library error.
                            or isinstance(reason, ssl.SSLError) and getattr(reason, 'library', None) == 'SYS')
        if not idle_failure or not progress['bytes_sent'] or not timeout_or_reset:
            raise
        elapsed = time.monotonic() - started
        if elapsed > IDLE_FAILURE_DEADLINE_SECONDS:
            raise RuntimeError(f'short upstream idle failure was not bounded ({elapsed:.1f}s)') from error
        return
    if idle_failure:
        raise RuntimeError('short upstream idle timeout accepted a stalled upload')
    if acknowledged != 1:
        raise RuntimeError('slow replay did not acknowledge the uploaded row')
    download = recipe['download']
    exports = []
    for interval in (0, SLOW_TRANSFER_INTERVAL_SECONDS):
        chunks = []
        with opener.open(urllib.request.Request(download['url'], headers=download['headers']), timeout=REQUEST_TIMEOUT_SECONDS) as response:
            if response.status != 200:
                raise RuntimeError('streamed export failed')
            while chunk := response.read(TRANSFER_CHUNK_BYTES):
                chunks.append(chunk)
                if interval:
                    time.sleep(interval)
        body = b''.join(chunks)
        if len(body) < LARGE_EXPORT_BYTES:
            raise RuntimeError('export was too small to qualify streaming')
        # Rows sharing a timestamp have no fixed order, so compare the rows, not the byte stream.
        exports.append(sorted(body.splitlines()))
    if exports[0] != exports[1]:
        raise RuntimeError('slow export was truncated or changed')

def upload_row_counts(records, query):
    study = str(uuid.UUID(records['study']))
    participant = records['participant']
    if not participant.startswith('smoke-') or not participant[6:].isalnum():
        raise ValueError('receipt is not a synthetic participant')
    counts = {}
    for table in records['tables']:
        if table not in TABLES.values():
            raise ValueError('unknown upload table')
        # chronicle_usage_events keeps study_id as text; the other upload tables use uuid.
        count = query(f"SET max_parallel_workers_per_gather=0; SELECT count(*) FROM {table} WHERE study_id::text='{study}' AND participant_id='{participant}'")
        counts[table] = int(str(count).strip())
    return counts


def assert_persisted(records, query):
    expected = records.get('counts', dict.fromkeys(records['tables'], 1))
    if upload_row_counts(records, query) != expected:
        raise RuntimeError('persisted upload table counts differ from the recorded receipt')


def write_upload_security_environment(public, management, password, credentials, ca, resolve_public, destination):
    browser, _ = dashboard_client(management, ca, password)
    token = next((cookie.value for handler in browser.handlers if isinstance(handler, urllib.request.HTTPCookieProcessor)
                  for cookie in handler.cookiejar if cookie.name == 'chronicle_auth'), None)
    if not token:
        raise RuntimeError('dashboard session did not issue an authentication cookie')
    environment = dict(json.loads(Path(credentials).read_text()), BASE_URL=public, NO_PROXY='*',
                       MANAGEMENT_URL=management, AUTH_TOKEN=token)
    if ca:
        environment.update(CURL_CA_BUNDLE=ca, CA_CERT=ca, SSL_CERT_FILE=ca)
    if resolve_public:
        origin, endpoint = urlsplit(public), urlsplit('//' + resolve_public)
        environment['UPLOAD_CONNECT_TO'] = f'{origin.hostname}:{origin.port or 443}:{endpoint.hostname}:{endpoint.port}'
    with open(destination, 'x', opener=lambda path, flags: os.open(path, flags, 0o600)) as output:
        output.writelines(f'export {key}={shlex.quote(value)}\n' for key, value in environment.items())


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('--public')
    parser.add_argument('--management')
    parser.add_argument('--ca')
    parser.add_argument('--records', required=True)
    parser.add_argument('--seed-only', action='store_true', help='Seed enrollment and uploads without export or security checks')
    parser.add_argument('--assert-db', action='store_true')
    parser.add_argument('--assert-study', action='store_true')
    parser.add_argument('--create-study', action='store_true')
    parser.add_argument('--api-study', help='Researcher API root (.../chronicle/v3): create a fixture study with the '
                                            'bearer token on stdin; --public names its policy origin')
    parser.add_argument('--participant', help='Participant id for --api-study')
    parser.add_argument('--capture-db', action='store_true', help='Record upload-table counts before restoring')
    parser.add_argument('--enrollment-credentials', help='Private fixture credentials; never upload as an artifact')
    parser.add_argument('--upload-security-environment', help='Write a private shell environment for the upload layer')
    parser.add_argument('--benchmark-device-fixtures', help='Write a private real enrolled-device inventory for k6')
    parser.add_argument('--benchmark-device-count', type=int, help='One real device per configured peak VU')
    parser.add_argument('--project')
    parser.add_argument('--resolve-public', help='Fixture transport endpoint; TLS still validates the public hostname')
    parser.add_argument('--ipv4', action='store_true')
    parser.add_argument('--transport-recipe', help='Private synthetic transfer recipe; never upload as an artifact')
    parser.add_argument('--mobile-canary', help='Private verification recipe for this synthetic participant')
    parser.add_argument('--transport-replay', action='store_true')
    parser.add_argument('--idle-failure', action='store_true')
    parser.add_argument('--browser-burst', action='store_true')
    parser.add_argument('--body-deadline-test-seconds', type=float)
    parser.add_argument('--session-save', help='Private file for one dashboard session; never upload as an artifact')
    parser.add_argument('--session-check', help='Print whether a saved dashboard session still reads --records study')
    parser.add_argument('--expect-login-refused', action='store_true', help='Fail unless the stdin password is refused')
    args = parser.parse_args()
    if args.seed_only and (args.upload_security_environment is not None or args.transport_recipe is not None):
        parser.error('--seed-only cannot be combined with --upload-security-environment or --transport-recipe')
    return args


def main():
    args = parse_args()
    if args.resolve_public:
        configure_fixture_address(args.public, args.resolve_public)
    if args.ipv4:
        resolve_ipv4 = socket.getaddrinfo
        socket.getaddrinfo = lambda host, port, *arguments, **keywords: [
            address for address in resolve_ipv4(host, port, *arguments, **keywords) if address[0] == socket.AF_INET]
    if args.body_deadline_test_seconds is not None:
        for origin in (args.public, args.management):
            probe_body_deadline(origin, args.ca, args.body_deadline_test_seconds)
        return
    if args.transport_replay:
        recipe = json.loads(Path(args.transport_recipe).read_text())
        if args.browser_burst:
            browser = client(args.ca)
            for _ in range(BROWSER_BURST_REQUESTS):
                request(browser, recipe['browser']['url'], headers=recipe['browser']['headers'])
            print('PASS browser session burst through shared VPN NAT')
            return
        transport_replay(recipe, args.ca, args.idle_failure)
        print('PASS bounded short-idle failure' if args.idle_failure else 'PASS slow near-limit replay and complete large export')
        return
    if args.upload_security_environment:
        # Its probes add rows for the enrolled participant, so it runs after the receipt counts are asserted.
        if not args.enrollment_credentials:
            raise ValueError('upload security requires --enrollment-credentials')
        write_upload_security_environment(args.public, args.management, sys.stdin.readline().rstrip('\n'), args.enrollment_credentials,
                                          args.ca, args.resolve_public, args.upload_security_environment)
        return
    if args.benchmark_device_fixtures:
        if args.benchmark_device_count is None or not args.enrollment_credentials:
            raise ValueError('benchmark inventory requires --benchmark-device-count and --enrollment-credentials')
        credentials = benchmark_device_inventory(args.public, args.management, args.ca,
                                                 sys.stdin.readline().rstrip('\n'), args.benchmark_device_count,
                                                 args.benchmark_device_fixtures)
        write_private_fixture(args.enrollment_credentials, credentials)
        print(f'PASS enrolled {args.benchmark_device_count} distinct acknowledged benchmark devices')
        return
    if args.api_study:
        records = api_fixture_study(args.api_study, sys.stdin.readline().rstrip('\n'), args.public, args.participant)
        write_private_fixture(args.records, records)
        print('PASS API created a configured fixture study with conditional edits')
        return
    if args.create_study:
        browser, headers = dashboard_client(args.management, args.ca, sys.stdin.readline().rstrip('\n'))
        study = create_study(browser, headers, args.management + DASHBOARD_API, datetime.now(timezone.utc))
        Path(args.records).write_text(json.dumps({'study': study}))
        print('PASS API created a study with researcher permissions')
        return
    if args.session_save:
        save_session(args.management, args.ca, sys.stdin.readline().rstrip('\n'), args.session_save)
        return
    if args.session_check:
        print(session_state(args.management, args.ca, args.session_check, json.loads(Path(args.records).read_text())))
        return
    if args.expect_login_refused:
        if not login_refused(args.management, args.ca, sys.stdin.readline().rstrip('\n')):
            raise SystemExit('the dashboard accepted a retired password')
        print('PASS retired dashboard password refused')
        return
    if args.assert_study:
        assert_study(json.loads(Path(args.records).read_text()), args.management, args.ca, sys.stdin.readline().rstrip('\n'))
        print('PASS study and researcher permissions survived backend restart')
        return
    if args.assert_db or args.capture_db:
        records = json.loads(Path(args.records).read_text())
        def query(sql):
            result = subprocess.run(['docker', 'compose', '-p', args.project, 'exec', '-T', 'postgres', '/bin/bash', '-ceu',
                                     'PGPASSWORD="$POSTGRES_PASSWORD" psql -X -qAt -v ON_ERROR_STOP=1 -h 127.0.0.1 '
                                     '-U "${POSTGRES_USER:-chronicle}" -d "${POSTGRES_DB:-chronicle}" -f -'],
                                    input=sql, capture_output=True, text=True, timeout=REQUEST_TIMEOUT_SECONDS, check=True)
            return result.stdout
        if args.capture_db:
            records['counts'] = upload_row_counts(records, query)
            Path(args.records).write_text(json.dumps(records))
            print('PASS captured upload-table counts for restore verification')
            return
        deadline = time.monotonic() + PERSIST_WAIT_SECONDS
        while True:
            try:
                assert_persisted(records, query)
                break
            except RuntimeError:
                if time.monotonic() >= deadline:
                    raise
                time.sleep(2)
    else:
        records = exercise(args.public, args.management, args.ca, sys.stdin.readline().rstrip('\n'),
                           transport_recipe=args.transport_recipe, enrollment_credentials=args.enrollment_credentials,
                           seed_only=args.seed_only, mobile_canary=args.mobile_canary)
        Path(args.records).write_text(json.dumps(records))
    print('PASS real enrollment, upload contracts and receipts' if args.assert_db else 'PASS dashboard session, enrollment and uploads')


if __name__ == '__main__':
    main()
