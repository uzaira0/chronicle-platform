"""Authorization probes use valid inputs derived from the published contract."""
import importlib.util
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
MODULE = ROOT / 'tests/security/route_probe_inputs.py'
inputs = None
if MODULE.exists():
    spec = importlib.util.spec_from_file_location('route_probe_inputs', MODULE)
    inputs = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(inputs)


class RouteProbeInputsTest(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(inputs, 'Missing contract-derived request input reader')
        self.document = yaml.safe_load((ROOT / 'chronicle-api/chronicle.yaml').read_text())
        self.fixtures = {'studyId': '00000000-0000-4000-8000-000000000002', 'participantId': 'probe-participant',
                         'headers': {'Idempotency-Key': '00000000-0000-4000-8000-000000000003', 'If-Match': '"7"'}}

    def test_real_create_request_uses_schema_required_fields_and_seeded_headers(self):
        result = inputs.request_inputs(self.document, '/chronicle/v3/study/{studyId}/api-keys', 'POST', self.fixtures)
        self.assertEqual({'name': 'probe'}, result['json'])
        self.assertEqual(self.fixtures['headers']['Idempotency-Key'], result['headers']['Idempotency-Key'])

    def test_native_upload_and_read_probes_keep_the_enrollment_credential_and_device_binding(self):
        headers = self.fixtures['headers'] | {'X-Api-Key': 'fixture-enrollment-key',
                                              'X-Chronicle-Random-Device-Id': 'fixture-device'}
        fixtures = self.fixtures | {'headers': headers, 'body': []}
        base = '/chronicle/v4/study/{studyId}/participant/{participantId}'
        for suffix, method in (('/android', 'POST'), ('/reminders', 'GET'), ('/status', 'GET')):
            result = inputs.request_inputs(self.document, base + suffix, method, fixtures)
            self.assertEqual(headers['X-Api-Key'], result['headers'].get('X-Api-Key'), suffix)
            self.assertEqual(headers['X-Chronicle-Random-Device-Id'],
                             result['headers'].get('X-Chronicle-Random-Device-Id'), suffix)

    def test_v4_form_codes_describe_native_headers_without_requiring_them_for_researchers(self):
        path = '/chronicle/v4/study/{studyId}/participant/{participantId}/form-access-codes'
        headers = {'X-Api-Key': 'fixture-enrollment-key', 'X-Chronicle-Random-Device-Id': 'fixture-device'}
        body = {'formKind': 'APP_USAGE'}
        native = inputs.request_inputs(self.document, path, 'POST', self.fixtures | {'headers': headers, 'body': body})
        self.assertEqual(headers, native['headers'])
        researcher = inputs.request_inputs(self.document, path, 'POST', self.fixtures | {'headers': {}, 'body': body})
        self.assertEqual({}, researcher['headers'])

    def test_utf16_minimum_generates_ascii_within_the_same_native_budget(self):
        schema = {'type': 'string', 'minLength': 16, 'maxLength': 255,
                  'x-minLengthUtf16': 32, 'x-maxLengthUtf16': 255}
        document = {'paths': {'/probe': {'post': {'requestBody': {'content': {'application/json': {'schema': schema}}}}}}}
        result = inputs.request_inputs(document, '/probe', 'POST', {})
        self.assertGreaterEqual(len(result['json']), 32)
        actual = inputs.request_inputs(document, '/probe', 'POST', {'body': '\U0001f600' * 16})
        self.assertEqual('\U0001f600' * 16, actual['json'])

    def test_utf16_maximum_refuses_a_fixture_that_only_satisfies_standard_maxlength(self):
        schema = {'type': 'string', 'maxLength': 255, 'x-maxLengthUtf16': 255}
        document = {'paths': {'/probe': {'post': {'requestBody': {'content': {'application/json': {'schema': schema}}}}}}}
        with self.assertRaisesRegex(inputs.UnsupportedSchema, 'UTF-16'):
            inputs.request_inputs(document, '/probe', 'POST', {'body': '\U0001f600' * 128})

    def test_servlet_aliases_use_the_same_published_operation(self):
        for published, alias, method in (
            ('/chronicle/v3/study/{studyId}/api-keys', '/v3/study/{studyId}/api-keys', 'POST'),
            ('/chronicle/v3/limits/study/{studyId}', '/limits/study/{studyId}', 'PUT'),
            ('/chronicle/v3/compliance/study/{studyId}', '/compliance/study/{studyId}', 'GET'),
        ):
            canonical = inputs.request_inputs(self.document, published, method, self.fixtures)
            self.assertEqual(canonical, inputs.request_inputs(self.document, alias, method, self.fixtures))

    def test_required_query_arrays_and_dates_use_fixture_values(self):
        path = '/chronicle/v3/study/{studyId}/participants/data'
        fixtures = self.fixtures | {'query': {'dataType': 'UsageEvents', 'participantId': ['probe-participant'],
                                             'startDate': '2026-01-01T00:00:00Z', 'endDate': '2026-01-02T00:00:00Z'}}
        result = inputs.request_inputs(self.document, path, 'GET', fixtures)
        self.assertIn(('participantId', 'probe-participant'), result['query'])
        self.assertIn(('dataType', 'UsageEvents'), result['query'])

    def test_form_exports_reuse_real_schema_and_fixture_participant(self):
        fixtures = self.fixtures | {'body': {'dataType': 'UsageEvents', 'participantId': ['probe-participant']}}
        result = inputs.request_inputs(self.document, '/chronicle/v3/study/{studyId}/participants/data', 'POST', fixtures)
        self.assertEqual(fixtures['body'], result['form'])
        self.assertNotIn('json', result)

    def test_refs_allof_enum_and_minimums_are_resolved_without_schema_copies(self):
        document = {'components': {'schemas': {'Input': {'allOf': [
            {'type': 'object', 'required': ['label'], 'properties': {'label': {'type': 'string', 'minLength': 6}}},
            {'type': 'object', 'required': ['kind'], 'properties': {'kind': {'type': 'string', 'enum': ['READ', 'WRITE']}}},
        ]}}}, 'paths': {'/probe': {'post': {'requestBody': {'content': {'application/json': {
            'schema': {'$ref': '#/components/schemas/Input'},
        }}}}}}}
        result = inputs.request_inputs(document, '/probe', 'POST', {})
        self.assertGreaterEqual(len(result['json']['label']), 6)
        self.assertEqual('READ', result['json']['kind'])

    def test_missing_scoped_contract_or_seeded_identity_fails_explicitly(self):
        with self.assertRaisesRegex(inputs.UnsupportedSchema, 'operation'):
            inputs.request_inputs(self.document, '/chronicle/v3/study/{studyId}/unlisted', 'POST', self.fixtures)
        with self.assertRaisesRegex(inputs.UnsupportedSchema, 'studyId'):
            inputs.request_inputs(self.document, '/chronicle/v3/study/{studyId}/api-keys', 'POST', {})

    def test_missing_required_precondition_is_never_guessed(self):
        with self.assertRaisesRegex(inputs.UnsupportedSchema, 'If-Match'):
            inputs.request_inputs(self.document, '/chronicle/v3/survey/{studyId}/filtered', 'PUT',
                                  self.fixtures | {'headers': {}})

    def test_query_array_serialization_follows_the_declared_explode_setting(self):
        document = {'paths': {'/probe': {'get': {'parameters': [{
            'name': 'ids', 'in': 'query', 'required': True, 'explode': False,
            'schema': {'type': 'array', 'items': {'type': 'integer'}},
        }]}}}}
        result = inputs.request_inputs(document, '/probe', 'GET', {'query': {'ids': [1, 2]}})
        self.assertEqual([('ids', '1,2')], result['query'])

    def test_parameter_and_media_examples_are_read_from_the_owner(self):
        document = {'paths': {'/probe': {'post': {
            'parameters': [{'name': 'mode', 'in': 'query', 'required': True, 'example': 'example-mode',
                            'schema': {'type': 'string'}}],
            'requestBody': {'content': {'application/json': {
                'examples': {'valid': {'value': {'label': 'fixture-label'}}},
                'schema': {'type': 'object', 'required': ['label'], 'properties': {'label': {'type': 'string'}}},
            }}},
        }}}}
        result = inputs.request_inputs(document, '/probe', 'POST', {})
        self.assertEqual([('mode', 'example-mode')], result['query'])
        self.assertEqual({'label': 'fixture-label'}, result['json'])

    def test_uuid_examples_cannot_impersonate_a_seeded_identity(self):
        schema = {'type': 'string', 'format': 'uuid', 'example': self.fixtures['studyId']}
        document = {'paths': {'/probe': {'post': {'requestBody': {'content': {'application/json': {'schema': schema}}}}}}}
        with self.assertRaises(inputs.UnsupportedSchema):
            inputs.request_inputs(document, '/probe', 'POST', {})
        document['paths']['/probe']['post']['requestBody']['content']['application/json'] = {
            'example': {'id': self.fixtures['studyId']},
            'schema': {'type': 'object', 'required': ['id'], 'properties': {'id': schema}},
        }
        with self.assertRaises(inputs.UnsupportedSchema):
            inputs.request_inputs(document, '/probe', 'POST', {})

    def test_unsupported_schema_and_recursive_required_inputs_fail_closed(self):
        for schema in ({'type': 'string', 'format': 'binary'}, {'$ref': 'https://example.invalid/schema'},
                       {'type': 'string', 'pattern': '^never-generate-this$'}):
            document = {'paths': {'/probe': {'post': {'requestBody': {'content': {'application/json': {'schema': schema}}}}}}}
            with self.subTest(schema=schema), self.assertRaises(inputs.UnsupportedSchema):
                inputs.request_inputs(document, '/probe', 'POST', {})
        node = {'type': 'object', 'required': ['child'], 'properties': {'child': {'$ref': '#/components/schemas/Node'}}}
        document = {'components': {'schemas': {'Node': node}}, 'paths': {'/probe': {'post': {'requestBody': {
            'content': {'application/json': {'schema': {'$ref': '#/components/schemas/Node'}}},
        }}}}}
        with self.assertRaises(inputs.UnsupportedSchema):
            inputs.request_inputs(document, '/probe', 'POST', {})


if __name__ == '__main__':
    unittest.main()
