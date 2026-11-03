"""The executable contract lint rejects incomplete wire schemas and copied values."""
import importlib.util
import inspect
import json
import re
import sys
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('contract_drift', ROOT / 'tests/security/contract-drift-diff.py')
drift = importlib.util.module_from_spec(spec)
argv = sys.argv
sys.argv = [sys.argv[0]]
spec.loader.exec_module(drift)
sys.argv = argv


class ContractDriftTest(unittest.TestCase):
    def setUp(self):
        drift.failures.clear()
        for name in ("check_numeric_units", "check_typed_bodies", "check_request_operations", "check_api_literal_unions"):
            self.assertTrue(hasattr(drift, name), f"Missing contract lint: {name}")

    def test_device_usage_publishes_seconds(self):
        document = yaml.safe_load((ROOT / 'chronicle-api/chronicle.yaml').read_text())
        drift.check_numeric_units(document['components']['schemas'])
        self.assertEqual([], drift.failures)

    def test_component_references_resolve(self):
        document = yaml.safe_load((ROOT / 'chronicle-api/chronicle.yaml').read_text())
        references = set(re.findall(r'#/components/schemas/([^" ]+)', json.dumps(document)))
        for reference in references:
            node = document['components']['schemas']
            for token in reference.split('/'):
                self.assertIn(token, node, reference)
                node = node[token]

    def test_unit_lint_rejects_unnamed_duration(self):
        drift.check_numeric_units({'Usage': {'properties': {
            'totalTime': {'type': 'number'}, 'samplingRate': {'type': 'number'},
        }}})
        self.assertEqual(2, len(drift.failures))

    def test_unit_lint_accepts_units_and_timestamp_formats(self):
        drift.check_numeric_units({'Usage': {'properties': {
            'durationSeconds': {'type': 'number'},
            'samplingRateHz': {'type': 'number'},
            'totalTime': {'type': 'number', 'description': 'Total seconds.'},
            'timestamp': {'type': 'string', 'format': 'date-time'},
        }}})
        self.assertEqual([], drift.failures)

    def test_all_request_and_response_objects_are_typed(self):
        document = yaml.safe_load((ROOT / 'chronicle-api/chronicle.yaml').read_text())
        self.assertIn('schemas', inspect.signature(drift.check_typed_bodies).parameters)
        drift.check_typed_bodies(document['paths'], document['components']['schemas'])
        self.assertEqual([], drift.failures)

    def test_opaque_nested_response_is_rejected(self):
        drift.check_typed_bodies({'/test': {'get': {'responses': {'200': {'content': {
            'application/json': {'schema': {'type': 'array', 'items': {'type': 'object'}}},
        }}}}}})
        self.assertEqual(1, len(drift.failures))

    def test_opaque_referenced_component_is_rejected(self):
        self.assertIn('schemas', inspect.signature(drift.check_typed_bodies).parameters)
        drift.check_typed_bodies({'/test': {'post': {'requestBody': {'content': {
            'application/json': {'schema': {'$ref': '#/components/schemas/Body'}},
        }}}}}, {'Body': {'type': 'object'}})
        self.assertEqual(1, len(drift.failures))

    def test_web_methods_must_match_the_documented_operation(self):
        paths = {'/chronicle/v3/test': {'get': {}}}
        drift.check_request_operations(paths, [{'path': '/test', 'method': 'POST', 'callee': 'baseQuery'}], set())
        self.assertEqual(1, len(drift.failures))

    def test_api_layer_cannot_copy_a_wire_enum(self):
        for source in ("export type Scope = 'READ' | 'WRITE';", "export type Scope =\n | 'READ'\n | 'WRITE';"):
            drift.failures.clear()
            drift.check_api_literal_unions(source)
            self.assertEqual(1, len(drift.failures))
        drift.failures.clear()
        drift.check_api_literal_unions("export type Scope = components['schemas']['Scope'];")
        self.assertEqual([], drift.failures)


if __name__ == '__main__':
    unittest.main()
