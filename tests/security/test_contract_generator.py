"""LinkML owns every shared enum and the generated database value constraints."""
import importlib.util
import json
import re
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import yaml

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('contracts', ROOT / 'scripts/generate-chronicle-contracts.py')
contracts = importlib.util.module_from_spec(spec)
spec.loader.exec_module(contracts)


class ContractGeneratorTest(unittest.TestCase):
    def test_acknowledgment_generated_limit_uses_the_utf16_owner(self):
        document = yaml.safe_load(contracts.OPENAPI_PATH.read_text())
        field = document['components']['schemas']['CollectionAcknowledgment']['properties']['appVersion']
        self.assertEqual(64, field['x-maxLengthUtf16'])
        field['x-maxLengthUtf16'] = 65
        scratch = ROOT / 'build/operator-test-runs'
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as directory:
            source = Path(directory) / 'contract.yaml'
            source.write_text(yaml.safe_dump(document))
            with patch.object(contracts, 'OPENAPI_PATH', source):
                outputs = contracts.api_constraint_outputs()
        target = ROOT / 'chronicle-models/src/main/kotlin/com/openlattice/chronicle/generated/CollectionAcknowledgmentConstraints.kt'
        self.assertIn('public const val MAX_APP_VERSION_UTF16_LENGTH: Int = 65', outputs[target])

    def test_producer_version_bounds_are_generated_from_the_openapi_owner(self):
        self.assertTrue(hasattr(contracts, 'api_constraint_outputs'))
        output = contracts.api_constraint_outputs()
        target = ROOT / 'chronicle-models/src/main/kotlin/com/openlattice/chronicle/generated/ProducerVersionConstraints.kt'
        self.assertIn(target, output)
        self.assertIn('public const val MAX_LENGTH: Int = 64', output[target])
        declaration = next(line for line in output[target].splitlines() if 'const val PATTERN:' in line)
        pattern = yaml.safe_load(contracts.OPENAPI_PATH.read_text())['components']['schemas']['BatterySample']['properties']['producerVersion']['pattern']
        self.assertEqual(pattern, json.loads(declaration.split(' = ', 1)[1]))

    def test_producer_version_uses_exact_unicode_white_space_members(self):
        pattern = yaml.safe_load(contracts.OPENAPI_PATH.read_text())['components']['schemas']['BatterySample']['properties']['producerVersion']['pattern']
        # Unicode PropList White_Space, 25 code points; nearby controls/BOM are outside this declared set.
        white_space = [*range(0x0009, 0x000E), 0x0020, 0x0085, 0x00A0, 0x1680,
                       *range(0x2000, 0x200B), 0x2028, 0x2029, 0x202F, 0x205F, 0x3000]
        self.assertEqual(25, len(white_space))
        for codepoint in white_space:
            self.assertIsNone(re.fullmatch(pattern, chr(codepoint)))
        for value in ('v1.2.3', '\u001c', '\u200b', '\ufeff', ' \U0001f642 '):
            self.assertIsNotNone(re.fullmatch(pattern, value))

    def test_generated_document_title_uses_sentence_case(self):
        title = contracts.render_markdown(contracts.load_schema()).splitlines()[0]
        self.assertEqual('# Chronicle generated contracts', title)

    def test_new_shared_enums_have_one_owner_and_generated_kotlin_consumers(self):
        schema = contracts.load_schema()
        for name in ('ApiKeyScope', 'ParticipantFormKind', 'UploadType'):
            self.assertIn(name, schema['enums'])
        outputs = contracts.study_enum_outputs(schema)
        for name, target in (
            ('ApiKeyScope', 'chronicle-api/src/main/kotlin/com/openlattice/chronicle/apikey/ApiKeyScope.kt'),
            ('ParticipantFormKind', 'chronicle-models/src/main/kotlin/com/openlattice/chronicle/participantaccess/ParticipantFormKind.kt'),
            ('UploadType', 'chronicle-server/src/main/kotlin/com/openlattice/chronicle/services/upload/UploadType.kt'),
        ):
            self.assertIn(ROOT / target, outputs)
            for value, _ in contracts.enum_values(schema, name):
                self.assertIn(f'    {value}', outputs[ROOT / target])
        self.assertIn('AndroidSensorRejected', dict(contracts.enum_values(schema, 'UploadType')))

    def test_database_constraints_are_derived_from_the_ontology(self):
        self.assertTrue(hasattr(contracts, 'fresh_schema_output'), 'Database constraints must be generated')
        schema = contracts.load_schema()
        generated = contracts.fresh_schema_output(schema)
        self.assertIn("CHECK (participant_id ~ '^(?![.]{1,2}$)[A-Za-z0-9_.-]{1,255}$')", generated)
        self.assertIn("CHECK (upload_type IN ('Android', 'AndroidSensor', 'AndroidSensorRejected'))", generated)

    def test_producer_database_bound_follows_the_openapi_scalar(self):
        document = yaml.safe_load(contracts.OPENAPI_PATH.read_text())
        document['components']['schemas']['BatterySample']['properties']['producerVersion']['maxLength'] = 65
        scratch = ROOT / 'build/operator-test-runs'
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as directory:
            source = Path(directory) / 'contract.yaml'
            source.write_text(yaml.safe_dump(document))
            with patch.object(contracts, 'OPENAPI_PATH', source):
                output = contracts.fresh_schema_output(contracts.load_schema())
        constraint = next(line for line in output.splitlines() if 'ADD CONSTRAINT battery_telemetry_producer_version_check ' in line)
        self.assertIn('char_length(producer_version) <= 65', constraint)

    def test_producer_database_regex_is_safe_for_strict_dump_framing(self):
        generated = contracts.fresh_schema_output(contracts.load_schema())
        constraint = next(line for line in generated.splitlines()
                          if 'ADD CONSTRAINT battery_telemetry_producer_version_check ' in line)
        self.assertNotIn("\\", constraint)

    def test_producer_database_regex_preserves_backslash_and_apostrophe_quoting(self):
        document = yaml.safe_load(contracts.OPENAPI_PATH.read_text())
        document['components']['schemas']['BatterySample']['properties']['producerVersion']['pattern'] = r"a\b'c"
        scratch = ROOT / 'build/operator-test-runs'
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as directory:
            source = Path(directory) / 'contract.yaml'
            source.write_text(yaml.safe_dump(document))
            with patch.object(contracts, 'OPENAPI_PATH', source):
                output = contracts.fresh_schema_output(contracts.load_schema())
        constraint = next(line for line in output.splitlines()
                          if 'ADD CONSTRAINT battery_telemetry_producer_version_check ' in line)
        self.assertEqual(
            "ALTER TABLE public.battery_telemetry ADD CONSTRAINT battery_telemetry_producer_version_check "
            "CHECK (producer_version IS NULL OR (char_length(producer_version) <= 64 "
            "AND producer_version ~ ('a' || chr(92) || 'b''c')));", constraint)
        self.assertNotIn("\\", constraint)


if __name__ == '__main__':
    unittest.main()
