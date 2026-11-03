import { expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';
import Ajv from '../../chronicle-web/node_modules/ajv';
import { parse } from '../../chronicle-web/node_modules/yaml';

const document = parse(readFileSync(new URL('../../chronicle-api/chronicle.yaml', import.meta.url), 'utf8'));
const validate = new Ajv({ strict: false }).compile(
  document.components.schemas.AndroidUploadDiagnosticEvent.properties.issueCode,
);

test('the published request schema accepts a bounded code from a newer collector', () => {
  expect(validate('FUTURE_COLLECTOR_ISSUE')).toBe(true);
  expect(validate('x'.repeat(129))).toBe(false);
});

test('the request schema measures code length in Unicode characters', () => {
  expect(validate('🙂'.repeat(128))).toBe(true);
  expect(validate('🙂'.repeat(129))).toBe(false);
});

test('Android usage uploads publish the same array body that ChronicleData reads', () => {
  const usageSchema = document.components.schemas.ChronicleData;
  const validateBody = new Ajv({ strict: false }).compile({
    ...usageSchema,
    components: document.components,
  });
  expect(validateBody([])).toBe(true);
  expect(validateBody({})).toBe(false);
});
