import { expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';
import Ajv from '../../chronicle-web/node_modules/ajv';
import { parse } from '../../chronicle-web/node_modules/yaml';

const document = parse(readFileSync(new URL('../../chronicle-api/chronicle.yaml', import.meta.url), 'utf8'));
const fields = JSON.parse(readFileSync(new URL('./fixtures/string-length-cases.json', import.meta.url), 'utf8')) as {
  model: string;
  property: string;
}[];
const validator = new Ajv({ strict: false });
validator.addKeyword({
  keyword: 'x-minLengthUtf16',
  type: 'string',
  schemaType: 'number',
  validate: (limit: number, value: string) => value.length >= limit,
});
validator.addKeyword({
  keyword: 'x-maxLengthUtf16',
  type: 'string',
  schemaType: 'number',
  validate: (limit: number, value: string) => value.length <= limit,
});

for (const field of fields) {
  test(`${field.model}.${field.property} validates its declared UTF-16 length budget in actual Ajv`, () => {
    const schema = document.components.schemas[field.model].properties[field.property];
    const maximum = schema['x-maxLengthUtf16'];
    const minimum = schema['x-minLengthUtf16'] ?? 0;
    expect(typeof maximum).toBe('number');
    const validate = validator.compile(schema);
    const samples = [
      '',
      'a'.repeat(maximum),
      'a'.repeat(maximum + 1),
      '😀'.repeat(Math.floor(maximum / 2)) + (maximum % 2 ? 'a' : ''),
      '😀'.repeat(maximum),
      '😀'.repeat(Math.ceil(minimum / 2)),
    ];
    for (const value of samples) expect(validate(value)).toBe(value.length >= minimum && value.length <= maximum);
  });
}

test('standard maxLength retains Unicode semantics while the declared application constraint counts UTF-16', () => {
  const schema = document.components.schemas.Study.properties.title;
  const value = '😀'.repeat(schema.maxLength);
  expect(new Ajv({ strict: false }).compile({ type: 'string', maxLength: schema.maxLength })(value)).toBe(true);
  expect(validator.compile(schema)(value)).toBe(false);
});

test('all published patterns compile as ECMA regular expressions', () => {
  const pending: unknown[] = [document];
  let count = 0;
  while (pending.length) {
    const node = pending.pop();
    if (!node || typeof node !== 'object') continue;
    for (const [key, value] of Object.entries(node)) {
      if (key === 'pattern' && typeof value === 'string') {
        expect(() => new RegExp(value, 'u')).not.toThrow();
        count++;
      } else if (value && typeof value === 'object') pending.push(value);
    }
  }
  expect(count).toBeGreaterThan(0);
});

test('the complete webhook schema preserves the Java URL pattern boundaries', () => {
  const validate = validator.compile({
    components: document.components,
    ...document.components.schemas.WebhookCreateRequest,
  });
  // Reflected from the actual @Pattern: ASCII case folding and Java's complete-match line terminators.
  const cases: [string, boolean][] = [
    ['https://example.invalid/path', true],
    ['HTTPS://example.invalid/path', true],
    ['hTtPs://example.invalid/path', true],
    ['http\u017F://example.invalid/path', false],
    ['http://example.invalid/path', false],
    ['https://', true],
    ['https://example.invalid/path\n', false],
    ['https://example.invalid/\rpath', false],
    ['https://example.invalid/\u0085path', false],
    ['https://example.invalid/\u2028path', false],
    ['https://example.invalid/\u2029path', false],
    ['https://example.invalid/\u000Bpath', true],
    ['https://example.invalid/\fpath', true],
    ['https://example.invalid/😀', true],
  ];
  for (const [url, accepted] of cases) {
    expect(
      validate({ url, secret: 's'.repeat(32), eventTypes: [document.components.schemas.WebhookEventType.enum[0]] }),
    ).toBe(accepted);
  }
});

test('optional authentication request bodies stay optional in the published operations', () => {
  const source = readFileSync(
    new URL(
      '../../chronicle-server/src/main/kotlin/com/openlattice/chronicle/controllers/AuthTokenController.kt',
      import.meta.url,
    ),
    'utf8',
  );
  const optional = [...source.matchAll(/public fun (\w+)\(\s*@RequestBody\(required\s*=\s*false\)/g)].map(
    (match) => match[1],
  );
  const paths = document.paths as Record<
    string,
    Record<string, { operationId?: string; requestBody?: { required?: boolean } }>
  >;
  const operations = Object.values(paths).flatMap((path) => Object.values(path));
  expect(optional.length).toBeGreaterThan(0);
  for (const name of optional) {
    const documented = operations.filter((operation) => operation.operationId === name);
    expect(documented.length).toBeGreaterThan(0);
    for (const operation of documented) expect(operation.requestBody?.required ?? false).toBe(false);
  }
});
