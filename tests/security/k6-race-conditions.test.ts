import { expect, mock, test } from 'bun:test';
import { createHash, createHmac, randomBytes } from 'node:crypto';
import contracts from '../../generated/domain-contracts/chronicle-domain-contracts.json';
import { isBackendApiPath } from '../../chronicle-web/scripts/backend-api-path';

const routes = await Bun.file(new URL('../../chronicle-server/src/test/resources/route-inventory.json', import.meta.url)).json() as {
  method: string; path: string;
}[];
const requests: { path: string; headers: Record<string, string>; body?: string }[] = [];
const checks: boolean[] = [];
const counters = new Map<string, number>();
const pauses: number[] = [];
let forcedStatus: number | undefined;
let operationIdFor: () => string = () => 'synthetic-operation';
const environment = {
  AUTH_TOKEN: 'synthetic-researcher', JWT_TOKEN: 'synthetic-researcher', STUDY_ID: '00000000-0000-0000-0000-000000000001',
  TEST_RANDOM_DEVICE_ID: '00000000-0000-0000-0000-000000000002', MOBILE_SIGNING_SECRET: 'synthetic-signing-key',
  MAX_VUS: '1', DEVICE_FIXTURES_FILE: 'synthetic-devices.json',
};
const mobileHeaders = await Bun.file(new URL('../../chronicle-web/e2e/dsl/mobile-headers.json', import.meta.url)).text();
const headerNames = JSON.parse(mobileHeaders);
const uploadProbe = await Bun.file(new URL('../../chronicle-server/src/test/resources/upload-probe-contract.json', import.meta.url)).json();
Object.assign(globalThis, { __ENV: environment, __VU: 1, open: (path: string) => path.endsWith('mobile-headers.json') ? mobileHeaders
  : path.endsWith('synthetic-devices.json') ? JSON.stringify([{ participant_id: 'synthetic-phone', random_device_id: environment.TEST_RANDOM_DEVICE_ID, api_key: 'synthetic-device-key' }]) : JSON.stringify(contracts) });

function respond(method: string, url: string, body?: string, options?: { headers: Record<string, string> }) {
  const path = new URL(url).pathname;
  const headers = options?.headers ?? {};
  requests.push({ path, headers, ...(body !== undefined ? { body } : {}) });
  const documented = routes.some((route) => route.method.toLowerCase() === method &&
    new RegExp(`^${route.path.replace(/\{[^}]+\}/g, '[^/]+')}$`).test(path));
  let payload: unknown = {};
  if (path.endsWith('/form-access-codes')) payload = { accessCode: 'synthetic-invitation' };
  if (path.endsWith('/enrollment-preview')) payload = { manifestDigest: 'synthetic-digest', manifest: {
    collectionSettings: { modules: Object.fromEntries(contracts.contracts.activeDefaultEnabledCollectionModuleIds.map((id) => [id, { enabled: true }])) },
    settingsVersion: 1, participantPolicy: { version: 'fixture-policy' },
  } };
  if (path.endsWith('/enroll')) payload = { apiKey: headers[headerNames.proposedApiKey] };
  if (path.endsWith('/android') && method === 'post') payload = {
    acceptedIds: JSON.parse(body ?? '[]').map((event: { clientEventId: string }) => event.clientEventId), discardedIds: [], settingsVersion: 1,
  };
  if (path.endsWith('/android/sensors') && method === 'post') payload = JSON.parse(body ?? '[]').length;
  if (method === 'delete' && path.endsWith('/participants')) payload = [operationIdFor()];
  return { status: forcedStatus ?? (path === '/health' ? 204 : documented ? 200 : 404),
    headers: { Etag: '"1"' }, timings: { duration: 1 }, json: () => payload };
}

mock.module('k6/http', () => ({ default: {
  get: (url: string, options: { headers: Record<string, string> }) => respond('get', url, undefined, options),
  post: (url: string, body: string, options: { headers: Record<string, string> }) => respond('post', url, body, options),
  del: (url: string, body: string, options: { headers: Record<string, string> }) => respond('delete', url, body, options),
} }));
mock.module('k6', () => ({ sleep: (seconds: number) => { pauses.push(seconds); }, group: (_name: string, work: () => unknown) => work(), check: (response: unknown, predicates: Record<string, (value: unknown) => boolean>) => {
  const passed = Object.values(predicates).every((predicate) => predicate(response));
  checks.push(passed);
  return passed;
} }));
mock.module('k6/metrics', () => ({ Counter: class { constructor(private name: string) {} add(value: number) { counters.set(this.name, (counters.get(this.name) ?? 0) + value); } }, Rate: class { add() {} }, Trend: class { add() {} } }));
mock.module('k6/data', () => ({ SharedArray: class { constructor(_name: string, read: () => unknown[]) { return read(); } } }));
mock.module('k6/crypto', () => ({ randomBytes: (length: number) => Uint8Array.from(randomBytes(length)).buffer, default: {
  randomBytes: (length: number) => Uint8Array.from(randomBytes(length)).buffer,
  sha256: (data: string, encoding: 'hex') => createHash('sha256').update(data).digest(encoding),
  hmac: (_algorithm: string, key: string, data: string, encoding: 'base64') => createHmac('sha256', key).update(data).digest(encoding),
} }));

const probe = await import('./k6-race-conditions.js');
const perf = await import('../performance/helpers.js');
const load = await import('../load/chronicle-load-test.js');
test('performance health uses the public empty-body health contract', () => {
  checks.length = 0;
  expect(perf.checkHealth().status).toBe(204);
  expect(checks).toEqual([true]);
});
test('the phone cohort accepts real usage receipts and generates post-consent sample identities', () => {
  requests.length = 0; checks.length = 0; pauses.length = 0; counters.clear();
  const originalRandom = Math.random;
  Math.random = () => 0;
  const started = Date.now();
  try { load.setup(); load.default(); } finally { Math.random = originalRandom; }
  expect(checks).toEqual([true, true]);
  expect(counters.get('events_uploaded')).toBe(10);
  expect(counters.get('samples_uploaded')).toBe(500);
  const usage = requests.find(({ path }) => path.endsWith('/android'));
  const events = JSON.parse(usage?.body ?? '[]');
  expect(events.every((event: { clientEventId?: string; timestamp: string }) => event.clientEventId && Date.parse(event.timestamp) >= started)).toBe(true);
  expect(pauses).toHaveLength(1);
  expect(pauses[0]).toBeGreaterThan(0);
  expect(pauses[0]).toBeLessThanOrEqual(60);
});
test('each synthetic usage event is a distinct stored row, so accepted counts equal new rows', () => {
  // The server's logical-duplicate identity is every column except uploaded_at and client_event_id
  // (PostgresEventTables.kt): a fresh clientEventId does not make a repeated (package, type, timestamp) a new event.
  const events = perf.generateUsageEventBatch(10, environment.STUDY_ID, 'perf-participant');
  const logical = events.map(({ clientEventId: _id, ...stored }: Record<string, unknown>) =>
    JSON.stringify(Object.entries(stored).sort(([left], [right]) => left.localeCompare(right))));
  expect(events).toHaveLength(10);
  expect(new Set(logical).size).toBe(10);
});
test('the compact load summary keeps the upload median and the sensor tail the thresholds judge', () => {
  expect(load.options.summaryTrendStats).toEqual(expect.arrayContaining(['med', 'p(95)', 'p(99)']));
  const result = load.handleSummary({ metrics: {
    upload_duration: { values: { med: 10, 'p(95)': 20, 'p(99)': 30 } },
    sensor_upload_duration: { values: { med: 35, 'p(95)': 40, 'p(99)': 50 } },
  } });
  const metrics = JSON.parse(result['load-test-results.json']).metrics;
  expect(metrics).toMatchObject({ upload_p50: 10, upload_p95: 20, upload_p99: 30, sensor_p95: 40, sensor_p99: 50 });
  expect(JSON.parse(result.stdout)).toEqual(JSON.parse(result['load-test-results.json']));
});
test('performance writes invite, bind a device key, acknowledge consent and sign real uploads', () => {
  requests.length = 0;
  perf.enrollDevice(environment.STUDY_ID, 'perf-participant', environment.TEST_RANDOM_DEVICE_ID,
    perf.generateAndroidDevice(environment.TEST_RANDOM_DEVICE_ID));
  perf.uploadAndroidUsageEvents(environment.STUDY_ID, 'perf-participant', environment.TEST_RANDOM_DEVICE_ID,
    perf.generateUsageEventBatch(2, environment.STUDY_ID, 'perf-participant'));
  expect(requests.some(({ path }) => path.endsWith('/form-access-codes'))).toBe(true);
  const enrolled = requests.find(({ path }) => path.endsWith('/enroll'));
  const acknowledged = requests.find(({ path }) => path.endsWith('/collection-ack'));
  const uploaded = requests.find(({ path }) => path.endsWith('/android'));
  expect(enrolled?.headers[headerNames.enrollmentCode]).toBe('synthetic-invitation');
  expect(enrolled?.headers[headerNames.enrollmentAttemptId]).toMatch(/^[0-9a-f-]{36}$/);
  expect(enrolled?.headers[headerNames.manifestDigest]).toBe('synthetic-digest');
  const key = enrolled?.headers[headerNames.proposedApiKey];
  expect(acknowledged?.headers[headerNames.apiKey]).toBe(key);
  expect(uploaded?.headers[headerNames.apiKey]).toBe(key);
  expect(uploaded?.headers.Authorization).toBeUndefined();
  expect(JSON.parse(acknowledged?.body ?? '{}').disclosureVersion).toBe('fixture-policy');
  for (const request of requests.filter(({ headers }) => headers[headerNames.signature])) {
    const canonical = ['POST', request.path, request.headers[headerNames.timestamp], request.headers[headerNames.nonce],
      createHash('sha256').update(request.body ?? '').digest('hex')].join('|');
    expect(request.headers[headerNames.signature]).toBe(createHmac('sha256', environment.MOBILE_SIGNING_SECRET).update(canonical).digest('base64'));
  }
  expect(uploaded?.headers[headerNames.signature]).toBeDefined();
  const events = JSON.parse(uploaded?.body ?? '[]');
  expect(events[0].studyId).toBe(environment.STUDY_ID);
  expect(events[0].participantId).toBe('perf-participant');
  expect(events[0]['@class']).toBe('com.openlattice.chronicle.android.ChronicleUsageEvent');
  expect(new Set(events.map((event: { clientEventId: string }) => event.clientEventId)).size).toBe(2);
});
test('signed race setup reaches a registered mobile route without bypassing nonce verification', () => {
  requests.length = 0;
  expect(headerNames).toEqual(uploadProbe.mobileHeaders);
  const fixture = probe.setup();
  probe.nonce(fixture);
  const signed = requests.filter(({ headers }) => headers[headerNames.signature]);
  expect(signed.length).toBeGreaterThan(0);
  for (const request of signed) {
    expect(new Headers(request.headers).get('Authorization')).toBe(`Bearer ${environment.AUTH_TOKEN}`);
    expect(request.headers[probe.RANDOM_DEVICE_ID_HEADER]).toBe(environment.TEST_RANDOM_DEVICE_ID);
    expect(request.headers[probe.API_KEY_HEADER]).toBeUndefined();
  }
  const enrolled = requests.find(({ headers }) => headers[headerNames.proposedApiKey]);
  const secret = enrolled?.headers[headerNames.proposedApiKey].split('_').at(-1);
  for (const request of signed) expect(request.headers[headerNames.nonce].replaceAll('-', '')).not.toBe(secret);
});

const rate = await import('../load/k6-rate-limit-validation.js');
test.each([200, 404])('load probes fail when status %s never demonstrates throttling', (status) => {
  forcedStatus = status;
  checks.length = 0;
  try {
    rate.authBurst();
    expect(checks).toContain(false);
  } finally {
    forcedStatus = undefined;
  }
});

test('the preview proxy recognizes every registered versioned API route', () => {
  const registered = routes.filter(({ path }) => /^\/chronicle\/v\d+\//.test(path));
  expect(registered.length).toBeGreaterThan(0);
  for (const { path } of registered) expect(isBackendApiPath(path)).toBe(true);
});

const dos = await import('../load/k6-dos-patterns.js');
test('DoS assertions gate k6 exit status', () => {
  expect(dos.options.thresholds.checks).toContain('rate==1');
});

test.each([200, 404])('the signed race probe rejects a server that only returns %s', (status) => {
  const fixture = probe.setup();
  forcedStatus = status;
  checks.length = 0;
  counters.clear();
  try {
    const scenario = probe.options.scenarios.nonce;
    for (let index = 0; index < scenario.vus; index++) probe.nonce(fixture);
    const threshold = probe.options.thresholds.nonce_accepted[0];
    const expectedCount = Number(threshold.split('==')[1]);
    expect(counters.get('nonce_accepted') ?? 0).not.toBe(expectedCount);
    if (status === 404) expect(checks).toContain(false);
  } finally {
    forcedStatus = undefined;
  }
});

test('the enrollment race is the first enrollment of its participant', () => {
  requests.length = 0;
  const fixture = probe.setup();
  const target = new URL(fixture.fresh.mobile).pathname + '/enroll';
  expect(requests.filter(({ path }) => path === target)).toHaveLength(0);
  probe.enrollment(fixture);
  expect(requests.filter(({ path }) => path === target)).toHaveLength(1);
});

test('the erasure race rejects a server that opens an operation per request', () => {
  const fixture = probe.setup();
  checks.length = 0;
  let next = 0;
  try {
    operationIdFor = () => `operation-${next++}`;
    probe.deletion(fixture);
    expect(checks).toEqual([false]);
    operationIdFor = () => 'one-operation';
    probe.deletion(fixture);
    expect(checks).toEqual([false, true]);
  } finally {
    operationIdFor = () => 'synthetic-operation';
  }
});
