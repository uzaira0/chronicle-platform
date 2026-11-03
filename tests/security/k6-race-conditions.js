import http from 'k6/http';
import { check } from 'k6';
import { Counter } from 'k6/metrics';

// Disposable study with participant disclosures configured and no other traffic.
const BASE = __ENV.BASE_URL || 'http://localhost:40320';
const RESEARCHER_API = __ENV.MANAGEMENT_URL ? __ENV.MANAGEMENT_URL + '/chronicle/api/web' : BASE + '/chronicle/v3';
const STUDY = __ENV.STUDY_ID;
const DEVICE = __ENV.TEST_RANDOM_DEVICE_ID;
import { MOBILE_HEADERS, control, newNonce, prepareEnrollment, enrollInvitedDevice, signedMobileHeaders } from '../load/mobile-client.js';
export const RANDOM_DEVICE_ID_HEADER = MOBILE_HEADERS.randomDeviceId;
export const API_KEY_HEADER = MOBILE_HEADERS.apiKey;
const CONCURRENCY = 10;
const signingEnabled = Boolean(__ENV.MOBILE_SIGNING_SECRET);
const races = signingEnabled ? ['enrollment', 'nonce', 'deletion', 'settings'] : ['enrollment', 'deletion', 'settings'];
const operations = new Counter('operations');
const nonceAccepted = new Counter('nonce_accepted');
const nonceRejected = new Counter('nonce_rejected');
const settingsCommitted = new Counter('settings_committed');
const settingsRejected = new Counter('settings_rejected');
const headers = { Authorization: `Bearer ${__ENV.AUTH_TOKEN}`, 'Content-Type': 'application/json' };
if (!STUDY || !DEVICE || !__ENV.AUTH_TOKEN) {
  throw new Error('STUDY_ID, TEST_RANDOM_DEVICE_ID and AUTH_TOKEN are required');
}
export const options = {
  scenarios: Object.fromEntries(races.map((operation, index) => [operation, {
    executor: 'per-vu-iterations', vus: CONCURRENCY, iterations: 1, exec: operation,
    startTime: `${index * 10}s`, maxDuration: '10s', gracefulStop: '0s',
  }])),
  thresholds: Object.assign({
    checks: ['rate==1'],
    settings_committed: ['count==1'],
    settings_rejected: [`count==${CONCURRENCY - 1}`],
  }, Object.fromEntries(races.map(operation => [
    `operations{operation:${operation}}`, [`count==${CONCURRENCY}`],
  ])), signingEnabled ? { nonce_accepted: ['count==1'], nonce_rejected: [`count==${CONCURRENCY - 1}`] } : {}),
};
if (__ENV.UPLOAD_CONNECT_TO) {
  const mapping = __ENV.UPLOAD_CONNECT_TO.match(/^(\[[^\]]+\]:\d+|[^:]+:\d+):(\[[^\]]+\]:\d+|[^:]+:\d+)$/);
  if (!mapping) throw new Error('UPLOAD_CONNECT_TO requires host:port:host:port');
  options.hosts = { [mapping[1]]: mapping[2] };
}
function signedHeaders(path, nonce, timestamp) {
  return signedMobileHeaders(BASE + path, '[]', Object.assign({}, headers, { [RANDOM_DEVICE_ID_HEADER]: DEVICE }),
    __ENV.MOBILE_SIGNING_SECRET, nonce, timestamp);
}
export function setup() {
  if (!signingEnabled) console.log('Nonce replay race is not applicable because legacy mobile signing is disabled.');
  const study = `${RESEARCHER_API}/study/${STUDY}`;
  control(http.get(study, { headers }), 'researcher can read the fixture study');
  const participant = `race-${Date.now()}`;
  // The enrollment race needs a participant nobody has enrolled yet, so the first enrollment is the race.
  const fresh = invite(study, `${participant}-fresh`, newNonce());
  const enrolled = invite(study, participant, DEVICE);
  const { mobile } = enrolled;
  enrollInvitedDevice(enrolled);
  const apiKey = enrolled.apiKey;
  const nonce = newNonce();
  const path = `${mobile.substring(BASE.length)}/android/sensors`;
  const timestamp = String(Math.floor(Date.now() / 1000));
  if (signingEnabled) {
    control(http.post(BASE + path, '[]', { headers: signedHeaders(path, newNonce(), timestamp) }), 'valid signed replay control');
  }
  const settingsUrl = `${study}/settings/type/DataCollection`;
  const settingsResponse = http.get(settingsUrl, { headers });
  control(settingsResponse, 'read authoritative settings');
  if (!settingsResponse.headers.Etag) throw new Error('settings positive control has no revision ETag');
  return { study, mobile, participant, fresh, apiKey, path,
    replayHeaders: signingEnabled ? signedHeaders(path, nonce, timestamp) : null,
    revision: settingsResponse.headers.Etag };
}
function invite(study, participant, device) {
  return prepareEnrollment(study, `${BASE}/chronicle/v4/study/${STUDY}/participant/${participant}`,
    participant, device, headers);
}
export function enrollment(data) {
  const { mobile, body, enrollHeaders, apiKey } = data.fresh;
  const response = http.post(`${mobile}/enroll`, body, { headers: enrollHeaders });
  check(response, { 'concurrent first enrollments of one attempt bind one credential': r => r.status === 200 && r.json().apiKey === apiKey });
  if (response.status === 200) operations.add(1, { operation: 'enrollment' });
}
export function nonce(data) {
  const response = http.post(BASE + data.path, '[]', { headers: data.replayHeaders });
  check(response, { 'valid signed replay is accepted once or rejected as replay': r => r.status === 200 || r.status === 401 });
  if (response.status === 200) nonceAccepted.add(1);
  if (response.status === 401) nonceRejected.add(1);
  if (response.status === 200 || response.status === 401) operations.add(1, { operation: 'nonce' });
}
export function deletion(data) {
  const erase = () => http.del(`${data.study}/participants`, JSON.stringify([data.participant]), { headers });
  const response = erase();
  // A repeat names the participant's open operation. Every VU gets back its own first ID only when the
  // concurrent requests all joined one operation; a second operation leaves some VU holding a different ID.
  const repeat = erase();
  check(response, { 'parallel erasure requests join one operation': r => r.status === 200 && Array.isArray(r.json())
    && r.json().length === 1 && repeat.status === 200 && repeat.json()[0] === r.json()[0] });
  if (response.status === 200) operations.add(1, { operation: 'deletion' });
}
export function settings(data) {
  // Study details share the settings revision. Each VU writes a distinct description: an unchanged write is
  // a no-op that keeps the revision, so identical bodies would all succeed without racing.
  const response = http.patch(data.study, JSON.stringify({ description: `settings race ${__VU}` }),
    { headers: Object.assign({}, headers, { 'If-Match': data.revision }) });
  check(response, { 'concurrent revision writes succeed or report a stale revision': r => r.status === 200 || r.status === 412 });
  if (response.status === 200) settingsCommitted.add(1);
  if (response.status === 412) settingsRejected.add(1);
  if (response.status === 200 || response.status === 412) operations.add(1, { operation: 'settings' });
}
