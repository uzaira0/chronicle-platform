import http from 'k6/http';
import crypto from 'k6/crypto';
import { check } from 'k6';

export const MOBILE_HEADERS = JSON.parse(open('../../chronicle-web/e2e/dsl/mobile-headers.json'));
const RANDOM_DEVICE_ID_HEADER = MOBILE_HEADERS.randomDeviceId;
const PARTICIPATION_STATUS = Object.fromEntries(
  JSON.parse(open('../../generated/domain-contracts/chronicle-domain-contracts.json')).contracts.participationStatuses
    .map(status => [status, status]));

export function control(response, label) {
  if (!check(response, { [label]: r => r.status === 200 || r.status === 201 })) throw new Error(label);
  return response.json();
}
function randomHex() {
  return Array.from(new Uint8Array(crypto.randomBytes(16)), byte => byte.toString(16).padStart(2, '0')).join('');
}
export function newNonce() {
  return randomHex().replace(/^(.{8})(.{4})(.{4})(.{4})(.{12})$/, '$1-$2-$3-$4-$5');
}
export function prepareEnrollment(study, mobile, participant, device, headers, deviceInfo) {
  control(http.post(`${study}/participant`, JSON.stringify({ participantId: participant, candidate: {},
    participationStatus: PARTICIPATION_STATUS.ENROLLED }), { headers: Object.assign({}, headers, { 'Idempotency-Key': newNonce() }) }), 'register a real disposable participant');
  const invitation = control(http.post(`${study}/participant/${participant}/form-access-codes`,
    JSON.stringify({ formKind: 'ENROLLMENT' }), { headers: Object.assign({}, headers, { 'Idempotency-Key': newNonce() }) }), 'issue an enrollment invitation');
  const enrollHeaders = { 'Content-Type': 'application/json', [RANDOM_DEVICE_ID_HEADER]: device,
    [MOBILE_HEADERS.enrollmentCode]: invitation.accessCode };
  const preview = control(http.get(`${mobile}/enrollment-preview`, { headers: enrollHeaders }), 'preview invitation');
  const random = randomHex();
  const apiKey = `ck_${random.slice(0, 8)}_${random}`;
  Object.assign(enrollHeaders, { [MOBILE_HEADERS.manifestDigest]: preview.manifestDigest,
    [MOBILE_HEADERS.enrollmentAttemptId]: newNonce(), [MOBILE_HEADERS.proposedApiKey]: apiKey });
  const body = JSON.stringify(deviceInfo || { '@class': 'com.openlattice.chronicle.sources.AndroidDevice', randomDeviceId: device,
    sdkVersion: '36', osVersion: '16', device: 'synthetic', model: 'synthetic', codename: 'synthetic', brand: 'synthetic', product: 'synthetic' });
  return { mobile, preview, enrollHeaders, body, apiKey };
}

export function signedMobileHeaders(url, body, headers, secret, nonce = newNonce(), timestamp = String(Math.floor(Date.now() / 1000))) {
  if (!secret) return headers;
  const path = url.replace(/^https?:\/\/[^/]+/, '').split('?')[0];
  const canonical = ['POST', path, timestamp, nonce, crypto.sha256(body, 'hex')].join('|');
  return Object.assign({}, headers, { [MOBILE_HEADERS.timestamp]: timestamp, [MOBILE_HEADERS.nonce]: nonce,
    [MOBILE_HEADERS.signature]: crypto.hmac('sha256', secret, canonical, 'base64') });
}

export function enrollInvitedDevice(fixture, signingSecret) {
  const response = http.post(`${fixture.mobile}/enroll`, fixture.body, { headers: fixture.enrollHeaders });
  if (control(response, 'valid enrollment control').apiKey !== fixture.apiKey) {
    throw new Error('enrollment did not bind the proposed credential');
  }
  const headers = { 'Content-Type': 'application/json', [MOBILE_HEADERS.apiKey]: fixture.apiKey,
    [RANDOM_DEVICE_ID_HEADER]: fixture.enrollHeaders[RANDOM_DEVICE_ID_HEADER] };
  const { preview } = fixture;
  const body = JSON.stringify({
    acknowledgedModules: Object.keys(preview.manifest.collectionSettings.modules)
      .filter(module => preview.manifest.collectionSettings.modules[module].enabled),
    acknowledgedAt: new Date().toISOString(), settingsVersion: preview.manifest.settingsVersion,
    disclosureVersion: preview.manifest.participantPolicy.version, manifestDigest: preview.manifestDigest,
  });
  const url = `${fixture.mobile}/android/collection-ack`;
  control(http.post(url, body, { headers: signedMobileHeaders(url, body, headers, signingSecret) }), 'record fixture consent');
  return { response, headers };
}

export function uploadAcknowledged(response, rows, usage) {
  if (response.status !== 200) return false;
  try {
    const receipt = response.json();
    if (!usage) return receipt === rows.length;
    // UploadReceipt (chronicle-models) partitions the submitted IDs into accepted and discarded only.
    if (!Array.isArray(receipt.acceptedIds) || !Array.isArray(receipt.discardedIds)) return false;
    const ids = new Set(receipt.acceptedIds);
    return receipt.discardedIds.length === 0 && ids.size === rows.length
      && rows.every(event => ids.has(event.clientEventId));
  } catch (_) {
    return false;
  }
}

export function generateUsageEventBatch(count, studyId, participantId) {
  const events = [];
  const now = Date.now();
  const packages = [
    'com.android.chrome',
    'com.whatsapp',
    'com.instagram.android',
    'com.twitter.android',
    'com.spotify.music',
    'com.google.android.youtube',
  ];

  for (let i = 0; i < count; i++) {
    events.push({
      '@class': 'com.openlattice.chronicle.android.ChronicleUsageEvent', studyId, participantId,
      appPackageName: packages[i % packages.length],
      interactionType: i % 2 === 0 ? 'Activity Resumed' : 'Activity Paused',
      eventType: i % 2 === 0 ? 1 : 2,
      // One millisecond apart: the cycled package and type alone repeat a stored row every six events.
      timestamp: new Date(now + i).toISOString(),
      clientEventId: newNonce(),
      timezone: 'America/New_York',
      user: 'user0',
      applicationLabel: packages[i % packages.length].split('.').pop(),
    });
  }
  return events;
}

export function generateSensorDataBatch(count) {
  const samples = [];
  const now = Date.now();
  const sensors = ['accelerometer', 'gyroscope', 'light', 'proximity'];

  for (let i = 0; i < count; i++) {
    samples.push({
      id: newNonce(),
      sensor: sensors[i % sensors.length],
      timestamp: new Date(now).toISOString(),
      timezone: 'America/New_York',
      x: Math.random() * 10 - 5,
      y: Math.random() * 10 - 5,
      z: Math.random() * 10 - 5,
      w: null,
      accuracy: 3,
    });
  }
  return samples;
}

export function generateAndroidDevice(sourceRandomDeviceId) {
  return {
    '@class': 'com.openlattice.chronicle.sources.AndroidDevice',
    randomDeviceId: sourceRandomDeviceId,
    codename: 'panther',
    model: 'Pixel 7',
    brand: 'Google',
    device: 'panther',
    product: 'panther',
    osVersion: '14',
    sdkVersion: '34',
  };
}
