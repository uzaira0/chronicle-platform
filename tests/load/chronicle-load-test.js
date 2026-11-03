import http from 'k6/http';
import { check, group, sleep } from 'k6';
import { Counter, Rate, Trend } from 'k6/metrics';
import { SharedArray } from 'k6/data';
import { generateUsageEventBatch, generateSensorDataBatch, signedMobileHeaders, uploadAcknowledged, MOBILE_HEADERS } from './mobile-client.js';

/**
 * Chronicle Load Test
 *
 * Validates the expected peak of 25 concurrent devices at 2–5x load
 * uploading usage events every minute with optional sensor batches.
 *
 * Usage:
 *   DEVICE_FIXTURES_FILE=/private/synthetic-devices.json STUDY_ID=<uuid> k6 run tests/load/chronicle-load-test.js
 *
 * Optional env vars:
 *   BASE_URL  - Chronicle server URL (default: http://127.0.0.1:40320)
 *   MAX_VUS   - Stress peak virtual users (default: 5x the owner's 25-device peak)
 *   STUDY_ID  - UUID of the study to test against (required)
 */

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

const BASE_URL = __ENV.BASE_URL || 'http://127.0.0.1:40320';
const STUDY_ID = __ENV.STUDY_ID;
// 25 simultaneous participants; exercise 2–5x that peak.
const PILOT_PEAK_VUS = 25;
const MAX_VUS = Number(__ENV.MAX_VUS || String(5 * PILOT_PEAK_VUS));
if (!Number.isInteger(MAX_VUS) || MAX_VUS <= 0) throw new Error('MAX_VUS must be a positive integer');
const UPLOAD_INTERVAL_SECONDS = Number(__ENV.UPLOAD_INTERVAL_SECONDS || '60');
if (!Number.isFinite(UPLOAD_INTERVAL_SECONDS) || UPLOAD_INTERVAL_SECONDS <= 0) {
  throw new Error('UPLOAD_INTERVAL_SECONDS must be positive');
}

if (!STUDY_ID) {
  throw new Error('STUDY_ID env var is required. Pass the UUID of an existing study.');
}
if (!__ENV.DEVICE_FIXTURES_FILE) throw new Error('DEVICE_FIXTURES_FILE must contain enrolled synthetic devices');
const devices = new SharedArray('synthetic devices', () => JSON.parse(open(__ENV.DEVICE_FIXTURES_FILE)));

const CHRONICLE_BASE = `${BASE_URL}/chronicle/v4/study/${encodeURIComponent(STUDY_ID)}`;

// ---------------------------------------------------------------------------
// Custom metrics
// ---------------------------------------------------------------------------

const uploadDuration = new Trend('upload_duration', true);
const sensorUploadDuration = new Trend('sensor_upload_duration', true);
const uploadErrors = new Rate('upload_errors');
const sensorUploadErrors = new Rate('sensor_upload_errors');
const eventsUploaded = new Counter('events_uploaded');
const samplesUploaded = new Counter('samples_uploaded');

const responseClasses = new Counter('response_classes');

function recordResponse(response, surface, rows) {
  const status = response.status;
  let acknowledged = false;
  if (status >= 200 && status < 300) {
    acknowledged = uploadAcknowledged(response, rows, surface === 'usage');
  }
  const outcome = status >= 200 && status < 300 ? (acknowledged ? 'accepted' : 'acknowledgement_failed')
    : status === 429 ? 'throttled'
    : status === 401 || status === 403 ? 'authentication_failed'
    : status >= 500 ? 'server_failed'
    : status === 0 ? 'transport_failed' : 'request_rejected';
  const tags = { surface, outcome };
  responseClasses.add(1, tags);
  return check(response, { 'request accepted': () => outcome === 'accepted' }, tags);
}

// ---------------------------------------------------------------------------
// Ramp-up stages
// ---------------------------------------------------------------------------

export const options = {
  stages: [
    // Phase 1: Initial device cohort
    { duration: '30s', target: Math.min(PILOT_PEAK_VUS, MAX_VUS) },
    { duration: '30s', target: Math.min(PILOT_PEAK_VUS, MAX_VUS) },

    // Phase 2: Steady usage event uploads
    { duration: '1m', target: Math.min(2 * PILOT_PEAK_VUS, MAX_VUS) },
    { duration: '1m', target: Math.min(2 * PILOT_PEAK_VUS, MAX_VUS) },

    // Phase 3: Peak load — mixed uploads
    { duration: '1m', target: MAX_VUS },
    { duration: '1m', target: MAX_VUS },

    // Phase 4: Cooldown
    { duration: '30s', target: 0 },
  ],

  // handleSummary's compact summary reads these values; k6 reports only up to p(95) by default.
  summaryTrendStats: ['avg', 'min', 'med', 'max', 'p(90)', 'p(95)', 'p(99)'],

  thresholds: {
    // Upload latency thresholds
    upload_duration: ['p(95)<500', 'p(99)<2000'],
    sensor_upload_duration: ['p(95)<500', 'p(99)<2000'],

    // Error rate thresholds
    upload_errors: ['rate<0.01'],
    sensor_upload_errors: ['rate<0.01'],

    // Global
    http_req_failed: ['rate<0.01'],
    http_req_duration: ['p(95)<1000'],
  },
};

// ---------------------------------------------------------------------------
// Data generators
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Test scenarios
// ---------------------------------------------------------------------------

function uploadUsageEvents(device, batchSize, headers) {
  const url = `${CHRONICLE_BASE}/participant/${encodeURIComponent(device.participant_id)}/android`;
  const events = generateUsageEventBatch(batchSize, STUDY_ID, device.participant_id);
  const payload = JSON.stringify(events);

  const res = http.post(url, payload, {
    headers: signedMobileHeaders(url, payload, headers, __ENV.MOBILE_SIGNING_SECRET),
    tags: { name: 'upload_usage' },
  });

  uploadDuration.add(res.timings.duration);

  const ok = recordResponse(res, 'usage', events);

  uploadErrors.add(!ok);
  if (ok) eventsUploaded.add(batchSize);
  return ok;
}

function uploadSensorData(device, batchSize, headers) {
  const url = `${CHRONICLE_BASE}/participant/${encodeURIComponent(device.participant_id)}/android/sensors`;
  const samples = generateSensorDataBatch(batchSize);
  const payload = JSON.stringify(samples);

  const res = http.post(url, payload, {
    headers: signedMobileHeaders(url, payload, headers, __ENV.MOBILE_SIGNING_SECRET),
    tags: { name: 'upload_sensors' },
  });

  sensorUploadDuration.add(res.timings.duration);

  const ok = recordResponse(res, 'sensors', samples);

  sensorUploadErrors.add(!ok);
  if (ok) samplesUploaded.add(batchSize);
  return ok;
}

// ---------------------------------------------------------------------------
// Main VU function
// ---------------------------------------------------------------------------

export function setup() {
  if (devices.length < MAX_VUS || devices.some(device =>
    ['participant_id', 'random_device_id', 'api_key'].some(key =>
      typeof device[key] !== 'string' || !device[key].trim() || /[\r\n]/.test(device[key])))) {
    throw new Error('one enrolled synthetic device with participant_id, random_device_id and api_key is required per VU');
  }
  if (new Set(devices.map(device => device.api_key)).size !== devices.length) {
    throw new Error('synthetic device credentials must be distinct');
  }
}

export default function () {
  const started = Date.now();
  const device = devices[__VU - 1];
  const headers = { 'Content-Type': 'application/json', [MOBILE_HEADERS.apiKey]: device.api_key,
    [MOBILE_HEADERS.randomDeviceId]: device.random_device_id };

  // All iterations: upload data
  group('usage_event_upload', () => {
    uploadUsageEvents(device, 10, headers);
  });

  // 30% of iterations also upload sensor data
  if (Math.random() < 0.3) {
    group('sensor_data_upload', () => {
    uploadSensorData(device, 500, headers);
    });
  }

  sleep(Math.max(0, UPLOAD_INTERVAL_SECONDS - (Date.now() - started) / 1000));
}

export function handleSummary(data) {
  // k6 v0.50 (the gate's pinned runner) cannot parse optional chaining.
  const stat = (name, key) => ((data.metrics || {})[name] || { values: {} }).values[key];
  const summary = {
    timestamp: new Date().toISOString(),
    thresholds_passed: Object.values(data.metrics || {}).every(metric =>
      Object.values(metric.thresholds || {}).every(threshold => threshold.ok)),
    metrics: {
      upload_p50: stat('upload_duration', 'med'),
      upload_p95: stat('upload_duration', 'p(95)'),
      upload_p99: stat('upload_duration', 'p(99)'),
      sensor_p95: stat('sensor_upload_duration', 'p(95)'),
      sensor_p99: stat('sensor_upload_duration', 'p(99)'),
      error_rate: stat('http_req_failed', 'rate'),
      total_requests: stat('http_reqs', 'count'),
      throughput_rps: stat('http_reqs', 'rate'),
      events_uploaded: stat('events_uploaded', 'count'),
      samples_uploaded: stat('samples_uploaded', 'count'),
    },
  };

  return {
    stdout: JSON.stringify(summary, null, 2) + '\n',
    'load-test-results.json': JSON.stringify(summary, null, 2),
  };
}
