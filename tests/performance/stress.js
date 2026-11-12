import { group, sleep } from 'k6';
import { Counter, Rate, Trend } from 'k6/metrics';
import { thresholds } from '../load/latency-budgets.js';
import http from 'k6/http';
import { check } from 'k6';
import {
  checkHealth,
  listStudies,
  getStudy,
  getParticipants,
  getParticipantStats,
  uploadAndroidUsageEvents,
  uploadAndroidSensorData,
  enrollDevice,
  generateUsageEventBatch,
  generateSensorDataBatch,
  generateAndroidDevice,
  JWT_TOKEN,
  STUDY_LIST_URL,
  authHeaders,
} from './helpers.js';

/**
 * Stress test — ramp to 125 VUs to find breaking points.
 *
 * Intended for manual runs against a staging or pre-production environment.
 * NOT for CI — this test runs ~4 minutes and generates significant load.
 *
 * Usage:
 *   k6 run --env JWT_TOKEN=<token> --env STUDY_ID=<uuid> tests/performance/stress.js
 *   k6 run --env JWT_TOKEN=<token> --env STUDY_ID=<uuid> --env MAX_VUS=125 tests/performance/stress.js
 *
 * Environment variables:
 *   BASE_URL   - Chronicle server URL (default: http://127.0.0.1:40320)
 *   JWT_TOKEN  - Bearer token (required)
 *   STUDY_ID   - UUID of study for write tests (required)
 *   MAX_VUS    - Peak virtual users (default: 125, five times the owner's 25-device pilot peak)
 */

const STUDY_ID = __ENV.STUDY_ID;
const MAX_VUS = parseInt(__ENV.MAX_VUS || '125', 10);

if (!JWT_TOKEN) {
  throw new Error('JWT_TOKEN env var is required. Generate with: docker/generate-jwt.sh');
}
if (!STUDY_ID) {
  throw new Error('STUDY_ID env var is required. Pass the UUID of an existing study.');
}

// ---------------------------------------------------------------------------
// Custom metrics
// ---------------------------------------------------------------------------

const healthDuration = new Trend('health_duration', true);
const readDuration = new Trend('read_api_duration', true);
const writeDuration = new Trend('write_api_duration', true);
const enrollDuration = new Trend('enroll_duration', true);
const readErrors = new Rate('read_errors');
const writeErrors = new Rate('write_errors');
const enrollErrors = new Rate('enroll_errors');
const eventsUploaded = new Counter('events_uploaded');
const samplesUploaded = new Counter('samples_uploaded');

// ---------------------------------------------------------------------------
// Ramp-up stages — staircase pattern to find breaking point
// ---------------------------------------------------------------------------

export const options = {
  stages: [
    // Step 1: Warm up
    { duration: '15s', target: 10 },
    { duration: '15s', target: 10 },

    // Step 2: Moderate
    { duration: '15s', target: 50 },
    { duration: '30s', target: 50 },

    // Step 3: Heavy
    { duration: '15s', target: 100 },
    { duration: '30s', target: 100 },

    // Step 4: Stress
    { duration: '15s', target: MAX_VUS },
    { duration: '1m', target: MAX_VUS },

    // Recovery
    { duration: '15s', target: 50 },
    { duration: '15s', target: 50 },

    // Cooldown
    { duration: '15s', target: 0 },
  ],
  thresholds: thresholds({
    checks: ['rate==1'],
    // Error budgets — more lenient for stress test
    read_errors: ['rate<0.10'],
    write_errors: ['rate<0.10'],
    enroll_errors: ['rate<0.15'],

    // Global
    http_req_failed: ['rate<0.10'],
  }, {
    // Health must stay responsive even under stress
    'http_req_duration{name:health}': ['p(95)<1000'],

    // Read APIs — relaxed thresholds for stress
    read_api_duration: ['p(95)<5000'],

    // Write APIs — relaxed thresholds for stress
    write_api_duration: ['p(95)<5000'],

    // Enrollment
    enroll_duration: ['p(95)<3000'],
  }),
};

// ---------------------------------------------------------------------------
// Setup — verify study exists
// ---------------------------------------------------------------------------

export function setup() {
  const res = http.get(`${STUDY_LIST_URL}/${STUDY_ID}`, {
    headers: authHeaders(),
  });
  check(res, {
    'setup: study exists': (r) => r.status === 200,
  });
  if (res.status !== 200) {
    throw new Error(`Study ${STUDY_ID} not found (status ${res.status}).`);
  }
  return { studyId: STUDY_ID, runId: Date.now() };
}

// ---------------------------------------------------------------------------
// Main VU function
// ---------------------------------------------------------------------------

export default function (data) {
  const vuId = __VU;
  const participantId = `stress-${data.runId}-vu${vuId}`;
  const randomDeviceId = `device-stress-${data.runId}-vu${vuId}`;

  // Health check (lightweight, every iteration)
  group('health_check', () => {
    const res = checkHealth();
    healthDuration.add(res.timings.duration);
  });

  // Read endpoints (50% of iterations to reduce noise)
  if (__ITER % 2 === 0) {
    group('read_api', () => {
      let res = listStudies();
      readDuration.add(res.timings.duration);
      readErrors.add(res.status !== 200);

      res = getStudy(data.studyId);
      readDuration.add(res.timings.duration);
      readErrors.add(res.status !== 200);

      res = getParticipants(data.studyId);
      readDuration.add(res.timings.duration);
      readErrors.add(!(res.status === 200 || res.status === 403));
    });
  }

  // Write endpoints
  group('write_api', () => {
    // Enroll on first iteration
    if (__ITER === 0) {
      const res = enrollDevice(
        data.studyId,
        participantId,
        randomDeviceId,
        generateAndroidDevice(randomDeviceId),
      );
      enrollDuration.add(res.timings.duration);
      enrollErrors.add(!(res.status >= 200 && res.status < 300));
    }

    // Upload usage events (batch of 10 — realistic per-device upload)
    const events = generateUsageEventBatch(10, data.studyId, participantId);
    let res = uploadAndroidUsageEvents(data.studyId, participantId, randomDeviceId, events);
    writeDuration.add(res.timings.duration);
    const usageOk = res.status >= 200 && res.status < 300;
    writeErrors.add(!usageOk);
    if (usageOk) eventsUploaded.add(10);

    // Upload sensor data (batch of 100 — moderate size)
    if (Math.random() < 0.4) {
      const samples = generateSensorDataBatch(100);
      res = uploadAndroidSensorData(data.studyId, participantId, randomDeviceId, samples);
      writeDuration.add(res.timings.duration);
      const sensorOk = res.status >= 200 && res.status < 300;
      writeErrors.add(!sensorOk);
      if (sensorOk) samplesUploaded.add(100);
    }
  });

  // Simulate inter-upload interval (compressed)
  sleep(0.5 + Math.random() * 1.5);
}

// ---------------------------------------------------------------------------
// Summary
// ---------------------------------------------------------------------------

export function handleSummary(data) {
  const summary = {
    timestamp: new Date().toISOString(),
    test: 'stress',
    max_vus: MAX_VUS,
    metrics: {
      health_p95: data.metrics?.health_duration?.values?.['p(95)'],
      read_p95: data.metrics?.read_api_duration?.values?.['p(95)'],
      read_p99: data.metrics?.read_api_duration?.values?.['p(99)'],
      write_p95: data.metrics?.write_api_duration?.values?.['p(95)'],
      write_p99: data.metrics?.write_api_duration?.values?.['p(99)'],
      enroll_p95: data.metrics?.enroll_duration?.values?.['p(95)'],
      read_error_rate: data.metrics?.read_errors?.values?.rate,
      write_error_rate: data.metrics?.write_errors?.values?.rate,
      total_requests: data.metrics?.http_reqs?.values?.count,
      throughput_rps: data.metrics?.http_reqs?.values?.rate,
      events_uploaded: data.metrics?.events_uploaded?.values?.count,
      samples_uploaded: data.metrics?.samples_uploaded?.values?.count,
    },
  };

  return {
    stdout: JSON.stringify(summary, null, 2) + '\n',
    'tests/performance/stress-results.json': JSON.stringify(summary, null, 2),
  };
}
