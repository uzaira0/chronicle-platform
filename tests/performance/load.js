import { group, sleep } from 'k6';
import { Counter, Rate, Trend } from 'k6/metrics';
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
import http from 'k6/http';
import { check } from 'k6';

/**
 * Load test — moderate sustained load for staging validation.
 *
 * 50 VUs, ~30s total. Exercises both read and write endpoints with
 * realistic traffic patterns.
 *
 * Usage:
 *   k6 run --env JWT_TOKEN=<token> tests/performance/load.js
 *   k6 run --env JWT_TOKEN=<token> --env STUDY_ID=<uuid> tests/performance/load.js
 *   k6 run --env JWT_TOKEN=<token> --env BASE_URL=http://staging:40320 tests/performance/load.js
 *
 * Environment variables:
 *   BASE_URL   - Chronicle server URL (default: http://127.0.0.1:40320)
 *   JWT_TOKEN  - Bearer token for authenticated endpoints (required)
 *   STUDY_ID   - UUID of study for write tests (optional; skips writes if absent)
 */

const STUDY_ID = __ENV.STUDY_ID || '';

// ---------------------------------------------------------------------------
// Custom metrics
// ---------------------------------------------------------------------------

const healthDuration = new Trend('health_duration', true);
const readDuration = new Trend('read_api_duration', true);
const writeDuration = new Trend('write_api_duration', true);
const readErrors = new Rate('read_errors');
const writeErrors = new Rate('write_errors');
const eventsUploaded = new Counter('events_uploaded');

// ---------------------------------------------------------------------------
// Options
// ---------------------------------------------------------------------------

export const options = {
  stages: [
    { duration: '5s', target: 25 },   // Ramp up
    { duration: '20s', target: 50 },   // Sustained load
    { duration: '5s', target: 0 },     // Ramp down
  ],
  thresholds: {
    checks: ['rate==1'],
    // Health endpoint
    'http_req_duration{name:health}': ['p(95)<500'],

    // Read API endpoints
    read_api_duration: ['p(95)<2000', 'p(99)<5000'],

    // Write API endpoints
    write_api_duration: ['p(95)<2000', 'p(99)<5000'],

    // Error budgets
    read_errors: ['rate<0.05'],
    write_errors: ['rate<0.05'],
    http_req_failed: ['rate<0.05'],
  },
};

// ---------------------------------------------------------------------------
// Setup — discover a study ID if not provided
// ---------------------------------------------------------------------------

export function setup() {
  if (!JWT_TOKEN) {
    throw new Error('JWT_TOKEN env var is required. Generate with: docker/generate-jwt.sh');
  }

  let studyId = STUDY_ID;

  // If no STUDY_ID provided, try to discover one
  if (!studyId) {
    const res = http.get(STUDY_LIST_URL, { headers: authHeaders() });
    if (res.status === 200) {
      try {
        const studies = JSON.parse(res.body);
        if (Array.isArray(studies) && studies.length > 0) {
          studyId = studies[0].id;
          console.log(`Auto-discovered study: ${studyId}`);
        }
      } catch {
        // ignore
      }
    }
  }

  return { studyId, runId: Date.now() };
}

// ---------------------------------------------------------------------------
// Main VU function
// ---------------------------------------------------------------------------

export default function (data) {
  const vuId = __VU;
  const studyId = data.studyId;

  // 1. Health check (every iteration)
  group('health_check', () => {
    const res = checkHealth();
    healthDuration.add(res.timings.duration);
  });

  // 2. Read endpoints (every iteration, if study exists)
  if (studyId) {
    group('read_api', () => {
      let res = listStudies();
      readDuration.add(res.timings.duration);
      readErrors.add(res.status !== 200);

      res = getStudy(studyId);
      readDuration.add(res.timings.duration);
      readErrors.add(res.status !== 200);

      res = getParticipants(studyId);
      readDuration.add(res.timings.duration);
      readErrors.add(!(res.status === 200 || res.status === 403));

      res = getParticipantStats(studyId);
      readDuration.add(res.timings.duration);
      readErrors.add(!(res.status === 200 || res.status === 403));
    });
  }

  // 3. Write endpoints (only if STUDY_ID was explicitly provided)
  if (STUDY_ID) {
    group('write_api', () => {
      const participantId = `perf-${data.runId}-vu${vuId}`;
      const randomDeviceId = `device-perf-${data.runId}-vu${vuId}`;

      // Enroll on first iteration
      if (__ITER === 0) {
        const res = enrollDevice(
          STUDY_ID,
          participantId,
          randomDeviceId,
          generateAndroidDevice(randomDeviceId),
        );
        writeDuration.add(res.timings.duration);
        writeErrors.add(!(res.status >= 200 && res.status < 300));
      }

      // Upload usage events
      const events = generateUsageEventBatch(10, data.studyId, participantId);
      let res = uploadAndroidUsageEvents(STUDY_ID, participantId, randomDeviceId, events);
      writeDuration.add(res.timings.duration);
      const ok = res.status >= 200 && res.status < 300;
      writeErrors.add(!ok);
      if (ok) eventsUploaded.add(10);

      // 30% chance: also upload sensor data
      if (Math.random() < 0.3) {
        const samples = generateSensorDataBatch(50);
        res = uploadAndroidSensorData(STUDY_ID, participantId, randomDeviceId, samples);
        writeDuration.add(res.timings.duration);
        writeErrors.add(!(res.status >= 200 && res.status < 300));
      }
    });
  }

  sleep(0.5 + Math.random());
}

// ---------------------------------------------------------------------------
// Summary
// ---------------------------------------------------------------------------

export function handleSummary(data) {
  const summary = {
    timestamp: new Date().toISOString(),
    test: 'load',
    metrics: {
      health_p95: data.metrics?.health_duration?.values?.['p(95)'],
      read_p95: data.metrics?.read_api_duration?.values?.['p(95)'],
      write_p95: data.metrics?.write_api_duration?.values?.['p(95)'],
      error_rate: data.metrics?.http_req_failed?.values?.rate,
      total_requests: data.metrics?.http_reqs?.values?.count,
      throughput_rps: data.metrics?.http_reqs?.values?.rate,
    },
  };

  return {
    stdout: JSON.stringify(summary, null, 2) + '\n',
    'tests/performance/load-results.json': JSON.stringify(summary, null, 2),
  };
}
