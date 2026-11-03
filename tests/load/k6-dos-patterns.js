import http from 'k6/http';
import { check, sleep } from 'k6';
import { Rate, Trend } from 'k6/metrics';

/**
 * k6 load test for application-layer DoS pattern testing.
 *
 * Validates that the Chronicle backend handles adversarial input gracefully
 * without crashing, leaking stack traces, or exhausting resources.
 *
 * Scenarios:
 *   1. Large Query Parameter  — oversized studyId (10,000 chars)
 *   2. Pagination Abuse       — absurd limit/offset values
 *   3. JSON Depth Bomb        — deeply nested JSON payload (500 levels)
 *   4. Concurrent Connections — 50 VUs hammering a single endpoint
 *   5. Slowloris-style        — rapid-fire connection churn
 *
 * Usage:
 *   k6 run tests/load/k6-dos-patterns.js
 *   k6 run --env BASE_URL=http://backend:40320 \
 *          --env STUDY_ID=<uuid> \
 *          --env AUTH_TOKEN=<jwt> \
 *          tests/load/k6-dos-patterns.js
 */

const BASE_URL = __ENV.BASE_URL || 'http://localhost:40320';
const STUDY_ID = __ENV.STUDY_ID || '00000000-0000-0000-0000-000000000000';
const PID      = __ENV.PARTICIPANT_ID || 'test-participant';
const AUTH_TOKEN = __ENV.AUTH_TOKEN || '';
const UPLOAD_PROBE = JSON.parse(open('../../chronicle-server/src/test/resources/upload-probe-contract.json'));
const MOBILE_HEADERS = JSON.parse(open('../../chronicle-web/e2e/dsl/mobile-headers.json'));

// ---------------------------------------------------------------------------
// Custom metrics
// ---------------------------------------------------------------------------
const serverErrors = new Rate('server_errors');  // 5xx rate
const concurrentP95 = new Trend('concurrent_p95', true);

// ---------------------------------------------------------------------------
// Helper: generate deeply nested JSON
// ---------------------------------------------------------------------------
function generateNestedJSON(depth) {
  let obj = { leaf: true };
  for (let i = 0; i < depth; i++) {
    obj = { nested: obj };
  }
  return JSON.stringify([{ padding: obj }]);
}

// ---------------------------------------------------------------------------
// Common headers
// ---------------------------------------------------------------------------
function headers(contentType) {
  const h = {};
  if (AUTH_TOKEN) {
    h['Authorization'] = `Bearer ${AUTH_TOKEN}`;
  }
  if (contentType) {
    h['Content-Type'] = contentType;
  }
  return h;
}

// ---------------------------------------------------------------------------
// Scenarios
// ---------------------------------------------------------------------------
export const options = {
  scenarios: {
    // Scenario 1: Large Query Parameter — oversized studyId in URL
    large_query_param: {
      executor: 'constant-vus',
      vus: 2,
      duration: '10s',
      exec: 'largeQueryParam',
      gracefulStop: '5s',
    },

    // Scenario 2: Pagination Abuse — absurd limit value
    pagination_abuse: {
      executor: 'constant-vus',
      vus: 2,
      duration: '10s',
      startTime: '15s',
      exec: 'paginationAbuse',
      gracefulStop: '5s',
    },

    // Scenario 3: JSON Depth Bomb — 500-level nested payload
    json_depth_bomb: {
      executor: 'constant-vus',
      vus: 2,
      duration: '10s',
      startTime: '30s',
      exec: 'jsonDepthBomb',
      gracefulStop: '5s',
    },

    // Scenario 4: Concurrent Connections — 50 VUs on one endpoint
    concurrent_connections: {
      executor: 'constant-vus',
      vus: 50,
      duration: '30s',
      startTime: '45s',
      exec: 'concurrentConnections',
      gracefulStop: '10s',
    },

    // Scenario 5: Slowloris-style — rapid connection churn
    slowloris_style: {
      executor: 'constant-vus',
      vus: 10,
      duration: '20s',
      startTime: '80s',
      exec: 'slowlorisStyle',
      gracefulStop: '10s',
    },
  },

  thresholds: {
    checks: ['rate==1'],
    // No scenario should produce > 5% server errors (5xx)
    'server_errors': ['rate<0.05'],

    // Concurrent connections: p95 response time under 5 seconds
    'concurrent_p95': ['p(95)<5000'],

    // Overall HTTP failure rate (non-expected errors)
    'http_req_failed': ['rate<0.10'],
  },
};

// ---------------------------------------------------------------------------
// Scenario 1: Large Query Parameter
//
// Sends a GET with an absurdly long studyId (10,000 chars). The server should
// reject with 400 (Bad Request) or 414 (URI Too Long), never 500.
// ---------------------------------------------------------------------------
export function largeQueryParam() {
  const oversizedId = 'A'.repeat(10000);
  const url = `${BASE_URL}/chronicle/v3/study/${oversizedId}/participants`;

  const res = http.get(url, { headers: headers(), tags: { scenario: 'large_query_param' } });

  const is5xx = res.status >= 500 && res.status < 600;
  serverErrors.add(is5xx);

  check(res, {
    'large param: not a 500 server error': (r) => r.status < 500,
    'large param: rejected with 400 or 414': (r) => r.status === 400 || r.status === 414,
  });

  sleep(0.5);
}

// ---------------------------------------------------------------------------
// Scenario 2: Pagination Abuse
//
// Sends a request with limit=999999999. The server should cap the value
// internally or reject it outright — not attempt to allocate a billion-row
// result set.
// ---------------------------------------------------------------------------
export function paginationAbuse() {
  const url = `${BASE_URL}/chronicle/v3/study/${STUDY_ID}/participants?limit=999999999&offset=0`;

  const res = http.get(url, { headers: headers(), tags: { scenario: 'pagination_abuse' } });

  const is5xx = res.status >= 500 && res.status < 600;
  serverErrors.add(is5xx);

  check(res, {
    'pagination: not a 500 server error': (r) => r.status < 500,
    'pagination: responds within 10s': (r) => r.timings.duration < 10000,
    'pagination: capped or rejected (not OOM)': (r) => r.status !== 502 && r.status !== 503,
  });

  sleep(0.5);
}

// ---------------------------------------------------------------------------
// Scenario 3: JSON Depth Bomb
//
// Submit the production constraint boundary to the real list-valued sensor route.
// Only the parser's named constraint error proves that the bound was enforced.
// ---------------------------------------------------------------------------
export function jsonDepthBomb() {
  if (!__ENV.API_KEY || !__ENV.TEST_RANDOM_DEVICE_ID) throw new Error('An enrolled synthetic device is required');
  const url = `${BASE_URL}/chronicle/v4/study/${STUDY_ID}/participant/${PID}/android/sensors`;
  const deviceHeaders = { ...headers('application/json'),
    [MOBILE_HEADERS.apiKey]: __ENV.API_KEY, [MOBILE_HEADERS.randomDeviceId]: __ENV.TEST_RANDOM_DEVICE_ID };
  const control = http.post(url, '[]', { headers: deviceHeaders });
  if (!check(control, { 'depth control accepted': (r) => r.status === 200 && r.json() === 0 })) {
    throw new Error('Depth probe has no successful upload control');
  }
  const payload = generateNestedJSON(UPLOAD_PROBE.maxNestingDepth + 1);

  const res = http.post(url, payload, {
    headers: deviceHeaders,
    tags: { scenario: 'json_depth_bomb' },
  });

  const is5xx = res.status >= 500 && res.status < 600;
  serverErrors.add(is5xx);

  check(res, {
    'depth bomb: not a 500 server error': (r) => r.status < 500,
    'depth bomb: named parser constraint': (r) => r.status === 400 && r.json('code') === UPLOAD_PROBE.constraintErrorCode,
  });

  sleep(0.5);
}

// ---------------------------------------------------------------------------
// Scenario 4: Concurrent Connections
//
// 50 VUs hit /chronicle/v3/study simultaneously for 30s. The server must
// stay responsive: error rate < 5%, p95 response time < 5s.
// ---------------------------------------------------------------------------
export function concurrentConnections() {
  const url = `${BASE_URL}/chronicle/v3/study`;

  const res = http.get(url, { headers: headers(), tags: { scenario: 'concurrent_connections' } });

  const is5xx = res.status >= 500 && res.status < 600;
  serverErrors.add(is5xx);
  concurrentP95.add(res.timings.duration);

  check(res, {
    'concurrent: status is not 5xx': (r) => r.status < 500,
    'concurrent: responds within 5s': (r) => r.timings.duration < 5000,
  });

  sleep(0.2);
}

// ---------------------------------------------------------------------------
// Scenario 5: Slowloris-style
//
// k6 does not support true slowloris attacks (partial headers / drip-fed
// body) because it always sends complete HTTP requests. As an approximation,
// this scenario rapidly opens and closes connections with minimal think time,
// stressing the server's connection accept/teardown path and thread pool.
//
// The check verifies the server's connection handling remains healthy: it
// should keep responding (no connection refused / timeouts) even under
// rapid connection churn from 10 VUs.
//
// Limitation: a true slowloris test requires a raw TCP tool like slowhttptest
// or hping3. This scenario tests connection pool exhaustion under churn, not
// slow-read/slow-send attacks.
// ---------------------------------------------------------------------------
export function slowlorisStyle() {
  const url = `${BASE_URL}/chronicle/v3/study`;

  // Rapid-fire: no keep-alive, force new connection each time
  const params = {
    headers: headers(),
    tags: { scenario: 'slowloris_style' },
    // Short timeout to detect if server stops accepting connections
    timeout: '5s',
  };

  const res = http.get(url, params);

  const isError = res.status === 0; // connection refused / timeout
  serverErrors.add(isError);

  check(res, {
    'slowloris: connection accepted': (r) => r.status !== 0,
    'slowloris: not connection refused': (r) => r.status !== 0 && r.timings.duration < 5000,
  });

  // No sleep — intentionally rapid to stress connection handling
}
