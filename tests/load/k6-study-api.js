import http from 'k6/http';
import { check, sleep } from 'k6';

/**
 * k6 load test for Chronicle study read endpoints.
 *
 * Usage:
 *   k6 run --env JWT_TOKEN=<token> tests/load/k6-study-api.js
 *   k6 run --env JWT_TOKEN=<token> --env BASE_URL=http://localhost:40320 tests/load/k6-study-api.js
 */

const BASE_URL = __ENV.BASE_URL || 'http://127.0.0.1:40320';
const JWT_TOKEN = __ENV.JWT_TOKEN;

if (!JWT_TOKEN) {
  throw new Error('JWT_TOKEN env var is required. Generate with: docker/generate-jwt.sh');
}

const headers = {
  Authorization: `Bearer ${JWT_TOKEN}`,
  'Content-Type': 'application/json',
};

export const options = {
  stages: [
    { duration: '10s', target: 10 },  // Ramp up to 10 VUs
    { duration: '1m', target: 10 },   // Hold at 10 VUs
    { duration: '10s', target: 0 },   // Ramp down
  ],
  thresholds: {
    http_req_duration: ['p(95)<500'],  // 95% of requests under 500ms
    http_req_failed: ['rate<0.01'],    // Less than 1% error rate
  },
};

export default function () {
  // GET /chronicle/v3/study — list all studies
  const studiesRes = http.get(`${BASE_URL}/chronicle/v3/study`, { headers });
  check(studiesRes, {
    'list studies: status 200': (r) => r.status === 200,
    'list studies: is array': (r) => {
      // k6 v0.50 (the gate's pinned runner) cannot parse an optional catch binding.
      try { return Array.isArray(JSON.parse(r.body)); } catch (_) { return false; }
    },
  });

  // If studies exist, test detail endpoints
  const studies = studiesRes.json();
  if (Array.isArray(studies) && studies.length > 0) {
    const studyId = studies[0].id;

    // GET /chronicle/v3/study/{studyId}
    const detailRes = http.get(`${BASE_URL}/chronicle/v3/study/${encodeURIComponent(studyId)}`, { headers });
    check(detailRes, {
      'study detail: status 200': (r) => r.status === 200,
    });

    // GET /chronicle/v3/study/{studyId}/participants
    const participantsRes = http.get(`${BASE_URL}/chronicle/v3/study/${encodeURIComponent(studyId)}/participants`, { headers });
    check(participantsRes, {
      'participants: status 200': (r) => r.status === 200,
    });

    // GET /chronicle/v3/study/{studyId}/participants/stats
    const statsRes = http.get(`${BASE_URL}/chronicle/v3/study/${encodeURIComponent(studyId)}/participants/stats`, { headers });
    check(statsRes, {
      'participant stats: status 200': (r) => r.status === 200,
    });
  }

  sleep(1);
}
