import http from 'k6/http';
import { check, sleep } from 'k6';
import { thresholds } from './latency-budgets.js';

/**
 * k6 load test for Chronicle mutation endpoints (register/delete participant).
 *
 * Usage:
 *   k6 run --env JWT_TOKEN=<token> --env STUDY_ID=<uuid> tests/load/k6-mutations.js
 */

const BASE_URL = __ENV.BASE_URL || 'http://127.0.0.1:40320';
const JWT_TOKEN = __ENV.JWT_TOKEN;
const STUDY_ID = __ENV.STUDY_ID;

if (!JWT_TOKEN) {
  throw new Error('JWT_TOKEN env var is required.');
}
if (!STUDY_ID) {
  throw new Error('STUDY_ID env var is required.');
}

const headers = {
  Authorization: `Bearer ${JWT_TOKEN}`,
  'Content-Type': 'application/json',
};

export const options = {
  stages: [
    { duration: '10s', target: 5 },   // Ramp up to 5 VUs
    { duration: '1m', target: 5 },    // Hold at 5 VUs
    { duration: '10s', target: 0 },   // Ramp down
  ],
  thresholds: thresholds({
    http_req_failed: ['rate<0.01'],
  }, {
    http_req_duration: ['p(95)<500'],
  }),
};

export default function () {
  const participantId = `k6-load-test-${__VU}-${__ITER}-${Date.now()}`;
  const encodedStudyId = encodeURIComponent(STUDY_ID);

  // Register participant
  const registerBody = JSON.stringify({
    candidate: { id: '00000000-0000-0000-0000-000000000000' },
    participantId,
    participationStatus: 'ENROLLED',
  });

  const registerRes = http.post(
    `${BASE_URL}/chronicle/v3/study/${encodedStudyId}/participant`,
    registerBody,
    { headers },
  );
  check(registerRes, {
    'register participant: status 2xx': (r) => r.status >= 200 && r.status < 300,
  });

  sleep(0.5);

  // Delete participant
  const deleteBody = JSON.stringify([participantId]);
  const deleteRes = http.del(
    `${BASE_URL}/chronicle/v3/study/${encodedStudyId}/participants`,
    deleteBody,
    { headers },
  );
  check(deleteRes, {
    'delete participant: status 2xx': (r) => r.status >= 200 && r.status < 300,
  });

  sleep(1);
}
