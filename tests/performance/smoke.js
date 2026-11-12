import { group, sleep } from 'k6';
import { thresholds } from '../load/latency-budgets.js';
import {
  checkHealth,
  listStudies,
  getStudy,
  getParticipants,
  JWT_TOKEN,
} from './helpers.js';

/**
 * Smoke test — lightweight sanity check for CI.
 *
 * 1 VU, 10 seconds. Verifies the server is reachable, the health endpoint
 * responds, and (if a JWT is provided) basic authenticated endpoints work.
 *
 * Usage:
 *   k6 run tests/performance/smoke.js
 *   k6 run --env JWT_TOKEN=<token> tests/performance/smoke.js
 *   k6 run --env BASE_URL=http://staging:40320 --env JWT_TOKEN=<token> tests/performance/smoke.js
 */

export const options = {
  vus: 1,
  duration: '10s',
  thresholds: thresholds({
    // No failures allowed in smoke
    http_req_failed: ['rate==0'],
    // All checks must pass
    checks: ['rate==1'],
  }, {
    // Health endpoint must be fast
    'http_req_duration{name:health}': ['p(95)<500'],
    // Authenticated endpoints get more headroom
    'http_req_duration{name:list_studies}': ['p(95)<2000'],
  }),
};

export default function () {
  group('health', () => {
    checkHealth();
  });

  if (JWT_TOKEN) {
    group('authenticated_endpoints', () => {
      const res = listStudies();

      // If studies exist, probe one
      try {
        const studies = JSON.parse(res.body);
        if (Array.isArray(studies) && studies.length > 0) {
          const studyId = studies[0].id;
          getStudy(studyId);
          getParticipants(studyId);
        }
      } catch {
        // Non-fatal: list may be empty or auth may differ
      }
    });
  }

  sleep(1);
}
