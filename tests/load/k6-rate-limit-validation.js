import http from 'k6/http';
import { check } from 'k6';
import { Counter } from 'k6/metrics';

// Run against a quiet disposable backend with empty buckets and no proxy throttling.
const BASE = __ENV.BASE_URL || 'http://localhost:40320';
const AUTH_LIMIT = Number(__ENV.AUTH_LIMIT || 10);
const BURST_MULTIPLIER = Number(__ENV.BURST_MULTIPLIER || 1.5);
const WINDOW_SECONDS = 60;
const throttled = new Counter('throttled');
if (AUTH_LIMIT <= 0 || BURST_MULTIPLIER < 1) {
  throw new Error('Provide the configured auth limit and burst multiplier');
}
export const options = {
  scenarios: {
    auth_burst: { executor: 'shared-iterations', vus: 1, iterations: 1, exec: 'authBurst', maxDuration: '30s' },
  },
  thresholds: {
    checks: ['rate==1'],
    'throttled{tier:auth}': ['count==1'],
  },
};
function burst(tier, limit, send) {
  const started = Date.now();
  const capacity = Math.floor(limit * BURST_MULTIPLIER);
  // The bounded request budget includes at most one window of greedy refill.
  for (let index = 1; index <= capacity + limit + 1; index++) {
    const response = send();
    if (response.status === 429) {
      throttled.add(1, { tier });
      const refill = Math.ceil((Date.now() - started) / 1000 * limit / WINDOW_SECONDS);
      check(response, {
        'first rejection occurs at configured burst capacity': () => index >= capacity + 1 && index <= capacity + refill + 1,
        'Retry-After is a positive number': r => Number(r.headers['Retry-After']) > 0,
      });
      return;
    }
    check(response, { 'positive control reaches the production handler': r => r.status === 200 });
  }
  check(false, { 'burst must observe throttling': value => value });
}
export function authBurst() {
  burst('auth', AUTH_LIMIT, () => http.get(`${BASE}/chronicle/v3/auth/session`));
}
