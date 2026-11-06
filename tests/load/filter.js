import http from 'k6/http';
import { check } from 'k6';
import exec from 'k6/execution';
import { SharedArray } from 'k6/data';
import { Counter, Rate, Trend } from 'k6/metrics';

const cases = new SharedArray('domain policies', () => JSON.parse(open(__ENV.CASES || './cases.json')));
const lookup = new Trend('matcher_duration_ms', true);
const handled = new Counter('successful_requests');
const policyErrors = new Rate('policy_error_rate');
const base = __ENV.BASE_URL || 'http://127.0.0.1:8787';
const devices = Number(__ENV.DEVICES || 2000);
const vus = Number(__ENV.VUS || 200);
const duration = __ENV.DURATION || '15m';
const scenario = __ENV.MODE === 'concurrency'
  ? { executor: 'constant-vus', vus, duration }
  : { executor: 'constant-arrival-rate', rate: Number(__ENV.RATE || 2500), timeUnit: '1s', duration, preAllocatedVUs: vus, maxVUs: vus };

export const options = {
  scenarios: { filtering: scenario },
  systemTags: ['status', 'method', 'name', 'scenario', 'expected_response'],
  summaryTrendStats: ['avg', 'med', 'p(95)', 'p(99)', 'max'],
  thresholds: {
    checks: ['rate==1'],
    http_req_failed: ['rate==0'],
    'http_req_duration{scenario:filtering}': [`p(99)<${__ENV.HTTP_P99_MS || 20}`],
    matcher_duration_ms: [`p(99)<${__ENV.MATCHER_P99_MS || 0.05}`],
    successful_requests: ['count>0'],
    policy_error_rate: ['rate==0'],
    'http_reqs{scenario:filtering}': ['count>0'],
    ...(__ENV.MODE === 'concurrency' ? {} : { dropped_iterations: ['count==0'] }),
  },
};

export function setup() {
  if (!cases.length || !Number.isInteger(devices) || devices < 1) throw new Error('invalid cases/devices');
  const health = http.get(`${base}/health`);
  if (health.status !== 200) throw new Error('load harness unavailable');
  // Exercise every expected policy once, before any load measurement.
  for (const item of cases) {
    const response = http.get(`${base}/check/${item.categories}/${item.domain}`, { tags: { name: 'policy-preflight' } });
    if (response.status !== 200 || response.json('blocked') !== item.blocked) {
      throw new Error(`incorrect fixture decision for ${item.domain}`);
    }
  }
}

export default function () {
  const n = exec.scenario.iterationInTest;
  const item = cases[n % cases.length];
  const response = http.get(`${base}/check/${item.categories}/${item.domain}`, {
    headers: { 'X-Test-Device': String(n % devices) },
    tags: { name: 'policy-check' },
    timeout: '2s',
  });
  const elapsed = Number(response.headers['X-Lookup-Ns']);
  let correct = false;
  try {
    correct = response.status === 200 && response.json('blocked') === item.blocked;
  } catch (_) {
    // A malformed 200 response must count as an error, not escape the metrics.
  }
  policyErrors.add(!correct);
  if (correct) handled.add(1);
  check(response, {
    'HTTP 200': r => r.status === 200,
    'correct policy': () => correct,
    'matcher timing present': () => Number.isFinite(elapsed) && elapsed >= 0,
  });
  if (Number.isFinite(elapsed) && elapsed >= 0) lookup.add(elapsed / 1e6);
}

export function handleSummary(data) {
  const metric = name => data.metrics[name] ? data.metrics[name].values : null;
  const summary = {
    kind: 'k6-http-harness',
    configured_duration: duration,
    configured_mode: __ENV.MODE === 'concurrency' ? 'concurrency' : 'arrival',
    configured_rate: __ENV.MODE === 'concurrency' ? null : Number(__ENV.RATE || 2500),
    configured_devices: devices,
    configured_vus: vus,
    http_duration_ms: metric('http_req_duration{scenario:filtering}'),
    matcher_duration_ms: metric('matcher_duration_ms'),
    issued_requests: metric('http_reqs{scenario:filtering}'),
    successful_requests: metric('successful_requests'),
    http_error_rate: metric('http_req_failed'),
    policy_error_rate: metric('policy_error_rate'),
    dropped_iterations: metric('dropped_iterations'),
    raw: data,
  };
  return {
    [__ENV.REPORT || 'k6-summary.json']: JSON.stringify(summary, null, 2),
    stdout: JSON.stringify({ ...summary, raw: undefined }, null, 2) + '\n',
  };
}
