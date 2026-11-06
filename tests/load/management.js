// Real management API, not the development matcher adapter. Keep the offered
// rate below its documented 64-connection/second admission ceiling.
import http from 'k6/http';
import { check } from 'k6';
import { Rate } from 'k6/metrics';
const errors = new Rate('status_error_rate');
const base = __ENV.BASE_URL || 'http://127.0.0.1:8788';
const token = __ENV.MANAGEMENT_TOKEN;
const rate = Number(__ENV.RATE || 20);
export const options = {
  scenarios: { management: { executor:'constant-arrival-rate', rate, timeUnit:'1s', duration:__ENV.DURATION || '60s', preAllocatedVUs:4, maxVUs:4 } },
  summaryTrendStats: ['avg','med','p(95)','p(99)','max'],
  systemTags: ['status','method','name','scenario','expected_response'],
  thresholds: { checks:['rate==1'], status_error_rate:['rate==0'], http_req_failed:['rate==0'], dropped_iterations:['count==0'], http_req_duration:['p(99)<20'] },
};
export function setup() {
  if (!token || !/^[0-9a-f]{64}$/.test(token)) throw new Error('explicit management token required');
  if (!(rate >= 1 && rate <= 48)) throw new Error('management test rate must be 1..48');
}
export default function () {
  const response = http.get(`${base}/api/v1/status`, { headers:{Authorization:`Bearer ${token}`}, timeout:'2s', tags:{name:'management-status'} });
  let valid = false;
  try { valid = response.status === 200 && response.json('schema_version') === 1 && Number.isFinite(response.json('dns.received')); } catch (_) {}
  check(response, {'authenticated versioned counters': () => valid});
  errors.add(!valid);
}
export function handleSummary(data) {
  const output = __ENV.SUMMARY_PATH || 'results/management-k6.json';
  return { [output]: JSON.stringify({kind:'k6-real-management-api', configured_rate:rate, duration:__ENV.DURATION || '60s', metrics:data.metrics}, null, 2) + '\n' };
}
