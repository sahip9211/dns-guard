import unittest
from tools.bench.load_report import summarize_run


class LoadReportTests(unittest.TestCase):
    def report(self):
        return {
            'issued_requests': {'count': 5000, 'rate': 2500},
            'successful_requests': {'count': 5000, 'rate': 2500},
            'http_duration_ms': {'p(99)': 1.2},
            'matcher_duration_ms': {'p(99)': 0.004},
            'http_error_rate': {'rate': 0},
            'policy_error_rate': {'rate': 0},
            'dropped_iterations': {'count': 0},
        }

    def test_complete_run_exposes_requested_metrics(self):
        summary = summarize_run(self.report(), 0)
        self.assertTrue(summary['completed'])
        self.assertEqual(summary['handled_requests_per_s'], 2500)
        self.assertEqual(summary['http_p99_ms'], 1.2)
        self.assertEqual(summary['policy_error_percent'], 0)

    def test_no_requests_never_becomes_zero_latency_success(self):
        report = self.report()
        report['issued_requests'] = {'count': 0, 'rate': 0}
        report['successful_requests'] = {'count': 0, 'rate': 0}
        report['http_duration_ms']['p(99)'] = 0
        result = summarize_run(report, 0)
        self.assertFalse(result['completed'])
        self.assertIsNone(result['http_p99_ms'])
        self.assertIsNone(result['handled_requests_per_s'])

    def test_missing_corrupt_and_failed_runs_cannot_pass(self):
        for report in [None, {}, {'issued_requests': {'count': 1}}, self.report()]:
            self.assertFalse(summarize_run(report, 107)['completed'])
        report = self.report()
        report['http_duration_ms']['p(99)'] = float('nan')
        self.assertFalse(summarize_run(report, 0)['completed'])

    def test_policy_errors_and_dropped_load_fail_even_if_exit_status_is_zero(self):
        for key, field in [('policy_error_rate', 'rate'), ('http_error_rate', 'rate'), ('dropped_iterations', 'count')]:
            report = self.report()
            report[key][field] = 1
            result = summarize_run(report, 0)
            self.assertFalse(result['completed'])
            self.assertEqual(result['handled_requests_per_s'], 2500)

    def test_load_phase_rate_separates_preflight_and_preserves_failed_targets(self):
        report = self.report()
        report['configured_duration'] = '1m30s'
        report['configured_rate'] = 25000
        result = summarize_run(report, 99)
        self.assertAlmostEqual(result['requests_per_configured_load_second'], 5000 / 90)
        self.assertEqual(result['target_requests_per_s'], 25000)
        self.assertFalse(result['completed'])
        self.assertIsNone(summarize_run(report, 107)['requests_per_configured_load_second'])
