import unittest
from tools.bench.process_metrics import parse_proc_stat, summarize


class ProcessMetricsTests(unittest.TestCase):
    def test_process_name_can_contain_spaces_and_parentheses(self):
        # Fields 14/15: user/system CPU; field 24: resident pages.
        fields = ['S'] + ['0'] * 21
        fields[11], fields[12], fields[21] = '125', '25', '512'
        self.assertEqual(parse_proc_stat('42 (worker (test)) ' + ' '.join(fields), 100, 4096), (1.5, 2097152))

    def test_cpu_counts_one_core_as_100_percent_and_excludes_initial_sample(self):
        report = summarize([
            {'elapsed_s': 0, 'cpu_s': 1, 'rss_bytes': 1000},
            {'elapsed_s': 1, 'cpu_s': 2.5, 'rss_bytes': 3000},
            {'elapsed_s': 2, 'cpu_s': 4, 'rss_bytes': 2000},
        ], 4)
        self.assertEqual(report['cpu_mean_percent_one_core'], 150)
        self.assertEqual(report['cpu_mean_percent_machine'], 37.5)
        self.assertEqual(report['rss_peak_sampled_bytes'], 3000)
        self.assertEqual(report['rss_mean_sampled_bytes'], 2000)

    def test_short_final_sample_does_not_turn_one_cpu_tick_into_a_peak_spike(self):
        report = summarize([
            {'elapsed_s': 0, 'cpu_s': 0, 'rss_bytes': 1000},
            {'elapsed_s': .2, 'cpu_s': .05, 'rss_bytes': 1000},
            {'elapsed_s': .204, 'cpu_s': .06, 'rss_bytes': 1000},
        ], 1)
        self.assertEqual(report['cpu_peak_sampled_percent_one_core'], 25)
        self.assertAlmostEqual(report['cpu_mean_percent_one_core'], 100 * .06 / .204)

    def test_peak_cpu_windows_accumulate_short_samples(self):
        report = summarize([
            {'elapsed_s': 0, 'cpu_s': 0, 'rss_bytes': 1000},
            {'elapsed_s': .02, 'cpu_s': .01, 'rss_bytes': 1000},
            {'elapsed_s': .04, 'cpu_s': .02, 'rss_bytes': 1000},
            {'elapsed_s': .1, 'cpu_s': .05, 'rss_bytes': 1000},
        ], 1)
        self.assertEqual(report['cpu_peak_sampled_percent_one_core'], 50)


if __name__ == '__main__':
    unittest.main()
