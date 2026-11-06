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


if __name__ == '__main__':
    unittest.main()
