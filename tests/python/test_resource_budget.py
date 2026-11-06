import pathlib
import tempfile
import unittest
from tools.bench.resource_budget import command_for_budget, read_cgroup, verify_limits


class ResourceBudgetTests(unittest.TestCase):
    def test_command_sets_real_caps_no_swap_and_short_cpu_period(self):
        cmd = command_for_budget('dns-guard-bench-123.service', ['/tmp/server', 'rules.dngi'], 50, 8)
        for setting in ['CPUQuota=50%', 'CPUQuotaPeriodSec=10ms', 'MemoryMax=8388608', 'MemorySwapMax=0', 'TasksMax=64']:
            self.assertIn(setting, cmd)
        self.assertEqual(cmd[-2:], ['/tmp/server', 'rules.dngi'])
        self.assertNotIn('--remain-after-exit', cmd)  # incompatible with --pipe
        for cpu, memory in [(0, 8), (50, 0), (-1, 16)]:
            with self.assertRaises(ValueError): command_for_budget('dns-guard-bench-123.service', ['/tmp/server'], cpu, memory)

    def test_verified_limits_and_oom_and_throttle_counters(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = pathlib.Path(tmp)
            values = {'cpu.max': '5000 10000', 'memory.max': '8388608', 'memory.swap.max': '0', 'memory.current': '123456', 'memory.peak': '200000', 'memory.events': 'low 0\nmax 3\noom 1\noom_kill 1\n', 'cpu.stat': 'usage_usec 12345\nnr_throttled 10\nthrottled_usec 1000\n'}
            for name, value in values.items(): (p/name).write_text(value)
            actual = read_cgroup(p)
            verify_limits(actual, 50, 8)
            self.assertEqual(actual['memory_events']['oom_kill'], 1)
            self.assertEqual(actual['cpu_stat']['nr_throttled'], 10)
            with self.assertRaises(ValueError): verify_limits(actual, 100, 8)
            with self.assertRaises(ValueError): verify_limits(actual, 50, 16)
            (p/'memory.max').write_text('max')
            with self.assertRaises(ValueError): verify_limits(read_cgroup(p), 50, 8)
