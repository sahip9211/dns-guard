import contextlib
import io
import unittest
from tools.bench.run_k6 import parse_args


class LoadDefaultsTests(unittest.TestCase):
    def test_small_default_and_explicit_parallel_override(self):
        defaults = parse_args(['--index', 'rules.dngi', '--output', 'results/test'])
        self.assertEqual(defaults.server, 'target/release/examples/load_server_async')
        self.assertEqual(defaults.workers, 1)
        parallel = parse_args(['--index', 'rules.dngi', '--output', 'results/test', '--workers', '2',
                               '--cpu-percent', '50', '--memory-mib', '8'])
        self.assertEqual((parallel.workers, parallel.cpu_percent, parallel.memory_mib), (2, 50, 8))

    def test_incomplete_budget_fails_before_creating_output_or_starting_server(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as error:
            parse_args(['--index', 'rules.dngi', '--output', 'results/test', '--cpu-percent', '50'])
        self.assertEqual(error.exception.code, 2)
