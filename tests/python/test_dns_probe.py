import struct
import unittest
from tools.bench.dns_probe import make_query, validate_block_reply, Histogram

class DnsProbeTests(unittest.TestCase):
    def test_validates_id_question_flags_and_empty_refusal(self):
        query = make_query('ads.example', 1234)
        reply = bytearray(query)
        reply[2:4] = b'\x81\x85'
        self.assertTrue(validate_block_reply(reply, query))
        for position, value in [(0, 0), (2, 1), (3, 0x80), (5, 2), (7, 1), (12, 2)]:
            bad = bytearray(reply); bad[position] = value
            self.assertFalse(validate_block_reply(bad, query))
        self.assertFalse(validate_block_reply(reply + b'extra', query))
        self.assertFalse(validate_block_reply(reply[:8], query))
        self.assertEqual(struct.unpack('!H', query[:2])[0], 1234)
        with self.assertRaises(ValueError): make_query('a..example', 0)
        with self.assertRaises(ValueError): make_query('a'*64 + '.example', 0)

    def test_histogram_reports_upper_bounds_and_overflow(self):
        histogram = Histogram()
        for value in [1, 1000, 1001, 100_000_001]: histogram.add(value)
        self.assertEqual(histogram.percentile(50), 0.001)
        self.assertEqual(histogram.percentile(75), 0.002)
        self.assertIsNone(histogram.percentile(99))
        self.assertEqual(histogram.overflow, 1)
        self.assertIsNone(Histogram().percentile(99))
