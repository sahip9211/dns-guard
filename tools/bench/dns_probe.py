"""Closed-loop UDP diagnostic for locally blocked DNS queries; not a k6 capacity test."""
import argparse
from array import array
import asyncio
from datetime import datetime, timezone
import json
import math
import os
from pathlib import Path
import socket
import struct
import time
from .process_metrics import sample, summarize


def make_query(hostname, identifier):
    labels = hostname.removesuffix('.').encode('ascii').split(b'.')
    if any(not 1 <= len(label) <= 63 for label in labels) or sum(map(len, labels)) + len(labels) > 254:
        raise ValueError('invalid DNS hostname length')
    name = b''.join(bytes([len(label)]) + label for label in labels) + b'\0'
    return struct.pack('!6H', identifier, 0x0100, 1, 0, 0, 0) + name + b'\0\x01\0\x01'


def validate_block_reply(reply, query):
    if len(reply) != len(query) or len(reply) < 12:
        return False
    identifier, flags, questions, answers, authority, additional = struct.unpack('!6H', reply[:12])
    return (reply[:2] == query[:2] and flags == 0x8185 and questions == 1
            and answers == authority == additional == 0 and reply[12:] == query[12:])


class Histogram:
    """Fixed 800 KB histogram, 1 us bins through 100 ms; larger values counted separately."""
    def __init__(self):
        self.bins = array('Q', [0]) * 100001
        self.count = self.overflow = self.maximum = 0

    def add(self, ns):
        self.count += 1
        self.maximum = max(self.maximum, ns)
        slot = (ns + 999) // 1000
        if slot >= len(self.bins): self.overflow += 1
        else: self.bins[slot] += 1

    def percentile(self, percent):
        if not self.count: return None
        rank = math.ceil(self.count * percent / 100)
        seen = 0
        for slot, count in enumerate(self.bins):
            seen += count
            if seen >= rank: return slot / 1000
        return None


async def probe(args):
    loop = asyncio.get_running_loop()
    host, port = args.address.rsplit(':', 1)
    host = host.strip('[]')
    family = socket.AF_INET6 if ':' in host else socket.AF_INET
    socket.inet_pton(family, host)  # Only explicit IPs; no bootstrap DNS dependency.
    target = (host, int(port))
    started = time.monotonic()
    deadline = started + args.duration
    histogram = Histogram()
    counts = {'attempts': 0, 'correct': 0, 'errors': 0, 'timeouts': 0}
    samples = {'server': [], 'generator': []}
    done = asyncio.Event()

    async def sampler():
        while True:
            for label, pid in [('server', args.pid), ('generator', os.getpid())]:
                if pid:
                    row = sample(pid, started)
                    if row is not None: samples[label].append(row)
            if done.is_set(): return
            try: await asyncio.wait_for(done.wait(), .2)
            except asyncio.TimeoutError: pass

    async def worker(number):
        sock = socket.socket(family, socket.SOCK_DGRAM)
        sock.setblocking(False)
        identifier = number
        try:
            await loop.sock_connect(sock, target)
            while time.monotonic() < deadline:
                identifier = (identifier + 1) & 65535
                query = make_query(args.hostname, identifier)
                before = time.perf_counter_ns()
                counts['attempts'] += 1
                try:
                    await loop.sock_sendall(sock, query)
                    reply = await asyncio.wait_for(loop.sock_recv(sock, 4096), 1)
                    if not validate_block_reply(reply, query):
                        counts['errors'] += 1
                    else:
                        counts['correct'] += 1
                        histogram.add(time.perf_counter_ns() - before)
                except asyncio.TimeoutError:
                    counts['errors'] += 1; counts['timeouts'] += 1
                except OSError:
                    counts['errors'] += 1
        finally: sock.close()

    sampling = asyncio.create_task(sampler())
    try: await asyncio.gather(*(worker(n) for n in range(args.clients)))
    finally:
        done.set()
        await sampling
    elapsed = time.monotonic() - started
    return {
        'kind': 'closed-loop-blocked-udp-diagnostic-not-k6',
        'created_at': datetime.now(timezone.utc).isoformat(),
        'clients': args.clients, 'configured_duration_s': args.duration,
        'elapsed_with_drain_s': elapsed, **counts,
        'error_rate': counts['errors'] / counts['attempts'] if counts['attempts'] else None,
        'correct_per_elapsed_second': counts['correct'] / elapsed,
        'offered_arrival_capacity': 'not measured by a closed-loop diagnostic',
        'latency_scope': 'valid replies only, send through receive and validation',
        'p50_ms_upper_bound': histogram.percentile(50),
        'p95_ms_upper_bound': histogram.percentile(95),
        'p99_ms_upper_bound': histogram.percentile(99),
        'max_ms': histogram.maximum / 1e6, 'latency_above_100ms': histogram.overflow,
        'resources': {label: summarize(rows, os.cpu_count() or 1) for label, rows in samples.items()},
        'resource_samples': samples,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--address', default='127.0.0.1:5353')
    parser.add_argument('--hostname', default='ads.example')
    parser.add_argument('--duration', type=int, default=60)
    parser.add_argument('--clients', type=int, default=32)
    parser.add_argument('--pid', type=int, help='server PID for Linux CPU/RSS sampling')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if not 1 <= args.duration <= 600 or not 1 <= args.clients <= 1024:
        parser.error('duration must be 1..600 seconds and clients 1..1024')
    report = asyncio.run(probe(args))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({key: value for key, value in report.items() if key != 'resource_samples'}, indent=2))
    if report['errors'] or not report['correct']: raise SystemExit(1)


if __name__ == '__main__': main()
