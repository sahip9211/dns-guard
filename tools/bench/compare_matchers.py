#!/usr/bin/env python3
"""Alternate two direct matcher binaries. Both validate expected decisions first."""
import argparse
import hashlib
import json
import pathlib
import statistics
import subprocess

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--before', required=True)
parser.add_argument('--after', required=True)
parser.add_argument('--before-index', required=True)
parser.add_argument('--after-index', required=True)
parser.add_argument('--queries', required=True)
parser.add_argument('--pairs', type=int, default=6)
parser.add_argument('--cpu', type=int)
parser.add_argument('--output', required=True)
args = parser.parse_args()
if args.pairs < 1:
    parser.error('--pairs must be positive')
paths = {key: getattr(args, key) for key in ['before', 'after', 'before_index', 'after_index', 'queries']}
manifest = {key: {'path': value, 'bytes': pathlib.Path(value).stat().st_size,
                 'sha256': hashlib.sha256(pathlib.Path(value).read_bytes()).hexdigest()} for key, value in paths.items()}
runs = []
for pair in range(args.pairs):
    for variant in (['before', 'after'] if pair % 2 == 0 else ['after', 'before']):
        command = [paths[variant], paths[variant + '_index'], paths['queries']]
        if args.cpu is not None:
            command = ['taskset', '-c', str(args.cpu)] + command
        result = json.loads(subprocess.check_output(command, text=True))
        runs.append(dict(pair=pair, variant=variant, **result))
medians = {variant: {metric: statistics.median(run[metric] for run in runs if run['variant'] == variant)
                    for metric in ['p50_ns', 'p95_ns', 'p99_ns']} for variant in ['before', 'after']}
report = dict(configuration=vars(args), manifest=manifest, runs=runs, median_of_runs=medians,
              decrease_percent={metric: (1 - medians['after'][metric] / medians['before'][metric]) * 100
                                for metric in medians['before']})
with open(args.output, 'x') as output:
    json.dump(report, output, indent=2)
    output.write('\n')
print(json.dumps({key: report[key] for key in ['median_of_runs', 'decrease_percent']}, indent=2))
