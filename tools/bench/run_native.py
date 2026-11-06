#!/usr/bin/env python3
"""Run a separately labelled native diagnostic with the same server cgroup caps."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import uuid
from .resource_budget import command_for_budget, inspect_unit, read_cgroup, verify_limits
from .process_metrics import sample, summarize

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--server', required=True)
parser.add_argument('--index', required=True)
parser.add_argument('--probe', required=True)
parser.add_argument('--cases', default='tests/load/cases.json')
parser.add_argument('--output', required=True)
parser.add_argument('--duration', default='30s')
parser.add_argument('--rate', default='25000')
parser.add_argument('--workers', default='200')
args = parser.parse_args()
out = Path(args.output); out.mkdir(parents=True, exist_ok=False)
index = args.index
cases = args.cases
probe = str(Path(args.probe).resolve())
unit = f'dns-guard-bench-{uuid.uuid4().hex}.service'
manifest = {p: hashlib.sha256(Path(p).read_bytes()).hexdigest() for p in [args.server, index, cases, probe]}
started = time.monotonic()
server = client = None
samples = [[], []]
initial = final = result = failure = cgroup = None
status = None
try:
    with (out/'server.log').open('w') as log, (out/'client.json').open('w') as output, (out/'client.log').open('w') as errors, (out/'samples.jsonl').open('w') as raw:
        command = [str(Path(args.server).resolve()), index, '127.0.0.1:8787', '1']
        server = subprocess.Popen(command_for_budget(unit, command, 50, 8), stdout=log, stderr=log)
        for _ in range(100):
            if server.poll() is not None: raise RuntimeError('server exited at startup')
            if 'listening on' in (out/'server.log').read_text(): break
            time.sleep(.1)
        else: raise RuntimeError('startup timeout')
        info = inspect_unit(unit); pid = int(info['MainPID'])
        cgroup = Path('/sys/fs/cgroup') / info['ControlGroup'].lstrip('/')
        initial = read_cgroup(cgroup); verify_limits(initial, 50, 8)
        client = subprocess.Popen([probe, '-cases', cases, '-duration', args.duration, '-rate', args.rate, '-workers', args.workers], env=dict(os.environ, GOMAXPROCS='2'), stdout=output, stderr=errors)
        while client.poll() is None:
            row = {}
            for i, (label, child_pid) in enumerate([('server', pid), ('generator', client.pid)]):
                value = sample(child_pid, started)
                if value: samples[i].append(value)
                row[label] = value
            final = read_cgroup(cgroup); row['cgroup'] = final
            raw.write(json.dumps(row)+'\n'); raw.flush()
            if server.poll() is not None: raise RuntimeError('server exited under load')
            time.sleep(1)
        status = client.returncode
except (OSError, RuntimeError, subprocess.SubprocessError, KeyboardInterrupt) as error:
    failure = str(error) or 'interrupted'
finally:
    try:
        result = inspect_unit(unit)
        if cgroup and cgroup.exists(): final = read_cgroup(cgroup)
    except (OSError, subprocess.SubprocessError): pass
    subprocess.run(['systemctl', '--user', 'stop', unit], capture_output=True)
    subprocess.run(['systemctl', '--user', 'reset-failed', unit], capture_output=True)
    for child in [client, server]:
        if child and child.poll() is None:
            child.terminate()
            try: child.wait(timeout=5)
            except subprocess.TimeoutExpired: child.kill(); child.wait()
try: measured = json.loads((out/'client.json').read_text())
except (OSError, ValueError): measured = None
report = dict(kind='native-diagnostic-not-k6', configuration=vars(args), manifest=manifest, generator_GOMAXPROCS=2, exit_code=status, failure=failure, initial_limits=initial, final_limits=final, unit_result=result, request_metrics=measured, server_resources=summarize(samples[0],os.cpu_count() or 1), generator_resources=summarize(samples[1],os.cpu_count() or 1))
(out/'report.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps(report,indent=2))
sys.exit(0 if status==0 and failure is None else 1)
