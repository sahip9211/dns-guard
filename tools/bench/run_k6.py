#!/usr/bin/env python3
"""Linux k6 runner: target and generator CPU/RSS plus request/latency/error stats.

Does not install anything. Build the harness and compile an index first.
"""
import argparse
import hashlib
import json
import os
import pathlib
import signal
import subprocess
import time
import uuid
from .process_metrics import sample, summarize
from .load_report import summarize_run
from .resource_budget import command_for_budget, inspect_unit, read_cgroup, verify_limits


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--index', required=True)
    parser.add_argument('--output', required=True)
    parser.add_argument('--k6', default='k6')
    parser.add_argument('--server', default='target/release/examples/load_server_async')
    parser.add_argument('--duration', default='15m')
    parser.add_argument('--rate', type=int, default=2500)
    parser.add_argument('--vus', type=int, default=200)
    parser.add_argument('--devices', type=int, default=2000)
    parser.add_argument('--mode', choices=['arrival', 'concurrency'], default='arrival')
    parser.add_argument('--workers', type=int, default=1)
    parser.add_argument('--port', type=int, default=8787)
    parser.add_argument('--cases', default='tests/load/cases.json')
    parser.add_argument('--cpu-percent', type=int, help='server CPU cap: 100 = one logical CPU')
    parser.add_argument('--memory-mib', type=int, help='server hard cgroup memory limit; swap disabled')
    args = parser.parse_args(argv)
    if (args.cpu_percent is None) != (args.memory_mib is None):
        parser.error('--cpu-percent and --memory-mib must be supplied together')
    return args


def main():
    args = parse_args()
    output = pathlib.Path(args.output).resolve()
    output.mkdir(parents=True, exist_ok=False)
    config = vars(args)
    (output/'configuration.json').write_text(json.dumps(config, indent=2)+'\n')
    # Save the exact executable/corpus and only the non-secret tuning variables.
    manifest = {
        'files': {name: {'path': path, 'sha256': hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()}
                  for name, path in [('server', args.server), ('index', args.index), ('cases', args.cases), ('script', 'tests/load/filter.js')]},
        'generator_tuning': {key: os.environ[key] for key in ('GOMAXPROCS', 'GOGC', 'GOMEMLIMIT') if key in os.environ},
    }
    (output/'manifest.json').write_text(json.dumps(manifest, indent=2)+'\n')
    env = dict(os.environ, K6_NO_USAGE_REPORT='true')
    # -e works consistently for both `k6 inspect` and `k6 run`.
    values = {'DURATION': args.duration, 'RATE': args.rate, 'VUS': args.vus, 'DEVICES': args.devices, 'MODE': args.mode, 'BASE_URL': f'http://127.0.0.1:{args.port}', 'CASES': str(pathlib.Path(args.cases).resolve()), 'REPORT': str(output/'k6.json')}
    command = [args.k6, 'run', '--quiet']
    for name, value in values.items():
        command += ['-e', f'{name}={value}']
    command.append('tests/load/filter.js')
    server = load = None
    target_samples, generator_samples = [], []
    started = time.monotonic()
    status = None
    failure = None
    unit = f'dns-guard-bench-{uuid.uuid4().hex}.service' if args.cpu_percent is not None else None
    cgroup = None
    cgroup_initial = cgroup_final = unit_result = None
    try:
        with (output/'server.log').open('w') as server_log, (output/'k6.log').open('w') as k6_log, (output/'samples.jsonl').open('w') as raw:
            server_command = [str(pathlib.Path(args.server).resolve()), str(pathlib.Path(args.index).resolve()), f'127.0.0.1:{args.port}', str(args.workers)]
            if unit:
                server_command = command_for_budget(unit, server_command, args.cpu_percent, args.memory_mib)
            server = subprocess.Popen(server_command, stdout=server_log, stderr=server_log)
            # Bound startup wait; k6 setup verifies /health and every fixture.
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                if server.poll() is not None:
                    detail = (output/'server.log').read_text()[-1000:].strip()
                    raise RuntimeError(f'harness exited {server.returncode}: {detail}')
                if 'listening on' in (output/'server.log').read_text():
                    break
                time.sleep(0.1)
            else:
                raise RuntimeError('harness did not become ready within 10s')
            target_pid = server.pid
            if unit:
                unit_result = inspect_unit(unit)
                target_pid = int(unit_result['MainPID'])
                if target_pid <= 0: raise RuntimeError('budgeted server has no main PID')
                cgroup = pathlib.Path('/sys/fs/cgroup') / unit_result['ControlGroup'].lstrip('/')
                cgroup_initial = read_cgroup(cgroup)
                verify_limits(cgroup_initial, args.cpu_percent, args.memory_mib)
            load = subprocess.Popen(command, env=env, stdout=k6_log, stderr=k6_log)
            while load.poll() is None:
                target = sample(target_pid, started)
                generator = sample(load.pid, started)
                if target:
                    target_samples.append(target)
                if generator:
                    generator_samples.append(generator)
                if cgroup:
                    try: cgroup_final = read_cgroup(cgroup)
                    except FileNotFoundError: pass
                raw.write(json.dumps({'target': target, 'generator': generator, 'cgroup': cgroup_final})+'\n')
                raw.flush()
                if server.poll() is not None:
                    raise RuntimeError('harness exited during load')
                time.sleep(1)
            status = load.returncode
    except (OSError, RuntimeError, ValueError, subprocess.SubprocessError, KeyboardInterrupt) as error:
        failure = str(error) or 'interrupted'
    finally:
        if unit:
            try:
                unit_result = inspect_unit(unit)
                if cgroup and cgroup.exists(): cgroup_final = read_cgroup(cgroup)
            except (OSError, subprocess.SubprocessError): pass
            subprocess.run(['systemctl', '--user', 'stop', unit], capture_output=True)
            subprocess.run(['systemctl', '--user', 'reset-failed', unit], capture_output=True)
        for child in (load, server):
            if child is not None and child.poll() is None:
                child.send_signal(signal.SIGTERM)
                try:
                    child.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait()
    metrics = None
    if (output/'k6.json').exists():
        try:
            metrics = json.loads((output/'k6.json').read_text())
        except (OSError, ValueError) as error:
            failure = failure or f'invalid k6 report: {error}'
    summary = summarize_run(metrics, status)
    report = {
        'kind': 'k6-http-harness', 'exit_code': status, 'failure': failure,
        'completed': summary['completed'] and failure is None,
        'summary': summary,
        'enforced_limits': {'cpu_percent': args.cpu_percent, 'memory_mib': args.memory_mib, 'swap_bytes': 0, 'unit': unit, 'verified_initial': cgroup_initial, 'final': cgroup_final, 'unit_result': unit_result} if unit else None,
        'target_resources': summarize(target_samples, os.cpu_count() or 1),
        'generator_resources': summarize(generator_samples, os.cpu_count() or 1),
        'request_metrics': metrics,
        'note': 'HTTP adapter, not DNS. CPU 100% equals one logical core. RSS includes adapter and index. Device header is a workload label, not authenticated client enrollment.',
    }
    (output/'report.json').write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps({k: v for k,v in report.items() if k != 'request_metrics'}, indent=2))
    raise SystemExit(0 if report['completed'] else 1)


if __name__ == '__main__':
    main()
