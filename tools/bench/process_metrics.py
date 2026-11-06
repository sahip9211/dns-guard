"""Linux /proc CPU/RSS sampler used by both k6 and direct-engine workloads."""
import json
import os
import pathlib
import statistics
import subprocess
import sys
import time


def parse_proc_stat(text, ticks_per_second, page_size):
    fields = text.rsplit(')', 1)[1].split()
    return (int(fields[11]) + int(fields[12])) / ticks_per_second, int(fields[21]) * page_size


def summarize(samples, logical_cpus):
    if len(samples) < 2:
        return {'samples': len(samples), 'warning': 'insufficient process samples'}
    intervals = []
    # /proc CPU time is quantized in clock ticks. A short final sample can
    # otherwise turn one tick into an impossible-looking instantaneous spike.
    window = samples[0]
    for curr in samples[1:]:
        duration = curr['elapsed_s'] - window['elapsed_s']
        if duration >= .1:
            intervals.append(100 * (curr['cpu_s'] - window['cpu_s']) / duration)
            window = curr
    duration = samples[-1]['elapsed_s'] - samples[0]['elapsed_s']
    cpu = 100 * (samples[-1]['cpu_s'] - samples[0]['cpu_s']) / duration
    return {
        'samples': len(samples),
        'sampled_duration_s': duration,
        'logical_cpus': logical_cpus,
        'cpu_mean_percent_one_core': cpu,
        'cpu_peak_sampled_percent_one_core': max(intervals, default=None),
        'cpu_peak_window_min_s': .1,
        'cpu_mean_percent_machine': cpu / logical_cpus,
        'rss_peak_sampled_bytes': max(s['rss_bytes'] for s in samples),
        'rss_mean_sampled_bytes': statistics.mean(s['rss_bytes'] for s in samples),
    }


def sample(pid, started):
    try:
        cpu, rss = parse_proc_stat(pathlib.Path(f'/proc/{pid}/stat').read_text(), os.sysconf('SC_CLK_TCK'), os.sysconf('SC_PAGE_SIZE'))
    except FileNotFoundError:
        return None
    # Do not let a zombie's zero RSS distort the process average.
    if rss == 0:
        return None
    return {'elapsed_s': time.monotonic() - started, 'cpu_s': cpu, 'rss_bytes': rss}


def main():
    if len(sys.argv) < 4 or sys.argv[2] != '--':
        raise SystemExit('usage: python3 -m tools.bench.process_metrics REPORT.json -- COMMAND [ARGS...]')
    report_path = pathlib.Path(sys.argv[1])
    report_path.parent.mkdir(parents=True, exist_ok=True)
    samples = []
    started = time.monotonic()
    # Files avoid pipe deadlocks on verbose long-running children.
    with report_path.with_suffix('.stdout').open('w') as stdout, report_path.with_suffix('.stderr').open('w') as stderr, report_path.with_suffix('.samples.jsonl').open('w') as raw:
        child = subprocess.Popen(sys.argv[3:], stdout=stdout, stderr=stderr)
        try:
            while child.poll() is None:
                reading = sample(child.pid, started)
                if reading:
                    samples.append(reading)
                    raw.write(json.dumps(reading) + '\n')
                    raw.flush()
                time.sleep(1)
        finally:
            if child.poll() is None:
                child.terminate()
                child.wait(timeout=10)
    result = {'command': sys.argv[3:], 'exit_code': child.returncode, 'resources': summarize(samples, os.cpu_count() or 1)}
    report_path.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))
    raise SystemExit(child.returncode)


if __name__ == '__main__':
    main()
