"""Transient systemd user units and verified cgroup-v2 limits for the test server."""
import pathlib
import re
import subprocess


def command_for_budget(unit, command, cpu_percent, memory_mib):
    if not re.fullmatch(r'dns-guard-bench-[0-9a-f-]+\.service', unit):
        raise ValueError('invalid benchmark unit name')
    if not (0 < cpu_percent <= 10000 and 0 < memory_mib <= 65536):
        raise ValueError('CPU percentage and memory MiB must be positive and bounded')
    return ['systemd-run', '--user', '--quiet', '--wait', '--pipe', '--unit', unit,
            '-p', f'CPUQuota={cpu_percent}%', '-p', 'CPUQuotaPeriodSec=10ms',
            '-p', f'MemoryMax={memory_mib * 1048576}', '-p', 'MemorySwapMax=0',
            '-p', 'MemoryAccounting=yes', '-p', 'TasksMax=64', '--', *command]


def read_cgroup(path):
    path = pathlib.Path(path)
    def scalar(name):
        value = (path/name).read_text().strip()
        return value if value == 'max' else int(value)
    def counters(name):
        return {key: int(value) for key, value in (line.split() for line in (path/name).read_text().splitlines())}
    quota, period = (path/'cpu.max').read_text().split()
    return {'cpu_quota_us': quota if quota == 'max' else int(quota), 'cpu_period_us': int(period),
            'memory_max_bytes': scalar('memory.max'), 'swap_max_bytes': scalar('memory.swap.max'),
            'memory_current_bytes': scalar('memory.current'), 'memory_peak_bytes': scalar('memory.peak'),
            'memory_events': counters('memory.events'), 'cpu_stat': counters('cpu.stat')}


def verify_limits(actual, cpu_percent, memory_mib):
    if (actual['memory_max_bytes'] != memory_mib * 1048576 or actual['swap_max_bytes'] != 0
            or not isinstance(actual['cpu_quota_us'], int)
            or abs(actual['cpu_quota_us'] / actual['cpu_period_us'] * 100 - cpu_percent) > .01):
        raise ValueError(f'kernel resource limits do not match requested budget: {actual}')


def inspect_unit(unit):
    result = subprocess.run(['systemctl', '--user', 'show', unit, '--property=MainPID,ControlGroup,Result,MemoryPeak,CPUUsageNSec,ExecMainStatus'], check=True, capture_output=True, text=True)
    return dict(line.split('=', 1) for line in result.stdout.splitlines() if '=' in line)
