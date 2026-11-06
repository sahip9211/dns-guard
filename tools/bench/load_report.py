"""Normalize k6 reports without treating an empty run as zero-latency success."""
import math
import re


def summarize_run(report, exit_code):
    report = report if isinstance(report, dict) else {}

    def value(name, field):
        metric = report.get(name)
        result = metric.get(field) if isinstance(metric, dict) else None
        if isinstance(result, bool) or not isinstance(result, (int, float)) or not math.isfinite(result) or result < 0:
            return None
        return result

    issued = value('issued_requests', 'count')
    handled = value('successful_requests', 'count')
    observed = issued is not None and issued > 0
    http_error = value('http_error_rate', 'rate')
    policy_error = value('policy_error_rate', 'rate')
    dropped = value('dropped_iterations', 'count')
    # Closed-loop scenarios do not emit dropped_iterations.
    if report.get('configured_mode') == 'concurrency' and dropped is None:
        dropped = 0
    result = {
        'workload_observed': observed,
        'issued_requests': issued,
        'handled_requests': handled,
        'handled_requests_per_s': value('successful_requests', 'rate') if observed else None,
        'http_p99_ms': value('http_duration_ms', 'p(99)') if observed else None,
        'matcher_p99_ms': value('matcher_duration_ms', 'p(99)') if observed else None,
        'http_error_percent': http_error * 100 if observed and http_error is not None else None,
        'policy_error_percent': policy_error * 100 if observed and policy_error is not None else None,
        'dropped_iterations': dropped,
    }
    required = ('handled_requests_per_s', 'http_p99_ms', 'matcher_p99_ms', 'http_error_percent', 'policy_error_percent')
    result['completed'] = (exit_code == 0 and observed and handled == issued
                           and all(result[key] is not None for key in required)
                           and http_error == 0 and policy_error == 0 and dropped == 0)
    # k6 counter rates include preflight time. Also expose a clearly labelled
    # count/requested-load-duration rate for runs that reached normal completion.
    # Exit 99 is an end-of-run threshold failure, not successful target capacity.
    duration = report.get('configured_duration', '')
    pieces = re.findall(r'(\d+(?:\.\d+)?)(ms|s|m|h)', duration) if isinstance(duration, str) else []
    seconds = sum(float(n) * {'ms': .001, 's': 1, 'm': 60, 'h': 3600}[unit] for n, unit in pieces)
    valid_duration = ''.join(n + unit for n, unit in pieces) == duration and seconds > 0
    result['requests_per_configured_load_second'] = handled / seconds if (observed and handled is not None and exit_code in (0, 99) and valid_duration) else None
    result['target_requests_per_s'] = report.get('configured_rate')
    return result
