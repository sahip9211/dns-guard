//! Sustained matcher-only workload; does not measure DNS or HTTP throughput.
use dns_guard::{Index, Limits};
use std::{
    path::Path,
    time::{Duration, Instant},
};

const BIN_NS: u64 = 100;
const BINS: usize = 100_001;

struct Stats {
    bins: Vec<u64>,
    count: u64,
    errors: u64,
    max_ns: u64,
}
impl Stats {
    fn new() -> Self {
        Self {
            bins: vec![0; BINS],
            count: 0,
            errors: 0,
            max_ns: 0,
        }
    }
    fn record(&mut self, ns: u64, error: bool) {
        self.bins[(ns / BIN_NS).min((BINS - 1) as u64) as usize] += 1;
        self.count += 1;
        self.errors += u64::from(error);
        self.max_ns = self.max_ns.max(ns);
    }
    fn percentile(&self, percent: u64) -> u64 {
        if self.count == 0 {
            return 0;
        }
        let rank = (self.count * percent).div_ceil(100).max(1);
        let mut cumulative = 0;
        for (bin, count) in self.bins.iter().enumerate() {
            cumulative += count;
            if cumulative >= rank {
                return if bin == BINS - 1 {
                    self.max_ns
                } else {
                    ((bin as u64 + 1) * BIN_NS - 1).min(self.max_ns)
                };
            }
        }
        self.max_ns
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.len() != 4 {
        return Err("usage: soak INDEX QUERIES.tsv SECONDS WORKERS".into());
    }
    let seconds = args[2].parse::<u64>()?;
    let workers = args[3].parse::<usize>()?;
    if !(1..=3600).contains(&seconds) || !(1..=64).contains(&workers) {
        return Err("seconds must be 1..3600 and workers 1..64".into());
    }
    let index = Index::load(Path::new(&args[0]), Limits::default().max_index_bytes)?;
    let text = std::fs::read_to_string(&args[1])?;
    let queries: Vec<_> = text
        .lines()
        .map(|line| {
            let fields: Vec<_> = line.split('\t').collect();
            if fields.len() != 3 {
                return Err("expected three TSV columns".into());
            }
            Ok::<_, Box<dyn std::error::Error>>((
                fields[0],
                fields[1].parse::<u32>()?,
                fields[2].parse::<u32>()?,
            ))
        })
        .collect::<Result<_, _>>()?;
    if queries.is_empty() {
        return Err("empty queries".into());
    }
    for &(domain, enabled, expected) in &queries {
        if index.check(domain, enabled)?.blocked != expected {
            return Err(format!("fixture mismatch: {domain}").into());
        }
    }
    let barrier = std::sync::Barrier::new(workers + 1);
    let started = Instant::now();
    let results = std::thread::scope(|scope| {
        let mut handles = Vec::new();
        for worker in 0..workers {
            let (index, queries, barrier) = (&index, &queries, &barrier);
            handles.push(scope.spawn(move || {
                let mut stats = Stats::new();
                let mut cursor = worker * 997;
                barrier.wait();
                let deadline = Instant::now() + Duration::from_secs(seconds);
                while Instant::now() < deadline {
                    for _ in 0..256 {
                        let (domain, enabled, expected) = queries[cursor % queries.len()];
                        cursor += 1;
                        let start = Instant::now();
                        let result = index.check(std::hint::black_box(domain), enabled);
                        let elapsed = start.elapsed().as_nanos() as u64;
                        let error = result.map_or(true, |decision| decision.blocked != expected);
                        stats.record(elapsed, error);
                    }
                }
                stats
            }));
        }
        barrier.wait();
        handles
            .into_iter()
            .map(|h| h.join().expect("benchmark worker panicked"))
            .collect::<Vec<_>>()
    });
    let elapsed = started.elapsed().as_secs_f64();
    let mut stats = Stats::new();
    for result in results {
        stats.count += result.count;
        stats.errors += result.errors;
        stats.max_ns = stats.max_ns.max(result.max_ns);
        for (a, b) in stats.bins.iter_mut().zip(result.bins) {
            *a += b;
        }
    }
    println!(
        "{{\"kind\":\"direct-engine\",\"duration_s\":{elapsed:.6},\"workers\":{workers},\"rules\":{},\"lookups\":{},\"lookups_per_s\":{:.3},\"errors\":{},\"error_rate\":{:.9},\"p50_ms\":{:.6},\"p95_ms\":{:.6},\"p99_ms\":{:.6},\"max_ms\":{:.6},\"histogram_resolution_ns\":100,\"histogram_overflow_samples\":{}}}",
        index.rule_count(),
        stats.count,
        stats.count as f64 / elapsed,
        stats.errors,
        stats.errors as f64 / stats.count as f64,
        stats.percentile(50) as f64 / 1e6,
        stats.percentile(95) as f64 / 1e6,
        stats.percentile(99) as f64 / 1e6,
        stats.max_ns as f64 / 1e6,
        stats.bins[BINS - 1]
    );
    if stats.errors != 0 {
        return Err("correctness errors during sustained test".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn histogram_reports_upper_bound_percentiles_errors_and_overflow() {
        let mut stats = Stats::new();
        for _ in 0..98 {
            stats.record(1250, false);
        }
        stats.record(9999, true);
        stats.record(100_000_000, false);
        assert_eq!(stats.count, 100);
        assert_eq!(stats.errors, 1);
        assert_eq!(stats.percentile(50), 1299);
        assert_eq!(stats.percentile(99), 9999);
        assert_eq!(stats.percentile(100), 100_000_000);
        assert_eq!(Stats::new().percentile(99), 0);
    }
}
