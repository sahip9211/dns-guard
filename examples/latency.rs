//! Direct warm matcher benchmark. Query file: domain<TAB>category mask<TAB>expected blocked mask.
use dns_guard::{Index, Limits};
use std::{hint::black_box, path::Path, time::Instant};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.len() != 2 {
        return Err("usage: latency INDEX QUERIES.tsv".into());
    }
    let index = Index::load(Path::new(&args[0]), Limits::default().max_index_bytes)?;
    let text = std::fs::read_to_string(&args[1])?;
    let queries: Vec<_> = text
        .lines()
        .map(|line| {
            let mut fields = line.split('\t');
            let domain = fields.next().ok_or("missing domain")?;
            let categories = fields.next().ok_or("missing categories")?.parse::<u32>()?;
            let expected = fields
                .next()
                .ok_or("missing expected result")?
                .parse::<u32>()?;
            Ok::<_, Box<dyn std::error::Error>>((domain, categories, expected))
        })
        .collect::<Result<_, _>>()?;
    if queries.is_empty() {
        return Err("empty queries".into());
    }
    for &(domain, categories, expected) in &queries {
        assert_eq!(
            index.check(domain, categories)?.blocked,
            expected,
            "{domain}"
        );
    }
    for _ in 0..3 {
        for &(domain, categories, _) in &queries {
            black_box(index.check(black_box(domain), categories)?);
        }
    }
    let mut samples = Vec::with_capacity(queries.len() * 10);
    for _ in 0..10 {
        for &(domain, categories, _) in &queries {
            let start = Instant::now();
            black_box(index.check(black_box(domain), categories)?);
            samples.push(start.elapsed().as_nanos());
        }
    }
    samples.sort_unstable();
    let percentile =
        |p: usize| samples[((samples.len() * p).div_ceil(100) - 1).min(samples.len() - 1)];
    println!(
        "{{\"queries\":{},\"samples\":{},\"index_bytes\":{},\"p50_ns\":{},\"p95_ns\":{},\"p99_ns\":{},\"max_ns\":{}}}",
        queries.len(),
        samples.len(),
        index.as_bytes().len(),
        percentile(50),
        percentile(95),
        percentile(99),
        samples[samples.len() - 1]
    );
    Ok(())
}
