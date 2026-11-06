//! Exact hash-table experiment, not a production backend. Same normalization
//! as the production matcher; complete keys are retained to resolve collisions.
use dns_guard::{Category, Decision, Index, Limits};
use std::{
    collections::{HashMap, hash_map::RandomState},
    hash::BuildHasher,
};

#[derive(Debug)]
struct Error(String);
impl Error {
    fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}
impl std::error::Error for Error {}
type Result<T> = std::result::Result<T, Error>;
// Reuse validation exactly without publishing a new production API.
#[allow(dead_code)]
#[path = "../src/domain.rs"]
mod domain;

struct Record {
    start: usize,
    end: usize,
    tag: usize,
    categories: u32,
}
struct HashIndex<'a, S = RandomState> {
    maps: Vec<HashMap<&'a [u8], u32, S>>,
    sharded: bool,
}

impl<'a, S: BuildHasher + Clone> HashIndex<'a, S> {
    fn new(pool: &'a [u8], records: &[Record], sharded: bool, hasher: S) -> Self {
        let mut sizes = vec![0; if sharded { 9 * 36 } else { 9 }];
        for r in records {
            sizes[bucket(r.tag, &pool[r.start..r.end], sharded)] += 1;
        }
        let mut maps: Vec<HashMap<&[u8], u32, S>> = sizes
            .into_iter()
            .map(|n| HashMap::with_capacity_and_hasher(n, hasher.clone()))
            .collect();
        for r in records {
            let key = &pool[r.start..r.end];
            *maps[bucket(r.tag, key, sharded)].entry(key).or_default() |= r.categories;
        }
        Self { maps, sharded }
    }
    fn check(&self, name: &str, enabled: u32) -> Result<Decision> {
        if enabled & !Category::ALL != 0 {
            return Err(Error::new("unknown category bits"));
        }
        let normalized = domain::Domain::parse(name)?;
        let name = normalized.as_bytes();
        if enabled == 0 {
            return Ok(Decision::default());
        }
        let mut found = [0; 3];
        let mut start = 0;
        loop {
            let suffix = &name[start..];
            for scope in 0..3 {
                if (scope == 0 && start != 0) || (scope == 2 && start == 0) {
                    continue;
                }
                for (action, mask) in found.iter_mut().enumerate() {
                    let map = &self.maps[bucket(scope * 3 + action, suffix, self.sharded)];
                    if let Some(categories) = map.get(suffix) {
                        *mask |= categories;
                    }
                }
            }
            let Some(dot) = suffix.iter().position(|&b| b == b'.') else {
                break;
            };
            start += dot + 1;
        }
        Ok(Decision {
            blocked: ((found[0] & !found[1]) | found[2]) & enabled,
            allowed: found[1] & enabled,
            enforced: found[2] & enabled,
        })
    }
}

fn bucket(tag: usize, name: &[u8], sharded: bool) -> usize {
    if !sharded {
        return tag;
    }
    let last = *name.last().expect("validated nonempty hostname");
    let letter = if last.is_ascii_digit() {
        last - b'0'
    } else {
        last - b'a' + 10
    };
    tag * 36 + letter as usize
}

fn records(index: &Index) -> (Vec<u8>, Vec<Record>) {
    use fst::Streamer;
    // Version-specific benchmark decoder; the production loader validated it.
    let packed = &index.as_bytes()[..8] == b"DNGIDX02";
    let map = fst::Map::new(&index.as_bytes()[32..]).expect("validated snapshot");
    let mut stream = map.stream();
    let mut pool = Vec::new();
    let mut result = Vec::with_capacity(index.rule_count());
    while let Some((key, categories)) = stream.next() {
        let start = pool.len();
        pool.extend(key[usize::from(!packed)..].iter().rev());
        if packed {
            for group in 0..3 {
                for action in 0..3 {
                    let mask = ((categories >> ((group * 3 + action) * 7)) & 127) as u32;
                    if mask != 0 {
                        let scope = [1, 0, 2][group];
                        result.push(Record {
                            start,
                            end: pool.len(),
                            tag: scope * 3 + action,
                            categories: mask,
                        });
                    }
                }
            }
        } else {
            result.push(Record {
                start,
                end: pool.len(),
                tag: key[0] as usize,
                categories: categories as u32,
            });
        }
    }
    pool.shrink_to_fit();
    (pool, result)
}

fn memory_bytes(field: &str) -> Option<u64> {
    // Linux-only observations; other platforms explicitly report null.
    std::fs::read_to_string("/proc/self/status")
        .ok()?
        .lines()
        .find_map(|line| {
            line.strip_prefix(field)?
                .split_whitespace()
                .next()?
                .parse::<u64>()
                .ok()
                .map(|n| n * 1024)
        })
}

fn measure(
    mut check: impl FnMut(&str, u32) -> Result<Decision>,
    mode: &str,
    queries: &[(String, u32, u32)],
    pool_bytes: usize,
    map_lower_bound: usize,
) -> Result<()> {
    use std::{hint::black_box, time::Instant};
    for _ in 0..3 {
        for (name, enabled, expected) in queries {
            assert_eq!(check(name, *enabled)?.blocked, *expected);
        }
    }
    let rss = memory_bytes("VmRSS:").map_or("null".to_owned(), |n| n.to_string());
    let mut times = Vec::with_capacity(queries.len() * 10);
    let started = Instant::now();
    for _ in 0..10 {
        for (name, enabled, expected) in queries {
            let now = Instant::now();
            let decision = black_box(check(black_box(name), *enabled)?);
            times.push(now.elapsed().as_nanos() as u64);
            assert_eq!(decision.blocked, *expected);
        }
    }
    let elapsed = started.elapsed().as_secs_f64();
    times.sort_unstable();
    let p = |n: usize| times[(times.len() * n).div_ceil(100) - 1];
    let peak = memory_bytes("VmHWM:").map_or("null".to_owned(), |n| n.to_string());
    println!(
        "{{\"mode\":\"{mode}\",\"samples\":{},\"p50_ns\":{},\"p95_ns\":{},\"p99_ns\":{},\"instrumented_lookups_per_s\":{},\"rss_before_timing_bytes\":{rss},\"whole_process_peak_bytes\":{peak},\"key_pool_bytes\":{pool_bytes},\"map_slot_lower_bound_bytes\":{map_lower_bound},\"errors\":0}}",
        times.len(),
        p(50),
        p(95),
        p(99),
        times.len() as f64 / elapsed
    );
    Ok(())
}

fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.len() != 3 || !["fst", "hash", "sharded-hash"].contains(&args[0].as_str()) {
        return Err("usage: hash_compare fst|hash|sharded-hash INDEX QUERIES.tsv".into());
    }
    let index = Index::load(
        std::path::Path::new(&args[1]),
        Limits::default().max_index_bytes,
    )?;
    let text = std::fs::read_to_string(&args[2])?;
    let queries = text
        .lines()
        .map(|line| {
            let f: Vec<_> = line.split('\t').collect();
            if f.len() != 3 {
                return Err(Error::new("expected three TSV columns"));
            }
            Ok((
                f[0].to_owned(),
                f[1].parse().map_err(|_| Error::new("invalid category"))?,
                f[2].parse()
                    .map_err(|_| Error::new("invalid expectation"))?,
            ))
        })
        .collect::<Result<Vec<(String, u32, u32)>>>()?;
    if queries.is_empty() {
        return Err("empty fixture".into());
    }
    if args[0] == "fst" {
        measure(
            |name, enabled| {
                index
                    .check(name, enabled)
                    .map_err(|e| Error::new(e.to_string()))
            },
            &args[0],
            &queries,
            0,
            0,
        )?;
    } else {
        let (pool, entries) = records(&index);
        drop(index);
        let hash = HashIndex::new(
            &pool,
            &entries,
            args[0] == "sharded-hash",
            RandomState::new(),
        );
        drop(entries);
        // Capacity omits control bytes, padding and unused allocated buckets:
        // this is a conservative lower bound, not an allocator measurement.
        let lower = hash
            .maps
            .iter()
            .map(|m| m.capacity() * std::mem::size_of::<(&[u8], u32)>())
            .sum();
        measure(
            |name, enabled| hash.check(name, enabled),
            &args[0],
            &queries,
            pool.len(),
            lower,
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use dns_guard::{Action, Rule, Scope, compile};
    use std::hash::{BuildHasherDefault, Hasher};

    #[derive(Default)]
    struct Collision;
    impl Hasher for Collision {
        fn finish(&self) -> u64 {
            0
        }
        fn write(&mut self, _: &[u8]) {}
    }

    #[test]
    fn hash_collisions_never_turn_an_unknown_name_into_a_match() {
        let index = compile(
            &[
                Rule::new("ads.example", Scope::Domain, Action::Block, 1).unwrap(),
                Rule::new("safe.ads.example", Scope::Domain, Action::Allow, 1).unwrap(),
            ],
            Limits::default(),
        )
        .unwrap();
        let (pool, entries) = records(&index);
        for sharded in [false, true] {
            let hash = HashIndex::new(
                &pool,
                &entries,
                sharded,
                BuildHasherDefault::<Collision>::default(),
            );
            assert_eq!(hash.check("ads.example", 1).unwrap().blocked, 1);
            assert_eq!(hash.check("clean.example", 1).unwrap().blocked, 0);
            assert_eq!(hash.check("safe.ads.example", 1).unwrap().allowed, 1);
        }
    }

    #[test]
    fn hashed_and_alphabet_partitioned_indexes_preserve_all_policy_kinds() {
        let mut rules = Vec::new();
        for (n, name) in ["a", "ab", "example.com", "safe.example.com", "x.123"]
            .iter()
            .enumerate()
        {
            for (s, scope) in [Scope::Exact, Scope::Domain, Scope::Subdomains]
                .into_iter()
                .enumerate()
            {
                for (a, action) in [Action::Block, Action::Allow, Action::Enforce]
                    .into_iter()
                    .enumerate()
                {
                    rules.push(Rule::new(name, scope, action, 1 << ((n + s + a) % 7)).unwrap());
                }
            }
        }
        let index = compile(&rules, Limits::default()).unwrap();
        let (pool, entries) = records(&index);
        for sharded in [false, true] {
            let hash = HashIndex::new(&pool, &entries, sharded, RandomState::new());
            for name in [
                "a",
                "ab",
                "x.a",
                "x.ab",
                "example.com",
                "X.SAFE.EXAMPLE.COM.",
                "badexample.com",
                "example.com.evil",
                "x.123",
                "unknown.invalid",
            ] {
                for enabled in 0..=Category::ALL {
                    assert_eq!(
                        hash.check(name, enabled).unwrap(),
                        index.check(name, enabled).unwrap(),
                        "{name}/{enabled}/{sharded}"
                    );
                }
            }
            for invalid in ["", "bad..name", "127.0.0.1"] {
                assert!(hash.check(invalid, 1).is_err());
            }
            assert!(hash.check("example.com", 128).is_err());
        }
    }
}
