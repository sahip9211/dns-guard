use crate::{Category, Decision, Error, Limits, Result, Rule, domain::Domain, validate_categories};
use fst::{Map, MapBuilder, Streamer};
use std::io::{self, Write};

const LEGACY_MAGIC: &[u8; 8] = b"DNGIDX01";
const MAGIC: &[u8; 8] = b"DNGIDX02";
const ACTION_MASK: u64 = (1 << 21) - 1;
const HEADER: usize = 32;

struct Snapshot(Vec<u8>);
impl AsRef<[u8]> for Snapshot {
    fn as_ref(&self) -> &[u8] {
        &self.0[HEADER..]
    }
}

/// Immutable index; share one instance across threads and client policies.
/// Snapshots are local compiler artifacts, not an authenticated interchange format.
pub struct Index {
    map: Map<Snapshot>,
    logical_count: usize,
    packed: bool,
    packed_jumps: Option<Box<[Jump]>>,
    // Cache the nine possible scope/action roots once, not once per query.
    roots: [Option<(usize, u64)>; 9],
    // Dense upper level, compact FST below it. 10,656 bytes per present kind;
    // derived at load time, never serialized or mutated on the query path.
    jumps: [Option<Box<[u64]>>; 9],
}

#[derive(Clone, Copy)]
struct Jump {
    address: usize,
    output: u64,
}

impl Index {
    pub fn from_bytes(bytes: Vec<u8>, max_bytes: usize) -> Result<Self> {
        if bytes.len() > max_bytes || bytes.len() < HEADER + 36 {
            return Err(Error::new("invalid snapshot size"));
        }
        let packed = &bytes[..8] == MAGIC;
        if !packed && (&bytes[..8] != LEGACY_MAGIC || bytes[24..HEADER] != [0; 8]) {
            return Err(Error::new("unknown snapshot format"));
        }
        let length = read_u64(&bytes[8..16]);
        let count = read_u64(&bytes[16..24]);
        let key_count = if packed {
            read_u64(&bytes[24..32])
        } else {
            count
        };
        if length != (bytes.len() - HEADER) as u64 || count == 0 {
            return Err(Error::new("invalid snapshot header"));
        }
        let data = &bytes[HEADER..];
        // Pin the checksum-bearing FST format and validate its footer before its
        // constructor. This also avoids overflow in third-party root checks.
        let root = read_u64(&data[data.len() - 12..data.len() - 4]);
        if read_u64(&data[..8]) != 3
            || read_u64(&data[8..16]) != 0
            || root.checked_add(21) != Some(data.len() as u64)
            || read_u64(&data[data.len() - 20..data.len() - 12]) != key_count
        {
            return Err(Error::new("invalid FST header or footer"));
        }
        let map = Map::new(Snapshot(bytes))?;
        map.as_fst().verify()?;
        let mut stream = map.stream();
        let mut seen = 0_u64;
        while let Some((key, categories)) = stream.next() {
            let name = if packed {
                if categories == 0 || categories >> 63 != 0 {
                    return Err(Error::new("invalid packed policy output"));
                }
                key
            } else {
                if key.len() < 2
                    || key[0] > 8
                    || categories == 0
                    || categories & !(Category::ALL as u64) != 0
                {
                    return Err(Error::new("invalid policy record"));
                }
                &key[1..]
            };
            if name.is_empty() || name.len() > 253 {
                return Err(Error::new("invalid policy name length"));
            }
            let mut domain = [0; 253];
            for (out, byte) in domain.iter_mut().zip(name.iter().rev()) {
                *out = *byte;
            }
            let text = std::str::from_utf8(&domain[..name.len()])
                .map_err(|_| Error::new("non-ASCII policy record"))?;
            if Domain::parse(text)?.as_str() != text {
                return Err(Error::new("non-canonical policy record"));
            }
            seen += if packed { policy_count(categories) } else { 1 };
        }
        if seen != count {
            return Err(Error::new("snapshot rule count mismatch"));
        }
        let root = map.as_fst().root();
        let roots = std::array::from_fn(|tag| {
            if packed {
                return None;
            }
            root.find_input(tag as u8).map(|i| {
                let transition = root.transition(i);
                (transition.addr, transition.out.value())
            })
        });
        let jumps = std::array::from_fn(|tag| roots[tag].and_then(|root| build_jumps(&map, root)));
        let packed_jumps = packed.then(|| build_packed_jumps(&map));
        let logical_count =
            usize::try_from(count).map_err(|_| Error::new("rule count overflow"))?;
        Ok(Self {
            map,
            logical_count,
            packed,
            packed_jumps,
            roots,
            jumps,
        })
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.map.as_fst().as_inner().0
    }
    pub fn rule_count(&self) -> usize {
        self.logical_count
    }

    pub fn format_version(&self) -> u8 {
        if self.packed { 2 } else { 1 }
    }

    /// No heap allocation, database lookup, lock or probabilistic decision.
    /// Broad allows apply to their category across all ordinary matching blocks;
    /// enforced blocks win. More-specific ordinary blocks do not beat an allow.
    pub fn check(&self, domain: &str, enabled: u32) -> Result<Decision> {
        validate_categories(enabled)?;
        let domain = Domain::parse(domain)?;
        self.check_canonical(domain.as_bytes(), enabled)
    }

    /// Match raw DNS labels without treating embedded dots or arbitrary label
    /// bytes as hostname separators. Non-hostname labels cannot match a rule,
    /// but valid ancestor rules still apply (for example to SRV names).
    pub fn check_dns_labels<'a>(
        &self,
        labels: impl IntoIterator<Item = &'a [u8]>,
        enabled: u32,
    ) -> Result<Decision> {
        validate_categories(enabled)?;
        let mut bytes = [0_u8; 253];
        let mut len = 0;
        for label in labels {
            let separator = usize::from(len != 0);
            if label.is_empty() || label.len() > 63 || len + separator + label.len() > bytes.len() {
                return Err(Error::new("invalid DNS label length"));
            }
            if separator != 0 {
                bytes[len] = b'.';
                len += 1;
            }
            for &byte in label {
                bytes[len] = if byte.is_ascii_alphanumeric() || byte == b'-' {
                    byte.to_ascii_lowercase()
                } else {
                    b'!'
                };
                len += 1;
            }
        }
        // No compiled hostname ends in a non-alphanumeric byte, or has a
        // non-hostname byte immediately before its final character. This also
        // keeps the dense two-byte jump table inside its hostname alphabet.
        if len == 0
            || !bytes[len - 1].is_ascii_alphanumeric()
            || (len >= 2 && bytes[len - 2] == b'!')
        {
            return Ok(Decision::default());
        }
        self.check_canonical(&bytes[..len], enabled)
    }

    fn check_canonical(&self, domain: &[u8], enabled: u32) -> Result<Decision> {
        if enabled == 0 {
            return Ok(Decision::default());
        }
        if self.packed {
            return Ok(self.check_packed(domain, enabled));
        }
        let mut matches = [0_u32; 3];
        let fst = self.map.as_fst();
        // Walk the reversed name once per present rule kind, emitting matches
        // at label boundaries. Repeated Map::get calls would re-read common
        // suffixes for every ancestor: up to O(labels * name length). This is
        // O(present rule kinds * name length), with at most nine kinds.
        for (tag, root) in self.roots.iter().enumerate() {
            let Some((address, initial_output)) = *root else {
                continue;
            };
            let cached = self.jumps[tag]
                .as_ref()
                .filter(|_| domain.len() >= 2 && domain[domain.len() - 2] != b'.');
            let (address, mut output, skipped) = if let Some(table) = cached {
                let jump = table[prefix_slot(domain[domain.len() - 1], domain[domain.len() - 2])];
                if jump == 0 {
                    continue;
                }
                (((jump as u32) - 1) as usize, jump >> 32, 2)
            } else {
                (address, initial_output, 0)
            };
            let mut node = fst.node(address);
            // A two-character rule can terminate at the jump destination.
            // A one-character rule followed by '.' uses the scalar fallback.
            if skipped == 2
                && node.is_final()
                && (domain.len() == 2 || domain[domain.len() - 3] == b'.')
                && match tag / 3 {
                    0 => domain.len() == 2,
                    1 => true,
                    _ => domain.len() != 2,
                }
            {
                matches[tag % 3] |= (output + node.final_output().value()) as u32;
            }
            for (offset, &byte) in domain[..domain.len() - skipped].iter().rev().enumerate() {
                let position = offset + skipped;
                let Some(i) = node.find_input(byte) else {
                    break;
                };
                let transition = node.transition(i);
                output += transition.out.value();
                node = fst.node(transition.addr);
                let full_name = position + 1 == domain.len();
                let eligible = match tag / 3 {
                    0 => full_name,
                    1 => true,
                    _ => !full_name,
                };
                if eligible
                    && node.is_final()
                    && (full_name || domain[domain.len() - position - 2] == b'.')
                {
                    matches[tag % 3] |= (output + node.final_output().value()) as u32;
                }
            }
        }
        Ok(Decision {
            blocked: ((matches[0] & !matches[1]) | matches[2]) & enabled,
            allowed: matches[1] & enabled,
            enforced: matches[2] & enabled,
        })
    }

    fn check_packed(&self, domain: &[u8], enabled: u32) -> Decision {
        let fst = self.map.as_fst();
        let mut node = fst.root();
        let mut output = 0;
        let mut skipped = 0;
        let mut matches = 0_u64;
        if domain.len() >= 2 && domain[domain.len() - 2] != b'.' {
            let jump = self.packed_jumps.as_ref().expect("packed prefix table")
                [prefix_slot(domain[domain.len() - 1], domain[domain.len() - 2])];
            if jump.address == usize::MAX {
                return Decision::default();
            }
            node = fst.node(jump.address);
            output = jump.output;
            skipped = 2;
            if node.is_final() && (domain.len() == 2 || domain[domain.len() - 3] == b'.') {
                matches |=
                    eligible_actions(output + node.final_output().value(), domain.len() == 2);
            }
        }
        for (offset, &byte) in domain[..domain.len() - skipped].iter().rev().enumerate() {
            let Some(i) = node.find_input(byte) else {
                break;
            };
            let transition = node.transition(i);
            output += transition.out.value();
            node = fst.node(transition.addr);
            let position = offset + skipped + 1;
            let full_name = position == domain.len();
            if node.is_final() && (full_name || domain[domain.len() - position - 1] == b'.') {
                matches |= eligible_actions(output + node.final_output().value(), full_name);
            }
        }
        let blocks = matches as u32 & Category::ALL;
        let allows = (matches >> 7) as u32 & Category::ALL;
        let enforced = (matches >> 14) as u32 & Category::ALL;
        Decision {
            blocked: ((blocks & !allows) | enforced) & enabled,
            allowed: allows & enabled,
            enforced: enforced & enabled,
        }
    }
}

// Domain rules occupy the lowest 21 bits so ordinary feed values stay small.
// Exact rules occupy the next 21 bits, subdomain-only rules the highest 21.
fn eligible_actions(value: u64, full_name: bool) -> u64 {
    (value | (value >> if full_name { 21 } else { 42 })) & ACTION_MASK
}

fn policy_count(value: u64) -> u64 {
    (0..9).filter(|n| (value >> (n * 7)) & 127 != 0).count() as u64
}

fn build_packed_jumps(map: &Map<Snapshot>) -> Box<[Jump]> {
    let fst = map.as_fst();
    let root = fst.root();
    let mut table = vec![
        Jump {
            address: usize::MAX,
            output: 0
        };
        36 * 37
    ]
    .into_boxed_slice();
    for &first in b"0123456789abcdefghijklmnopqrstuvwxyz" {
        let Some(i) = root.find_input(first) else {
            continue;
        };
        let one = root.transition(i);
        let node = fst.node(one.addr);
        for &second in b"0123456789abcdefghijklmnopqrstuvwxyz-" {
            let Some(j) = node.find_input(second) else {
                continue;
            };
            let two = node.transition(j);
            table[prefix_slot(first, second)] = Jump {
                address: two.addr,
                output: one.out.value() + two.out.value(),
            };
        }
    }
    table
}

fn prefix_slot(first: u8, second: u8) -> usize {
    fn symbol(byte: u8) -> usize {
        match byte {
            b'0'..=b'9' => (byte - b'0') as usize,
            b'a'..=b'z' => (byte - b'a') as usize + 10,
            b'-' => 36,
            _ => unreachable!("canonical hostname prefix"),
        }
    }
    symbol(first) * 37 + symbol(second)
}

fn build_jumps(map: &Map<Snapshot>, (address, initial): (usize, u64)) -> Option<Box<[u64]>> {
    // Packed 32-bit addresses reduce the cache footprint. Larger indexes use
    // the existing exact traversal instead of truncating an address.
    if map.as_fst().as_inner().0.len() >= u32::MAX as usize {
        return None;
    }
    let fst = map.as_fst();
    let root = fst.node(address);
    let mut table = vec![0; 36 * 37].into_boxed_slice();
    for &first in b"0123456789abcdefghijklmnopqrstuvwxyz" {
        let Some(i) = root.find_input(first) else {
            continue;
        };
        let one = root.transition(i);
        let node = fst.node(one.addr);
        for &second in b"0123456789abcdefghijklmnopqrstuvwxyz-" {
            let Some(j) = node.find_input(second) else {
                continue;
            };
            let two = node.transition(j);
            let output = initial + one.out.value() + two.out.value();
            let output = u32::try_from(output).ok()?;
            table[prefix_slot(first, second)] = ((output as u64) << 32) | (two.addr as u64 + 1);
        }
    }
    Some(table)
}

pub fn compile(rules: &[Rule], limits: Limits) -> Result<Index> {
    compile_iter(rules.iter(), rules.len(), limits)
}

/// Build only selected sources, preserving all enabled contributions to shared
/// hostnames. Does not mutate an active index or retain disabled-source payloads.
/// An empty selection is rejected, like `compile(&[], ...)`.
pub fn compile_sources(sources: &[crate::RuleSource<'_>], limits: Limits) -> Result<Index> {
    let count = sources
        .iter()
        .filter(|source| source.enabled)
        .try_fold(0_usize, |n, source| {
            n.checked_add(source.rules.len())
                .ok_or_else(|| Error::new("rule count overflow"))
        })?;
    let rules = sources
        .iter()
        .filter(|source| source.enabled)
        .flat_map(|source| source.rules.iter());
    compile_iter(rules, count, limits)
}

fn compile_iter<'a>(
    rules: impl Iterator<Item = &'a Rule> + Clone,
    count: usize,
    limits: Limits,
) -> Result<Index> {
    if count == 0 || count > limits.max_rules {
        return Err(Error::new("empty rule set or rule count limit exceeded"));
    }
    if limits.max_index_bytes < HEADER + 36 {
        return Err(Error::new("index byte limit too small"));
    }
    // Keep the smaller existing cache/format when there is only one kind.
    // Packing wins when it removes repeated walks; see the paired benchmarks.
    let kinds = rules.clone().fold(0_u16, |mask, rule| {
        mask | (1 << (rule.scope as u8 * 3 + rule.action as u8))
    });
    let packed = kinds.count_ones() > 1;
    let mut entries: Vec<_> = rules
        .map(|rule| {
            let mut key = Vec::with_capacity(rule.domain.len() + usize::from(!packed));
            if !packed {
                key.push(rule.scope as u8 * 3 + rule.action as u8);
            }
            key.extend(rule.domain.bytes().rev());
            if !packed {
                return (key, rule.categories as u64);
            }
            let group = match rule.scope {
                crate::Scope::Domain => 0,
                crate::Scope::Exact => 1,
                crate::Scope::Subdomains => 2,
            };
            (
                key,
                (rule.categories as u64) << ((group * 3 + rule.action as usize) * 7),
            )
        })
        .collect();
    entries.sort_unstable_by(|a, b| a.0.cmp(&b.0));
    let writer = LimitedWriter {
        bytes: vec![0; HEADER],
        limit: limits.max_index_bytes,
    };
    let mut builder = MapBuilder::new(writer)?;
    let mut count = 0_u64;
    let mut key_count = 0_u64;
    let mut i = 0;
    while i < entries.len() {
        let (key, mut categories) = (&entries[i].0, entries[i].1);
        i += 1;
        while i < entries.len() && entries[i].0 == *key {
            categories |= entries[i].1;
            i += 1;
        }
        builder.insert(key, categories)?;
        count += if packed { policy_count(categories) } else { 1 };
        key_count += 1;
    }
    let mut bytes = builder.into_inner()?.bytes;
    let payload_length = (bytes.len() - HEADER) as u64;
    bytes[..8].copy_from_slice(if packed { MAGIC } else { LEGACY_MAGIC });
    bytes[8..16].copy_from_slice(&payload_length.to_le_bytes());
    bytes[16..24].copy_from_slice(&count.to_le_bytes());
    if packed {
        bytes[24..32].copy_from_slice(&key_count.to_le_bytes());
    }
    Index::from_bytes(bytes, limits.max_index_bytes)
}

fn read_u64(bytes: &[u8]) -> u64 {
    u64::from_le_bytes(bytes[..8].try_into().expect("checked field size"))
}

struct LimitedWriter {
    bytes: Vec<u8>,
    limit: usize,
}
impl Write for LimitedWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.limit.saturating_sub(self.bytes.len()) {
            return Err(io::Error::other("compiled index exceeds byte limit"));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Action, Scope};

    #[test]
    fn prefix_jumps_equal_two_exact_fst_transitions() {
        let rules = &[
            "a", "ab", "x.a", "x.ab", "a-b", "foo.com", "foo.net", "x.123",
        ]
        .map(|s| Rule::new(s, Scope::Domain, Action::Block, Category::ALL).unwrap());
        let mut entries: Vec<_> = rules
            .iter()
            .map(|r| {
                let mut key = vec![3];
                key.extend(r.domain.bytes().rev());
                (key, r.categories as u64)
            })
            .collect();
        entries.sort();
        let mut builder = MapBuilder::memory();
        for (key, value) in entries {
            builder.insert(key, value).unwrap();
        }
        let payload = builder.into_inner().unwrap();
        let mut bytes = LEGACY_MAGIC.to_vec();
        bytes.extend_from_slice(&(payload.len() as u64).to_le_bytes());
        bytes.extend_from_slice(&(rules.len() as u64).to_le_bytes());
        bytes.extend_from_slice(&0_u64.to_le_bytes());
        bytes.extend_from_slice(&payload);
        let index = Index::from_bytes(bytes, Limits::default().max_index_bytes).unwrap();
        let table = index.jumps[3].as_ref().unwrap();
        assert_eq!(table.len(), 36 * 37);
        assert_eq!(std::mem::size_of_val(table.as_ref()), 10_656);
        let fst = index.map.as_fst();
        let (addr, initial) = index.roots[3].unwrap();
        for first in b"0123456789abcdefghijklmnopqrstuvwxyz" {
            for second in b"0123456789abcdefghijklmnopqrstuvwxyz-" {
                let mut node = fst.node(addr);
                let mut out = initial;
                let mut expected = 0;
                for (n, byte) in [first, second].into_iter().enumerate() {
                    let Some(i) = node.find_input(*byte) else {
                        break;
                    };
                    let t = node.transition(i);
                    out += t.out.value();
                    node = fst.node(t.addr);
                    if n == 1 {
                        expected = (out << 32) | (t.addr as u64 + 1);
                    }
                }
                assert_eq!(table[prefix_slot(*first, *second)], expected);
            }
        }
    }
}
