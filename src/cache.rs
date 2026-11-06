//! Small four-way response cache. Hashes select a set; complete keys decide hits.
//! Each set has a byte quota, so lookup and eviction examine at most four slots.
use hickory_proto::{
    op::{Message, MessageType, OpCode, ResponseCode},
    rr::RData,
};
use std::{
    collections::hash_map::RandomState,
    hash::BuildHasher,
    mem::size_of,
    time::{Duration, Instant, SystemTime},
};

const WAYS: usize = 4;
const MAX_PACKET: usize = 4096;
const MAX_RECORDS: usize = 128;
pub(crate) const MAX_CACHE_BYTES: usize = 16 * 1024 * 1024;

pub(crate) fn cache_key(request: &Message) -> Option<Box<[u8]>> {
    if request.metadata.message_type != MessageType::Query
        || request.metadata.op_code != OpCode::Query
        || request.queries.len() != 1
        || !request.answers.is_empty()
        || !request.authorities.is_empty()
        || !request.additionals.is_empty()
        || request.signature.is_some()
        || request.edns.as_ref().is_some_and(|e| {
            e.version() != 0 || e.flags().dnssec_ok || !e.options().as_ref().is_empty()
        })
    {
        return None;
    }
    // Preserve question case and every flag/EDNS variant. Only IDs are reusable.
    let mut bytes = request.to_vec().ok()?;
    if bytes.len() > 512 {
        return None;
    }
    bytes[..2].fill(0);
    Some(bytes.into_boxed_slice())
}

struct Entry {
    key: Box<[u8]>,
    wire: Box<[u8]>,
    ttl_offsets: Box<[u16]>,
    expires: Instant,
    expires_wall: SystemTime,
    ttl_cap: u32,
    used: u64,
}
impl Entry {
    fn bytes(&self) -> usize {
        self.key.len() + self.wire.len() + self.ttl_offsets.len() * size_of::<u16>()
    }
}
#[derive(Clone, Copy)]
pub(crate) struct Usage {
    pub entries: usize,
    pub bytes: usize,
    pub evictions: u64,
}
pub(crate) struct Cache {
    slots: Box<[Option<Entry>]>,
    hash: RandomState,
    set_quota: usize,
    bytes: usize,
    entries: usize,
    clock: u64,
    evictions: u64,
}
impl Cache {
    pub(crate) fn new(budget: usize) -> Self {
        let mut cache = Self {
            slots: Box::new([]),
            hash: RandomState::new(),
            set_quota: 0,
            bytes: 0,
            entries: 0,
            clock: 0,
            evictions: 0,
        };
        if budget < 4096 {
            return cache;
        }
        let maximum_sets =
            ((budget - size_of::<Self>()) / (size_of::<Option<Entry>>() * WAYS * 8)).clamp(1, 1024);
        let sets = 1_usize << maximum_sets.ilog2();
        cache.slots = (0..sets * WAYS).map(|_| None).collect();
        cache.bytes = size_of::<Self>() + cache.slots.len() * size_of::<Option<Entry>>();
        cache.set_quota = (budget - cache.bytes) / sets;
        cache
    }
    pub(crate) fn usage(&self) -> Usage {
        Usage {
            entries: self.entries,
            bytes: self.bytes,
            evictions: self.evictions,
        }
    }
    fn start(&self, key: &[u8]) -> usize {
        (self.hash.hash_one(key) as usize & (self.slots.len() / WAYS - 1)) * WAYS
    }
    fn remove(&mut self, slot: usize, evicted: bool) {
        if let Some(entry) = self.slots[slot].take() {
            self.bytes -= entry.bytes();
            self.entries -= 1;
            self.evictions += u64::from(evicted);
        }
    }
    pub(crate) fn get(&mut self, key: &[u8], id: u16, now: Instant) -> Option<Vec<u8>> {
        if self.slots.is_empty() {
            return None;
        }
        let start = self.start(key);
        let wall_now = SystemTime::now();
        for slot in start..start + WAYS {
            if self.slots[slot]
                .as_ref()
                .is_some_and(|e| now >= e.expires || wall_now >= e.expires_wall)
            {
                self.remove(slot, false);
            }
            let Some(entry) = &mut self.slots[slot] else {
                continue;
            };
            if entry.key.as_ref() != key {
                continue;
            }
            self.clock = self.clock.saturating_add(1);
            entry.used = self.clock;
            // Round remaining lifetime down. Hits never renew the original expiry.
            let ttl = entry
                .expires
                .saturating_duration_since(now)
                .as_secs()
                .min(
                    entry
                        .expires_wall
                        .duration_since(wall_now)
                        .unwrap_or_default()
                        .as_secs(),
                )
                .min(u64::from(entry.ttl_cap)) as u32;
            let mut wire = entry.wire.to_vec();
            wire[..2].copy_from_slice(&id.to_be_bytes());
            wire[2] &= !0x04; // A cached reply is not an authoritative answer.
            wire[3] &= !0x20;
            for &offset in &entry.ttl_offsets {
                wire[offset as usize..offset as usize + 4].copy_from_slice(&ttl.to_be_bytes());
            }
            // OPT is transaction metadata, not cached data. Regenerate an empty
            // version-0 OPT for eligible EDNS clients; options/DO bypass caching.
            if key[10..12] == [0, 1] {
                let count = u16::from_be_bytes([wire[10], wire[11]]) + 1;
                wire[10..12].copy_from_slice(&count.to_be_bytes());
                wire.extend_from_slice(&[0, 0, 41, 4, 208, 0, 0, 0, 0, 0, 0]);
            }
            return Some(wire);
        }
        None
    }
    /// Only called after upstream correlation and policy checks, with the exact
    /// decoded message belonging to wire. No untrusted snapshots are imported.
    pub(crate) fn insert(
        &mut self,
        key: Box<[u8]>,
        wire: &[u8],
        response: &Message,
        now: Instant,
    ) -> bool {
        if self.slots.is_empty() || key.len() < 12 || key.len() > 512 {
            return false;
        }
        let Some((end, offsets, ttl)) = plan(wire, response) else {
            return false;
        };
        let Some(expires) = now.checked_add(Duration::from_secs(u64::from(ttl))) else {
            return false;
        };
        let wall_now = SystemTime::now();
        let Some(expires_wall) = wall_now.checked_add(Duration::from_secs(u64::from(ttl))) else {
            return false;
        };
        let cost = key.len() + end + offsets.len() * size_of::<u16>();
        if cost > self.set_quota {
            return false;
        }
        let start = self.start(&key);
        for slot in start..start + WAYS {
            if self.slots[slot]
                .as_ref()
                .is_some_and(|e| now >= e.expires || wall_now >= e.expires_wall || e.key == key)
            {
                self.remove(slot, false);
            }
        }
        loop {
            let used: usize = self.slots[start..start + WAYS]
                .iter()
                .flatten()
                .map(Entry::bytes)
                .sum();
            if used + cost <= self.set_quota
                && self.slots[start..start + WAYS].iter().any(Option::is_none)
            {
                break;
            }
            let oldest = (start..start + WAYS)
                .filter(|&i| self.slots[i].is_some())
                .min_by_key(|&i| self.slots[i].as_ref().unwrap().used)
                .unwrap();
            self.remove(oldest, true);
        }
        let slot = (start..start + WAYS)
            .find(|&i| self.slots[i].is_none())
            .unwrap();
        let mut stored = wire[..end].to_vec();
        if end != wire.len() {
            let count = u16::from_be_bytes([stored[10], stored[11]]) - 1;
            stored[10..12].copy_from_slice(&count.to_be_bytes());
        }
        self.clock = self.clock.saturating_add(1);
        self.slots[slot] = Some(Entry {
            key,
            wire: stored.into_boxed_slice(),
            ttl_offsets: offsets.into_boxed_slice(),
            expires,
            expires_wall,
            ttl_cap: ttl,
            used: self.clock,
        });
        self.entries += 1;
        self.bytes += cost;
        true
    }
}

fn plan(wire: &[u8], response: &Message) -> Option<(usize, Vec<u16>, u32)> {
    if !(12..=MAX_PACKET).contains(&wire.len())
        || response.queries.len() != 1
        || response.metadata.message_type != MessageType::Response
        || response.metadata.truncation
        || response.signature.is_some()
        || response.edns.as_ref().is_some_and(|e| {
            e.version() != 0 || e.flags().dnssec_ok || !e.options().as_ref().is_empty()
        })
    {
        return None;
    }
    let mut ttl = 86400_u32; // A conservative local maximum, never a TTL floor.
    match response.metadata.response_code {
        ResponseCode::NoError if !response.answers.is_empty() => {
            if !response
                .answers
                .iter()
                .any(|r| r.record_type() == response.queries[0].query_type)
            {
                return None;
            }
        }
        ResponseCode::NXDomain | ResponseCode::NoError if response.answers.is_empty() => {
            ttl = response
                .authorities
                .iter()
                .filter_map(|r| match &r.data {
                    RData::SOA(soa) if r.name.zone_of(&response.queries[0].name) => {
                        Some(soa.minimum.min(r.ttl))
                    }
                    _ => None,
                })
                .min()?
                .min(ttl);
        }
        _ => return None,
    }
    if ttl == 0 {
        return None;
    }
    if read16(wire, 4)? != 1 {
        return None;
    }
    let answers = usize::from(read16(wire, 6)?);
    let authorities = usize::from(read16(wire, 8)?);
    let additionals = usize::from(read16(wire, 10)?);
    let count = answers + authorities + additionals;
    if count == 0 || count > MAX_RECORDS {
        return None;
    }
    let mut cursor = skip_name(wire, 12)?.checked_add(4)?;
    if cursor > wire.len() {
        return None;
    }
    let mut offsets = Vec::new();
    let mut end = wire.len();
    for record in 0..count {
        let name = cursor;
        cursor = skip_name(wire, cursor)?;
        let kind = read16(wire, cursor)?;
        let value = u32::from_be_bytes(wire.get(cursor + 4..cursor + 8)?.try_into().ok()?);
        let data_len = usize::from(read16(wire, cursor + 8)?);
        let next = cursor.checked_add(10)?.checked_add(data_len)?;
        if next > wire.len() {
            return None;
        }
        match kind {
            24 | 46 | 249 | 250 => return None, // SIG/RRSIG and transaction signatures.
            41 => {
                // Only a final, empty, root-owned OPT can be removed without
                // moving record data or changing existing compression offsets.
                if record + 1 != count
                    || record < answers + authorities
                    || value != 0
                    || data_len != 0
                    || cursor != name + 1
                    || wire[name] != 0
                {
                    return None;
                }
                end = name;
            }
            _ => {
                if value == 0 || value > i32::MAX as u32 {
                    return None;
                }
                ttl = ttl.min(value);
                offsets.push((cursor + 4) as u16);
            }
        }
        cursor = next;
    }
    if cursor != wire.len() || offsets.is_empty() {
        return None;
    }
    Some((end, offsets, ttl))
}
fn read16(wire: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes(wire.get(at..at + 2)?.try_into().ok()?))
}
fn skip_name(wire: &[u8], mut at: usize) -> Option<usize> {
    loop {
        let byte = *wire.get(at)?;
        match byte {
            0 => return Some(at + 1),
            1..=63 => {
                at = at.checked_add(1 + usize::from(byte))?;
                if at >= wire.len() {
                    return None;
                }
            }
            0xc0..=0xff => {
                let target = ((usize::from(byte) & 0x3f) << 8) | usize::from(*wire.get(at + 1)?);
                return (target >= 12 && target < at).then_some(at + 2);
            }
            _ => return None,
        }
    }
}

#[cfg(test)]
mod tests;
