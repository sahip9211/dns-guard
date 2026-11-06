use super::{Cache, cache_key};
use hickory_proto::{
    op::{Edns, Message, MessageType, OpCode, Query, ResponseCode},
    rr::{
        Name, RData, Record, RecordType,
        rdata::{A, SOA},
    },
};
use std::time::{Duration, Instant};

fn query(name: &str) -> Message {
    let mut query = Message::new(17, MessageType::Query, OpCode::Query);
    query.metadata.recursion_desired = true;
    query.add_query(Query::query(Name::from_ascii(name).unwrap(), RecordType::A));
    query
}
fn answer(query: &Message, ttl: u32) -> Message {
    let mut answer = Message::response(query.metadata.id, OpCode::Query);
    answer.queries = query.queries.clone();
    answer.metadata.recursion_available = true;
    answer.metadata.recursion_desired = true;
    answer.metadata.authentic_data = true;
    answer.add_answer(Record::from_rdata(
        query.queries[0].name.clone(),
        ttl,
        RData::A(A::new(192, 0, 2, 7)),
    ));
    answer
}
fn negative(query: &Message, code: ResponseCode) -> Message {
    let mut response = answer(query, 30);
    response.answers.clear();
    response.metadata.response_code = code;
    response.add_authority(Record::from_rdata(
        Name::from_ascii("example.").unwrap(),
        30,
        RData::SOA(SOA::new(
            Name::from_ascii("ns.example.").unwrap(),
            Name::from_ascii("hostmaster.example.").unwrap(),
            1,
            60,
            60,
            3600,
            10,
        )),
    ));
    response
}

#[test]
fn ages_all_sections_without_extending_lifetimes_or_replaying_ids() {
    let mut cache = Cache::new(4096);
    let request = query("cache.example.");
    let mut response = answer(&request, 30);
    response.metadata.authoritative = true;
    response.add_additional(Record::from_rdata(
        Name::from_ascii("other.example.").unwrap(),
        10,
        RData::A(A::new(192, 0, 2, 8)),
    ));
    let now = Instant::now();
    let key = cache_key(&request).unwrap();
    assert!(cache.insert(key.clone(), &response.to_vec().unwrap(), &response, now));
    let hit = cache
        .get(&key, 99, now + Duration::from_millis(1100))
        .unwrap();
    let hit = Message::from_vec(&hit).unwrap();
    assert_eq!(hit.metadata.id, 99);
    assert!(!hit.metadata.authentic_data);
    assert!(!hit.metadata.authoritative);
    assert_eq!(hit.answers[0].ttl, 8);
    assert_eq!(hit.additionals[0].ttl, 8);
    assert_eq!(hit.answers[0].data, response.answers[0].data);
    assert!(cache.get(&key, 1, now + Duration::from_secs(10)).is_none());
    assert_eq!(cache.usage().entries, 0);
}

#[test]
fn negative_answers_obey_soa_minimum_and_do_not_cache_referrals_or_errors() {
    let now = Instant::now();
    let request = query("missing.example.");
    let key = cache_key(&request).unwrap();
    for code in [ResponseCode::NXDomain, ResponseCode::NoError] {
        let mut cache = Cache::new(4096);
        let response = negative(&request, code);
        assert!(cache.insert(key.clone(), &response.to_vec().unwrap(), &response, now));
        let hit =
            Message::from_vec(&cache.get(&key, 19, now + Duration::from_secs(3)).unwrap()).unwrap();
        assert_eq!(hit.metadata.response_code, code);
        assert_eq!(hit.authorities[0].ttl, 7);
        assert!(cache.get(&key, 1, now + Duration::from_secs(10)).is_none());
    }
    for code in [
        ResponseCode::ServFail,
        ResponseCode::Refused,
        ResponseCode::NXDomain,
        ResponseCode::NoError,
    ] {
        let mut response = answer(&request, 30);
        response.metadata.response_code = code;
        response.answers.clear();
        assert!(!Cache::new(4096).insert(key.clone(), &response.to_vec().unwrap(), &response, now));
    }
    let mut outside = negative(&request, ResponseCode::NXDomain);
    outside.authorities[0].name = Name::from_ascii("unrelated.test.").unwrap();
    assert!(!Cache::new(4096).insert(key, &outside.to_vec().unwrap(), &outside, now));
}

#[test]
fn keys_isolate_flags_record_types_case_and_edns_context() {
    let request = query("cache.example.");
    let original = cache_key(&request).unwrap();
    let mut variant = request.clone();
    variant.metadata.id = 99;
    assert_eq!(cache_key(&variant).unwrap(), original);
    variant = request.clone();
    variant.metadata.checking_disabled = true;
    assert_ne!(cache_key(&variant).unwrap(), original);
    variant = request.clone();
    variant.queries[0].query_type = RecordType::AAAA;
    assert_ne!(cache_key(&variant).unwrap(), original);
    assert_ne!(cache_key(&query("CACHE.example.")).unwrap(), original);
    variant = request.clone();
    variant.set_edns(Edns::new());
    assert_ne!(cache_key(&variant).unwrap(), original);
    variant.edns.as_mut().unwrap().set_dnssec_ok(true);
    assert!(cache_key(&variant).is_none());
    variant
        .edns
        .as_mut()
        .unwrap()
        .set_dnssec_ok(false)
        .set_version(1);
    assert!(cache_key(&variant).is_none());
    // A raw OPT with an unknown option is valid DNS, but not reusable cache context.
    let mut bytes = request.to_vec().unwrap();
    bytes[11] = 1;
    bytes.extend([0, 0, 41, 4, 208, 0, 0, 0, 0, 0, 4, 0xfd, 0xe9, 0, 0]);
    assert!(cache_key(&Message::from_vec(&bytes).unwrap()).is_none());
}

#[test]
fn four_way_collisions_preserve_exact_keys_and_evict_least_recently_used() {
    let mut cache = Cache::new(4096);
    let now = Instant::now();
    let mut keys = Vec::new();
    for n in 0..4 {
        let request = query(&format!("n{n}.example."));
        let response = answer(&request, 30);
        let key = cache_key(&request).unwrap();
        assert!(cache.insert(key.clone(), &response.to_vec().unwrap(), &response, now));
        keys.push(key);
    }
    assert_eq!(cache.usage().entries, 4);
    assert!(cache.get(&keys[0], 1, now).is_some());
    let request = query("new.example.");
    let response = answer(&request, 30);
    assert!(cache.insert(
        cache_key(&request).unwrap(),
        &response.to_vec().unwrap(),
        &response,
        now
    ));
    assert!(cache.get(&keys[1], 1, now).is_none());
    assert!(cache.get(&keys[0], 1, now).is_some());
    assert!(
        cache
            .get(&cache_key(&query("unknown.example.")).unwrap(), 1, now)
            .is_none()
    );
    assert_eq!(cache.usage().evictions, 1);
    assert!(cache.usage().bytes <= 4096);
}

#[test]
fn disabled_oversized_zero_ttl_truncated_and_malformed_packets_are_not_cached() {
    let request = query("cache.example.");
    let key = cache_key(&request).unwrap();
    let now = Instant::now();
    let response = answer(&request, 30);
    let wire = response.to_vec().unwrap();
    let mut disabled = Cache::new(0);
    assert!(!disabled.insert(key.clone(), &wire, &response, now));
    assert_eq!(disabled.usage().bytes, 0);
    for ttl in [0, 0x80000000, u32::MAX] {
        let response = answer(&request, ttl);
        assert!(!Cache::new(4096).insert(key.clone(), &response.to_vec().unwrap(), &response, now));
    }
    let mut truncated = response.clone();
    truncated.metadata.truncation = true;
    assert!(!Cache::new(4096).insert(key.clone(), &truncated.to_vec().unwrap(), &truncated, now));
    for end in 0..wire.len() {
        assert!(!Cache::new(4096).insert(key.clone(), &wire[..end], &response, now));
    }
    let mut trailing = wire.clone();
    trailing.push(0);
    assert!(!Cache::new(4096).insert(key.clone(), &trailing, &response, now));
    let mut large = response.clone();
    large
        .answers
        .extend(std::iter::repeat_n(response.answers[0].clone(), 300));
    let mut cache = Cache::new(4096);
    assert!(!cache.insert(key, &large.to_vec().unwrap(), &large, now));
    assert_eq!(cache.usage().entries, 0);
    assert!(cache.usage().bytes <= 4096);
}

#[test]
fn regenerates_empty_opt_and_preserves_record_bytes_except_ttls_and_header() {
    let mut request = query("cache.example.");
    request.set_edns(Edns::new().set_max_payload(4096).clone());
    let mut response = answer(&request, 30);
    response.set_edns(Edns::new().set_max_payload(4096).clone());
    let key = cache_key(&request).unwrap();
    let mut cache = Cache::new(4096);
    let now = Instant::now();
    assert!(cache.insert(key.clone(), &response.to_vec().unwrap(), &response, now));
    let hit =
        Message::from_vec(&cache.get(&key, 77, now + Duration::from_secs(2)).unwrap()).unwrap();
    assert_eq!(hit.answers[0].ttl, 28);
    assert_eq!(hit.edns.unwrap().max_payload(), 1232);
    assert_eq!(hit.answers[0].data, response.answers[0].data);
}

#[test]
fn sustained_admission_never_exceeds_the_byte_budget() {
    let mut cache = Cache::new(16384);
    let now = Instant::now();
    for n in 0..2000 {
        let request = query(&format!("host{n}.example."));
        let response = answer(&request, 30);
        let key = cache_key(&request).unwrap();
        cache.insert(key.clone(), &response.to_vec().unwrap(), &response, now);
        assert!(cache.usage().bytes <= 16384);
        if let Some(bytes) = cache.get(&key, n as u16, now) {
            assert_eq!(Message::from_vec(&bytes).unwrap().queries, request.queries);
        }
    }
}

#[test]
fn wall_clock_expiry_also_invalidates_a_cache_after_suspend() {
    let request = query("sleep.example.");
    let response = answer(&request, 30);
    let key = cache_key(&request).unwrap();
    let mut cache = Cache::new(4096);
    let now = Instant::now();
    assert!(cache.insert(key.clone(), &response.to_vec().unwrap(), &response, now));
    // Simulate wall time having passed the expiry while monotonic time stood still.
    for entry in cache.slots.iter_mut().flatten() {
        entry.expires_wall = std::time::SystemTime::UNIX_EPOCH;
    }
    assert!(cache.get(&key, 1, now).is_none());
}
