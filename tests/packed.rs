use dns_guard::{Action, Category, Decision, Index, Limits, Rule, Scope, compile};
use std::collections::BTreeMap;

fn snapshot(magic: &[u8; 8], records: BTreeMap<Vec<u8>, u64>, logical: u64) -> Vec<u8> {
    let mut builder = fst::MapBuilder::memory();
    for (key, value) in &records {
        builder.insert(key, *value).unwrap();
    }
    let payload = builder.into_inner().unwrap();
    let mut bytes = magic.to_vec();
    bytes.extend_from_slice(&(payload.len() as u64).to_le_bytes());
    bytes.extend_from_slice(&logical.to_le_bytes());
    bytes.extend_from_slice(
        &(if magic == b"DNGIDX02" {
            records.len() as u64
        } else {
            0
        })
        .to_le_bytes(),
    );
    bytes.extend_from_slice(&payload);
    bytes
}

fn legacy(rules: &[Rule]) -> Vec<u8> {
    let mut records = BTreeMap::<Vec<u8>, u64>::new();
    for rule in rules {
        let mut key = vec![rule.scope() as u8 * 3 + rule.action() as u8];
        key.extend(rule.domain().bytes().rev());
        *records.entry(key).or_default() |= rule.categories() as u64;
    }
    let count = records.len() as u64;
    snapshot(b"DNGIDX01", records, count)
}

fn oracle(rules: &[Rule], name: &str, enabled: u32) -> Decision {
    let name = name.trim_end_matches('.').to_ascii_lowercase();
    let mut masks = [0; 3];
    for rule in rules {
        let exact = name == rule.domain();
        let child = name.ends_with(&format!(".{}", rule.domain()));
        let hit = match rule.scope() {
            Scope::Exact => exact,
            Scope::Domain => exact || child,
            Scope::Subdomains => child,
        };
        if hit {
            masks[rule.action() as usize] |= rule.categories();
        }
    }
    Decision {
        blocked: ((masks[0] & !masks[1]) | masks[2]) & enabled,
        allowed: masks[1] & enabled,
        enforced: masks[2] & enabled,
    }
}

#[test]
fn packed_snapshot_merges_nine_kinds_into_one_key_without_losing_rule_count() {
    let mut rules = Vec::new();
    for scope in [Scope::Exact, Scope::Domain, Scope::Subdomains] {
        for action in [Action::Block, Action::Allow, Action::Enforce] {
            rules.push(Rule::new("a.example", scope, action, Category::ALL).unwrap());
        }
    }
    let index = compile(&rules, Limits::default()).unwrap();
    assert_eq!(&index.as_bytes()[..8], b"DNGIDX02");
    assert_eq!(index.rule_count(), 9);
    let map = fst::Map::new(&index.as_bytes()[32..]).unwrap();
    assert_eq!(map.len(), 1);
    assert_eq!(map.get(b"elpmaxe.a"), Some((1_u64 << 63) - 1));
}

#[test]
fn legacy_and_packed_agree_with_independent_oracle_for_every_category_mask() {
    let mut rules = Vec::new();
    for (n, name) in [
        "a",
        "ab",
        "x.a",
        "x.ab",
        "a-b",
        "test",
        "deep.test",
        "leaf.deep.test",
    ]
    .iter()
    .enumerate()
    {
        for scope in [Scope::Exact, Scope::Domain, Scope::Subdomains] {
            for action in [Action::Block, Action::Allow, Action::Enforce] {
                // Overlapping and distinct bits, including the highest packed bit.
                let bits = 1 << ((n + scope as usize * 3 + action as usize) % 7);
                rules.push(Rule::new(name, scope, action, bits).unwrap());
            }
        }
    }
    let packed = compile(&rules, Limits::default()).unwrap();
    let legacy = Index::from_bytes(legacy(&rules), 999_999).unwrap();
    assert_eq!(legacy.rule_count(), packed.rule_count());
    for rule in &rules {
        for name in [
            rule.domain().to_uppercase() + ".",
            format!("x.{}", rule.domain()),
            format!("y.x.{}", rule.domain()),
            format!("bad{}", rule.domain()),
            format!("{}.evil", rule.domain()),
        ] {
            for enabled in 0..=Category::ALL {
                let expected = oracle(&rules, &name, enabled);
                assert_eq!(
                    packed.check(&name, enabled).unwrap(),
                    expected,
                    "packed {name} {enabled}"
                );
                assert_eq!(
                    legacy.check(&name, enabled).unwrap(),
                    expected,
                    "legacy {name} {enabled}"
                );
            }
        }
    }
}

#[test]
fn packed_reader_rejects_invalid_outputs_and_logical_counts() {
    for (value, count) in [(0, 1), (1_u64 << 63, 1), (1, 2), (127 | (127 << 7), 1)] {
        let bytes = snapshot(
            b"DNGIDX02",
            BTreeMap::from([(b"tset.a".to_vec(), value)]),
            count,
        );
        assert!(Index::from_bytes(bytes, 999_999).is_err());
    }
}

#[test]
fn single_kind_compilation_preserves_compact_legacy_representation() {
    for scope in [Scope::Exact, Scope::Domain, Scope::Subdomains] {
        for action in [Action::Block, Action::Allow, Action::Enforce] {
            let rules = [
                Rule::new("a.example", scope, action, Category::ALL).unwrap(),
                Rule::new("b.example", scope, action, Category::ADS).unwrap(),
            ];
            let index = compile(&rules, Limits::default()).unwrap();
            assert_eq!(index.as_bytes(), legacy(&rules));
        }
    }
}
