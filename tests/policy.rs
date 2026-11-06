use dns_guard::{Action, Category, Index, Limits, Rule, Scope, compile};

fn rule(domain: &str, scope: Scope, action: Action, categories: u32) -> Rule {
    Rule::new(domain, scope, action, categories).unwrap()
}

#[test]
fn exact_suffix_and_subdomains_only_obey_label_boundaries() {
    let index = compile(
        &[
            rule("Ads.Example.", Scope::Domain, Action::Block, Category::ADS),
            rule("only.example", Scope::Exact, Action::Block, Category::ADULT),
            rule(
                "children.example",
                Scope::Subdomains,
                Action::Block,
                Category::TRACKING,
            ),
        ],
        Limits::default(),
    )
    .unwrap();
    for domain in ["ads.example", "A.ADS.EXAMPLE."] {
        assert_eq!(
            index.check(domain, Category::ALL).unwrap().blocked,
            Category::ADS
        );
    }
    for domain in [
        "badads.example",
        "ads.example.evil",
        "sub.only.example",
        "children.example",
        "example",
    ] {
        assert!(
            !index.check(domain, Category::ALL).unwrap().is_blocked(),
            "{domain}"
        );
    }
    assert!(
        index
            .check("only.example", Category::ALL)
            .unwrap()
            .is_blocked()
    );
    assert!(
        index
            .check("a.children.example", Category::ALL)
            .unwrap()
            .is_blocked()
    );
}

#[test]
fn category_scoped_allows_do_not_disable_other_categories_or_enforced_rules() {
    let index = compile(
        &[
            rule(
                "example",
                Scope::Domain,
                Action::Block,
                Category::ADS | Category::ADULT,
            ),
            rule("safe.example", Scope::Domain, Action::Allow, Category::ADS),
            rule(
                "locked.safe.example",
                Scope::Domain,
                Action::Enforce,
                Category::ADS,
            ),
        ],
        Limits::default(),
    )
    .unwrap();
    let safe = index.check("safe.example", Category::ALL).unwrap();
    assert_eq!(safe.blocked, Category::ADULT);
    assert_eq!(safe.allowed, Category::ADS);
    assert!(
        !index
            .check("safe.example", Category::ADS)
            .unwrap()
            .is_blocked()
    );
    assert_eq!(
        index
            .check("locked.safe.example", Category::ADS)
            .unwrap()
            .enforced,
        Category::ADS
    );
    assert!(
        index
            .check("locked.safe.example", Category::ADS)
            .unwrap()
            .is_blocked()
    );
    assert!(!index.check("locked.safe.example", 0).unwrap().is_blocked());
}

#[test]
fn duplicate_rules_merge_categories_and_snapshot_is_deterministic() {
    let mut rules = vec![
        rule("example.com", Scope::Domain, Action::Block, Category::ADS),
        rule(
            "EXAMPLE.COM.",
            Scope::Domain,
            Action::Block,
            Category::ADULT,
        ),
        rule("other.com", Scope::Exact, Action::Allow, Category::ADS),
    ];
    let a = compile(&rules, Limits::default()).unwrap();
    rules.reverse();
    let b = compile(&rules, Limits::default()).unwrap();
    assert_eq!(a.as_bytes(), b.as_bytes());
    assert_eq!(a.rule_count(), 2);
    assert_eq!(
        a.check("example.com", Category::ALL).unwrap().blocked,
        Category::ADS | Category::ADULT
    );
    let loaded = Index::from_bytes(a.as_bytes().to_vec(), a.as_bytes().len()).unwrap();
    assert_eq!(
        loaded.check("example.com", Category::ALL).unwrap(),
        a.check("example.com", Category::ALL).unwrap()
    );
}

#[test]
fn invalid_domains_and_categories_are_rejected() {
    for domain in [
        "",
        ".",
        "a..com",
        "a.com..",
        "https://a.com",
        "a.com/x",
        "a com",
        "*.com",
        "-a.com",
        "a-.com",
        "a_b.com",
        "127.0.0.1",
        "::1",
        "café.com",
    ] {
        assert!(
            Rule::new(domain, Scope::Domain, Action::Block, Category::ADS).is_err(),
            "{domain}"
        );
    }
    assert!(
        Rule::new(
            &format!("{}.com", "a".repeat(64)),
            Scope::Domain,
            Action::Block,
            Category::ADS
        )
        .is_err()
    );
    assert!(Rule::new("a.com", Scope::Domain, Action::Block, 0).is_err());
    assert!(Rule::new("a.com", Scope::Domain, Action::Block, 1 << 31).is_err());
    assert!(
        Rule::new(
            "xn--caf-dma.com",
            Scope::Domain,
            Action::Block,
            Category::ADS
        )
        .is_ok()
    );
    let index = compile(
        &[rule("a.com", Scope::Domain, Action::Block, Category::ADS)],
        Limits::default(),
    )
    .unwrap();
    assert!(index.check("invalid..name", Category::ALL).is_err());
    assert!(index.check("a.com", 1 << 31).is_err());
}

#[test]
fn snapshot_rejects_every_single_byte_mutation_and_truncation() {
    let index = compile(
        &[rule(
            "example.com",
            Scope::Domain,
            Action::Block,
            Category::ADS,
        )],
        Limits::default(),
    )
    .unwrap();
    let bytes = index.as_bytes();
    for i in 0..bytes.len() {
        assert!(
            Index::from_bytes(bytes[..i].to_vec(), bytes.len()).is_err(),
            "truncated at {i}"
        );
        let mut corrupt = bytes.to_vec();
        corrupt[i] ^= 1;
        assert!(
            Index::from_bytes(corrupt, bytes.len()).is_err(),
            "changed byte {i}"
        );
    }
    let mut trailing = bytes.to_vec();
    trailing.push(0);
    assert!(Index::from_bytes(trailing, bytes.len() + 1).is_err());
    assert!(Index::from_bytes(bytes.to_vec(), bytes.len() - 1).is_err());
}

#[test]
fn compiler_enforces_input_and_output_limits() {
    let rules = [rule(
        "example.com",
        Scope::Domain,
        Action::Block,
        Category::ADS,
    )];
    assert!(compile(&[], Limits::default()).is_err());
    assert!(
        compile(
            &rules,
            Limits {
                max_rules: 0,
                ..Limits::default()
            }
        )
        .is_err()
    );
    assert!(
        compile(
            &rules,
            Limits {
                max_index_bytes: 16,
                ..Limits::default()
            }
        )
        .is_err()
    );
}

#[test]
fn shared_index_serves_thousands_of_independent_clients() {
    let rules: Vec<_> = (0..2048)
        .map(|n| {
            rule(
                &format!("d{n}.example"),
                Scope::Domain,
                Action::Block,
                if n % 2 == 0 {
                    Category::ADS
                } else {
                    Category::ADULT
                },
            )
        })
        .collect();
    let index = compile(&rules, Limits::default()).unwrap();
    std::thread::scope(|scope| {
        for worker in 0..8 {
            let index = &index;
            scope.spawn(move || {
                for client in 0..2048 {
                    let domain = format!("client{worker}.d{client}.example");
                    assert_eq!(
                        index.check(&domain, Category::ADS).unwrap().is_blocked(),
                        client % 2 == 0
                    );
                    assert!(
                        !index
                            .check(&format!("d{client}.example.evil"), Category::ALL)
                            .unwrap()
                            .is_blocked()
                    );
                }
            });
        }
    });
}

#[test]
fn every_matching_ancestor_contributes_even_with_shared_fst_outputs() {
    let rules = [
        rule("test", Scope::Domain, Action::Block, Category::ADS),
        rule(
            "example.test",
            Scope::Subdomains,
            Action::Block,
            Category::ADULT,
        ),
        rule(
            "deep.example.test",
            Scope::Exact,
            Action::Block,
            Category::TRACKING,
        ),
        rule("example.test", Scope::Domain, Action::Allow, Category::ADS),
        rule(
            "deep.example.test",
            Scope::Subdomains,
            Action::Enforce,
            Category::MALWARE,
        ),
        rule(
            "other.test",
            Scope::Exact,
            Action::Enforce,
            Category::PHISHING,
        ),
    ];
    let index = compile(&rules, Limits::default()).unwrap();
    assert_eq!(
        index.check("example.test", Category::ALL).unwrap().blocked,
        0
    );
    assert_eq!(
        index
            .check("deep.example.test", Category::ALL)
            .unwrap()
            .blocked,
        Category::ADULT | Category::TRACKING
    );
    assert_eq!(
        index
            .check("child.deep.example.test", Category::ALL)
            .unwrap()
            .blocked,
        Category::ADULT | Category::MALWARE
    );
    assert_eq!(
        index.check("other.test", Category::ALL).unwrap().blocked,
        Category::ADS | Category::PHISHING
    );
    assert_eq!(
        index
            .check("badexample.test", Category::ALL)
            .unwrap()
            .blocked,
        Category::ADS
    );
}

#[test]
fn normalization_preserves_max_length_names_and_numeric_hostname_semantics() {
    let longest = format!(
        "{}.{}.{}.{}",
        "a".repeat(63),
        "b".repeat(63),
        "c".repeat(63),
        "d".repeat(61)
    );
    assert_eq!(longest.len(), 253);
    let index = compile(
        &[
            rule(&longest, Scope::Exact, Action::Block, Category::ADS),
            rule("123.456", Scope::Domain, Action::Block, Category::ADULT),
            rule(
                "1-2.3example",
                Scope::Domain,
                Action::Block,
                Category::TRACKING,
            ),
        ],
        Limits::default(),
    )
    .unwrap();
    assert_eq!(
        index
            .check(&(longest.to_uppercase() + "."), Category::ALL)
            .unwrap()
            .blocked,
        Category::ADS
    );
    assert_eq!(
        index.check("123.456", Category::ALL).unwrap().blocked,
        Category::ADULT
    );
    assert_eq!(
        index.check("1-2.3EXAMPLE", Category::ALL).unwrap().blocked,
        Category::TRACKING
    );
    for invalid in [
        longest.clone() + "d",
        "a.-b.test".into(),
        "a.b-.test".into(),
        "a.\0.test".into(),
        "a.é.test".into(),
        "1.2.3.4".into(),
        "a..".into(),
    ] {
        assert!(index.check(&invalid, Category::ALL).is_err(), "{invalid:?}");
    }
}
