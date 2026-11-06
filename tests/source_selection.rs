use dns_guard::{Action, Category, Limits, Rule, RuleSource, Scope, compile_sources};

fn rule(name: &str, action: Action, category: u32) -> Rule {
    Rule::new(name, Scope::Domain, action, category).unwrap()
}

#[test]
fn disabling_a_source_removes_only_its_rules_and_preserves_shared_domains() {
    let ads = [
        rule("shared.test", Action::Block, Category::ADS),
        rule("ads-only.test", Action::Block, Category::ADS),
    ];
    let adult = [rule("shared.test", Action::Block, Category::ADULT)];
    let enabled = compile_sources(
        &[
            RuleSource {
                enabled: true,
                rules: &ads,
            },
            RuleSource {
                enabled: true,
                rules: &adult,
            },
        ],
        Limits::default(),
    )
    .unwrap();
    let disabled = compile_sources(
        &[
            RuleSource {
                enabled: false,
                rules: &ads,
            },
            RuleSource {
                enabled: true,
                rules: &adult,
            },
        ],
        Limits::default(),
    )
    .unwrap();
    assert_eq!(
        enabled.check("shared.test", Category::ALL).unwrap().blocked,
        Category::ADS | Category::ADULT
    );
    assert_eq!(
        disabled
            .check("shared.test", Category::ALL)
            .unwrap()
            .blocked,
        Category::ADULT
    );
    assert_eq!(
        disabled
            .check("ads-only.test", Category::ALL)
            .unwrap()
            .blocked,
        0
    );
    assert_eq!(disabled.rule_count(), 1);
    assert_eq!(enabled.rule_count(), 2);
    assert!(disabled.as_bytes().len() < enabled.as_bytes().len());
    // Existing readers still see their old snapshot while replacement is built.
    assert!(
        enabled
            .check("ads-only.test", Category::ADS)
            .unwrap()
            .is_blocked()
    );
}

#[test]
fn disabling_allow_source_restores_blocking_and_disabled_rules_do_not_consume_budget() {
    let blocks = [rule("shared.test", Action::Block, Category::ADS)];
    let allows = [
        rule("shared.test", Action::Allow, Category::ADS),
        rule("unrelated.test", Action::Allow, Category::ADS),
    ];
    let enabled = compile_sources(
        &[
            RuleSource {
                enabled: true,
                rules: &blocks,
            },
            RuleSource {
                enabled: true,
                rules: &allows,
            },
        ],
        Limits::default(),
    )
    .unwrap();
    assert_eq!(
        enabled.check("shared.test", Category::ALL).unwrap().blocked,
        0
    );
    let selected = compile_sources(
        &[
            RuleSource {
                enabled: true,
                rules: &blocks,
            },
            RuleSource {
                enabled: false,
                rules: &allows,
            },
        ],
        Limits {
            max_rules: 1,
            ..Limits::default()
        },
    )
    .unwrap();
    assert_eq!(
        selected
            .check("shared.test", Category::ALL)
            .unwrap()
            .blocked,
        Category::ADS
    );
    assert!(
        compile_sources(
            &[
                RuleSource {
                    enabled: true,
                    rules: &blocks
                },
                RuleSource {
                    enabled: true,
                    rules: &allows
                }
            ],
            Limits {
                max_rules: 1,
                ..Limits::default()
            }
        )
        .is_err()
    );
    let empty = compile_sources(
        &[RuleSource {
            enabled: false,
            rules: &blocks,
        }],
        Limits {
            max_rules: 0,
            ..Limits::default()
        },
    )
    .unwrap();
    assert_eq!(empty.rule_count(), 0);
    assert!(
        !empty
            .check("shared.test", Category::ALL)
            .unwrap()
            .is_blocked()
    );
}

#[test]
fn no_sources_is_valid_but_an_unexpected_empty_enabled_source_fails_closed() {
    assert_eq!(
        compile_sources(&[], Limits::default())
            .unwrap()
            .rule_count(),
        0
    );
    assert!(
        compile_sources(
            &[RuleSource {
                enabled: true,
                rules: &[]
            }],
            Limits::default()
        )
        .is_err()
    );
}
