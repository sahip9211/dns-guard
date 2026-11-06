use dns_guard::{Action, Category, Limits, Rule, Scope, compile};

#[test]
fn dns_wire_labels_preserve_boundaries_and_policy_kinds() {
    for mixed in [false, true] {
        let mut rules =
            vec![Rule::new("example", Scope::Domain, Action::Block, Category::ADS).unwrap()];
        if mixed {
            rules.push(
                Rule::new("safe.example", Scope::Domain, Action::Allow, Category::ADS).unwrap(),
            );
        }
        let index = compile(&rules, Limits::default()).unwrap();
        for (labels, blocked) in [
            (vec![b"_service".as_slice(), b"EXAMPLE"], true),
            (vec![b"dot.example".as_slice()], false),
            (vec![b"\xff".as_slice(), b"example"], true),
            (vec![b"example_".as_slice()], false),
            (vec![b"_a".as_slice()], false),
            (vec![], false),
            (vec![b"safe".as_slice(), b"example"], !mixed),
        ] {
            assert_eq!(
                index
                    .check_dns_labels(labels, Category::ALL)
                    .unwrap()
                    .is_blocked(),
                blocked
            );
        }
        assert!(
            index
                .check_dns_labels([b"".as_slice()], Category::ALL)
                .is_err()
        );
        assert!(
            index
                .check_dns_labels([b"example".as_slice()], 128)
                .is_err()
        );
    }
}
