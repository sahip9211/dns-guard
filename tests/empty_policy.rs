use dns_guard::{Action, Budget, Category, Index, Limits, Rule, Scope, compile};

#[test]
fn explicit_empty_snapshot_is_small_validated_and_does_not_invent_rules() {
    let index = Index::empty(Limits::default()).unwrap();
    assert_eq!(index.rule_count(), 0);
    assert_eq!(index.as_bytes().len(), 71);
    let loaded = Index::from_bytes(index.as_bytes().to_vec(), 71).unwrap();
    for name in ["ads.example", "adult.example", "anything.test"] {
        assert_eq!(
            loaded.check(name, Category::ALL).unwrap(),
            Default::default()
        );
    }
    assert_eq!(
        loaded
            .check_dns_labels([b"ads".as_slice(), b"example"], Category::ALL)
            .unwrap(),
        Default::default()
    );
    assert!(loaded.check("bad..name", Category::ALL).is_err());
    assert!(loaded.check("a.test", 128).is_err());
    assert!(
        Index::empty(Limits {
            max_index_bytes: 70,
            ..Limits::default()
        })
        .is_err()
    );
    assert!(compile(&[], Limits::default()).is_err());
    let populated = compile(
        &[Rule::new("a.test", Scope::Domain, Action::Block, Category::ADS).unwrap()],
        Limits::default(),
    )
    .unwrap();
    let mut corrupt = populated.as_bytes().to_vec();
    corrupt[16..24].fill(0);
    assert!(Index::from_bytes(corrupt, 10000).is_err());
    for i in 0..index.as_bytes().len() {
        let mut bytes = index.as_bytes().to_vec();
        bytes[i] ^= 1;
        assert!(
            Index::from_bytes(bytes, 10000).is_err(),
            "corruption at byte {i}"
        );
    }
}

#[test]
fn cli_requires_explicit_empty_selection_and_publishes_it_atomically() {
    use std::{fs, process::Command};
    let dir = std::env::temp_dir().join(format!("dns-empty-{}", std::process::id()));
    fs::create_dir(&dir).unwrap();
    let path = dir.join("rules.dngi");
    let index = compile(
        &[Rule::new("ads.example", Scope::Domain, Action::Block, Category::ADS).unwrap()],
        Limits::default(),
    )
    .unwrap();
    index
        .publish(
            &path,
            Budget {
                ceiling_bytes: 10000,
                other_bytes: 0,
            },
        )
        .unwrap();
    let run = |extra: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_dns-guard"))
            .arg("compile")
            .arg(&path)
            .args(["--other-bytes", "0"])
            .args(extra)
            .output()
            .unwrap()
    };
    assert!(!run(&[]).status.success());
    assert!(
        !run(&["--empty", "--feed", "domains", "ads", "missing.txt"])
            .status
            .success()
    );
    assert_eq!(fs::read(&path).unwrap(), index.as_bytes());
    assert!(run(&["--empty"]).status.success());
    let empty = Index::load(&path, 10000).unwrap();
    assert_eq!(empty.rule_count(), 0);
    assert!(
        !empty
            .check("ads.example", Category::ALL)
            .unwrap()
            .is_blocked()
    );
    assert_eq!(fs::read_dir(&dir).unwrap().count(), 1);
    fs::remove_dir_all(dir).unwrap();
}
