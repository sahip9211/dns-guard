use dns_guard::{Action, Budget, Category, Index, Limits, Rule, Scope, compile};
use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "dns-guard-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn index(domain: &str) -> Index {
    compile(
        &[Rule::new(domain, Scope::Domain, Action::Block, Category::ADS).unwrap()],
        Limits::default(),
    )
    .unwrap()
}

#[test]
fn publish_counts_old_and_new_index_and_preserves_old_when_over_budget() {
    let dir = Temp::new();
    let path = dir.0.join("rules.dngi");
    let a = index("old.example");
    let b = index("new.example");
    a.publish(
        &path,
        Budget {
            ceiling_bytes: 10_000_000,
            other_bytes: 1000,
        },
    )
    .unwrap();
    let peak = 1000 + a.as_bytes().len() as u64 + b.as_bytes().len() as u64;
    assert!(
        b.publish(
            &path,
            Budget {
                ceiling_bytes: peak,
                other_bytes: 1000
            }
        )
        .is_err()
    );
    assert_eq!(fs::read(&path).unwrap(), a.as_bytes());
    b.publish(
        &path,
        Budget {
            ceiling_bytes: peak + 1,
            other_bytes: 1000,
        },
    )
    .unwrap();
    let loaded = Index::load(&path, 10_000_000).unwrap();
    assert!(
        loaded
            .check("new.example", Category::ALL)
            .unwrap()
            .is_blocked()
    );
    assert!(
        !loaded
            .check("old.example", Category::ALL)
            .unwrap()
            .is_blocked()
    );
    assert_eq!(fs::read_dir(&dir.0).unwrap().count(), 1);
}

#[test]
fn stale_staging_file_is_preserved_and_budget_overflow_is_rejected() {
    let dir = Temp::new();
    let path = dir.0.join("rules.dngi");
    let stage = dir.0.join("rules.dngi.staging");
    fs::write(&stage, b"interrupted update").unwrap();
    assert!(
        index("a.example")
            .publish(
                &path,
                Budget {
                    ceiling_bytes: 10_000_000,
                    other_bytes: 0
                }
            )
            .is_err()
    );
    assert!(!path.exists());
    assert_eq!(fs::read(&stage).unwrap(), b"interrupted update");
    fs::remove_file(stage).unwrap();
    assert!(
        index("a.example")
            .publish(
                &path,
                Budget {
                    ceiling_bytes: u64::MAX,
                    other_bytes: u64::MAX
                }
            )
            .is_err()
    );
}

#[test]
fn oversized_file_is_rejected_by_loader() {
    let dir = Temp::new();
    let path = dir.0.join("rules.dngi");
    let i = index("a.example");
    fs::write(&path, i.as_bytes()).unwrap();
    assert!(Index::load(&path, i.as_bytes().len() - 1).is_err());
}
