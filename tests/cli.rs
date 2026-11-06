use std::{fs, process::Command};

#[test]
fn cli_compiles_queries_and_inspects_an_index() {
    let dir = std::env::temp_dir().join(format!("dns-guard-cli-{}", std::process::id()));
    fs::create_dir(&dir).unwrap();
    let input = dir.join("feed.txt");
    let output = dir.join("rules.dngi");
    fs::write(&input, "||ads.example^\n@@||safe.ads.example^\n").unwrap();
    let binary = env!("CARGO_BIN_EXE_dns-guard");
    let result = Command::new(binary)
        .args([
            "compile",
            output.to_str().unwrap(),
            "--other-bytes",
            "1000000",
            "--feed",
            "adblock",
            "ads",
            input.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(output.exists());
    let result = Command::new(binary)
        .args([
            "check",
            output.to_str().unwrap(),
            "ads",
            "x.ads.example",
            "safe.ads.example",
            "clean.example",
        ])
        .output()
        .unwrap();
    assert!(result.status.success());
    let stdout = String::from_utf8(result.stdout).unwrap();
    assert!(stdout.contains("BLOCK x.ads.example"), "{stdout}");
    assert!(stdout.contains("ALLOW safe.ads.example"), "{stdout}");
    assert!(stdout.contains("ALLOW clean.example"), "{stdout}");
    let result = Command::new(binary)
        .args(["inspect", output.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(result.status.success());
    assert!(String::from_utf8_lossy(&result.stdout).contains("rules=2"));
    let before = fs::read(&output).unwrap();
    fs::write(&input, "||ads.example^$third-party").unwrap();
    let result = Command::new(binary)
        .args([
            "compile",
            output.to_str().unwrap(),
            "--other-bytes",
            "1000000",
            "--feed",
            "adblock",
            "ads",
            input.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert_eq!(fs::read(&output).unwrap(), before);
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn cli_requires_explicit_budget_and_rejects_invalid_arguments() {
    let binary = env!("CARGO_BIN_EXE_dns-guard");
    for args in [
        vec!["compile", "out.dngi"],
        vec!["unknown"],
        vec!["check"],
        vec!["inspect"],
    ] {
        let result = Command::new(binary).args(args).output().unwrap();
        assert_eq!(result.status.code(), Some(2));
        assert!(!result.stderr.is_empty());
    }
}

#[test]
fn inspect_reports_the_actual_snapshot_version() {
    use dns_guard::{Action, Category, Limits, Rule, Scope, compile};
    let path = std::env::temp_dir().join(format!("dns-guard-inspect-{}.dngi", std::process::id()));
    let index = compile(
        &[
            Rule::new("ads.example", Scope::Domain, Action::Block, Category::ADS).unwrap(),
            Rule::new(
                "safe.ads.example",
                Scope::Domain,
                Action::Allow,
                Category::ADS,
            )
            .unwrap(),
        ],
        Limits::default(),
    )
    .unwrap();
    fs::write(&path, index.as_bytes()).unwrap();
    let result = Command::new(env!("CARGO_BIN_EXE_dns-guard"))
        .args(["inspect", path.to_str().unwrap()])
        .output()
        .unwrap();
    fs::remove_file(path).unwrap();
    assert!(result.status.success());
    assert!(String::from_utf8_lossy(&result.stdout).contains("format=2"));
}

#[test]
fn serve_requires_explicit_upstream_and_rejects_duplicate_options() {
    let binary = env!("CARGO_BIN_EXE_dns-guard");
    for args in [
        vec!["serve", "missing.dngi"],
        vec![
            "serve",
            "missing.dngi",
            "--upstream",
            "127.0.0.1:53",
            "--upstream",
            "127.0.0.1:54",
        ],
        vec![
            "serve",
            "missing.dngi",
            "--upstream",
            "127.0.0.1:53",
            "--max-inflight",
            "0",
        ],
    ] {
        assert_eq!(
            Command::new(binary)
                .args(args)
                .output()
                .unwrap()
                .status
                .code(),
            Some(2)
        );
    }
    let result = Command::new(binary).arg("--help").output().unwrap();
    assert!(String::from_utf8_lossy(&result.stdout).contains("dns-guard serve"));
}
