use std::process::Command;

#[test]
fn key_sources_are_explicit_exclusive_and_validated_before_storage_access() {
    for args in [
        vec!["config", "show", "absent.sqlite", "--keyring", "../bad"],
        vec!["config", "show", "absent.sqlite", "--keyring"],
        vec![
            "config",
            "show",
            "absent.sqlite",
            "--keyring",
            "abc",
            "--key-file",
            "absent.key",
        ],
        vec![
            "config",
            "show",
            "absent.sqlite",
            "--keyring",
            "abc",
            "--keyring",
            "abc",
        ],
        vec!["config", "keygen", "--keyring", "do-not-overwrite-this-id"],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_dns-guard"))
            .args(&args)
            .output()
            .unwrap();
        assert!(!output.status.success(), "{args:?}");
        assert!(output.stdout.is_empty());
    }
}

#[cfg(all(feature = "os-keyring", target_os = "linux"))]
#[test]
fn missing_secret_service_has_no_file_or_plaintext_fallback() {
    let output = Command::new(env!("CARGO_BIN_EXE_dns-guard"))
        .args(["config", "keygen", "--keyring"])
        .env(
            "DBUS_SESSION_BUS_ADDRESS",
            "unix:path=/nonexistent-dns-guard-test-bus",
        )
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("credential store"));
}
