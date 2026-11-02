//! The known_hosts parser `ssh_exec` relies on (russh's), on arbitrary
//! file content: never panics, and a file that does not contain the
//! host's key never verifies it.
#![no_main]
use libfuzzer_sys::fuzz_target;
use russh::keys::ssh_key::PublicKey;
use std::sync::LazyLock;

static KEY: LazyLock<PublicKey> = LazyLock::new(|| {
    PublicKey::from_openssh(
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl",
    )
    .unwrap()
});

fuzz_target!(|text: &str| {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("known_hosts");
    std::fs::write(&path, text).unwrap();
    let verified = russh::keys::check_known_hosts_path("example.com", 22, &KEY, &path);
    if matches!(verified, Ok(true)) {
        assert!(
            text.contains("AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"),
            "verified a key the file does not contain: {text:?}"
        );
    }
});
