//! Parsing and validating `config.toml`, as `mcp-warden mcp` does at start.
#![no_main]
use libfuzzer_sys::fuzz_target;
use mcp_warden_core::config::Config;
use mcp_warden_core::keychain::KeychainStore;
use mcp_warden_core::keychain::memory::InMemoryKeychain;
use mcp_warden_core::secret::Secret;

fuzz_target!(|text: &str| {
    let Ok(cfg) = toml::from_str::<Config>(text) else {
        return;
    };
    let kc = InMemoryKeychain::new();
    for p in &cfg.preset {
        let _ = kc.set(&p.name, Secret::new("x".into()));
    }
    let _ = cfg.validate(&kc);
    let mut presets = cfg.preset.clone();
    let _ = mcp_warden_core::stamp::demote_unconfirmed_auto(&mut presets, &kc);
});
