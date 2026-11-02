//! `response_fields` selection: never panics; the result is no larger than
//! the body.
#![no_main]
use libfuzzer_sys::fuzz_target;
use mcp_warden_core::config::Preset;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let Some((fields, body)) = text.split_once('\u{0}') else {
        return;
    };
    let Ok(body) = serde_json::from_str::<serde_json::Value>(body) else {
        return;
    };
    let mut preset: Preset =
        toml::from_str("name = \"p\"\ntype = \"http\"\ndescription = \"x\"\napproval = \"auto\"\n")
            .unwrap();
    preset.response_fields = fields
        .split('\n')
        .filter(|f| mcp_warden_core::config::parse_field_path(f).is_ok())
        .map(str::to_string)
        .collect();
    if let Some(picked) = mcp_warden::fuzz::select_fields(&body, &preset) {
        assert!(picked.to_string().len() <= body.to_string().len().max(2));
    }
});
