//! A named command filled in from arbitrary values. Whatever renders must
//! pass the shell-syntax check, fit 1024 bytes and keep the template's
//! word count: a value that split into two words would be an injection.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some((&selector, rest)) = data.split_first() else {
        return;
    };
    let Ok(text) = std::str::from_utf8(rest) else {
        return;
    };
    let mut parts = text.splitn(2, '\u{0}');
    let (a, b) = (parts.next().unwrap_or(""), parts.next().unwrap_or(""));
    let (command, params, words) = if selector % 2 == 0 {
        ("word", serde_json::json!({ "v": a, "w": b }), 3)
    } else {
        // The int as a string or a number, the enum as given.
        let n = match a.parse::<i64>() {
            Ok(n) if selector & 2 == 0 => serde_json::json!(n),
            _ => serde_json::json!(a),
        };
        ("num", serde_json::json!({ "n": n, "c": b }), 5)
    };
    if let Some(cmd) = mcp_warden::fuzz::named_command(command, &params) {
        assert!(mcp_warden::fuzz::check_words(&cmd), "{cmd:?}");
        assert!(cmd.len() <= 1024);
        assert_eq!(cmd.split(' ').count(), words, "{cmd:?}");
    }
});
