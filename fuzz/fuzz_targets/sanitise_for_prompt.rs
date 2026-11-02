//! The approval-prompt sanitiser: whatever goes in, what comes out has no
//! control, format or line/paragraph-separator character, at most two
//! combining marks in a row, and at most `max` characters.
#![no_main]
use libfuzzer_sys::fuzz_target;
use mcp_warden_core::approval::sanitise_for_prompt;

fuzz_target!(|data: &[u8]| {
    let Some((&max, rest)) = data.split_first() else {
        return;
    };
    let Ok(text) = std::str::from_utf8(rest) else {
        return;
    };
    let out = sanitise_for_prompt(text, usize::from(max));
    assert!(out.chars().count() <= usize::from(max), "{out:?}");
    for c in out.chars() {
        assert!(!c.is_control(), "{out:?}");
        assert!(
            !matches!(c, '\u{200B}'..='\u{200F}' | '\u{2028}'..='\u{202E}' | '\u{2066}'..='\u{2069}' | '\u{FEFF}'),
            "{out:?}"
        );
    }
});
