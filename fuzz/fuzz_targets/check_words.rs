//! `ssh_exec`'s shell-syntax check: never panics, and anything it accepts
//! is made only of the permitted characters, single spaces, no leading
//! `=`, `%` or NAME=value.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|command: &str| {
    if mcp_warden::fuzz::check_words(command) {
        for word in command.split(' ') {
            assert!(
                !word.is_empty() && !word.starts_with(['=', '%']),
                "{command:?}"
            );
            assert!(
                word.chars().all(|c| c.is_ascii_alphanumeric()
                    || matches!(c, '-' | '_' | '.' | '/' | ':' | '=' | '@' | ',' | '+' | '%')),
                "{command:?}"
            );
        }
    }
});
