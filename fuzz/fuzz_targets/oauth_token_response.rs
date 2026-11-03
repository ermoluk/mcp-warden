//! An OAuth2 token endpoint's answer. An accepted token must be printable
//! ASCII without spaces — no CR/LF into a header — and at most 16 KiB.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some((&status, body)) = data.split_first() else {
        return;
    };
    let status = if status % 4 == 0 { 400 } else { 200 };
    if let Some((access, refresh)) = mcp_warden::fuzz::oauth_token_answer(status, body) {
        assert_eq!(status, 200);
        for token in std::iter::once(access).chain(refresh) {
            assert!(!token.is_empty() && token.len() <= 16 * 1024);
            assert!(
                token.bytes().all(|b| (0x21..=0x7e).contains(&b)),
                "{token:?}"
            );
        }
    }
});
