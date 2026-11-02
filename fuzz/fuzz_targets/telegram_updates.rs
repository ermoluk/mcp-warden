//! Telegram `getUpdates` results as the approval bot parses them.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    mcp_warden::fuzz::telegram_updates(data);
});
