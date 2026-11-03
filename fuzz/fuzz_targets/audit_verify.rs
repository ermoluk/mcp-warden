//! `audit verify` over arbitrary chain rows: a corrupt or hostile database
//! is reported, never a panic.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let rows: Vec<(i64, i64, String, String)> = text
        .split('\n')
        .take(64)
        .enumerate()
        .map(|(i, line)| {
            let mut f = line.splitn(3, '\t');
            let seq = f
                .next()
                .and_then(|s| s.parse().ok())
                .unwrap_or(i as i64 + 1);
            let record = f.next().unwrap_or("").to_string();
            let hash = f.next().unwrap_or("").to_string();
            (seq, i as i64, record, hash)
        })
        .collect();
    mcp_warden::fuzz::audit_verify(&rows);
});
