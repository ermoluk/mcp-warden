//! The credential scrub: after it, no string or key of the body holds the
//! secret (ignoring ASCII case), whatever the body and the secret.
#![no_main]
use libfuzzer_sys::fuzz_target;
use mcp_warden::executor::credential_echo::{CredentialForms, MARKER};
use mcp_warden_core::config::Auth;
use mcp_warden_core::secret::Secret;

fn texts(v: &serde_json::Value, out: &mut Vec<String>) {
    match v {
        serde_json::Value::String(s) => out.push(s.clone()),
        serde_json::Value::Number(n) => out.push(n.to_string()),
        serde_json::Value::Array(a) => a.iter().for_each(|x| texts(x, out)),
        serde_json::Value::Object(m) => {
            for (k, x) in m {
                out.push(k.clone());
                texts(x, out);
            }
        }
        _ => {}
    }
}

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let Some((secret, body)) = text.split_once('\u{0}') else {
        return;
    };
    let Ok(mut body) = serde_json::from_str::<serde_json::Value>(body) else {
        return;
    };
    let auth = Some(Auth::Basic {
        username: "u".into(),
        secret: "k".into(),
    });
    let forms = CredentialForms::http(&auth, &Secret::new(secret.to_string()));
    forms.scrub(&mut body);
    // A secret that the marker itself contains, or that a marker next to
    // the rest of the text can spell, would make the oracle meaningless.
    let lower = secret.to_ascii_lowercase();
    if secret.len() < 4 || MARKER.to_ascii_lowercase().contains(&lower) {
        return;
    }
    let mut seen = Vec::new();
    texts(&body, &mut seen);
    for t in seen {
        let t = t.to_ascii_lowercase();
        if t.contains(&lower) && !t.contains(&MARKER.to_ascii_lowercase()) {
            panic!("secret {secret:?} survived in {t:?}");
        }
    }
});
