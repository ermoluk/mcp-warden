//! Scrub a credential the upstream echoed back before the response reaches
//! the agent (invariants 1–2).
//!
//! An upstream that reflects the request — httpbin-style `/headers`, debug
//! endpoints, error payloads that quote the token — would otherwise hand the
//! injected credential straight to the agent. Every key, string and number
//! of the JSON body is searched for each form the credential was sent in,
//! raw or percent-encoded, and each occurrence becomes [`MARKER`].
//!
//! Besides the forms it was sent in, base64, base64url and hex of the bare
//! credential are found, and matching ignores ASCII case. A credential that
//! comes back truncated, split across fields, hashed, inside a larger
//! base64 blob at another alignment or otherwise transformed cannot be
//! detected.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use mcp_warden_core::config::Auth;
use mcp_warden_core::error::WardenError;
use mcp_warden_core::secret::Secret;
use serde_json::Value;
use zeroize::Zeroizing;

/// What an echoed credential is replaced with.
pub const MARKER: &str = "[redacted by mcp-warden]";

/// The forms in which an injected credential can come back. Each is secret
/// material, zeroized on drop like the [`Secret`] it was derived from.
pub struct CredentialForms(Vec<Zeroizing<String>>);

impl CredentialForms {
    /// The bare secret plus every form `http::inject_auth` sends it in:
    /// `<prefix><secret>` for `Auth::Header`, `base64(username:secret)`
    /// (padded or not) for `Auth::Basic`. Bearer's `Bearer ` scheme word is
    /// left visible, as is Basic's. On top of those, forms an upstream may
    /// reflect it in: base64 and base64url of the bare secret (padded or
    /// not) and its hex. Matching ignores ASCII case, so `GHP_…`, upper-case
    /// hex and a re-cased base64 are found too.
    pub fn http(auth: &Option<Auth>, secret: &Secret) -> Self {
        use base64::engine::general_purpose::URL_SAFE;
        let raw = secret.expose();
        if raw.is_empty() {
            return Self(Vec::new());
        }
        let mut forms = vec![Zeroizing::new(raw.to_string())];
        match auth {
            Some(Auth::Header {
                prefix: Some(p), ..
            }) => forms.push(Zeroizing::new(format!("{p}{raw}"))),
            Some(Auth::Basic { username, .. }) => {
                let pair = Zeroizing::new(format!("{username}:{raw}"));
                for engine in [&STANDARD, &URL_SAFE] {
                    let encoded = Zeroizing::new(engine.encode(pair.as_bytes()));
                    forms.push(Zeroizing::new(encoded.trim_end_matches('=').to_string()));
                    forms.push(encoded);
                }
            }
            // `key=secret` as it appears in a URL; `find_encoded` also
            // catches it percent- or form-encoded.
            Some(Auth::Query { name, .. }) => forms.push(Zeroizing::new(format!("{name}={raw}"))),
            // Every other kind is listed, so a new one cannot be missed here.
            // OAuth2's secrets are scrubbed one by one (`executor::auth`).
            Some(
                Auth::Bearer { .. }
                | Auth::Header { prefix: None, .. }
                | Auth::Oauth2 { .. }
                | Auth::AwsSigv4 { .. },
            )
            | None => {}
        }
        for engine in [&STANDARD, &URL_SAFE] {
            let encoded = Zeroizing::new(engine.encode(raw.as_bytes()));
            forms.push(Zeroizing::new(encoded.trim_end_matches('=').to_string()));
            forms.push(encoded);
        }
        let mut hex = Zeroizing::new(String::with_capacity(raw.len() * 2));
        for b in raw.bytes() {
            hex.push(char::from(b"0123456789abcdef"[usize::from(b >> 4)]));
            hex.push(char::from(b"0123456789abcdef"[usize::from(b & 0xf)]));
        }
        forms.push(hex);
        // Matched ignoring ASCII case (see `spans`), so keep them lower-case.
        let mut forms: Vec<Zeroizing<String>> = forms
            .iter()
            .map(|f| Zeroizing::new(f.to_ascii_lowercase()))
            .collect();
        forms.sort_unstable_by(|a, b| a.as_str().cmp(b.as_str()));
        forms.dedup_by(|a, b| a.as_str() == b.as_str());
        Self(forms)
    }

    /// The forms of several credentials together.
    pub fn merge(parts: impl IntoIterator<Item = Self>) -> Self {
        let mut forms: Vec<Zeroizing<String>> = parts.into_iter().flat_map(|p| p.0).collect();
        forms.sort_unstable_by(|a, b| a.as_str().cmp(b.as_str()));
        forms.dedup_by(|a, b| a.as_str() == b.as_str());
        Self(forms)
    }

    /// The forms of a secret that was not sent as an HTTP header — a database
    /// password, an SSH key — for scrubbing rows, output and error text.
    pub fn raw(secret: &Secret) -> Self {
        Self::http(&None, secret)
    }

    /// Replace every occurrence of a form in `text`; return how many.
    pub fn scrub_text(&self, text: &mut String) -> usize {
        if self.0.is_empty() {
            return 0;
        }
        self.scrub_string(text)
    }

    /// `err` with every form of the secret in its message replaced. Error
    /// text can come from the upstream (a driver quoting the server).
    pub fn scrub_error(&self, err: WardenError) -> WardenError {
        let scrub = |mut msg: String| {
            self.scrub_text(&mut msg);
            msg
        };
        match err {
            WardenError::Executor(msg) => WardenError::Executor(scrub(msg)),
            WardenError::Validation(msg) => WardenError::Validation(scrub(msg)),
            other => other,
        }
    }

    /// Replace every occurrence of a form in `body`'s keys, strings and
    /// numbers; return how many were replaced. A body that holds none is
    /// left untouched.
    pub fn scrub(&self, body: &mut Value) -> usize {
        if self.0.is_empty() {
            return 0;
        }
        match body {
            Value::String(s) => self.scrub_string(s),
            Value::Number(n) => {
                let text = n.to_string();
                if self.0.iter().any(|form| text.contains(form.as_str())) {
                    *body = Value::String(MARKER.into());
                    1
                } else {
                    0
                }
            }
            Value::Array(items) => items.iter_mut().map(|v| self.scrub(v)).sum(),
            Value::Object(map) => {
                let mut count = map.values_mut().map(|v| self.scrub(v)).sum();
                if map.keys().any(|k| !self.spans(k).is_empty()) {
                    for (mut key, value) in std::mem::take(map) {
                        count += self.scrub_string(&mut key);
                        // Two keys can redact to the same text; keep both.
                        let mut unique = key.clone();
                        let mut n = 2;
                        while map.contains_key(&unique) {
                            unique = format!("{key} ({n})");
                            n += 1;
                        }
                        map.insert(unique, value);
                    }
                }
                count
            }
            Value::Null | Value::Bool(_) => 0,
        }
    }

    fn scrub_string(&self, s: &mut String) -> usize {
        let spans = self.spans(s);
        if spans.is_empty() {
            return 0;
        }
        let bytes = s.as_bytes();
        let mut out = Vec::with_capacity(bytes.len());
        let mut last = 0;
        for &(start, end) in &spans {
            out.extend_from_slice(&bytes[last..start]);
            out.extend_from_slice(MARKER.as_bytes());
            last = end;
        }
        out.extend_from_slice(&bytes[last..]);
        // Spans start and end on char boundaries (a form is valid UTF-8, so
        // it never starts or ends mid-character); fail closed regardless.
        *s = String::from_utf8(out).unwrap_or_else(|_| MARKER.into());
        spans.len()
    }

    /// Byte ranges of `text` holding a form, sorted, overlaps merged — so the
    /// prefixed and the bare form of one occurrence make a single marker.
    fn spans(&self, text: &str) -> Vec<(usize, usize)> {
        let mut spans = Vec::new();
        // ASCII lower-casing keeps every byte offset, so spans found in
        // `lower` are spans of `text`. It can hold the secret: zeroized.
        let lower = Zeroizing::new(text.to_ascii_lowercase());
        for form in &self.0 {
            spans.extend(
                lower
                    .match_indices(form.as_str())
                    .map(|(i, m)| (i, i + m.len())),
            );
        }
        if text.contains('%') {
            find_encoded(text, &self.0, false, &mut spans);
        }
        if text.contains('+') && self.0.iter().any(|form| form.contains(' ')) {
            find_encoded(text, &self.0, true, &mut spans);
        }
        spans.sort_unstable();
        let mut merged: Vec<(usize, usize)> = Vec::with_capacity(spans.len());
        for (start, end) in spans {
            match merged.last_mut() {
                Some(last) if start < last.1 => last.1 = last.1.max(end),
                _ => merged.push((start, end)),
            }
        }
        merged
    }
}

/// Push the byte ranges of `text` that decode to one of `forms` (which are
/// lower-case) when `%XX` (either hex case) — and `+` when `plus_is_space` —
/// are decoded, ignoring ASCII case. Any mix
/// of encoded and literal bytes matches, so a form reflected through any URL
/// or form encoder is found whichever characters that encoder escapes.
fn find_encoded(
    text: &str,
    forms: &[Zeroizing<String>],
    plus_is_space: bool,
    spans: &mut Vec<(usize, usize)>,
) {
    let src = text.as_bytes();
    // `decoded[i]` came from `src[starts[i]..starts[i + 1]]`. It can hold the
    // credential, so it is zeroized like the forms.
    let mut decoded = Zeroizing::new(Vec::with_capacity(src.len()));
    let mut starts = Vec::with_capacity(src.len() + 1);
    let mut i = 0;
    while i < src.len() {
        starts.push(i);
        let (byte, width) = match (src[i], src.get(i + 1..i + 3)) {
            (b'%', Some(&[hi, lo])) if hi.is_ascii_hexdigit() && lo.is_ascii_hexdigit() => {
                ((hex(hi) << 4) | hex(lo), 3)
            }
            (b'+', _) if plus_is_space => (b' ', 1),
            (b, _) => (b, 1),
        };
        decoded.push(byte.to_ascii_lowercase());
        i += width;
    }
    starts.push(src.len());

    for form in forms {
        let finder = memchr::memmem::Finder::new(form.as_bytes());
        let mut from = 0;
        while let Some(at) = finder.find(&decoded[from..]) {
            let start = from + at;
            let end = start + form.len();
            spans.push((starts[start], starts[end]));
            from = end;
        }
    }
}

fn hex(digit: u8) -> u8 {
    match digit {
        b'0'..=b'9' => digit - b'0',
        b'a'..=b'f' => digit - b'a' + 10,
        _ => digit - b'A' + 10,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn bearer(token: &str) -> CredentialForms {
        let auth = Some(Auth::Bearer { secret: "k".into() });
        CredentialForms::http(&auth, &Secret::new(token.into()))
    }

    #[test]
    fn counts_one_replacement_per_occurrence() {
        let auth = Some(Auth::Header {
            name: "X-Api-Key".into(),
            secret: "k".into(),
            prefix: Some("Token ".into()),
        });
        let forms = CredentialForms::http(&auth, &Secret::new("abc123key".into()));
        let mut body = json!(["Token abc123key", "abc123key and abc123key", "abc123ke"]);
        // The prefixed and the bare form overlap: one occurrence, one marker.
        assert_eq!(forms.scrub(&mut body), 3);
        assert_eq!(
            body,
            json!([MARKER, format!("{MARKER} and {MARKER}"), "abc123ke"])
        );
    }

    #[test]
    fn numeric_echo_is_replaced() {
        let auth = Some(Auth::Basic {
            username: "u".into(),
            secret: "k".into(),
        });
        let forms = CredentialForms::http(&auth, &Secret::new("48151623".into()));
        let mut body = json!({ "pin": 48151623, "other": 4815 });
        assert_eq!(forms.scrub(&mut body), 1);
        assert_eq!(body, json!({ "pin": MARKER, "other": 4815 }));
    }

    #[test]
    fn the_marker_is_never_scanned_again() {
        // `ed` also occurs in the marker; matching runs once over the
        // original text, so the count and the output stay exact.
        let mut body = json!("red ed");
        assert_eq!(bearer("ed").scrub(&mut body), 2);
        assert_eq!(body, json!(format!("r{MARKER} {MARKER}")));
    }

    #[test]
    fn secret_that_looks_percent_encoded_is_matched_as_written() {
        let mut body = json!("x a%41b y");
        assert_eq!(bearer("a%41b").scrub(&mut body), 1);
        assert_eq!(body, json!(format!("x {MARKER} y")));
    }

    #[test]
    fn non_ascii_secret_is_matched_raw_and_percent_encoded() {
        let mut body = json!([
            "ы-пароль-ы",
            "?p=%D0%BF%D0%B0%D1%80%D0%BE%D0%BB%D1%8C&x=ы",
            "%d0%bf%d0%b0%d1%80%d0%be%d0%bb%d1%8c",
        ]);
        assert_eq!(bearer("пароль").scrub(&mut body), 3);
        assert_eq!(
            body,
            json!([format!("ы-{MARKER}-ы"), format!("?p={MARKER}&x=ы"), MARKER])
        );
    }

    #[test]
    fn keys_that_redact_to_the_same_text_keep_both_values() {
        let mut body = json!({ "abc/def": 1, "abc%2Fdef": 2 });
        assert_eq!(bearer("abc/def").scrub(&mut body), 2);
        let map = body.as_object().unwrap();
        assert_eq!(map.len(), 2, "{body}");
        assert!(map.keys().all(|k| k.starts_with(MARKER)), "{body}");
        let mut values: Vec<_> = map.values().map(|v| v.as_i64().unwrap()).collect();
        values.sort_unstable();
        assert_eq!(values, [1, 2]);
    }

    /// Forms an upstream may reflect a token in besides the ones it was sent
    /// in: base64 and base64url of the bare token (padded or not), hex, and
    /// another letter case.
    #[test]
    fn encoded_and_recased_echoes_are_redacted() {
        use base64::engine::general_purpose::{STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
        // `~~~?` encodes to `+`/`/` in standard base64 and `-`/`_` in url-safe.
        let token = "ghp_Tok3n~~~?xyz";
        let hex: String = token.bytes().map(|b| format!("{b:02x}")).collect();
        let reflected = [
            STANDARD.encode(token),
            STANDARD_NO_PAD.encode(token),
            URL_SAFE.encode(token),
            URL_SAFE_NO_PAD.encode(token),
            hex.clone(),
            hex.to_ascii_uppercase(),
            token.to_ascii_uppercase(),
            token.to_ascii_lowercase(),
            format!("{{\"inner\":\"{token}\"}}"),
        ];
        for form in reflected {
            let mut body = json!({ "echo": format!("seen: {form}!") });
            assert_eq!(bearer(token).scrub(&mut body), 1, "{form}");
            let shown = body["echo"].as_str().unwrap().to_string();
            assert!(
                shown.starts_with("seen: ") && shown.contains(MARKER),
                "{shown}"
            );
            assert!(!shown.contains(&form), "{form}: {shown}");
        }
    }

    #[test]
    fn plain_text_is_scrubbed_like_a_json_string() {
        let forms = CredentialForms::raw(&Secret::new("pw-PG-0123".into()));
        let mut text = "FATAL: password \"pw-PG-0123\" (cHctUEctMDEyMw==) rejected".to_string();
        assert_eq!(forms.scrub_text(&mut text), 2);
        assert_eq!(
            text,
            format!("FATAL: password \"{MARKER}\" ({MARKER}) rejected")
        );
    }

    #[test]
    fn empty_secret_redacts_nothing() {
        let mut body = json!({ "a": "b", "": [""] });
        let before = body.clone();
        assert_eq!(bearer("").scrub(&mut body), 0);
        assert_eq!(body, before);
    }
}
