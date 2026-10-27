//! What of an upstream response `proxy_http` hands the agent: at most
//! `max_response_bytes` of body, and only the preset's `response_fields`.

use mcp_warden_core::config::{FieldStep, Preset, parse_field_path};
use serde_json::{Map, Value};

/// The body, parsed as JSON (`null` if it isn't JSON), and a note for the
/// agent when mcp-warden withheld or trimmed it.
pub(crate) async fn read_body(resp: reqwest::Response, preset: &Preset) -> (Value, Option<String>) {
    match read_limited(resp, preset.max_response_bytes).await {
        Some(bytes) => (serde_json::from_slice(&bytes).unwrap_or(Value::Null), None),
        None => (
            Value::Null,
            Some(format!(
                "the response body is larger than this preset's max_response_bytes ({} bytes) \
                 and was not returned",
                preset.max_response_bytes.unwrap_or_default()
            )),
        ),
    }
}

/// Read the body, but no more than `max` bytes. `None`: it was larger. A
/// read error counts as an empty (non-JSON) body, as before limits existed.
async fn read_limited(mut resp: reqwest::Response, max: Option<u64>) -> Option<Vec<u8>> {
    let Some(max) = max else {
        return Some(resp.bytes().await.map(|b| b.to_vec()).unwrap_or_default());
    };
    if resp.content_length().is_some_and(|n| n > max) {
        return None;
    }
    let mut buf = Vec::new();
    while let Ok(Some(chunk)) = resp.chunk().await {
        if (buf.len() + chunk.len()) as u64 > max {
            return None;
        }
        buf.extend_from_slice(&chunk);
    }
    Some(buf)
}

/// Keep only the preset's `response_fields` (validated at startup). `None`
/// when the preset returns the whole body.
pub(crate) fn select_fields(body: &Value, preset: &Preset) -> Option<Value> {
    if preset.response_fields.is_empty() {
        return None;
    }
    let paths: Vec<Vec<FieldStep>> = preset
        .response_fields
        .iter()
        .filter_map(|f| parse_field_path(f).ok())
        .collect();
    let refs: Vec<&[FieldStep]> = paths.iter().map(Vec::as_slice).collect();
    Some(select(body, &refs).unwrap_or_else(|| match body {
        Value::Array(_) => Value::Array(Vec::new()),
        Value::Object(_) => Value::Object(Map::new()),
        _ => Value::Null,
    }))
}

/// The parts of `v` the paths reach, keeping the body's shape and key
/// order. A path that ends here takes the whole value.
fn select(v: &Value, paths: &[&[FieldStep]]) -> Option<Value> {
    if paths.iter().any(|p| p.is_empty()) {
        return Some(v.clone());
    }
    match v {
        Value::Object(map) => {
            let mut out = Map::new();
            for (key, child) in map {
                let rest: Vec<&[FieldStep]> = paths
                    .iter()
                    .filter_map(|p| match p.split_first() {
                        Some((FieldStep::Key(k), rest)) if k == key => Some(rest),
                        _ => None,
                    })
                    .collect();
                if let Some(picked) = (!rest.is_empty()).then(|| select(child, &rest)).flatten() {
                    out.insert(key.clone(), picked);
                }
            }
            (!out.is_empty()).then_some(Value::Object(out))
        }
        Value::Array(items) => {
            let rest: Vec<&[FieldStep]> = paths
                .iter()
                .filter_map(|p| match p.split_first() {
                    Some((FieldStep::Each, rest)) => Some(rest),
                    _ => None,
                })
                .collect();
            (!rest.is_empty())
                .then(|| Value::Array(items.iter().filter_map(|i| select(i, &rest)).collect()))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn preset(fields: &[&str]) -> Preset {
        let mut p: Preset = toml::from_str(
            r#"
            name = "p"
            type = "http"
            description = "x"
            approval = "auto"
            "#,
        )
        .unwrap();
        p.response_fields = fields.iter().map(|f| f.to_string()).collect();
        p
    }

    #[test]
    fn keeps_only_listed_fields_in_the_bodys_shape() {
        let body = json!({
            "id": 7,
            "name": "repo",
            "owner": { "login": "o", "email": "o@example.com" },
            "items": [ { "title": "a", "secret": 1 }, { "title": "b" }, { "other": 2 } ],
            "tags": ["x", "y"]
        });
        let got = select_fields(
            &body,
            &preset(&["id", "owner.login", "items[].title", "tags[]"]),
        );
        assert_eq!(
            got.unwrap(),
            json!({
                "id": 7,
                "owner": { "login": "o" },
                "items": [ { "title": "a" }, { "title": "b" } ],
                "tags": ["x", "y"]
            })
        );
    }

    #[test]
    fn top_level_arrays_and_whole_subtrees() {
        let body = json!([ { "name": "a", "x": 1 }, { "name": "b" } ]);
        assert_eq!(
            select_fields(&body, &preset(&["[].name"])).unwrap(),
            json!([ { "name": "a" }, { "name": "b" } ])
        );
        let body = json!({ "owner": { "login": "o", "id": 1 }, "x": 2 });
        assert_eq!(
            select_fields(&body, &preset(&["owner"])).unwrap(),
            json!({ "owner": { "login": "o", "id": 1 } })
        );
    }

    #[test]
    fn nothing_matched_gives_an_empty_body_of_the_same_kind() {
        assert_eq!(
            select_fields(&json!({ "a": 1 }), &preset(&["b"])).unwrap(),
            json!({})
        );
        assert_eq!(
            select_fields(&json!([1, 2]), &preset(&["a"])).unwrap(),
            json!([])
        );
        assert_eq!(
            select_fields(&json!("text"), &preset(&["a"])).unwrap(),
            Value::Null
        );
    }

    #[test]
    fn no_fields_means_the_whole_body() {
        assert_eq!(select_fields(&json!({ "a": 1 }), &preset(&[])), None);
    }
}
