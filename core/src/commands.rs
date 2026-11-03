//! Named SSH commands: a preset's fixed templates, filled with typed
//! parameter values (`ssh_run`).
//!
//! The agent never composes the command line. It names a command and
//! supplies values; each value becomes exactly one word of the command (or,
//! for `int` and `enum`, part of one), checked by type before anything else
//! happens. Templates are checked once at startup, so a config the server
//! accepted can only ever produce commands that pass the shell-syntax check
//! and fit the length limit (invariants 5 and 10).

use crate::config::{ParamSpec, Preset, anchored_regex};
use crate::error::{Result, WardenError};
use crate::limits::{MAX_SSH_COMMAND_BYTES, MAX_SSH_OUTPUT_BYTES, MAX_SSH_RUN_PARAM_BYTES};
use crate::ssh_words::check_words;
use std::collections::{BTreeMap, BTreeSet};

/// The MCP tools mcp-warden always serves. A generated tool may not take
/// one of these names.
pub const STATIC_TOOL_NAMES: [&str; 7] = [
    "db_query",
    "get_secret_for_env",
    "list_presets",
    "proxy_http",
    "sftp_transfer",
    "ssh_exec",
    "ssh_run",
];

/// The most tools `expose_as_tools` may add across the whole config.
pub const MAX_GENERATED_TOOLS: usize = 32;

/// The longest command description, in characters.
const MAX_DESCRIPTION_CHARS: usize = 512;

/// One word of a template.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TemplateWord {
    /// Fixed text.
    Literal(String),
    /// A parameter, with fixed text around it (`--lines={n}`); the text is
    /// empty for a whole-word placeholder.
    Param {
        prefix: String,
        name: String,
        suffix: String,
    },
}

/// Split a template into words. Words are separated by single spaces; a
/// word holds at most one `{name}` placeholder, and braces mean nothing
/// else.
pub fn parse_template(template: &str) -> Result<Vec<TemplateWord>> {
    let bad = |why: &str| WardenError::Validation(format!("template: {why}"));
    let mut words = Vec::new();
    for word in template.split(' ') {
        if word.is_empty() {
            return Err(bad("words must be separated by single spaces"));
        }
        let Some(open) = word.find('{') else {
            if word.contains('}') {
                return Err(bad("'}' without '{'"));
            }
            words.push(TemplateWord::Literal(word.to_string()));
            continue;
        };
        let close = word[open..]
            .find('}')
            .map(|i| open + i)
            .ok_or_else(|| bad("'{' without '}'"))?;
        let (prefix, name, suffix) = (&word[..open], &word[open + 1..close], &word[close + 1..]);
        if prefix.contains('}') || suffix.contains(['{', '}']) {
            return Err(bad("at most one {placeholder} per word"));
        }
        if !is_identifier(name) {
            return Err(bad(&format!(
                "placeholder '{{{name}}}': names are [a-z][a-z0-9_]{{0,31}}"
            )));
        }
        words.push(TemplateWord::Param {
            prefix: prefix.to_string(),
            name: name.to_string(),
            suffix: suffix.to_string(),
        });
    }
    Ok(words)
}

/// `[a-z][a-z0-9_]{0,31}`: command and parameter names.
pub fn is_identifier(name: &str) -> bool {
    let mut chars = name.chars();
    name.len() <= 32
        && chars.next().is_some_and(|c| c.is_ascii_lowercase())
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

/// The tool a command becomes with `expose_as_tools`.
pub fn tool_name(preset: &str, command: &str) -> String {
    format!("ssh_{preset}_{command}")
}

/// Check one preset's commands; every error names the preset and the
/// command. Runs at startup, before the server serves anything.
pub fn validate_preset(p: &Preset) -> Result<()> {
    let refuse = |what: String| WardenError::Validation(format!("preset '{}': {what}", p.name));
    if let Some(max) = p.max_output_bytes {
        check_output_limit(max).map_err(refuse)?;
    }
    if p.expose_as_tools && p.commands.is_empty() {
        return Err(refuse(
            "expose_as_tools = true needs at least one [[preset.commands]] entry".into(),
        ));
    }
    let mut names = BTreeSet::new();
    for c in &p.commands {
        let refuse = |what: String| refuse(format!("command '{}': {what}", c.name));
        if !is_identifier(&c.name) {
            return Err(refuse("names are [a-z][a-z0-9_]{0,31}".into()));
        }
        if !names.insert(c.name.as_str()) {
            return Err(refuse("more than one command with this name".into()));
        }
        if c.description.trim().is_empty()
            || c.description.chars().count() > MAX_DESCRIPTION_CHARS
            || c.description.chars().any(char::is_control)
        {
            return Err(refuse(format!(
                "description must be 1–{MAX_DESCRIPTION_CHARS} characters without control \
                 characters"
            )));
        }
        if let Some(max) = c.max_output_bytes {
            check_output_limit(max).map_err(refuse)?;
        }
        for (name, spec) in &c.params {
            if !is_identifier(name) {
                return Err(refuse(format!(
                    "parameter '{name}': names are [a-z][a-z0-9_]{{0,31}}"
                )));
            }
            check_spec(spec).map_err(|e| refuse(format!("parameter '{name}': {e}")))?;
        }
        check_template(&c.template, &c.params).map_err(|e| refuse(error_text(e)))?;
    }
    Ok(())
}

/// Tool names generated across the config: valid MCP names, unique, none
/// taken by a static tool, at most [`MAX_GENERATED_TOOLS`].
pub fn validate_tool_names(presets: &[Preset]) -> Result<()> {
    let mut seen = BTreeSet::new();
    for p in presets.iter().filter(|p| p.expose_as_tools) {
        for c in &p.commands {
            let tool = tool_name(&p.name, &c.name);
            let refuse = |why: &str| {
                WardenError::Validation(format!(
                    "preset '{}': command '{}': tool name '{tool}' {why}",
                    p.name, c.name
                ))
            };
            if tool.len() > 64
                || !tool
                    .chars()
                    .all(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == '-')
            {
                return Err(refuse(
                    "is not a valid MCP tool name (^[a-zA-Z0-9_-]{1,64}$): shorten the preset \
                     name or set expose_as_tools = false",
                ));
            }
            if STATIC_TOOL_NAMES.contains(&tool.as_str()) || !seen.insert(tool.clone()) {
                return Err(refuse("is taken by another tool"));
            }
        }
    }
    if seen.len() > MAX_GENERATED_TOOLS {
        return Err(WardenError::Validation(format!(
            "expose_as_tools would add {} tools; at most {MAX_GENERATED_TOOLS} — use ssh_run \
             for the rest",
            seen.len()
        )));
    }
    Ok(())
}

fn check_output_limit(max: u64) -> std::result::Result<(), String> {
    if max == 0 || max > MAX_SSH_OUTPUT_BYTES as u64 {
        return Err(format!(
            "max_output_bytes must be 1..={MAX_SSH_OUTPUT_BYTES}, got {max}"
        ));
    }
    Ok(())
}

fn check_spec(spec: &ParamSpec) -> std::result::Result<(), String> {
    match spec {
        ParamSpec::String { pattern } | ParamSpec::Path { pattern } => anchored_regex(pattern)
            .map(|_| ())
            .map_err(|e| format!("bad pattern '{pattern}': {e}")),
        ParamSpec::Int { min, max } => {
            if min > max {
                return Err(format!("min {min} is greater than max {max}"));
            }
            Ok(())
        }
        ParamSpec::Enum { values } => {
            if values.is_empty() {
                return Err("enum needs at least one value".into());
            }
            let mut seen = BTreeSet::new();
            for v in values {
                if v.contains(' ') || check_words(v).is_err() {
                    return Err(format!(
                        "enum value '{v}' must be one word of letters, digits and - _ . / : = @ \
                         , + % (no leading '=' or '%')"
                    ));
                }
                if !seen.insert(v) {
                    return Err(format!("enum value '{v}' is listed twice"));
                }
            }
            Ok(())
        }
    }
}

/// The template's words are valid, every placeholder is a declared
/// parameter and every parameter is used exactly once; with every possible
/// kind of value filled in, the command passes the shell-syntax check and
/// its longest expansion fits the length limit.
fn check_template(template: &str, params: &BTreeMap<String, ParamSpec>) -> Result<()> {
    let words = parse_template(template)?;
    let bad = |why: String| WardenError::Validation(format!("template: {why}"));
    let mut used = BTreeSet::new();
    for (i, word) in words.iter().enumerate() {
        let TemplateWord::Param {
            prefix,
            name,
            suffix,
        } = word
        else {
            continue;
        };
        let spec = params
            .get(name)
            .ok_or_else(|| bad(format!("{{{name}}} is not a declared parameter")))?;
        if !used.insert(name.as_str()) {
            return Err(bad(format!("{{{name}}} is used more than once")));
        }
        let whole = prefix.is_empty() && suffix.is_empty();
        match spec {
            ParamSpec::String { .. } | ParamSpec::Path { .. } if !whole => {
                return Err(bad(format!(
                    "{{{name}}} must be a whole word: only int and enum parameters can be part \
                     of one"
                )));
            }
            ParamSpec::Enum { .. } => {}
            _ if i == 0 => {
                return Err(bad(format!(
                    "{{{name}}} picks the program: only an enum parameter may be the first word"
                )));
            }
            _ => {}
        }
    }
    if let Some(unused) = params.keys().find(|k| !used.contains(k.as_str())) {
        return Err(bad(format!(
            "parameter '{unused}' is declared but not used"
        )));
    }
    // Every enum value and the bounds of every int, filled in one parameter
    // at a time; string and path values are checked word by word at call
    // time, so a plain word stands in for them here.
    let fill = |which: Option<(&str, &str)>| -> String {
        words
            .iter()
            .map(|w| match w {
                TemplateWord::Literal(s) => s.clone(),
                TemplateWord::Param {
                    prefix,
                    name,
                    suffix,
                } => {
                    let value = match which {
                        Some((n, v)) if n == name => v.to_string(),
                        _ => sample(&params[name]),
                    };
                    format!("{prefix}{value}{suffix}")
                }
            })
            .collect::<Vec<_>>()
            .join(" ")
    };
    let mut variants = vec![fill(None)];
    for (name, spec) in params {
        let values: Vec<String> = match spec {
            ParamSpec::Enum { values } => values.clone(),
            ParamSpec::Int { min, max } => vec![min.to_string(), max.to_string()],
            _ => continue,
        };
        variants.extend(values.iter().map(|v| fill(Some((name, v)))));
    }
    for command in &variants {
        check_words(command).map_err(|e| bad(format!("'{command}': {}", error_text(e))))?;
    }
    let longest: usize = words
        .iter()
        .map(|w| match w {
            TemplateWord::Literal(s) => s.len(),
            TemplateWord::Param {
                prefix,
                name,
                suffix,
            } => prefix.len() + longest_value(&params[name]) + suffix.len(),
        })
        .sum::<usize>()
        + words.len().saturating_sub(1);
    if longest > MAX_SSH_COMMAND_BYTES {
        return Err(bad(format!(
            "the longest possible command is {longest} bytes; at most {MAX_SSH_COMMAND_BYTES}"
        )));
    }
    Ok(())
}

/// A value of the parameter's kind that passes the shell-syntax check.
fn sample(spec: &ParamSpec) -> String {
    match spec {
        ParamSpec::String { .. } => "x".into(),
        ParamSpec::Path { .. } => "/x".into(),
        ParamSpec::Int { min, .. } => min.to_string(),
        ParamSpec::Enum { values } => values[0].clone(),
    }
}

fn longest_value(spec: &ParamSpec) -> usize {
    match spec {
        ParamSpec::String { .. } | ParamSpec::Path { .. } => MAX_SSH_RUN_PARAM_BYTES,
        ParamSpec::Int { max, .. } => max.to_string().len(),
        ParamSpec::Enum { values } => values.iter().map(String::len).max().unwrap_or(0),
    }
}

/// A validation error's message without its "validation error:" prefix.
fn error_text(e: WardenError) -> String {
    match e {
        WardenError::Validation(m) => m,
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    fn fixture() -> Config {
        toml::from_str(include_str!("../../tests/fixtures/named_commands.toml")).unwrap()
    }

    /// The fixture with one edit; the error text, if it is refused.
    fn edited(from: &str, to: &str) -> Option<String> {
        let base = include_str!("../../tests/fixtures/named_commands.toml");
        assert!(base.contains(from), "fixture lacks {from}");
        let cfg: Config = toml::from_str(&base.replacen(from, to, 1)).unwrap();
        cfg.preset
            .iter()
            .try_for_each(validate_preset)
            .and_then(|()| validate_tool_names(&cfg.preset))
            .err()
            .map(|e| e.to_string())
    }

    #[test]
    fn the_fixture_is_valid() {
        let cfg = fixture();
        validate_preset(&cfg.preset[0]).unwrap();
        validate_tool_names(&cfg.preset).unwrap();
    }

    #[test]
    fn templates_split_into_words_and_placeholders() {
        assert_eq!(
            parse_template("sed -n 1,{n}p f").unwrap(),
            [
                TemplateWord::Literal("sed".into()),
                TemplateWord::Literal("-n".into()),
                TemplateWord::Param {
                    prefix: "1,".into(),
                    name: "n".into(),
                    suffix: "p".into()
                },
                TemplateWord::Literal("f".into()),
            ]
        );
        for bad in [
            "a  b", " a", "a ", "a {b", "a b}", "a {b}{c}", "a {B}", "a {}", "a {b c}",
        ] {
            assert!(parse_template(bad).is_err(), "{bad}");
        }
    }

    /// Each rule, and the error names the preset and the command.
    #[test]
    fn every_rule_is_enforced_and_names_the_command() {
        let cases = [
            // Names.
            ("name = \"restart\"", "name = \"Restart\""),
            ("name = \"restart\"", "name = \"tail_log\""),
            // Description.
            (
                "description = \"Restart one service\"",
                "description = \" \"",
            ),
            // Template words and placeholders.
            (
                "sudo -n systemctl restart {unit}",
                "sudo -n systemctl  restart {unit}",
            ),
            (
                "sudo -n systemctl restart {unit}",
                "sudo -n systemctl restart {service}",
            ),
            (
                "sudo -n systemctl restart {unit}",
                "sudo -n systemctl restart",
            ),
            (
                "sudo -n systemctl restart {unit}",
                "sudo -n systemctl restart {unit} {unit}",
            ),
            (
                "sudo -n systemctl restart {unit}",
                "sudo -n systemctl restart $(id)",
            ),
            (
                "sudo -n systemctl restart {unit}",
                "LD_PRELOAD=/x sudo {unit}",
            ),
            (
                "mv {path} /srv/app/.trash/",
                "mv --target={path} /srv/app/.trash/",
            ),
            (
                "git -C /srv/app checkout {tag}",
                "git -C /srv/app checkout v{tag}",
            ),
            ("journalctl -u app -n {lines} --no-pager", "{lines} -u app"),
            // Parameter specs.
            (
                "type = \"int\", min = 1, max = 500",
                "type = \"int\", min = 9, max = 5",
            ),
            (
                "pattern = \"/srv/app/uploads/[a-z0-9._-]+\"",
                "pattern = \"/srv/app/uploads/[a-z\"",
            ),
            (
                "values = [\"app.service\", \"worker.service\"]",
                "values = []",
            ),
            (
                "values = [\"app.service\", \"worker.service\"]",
                "values = [\"app.service\", \"app.service\"]",
            ),
            (
                "values = [\"app.service\", \"worker.service\"]",
                "values = [\"app.service; id\"]",
            ),
            (
                "values = [\"app.service\", \"worker.service\"]",
                "values = [\"=id\"]",
            ),
            ("params.unit =", "params.Unit ="),
            // Output limits.
            ("max_output_bytes = 262144", "max_output_bytes = 0"),
            ("max_output_bytes = 262144", "max_output_bytes = 2097152"),
            ("max_output_bytes = 65536", "max_output_bytes = 0"),
        ];
        for (from, to) in cases {
            let err = edited(from, to).unwrap_or_else(|| panic!("accepted: {to}"));
            assert!(err.contains("preset 'deploy'"), "{err}");
        }
        // Command errors also name the command.
        let err = edited(
            "sudo -n systemctl restart {unit}",
            "sudo -n systemctl restart {service}",
        )
        .unwrap();
        assert!(err.contains("command 'restart'"), "{err}");
    }

    #[test]
    fn placeholders_inside_a_word_are_for_int_and_enum_only() {
        assert!(
            edited(
                "sudo -n systemctl restart {unit}",
                "sudo -n systemctl restart --unit={unit}"
            )
            .is_none()
        );
        assert!(
            edited(
                "journalctl -u app -n {lines} --no-pager",
                "journalctl -u app --lines={lines} --no-pager"
            )
            .is_none()
        );
        // An enum may pick the program: its values are fixed in the config.
        assert!(edited("sudo -n systemctl restart {unit}", "{unit} --version").is_none());
    }

    #[test]
    fn the_longest_expansion_must_fit() {
        // Four string parameters of up to 256 bytes each overflow 1024.
        let long = "template = \"git -C /srv/app checkout {tag} {a} {b} {c}\"\nparams.a = { type = \"string\", pattern = \"x\" }\nparams.b = { type = \"string\", pattern = \"x\" }\nparams.c = { type = \"string\", pattern = \"x\" }";
        let err = edited("template = \"git -C /srv/app checkout {tag}\"", long).unwrap();
        assert!(err.contains("longest possible command"), "{err}");
    }

    #[test]
    fn expose_as_tools_needs_commands() {
        let mut cfg = fixture();
        cfg.preset[0].commands.clear();
        assert!(validate_preset(&cfg.preset[0]).is_err());
        cfg.preset[0].expose_as_tools = false;
        validate_preset(&cfg.preset[0]).unwrap();
    }

    #[test]
    fn generated_tool_names_are_valid_unique_and_capped() {
        let mut cfg = fixture();
        // Not a valid MCP tool name.
        cfg.preset[0].name = "prod deploy".into();
        assert!(validate_tool_names(&cfg.preset).is_err());
        cfg.preset[0].name = "p".repeat(60);
        assert!(validate_tool_names(&cfg.preset).is_err());

        // `a_b` + `c` and `a` + `b_c` both make ssh_a_b_c.
        let mut cfg = fixture();
        let mut other = cfg.preset[0].clone();
        cfg.preset[0].name = "a_b".into();
        cfg.preset[0].commands.truncate(1);
        cfg.preset[0].commands[0].name = "c".into();
        other.name = "a".into();
        other.commands.truncate(1);
        other.commands[0].name = "b_c".into();
        cfg.preset.push(other);
        let err = validate_tool_names(&cfg.preset).unwrap_err().to_string();
        assert!(err.contains("ssh_a_b_c"), "{err}");

        // At most 32 across the config.
        let mut cfg = fixture();
        let template = cfg.preset[0].commands[0].clone();
        cfg.preset[0].commands = (0..33)
            .map(|i| {
                let mut c = template.clone();
                c.name = format!("c{i}");
                c
            })
            .collect();
        let err = validate_tool_names(&cfg.preset).unwrap_err().to_string();
        assert!(err.contains("at most 32"), "{err}");
        cfg.preset[0].expose_as_tools = false;
        validate_tool_names(&cfg.preset).unwrap();
    }
}
