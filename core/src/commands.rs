//! Named SSH commands: a preset's fixed templates, filled with typed
//! parameter values (`ssh_run`).
//!
//! The agent never composes the command line. It names a command and
//! supplies values; each value becomes exactly one word of the command (or,
//! for `int` and `enum`, part of one), checked by type before anything else
//! happens. Templates are checked once at startup, so a config the server
//! accepted can only ever produce commands that pass the shell-syntax check
//! and fit the length limit (invariants 5 and 10).

use crate::config::{ApprovalPolicy, NamedCommand, ParamSpec, Preset, anchored_regex};
use crate::error::{Result, WardenError};
use crate::limits::{
    MAX_SSH_COMMAND_BYTES, MAX_SSH_OUTPUT_BYTES, MAX_SSH_RUN_PARAM_BYTES, MAX_SSH_RUN_PARAMS,
};
use crate::ssh_words::check_words;
use serde_json::Value;
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

/// A named command filled in for one call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rendered {
    /// The command line, exactly as it is sent.
    pub command: String,
    /// The policy that applies to this command.
    pub approval: ApprovalPolicy,
    /// The most stdout and stderr, each, read from the host.
    pub max_output: usize,
}

/// The preset's command called `name`.
pub fn find<'a>(p: &'a Preset, name: &str) -> Result<&'a NamedCommand> {
    p.commands.iter().find(|c| c.name == name).ok_or_else(|| {
        let known: Vec<&str> = p.commands.iter().map(|c| c.name.as_str()).collect();
        let shown = if is_identifier(name) {
            format!("'{name}'")
        } else {
            "with that name".into()
        };
        WardenError::Validation(format!(
            "preset '{}' has no command {shown}; it has: {}",
            p.name,
            if known.is_empty() {
                "none".into()
            } else {
                known.join(", ")
            }
        ))
    })
}

/// The command's own policy, else the preset's. A preset set to `deny` is
/// off, whatever its commands say.
pub fn effective_approval(p: &Preset, c: &NamedCommand) -> ApprovalPolicy {
    match p.approval {
        ApprovalPolicy::Deny => ApprovalPolicy::Deny,
        preset => c.approval.unwrap_or(preset),
    }
}

/// The command's output limit, else the preset's, never above
/// [`MAX_SSH_OUTPUT_BYTES`].
pub fn max_output(p: &Preset, c: Option<&NamedCommand>) -> usize {
    c.and_then(|c| c.max_output_bytes)
        .or(p.max_output_bytes)
        .map_or(MAX_SSH_OUTPUT_BYTES, |m| {
            usize::try_from(m).map_or(MAX_SSH_OUTPUT_BYTES, |m| m.min(MAX_SSH_OUTPUT_BYTES))
        })
}

/// Fill in a named command from the agent's values, refusing anything that
/// is not exactly what the parameter declares. Pure: nothing is read or
/// sent. In order: the input limits, the exact set of parameters, each
/// value by its type, then the whole command again (shell-syntax check and
/// length), so a refusal never depends on a credential (invariant 3).
pub fn render(p: &Preset, name: &str, params: &BTreeMap<String, Value>) -> Result<Rendered> {
    let c = find(p, name)?;
    let refuse = |why: String| {
        WardenError::Validation(format!("preset '{}': command '{}': {why}", p.name, c.name))
    };
    if params.len() > MAX_SSH_RUN_PARAMS {
        return Err(refuse(format!(
            "{} parameters; the limit is {MAX_SSH_RUN_PARAMS}",
            params.len()
        )));
    }
    for key in params.keys() {
        if !c.params.contains_key(key) {
            let key = if is_identifier(key) {
                format!("'{key}'")
            } else {
                "with that name".into()
            };
            return Err(refuse(format!(
                "no parameter {key}; it takes: {}",
                list(c.params.keys())
            )));
        }
    }
    let mut values = BTreeMap::new();
    for (key, spec) in &c.params {
        let value = params
            .get(key)
            .ok_or_else(|| refuse(format!("missing parameter '{key}'")))?;
        let text =
            check_value(spec, value).map_err(|why| refuse(format!("parameter '{key}': {why}")))?;
        values.insert(key.as_str(), text);
    }
    let words = parse_template(&c.template).map_err(|e| refuse(error_text(e)))?;
    let command = words
        .iter()
        .map(|w| match w {
            TemplateWord::Literal(s) => s.clone(),
            TemplateWord::Param {
                prefix,
                name,
                suffix,
            } => format!("{prefix}{}{suffix}", values[name.as_str()]),
        })
        .collect::<Vec<_>>()
        .join(" ");
    check_words(&command).map_err(|e| refuse(error_text(e)))?;
    if command.len() > MAX_SSH_COMMAND_BYTES {
        return Err(refuse(format!(
            "the command is {} bytes; the limit is {MAX_SSH_COMMAND_BYTES}",
            command.len()
        )));
    }
    Ok(Rendered {
        command,
        approval: effective_approval(p, c),
        max_output: max_output(p, Some(c)),
    })
}

/// The value as it goes into the command, or why it is refused. The
/// reason never repeats the value.
fn check_value(spec: &ParamSpec, value: &Value) -> std::result::Result<String, String> {
    let text = match (spec, value) {
        (ParamSpec::Int { min, max }, Value::Number(n)) => {
            let n = n.as_u64().ok_or("must be a whole number, 0 or more")?;
            in_range(n, *min, *max)?
        }
        (ParamSpec::Int { min, max }, Value::String(s)) => {
            let decimal = !s.is_empty()
                && s.len() <= 20
                && s.bytes().all(|b| b.is_ascii_digit())
                && (s == "0" || !s.starts_with('0'));
            let n = s
                .parse::<u64>()
                .ok()
                .filter(|_| decimal)
                .ok_or("must be a decimal number without sign or leading zeros")?;
            in_range(n, *min, *max)?
        }
        (ParamSpec::Int { .. }, _) => return Err("must be a number".into()),
        (ParamSpec::Enum { values }, Value::String(s)) => {
            if !values.contains(s) {
                return Err(format!("must be one of: {}", values.join(", ")));
            }
            s.clone()
        }
        (ParamSpec::Enum { values }, _) => {
            return Err(format!("must be one of: {}", values.join(", ")));
        }
        (ParamSpec::String { pattern } | ParamSpec::Path { pattern }, Value::String(s)) => {
            if s.len() > MAX_SSH_RUN_PARAM_BYTES {
                return Err(format!(
                    "{} bytes; the limit is {MAX_SSH_RUN_PARAM_BYTES}",
                    s.len()
                ));
            }
            if s.is_empty() || s.contains(' ') || check_words(s).is_err() {
                return Err(
                    "must be one word of letters, digits and - _ . / : = @ , + % (no leading \
                     '=' or '%')"
                        .into(),
                );
            }
            if s.starts_with('-') {
                return Err("must not start with '-': it would be read as an option".into());
            }
            if let ParamSpec::Path { .. } = spec {
                if !s.starts_with('/') {
                    return Err("must be an absolute path".into());
                }
                if s.contains("//") || s.split('/').any(|seg| seg == "." || seg == "..") {
                    return Err("must not contain '//' or a '.' or '..' segment".into());
                }
            }
            let rx = anchored_regex(pattern).map_err(|e| format!("bad pattern: {e}"))?;
            if !rx.is_match(s) {
                return Err(format!("does not match the pattern {pattern}"));
            }
            s.clone()
        }
        (ParamSpec::String { .. } | ParamSpec::Path { .. }, _) => {
            return Err("must be a string".into());
        }
    };
    Ok(text)
}

fn in_range(n: u64, min: u64, max: u64) -> std::result::Result<String, String> {
    if n < min || n > max {
        return Err(format!("must be from {min} to {max}"));
    }
    Ok(n.to_string())
}

fn list<'a>(names: impl Iterator<Item = &'a String>) -> String {
    let names: Vec<&str> = names.map(String::as_str).collect();
    if names.is_empty() {
        "nothing".into()
    } else {
        names.join(", ")
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

    fn run(command: &str, params: serde_json::Value) -> Result<Rendered> {
        let cfg = fixture();
        let params: BTreeMap<String, Value> = serde_json::from_value(params).unwrap();
        render(&cfg.preset[0], command, &params)
    }

    #[test]
    fn values_fill_the_template() {
        use serde_json::json;
        let r = run("tail_log", json!({"lines": 50})).unwrap();
        assert_eq!(r.command, "journalctl -u app -n 50 --no-pager");
        assert_eq!(r.max_output, 262144);
        assert_eq!(r.approval, ApprovalPolicy::Prompt);
        assert_eq!(
            run("tail_log", json!({"lines": "500"})).unwrap().command,
            "journalctl -u app -n 500 --no-pager"
        );
        assert_eq!(
            run("restart", json!({"unit": "worker.service"}))
                .unwrap()
                .command,
            "sudo -n systemctl restart worker.service"
        );
        let r = run("trash_file", json!({"path": "/srv/app/uploads/a.png"})).unwrap();
        assert_eq!(r.command, "mv /srv/app/uploads/a.png /srv/app/.trash/");
        assert_eq!(r.max_output, 65536);
        assert_eq!(
            run("checkout", json!({"tag": "v1.2.3"})).unwrap().command,
            "git -C /srv/app checkout v1.2.3"
        );
        assert_eq!(
            run("head_log", json!({"n": 7})).unwrap().command,
            "sed -n 1,7p /srv/app/log.txt"
        );
    }

    #[test]
    fn anything_but_the_declared_value_is_refused() {
        use serde_json::json;
        let cases = [
            ("tail_log", json!({})),
            ("tail_log", json!({"lines": 50, "extra": 1})),
            ("tail_log", json!({"lines": 0})),
            ("tail_log", json!({"lines": 501})),
            ("tail_log", json!({"lines": -1})),
            ("tail_log", json!({"lines": 1.5})),
            ("tail_log", json!({"lines": "050"})),
            ("tail_log", json!({"lines": "+5"})),
            ("tail_log", json!({"lines": " 5"})),
            ("tail_log", json!({"lines": "5;id"})),
            ("tail_log", json!({"lines": "99999999999999999999999"})),
            ("tail_log", json!({"lines": true})),
            ("tail_log", json!({"lines": null})),
            ("restart", json!({"unit": "APP.SERVICE"})),
            ("restart", json!({"unit": "app.service "})),
            ("restart", json!({"unit": ["app.service"]})),
            ("trash_file", json!({"path": "uploads/a.png"})),
            (
                "trash_file",
                json!({"path": "/srv/app/uploads/../../etc/passwd"}),
            ),
            ("trash_file", json!({"path": "/srv/app/uploads/./a"})),
            ("trash_file", json!({"path": "/srv/app//uploads/a"})),
            ("trash_file", json!({"path": "/srv/app/uploads/a b"})),
            ("trash_file", json!({"path": "/srv/app/uploads/$(id)"})),
            ("trash_file", json!({"path": "/srv/app/other/a.png"})),
            ("trash_file", json!({"path": 5})),
            ("checkout", json!({"tag": "-v1.2.3"})),
            ("checkout", json!({"tag": "v1.2.3 --force"})),
            ("checkout", json!({"tag": "v1.2"})),
            ("checkout", json!({"tag": "v1.2.3\n"})),
            ("checkout", json!({"tag": "v1.2.3\u{0}"})),
            ("checkout", json!({"tag": "v１.2.3"})),
            ("checkout", json!({"tag": ""})),
            ("checkout", json!({"tag": "x".repeat(300)})),
            ("nope", json!({})),
        ];
        for (command, params) in cases {
            assert!(run(command, params.clone()).is_err(), "{command} {params}");
        }
        let many: BTreeMap<String, Value> = (0..17).map(|i| (format!("p{i}"), json!(1))).collect();
        assert!(run("tail_log", serde_json::to_value(many).unwrap()).is_err());
    }

    /// Errors name the parameter, not the agent's value.
    #[test]
    fn refusals_do_not_repeat_the_value() {
        use serde_json::json;
        let err = run("checkout", json!({"tag": "v1.2.3 --upload-pack=/tmp/x"}))
            .unwrap_err()
            .to_string();
        assert!(err.contains("parameter 'tag'"), "{err}");
        assert!(!err.contains("upload-pack"), "{err}");
        let err = run("tail_log", json!({"evil$(id)": 1}))
            .unwrap_err()
            .to_string();
        assert!(!err.contains("evil"), "{err}");
    }

    #[test]
    fn a_command_policy_never_overrides_a_denied_preset() {
        let mut p = fixture().preset[0].clone();
        p.commands[0].approval = Some(ApprovalPolicy::Auto);
        assert_eq!(effective_approval(&p, &p.commands[0]), ApprovalPolicy::Auto);
        assert_eq!(
            effective_approval(&p, &p.commands[1]),
            ApprovalPolicy::Prompt
        );
        p.approval = ApprovalPolicy::Deny;
        assert_eq!(effective_approval(&p, &p.commands[0]), ApprovalPolicy::Deny);
        p.approval = ApprovalPolicy::Auto;
        p.commands[1].approval = Some(ApprovalPolicy::Prompt);
        assert_eq!(
            effective_approval(&p, &p.commands[1]),
            ApprovalPolicy::Prompt
        );
    }
}
