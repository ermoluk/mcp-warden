//! `mcp-warden scan`: find plaintext secrets in MCP client configs and
//! `.env` files. Read-only — nothing is written and nothing is sent — and
//! findings carry no secret material (see `detect::Detection::redacted`).

pub mod detect;

use detect::{Confidence, detect};
use serde::Serialize;
use serde_json::Value;
use std::path::{Path, PathBuf};

/// One plaintext secret: where it is and what it looks like, never its value.
#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub file: PathBuf,
    pub client: &'static str,
    pub location: String,
    pub kind: &'static str,
    pub confidence: Confidence,
    pub redacted: String,
    /// Set when `mcp-warden import` can move it: a stdio server's `env`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub import: Option<ImportTarget>,
    /// What to do instead, when `import` can't.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hint: Option<&'static str>,
}

/// Where `import` finds the server entry again in a JSON config.
#[derive(Debug, Clone, Serialize)]
pub struct ImportTarget {
    /// Keys from the file's root to the server object.
    pub server_path: Vec<String>,
    pub server: String,
    pub var: String,
}

pub struct Report {
    pub files_checked: usize,
    pub findings: Vec<Finding>,
}

/// Where to look. `home` / `config_dir` are the user's home and platform
/// config directory (`None` skips user-level client configs); `dirs` are
/// project directories.
pub struct Options {
    pub home: Option<PathBuf>,
    pub config_dir: Option<PathBuf>,
    pub dirs: Vec<PathBuf>,
}

const ARGS_HINT: &str = "in the server's arguments: if it can read the key from an environment \
     variable, move it to `env`, then run `mcp-warden import`";
const HEADER_HINT: &str = "in a remote server's headers: `mcp-warden run` can't wrap remote MCP \
     servers; use the client's own secret input if it has one";
const URL_HINT: &str = "in the server URL: rotate the key and pass it some other way (a header or the client's secret input)";
const NO_COMMAND_HINT: &str = "the server has no command, so `mcp-warden run` can't launch it";
const CODEX_HINT: &str = "`import` doesn't rewrite Codex's TOML: use `mcp-warden server add`, \
     then point the entry at `mcp-warden run`";
const DOTENV_HINT: &str = "not imported — tools read .env directly; keep the file out of the \
     agent's reach, or move the key into a preset (`mcp-warden secret add`)";

#[derive(Debug, Clone, Copy)]
enum Format {
    /// A JSON file whose MCP servers sit under this key.
    McpJson(&'static str),
    /// `~/.claude.json`: `mcpServers` and `projects.*.mcpServers` only.
    ClaudeJson,
    CodexToml,
    DotEnv,
}

struct Source {
    client: &'static str,
    path: PathBuf,
    format: Format,
}

pub fn scan(opts: &Options) -> Report {
    let mut sources = Vec::new();
    if let Some(home) = &opts.home {
        sources.extend(user_sources(home, opts.config_dir.as_deref()));
    }
    for dir in &opts.dirs {
        sources.extend(project_sources(dir));
    }
    let mut seen = std::collections::HashSet::new();
    let mut report = Report {
        files_checked: 0,
        findings: Vec::new(),
    };
    for source in sources {
        let key = std::fs::canonicalize(&source.path).unwrap_or(source.path.clone());
        if !seen.insert(key) {
            continue;
        }
        let Ok(raw) = std::fs::read_to_string(&source.path) else {
            continue;
        };
        report.files_checked += 1;
        let mut found = Found {
            source: &source,
            out: &mut report.findings,
        };
        match source.format {
            Format::McpJson(key) => {
                if let Ok(v) = serde_json::from_str::<Value>(&raw) {
                    found.servers(&v[key], &[key.to_string()]);
                }
            }
            Format::ClaudeJson => {
                if let Ok(v) = serde_json::from_str::<Value>(&raw) {
                    found.servers(&v["mcpServers"], &["mcpServers".into()]);
                    for (project, p) in v["projects"].as_object().into_iter().flatten() {
                        let base = ["projects".into(), project.clone(), "mcpServers".into()];
                        found.servers(&p["mcpServers"], &base);
                    }
                }
            }
            Format::CodexToml => {
                if let Ok(v) = toml::from_str::<toml::Value>(&raw) {
                    found.codex(&v);
                }
            }
            Format::DotEnv => found.dotenv(&raw),
        }
    }
    report
}

fn user_sources(home: &Path, config_dir: Option<&Path>) -> Vec<Source> {
    let mut v = vec![
        Source {
            client: "Claude Code",
            path: home.join(".claude.json"),
            format: Format::ClaudeJson,
        },
        Source {
            client: "Cursor",
            path: home.join(".cursor/mcp.json"),
            format: Format::McpJson("mcpServers"),
        },
        Source {
            client: "Windsurf",
            path: home.join(".codeium/windsurf/mcp_config.json"),
            format: Format::McpJson("mcpServers"),
        },
        Source {
            client: "Codex",
            path: home.join(".codex/config.toml"),
            format: Format::CodexToml,
        },
    ];
    if let Some(config) = config_dir {
        v.push(Source {
            client: "Claude Desktop",
            path: config.join("Claude/claude_desktop_config.json"),
            format: Format::McpJson("mcpServers"),
        });
        v.push(Source {
            client: "VS Code",
            path: config.join("Code/User/mcp.json"),
            format: Format::McpJson("servers"),
        });
    }
    v
}

fn project_sources(dir: &Path) -> Vec<Source> {
    let mut v = vec![
        Source {
            client: "Claude Code (project)",
            path: dir.join(".mcp.json"),
            format: Format::McpJson("mcpServers"),
        },
        Source {
            client: "Cursor (project)",
            path: dir.join(".cursor/mcp.json"),
            format: Format::McpJson("mcpServers"),
        },
        Source {
            client: "VS Code (project)",
            path: dir.join(".vscode/mcp.json"),
            format: Format::McpJson("servers"),
        },
    ];
    let mut env_files: Vec<PathBuf> = std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(is_env_file)
        })
        .collect();
    env_files.sort();
    v.extend(env_files.into_iter().map(|path| Source {
        client: ".env",
        path,
        format: Format::DotEnv,
    }));
    v
}

/// `.env`, `.env.local`, … but not the committed samples.
fn is_env_file(name: &str) -> bool {
    let samples = [".example", ".sample", ".template", ".dist"];
    (name == ".env" || name.starts_with(".env.")) && !samples.iter().any(|s| name.ends_with(s))
}

/// Collects findings for one source file.
struct Found<'a> {
    source: &'a Source,
    out: &'a mut Vec<Finding>,
}

impl Found<'_> {
    fn push(
        &mut self,
        location: String,
        key: Option<&str>,
        value: &str,
        import: Option<ImportTarget>,
        hint: Option<&'static str>,
    ) {
        if let Some(d) = detect(key, value) {
            self.out.push(Finding {
                file: self.source.path.clone(),
                client: self.source.client,
                location,
                kind: d.kind,
                confidence: d.confidence,
                redacted: d.redacted,
                import,
                hint,
            });
        }
    }

    /// Every MCP server entry in an object of servers.
    fn servers(&mut self, servers: &Value, base: &[String]) {
        for (name, entry) in servers.as_object().into_iter().flatten() {
            let mut path = base.to_vec();
            path.push(name.clone());
            let stdio = entry.get("command").and_then(Value::as_str).is_some();
            for (var, v) in entry["env"].as_object().into_iter().flatten() {
                let Some(value) = v.as_str() else { continue };
                let import = stdio.then(|| ImportTarget {
                    server_path: path.clone(),
                    server: name.clone(),
                    var: var.clone(),
                });
                let hint = (!stdio).then_some(NO_COMMAND_HINT);
                self.push(
                    location(&path, &["env", var]),
                    Some(var),
                    value,
                    import,
                    hint,
                );
            }
            for (header, v) in entry["headers"].as_object().into_iter().flatten() {
                if let Some(value) = v.as_str() {
                    let loc = location(&path, &["headers", header]);
                    self.push(loc, Some(header), value, None, Some(HEADER_HINT));
                }
            }
            for (i, arg) in entry["args"].as_array().into_iter().flatten().enumerate() {
                let Some(arg) = arg.as_str() else { continue };
                let loc = location(&path, &[&format!("args[{i}]")]);
                // `--api-key=…` carries its own name; a bare value doesn't.
                match arg.split_once('=') {
                    Some((flag, value)) => self.push(loc, Some(flag), value, None, Some(ARGS_HINT)),
                    None => self.push(loc, None, arg, None, Some(ARGS_HINT)),
                }
            }
            if let Some(url) = entry["url"].as_str().and_then(|u| url::Url::parse(u).ok()) {
                for (param, value) in url.query_pairs() {
                    let loc = location(&path, &["url", &format!("?{param}")]);
                    self.push(loc, Some(&param), &value, None, Some(URL_HINT));
                }
            }
        }
    }

    fn codex(&mut self, v: &toml::Value) {
        let servers = v.get("mcp_servers").and_then(toml::Value::as_table);
        for (name, entry) in servers.into_iter().flatten() {
            let base = ["mcp_servers".to_string(), name.clone()];
            let env = entry.get("env").and_then(toml::Value::as_table);
            for (var, value) in env.into_iter().flatten() {
                if let Some(value) = value.as_str() {
                    let loc = location(&base, &["env", var]);
                    self.push(loc, Some(var), value, None, Some(CODEX_HINT));
                }
            }
            let args = entry.get("args").and_then(toml::Value::as_array);
            for (i, arg) in args.into_iter().flatten().enumerate() {
                if let Some(arg) = arg.as_str() {
                    let loc = location(&base, &[&format!("args[{i}]")]);
                    self.push(loc, None, arg, None, Some(CODEX_HINT));
                }
            }
        }
    }

    fn dotenv(&mut self, raw: &str) {
        for (n, line) in raw.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let line = line.strip_prefix("export ").unwrap_or(line);
            let Some((key, value)) = line.split_once('=') else {
                continue;
            };
            let key = key.trim();
            let value = value.trim().trim_matches(|c| c == '"' || c == '\'');
            let loc = format!("{key} (line {})", n + 1);
            self.push(loc, Some(key), value, None, Some(DOTENV_HINT));
        }
    }
}

/// `mcpServers.github.env.TOKEN`, quoting segments that aren't plain words
/// (`projects["/Users/me/app"].mcpServers…`).
fn location(path: &[String], tail: &[&str]) -> String {
    let mut s = String::new();
    for seg in path.iter().map(String::as_str).chain(tail.iter().copied()) {
        let plain = seg
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-');
        if seg.starts_with("args[") || seg.starts_with('?') {
            s.push_str(&format!(".{seg}"));
        } else if plain {
            if !s.is_empty() {
                s.push('.');
            }
            s.push_str(seg);
        } else {
            s.push_str(&format!("[{seg:?}]"));
        }
    }
    s
}

#[cfg(test)]
mod tests {
    use super::detect::tests::fake;
    use super::*;

    fn gh() -> String {
        fake(&["gh", "p_"].concat(), 36)
    }

    fn write(path: &Path, body: &str) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, body).unwrap();
    }

    fn scan_home(home: &Path, project: &Path) -> Report {
        scan(&Options {
            home: Some(home.to_path_buf()),
            config_dir: Some(home.join("Library/Application Support")),
            dirs: vec![project.to_path_buf()],
        })
    }

    #[test]
    fn finds_secrets_where_clients_keep_them() {
        let home = tempfile::tempdir().unwrap();
        let project = tempfile::tempdir().unwrap();
        let token = gh();
        let claude = serde_json::json!({
            "customApiKeyResponses": { "approved": [token] },
            "mcpServers": {
                "github": { "command": "npx", "env": { "GITHUB_TOKEN": token, "LOG_LEVEL": "debug" } }
            },
            "projects": {
                "/Users/me/app": { "mcpServers": {
                    "remote": { "type": "http", "url": format!("https://x.dev/mcp?api_key={token}"),
                                "headers": { "Authorization": format!("Bearer {token}") } }
                } }
            }
        });
        write(&home.path().join(".claude.json"), &claude.to_string());
        let desktop = serde_json::json!({ "mcpServers": {
            "search": { "command": "node", "args": ["server.js", format!("--api-key={token}")] }
        }});
        write(
            &home
                .path()
                .join("Library/Application Support/Claude/claude_desktop_config.json"),
            &desktop.to_string(),
        );
        write(
            &home.path().join(".codex/config.toml"),
            &format!("[mcp_servers.gh]\ncommand = \"npx\"\nenv = {{ TOKEN = \"{token}\" }}\n"),
        );
        write(
            &project.path().join(".env"),
            &format!("# comment\nexport GITHUB_TOKEN=\"{token}\"\nDEBUG=1\n"),
        );
        write(
            &project.path().join(".env.example"),
            &format!("GITHUB_TOKEN={token}\n"),
        );

        let report = scan_home(home.path(), project.path());
        let locs: Vec<&str> = report
            .findings
            .iter()
            .map(|f| f.location.as_str())
            .collect();
        assert_eq!(
            locs,
            [
                "mcpServers.github.env.GITHUB_TOKEN",
                "projects[\"/Users/me/app\"].mcpServers.remote.headers.Authorization",
                "projects[\"/Users/me/app\"].mcpServers.remote.url.?api_key",
                "mcp_servers.gh.env.TOKEN",
                "mcpServers.search.args[1]",
                "GITHUB_TOKEN (line 2)",
            ]
        );
        assert_eq!(report.files_checked, 4, ".env.example is not read");

        let importable: Vec<&Finding> = report
            .findings
            .iter()
            .filter(|f| f.import.is_some())
            .collect();
        assert_eq!(importable.len(), 1);
        let target = importable[0].import.as_ref().unwrap();
        assert_eq!(target.server_path, ["mcpServers", "github"]);
        assert_eq!(target.var, "GITHUB_TOKEN");
        assert!(
            report
                .findings
                .iter()
                .all(|f| f.import.is_some() || f.hint.is_some())
        );
    }

    #[test]
    fn findings_never_carry_the_value() {
        let home = tempfile::tempdir().unwrap();
        let project = tempfile::tempdir().unwrap();
        let token = gh();
        write(
            &project.path().join(".mcp.json"),
            &serde_json::json!({ "mcpServers": { "gh": { "command": "x", "env": { "T": token } } } })
                .to_string(),
        );
        let report = scan_home(home.path(), project.path());
        assert_eq!(report.findings.len(), 1);
        let json = serde_json::to_string(&report.findings).unwrap();
        assert!(!json.contains(&token[4..]), "{json}");
    }

    #[test]
    fn missing_and_unparsable_files_are_skipped() {
        let home = tempfile::tempdir().unwrap();
        let project = tempfile::tempdir().unwrap();
        write(&project.path().join(".mcp.json"), "{ not json");
        let report = scan_home(home.path(), project.path());
        assert_eq!(report.files_checked, 1);
        assert!(report.findings.is_empty());
    }
}
