//! Hard limits on what an agent can send. `policy::check_request` checks
//! them before anything else — before the preset's patterns, percent-decoding
//! or any credential — so oversized input never reaches a regex, an approval
//! prompt, the audit log or an upstream.

use super::policy::Request;
use mcp_warden_core::error::{Result, WardenError};
use serde_json::Value;

/// `proxy_http` path, in bytes.
pub const MAX_HTTP_PATH_BYTES: usize = 2048;
/// `proxy_http` query parameters.
pub const MAX_HTTP_QUERY_PAIRS: usize = 64;
/// All `proxy_http` query keys and values together, in bytes.
pub const MAX_HTTP_QUERY_BYTES: usize = 4096;
/// `proxy_http` JSON body, serialised, in bytes.
pub const MAX_HTTP_BODY_BYTES: usize = 1024 * 1024;
/// `ssh_exec` command, in bytes.
pub const MAX_SSH_COMMAND_BYTES: usize = 1024;
/// Each of the `sftp_transfer` remote and local paths, in bytes.
pub const MAX_SFTP_PATH_BYTES: usize = 1024;
/// `db_query` parameters.
pub const MAX_DB_PARAMS: usize = 32;
/// Each `db_query` parameter, in bytes: a string's own bytes, anything else
/// serialised as JSON.
pub const MAX_DB_PARAM_BYTES: usize = 16 * 1024;

/// Refuse a request with any field over its limit. The error names the field
/// and the limit, never the input itself.
pub fn check(req: &Request) -> Result<()> {
    match *req {
        Request::Http {
            path, query, body, ..
        } => {
            at_most("proxy_http path", path.len(), MAX_HTTP_PATH_BYTES, "bytes")?;
            if let Some(query) = query {
                let pairs = query.len();
                at_most(
                    "proxy_http query",
                    pairs,
                    MAX_HTTP_QUERY_PAIRS,
                    "parameters",
                )?;
                let bytes = query.iter().map(|(k, v)| k.len() + v.len()).sum();
                at_most("proxy_http query", bytes, MAX_HTTP_QUERY_BYTES, "bytes")?;
            }
            if let Some(body) = body
                && json_longer_than(body, MAX_HTTP_BODY_BYTES)
            {
                return Err(WardenError::Validation(format!(
                    "proxy_http body is over the limit of {MAX_HTTP_BODY_BYTES} bytes \
                     (serialised as JSON)"
                )));
            }
        }
        Request::Ssh { command } => {
            let bytes = command.len();
            at_most("ssh_exec command", bytes, MAX_SSH_COMMAND_BYTES, "bytes")?;
        }
        Request::Sftp { remote, local } => {
            let max = MAX_SFTP_PATH_BYTES;
            at_most("sftp_transfer remote path", remote.len(), max, "bytes")?;
            at_most("sftp_transfer local path", local.len(), max, "bytes")?;
        }
        Request::Db { params, .. } => {
            at_most("db_query", params.len(), MAX_DB_PARAMS, "parameters")?;
            for (i, param) in params.iter().enumerate() {
                let over = match param {
                    Value::String(s) => s.len() > MAX_DB_PARAM_BYTES,
                    other => json_longer_than(other, MAX_DB_PARAM_BYTES),
                };
                if over {
                    return Err(WardenError::Validation(format!(
                        "db_query parameter {} is over the limit of {MAX_DB_PARAM_BYTES} bytes",
                        i + 1
                    )));
                }
            }
        }
    }
    Ok(())
}

fn at_most(what: &str, n: usize, max: usize, unit: &str) -> Result<()> {
    if n > max {
        return Err(WardenError::Validation(format!(
            "{what} has {n} {unit}; the limit is {max} {unit}"
        )));
    }
    Ok(())
}

/// Whether `value` serialises to more than `max` bytes. Stops writing as
/// soon as it does, so a huge body is never serialised in full.
fn json_longer_than(value: &Value, max: usize) -> bool {
    struct Budget(usize);
    impl std::io::Write for Budget {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0 = self
                .0
                .checked_sub(buf.len())
                .ok_or_else(|| std::io::Error::other("over budget"))?;
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    serde_json::to_writer(Budget(max), value).is_err()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::collections::BTreeMap;

    fn refused(req: Request) -> String {
        check(&req).unwrap_err().to_string()
    }

    #[test]
    fn http_path_up_to_the_limit_passes() {
        let at = format!("/{}", "a".repeat(MAX_HTTP_PATH_BYTES - 1));
        check(&Request::http("GET", &at)).unwrap();
        let over = format!("{at}a");
        let err = refused(Request::http("GET", &over));
        assert!(
            err.contains("proxy_http path") && err.contains("2048"),
            "{err}"
        );
        assert!(
            !err.contains("aaaa"),
            "the error must not echo the input: {err}"
        );
    }

    #[test]
    fn http_query_pairs_and_bytes_are_capped() {
        let many: BTreeMap<String, String> = (0..=MAX_HTTP_QUERY_PAIRS)
            .map(|i| (format!("k{i}"), "v".into()))
            .collect();
        let req = Request::Http {
            method: "GET",
            path: "/x",
            query: Some(&many),
            body: None,
        };
        assert!(refused(req).contains("64 parameters"));

        let mut big = BTreeMap::new();
        big.insert("q".to_string(), "v".repeat(MAX_HTTP_QUERY_BYTES));
        let req = Request::Http {
            method: "GET",
            path: "/x",
            query: Some(&big),
            body: None,
        };
        assert!(refused(req).contains("4096 bytes"));

        big.insert("q".to_string(), "v".repeat(MAX_HTTP_QUERY_BYTES - 1));
        let req = Request::Http {
            method: "GET",
            path: "/x",
            query: Some(&big),
            body: None,
        };
        check(&req).unwrap();
    }

    #[test]
    fn http_body_is_capped_when_serialised() {
        // `"…"` adds two bytes of quotes to the string.
        let fits = json!("x".repeat(MAX_HTTP_BODY_BYTES - 2));
        let req = Request::Http {
            method: "POST",
            path: "/x",
            query: None,
            body: Some(&fits),
        };
        check(&req).unwrap();
        let over = json!({ "data": "x".repeat(MAX_HTTP_BODY_BYTES) });
        let req = Request::Http {
            method: "POST",
            path: "/x",
            query: None,
            body: Some(&over),
        };
        assert!(refused(req).contains("proxy_http body"));
    }

    #[test]
    fn ssh_command_is_capped() {
        let at = "a".repeat(MAX_SSH_COMMAND_BYTES);
        check(&Request::Ssh { command: &at }).unwrap();
        let over = format!("{at}a");
        let err = refused(Request::Ssh { command: &over });
        assert!(
            err.contains("ssh_exec command") && err.contains("1024"),
            "{err}"
        );
    }

    #[test]
    fn sftp_paths_are_capped_each() {
        let at = format!("/{}", "a".repeat(MAX_SFTP_PATH_BYTES - 1));
        let over = format!("{at}a");
        check(&Request::Sftp {
            remote: &at,
            local: &at,
        })
        .unwrap();
        let err = refused(Request::Sftp {
            remote: &over,
            local: "/tmp/x",
        });
        assert!(err.contains("remote path"), "{err}");
        let err = refused(Request::Sftp {
            remote: "/srv/x",
            local: &over,
        });
        assert!(err.contains("local path"), "{err}");
    }

    #[test]
    fn db_params_are_capped_in_number_and_size() {
        let many = vec![Value::Null; MAX_DB_PARAMS + 1];
        let err = refused(Request::Db {
            query: "q",
            params: &many,
        });
        assert!(err.contains("32 parameters"), "{err}");

        let fits = vec![json!("x".repeat(MAX_DB_PARAM_BYTES)), json!(1)];
        check(&Request::Db {
            query: "q",
            params: &fits,
        })
        .unwrap();
        let over = vec![json!(1), json!("x".repeat(MAX_DB_PARAM_BYTES + 1))];
        let err = refused(Request::Db {
            query: "q",
            params: &over,
        });
        assert!(
            err.contains("parameter 2") && err.contains("16384"),
            "{err}"
        );
        let nested = vec![json!(["x".repeat(MAX_DB_PARAM_BYTES)])];
        assert!(
            check(&Request::Db {
                query: "q",
                params: &nested,
            })
            .is_err()
        );
    }
}
