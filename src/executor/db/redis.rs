use crate::executor::ActionExecutor;
use crate::executor::db::{DbQueryResponse, is_local_host};
use mcp_warden_core::config::{NamedQuery, Preset};
use mcp_warden_core::error::{Result, WardenError};
use serde_json::Value;

pub async fn run(
    actx: &ActionExecutor,
    preset: &Preset,
    nq: &NamedQuery,
    params: &[Value],
) -> Result<DbQueryResponse> {
    let password = actx
        .keychain
        .get(preset.secret.as_deref().unwrap_or(""))?
        .ok_or_else(|| WardenError::MissingSecret {
            preset: preset.name.clone(),
            secret: preset.secret.clone().unwrap_or_default(),
        })?;
    let host = preset.host.as_deref().unwrap_or("").to_string();
    let port = preset.port.unwrap_or(6379);

    let info = redis::ConnectionInfo {
        addr: redis_addr(host, port),
        redis: redis::RedisConnectionInfo {
            db: preset
                .database
                .as_deref()
                .and_then(|s| s.parse::<i64>().ok())
                .unwrap_or(0),
            username: preset.user.clone(),
            password: Some(password.expose().to_string()),
            ..Default::default()
        },
    };
    drop(password);

    let client =
        redis::Client::open(info).map_err(|e| WardenError::Executor(format!("redis open: {e}")))?;
    let mut conn = client
        .get_multiplexed_async_connection()
        .await
        .map_err(|e| WardenError::Executor(format!("redis connect: {e}")))?;

    let mut cmd = redis::cmd(&nq.template);
    for p in params {
        match p {
            Value::String(s) => {
                cmd.arg(s);
            }
            Value::Number(n) => {
                if let Some(i) = n.as_i64() {
                    cmd.arg(i);
                } else if let Some(f) = n.as_f64() {
                    cmd.arg(f);
                }
            }
            Value::Bool(b) => {
                cmd.arg(if *b { 1 } else { 0 });
            }
            _ => {
                return Err(WardenError::Validation(format!(
                    "redis param must be string/number/bool, got {p}"
                )));
            }
        }
    }
    let val: redis::Value = cmd
        .query_async(&mut conn)
        .await
        .map_err(|e| WardenError::Executor(format!("redis query: {e}")))?;
    let json = redis_value_to_json(&val);
    Ok(DbQueryResponse {
        rows: vec![json],
        rows_affected: 1,
    })
}

fn redis_value_to_json(v: &redis::Value) -> Value {
    match v {
        redis::Value::Nil => Value::Null,
        redis::Value::Int(i) => Value::Number((*i).into()),
        redis::Value::BulkString(b) => match std::str::from_utf8(b) {
            Ok(s) => Value::String(s.to_string()),
            Err(_) => Value::String(format!("{:?}", b)),
        },
        redis::Value::SimpleString(s) => Value::String(s.clone()),
        redis::Value::Array(arr) | redis::Value::Set(arr) => {
            Value::Array(arr.iter().map(redis_value_to_json).collect())
        }
        redis::Value::Okay => Value::String("OK".into()),
        redis::Value::Boolean(b) => Value::Bool(*b),
        redis::Value::Double(f) => serde_json::Number::from_f64(*f)
            .map(Value::Number)
            .unwrap_or(Value::Null),
        _ => Value::Null,
    }
}

/// Plain TCP only when the connection cannot leave this machine; otherwise
/// TLS with certificate verification (`insecure: false`).
fn redis_addr(host: String, port: u16) -> redis::ConnectionAddr {
    if is_local_host(&host) {
        redis::ConnectionAddr::Tcp(host, port)
    } else {
        redis::ConnectionAddr::TcpTls {
            host,
            port,
            insecure: false,
            tls_params: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remote_hosts_require_verified_tls() {
        assert!(matches!(
            redis_addr("cache.example.com".into(), 6379),
            redis::ConnectionAddr::TcpTls {
                insecure: false,
                ..
            }
        ));
        assert!(matches!(
            redis_addr("localhost".into(), 6379),
            redis::ConnectionAddr::Tcp(..)
        ));
    }
}
