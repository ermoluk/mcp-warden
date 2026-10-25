use crate::executor::ActionExecutor;
use crate::executor::db::{DbQueryResponse, is_local_host};
use mcp_warden_core::config::{NamedQuery, Preset};
use mcp_warden_core::error::{Result, WardenError};
use serde_json::Value;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::task::JoinHandle;
use tokio_postgres::config::SslMode;
use tokio_postgres::types::Type;
use tokio_postgres::{Connection, NoTls};

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
    let host = preset.host.as_deref().unwrap_or("");
    let user = preset.user.as_deref().unwrap_or("");
    let port = preset.port.unwrap_or(5432);
    let database = preset.database.as_deref().unwrap_or("");

    let mut config = tokio_postgres::Config::new();
    config
        .host(host)
        .port(port)
        .user(user)
        .dbname(database)
        .password(password.expose());
    drop(password);

    // The password must never cross the network in plaintext: TLS with
    // certificate verification for any remote host; plaintext only when the
    // connection cannot leave this machine.
    let (client, conn_handle) = if is_local_host(host) {
        let (client, connection) = config
            .connect(NoTls)
            .await
            .map_err(|e| WardenError::Executor(format!("pg connect: {e}")))?;
        (client, spawn_connection(connection))
    } else {
        config.ssl_mode(SslMode::Require);
        let (client, connection) = config
            .connect(tls_connector()?)
            .await
            .map_err(|e| WardenError::Executor(format!("pg connect (TLS required): {e}")))?;
        (client, spawn_connection(connection))
    };

    let typed_params: Vec<Box<dyn tokio_postgres::types::ToSql + Sync + Send>> = params
        .iter()
        .zip(nq.param_types.iter())
        .map(|(v, t)| convert_param(v, t))
        .collect::<Result<_>>()?;
    let refs: Vec<&(dyn tokio_postgres::types::ToSql + Sync)> = typed_params
        .iter()
        .map(|b| &**b as &(dyn tokio_postgres::types::ToSql + Sync))
        .collect();

    let rows = client
        .query(&nq.template, &refs)
        .await
        .map_err(|e| WardenError::Executor(format!("pg query: {e}")))?;

    let json_rows: Vec<Value> = rows.iter().map(row_to_json).collect();
    conn_handle.abort();

    Ok(DbQueryResponse {
        rows_affected: json_rows.len() as u64,
        rows: json_rows,
    })
}

/// TLS connector that verifies the server certificate against the OS trust
/// store plus the Mozilla roots. A database with a private CA (e.g. AWS RDS)
/// works once that CA is added to the OS trust store.
fn tls_connector() -> Result<tokio_postgres_rustls::MakeRustlsConnect> {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    for cert in rustls_native_certs::load_native_certs().certs {
        let _ = roots.add(cert);
    }
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|e| WardenError::Executor(format!("tls config: {e}")))?
    .with_root_certificates(roots)
    .with_no_client_auth();
    Ok(tokio_postgres_rustls::MakeRustlsConnect::new(config))
}

fn spawn_connection<S, T>(connection: Connection<S, T>) -> JoinHandle<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    tokio::spawn(async move {
        if let Err(e) = connection.await {
            tracing::warn!("postgres connection error: {e}");
        }
    })
}

fn convert_param(
    v: &Value,
    type_name: &str,
) -> Result<Box<dyn tokio_postgres::types::ToSql + Sync + Send>> {
    match (type_name, v) {
        ("int8" | "bigint", Value::Number(n)) => {
            let i = n
                .as_i64()
                .ok_or_else(|| WardenError::Validation("not int8".into()))?;
            Ok(Box::new(i))
        }
        ("int4" | "int", Value::Number(n)) => {
            let i = n
                .as_i64()
                .and_then(|x| i32::try_from(x).ok())
                .ok_or_else(|| WardenError::Validation("not int4".into()))?;
            Ok(Box::new(i))
        }
        ("float8" | "double", Value::Number(n)) => {
            let f = n
                .as_f64()
                .ok_or_else(|| WardenError::Validation("not float8".into()))?;
            Ok(Box::new(f))
        }
        ("text" | "varchar", Value::String(s)) => Ok(Box::new(s.clone())),
        ("bool", Value::Bool(b)) => Ok(Box::new(*b)),
        _ => Err(WardenError::Validation(format!(
            "param type '{type_name}' incompatible with value {v}"
        ))),
    }
}

fn row_to_json(row: &tokio_postgres::Row) -> Value {
    let mut obj = serde_json::Map::new();
    for (i, col) in row.columns().iter().enumerate() {
        let name = col.name().to_string();
        let val = match col.type_().clone() {
            Type::INT2 => row
                .try_get::<_, Option<i16>>(i)
                .ok()
                .flatten()
                .map(|v| Value::Number(v.into()))
                .unwrap_or(Value::Null),
            Type::INT4 => row
                .try_get::<_, Option<i32>>(i)
                .ok()
                .flatten()
                .map(|v| Value::Number(v.into()))
                .unwrap_or(Value::Null),
            Type::INT8 => row
                .try_get::<_, Option<i64>>(i)
                .ok()
                .flatten()
                .map(|v| Value::Number(v.into()))
                .unwrap_or(Value::Null),
            Type::FLOAT4 => row
                .try_get::<_, Option<f32>>(i)
                .ok()
                .flatten()
                .and_then(|v| serde_json::Number::from_f64(v as f64))
                .map(Value::Number)
                .unwrap_or(Value::Null),
            Type::FLOAT8 => row
                .try_get::<_, Option<f64>>(i)
                .ok()
                .flatten()
                .and_then(serde_json::Number::from_f64)
                .map(Value::Number)
                .unwrap_or(Value::Null),
            Type::BOOL => row
                .try_get::<_, Option<bool>>(i)
                .ok()
                .flatten()
                .map(Value::Bool)
                .unwrap_or(Value::Null),
            Type::JSONB | Type::JSON => row
                .try_get::<_, Option<serde_json::Value>>(i)
                .ok()
                .flatten()
                .unwrap_or(Value::Null),
            _ => row
                .try_get::<_, Option<String>>(i)
                .ok()
                .flatten()
                .map(Value::String)
                .unwrap_or(Value::Null),
        };
        obj.insert(name, val);
    }
    Value::Object(obj)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tls_connector_builds() {
        tls_connector().unwrap();
    }
}
