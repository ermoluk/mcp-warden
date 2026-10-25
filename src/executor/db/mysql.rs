use crate::executor::ActionExecutor;
use crate::executor::db::DbQueryResponse;
use mcp_warden_core::config::{NamedQuery, Preset};
use mcp_warden_core::error::{Result, WardenError};
use mysql_async::prelude::*;
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
    let host = preset.host.as_deref().unwrap_or("");
    let user = preset.user.as_deref().unwrap_or("");
    let port = preset.port.unwrap_or(3306);
    let database = preset.database.as_deref().unwrap_or("");

    // OptsBuilder accepts the password as a separate field — never concatenate
    // into a URL string.
    let opts = mysql_async::OptsBuilder::default()
        .ip_or_hostname(host)
        .tcp_port(port)
        .user(Some(user.to_string()))
        .pass(Some(password.expose().to_string()))
        .db_name(Some(database.to_string()));
    drop(password);

    let pool = mysql_async::Pool::new(opts);
    let mut conn = pool
        .get_conn()
        .await
        .map_err(|e| WardenError::Executor(format!("mysql connect: {e}")))?;

    let mysql_params: Vec<mysql_async::Value> = params
        .iter()
        .zip(nq.param_types.iter())
        .map(|(v, t)| convert_param(v, t))
        .collect::<Result<_>>()?;

    let rows: Vec<mysql_async::Row> = conn
        .exec(&nq.template, mysql_async::Params::Positional(mysql_params))
        .await
        .map_err(|e| WardenError::Executor(format!("mysql query: {e}")))?;

    let json_rows: Vec<Value> = rows.iter().map(row_to_json).collect();
    drop(conn);
    pool.disconnect().await.ok();

    Ok(DbQueryResponse {
        rows_affected: json_rows.len() as u64,
        rows: json_rows,
    })
}

fn convert_param(v: &Value, type_name: &str) -> Result<mysql_async::Value> {
    use mysql_async::Value as MV;
    match (type_name, v) {
        ("int" | "bigint", Value::Number(n)) => {
            let i = n
                .as_i64()
                .ok_or_else(|| WardenError::Validation("not int".into()))?;
            Ok(MV::Int(i))
        }
        ("float" | "double", Value::Number(n)) => {
            let f = n
                .as_f64()
                .ok_or_else(|| WardenError::Validation("not float".into()))?;
            Ok(MV::Double(f))
        }
        ("text" | "varchar", Value::String(s)) => Ok(MV::Bytes(s.as_bytes().to_vec())),
        ("bool", Value::Bool(b)) => Ok(MV::Int(if *b { 1 } else { 0 })),
        _ => Err(WardenError::Validation(format!(
            "param type '{type_name}' incompatible with value {v}"
        ))),
    }
}

fn row_to_json(row: &mysql_async::Row) -> Value {
    let mut obj = serde_json::Map::new();
    for (i, col) in row.columns_ref().iter().enumerate() {
        let name = col.name_str().to_string();
        let val: mysql_async::Value = row.as_ref(i).cloned().unwrap_or(mysql_async::Value::NULL);
        obj.insert(name, mysql_value_to_json(&val));
    }
    Value::Object(obj)
}

fn mysql_value_to_json(v: &mysql_async::Value) -> Value {
    use mysql_async::Value as MV;
    match v {
        MV::NULL => Value::Null,
        MV::Bytes(b) => match std::str::from_utf8(b) {
            Ok(s) => Value::String(s.to_string()),
            Err(_) => Value::String(format!("{:?}", b)),
        },
        MV::Int(i) => Value::Number((*i).into()),
        MV::UInt(u) => Value::Number((*u).into()),
        MV::Float(f) => serde_json::Number::from_f64(*f as f64)
            .map(Value::Number)
            .unwrap_or(Value::Null),
        MV::Double(f) => serde_json::Number::from_f64(*f)
            .map(Value::Number)
            .unwrap_or(Value::Null),
        _ => Value::Null,
    }
}
