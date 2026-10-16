//! JSON-RPC 2.0 message shapes and the hello handshake types.

use kraken_proto::{ErrorCode, ProtoError};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

/// IPC protocol version spoken by this crate.
pub const PROTOCOL_VERSION: u32 = 1;

/// Reserved method name of the handshake request.
pub const HELLO_METHOD: &str = "hello";

/// Kind of connecting client.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClientKind {
    /// Command-line client.
    Cli,
    /// Graphical client.
    Gui,
    /// MCP server.
    Mcp,
}

/// Params of the hello request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HelloParams {
    /// Auth token from `daemon.token`.
    pub token: String,
    /// Client protocol version.
    pub protocol: u32,
    /// Client build id.
    pub build: String,
    /// Client kind.
    pub client_kind: ClientKind,
}

/// Result of a successful hello.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HelloResult {
    /// Daemon protocol version.
    pub protocol: u32,
    /// Daemon build id.
    pub build: String,
    /// Daemon process id.
    pub daemon_pid: u32,
}

/// Error for a rejected token.
pub fn unauthorized() -> ProtoError {
    ProtoError::new(ErrorCode::InvalidArgument, "invalid auth token")
        .with_details(json!({"reason": "unauthorized"}))
}

/// Error telling the client the daemon speaks a different protocol and must be restarted.
pub fn protocol_mismatch(server: u32, client: u32, server_build: &str) -> ProtoError {
    ProtoError::new(
        ErrorCode::Unsupported,
        format!(
            "protocol mismatch (daemon {server}, client {client}, daemon build {server_build}); \
             restart the daemon (`kraken daemon stop`)"
        ),
    )
    .with_details(json!({
        "reason": "protocol_mismatch",
        "restart_daemon": true,
        "server_protocol": server,
        "client_protocol": client,
        "server_build": server_build,
    }))
}

/// True when `e` is the structured "restart the daemon" error.
pub fn is_restart_required(e: &ProtoError) -> bool {
    e.details
        .as_ref()
        .and_then(|d| d.get("restart_daemon"))
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

/// True when `e` is an auth rejection.
pub fn is_unauthorized(e: &ProtoError) -> bool {
    e.details
        .as_ref()
        .and_then(|d| d.get("reason"))
        .and_then(Value::as_str)
        == Some("unauthorized")
}

pub(crate) fn request(id: u64, method: &str, params: Value) -> Vec<u8> {
    json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params})
        .to_string()
        .into_bytes()
}

pub(crate) fn notification(method: &str, params: Value) -> Vec<u8> {
    json!({"jsonrpc": "2.0", "method": method, "params": params})
        .to_string()
        .into_bytes()
}

pub(crate) fn response(id: &Value, res: Result<Value, ProtoError>) -> Vec<u8> {
    match res {
        Ok(result) => json!({"jsonrpc": "2.0", "id": id, "result": result}),
        Err(error) => json!({"jsonrpc": "2.0", "id": id, "error": error}),
    }
    .to_string()
    .into_bytes()
}

/// A decoded inbound message.
pub(crate) enum Inbound {
    Request {
        id: Value,
        method: String,
        params: Value,
    },
    Notification {
        method: String,
        params: Value,
    },
    Response {
        id: Value,
        result: Result<Value, ProtoError>,
    },
}

pub(crate) fn parse(bytes: &[u8]) -> Result<Inbound, ProtoError> {
    let bad = |m: &str| ProtoError::new(ErrorCode::InvalidArgument, m.to_owned());
    let v: Value = serde_json::from_slice(bytes).map_err(|e| bad(&format!("invalid JSON: {e}")))?;
    let Value::Object(mut o) = v else {
        return Err(bad("message must be a JSON object"));
    };
    if o.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
        return Err(bad("missing jsonrpc 2.0"));
    }
    let id = o.remove("id");
    if let Some(m) = o.remove("method") {
        let Value::String(method) = m else {
            return Err(bad("method must be a string"));
        };
        let params = o.remove("params").unwrap_or(Value::Null);
        return Ok(match id {
            Some(id) => Inbound::Request { id, method, params },
            None => Inbound::Notification { method, params },
        });
    }
    let id = id.ok_or_else(|| bad("response without id"))?;
    if let Some(e) = o.remove("error") {
        let err: ProtoError =
            serde_json::from_value(e).map_err(|e| bad(&format!("invalid error object: {e}")))?;
        return Ok(Inbound::Response {
            id,
            result: Err(err),
        });
    }
    let result = o
        .remove("result")
        .ok_or_else(|| bad("response without result or error"))?;
    Ok(Inbound::Response {
        id,
        result: Ok(result),
    })
}
