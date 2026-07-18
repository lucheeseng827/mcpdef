// SPDX-License-Identifier: Apache-2.0
//! `mcpdef-core` — the normalized JSON-RPC 2.0 envelope, MCP method-name helpers,
//! and the governance `Decision` type shared across the MCPdef gateway.
//!
//! Phase 1 of the [ROADMAP](../../../ROADMAP.md): a transport-multiplexing
//! reverse proxy + allowlist + audit. Every transport (stdio today; Streamable
//! HTTP / legacy HTTP+SSE in Phases 1/1.5) speaks the same [`Message`] envelope,
//! so the proxy stays transparent to fields it does not govern.
//!
//! Dependency direction is one-way: the other `mcpdef-*` crates depend on this
//! one, never the reverse.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// MCP / JSON-RPC method names the gateway recognizes (a non-exhaustive subset;
/// any other method is still forwarded — it is just not specially governed yet).
pub mod method {
    pub const INITIALIZE: &str = "initialize";
    pub const INITIALIZED: &str = "notifications/initialized";
    pub const TOOLS_LIST: &str = "tools/list";
    pub const TOOLS_CALL: &str = "tools/call";
    pub const RESOURCES_LIST: &str = "resources/list";
    pub const RESOURCES_READ: &str = "resources/read";
    pub const PROMPTS_LIST: &str = "prompts/list";
    pub const PROMPTS_GET: &str = "prompts/get";
    pub const PING: &str = "ping";
}

/// The JSON-RPC protocol version string MCP uses.
pub const JSONRPC_VERSION: &str = "2.0";

/// A JSON-RPC 2.0 id. A request carries a string or numeric id; notifications
/// omit it entirely (modelled as `Option<Id>` on [`Message`]).
///
/// `untagged` round-trips an id by value, and the gateway correlates responses by
/// exact `Id` equality — so numeric and string ids never collide. Note JSON-RPC
/// permits fractional/oversized numeric ids, which this `i64` variant does not
/// normalize; in practice MCP peers use small integer or string ids.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Id {
    Num(i64),
    Str(String),
}

/// A normalized JSON-RPC 2.0 message — request, response, or notification.
///
/// The shape is deliberately loose (every field optional) so the gateway can
/// forward messages verbatim and only *inspect* `method`/`params` to make a
/// governance decision. It is not a full MCP type model; it is the wire
/// envelope a transport-mux proxy needs.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Message {
    pub jsonrpc: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub id: Option<Id>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub method: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub params: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub error: Option<Value>,
}

impl Message {
    /// A request: has both a `method` and an `id`.
    pub fn request(id: Id, method: impl Into<String>, params: Option<Value>) -> Self {
        Message {
            jsonrpc: JSONRPC_VERSION.to_string(),
            id: Some(id),
            method: Some(method.into()),
            params,
            result: None,
            error: None,
        }
    }

    /// A notification: a `method` with no `id`.
    pub fn notification(method: impl Into<String>, params: Option<Value>) -> Self {
        Message {
            jsonrpc: JSONRPC_VERSION.to_string(),
            id: None,
            method: Some(method.into()),
            params,
            result: None,
            error: None,
        }
    }

    /// A successful response carrying `result`.
    pub fn result(id: Id, value: Value) -> Self {
        Message {
            jsonrpc: JSONRPC_VERSION.to_string(),
            id: Some(id),
            method: None,
            params: None,
            result: Some(value),
            error: None,
        }
    }

    /// A JSON-RPC error response (`error: { code, message }`).
    pub fn error(id: Id, code: i64, message: impl Into<String>) -> Self {
        Message {
            jsonrpc: JSONRPC_VERSION.to_string(),
            id: Some(id),
            method: None,
            params: None,
            result: None,
            error: Some(serde_json::json!({ "code": code, "message": message.into() })),
        }
    }

    /// A `tools/call` *result* with `isError: true`. The gateway uses this for a
    /// policy denial so the model receives a tool-execution error it can
    /// self-correct from, rather than a transport-killing protocol error
    /// (see README "What it does").
    pub fn tool_error_result(id: Id, text: impl Into<String>) -> Self {
        Message::result(
            id,
            serde_json::json!({
                "content": [{ "type": "text", "text": text.into() }],
                "isError": true
            }),
        )
    }

    /// True if this is a request (`method` + `id`).
    pub fn is_request(&self) -> bool {
        self.method.is_some() && self.id.is_some()
    }

    /// True if this is a notification (`method`, no `id`).
    pub fn is_notification(&self) -> bool {
        self.method.is_some() && self.id.is_none()
    }

    /// True if this is a response (`result` or `error`, no `method`).
    pub fn is_response(&self) -> bool {
        self.method.is_none() && (self.result.is_some() || self.error.is_some())
    }

    /// The method name, if any.
    pub fn method(&self) -> Option<&str> {
        self.method.as_deref()
    }

    /// For a `tools/call`, the target tool name (`params.name`).
    pub fn tool_name(&self) -> Option<&str> {
        self.params.as_ref()?.get("name")?.as_str()
    }

    /// Parse one newline-delimited JSON-RPC frame (the stdio wire format).
    pub fn from_json_line(line: &str) -> Result<Self, CoreError> {
        Ok(serde_json::from_str(line)?)
    }

    /// Serialize to a single compact line (no trailing newline) for stdio.
    pub fn to_json_line(&self) -> String {
        // Infallible for this type — all fields are plain JSON values.
        serde_json::to_string(self).expect("Message serializes to JSON")
    }
}

/// A governance decision for a single call.
#[derive(Debug, Clone, PartialEq)]
pub enum Decision {
    Allow,
    Deny { rule: String, reason: String },
}

impl Decision {
    /// The audit `decision` string (`"allow"` / `"deny"`).
    pub fn as_str(&self) -> &'static str {
        match self {
            Decision::Allow => "allow",
            Decision::Deny { .. } => "deny",
        }
    }

    pub fn is_allow(&self) -> bool {
        matches!(self, Decision::Allow)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum CoreError {
    #[error("invalid JSON-RPC frame: {0}")]
    Parse(#[from] serde_json::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_roundtrips_through_a_line() {
        let m = Message::request(
            Id::Num(7),
            method::TOOLS_CALL,
            Some(serde_json::json!({ "name": "delete_repo", "arguments": { "name": "x" } })),
        );
        let line = m.to_json_line();
        assert!(!line.contains('\n'));
        let back = Message::from_json_line(&line).unwrap();
        assert_eq!(back, m);
        assert!(back.is_request());
        assert_eq!(back.method(), Some("tools/call"));
        assert_eq!(back.tool_name(), Some("delete_repo"));
    }

    #[test]
    fn classifies_message_kinds() {
        assert!(Message::notification(method::INITIALIZED, None).is_notification());
        assert!(Message::result(Id::Num(1), serde_json::json!({})).is_response());
        assert!(Message::error(Id::Str("a".into()), -32601, "nope").is_response());
    }

    #[test]
    fn tool_error_result_marks_is_error() {
        let m = Message::tool_error_result(Id::Num(1), "denied by policy");
        assert_eq!(m.result.unwrap()["isError"], serde_json::json!(true));
    }
}
