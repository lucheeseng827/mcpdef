// SPDX-License-Identifier: Apache-2.0
//! Mock MCP upstreams the harness puts behind the gateway.
//!
//! Two transports, one behaviour. [`respond`] decides what a message gets back and
//! how long the reply waits; [`spawn_http`] serves that over Streamable HTTP from
//! inside the harness, and [`run_stdio`] serves it over stdio when the harness
//! binary is spawned *by the gateway* as an upstream (`mcpdef-bench mock-stdio`).
//! Keeping the decision in one place means an HTTP run and a stdio run differ
//! only in transport, which is the comparison the slow-neighbour scenario makes.

use anyhow::Result;
use axum::{
    extract::State,
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    routing::post,
    Router,
};
use serde_json::{json, Value};
use std::io::{BufRead, Write};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

/// The revision the mocks answer `initialize` with: the gateway's default era.
const PROTOCOL_VERSION: &str = "2025-11-25";

/// One tool a mock exposes, and how long a call to it takes to answer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MockTool {
    pub name: String,
    pub delay: Duration,
}

impl MockTool {
    /// A tool that answers at once.
    pub fn fast(name: impl Into<String>) -> Self {
        MockTool {
            name: name.into(),
            delay: Duration::ZERO,
        }
    }

    /// A tool that takes `delay` before answering — the slow neighbour.
    pub fn slow(name: impl Into<String>, delay: Duration) -> Self {
        MockTool {
            name: name.into(),
            delay,
        }
    }
}

/// What the mock does with one message: `None` for a notification (nothing is
/// sent back), otherwise the reply and how long to wait before sending it.
pub fn respond(tools: &[MockTool], msg: &Value) -> Option<(Value, Duration)> {
    // A notification carries no id and gets no reply (`notifications/initialized`).
    let id = msg.get("id")?;
    let method = msg
        .get("method")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let ok = |result: Value| json!({ "jsonrpc": "2.0", "id": id, "result": result });
    let err = |code: i64, message: &str| json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } });
    let reply = match method {
        "initialize" => ok(json!({
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": { "tools": {} },
            "serverInfo": { "name": "mcpdef-bench-mock", "version": env!("CARGO_PKG_VERSION") }
        })),
        "tools/list" => ok(json!({
            "tools": tools
                .iter()
                .map(|t| json!({
                    "name": t.name,
                    "description": "benchmark tool",
                    "inputSchema": { "type": "object" }
                }))
                .collect::<Vec<_>>()
        })),
        "tools/call" => {
            let name = msg
                .pointer("/params/name")
                .and_then(Value::as_str)
                .unwrap_or_default();
            return Some(match tools.iter().find(|t| t.name == name) {
                Some(t) => (
                    ok(json!({ "content": [{ "type": "text", "text": "ok" }], "isError": false })),
                    t.delay,
                ),
                None => (err(-32602, "unknown tool"), Duration::ZERO),
            });
        }
        "ping" => ok(json!({})),
        _ => err(-32601, "method not found"),
    };
    Some((reply, Duration::ZERO))
}

/// A mock upstream serving Streamable HTTP on a loopback port: one JSON-RPC
/// message per `POST /mcp`, answered with a single `application/json` body, or
/// `202 Accepted` for a notification. Stops when dropped.
pub struct HttpMock {
    pub url: String,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for HttpMock {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Start an HTTP mock exposing `tools`.
pub async fn spawn_http(tools: Vec<MockTool>) -> Result<HttpMock> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let app = Router::new()
        .route("/mcp", post(handle_http))
        .with_state(Arc::new(tools));
    let task = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    Ok(HttpMock {
        url: format!("http://{addr}/mcp"),
        task,
    })
}

async fn handle_http(State(tools): State<Arc<Vec<MockTool>>>, body: String) -> Response {
    let Ok(msg) = serde_json::from_str::<Value>(&body) else {
        return (StatusCode::BAD_REQUEST, "invalid JSON").into_response();
    };
    match respond(&tools, &msg) {
        Some((reply, delay)) => {
            if !delay.is_zero() {
                tokio::time::sleep(delay).await;
            }
            (
                [(header::CONTENT_TYPE, "application/json")],
                reply.to_string(),
            )
                .into_response()
        }
        None => StatusCode::ACCEPTED.into_response(),
    }
}

/// Serve `tools` over stdio until stdin closes — the upstream the gateway spawns
/// for the stdio scenarios.
///
/// A delayed call is answered from its own thread, so a slow tool never holds up
/// the next message on the same connection: replies can leave out of order, which
/// JSON-RPC allows and a gateway that multiplexes an upstream has to handle.
pub fn run_stdio(tools: Vec<MockTool>) -> Result<()> {
    let stdout = Arc::new(Mutex::new(std::io::stdout()));
    for line in std::io::stdin().lock().lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let Ok(msg) = serde_json::from_str::<Value>(&line) else {
            continue;
        };
        let Some((reply, delay)) = respond(&tools, &msg) else {
            continue;
        };
        if delay.is_zero() {
            write_line(&stdout, &reply);
        } else {
            let out = Arc::clone(&stdout);
            std::thread::spawn(move || {
                std::thread::sleep(delay);
                write_line(&out, &reply);
            });
        }
    }
    Ok(())
}

/// One reply per line, written whole: the lock keeps two threads' replies from
/// interleaving inside a line.
fn write_line(out: &Mutex<std::io::Stdout>, reply: &Value) {
    let mut out = out.lock().unwrap_or_else(PoisonError::into_inner);
    let _ = writeln!(out, "{reply}");
    let _ = out.flush();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tools() -> Vec<MockTool> {
        vec![
            MockTool::fast("echo"),
            MockTool::slow("nap", Duration::from_millis(7)),
        ]
    }

    #[test]
    fn a_notification_gets_no_reply() {
        let msg = json!({ "jsonrpc": "2.0", "method": "notifications/initialized" });
        assert!(respond(&tools(), &msg).is_none());
    }

    #[test]
    fn initialize_answers_the_gateways_default_era() {
        let msg = json!({ "jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {} });
        let (reply, delay) = respond(&tools(), &msg).unwrap();
        assert_eq!(reply["result"]["protocolVersion"], PROTOCOL_VERSION);
        assert_eq!(reply["id"], 1);
        assert!(delay.is_zero());
    }

    #[test]
    fn tools_list_names_every_tool() {
        let msg = json!({ "jsonrpc": "2.0", "id": "a", "method": "tools/list" });
        let (reply, _) = respond(&tools(), &msg).unwrap();
        let names: Vec<_> = reply["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["name"].as_str().unwrap().to_string())
            .collect();
        assert_eq!(names, ["echo", "nap"]);
    }

    #[test]
    fn a_call_waits_for_its_tools_delay() {
        let call = |name: &str| {
            json!({ "jsonrpc": "2.0", "id": 9, "method": "tools/call",
                    "params": { "name": name, "arguments": {} } })
        };
        let (reply, delay) = respond(&tools(), &call("nap")).unwrap();
        assert_eq!(reply["result"]["isError"], false);
        assert_eq!(delay, Duration::from_millis(7));
        let (reply, delay) = respond(&tools(), &call("missing")).unwrap();
        assert_eq!(reply["error"]["code"], -32602);
        assert!(delay.is_zero());
    }

    #[test]
    fn an_unknown_method_is_method_not_found() {
        let msg = json!({ "jsonrpc": "2.0", "id": 2, "method": "resources/list" });
        let (reply, _) = respond(&tools(), &msg).unwrap();
        assert_eq!(reply["error"]["code"], -32601);
    }
}
