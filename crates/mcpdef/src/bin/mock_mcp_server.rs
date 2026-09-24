// SPDX-License-Identifier: Apache-2.0
//! A minimal MCP server over stdio, used by `mcpdef`'s integration tests as a
//! real upstream child process. NOT a product component — it exposes a harmless
//! `echo` tool and a `delete_repo` tool (to exercise the deny path).
//!
//! Run with `--modern` and it is a **2026-07-28** server instead: no
//! `initialize`, `server/discover` implemented, and every request required to
//! carry its own `_meta`. That last part is the point — a request that arrives
//! without one is refused, so a test passing against this mock is evidence that
//! MCPdef really did stamp what the revision asks for, rather than evidence that
//! the mock was lenient.

use mcpdef_core::wire::{error_code, meta_key, SPEC_2026_07_28};
use mcpdef_core::{method, Message};
use std::io::{BufRead, Write};

fn main() {
    let modern = std::env::args().any(|a| a == "--modern");
    // A legacy server that simply drops an unknown method rather than answering
    // `-32601`. JSON-RPC requires that error; plenty of servers never send it,
    // and a probe that waits forever for one is a probe that hangs startup.
    let silent_on_discover = std::env::args().any(|a| a == "--silent-on-discover");
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    for line in stdin.lock().lines() {
        let Ok(line) = line else { break };
        if line.trim().is_empty() {
            continue;
        }
        let Ok(msg) = Message::from_json_line(&line) else {
            continue;
        };
        if silent_on_discover && msg.method() == Some(method::SERVER_DISCOVER) {
            continue;
        }
        let resp = if modern {
            handle_modern(&msg)
        } else {
            handle(&msg)
        };
        if let Some(resp) = resp {
            let _ = writeln!(out, "{}", resp.to_json_line());
            let _ = out.flush();
        }
    }
}

/// The 2026-07-28 side of the mock.
///
/// Tools are named `*_v2` so a test can front this server and the legacy one at
/// the same time and tell from the tool name which upstream answered.
fn handle_modern(msg: &Message) -> Option<Message> {
    let id = msg.id.clone()?;

    // Every request must carry its own metadata; there is no handshake it could
    // have come from. Refusing here is what makes the tests meaningful.
    let declared = msg
        .params
        .as_ref()
        .and_then(|p| p.get("_meta"))
        .and_then(|m| m.get(meta_key::PROTOCOL_VERSION))
        .and_then(|v| v.as_str());
    match declared {
        Some(SPEC_2026_07_28) => {}
        Some(other) => {
            return Some(Message::error(
                id,
                error_code::UNSUPPORTED_PROTOCOL_VERSION,
                format!("this server speaks {SPEC_2026_07_28}, not {other}"),
            ))
        }
        None => {
            return Some(Message::error(
                id,
                error_code::HEADER_MISMATCH,
                format!(
                    "every request must carry {} in params._meta",
                    meta_key::PROTOCOL_VERSION
                ),
            ))
        }
    }

    match msg.method() {
        Some(method::INITIALIZE) => Some(Message::error(
            id,
            error_code::METHOD_NOT_FOUND,
            format!("this server speaks {SPEC_2026_07_28}, which has no `initialize`"),
        )),
        Some(method::SERVER_DISCOVER) => Some(Message::result(
            id,
            serde_json::json!({
                "resultType": "complete",
                "supportedVersions": [SPEC_2026_07_28],
                "capabilities": { "tools": {} },
                "_meta": { meta_key::SERVER_INFO: {
                    "name": "mock-mcp-server", "version": "0.0.0"
                } },
            }),
        )),
        Some(method::TOOLS_LIST) => Some(Message::result(
            id,
            serde_json::json!({
                "tools": [
                    { "name": "echo_v2", "description": "echo arguments back",
                      "inputSchema": { "type": "object" } },
                    { "name": "delete_repo_v2", "description": "destructive",
                      "inputSchema": { "type": "object" } }
                ]
            }),
        )),
        Some(method::TOOLS_CALL) => {
            let name = msg.tool_name().unwrap_or_default();
            let args = msg
                .params
                .as_ref()
                .and_then(|p| p.get("arguments"))
                .cloned()
                .unwrap_or_else(|| serde_json::json!({}));
            Some(Message::result(
                id,
                serde_json::json!({
                    "content": [{ "type": "text", "text": format!("{name}: {args}") }],
                    "isError": false
                }),
            ))
        }
        _ => Some(Message::error(
            id,
            error_code::METHOD_NOT_FOUND,
            "unknown method",
        )),
    }
}

fn handle(msg: &Message) -> Option<Message> {
    let id = msg.id.clone();
    match msg.method() {
        Some(method::INITIALIZE) => Some(Message::result(
            id?,
            serde_json::json!({
                "protocolVersion": "2025-11-25",
                "capabilities": { "tools": {} },
                "serverInfo": { "name": "mock-mcp-server", "version": "0.0.0" }
            }),
        )),
        Some(method::INITIALIZED) => None,
        Some(method::TOOLS_LIST) => Some(Message::result(
            id?,
            serde_json::json!({
                "tools": [
                    { "name": "echo", "description": "echo arguments back", "inputSchema": { "type": "object" } },
                    { "name": "delete_repo", "description": "destructive", "inputSchema": { "type": "object" } }
                ]
            }),
        )),
        Some(method::TOOLS_CALL) => {
            let name = msg.tool_name().unwrap_or_default();
            let args = msg
                .params
                .as_ref()
                .and_then(|p| p.get("arguments"))
                .cloned()
                .unwrap_or_else(|| serde_json::json!({}));
            Some(Message::result(
                id?,
                serde_json::json!({
                    "content": [{ "type": "text", "text": format!("{name}: {args}") }],
                    "isError": false
                }),
            ))
        }
        Some(method::PING) => Some(Message::result(id?, serde_json::json!({}))),
        _ => id.map(|i| Message::error(i, -32601, "method not found")),
    }
}
