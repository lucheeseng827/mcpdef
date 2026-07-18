// SPDX-License-Identifier: Apache-2.0
//! A minimal MCP server over stdio, used by `mcpdef`'s integration test as a real
//! upstream child process. NOT a product component — it exposes a harmless
//! `echo` tool and a `delete_repo` tool (to exercise the deny path).

use mcpdef_core::{method, Message};
use std::io::{BufRead, Write};

fn main() {
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
        if let Some(resp) = handle(&msg) {
            let _ = writeln!(out, "{}", resp.to_json_line());
            let _ = out.flush();
        }
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
