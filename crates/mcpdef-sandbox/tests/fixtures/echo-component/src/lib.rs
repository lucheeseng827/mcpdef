//! A minimal MCP server as a `wasm32-wasip2` component (test fixture for the
//! mcpdef-sandbox component path). It speaks the gateway's MCP lifecycle over the
//! `mcpdef:server` `handle(string) -> string` interface, and exposes two tools:
//!   * `echo`  — returns its arguments as text.
//!   * `fetch` — attempts a TCP connect to `arguments.addr`, returning whether the
//!     sandbox's egress allowlist permitted it (used to test the egress gate).
wit_bindgen::generate!({ world: "server", path: "../../../wit" });

use serde_json::{json, Value};

struct Component;

fn handle_line(line: &str) -> Option<Value> {
    let req: Value = serde_json::from_str(line).ok()?;
    let id = req.get("id").cloned();
    let method = req.get("method").and_then(|m| m.as_str()).unwrap_or("");
    match method {
        "initialize" => Some(json!({
            "jsonrpc": "2.0", "id": id,
            "result": {
                "protocolVersion": "2025-11-25",
                "capabilities": { "tools": {} },
                "serverInfo": { "name": "echo-component", "version": "0.1.0" }
            }
        })),
        // notification: no response
        "notifications/initialized" => None,
        "tools/list" => Some(json!({
            "jsonrpc": "2.0", "id": id,
            "result": { "tools": [
                { "name": "echo",  "description": "echo the arguments", "inputSchema": { "type": "object" } },
                { "name": "fetch", "description": "attempt an outbound TCP connect to `addr`", "inputSchema": { "type": "object" } }
            ] }
        })),
        "tools/call" => {
            let params = req.get("params").cloned().unwrap_or(json!({}));
            let tool = params.get("name").and_then(|n| n.as_str()).unwrap_or("");
            let args = params.get("arguments").cloned().unwrap_or(json!({}));
            let text = match tool {
                "echo" => format!("echo: {args}"),
                "fetch" => {
                    let addr = args.get("addr").and_then(|a| a.as_str()).unwrap_or("");
                    match std::net::TcpStream::connect(addr) {
                        Ok(_) => "connected".to_string(),
                        Err(e) => format!("egress-error: {:?}", e.kind()),
                    }
                }
                other => format!("unknown tool: {other}"),
            };
            Some(json!({
                "jsonrpc": "2.0", "id": id,
                "result": { "content": [{ "type": "text", "text": text }], "isError": false }
            }))
        }
        _ => Some(json!({
            "jsonrpc": "2.0", "id": id,
            "error": { "code": -32601, "message": format!("method not found: {method}") }
        })),
    }
}

impl exports::mcpdef::server::handler::Guest for Component {
    fn handle(request: String) -> String {
        match handle_line(request.trim()) {
            Some(v) => v.to_string(),
            None => String::new(),
        }
    }
}

export!(Component);
