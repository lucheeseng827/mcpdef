// SPDX-License-Identifier: Apache-2.0
//! `[[server]] deny` globs, from a config file through the gateway.
//!
//! A regression test for a fail-open. `*` used to work only as a pattern's first
//! or last character, so `deny = ["*delete*"]` on a server with no `tools`
//! allowlist denied nothing, and every delete tool stayed callable.

use mcpdef::{Config, Gateway};
use mcpdef_audit::{Ledger, Record};
use mcpdef_core::{method, Id, Message};
use mcpdef_transport::{duplex_pair, Transport};
use serde_json::json;
use std::sync::{Arc, Mutex};

const CONFIG: &str = r#"
[gateway]

[[server]]
id        = "fs"
transport = "stdio"
command   = ["unused-the-test-supplies-the-upstream"]
deny      = ["*delete*", "get_*_secret"]
"#;

const TOOLS: [&str; 7] = [
    "read_file",
    "get_file_info",
    "delete_file",
    "rm_delete_all",
    "delete",
    "get_api_secret",
    "get_secret",
];

/// An upstream offering [`TOOLS`] that records every `tools/call` it runs.
fn spawn_upstream(ran: Arc<Mutex<Vec<String>>>) -> mcpdef_transport::Duplex {
    let (near, mut far) = duplex_pair();
    tokio::spawn(async move {
        while let Ok(Some(msg)) = far.recv().await {
            let Some(id) = msg.id.clone() else { continue };
            let reply = match msg.method() {
                Some(method::INITIALIZE) => Message::result(
                    id,
                    json!({
                        "protocolVersion": "2025-11-25",
                        "capabilities": { "tools": {} },
                        "serverInfo": { "name": "fs", "version": "0.0.0" },
                    }),
                ),
                Some(method::TOOLS_LIST) => {
                    let tools: Vec<_> = TOOLS
                        .iter()
                        .map(|n| json!({ "name": n, "inputSchema": { "type": "object" } }))
                        .collect();
                    Message::result(id, json!({ "tools": tools }))
                }
                Some(method::TOOLS_CALL) => {
                    ran.lock()
                        .unwrap()
                        .push(msg.tool_name().unwrap_or_default().to_string());
                    Message::result(
                        id,
                        json!({ "isError": false, "content": [{ "type": "text", "text": "ran" }] }),
                    )
                }
                _ => Message::result(id, json!({})),
            };
            if far.send(reply).await.is_err() {
                break;
            }
        }
    });
    near
}

fn call(tool: &str) -> Message {
    Message::request(
        Id::Num(1),
        method::TOOLS_CALL,
        Some(json!({ "name": tool, "arguments": {} })),
    )
}

fn is_error(resp: &Message) -> bool {
    resp.result.as_ref().unwrap()["isError"] == json!(true)
}

#[tokio::test]
async fn a_deny_starred_at_both_ends_denies_on_a_server_with_no_allowlist() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("mcpdef.toml");
    std::fs::write(&config, CONFIG).unwrap();
    let cfg = Config::load(&config).unwrap();
    assert_eq!(cfg.validate(), Vec::<String>::new());
    assert!(
        cfg.servers[0].tools.is_none(),
        "the scenario has no allowlist"
    );

    let audit = dir.path().join("audit.log");
    let ran = Arc::new(Mutex::new(Vec::new()));
    let mut gw = Gateway::new(cfg.to_policy(), Ledger::open(&audit).unwrap(), "agent:test");
    gw.add_upstream("fs", Box::new(spawn_upstream(Arc::clone(&ran))))
        .await
        .unwrap();

    // Denied tools are not offered.
    let list = gw
        .handle(Message::request(Id::Num(1), method::TOOLS_LIST, None))
        .await
        .unwrap()
        .unwrap();
    let offered: Vec<&str> = list.result.as_ref().unwrap()["tools"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|t| t["name"].as_str())
        .collect();
    assert_eq!(offered, ["read_file", "get_file_info", "get_secret"]);

    // And calling one anyway is refused, and never reaches the upstream.
    let denied = ["delete_file", "rm_delete_all", "delete", "get_api_secret"];
    for tool in denied {
        let resp = gw.handle(call(tool)).await.unwrap().unwrap();
        assert!(is_error(&resp), "{tool} must be denied");
    }
    for tool in ["read_file", "get_secret"] {
        let resp = gw.handle(call(tool)).await.unwrap().unwrap();
        assert!(!is_error(&resp), "{tool} must be allowed");
    }
    assert_eq!(*ran.lock().unwrap(), ["read_file", "get_secret"]);

    drop(gw);
    let records: Vec<Record> = std::fs::read_to_string(&audit)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    let deny_globs: Vec<_> = records
        .iter()
        .filter(|r| r.rule.as_deref() == Some("deny-glob"))
        .map(|r| r.tool.as_deref().unwrap_or_default())
        .collect();
    assert_eq!(deny_globs, denied);
}
