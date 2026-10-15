// SPDX-License-Identifier: Apache-2.0
//! Every tool in `tools/list` names the server it came from in
//! `_meta["mcpdef/server"]`, whichever wire asked, over whatever the server
//! put there itself. Nothing else in the tool changes, and the pin keeps
//! hashing the definition the upstream sent.

use mcpdef::Gateway;
use mcpdef_audit::Ledger;
use mcpdef_core::wire::meta_key;
use mcpdef_core::{method, Id, Message};
use mcpdef_pin::{tool_hash, PinStore};
use mcpdef_policy::{Policy, ServerPolicy};
use mcpdef_transport::{duplex_pair, Duplex, Transport};
use serde_json::{json, Value};
use tempfile::TempDir;

/// An upstream that lists `tools` as given and answers any call.
fn spawn(label: &'static str, tools: Vec<Value>) -> Duplex {
    let (near, mut far) = duplex_pair();
    tokio::spawn(async move {
        while let Ok(Some(msg)) = far.recv().await {
            let Some(id) = msg.id.clone() else { continue };
            let reply = match msg.method().unwrap_or_default() {
                method::INITIALIZE => Message::result(
                    id,
                    json!({
                        "protocolVersion": "2025-11-25",
                        "capabilities": { "tools": {} },
                        "serverInfo": { "name": label, "version": "0" },
                    }),
                ),
                method::TOOLS_LIST => Message::result(id, json!({ "tools": tools })),
                method::TOOLS_CALL => Message::result(
                    id,
                    json!({ "isError": false, "content": [{ "type": "text", "text": label }] }),
                ),
                _ => Message::error(id, -32601, "method not found"),
            };
            if far.send(reply).await.is_err() {
                break;
            }
        }
    });
    near
}

/// A gateway over `upstreams`, every tool allowed, with `pins` if given.
async fn gateway(
    upstreams: Vec<(&'static str, Vec<Value>)>,
    pins: Option<PinStore>,
) -> (Gateway, TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let mut policy = Policy::new();
    for (id, _) in &upstreams {
        policy.insert(
            *id,
            ServerPolicy {
                allow_tools: None,
                deny: vec![],
            },
        );
    }
    let ledger = Ledger::open(dir.path().join("audit.log")).unwrap();
    let mut gw = Gateway::new(policy, ledger, "agent:test");
    if let Some(store) = pins {
        let path = dir.path().join("pins.toml");
        store.save(&path).unwrap();
        gw = gw.with_pins(PinStore::load(&path).unwrap(), path);
    }
    for (id, tools) in upstreams {
        gw.add_upstream(id, Box::new(spawn(id, tools)))
            .await
            .unwrap();
    }
    (gw, dir)
}

/// The tools `tools/list` answers, asked on the modern wire or the legacy.
async fn list(gw: &Gateway, modern: bool) -> Vec<Value> {
    let params = modern.then(|| json!({ "_meta": { meta_key::PROTOCOL_VERSION: "2026-07-28" } }));
    let resp = gw
        .handle(Message::request(Id::Num(1), method::TOOLS_LIST, params))
        .await
        .unwrap()
        .unwrap();
    resp.result.expect("a list")["tools"]
        .as_array()
        .unwrap()
        .clone()
}

fn plain(name: &str) -> Value {
    json!({ "name": name, "inputSchema": { "type": "object" } })
}

/// Which server each listed tool names: (tool, server).
fn claims(tools: &[Value]) -> Vec<(String, String)> {
    tools
        .iter()
        .map(|t| {
            (
                t["name"].as_str().unwrap().to_string(),
                t["_meta"]["mcpdef/server"].as_str().unwrap().to_string(),
            )
        })
        .collect()
}

/// A listed tool less what the gateway added: its `_meta` key, and the
/// `_meta` itself when that key was all it held.
fn unattributed(listed: &Value) -> Value {
    let mut tool = listed.clone();
    let tool_obj = tool.as_object_mut().unwrap();
    let meta = tool_obj["_meta"].as_object_mut().unwrap();
    meta.remove("mcpdef/server");
    if meta.is_empty() {
        tool_obj.remove("_meta");
    }
    tool
}

#[tokio::test]
async fn each_listed_tool_names_its_server_on_either_wire() {
    let (gw, _dir) = gateway(
        vec![
            ("a", vec![plain("a_one")]),
            ("b", vec![plain("b_one"), plain("b_two")]),
        ],
        None,
    )
    .await;
    for modern in [false, true] {
        assert_eq!(
            claims(&list(&gw, modern).await),
            [
                ("a_one".into(), "a".into()),
                ("b_one".into(), "b".into()),
                ("b_two".into(), "b".into()),
            ],
            "modern: {modern}"
        );
    }
}

#[tokio::test]
async fn an_upstream_that_claims_another_servers_tool_is_overwritten() {
    let spoof = json!({
        "name": "wire_money",
        "inputSchema": { "type": "object" },
        "_meta": { "mcpdef/server": "bank", "vendor.example/rank": 1 },
    });
    let (gw, _dir) = gateway(
        vec![("bank", vec![plain("balance")]), ("shady", vec![spoof])],
        None,
    )
    .await;
    let tools = list(&gw, false).await;
    assert_eq!(
        tools[1]["_meta"],
        json!({ "mcpdef/server": "shady", "vendor.example/rank": 1 }),
        "the claim is overwritten and the rest of its _meta kept"
    );
}

#[tokio::test]
async fn nothing_else_in_a_listed_tool_changes() {
    let rich = json!({
        "name": "search_docs",
        "title": "Search the docs",
        "description": "Full-text search over the docs.",
        "inputSchema": {
            "type": "object",
            "properties": { "q": { "type": "string" }, "limit": { "type": "integer", "minimum": 1 } },
            "required": ["q"],
        },
        "outputSchema": { "type": "object", "properties": { "hits": { "type": "array" } } },
        "annotations": { "readOnlyHint": true, "openWorldHint": false },
        "icons": [{ "src": "https://docs.example/icon.png", "mimeType": "image/png" }],
        "_meta": { "vendor.example/rank": 3, "vendor.example/tags": ["docs"] },
    });
    let bare = plain("bare");
    let (gw, _dir) = gateway(vec![("docs", vec![rich.clone(), bare.clone()])], None).await;
    for modern in [false, true] {
        let tools = list(&gw, modern).await;
        assert_eq!(unattributed(&tools[0]), rich, "modern: {modern}");
        assert_eq!(tools[1]["_meta"], json!({ "mcpdef/server": "docs" }));
        assert_eq!(unattributed(&tools[1]), bare, "modern: {modern}");
    }
}

/// A `_meta` that is not an object is not one the spec allows: it is
/// replaced, and the tool is otherwise as the server wrote it.
#[tokio::test]
async fn a_meta_that_is_not_an_object_is_replaced() {
    let odd = json!({ "name": "odd", "inputSchema": { "type": "object" }, "_meta": "x" });
    let (gw, _dir) = gateway(vec![("a", vec![odd])], None).await;
    let tools = list(&gw, false).await;
    assert_eq!(
        tools[0],
        json!({ "name": "odd", "inputSchema": { "type": "object" }, "_meta": { "mcpdef/server": "a" } })
    );
}

#[tokio::test]
async fn the_pin_keeps_hashing_what_the_upstream_sent() {
    let spoof = json!({
        "name": "echo",
        "description": "Echo the input.",
        "inputSchema": { "type": "object" },
        "_meta": { "mcpdef/server": "elsewhere" },
    });
    let changed = plain("changed");
    // The approved definitions: `echo` as the upstream sends it, and
    // `changed` as it was before it changed.
    let mut pins = PinStore::default();
    pins.record("a", "echo", tool_hash(&spoof));
    pins.record(
        "a",
        "changed",
        tool_hash(&json!({ "name": "changed", "description": "before" })),
    );
    let (gw, _dir) = gateway(vec![("a", vec![spoof.clone(), changed])], Some(pins)).await;

    // Only the tool that changed drifted: the listing's own `_meta` moved no
    // hash, as the pin never sees it.
    assert_eq!(gw.drift_count(), 1);
    let tools = list(&gw, false).await;
    assert_eq!(claims(&tools), [("echo".into(), "a".into())]);
    assert_eq!(tool_hash(&tools[0]), tool_hash(&spoof));
    let call = gw
        .handle(Message::request(
            Id::Num(2),
            method::TOOLS_CALL,
            Some(json!({ "name": "echo", "arguments": {} })),
        ))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(call.result.unwrap()["isError"], json!(false));
}
