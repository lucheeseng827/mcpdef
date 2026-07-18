// SPDX-License-Identifier: Apache-2.0
//! Rug-pull / tool-def pinning integration tests against the real stdio mock
//! upstream. One pre-seeds a pin with the *wrong* hash (so the live tool drifts)
//! and asserts the tool is hidden from `tools/list`, its `tools/call` is denied,
//! and a `rug-pull` is audited. The other exercises trust-on-first-use: a fresh
//! store records the tool, the call is allowed, and the pin persists.

use mcpdef::Gateway;
use mcpdef_audit::{Ledger, Record};
use mcpdef_core::{method, Id, Message};
use mcpdef_pin::PinStore;
use mcpdef_policy::{Policy, ServerPolicy};
use mcpdef_transport::StdioChild;
use serde_json::json;

fn req(id: i64, method: &str, params: Option<serde_json::Value>) -> Message {
    Message::request(Id::Num(id), method, params)
}

fn allow_echo() -> Policy {
    let mut p = Policy::new();
    p.insert(
        "mock",
        ServerPolicy {
            allow_tools: Some(vec!["echo".into()]),
            deny: vec![],
        },
    );
    p
}

fn spawn_mock() -> Box<StdioChild> {
    let bin = env!("CARGO_BIN_EXE_mock_mcp_server").to_string();
    Box::new(StdioChild::spawn(&[bin]).unwrap())
}

fn names_in(list: &Message) -> Vec<String> {
    list.result.as_ref().unwrap()["tools"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|t| t["name"].as_str().map(String::from))
        .collect()
}

#[tokio::test]
async fn rug_pull_drift_hides_tool_denies_call_and_audits() {
    let dir = tempfile::tempdir().unwrap();
    let audit = dir.path().join("audit.log");
    let pins = dir.path().join("pins.toml");

    // Pin `mock/echo` to a hash that does NOT match the mock's live definition,
    // simulating a server that changed the tool after it was approved.
    let mut seed = PinStore::default();
    seed.record("mock", "echo", "deadbeef_not_the_real_hash");
    seed.save(&pins).unwrap();

    let ledger = Ledger::open(&audit).unwrap();
    let store = PinStore::load(&pins).unwrap();
    let mut gw = Gateway::new(allow_echo(), ledger, "agent:test").with_pins(store, pins.clone());
    gw.add_upstream("mock", spawn_mock()).await.unwrap();

    // Connect detected the drift.
    assert_eq!(gw.drift_count(), 1, "echo should be flagged as drifted");

    // The drifted tool is hidden from tools/list…
    let list = gw
        .handle(req(2, method::TOOLS_LIST, None))
        .await
        .unwrap()
        .unwrap();
    assert!(
        !names_in(&list).contains(&"echo".to_string()),
        "a rug-pulled tool must not be offered"
    );

    // …and its call is denied with a tool-error result.
    let deny = gw
        .handle(req(
            3,
            method::TOOLS_CALL,
            Some(json!({"name":"echo","arguments":{}})),
        ))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(deny.result.as_ref().unwrap()["isError"], json!(true));

    drop(gw);

    // The denial was audited with rule "rug-pull".
    let content = std::fs::read_to_string(&audit).unwrap();
    let recs: Vec<Record> = content
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    let rug = recs
        .iter()
        .find(|r| r.rule.as_deref() == Some("rug-pull"))
        .expect("a rug-pull audit record");
    assert_eq!(rug.tool.as_deref(), Some("echo"));
    assert_eq!(rug.decision, "deny");
}

#[tokio::test]
async fn trust_on_first_use_records_pin_and_allows() {
    let dir = tempfile::tempdir().unwrap();
    let audit = dir.path().join("audit.log");
    let pins = dir.path().join("pins.toml"); // does not exist yet

    let ledger = Ledger::open(&audit).unwrap();
    let store = PinStore::load(&pins).unwrap(); // empty (missing file)
    let mut gw = Gateway::new(allow_echo(), ledger, "agent:test").with_pins(store, pins.clone());
    gw.add_upstream("mock", spawn_mock()).await.unwrap();

    // First sight of every tool — nothing drifts.
    assert_eq!(gw.drift_count(), 0);
    gw.persist_pins().unwrap();

    // echo is exposed and the call is allowed (forwarded to the mock).
    let list = gw
        .handle(req(2, method::TOOLS_LIST, None))
        .await
        .unwrap()
        .unwrap();
    assert!(names_in(&list).contains(&"echo".to_string()));
    let allow = gw
        .handle(req(
            3,
            method::TOOLS_CALL,
            Some(json!({"name":"echo","arguments":{"msg":"hi"}})),
        ))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(allow.result.as_ref().unwrap()["isError"], json!(false));

    drop(gw);

    // The pin store was written and now records mock/echo.
    let reloaded = PinStore::load(&pins).unwrap();
    assert!(
        reloaded.pinned_hash("mock", "echo").is_some(),
        "TOFU should have persisted the echo pin"
    );
}
