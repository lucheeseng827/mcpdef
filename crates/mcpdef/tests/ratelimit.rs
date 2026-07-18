// SPDX-License-Identifier: Apache-2.0
//! Availability-control integration tests (ARCHITECTURE.md §5b): the token-bucket
//! rate limiter sheds a flood of `tools/call` (and audits it), and the per-call
//! upstream timeout fails a wedged upstream instead of hanging the gateway.

use mcpdef::Gateway;
use mcpdef_audit::{Ledger, Record};
use mcpdef_core::{method, Id, Message};
use mcpdef_policy::{Policy, ServerPolicy};
use mcpdef_transport::{duplex_pair, StdioChild, Transport};
use serde_json::json;
use std::time::Duration;

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

fn is_error(m: &Message) -> bool {
    m.result
        .as_ref()
        .and_then(|r| r["isError"].as_bool())
        .unwrap_or(false)
}

fn read_records(path: &std::path::Path) -> Vec<Record> {
    std::fs::read_to_string(path)
        .unwrap()
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}

#[tokio::test]
async fn rate_limit_sheds_a_flood_and_audits_it() {
    let dir = tempfile::tempdir().unwrap();
    let audit = dir.path().join("audit.log");
    let ledger = Ledger::open(&audit).unwrap();

    // Per-tool bucket: capacity 2, ~no refill within the test window → exactly the
    // first two `echo` calls pass, the rest are shed.
    let mut gw =
        Gateway::new(allow_echo(), ledger, "agent:test").with_rate_limit(Some((0.001, 2.0)), None);
    gw.add_upstream("mock", spawn_mock()).await.unwrap();

    let call = |id| {
        req(
            id,
            method::TOOLS_CALL,
            Some(json!({"name":"echo","arguments":{"msg":"x"}})),
        )
    };

    // First two are allowed (forwarded; the mock echoes isError:false).
    let r1 = gw.handle(call(1)).await.unwrap().unwrap();
    let r2 = gw.handle(call(2)).await.unwrap().unwrap();
    assert!(
        !is_error(&r1) && !is_error(&r2),
        "first two calls within burst must pass"
    );

    // The third is rate-limited (a tool-error result, not forwarded).
    let r3 = gw.handle(call(3)).await.unwrap().unwrap();
    assert!(is_error(&r3), "third call must be shed");

    drop(gw);

    let recs = read_records(&audit);
    let limited = recs
        .iter()
        .find(|r| r.rule.as_deref() == Some("rate-limited"));
    assert!(limited.is_some(), "a rate-limited call must be audited");
    assert_eq!(limited.unwrap().tool.as_deref(), Some("echo"));
    // The two allowed calls were also recorded (allow), so 3 governed records total.
    assert_eq!(
        recs.iter()
            .filter(|r| r.tool.as_deref() == Some("echo"))
            .count(),
        3
    );
}

/// A mock upstream that completes the handshake but NEVER answers `tools/call`,
/// holding the connection open so the gateway must time out rather than block.
async fn silent_upstream(mut server: Box<dyn Transport>) {
    while let Ok(Some(m)) = server.recv().await {
        match m.method() {
            Some(method::INITIALIZE) => {
                let id = m.id.clone().unwrap();
                let _ = server
                    .send(Message::result(
                        id,
                        json!({"protocolVersion":"2025-11-25","capabilities":{},"serverInfo":{"name":"silent"}}),
                    ))
                    .await;
            }
            Some(method::TOOLS_LIST) => {
                let id = m.id.clone().unwrap();
                let _ = server
                    .send(Message::result(
                        id,
                        json!({"tools":[{"name":"echo","description":"e","inputSchema":{"type":"object"}}]}),
                    ))
                    .await;
            }
            // tools/call and notifications: deliberately no response.
            _ => {}
        }
    }
}

#[tokio::test]
async fn upstream_timeout_fails_a_wedged_call_instead_of_hanging() {
    let dir = tempfile::tempdir().unwrap();
    let audit = dir.path().join("audit.log");
    let ledger = Ledger::open(&audit).unwrap();

    let (client, server) = duplex_pair();
    tokio::spawn(silent_upstream(Box::new(server)));

    let mut gw = Gateway::new(allow_echo(), ledger, "agent:test")
        .with_upstream_timeout(Some(Duration::from_millis(50)));
    gw.add_upstream("mock", Box::new(client)).await.unwrap();

    // The call must return (not hang) with a timeout error, well under a watchdog.
    let resp = tokio::time::timeout(
        Duration::from_secs(5),
        gw.handle(req(
            1,
            method::TOOLS_CALL,
            Some(json!({"name":"echo","arguments":{}})),
        )),
    )
    .await
    .expect("gateway must not hang on a wedged upstream")
    .unwrap()
    .unwrap();
    assert!(
        is_error(&resp),
        "a timed-out call returns a tool-error result"
    );

    drop(gw);
    let recs = read_records(&audit);
    assert!(
        recs.iter()
            .any(|r| r.rule.as_deref() == Some("upstream-timeout")),
        "the timeout must be audited"
    );
}
