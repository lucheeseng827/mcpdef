// SPDX-License-Identifier: Apache-2.0
//! Regression test: the audit identity is computed per request and never stored
//! on the long-lived `Gateway`, so an authenticated caller's subject cannot leak
//! into the audit record of a later (unauthenticated) request handled by the same
//! gateway instance. (A misattribution in a tamper-evident ledger is an integrity
//! bug.)

use mcpdef::Gateway;
use mcpdef_audit::{Ledger, Record};
use mcpdef_auth::Principal;
use mcpdef_core::{method, Id, Message};
use mcpdef_policy::{Policy, ServerPolicy};
use mcpdef_transport::StdioChild;

fn call(id: i64, tool: &str) -> Message {
    Message::request(
        Id::Num(id),
        method::TOOLS_CALL,
        Some(serde_json::json!({ "name": tool, "arguments": {} })),
    )
}

fn principal(subject: &str) -> Principal {
    Principal {
        subject: subject.into(),
        scopes: vec![],
        roles: vec![],
        client_id: None,
        issuer: "https://auth.example.com".into(),
    }
}

#[tokio::test]
async fn audit_identity_is_per_request_and_does_not_leak() {
    let dir = tempfile::tempdir().unwrap();
    let audit_path = dir.path().join("audit.log");

    let mut policy = Policy::new();
    policy.insert(
        "mock",
        ServerPolicy {
            allow_tools: Some(vec!["echo".into()]),
            deny: vec![],
        },
    );
    let ledger = Ledger::open(&audit_path).unwrap();
    // Baseline identity for unauthenticated requests.
    let mut gw = Gateway::new(policy, ledger, "agent:baseline");

    let bin = env!("CARGO_BIN_EXE_mock_mcp_server").to_string();
    gw.add_upstream("mock", Box::new(StdioChild::spawn(&[bin]).unwrap()))
        .await
        .unwrap();

    // 1. An authenticated call as `alice` → audited under `sub:alice`.
    let alice = principal("alice");
    gw.handle_authed(call(1, "echo"), Some(&alice))
        .await
        .unwrap()
        .unwrap();

    // 2. A subsequent UNAUTHENTICATED call on the same gateway → must be audited
    //    under the baseline identity, NOT alice's (the leak this guards against).
    gw.handle_authed(call(2, "echo"), None)
        .await
        .unwrap()
        .unwrap();

    drop(gw); // flush the ledger

    let content = std::fs::read_to_string(&audit_path).unwrap();
    let recs: Vec<Record> = content
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(recs.len(), 2);
    assert_eq!(recs[0].agent, "sub:alice", "first call is alice's");
    assert_eq!(
        recs[1].agent, "agent:baseline",
        "unauthenticated call must NOT inherit alice's identity"
    );
}
