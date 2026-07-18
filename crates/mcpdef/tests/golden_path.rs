// SPDX-License-Identifier: Apache-2.0
//! Golden-path integration test (ROADMAP Phase 1 exit criteria): a real stdio
//! upstream child process, an allowed call passes, a denied call is blocked and
//! audited, the denied tool is hidden from `tools/list`, and the audit ledger is
//! hash-linked and verifies.

use mcpdef::Gateway;
use mcpdef_audit::{verify, Ledger, Record};
use mcpdef_core::{method, Id, Message};
use mcpdef_policy::{Policy, ServerPolicy};
use mcpdef_transport::StdioChild;

fn req(id: i64, method: &str, params: Option<serde_json::Value>) -> Message {
    Message::request(Id::Num(id), method, params)
}

#[tokio::test]
async fn golden_path_allow_deny_list_filtering_and_audit_chain() {
    let dir = tempfile::tempdir().unwrap();
    let audit_path = dir.path().join("audit.log");

    // Policy: the "mock" server allows `echo`, denies `delete_*`.
    let mut policy = Policy::new();
    policy.insert(
        "mock",
        ServerPolicy {
            allow_tools: Some(vec!["echo".into()]),
            deny: vec!["delete_*".into()],
        },
    );

    let ledger = Ledger::open(&audit_path).unwrap();
    let mut gw = Gateway::new(policy, ledger, "agent:test");

    // Spawn the mock upstream as a real stdio child process.
    let bin = env!("CARGO_BIN_EXE_mock_mcp_server").to_string();
    let upstream = StdioChild::spawn(&[bin]).unwrap();
    gw.add_upstream("mock", Box::new(upstream)).await.unwrap();
    assert_eq!(gw.upstream_count(), 1);

    // Client initialize → gateway responds itself.
    let init = gw
        .handle(req(
            1,
            method::INITIALIZE,
            Some(serde_json::json!({ "clientInfo": { "name": "test-agent" } })),
        ))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(init.result.unwrap()["serverInfo"]["name"], "mcpdef");

    // tools/list aggregates the upstream's tools but hides the denied delete_repo.
    let list = gw
        .handle(req(2, method::TOOLS_LIST, None))
        .await
        .unwrap()
        .unwrap();
    let names: Vec<String> = list.result.unwrap()["tools"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|t| t["name"].as_str().map(String::from))
        .collect();
    assert!(
        names.contains(&"echo".to_string()),
        "echo should be exposed"
    );
    assert!(
        !names.contains(&"delete_repo".to_string()),
        "denied delete_repo must be hidden from tools/list"
    );

    // Allowed call: echo → forwarded to upstream, isError:false, id preserved.
    let allow = gw
        .handle(req(
            3,
            method::TOOLS_CALL,
            Some(serde_json::json!({ "name": "echo", "arguments": { "msg": "hi" } })),
        ))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(allow.id, Some(Id::Num(3)));
    assert_eq!(
        allow.result.as_ref().unwrap()["isError"],
        serde_json::json!(false)
    );

    // Denied call: delete_repo → blocked before dispatch, tool-error result.
    let deny = gw
        .handle(req(
            4,
            method::TOOLS_CALL,
            Some(serde_json::json!({ "name": "delete_repo", "arguments": {} })),
        ))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(deny.id, Some(Id::Num(4)));
    assert_eq!(
        deny.result.as_ref().unwrap()["isError"],
        serde_json::json!(true)
    );

    drop(gw); // flush/close the ledger and kill the child

    // The audit ledger recorded exactly the two tools/call (allow then deny),
    // and the hash chain verifies.
    let report = verify(&audit_path).unwrap();
    assert!(report.ok(), "audit chain must verify: {report:?}");

    let content = std::fs::read_to_string(&audit_path).unwrap();
    let recs: Vec<Record> = content
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(recs.len(), 2, "two governed tools/call expected");

    assert_eq!(recs[0].decision, "allow");
    assert_eq!(recs[0].tool.as_deref(), Some("echo"));
    assert_eq!(recs[0].agent, "agent:test-agent"); // captured from initialize

    assert_eq!(recs[1].decision, "deny");
    assert_eq!(recs[1].tool.as_deref(), Some("delete_repo"));
    assert_eq!(recs[1].rule.as_deref(), Some("deny-glob"));

    // The chain links the two records.
    assert_eq!(recs[1].prev_hash, recs[0].hash);
}
