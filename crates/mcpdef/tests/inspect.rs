// SPDX-License-Identifier: Apache-2.0
//! Inline injection / secret-exfil scanning (`[gateway.inspect]`) against the real
//! stdio mock upstream. The mock's `echo` returns its arguments in the tool
//! result, so smuggling a credential through the arguments makes the tool "leak" a
//! secret in its response — which the inspector must catch on the way back to the
//! model. Covers: enforce blocks + audits `secret-exfil` (and the secret is not
//! echoed in the block message), warn passes through (no deny), and a clean result
//! is unaffected.

use mcpdef::Gateway;
use mcpdef_audit::{Ledger, Record};
use mcpdef_core::{method, Id, Message};
use mcpdef_inspect::{Mode, Scanner};
use mcpdef_policy::{Policy, ServerPolicy};
use mcpdef_transport::StdioChild;
use serde_json::json;

// A well-formed AWS access-key id shape (AKIA + 16 upper-alnum) — a canonical
// secret to exfiltrate. Not a real credential.
const LEAKED_KEY: &str = "AKIAIOSFODNN7EXAMPLE";

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

fn read_records(path: &std::path::Path) -> Vec<Record> {
    std::fs::read_to_string(path)
        .unwrap()
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}

/// Build a gateway fronting the mock with `echo` allowed and inspect in `mode`.
async fn gw_with_inspect(audit: &std::path::Path, mode: Mode) -> Gateway {
    let ledger = Ledger::open(audit).unwrap();
    let mut gw = Gateway::new(allow_echo(), ledger, "agent:test").with_inspect(Scanner::new(mode));
    gw.add_upstream("mock", spawn_mock()).await.unwrap();
    gw
}

/// Call `echo`, which returns `arguments` in its result — so `leak` shows up in
/// the tool response text.
fn echo_leaking(id: i64) -> Message {
    req(
        id,
        method::TOOLS_CALL,
        Some(json!({ "name": "echo", "arguments": { "leak": LEAKED_KEY } })),
    )
}

#[tokio::test]
async fn secret_in_result_is_blocked_and_audited_in_enforce() {
    let dir = tempfile::tempdir().unwrap();
    let audit = dir.path().join("audit.log");
    let mut gw = gw_with_inspect(&audit, Mode::Enforce).await;

    let resp = gw.handle(echo_leaking(3)).await.unwrap().unwrap();

    // The result is refused as a tool error — the secret never reaches the client.
    assert_eq!(resp.result.as_ref().unwrap()["isError"], json!(true));
    let text = resp.result.as_ref().unwrap()["content"][0]["text"]
        .as_str()
        .unwrap_or("");
    assert!(
        text.contains("blocked"),
        "expected an inspect block, got: {text}"
    );
    // The block message must not itself echo the secret it caught.
    assert!(
        !text.contains(LEAKED_KEY),
        "the blocked secret must not leak in the error message: {text}"
    );

    drop(gw);
    let recs = read_records(&audit);
    let hit = recs
        .iter()
        .find(|r| r.rule.as_deref() == Some("secret-exfil"))
        .expect("a secret-exfil audit record");
    assert_eq!(hit.decision, "deny");
    assert_eq!(hit.tool.as_deref(), Some("echo"));
}

#[tokio::test]
async fn secret_in_result_passes_through_in_warn() {
    let dir = tempfile::tempdir().unwrap();
    let audit = dir.path().join("audit.log");
    let mut gw = gw_with_inspect(&audit, Mode::Warn).await;

    let resp = gw.handle(echo_leaking(3)).await.unwrap().unwrap();

    // Warn observes but does not block: the echo result returns normally.
    assert_eq!(resp.result.as_ref().unwrap()["isError"], json!(false));

    drop(gw);
    let recs = read_records(&audit);
    assert!(
        recs.iter()
            .all(|r| r.rule.as_deref() != Some("secret-exfil")),
        "warn mode must not record a deny"
    );
    assert!(
        recs.iter()
            .any(|r| r.tool.as_deref() == Some("echo") && r.decision == "allow"),
        "the call should still be audited as allowed"
    );
}

#[tokio::test]
async fn clean_result_is_unaffected_in_enforce() {
    let dir = tempfile::tempdir().unwrap();
    let audit = dir.path().join("audit.log");
    let mut gw = gw_with_inspect(&audit, Mode::Enforce).await;

    // An ordinary echo (no secret / injection) is allowed straight through.
    let resp = gw
        .handle(req(
            3,
            method::TOOLS_CALL,
            Some(json!({ "name": "echo", "arguments": { "msg": "hello" } })),
        ))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(resp.result.as_ref().unwrap()["isError"], json!(false));
}
