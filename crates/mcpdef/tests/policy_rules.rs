// SPDX-License-Identifier: Apache-2.0
//! Policy-as-code (`[[policy]]`) integration tests against the real stdio mock
//! upstream. The mock's `echo` is on the allowlist, so these exercise the richer
//! gate the rule engine adds *after* the allowlist: a per-argument deny (block
//! `echo` when an argument names a `prod-*` target), the audit under the rule's
//! own name, the allow path when the argument doesn't match, and the no-op when no
//! rules are configured.

use mcpdef::Gateway;
use mcpdef_audit::{Ledger, Record};
use mcpdef_core::{method, Id, Message};
use mcpdef_policy::{ArgMatch, ArgOp, Effect, Policy, PolicyRules, Rule, ServerPolicy};
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

fn read_records(path: &std::path::Path) -> Vec<Record> {
    std::fs::read_to_string(path)
        .unwrap()
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}

/// Deny `echo` when `args.target` is a `prod-*` value — the allowlist permits
/// `echo`, so only the policy engine can make this distinction.
fn no_echo_prod() -> PolicyRules {
    PolicyRules::new(vec![Rule {
        name: "no-echo-prod".into(),
        effect: Effect::Deny,
        agents: None,
        servers: None,
        tools: Some(vec!["echo".into()]),
        args: vec![ArgMatch {
            path: "target".into(),
            op: ArgOp::Glob("prod-*".into()),
        }],
    }])
}

async fn gw(audit: &std::path::Path, rules: PolicyRules) -> Gateway {
    let ledger = Ledger::open(audit).unwrap();
    let mut gw = Gateway::new(allow_echo(), ledger, "agent:test").with_policy_rules(rules);
    gw.add_upstream("mock", spawn_mock()).await.unwrap();
    gw
}

fn echo(target: &str) -> Message {
    req(
        1,
        method::TOOLS_CALL,
        Some(json!({ "name": "echo", "arguments": { "target": target } })),
    )
}

#[tokio::test]
async fn policy_denies_matching_arg_and_audits_the_rule_name() {
    let dir = tempfile::tempdir().unwrap();
    let audit = dir.path().join("audit.log");
    let mut gw = gw(&audit, no_echo_prod()).await;

    let resp = gw.handle(echo("prod-db")).await.unwrap().unwrap();

    assert_eq!(resp.result.as_ref().unwrap()["isError"], json!(true));
    let text = resp.result.as_ref().unwrap()["content"][0]["text"]
        .as_str()
        .unwrap_or("");
    assert!(
        text.contains("denied"),
        "expected a policy denial, got: {text}"
    );

    drop(gw);
    let recs = read_records(&audit);
    let hit = recs
        .iter()
        .find(|r| r.rule.as_deref() == Some("no-echo-prod"))
        .expect("a policy-rule audit record");
    assert_eq!(hit.decision, "deny");
    assert_eq!(hit.tool.as_deref(), Some("echo"));
}

#[tokio::test]
async fn policy_allows_when_the_arg_does_not_match() {
    let dir = tempfile::tempdir().unwrap();
    let audit = dir.path().join("audit.log");
    let mut gw = gw(&audit, no_echo_prod()).await;

    // A non-prod target does not match the rule → the call is forwarded to the mock.
    let resp = gw.handle(echo("dev-sandbox")).await.unwrap().unwrap();
    assert_eq!(resp.result.as_ref().unwrap()["isError"], json!(false));
}

#[tokio::test]
async fn no_policy_rules_is_a_passthrough() {
    let dir = tempfile::tempdir().unwrap();
    let audit = dir.path().join("audit.log");
    // Even a prod-* target is allowed when no rules are configured.
    let mut gw = gw(&audit, PolicyRules::default()).await;
    let resp = gw.handle(echo("prod-db")).await.unwrap().unwrap();
    assert_eq!(resp.result.as_ref().unwrap()["isError"], json!(false));
}
