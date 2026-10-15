// SPDX-License-Identifier: Apache-2.0
//! `transform` rules on a tool call's arguments, end to end: a config's rules,
//! the gateway `build_gateway` makes of it, and the real stdio mock, whose
//! `echo` answers with the arguments it was sent. So what the upstream got is
//! read from its answer.
//!
//! The rules run before admission (mutate, then validate): the upstream gets
//! what they made, the allow and deny rules judge it, one that cannot apply
//! denies the call under its own name, and the ledger names the rules that
//! fired and none of the values.

use mcpdef::connect::build_gateway;
use mcpdef::{Config, Gateway};
use mcpdef_audit::Record;
use mcpdef_core::{method, Id, Message};
use serde_json::{json, Value};
use tempfile::TempDir;

struct Setup {
    gw: Gateway,
    dir: TempDir,
}

impl Setup {
    /// The gateway over the mock, `echo` on its allowlist, with `rules`.
    async fn new(rules: &str) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let mock = env!("CARGO_BIN_EXE_mock_mcp_server");
        let config = format!(
            "[gateway]\naudit = {audit:?}\n\n\
             [[server]]\nid = \"mock\"\ntransport = \"stdio\"\ncommand = [{mock:?}]\n\
             tools = [\"echo\"]\n\n{rules}",
            audit = dir.path().join("audit.log").display().to_string(),
        );
        let path = dir.path().join("mcpdef.toml");
        std::fs::write(&path, config).unwrap();
        let cfg = Config::load(&path).unwrap();
        assert_eq!(cfg.validate(), Vec::<String>::new());
        let gw = build_gateway(&cfg).await.unwrap();
        Setup { gw, dir }
    }

    async fn call(&self, tool: &str, arguments: Value) -> Message {
        let params = json!({ "name": tool, "arguments": arguments });
        self.gw
            .handle(Message::request(
                Id::Num(1),
                method::TOOLS_CALL,
                Some(params),
            ))
            .await
            .unwrap()
            .unwrap()
    }

    fn ledger(&self) -> String {
        std::fs::read_to_string(self.dir.path().join("audit.log")).unwrap()
    }

    /// The records of the tool calls.
    fn calls(&self) -> Vec<Record> {
        self.ledger()
            .lines()
            .map(|line| serde_json::from_str::<Record>(line).unwrap())
            .filter(|r| r.method.as_deref() == Some(method::TOOLS_CALL))
            .collect()
    }
}

/// The arguments the upstream got, from the mock's `echo: <arguments>`.
fn received(resp: &Message) -> Value {
    let result = resp.result.as_ref().unwrap();
    assert_eq!(result["isError"], json!(false), "{result}");
    let text = result["content"][0]["text"].as_str().unwrap();
    serde_json::from_str(text.strip_prefix("echo: ").unwrap()).unwrap()
}

/// The text of a tool error MCPdef answered with.
fn refusal(resp: &Message) -> String {
    let result = resp.result.as_ref().unwrap();
    assert_eq!(result["isError"], json!(true), "{result}");
    result["content"][0]["text"].as_str().unwrap().to_string()
}

const CAP: &str = r#"
[[policy]]
name = "cap-page-size"
effect = "transform"
tools = ["echo"]
set_args = [{ path = "per_page", clamp = { max = 100 } }]
"#;

#[tokio::test]
async fn a_clamped_argument_reaches_the_upstream_clamped() {
    let s = Setup::new(CAP).await;
    let resp = s
        .call("echo", json!({ "per_page": 500, "q": "rust" }))
        .await;
    assert_eq!(received(&resp), json!({ "per_page": 100, "q": "rust" }));
    // Within the bound, the call goes as it came, and the rule still fired.
    let resp = s.call("echo", json!({ "per_page": 30 })).await;
    assert_eq!(received(&resp), json!({ "per_page": 30 }));

    let calls = s.calls();
    assert_eq!(calls.len(), 2);
    for record in &calls {
        assert_eq!(record.decision, "allow");
        assert_eq!(
            record.transforms.as_deref(),
            Some(&["cap-page-size".to_string()][..])
        );
    }
}

/// The arguments go upstream as the pass left them, even when its last rule
/// changed nothing.
#[tokio::test]
async fn a_change_is_sent_when_a_later_rule_changes_nothing() {
    let s = Setup::new(&format!(
        r#"{CAP}
[[policy]]
name = "sorted"
effect = "transform"
set_args = [{{ path = "sort", default = "created" }}]
"#
    ))
    .await;
    let resp = s
        .call("echo", json!({ "per_page": 500, "sort": "updated" }))
        .await;
    assert_eq!(
        received(&resp),
        json!({ "per_page": 100, "sort": "updated" })
    );
    assert_eq!(
        s.calls()[0].transforms.as_deref(),
        Some(&["cap-page-size".to_string(), "sorted".to_string()][..])
    );
}

#[tokio::test]
async fn admission_judges_the_arguments_the_transforms_made() {
    let s = Setup::new(
        r#"
[[policy]]
name = "no-dry-runs"
effect = "transform"
set_args = [{ path = "dry_run", set = false }]

[[policy]]
name = "no-live-runs"
effect = "deny"
args = [{ path = "dry_run", equals = "false" }]
"#,
    )
    .await;
    // The client asked for a dry run; the rule made it live, and the deny
    // judged the live one.
    let text = refusal(&s.call("echo", json!({ "dry_run": true })).await);
    assert!(text.contains("policy rule 'no-live-runs'"), "{text}");
    let calls = s.calls();
    assert_eq!(calls[0].decision, "deny");
    assert_eq!(calls[0].rule.as_deref(), Some("no-live-runs"));
    assert_eq!(
        calls[0].transforms.as_deref(),
        Some(&["no-dry-runs".to_string()][..])
    );

    // And the other way: a deny of what the client sent no longer matches
    // once the rule has changed it.
    let s = Setup::new(
        r#"
[[policy]]
name = "to-staging"
effect = "transform"
set_args = [{ path = "env", set = "staging" }]

[[policy]]
name = "no-prod"
effect = "deny"
args = [{ path = "env", equals = "prod" }]
"#,
    )
    .await;
    let resp = s.call("echo", json!({ "env": "prod", "n": 1 })).await;
    assert_eq!(received(&resp), json!({ "env": "staging", "n": 1 }));
}

#[tokio::test]
async fn a_transform_that_cannot_apply_denies_the_call_under_its_name() {
    let s = Setup::new(CAP).await;
    let text = refusal(&s.call("echo", json!({ "per_page": "all" })).await);
    assert_eq!(
        text,
        "MCPdef denied: transform rule 'cap-page-size' could not apply to 'echo' on 'mock': \
         `per_page` is a string, not a number"
    );
    let calls = s.calls();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].decision, "deny");
    assert_eq!(calls[0].rule.as_deref(), Some("cap-page-size"));
    // It did not fire: it could not apply.
    assert_eq!(calls[0].transforms, None);
}

#[tokio::test]
async fn a_rule_that_skips_lets_the_call_go_as_the_rules_before_it_left_it() {
    let s = Setup::new(
        r#"
[[policy]]
name = "defaults"
effect = "transform"
set_args = [{ path = "per_page", default = 50 }, { path = "sort", default = "created" }]

[[policy]]
name = "cap-quietly"
effect = "transform"
on_error = "skip"
set_args = [{ path = "sort", remove = true }, { path = "per_page", clamp = { max = 100 } }]
"#,
    )
    .await;
    // `per_page` a string: the second rule removed `sort`, failed on the
    // clamp, and keeps nothing; the first rule's defaults stand.
    let resp = s.call("echo", json!({ "per_page": "all" })).await;
    assert_eq!(
        received(&resp),
        json!({ "per_page": "all", "sort": "created" })
    );
    let calls = s.calls();
    assert_eq!(calls[0].decision, "allow");
    assert_eq!(
        calls[0].transforms.as_deref(),
        Some(&["defaults".to_string()][..])
    );
}

#[tokio::test]
async fn the_ledger_names_every_rule_that_fired_and_no_value() {
    let s = Setup::new(&format!(
        r#"{CAP}
[[policy]]
name = "strip-token"
effect = "transform"
set_args = [{{ path = "auth.token", remove = true }}]
"#
    ))
    .await;
    let resp = s
        .call(
            "echo",
            json!({ "per_page": 4321.5, "auth": { "token": "tok-9f3a2b1c7e", "user": "Ada-Lovelace" } }),
        )
        .await;
    assert_eq!(
        received(&resp),
        json!({ "per_page": 100, "auth": { "user": "Ada-Lovelace" } })
    );
    let calls = s.calls();
    assert_eq!(
        calls[0].transforms.as_deref(),
        Some(&["cap-page-size".to_string(), "strip-token".to_string()][..])
    );
    let ledger = s.ledger();
    // Each holds a character no hash or number in a record does.
    for value in ["4321.5", "tok-9f3a2b1c7e", "Ada-Lovelace"] {
        assert!(
            !ledger.contains(value),
            "the ledger holds {value}: {ledger}"
        );
    }
}

#[tokio::test]
async fn a_call_the_allowlist_denies_meets_no_transform() {
    let s = Setup::new(
        r#"
[[policy]]
name = "everything"
effect = "transform"
set_args = [{ path = "seen", set = true }]
"#,
    )
    .await;
    let text = refusal(&s.call("delete_repo", json!({ "name": "x" })).await);
    assert!(text.starts_with("MCPdef denied"), "{text}");
    let calls = s.calls();
    assert_eq!(calls[0].decision, "deny");
    assert_eq!(calls[0].transforms, None);
    // An allowed one does.
    let resp = s.call("echo", json!({})).await;
    assert_eq!(received(&resp), json!({ "seen": true }));
}

#[tokio::test]
async fn a_call_without_arguments_gets_those_the_rules_add() {
    let s = Setup::new(
        r#"
[[policy]]
name = "defaults"
effect = "transform"
set_args = [{ path = "per_page", default = 50 }]
"#,
    )
    .await;
    let params = json!({ "name": "echo" });
    let resp =
        s.gw.handle(Message::request(
            Id::Num(1),
            method::TOOLS_CALL,
            Some(params),
        ))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(received(&resp), json!({ "per_page": 50 }));
}
