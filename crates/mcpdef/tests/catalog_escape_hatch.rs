// SPDX-License-Identifier: Apache-2.0
//! A server whose **discovery surface is narrower than its execution surface**,
//! and what MCPdef does about it.
//!
//! This is a common and dangerous MCP shape. A server curates what it advertises
//! — one tool per approved job, filtered by a tag, a role, an allow-list it owns
//! — and then also exposes a generic "run this" tool that takes a job
//! *specification* as an argument. The curation is applied when listing. It is
//! not applied when running. So the narrow surface is a **display filter**, and
//! any client that knows the generic tool's name can hand it a specification the
//! curation would never have shown, which the server then executes.
//!
//! Servers that shell out are the acute case: the escape hatch is arbitrary
//! command execution wearing a tool call. The shape is worse again when a
//! sibling tool has a *model* write the specification.
//!
//! MCPdef's answer is the boring one, and it works because it is applied on the
//! wire rather than by the server: allow the curated globs, deny the generic
//! tool by name. Every remaining route to execution then runs through the
//! curated set, which is what the curation was supposed to mean.
//!
//! **The assertion that matters is not that a denied call returns an error — it
//! is that the upstream never sees it.** A gate that dispatches and then
//! complains is the bug being mitigated, not the fix for it.

use std::sync::{Arc, Mutex};

use mcpdef::Gateway;
use mcpdef_audit::{verify, Ledger, Record};
use mcpdef_core::{method, Id, Message};
use mcpdef_policy::{Policy, ServerPolicy};
use mcpdef_transport::{duplex_pair, Transport};
use serde_json::json;

/// Per-job tools the server generates from its own curated catalogue.
const CURATED: [&str; 2] = ["job_nightly_etl", "job_report"];
/// Read-only tools, and a runner that resolves its argument against the catalogue.
const SAFE: [&str; 3] = ["list_jobs", "get_run", "run_catalogued_job"];
/// The generic tools: one takes a raw specification, one has a model write it.
const ESCAPE_HATCHES: [&str; 2] = ["submit_raw_job", "generate_and_submit_job"];

/// A stand-in upstream that records every `tools/call` it is asked to execute,
/// so the test can assert on what was *dispatched*, not just what was returned.
fn spawn_upstream(seen: Arc<Mutex<Vec<String>>>) -> mcpdef_transport::Duplex {
    let (near, mut far) = duplex_pair();
    tokio::spawn(async move {
        while let Ok(Some(msg)) = far.recv().await {
            let Some(id) = msg.id.clone() else { continue }; // notifications
            let reply = match msg.method() {
                Some(m) if m == method::INITIALIZE => Message::result(
                    id,
                    json!({
                        "protocolVersion": "2025-11-25",
                        "capabilities": { "tools": {} },
                        "serverInfo": { "name": "catalogue-server", "version": "0.0.0" },
                    }),
                ),
                Some(m) if m == method::TOOLS_LIST => {
                    let tools: Vec<_> = CURATED
                        .iter()
                        .chain(SAFE.iter())
                        .chain(ESCAPE_HATCHES.iter())
                        .map(|n| json!({ "name": n, "inputSchema": { "type": "object" } }))
                        .collect();
                    Message::result(id, json!({ "tools": tools }))
                }
                Some(m) if m == method::TOOLS_CALL => {
                    seen.lock()
                        .unwrap()
                        .push(msg.tool_name().unwrap_or("<unnamed>").to_string());
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

/// The recommended shape: allow the curated globs and the safe tools, and *also*
/// name the generic tools as denies.
fn governed() -> Policy {
    let mut policy = Policy::new();
    policy.insert(
        "jobs",
        ServerPolicy {
            allow_tools: Some(
                std::iter::once("job_*".to_string())
                    .chain(SAFE.iter().map(|s| s.to_string()))
                    .collect(),
            ),
            deny: ESCAPE_HATCHES.iter().map(|s| s.to_string()).collect(),
        },
    );
    policy
}

fn req(id: i64, method: &str, params: Option<serde_json::Value>) -> Message {
    Message::request(Id::Num(id), method, params)
}

/// A specification the curated catalogue would never have offered.
fn uncurated_spec() -> serde_json::Value {
    json!({
        "name": "submit_raw_job",
        "arguments": { "spec": "tasks:\n  - name: arbitrary\n    command: [\"sh\", \"-c\", \"...\"]\n" },
    })
}

#[tokio::test]
async fn the_generic_tools_are_hidden_denied_and_never_dispatched() {
    let dir = tempfile::tempdir().unwrap();
    let audit_path = dir.path().join("audit.log");
    let seen = Arc::new(Mutex::new(Vec::new()));

    let ledger = Ledger::open(&audit_path).unwrap();
    let mut gw = Gateway::new(governed(), ledger, "agent:ci");
    gw.add_upstream("jobs", Box::new(spawn_upstream(seen.clone())))
        .await
        .unwrap();

    gw.handle(req(
        1,
        method::INITIALIZE,
        Some(json!({ "clientInfo": { "name": "agent" } })),
    ))
    .await
    .unwrap();

    // 1. The generic tools are not advertised. An agent cannot reach for what it
    //    is never told exists — the cheap half of the mitigation.
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
    for approved in CURATED.iter().chain(SAFE.iter()) {
        assert!(
            names.contains(&approved.to_string()),
            "{approved} must stay available: {names:?}"
        );
    }
    for hatch in ESCAPE_HATCHES {
        assert!(
            !names.contains(&hatch.to_string()),
            "{hatch} must be hidden from tools/list"
        );
    }

    // 2. A curated job still runs. The mitigation must not cost the server the
    //    thing agents actually use it for.
    let allowed = gw
        .handle(req(
            3,
            method::TOOLS_CALL,
            Some(json!({ "name": CURATED[0], "arguments": {} })),
        ))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(allowed.result.as_ref().unwrap()["isError"], json!(false));

    // 3. The uncurated call is refused *before dispatch* — the whole point.
    let denied = gw
        .handle(req(4, method::TOOLS_CALL, Some(uncurated_spec())))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(denied.result.as_ref().unwrap()["isError"], json!(true));

    let generated = gw
        .handle(req(
            5,
            method::TOOLS_CALL,
            Some(
                json!({ "name": "generate_and_submit_job", "arguments": { "prompt": "anything" } }),
            ),
        ))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(generated.result.as_ref().unwrap()["isError"], json!(true));

    drop(gw);

    assert_eq!(
        seen.lock().unwrap().clone(),
        vec![CURATED[0].to_string()],
        "only the curated job may reach the upstream; the generic calls must never arrive"
    );

    // 4. Every decision is on the ledger and the chain verifies — the record an
    //    incident review would need.
    assert!(
        verify(&audit_path).unwrap().ok(),
        "the audit chain must verify"
    );
    let content = std::fs::read_to_string(&audit_path).unwrap();
    let recs: Vec<Record> = content
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(recs.len(), 3, "one allow and two denies");
    assert_eq!(recs[0].decision, "allow");
    for rec in &recs[1..] {
        assert_eq!(rec.decision, "deny");
        assert_eq!(
            rec.rule.as_deref(),
            Some("deny-glob"),
            "the explicit deny is what fires, not the allowlist fallthrough"
        );
    }
}

/// Why the recommended config names the generic tools explicitly *and* keeps a
/// narrow allowlist, rather than relying on deny-by-default alone.
///
/// An operator widening the allowlist to `*` — to pick up a new tool without
/// thinking about it — would silently re-open the hole if the allowlist were the
/// only guard. Deny globs are evaluated first and always win, so the explicit
/// deny survives that mistake. This is the reason the deny lines stay in an
/// example config even where they look redundant.
#[tokio::test]
async fn an_explicit_deny_survives_an_allowlist_widened_to_everything() {
    let dir = tempfile::tempdir().unwrap();
    let audit_path = dir.path().join("audit.log");
    let seen = Arc::new(Mutex::new(Vec::new()));

    let mut policy = Policy::new();
    policy.insert(
        "jobs",
        ServerPolicy {
            allow_tools: Some(vec!["*".into()]), // the careless widening
            deny: ESCAPE_HATCHES.iter().map(|s| s.to_string()).collect(),
        },
    );

    let ledger = Ledger::open(&audit_path).unwrap();
    let mut gw = Gateway::new(policy, ledger, "agent:ci");
    gw.add_upstream("jobs", Box::new(spawn_upstream(seen.clone())))
        .await
        .unwrap();
    gw.handle(req(1, method::INITIALIZE, None)).await.unwrap();

    let denied = gw
        .handle(req(2, method::TOOLS_CALL, Some(uncurated_spec())))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        denied.result.as_ref().unwrap()["isError"],
        json!(true),
        "a widened allowlist must not re-open the raw-submit path"
    );

    drop(gw);
    assert!(
        seen.lock().unwrap().is_empty(),
        "nothing should have reached the upstream"
    );
}
