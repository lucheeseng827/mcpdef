// SPDX-License-Identifier: Apache-2.0
//! End-to-end Phase-4 test for the **component-model** sandbox: a real
//! `wasm32-wasip2` component (the `mcpdef:server` echo fixture) run in-path under
//! Wasmtime + capability-scoped WASI, fronted by the governance [`Gateway`].
//! Proves the `wasm-component` upstream completes the MCP handshake, surfaces its
//! tools through `tools/list`, and round-trips a governed `tools/call` with the
//! client id mapped back — the same contract as the stdio golden path, but over a
//! sandboxed component with zero ambient capability.

use mcpdef::Gateway;
use mcpdef_audit::Ledger;
use mcpdef_core::{method, Id, Message};
use mcpdef_policy::{Policy, ServerPolicy};
use mcpdef_sandbox::{EgressAllow, SandboxLimits, WasmComponentUpstream};

fn req(id: i64, method: &str, params: Option<serde_json::Value>) -> Message {
    Message::request(Id::Num(id), method, params)
}

/// The committed component fixture lives in the sibling mcpdef-sandbox crate.
fn fixture_path() -> String {
    format!(
        "{}/../mcpdef-sandbox/tests/fixtures/echo_component.wasm",
        env!("CARGO_MANIFEST_DIR")
    )
}

#[tokio::test]
async fn wasm_component_handshakes_lists_and_calls_through_the_gateway() {
    let dir = tempfile::tempdir().unwrap();
    let ledger = Ledger::open(dir.path().join("audit.log")).unwrap();

    // Policy: the sandboxed component server allows `echo`.
    let mut policy = Policy::new();
    policy.insert(
        "component",
        ServerPolicy {
            allow_tools: Some(vec!["echo".into()]),
            deny: vec![],
        },
    );
    let mut gw = Gateway::new(policy, ledger, "agent:test");

    // The upstream is a `wasm32-wasip2` component run under Wasmtime with deny-all
    // egress and no ambient capability. add_upstream runs the MCP handshake.
    let upstream = WasmComponentUpstream::from_file(
        fixture_path(),
        SandboxLimits::default(),
        EgressAllow::deny_all(),
    )
    .await
    .expect("load echo component fixture");
    gw.add_upstream("component", Box::new(upstream))
        .await
        .unwrap();
    assert_eq!(gw.upstream_count(), 1);

    // tools/list is filtered to the allowlist: the fixture exposes both `echo`
    // and `fetch`, but the policy allows only `echo`, so the gateway must surface
    // *exactly* `echo` — an exact assertion proves `fetch` is dropped, not merely
    // that `echo` is present.
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
    assert_eq!(
        names,
        vec!["echo".to_string()],
        "only the allowlisted `echo` should be exposed (fetch filtered out)"
    );

    // A governed tools/call round-trips through the component; the client id (3)
    // is preserved on the response.
    let call = gw
        .handle(req(
            3,
            method::TOOLS_CALL,
            Some(serde_json::json!({ "name": "echo", "arguments": { "msg": "hi" } })),
        ))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(call.id, Some(Id::Num(3)));
    assert_eq!(
        call.result.as_ref().unwrap()["isError"],
        serde_json::json!(false)
    );
}
