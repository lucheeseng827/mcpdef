// SPDX-License-Identifier: Apache-2.0
//! The upstream side of the dual wire: MCPdef speaking **2026-07-28** to a
//! server that requires it.
//!
//! `Y1-01`'s recorded exit condition is that one `mcpdef.toml` fronts a
//! 2025-11-25 upstream and a 2026-07-28 upstream **simultaneously**, from a
//! downstream client speaking either, with the allowlist/policy/pin/ledger path
//! unchanged for both. `both_eras_behind_one_gateway_at_once` is that condition,
//! run.
//!
//! The mock's modern mode refuses any request arriving without its own `_meta`,
//! so a passing test here is evidence that MCPdef actually stamped what the
//! revision asks for — not evidence that the mock was lenient.
//!
//! `spec = "auto"` gets the same treatment: the probe is run against both mocks
//! and against one that answers nothing at all, because "assume legacy" has to
//! hold for silence as much as for a `-32601`.

use mcpdef::{list_tools_speaking, Gateway};
use mcpdef_audit::Ledger;
use mcpdef_core::wire::SpecSetting;
use mcpdef_core::{method, Id, Message};
use mcpdef_policy::{Policy, ServerPolicy};
use mcpdef_transport::StdioChild;
use serde_json::{json, Value};
use std::time::Duration;

/// The stdio mock, in whichever era the test needs.
fn spawn(modern: bool) -> Box<StdioChild> {
    let bin = env!("CARGO_BIN_EXE_mock_mcp_server").to_string();
    let argv = if modern {
        vec![bin, "--modern".to_string()]
    } else {
        vec![bin]
    };
    Box::new(StdioChild::spawn(&argv).unwrap())
}

/// Allow the safe tool on each upstream, deny the destructive one on both.
fn policy() -> Policy {
    let mut p = Policy::new();
    for (server, safe) in [("old", "echo"), ("new", "echo_v2")] {
        p.insert(
            server,
            ServerPolicy {
                allow_tools: Some(vec![safe.into()]),
                deny: vec![],
            },
        );
    }
    p
}

/// A gateway with the shared allowlist and a ledger under `dir`.
fn gateway(dir: &tempfile::TempDir) -> Gateway {
    let ledger = Ledger::open(dir.path().join("audit.log")).unwrap();
    Gateway::new(policy(), ledger, "agent:test")
}

/// Call one tool through the full governance path and return its result.
async fn call(gw: &mut Gateway, id: i64, tool: &str) -> Value {
    let msg = Message::request(
        Id::Num(id),
        method::TOOLS_CALL,
        Some(json!({ "name": tool, "arguments": { "msg": "hi" } })),
    );
    gw.handle(msg).await.unwrap().unwrap().result.unwrap()
}

/// `Y1-01`'s exit condition. One gateway, both eras at once, same governance.
#[tokio::test]
async fn both_eras_behind_one_gateway_at_once() {
    let dir = tempfile::tempdir().unwrap();
    let mut gw = gateway(&dir);
    gw.add_upstream("old", spawn(false)).await.unwrap();
    gw.add_upstream_speaking("new", spawn(true), SpecSetting::V20260728)
        .await
        .unwrap();

    // Both catalogues aggregate, and the allowlist hides the destructive tool on
    // each — the era an upstream speaks is not something the policy layer sees.
    let listed = gw
        .handle(Message::request(Id::Num(1), method::TOOLS_LIST, None))
        .await
        .unwrap()
        .unwrap();
    let names: Vec<&str> = listed.result.as_ref().unwrap()["tools"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|t| t["name"].as_str())
        .collect();
    assert!(
        names.contains(&"echo"),
        "the legacy upstream's tool: {names:?}"
    );
    assert!(
        names.contains(&"echo_v2"),
        "the modern upstream's tool: {names:?}"
    );
    assert!(
        !names.iter().any(|n| n.starts_with("delete_repo")),
        "the allowlist hides the destructive tool on both upstreams: {names:?}"
    );

    // An allowed call reaches each upstream and comes back. For the modern one
    // this only works if MCPdef stamped `_meta`: the mock refuses a request
    // without it.
    let old = call(&mut gw, 2, "echo").await;
    assert_eq!(old["isError"], false, "got: {old}");
    assert!(old["content"][0]["text"]
        .as_str()
        .unwrap()
        .starts_with("echo:"));

    let new = call(&mut gw, 3, "echo_v2").await;
    assert_eq!(new["isError"], false, "the modern upstream answered: {new}");
    assert!(new["content"][0]["text"]
        .as_str()
        .unwrap()
        .starts_with("echo_v2:"));

    // And a denial is a denial on either wire.
    for (id, tool) in [(4, "delete_repo"), (5, "delete_repo_v2")] {
        let denied = call(&mut gw, id, tool).await;
        assert_eq!(denied["isError"], true, "{tool} must be denied: {denied}");
        assert!(
            denied["content"][0]["text"]
                .as_str()
                .unwrap()
                .contains("MCPdef denied"),
            "{tool}: {denied}"
        );
    }
}

/// The stamping is what the modern upstream is actually checking, so prove the
/// negative too: told the wrong era, MCPdef opens with the handshake the server
/// has no method for, and the failure says so at startup rather than on the
/// first tool call.
#[tokio::test]
async fn a_modern_upstream_configured_as_legacy_fails_at_startup_with_the_reason() {
    let dir = tempfile::tempdir().unwrap();
    let mut gw = gateway(&dir);

    let e = gw
        .add_upstream("new", spawn(true))
        .await
        .expect_err("a modern server cannot complete an `initialize` handshake");

    let message = format!("{e:#}");
    assert!(
        message.contains("initialize") || message.contains("2026-07-28"),
        "the failure must point at the wire mismatch: {message}"
    );
}

/// The other way round: a legacy server told it is modern answers
/// `server/discover` with a method-not-found, and MCPdef says which knob to
/// change rather than letting `tools/list` fail for a reason nobody can trace.
#[tokio::test]
async fn a_legacy_upstream_configured_as_modern_names_the_knob_to_change() {
    let dir = tempfile::tempdir().unwrap();
    let mut gw = gateway(&dir);

    let e = gw
        .add_upstream_speaking("old", spawn(false), SpecSetting::V20260728)
        .await
        .expect_err("a 2025-11-25 server does not implement `server/discover`");

    let message = format!("{e:#}");
    assert!(message.contains("spec"), "it must name the knob: {message}");
    assert!(
        message.contains("2026-07-28"),
        "and what it was configured as: {message}"
    );
}

/// `spec = "auto"` against each era. The probe asks `server/discover`; a result
/// means modern, and anything else — including an ordinary JSON-RPC error from a
/// server that predates the method — means legacy.
#[tokio::test]
async fn auto_probes_each_upstream_and_reaches_the_right_wire() {
    for (modern, tool) in [(false, "echo"), (true, "echo_v2")] {
        let dir = tempfile::tempdir().unwrap();
        let mut gw = gateway(&dir);
        let server = if modern { "new" } else { "old" };

        gw.add_upstream_speaking(server, spawn(modern), SpecSetting::Auto)
            .await
            .unwrap_or_else(|e| panic!("auto must open a {server} upstream: {e:#}"));

        // Reaching the tool at all proves the probe resolved the era correctly:
        // the modern mock refuses a request with no `_meta`, and the legacy one
        // never answers `server/discover`.
        let result = call(&mut gw, 1, tool).await;
        assert_eq!(result["isError"], false, "{server}: {result}");
        assert!(result["content"][0]["text"]
            .as_str()
            .unwrap()
            .starts_with(tool));
    }
}

/// Both eras again, but with neither upstream told which it is. This is the
/// exit condition without the operator having to know the answer.
#[tokio::test]
async fn auto_fronts_both_eras_at_once_without_being_told_which_is_which() {
    let dir = tempfile::tempdir().unwrap();
    let mut gw = gateway(&dir);
    gw.add_upstream_speaking("old", spawn(false), SpecSetting::Auto)
        .await
        .unwrap();
    gw.add_upstream_speaking("new", spawn(true), SpecSetting::Auto)
        .await
        .unwrap();

    assert_eq!(call(&mut gw, 1, "echo").await["isError"], false);
    assert_eq!(call(&mut gw, 2, "echo_v2").await["isError"], false);

    // And the governance path still does not care which wire answered.
    let denied = call(&mut gw, 3, "delete_repo_v2").await;
    assert_eq!(denied["isError"], true, "got: {denied}");
}

/// A server that ignores an unknown method instead of answering `-32601` — which
/// JSON-RPC requires but not everything does. Silence is the same answer as
/// `-32601` here, just slower, so the probe must conclude legacy rather than
/// wait forever. `upstream_timeout` is deliberately unset: the probe carries its
/// own bound precisely because that one defaults to waiting indefinitely.
#[tokio::test]
async fn auto_falls_back_to_legacy_when_an_upstream_answers_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let mut gw = gateway(&dir);

    let started = std::time::Instant::now();
    gw.add_upstream_speaking("old", spawn_silent_on_discover(), SpecSetting::Auto)
        .await
        .expect("a silent `server/discover` must resolve to the legacy wire, not hang");

    assert!(
        started.elapsed() < std::time::Duration::from_secs(30),
        "the probe must be bounded on its own, not by a timeout nobody set"
    );
    assert_eq!(call(&mut gw, 1, "echo").await["isError"], false);
}

/// A stand-in that answers the legacy handshake but drops `server/discover` on
/// the floor, the way a server with no JSON-RPC error handling would.
fn spawn_silent_on_discover() -> Box<StdioChild> {
    let bin = env!("CARGO_BIN_EXE_mock_mcp_server").to_string();
    Box::new(StdioChild::spawn(&[bin, "--silent-on-discover".to_string()]).unwrap())
}

/// The same silence, but behind an `upstream_timeout_ms` shorter than the probe.
///
/// The two bounds answer different questions — "how long may a call take" is not
/// "how long until I conclude this server is legacy" — so the probe's budget is
/// added to the operator's rather than carved out of it. Before that it was
/// carved out by accident: the whole opening sat inside `upstream_timeout`, so a
/// timeout under five seconds fired first and startup failed naming a number the
/// operator set for something else, while the fallback the docs promise never
/// ran. The upstream above opens fine pinned; only `auto` could not reach it.
#[tokio::test]
async fn a_short_upstream_timeout_does_not_cut_the_probe_off_from_its_fallback() {
    let dir = tempfile::tempdir().unwrap();
    let mut gw = gateway(&dir).with_upstream_timeout(Some(Duration::from_millis(1500)));

    gw.add_upstream_speaking("old", spawn_silent_on_discover(), SpecSetting::Auto)
        .await
        .expect("a per-call timeout must not decide whether the era probe can fall back");

    // And the timeout still applies to what it is for: this call is bounded by
    // the 1500ms, not by the probe's budget, and the upstream answers well
    // inside it.
    assert_eq!(call(&mut gw, 1, "echo").await["isError"], false);
}

/// `mcpdef pin` and `mcpdef diff-tools` list an upstream's tools without building
/// a gateway. They used to call `handshake_list` directly, which sends
/// `initialize` — a method a 2026-07-28 server does not have — so neither command
/// worked against a modern upstream. They go through the same spec-aware opener
/// the gateway uses now.
#[tokio::test]
async fn listing_tools_for_pin_and_diff_works_on_both_eras() {
    for (spec, modern, expected) in [
        (SpecSetting::V20251125, false, "echo"),
        (SpecSetting::V20260728, true, "echo_v2"),
        (SpecSetting::Auto, true, "echo_v2"),
        (SpecSetting::Auto, false, "echo"),
    ] {
        let mut transport = spawn(modern);
        let tools = list_tools_speaking("x", &mut *transport, spec)
            .await
            .unwrap_or_else(|e| panic!("{spec:?} against modern={modern}: {e:#}"));
        let names: Vec<&str> = tools.iter().filter_map(|t| t["name"].as_str()).collect();
        assert!(
            names.contains(&expected),
            "{spec:?} against modern={modern} should list {expected}: {names:?}"
        );
    }
}
