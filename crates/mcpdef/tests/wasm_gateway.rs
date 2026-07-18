// SPDX-License-Identifier: Apache-2.0
//! End-to-end Phase-4 test: a real WebAssembly MCP server, run in-path under the
//! Wasmtime sandbox (`mcpdef-sandbox`), fronted by the governance [`Gateway`].
//! Proves the `wasm` transport completes the MCP handshake at connect, its tools
//! surface through `tools/list`, and a governed `tools/call` round-trips with the
//! client id mapped back — the same contract the stdio golden-path test asserts,
//! but over an untrusted sandboxed module instead of a child process.

use mcpdef::Gateway;
use mcpdef_audit::Ledger;
use mcpdef_core::{method, Id, Message};
use mcpdef_policy::{Policy, ServerPolicy};
use mcpdef_sandbox::{SandboxLimits, WasmUpstream};

fn req(id: i64, method: &str, params: Option<serde_json::Value>) -> Message {
    Message::request(Id::Num(id), method, params)
}

/// A minimal WASM MCP server. It ignores request content and replies with the
/// canned response for each step of the lifecycle, keyed by a call counter:
/// `1` = initialize (id 0), `2` = the `initialized` notification (no response),
/// `3` = tools/list (id 1, exposing `echo`), `4+` = tools/call (id 100). The
/// gateway's forwarded-request ids are deterministic (handshake uses 0 then 1,
/// the first tools/call uses 100), so the canned response ids line up and
/// `recv_response` matches them. `strlen` measures each response at runtime, so
/// the fixture needs no hand-counted byte lengths; `alloc` bump-allocates the
/// request buffer above the data region. The module imports nothing — it runs
/// against the sandbox's empty linker.
const MCP_SERVER: &str = r#"
(module
  (memory (export "memory") 1)
  (global $calls (mut i32) (i32.const 0))
  (global $next (mut i32) (i32.const 16384))
  (data (i32.const 1000) "{\"jsonrpc\":\"2.0\",\"id\":0,\"result\":{\"protocolVersion\":\"2025-11-25\",\"capabilities\":{\"tools\":{}},\"serverInfo\":{\"name\":\"wasm-echo\",\"version\":\"0.1.0\"}}}")
  (data (i32.const 3000) "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"tools\":[{\"name\":\"echo\",\"description\":\"echo back the arguments\",\"inputSchema\":{\"type\":\"object\"}}]}}")
  (data (i32.const 5000) "{\"jsonrpc\":\"2.0\",\"id\":100,\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"echoed\"}],\"isError\":false}}")
  (func (export "alloc") (param $len i32) (result i32)
    (local $p i32)
    (local.set $p (global.get $next))
    (global.set $next (i32.add (global.get $next) (local.get $len)))
    (local.get $p))
  (func $strlen (param $p i32) (result i32)
    (local $n i32)
    (loop $l
      (if (i32.load8_u (i32.add (local.get $p) (local.get $n)))
        (then
          (local.set $n (i32.add (local.get $n) (i32.const 1)))
          (br $l))))
    (local.get $n))
  (func $pack (param $p i32) (param $l i32) (result i64)
    (i64.or
      (i64.shl (i64.extend_i32_u (local.get $p)) (i64.const 32))
      (i64.extend_i32_u (local.get $l))))
  (func (export "handle") (param $ptr i32) (param $len i32) (result i64)
    (global.set $calls (i32.add (global.get $calls) (i32.const 1)))
    (if (result i64) (i32.eq (global.get $calls) (i32.const 1))
      (then (call $pack (i32.const 1000) (call $strlen (i32.const 1000))))
      (else
        (if (result i64) (i32.eq (global.get $calls) (i32.const 2))
          (then (i64.const 0))
          (else
            (if (result i64) (i32.eq (global.get $calls) (i32.const 3))
              (then (call $pack (i32.const 3000) (call $strlen (i32.const 3000))))
              (else (call $pack (i32.const 5000) (call $strlen (i32.const 5000)))))))))))
"#;

#[tokio::test]
async fn wasm_upstream_handshakes_lists_and_calls_through_the_gateway() {
    let dir = tempfile::tempdir().unwrap();
    let audit_path = dir.path().join("audit.log");
    let ledger = Ledger::open(&audit_path).unwrap();

    // Policy: the sandboxed "wasm" server allows `echo`.
    let mut policy = Policy::new();
    policy.insert(
        "wasm",
        ServerPolicy {
            allow_tools: Some(vec!["echo".into()]),
            deny: vec![],
        },
    );
    let mut gw = Gateway::new(policy, ledger, "agent:test");

    // The upstream is an untrusted .wasm module run under Wasmtime — no child
    // process, no ambient capability. `add_upstream` runs the MCP handshake
    // (initialize → notifications/initialized → tools/list) through the sandbox.
    let wasm = wat::parse_str(MCP_SERVER).expect("valid WAT fixture");
    let upstream = WasmUpstream::from_wasm(&wasm, SandboxLimits::default()).unwrap();
    gw.add_upstream("wasm", Box::new(upstream)).await.unwrap();
    assert_eq!(gw.upstream_count(), 1);

    // tools/list surfaces the sandboxed module's `echo`.
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
    assert_eq!(names, vec!["echo".to_string()]);

    // A governed tools/call round-trips through the sandbox; the upstream's local
    // response id (100) is mapped back to the client's id (3).
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
    assert_eq!(
        call.result.unwrap()["content"][0]["text"],
        serde_json::json!("echoed")
    );
}
