// SPDX-License-Identifier: Apache-2.0
//! The stateless **2026-07-28** wire, end to end through the real listener.
//!
//! `Y1-01`'s exit condition is that one gateway fronts both eras with the
//! allowlist/policy/pin/ledger path unchanged for each. These tests hold the
//! listener to that: the same `echo` allowlist, the same stdio mock upstream,
//! and a `tools/call` that has to be governed identically whichever wire carried
//! it. What differs is what the transport demands on the way in, and the fields
//! each revision requires on a result on the way out.
//!
//! The one worth reading first is
//! `a_name_header_disagreeing_with_the_body_is_refused_before_anything_routes` —
//! the allowlist keys on the tool name, so a request whose header says one tool
//! and whose body calls another is a policy bypass, not a formatting nit.

use mcpdef::listener::{serve_http_on, HttpConfig};
use mcpdef::Gateway;
use mcpdef_audit::Ledger;
use mcpdef_core::wire::{error_code, header, meta_key, WireMode, SPEC_2026_07_28};
use mcpdef_core::Message;
use mcpdef_policy::{Policy, ServerPolicy};
use mcpdef_transport::StdioChild;
use serde_json::{json, Value};
use tokio::net::TcpListener;

/// Allow `echo` on the mock upstream and nothing else, so a denial is
/// unambiguous whichever wire carried the call.
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

/// A loopback client that does not route through the ambient proxy.
fn client() -> reqwest::Client {
    mcpdef_transport::install_crypto_provider();
    reqwest::Client::builder().no_proxy().build().unwrap()
}

/// The gateway every test here fronts: the `echo` allowlist over the stdio mock.
async fn gateway(wire: WireMode) -> (Gateway, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let ledger = Ledger::open(dir.path().join("audit.log")).unwrap();
    let mut gw = Gateway::new(allow_echo(), ledger, "agent:test").with_wire(wire);
    let bin = env!("CARGO_BIN_EXE_mock_mcp_server").to_string();
    gw.add_upstream("mock", Box::new(StdioChild::spawn(&[bin]).unwrap()))
        .await
        .unwrap();
    (gw, dir)
}

/// Start a listener in the given wire mode; returns its `/mcp` URL.
async fn start(wire: WireMode) -> (String, tempfile::TempDir) {
    let (gw, dir) = gateway(wire).await;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let cfg = HttpConfig {
        listen: addr.to_string(),
        allowed_origins: vec![],
        max_inflight: None,
        wire,
    };
    tokio::spawn(serve_http_on(listener, gw, cfg, None));
    (format!("http://{addr}/mcp"), dir)
}

/// A conforming modern `tools/call`: `_meta` in `params`, mirrored headers.
fn modern_call(id: i64, tool: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "tools/call",
        "params": {
            "name": tool,
            "arguments": { "msg": "hi" },
            "_meta": {
                meta_key::PROTOCOL_VERSION: SPEC_2026_07_28,
                meta_key::CLIENT_INFO: { "name": "test", "version": "0" },
                meta_key::CLIENT_CAPABILITIES: {},
            }
        }
    })
}

/// A conforming modern request for a method that takes no arguments.
fn modern_request(id: i64, method: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": method,
        "params": {
            "_meta": {
                meta_key::PROTOCOL_VERSION: SPEC_2026_07_28,
                meta_key::CLIENT_INFO: { "name": "test", "version": "0" },
                meta_key::CLIENT_CAPABILITIES: {},
            }
        }
    })
}

/// POST a body with the headers a conforming client mirrors from it.
async fn post_modern(url: &str, body: &Value, name_header: Option<&str>) -> (u16, Value) {
    let method = body["method"].as_str().unwrap().to_string();
    let name = name_header
        .map(str::to_string)
        .or_else(|| body["params"]["name"].as_str().map(str::to_string));
    let mut req = client()
        .post(url)
        .header("content-type", "application/json")
        .header(header::PROTOCOL_VERSION, SPEC_2026_07_28)
        .header(header::METHOD, method);
    if let Some(n) = name {
        req = req.header(header::NAME, n);
    }
    let resp = req.body(body.to_string()).send().await.unwrap();
    let status = resp.status().as_u16();
    let text = resp.text().await.unwrap();
    let v = serde_json::from_str(&text).unwrap_or(Value::Null);
    (status, v)
}

/// The exit condition: the same allowed call, governed the same, over the new
/// wire — and the response names the revision it was served under.
#[tokio::test]
async fn a_modern_tools_call_is_governed_exactly_as_the_legacy_one_is() {
    let (url, _dir) = start(WireMode::Dual).await;

    let resp = client()
        .post(&url)
        .header("content-type", "application/json")
        .header(header::PROTOCOL_VERSION, SPEC_2026_07_28)
        .header(header::METHOD, "tools/call")
        .header(header::NAME, "echo")
        .body(modern_call(1, "echo").to_string())
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.headers()
            .get("mcp-protocol-version")
            .and_then(|v| v.to_str().ok()),
        Some(SPEC_2026_07_28),
        "the response names the revision this request was served under, not a constant"
    );
    let v: Value = serde_json::from_str(&resp.text().await.unwrap()).unwrap();
    assert_eq!(v["result"]["isError"], false, "got: {v}");

    // A tool the allowlist does not name is denied on the modern wire too — the
    // governance path does not know which era carried the call.
    let (status, v) = post_modern(&url, &modern_call(2, "rm_rf"), None).await;
    assert_eq!(
        status, 200,
        "a policy denial is a tool error, not an HTTP one"
    );
    assert_eq!(v["result"]["isError"], true, "got: {v}");
}

/// The bypass this whole check exists to stop. The allowlist, the pin and the
/// rate limit all key on the tool name; if the header could decide the routing
/// and the body the execution, `Mcp-Name: echo` would buy a call to anything.
#[tokio::test]
async fn a_name_header_disagreeing_with_the_body_is_refused_before_anything_routes() {
    let (url, _dir) = start(WireMode::Dual).await;

    // Header says the allowed tool; body calls a different one.
    let (status, v) = post_modern(&url, &modern_call(1, "rm_rf"), Some("echo")).await;

    assert_eq!(status, 400);
    assert_eq!(v["error"]["code"], error_code::HEADER_MISMATCH);
    let message = v["error"]["message"].as_str().unwrap_or_default();
    assert!(
        message.contains("echo") && message.contains("rm_rf"),
        "the rejection must name both sides: {message}"
    );
}

/// Every mirrored header is required, and dropping one says which.
#[tokio::test]
async fn a_modern_request_missing_a_mirrored_header_is_refused_by_name() {
    let (url, _dir) = start(WireMode::Dual).await;
    let body = modern_call(1, "echo").to_string();

    for missing in [header::PROTOCOL_VERSION, header::METHOD, header::NAME] {
        let mut req = client()
            .post(&url)
            .header("content-type", "application/json");
        for (name, value) in [
            (header::PROTOCOL_VERSION, SPEC_2026_07_28),
            (header::METHOD, "tools/call"),
            (header::NAME, "echo"),
        ] {
            if name != missing {
                req = req.header(name, value);
            }
        }
        let resp = req.body(body.clone()).send().await.unwrap();
        // Dropping the version header makes the request read as legacy-shaped,
        // which a dual listener still refuses — the body declares modern.
        assert_eq!(resp.status(), 400, "dropping {missing} must be refused");
        let v: Value = serde_json::from_str(&resp.text().await.unwrap()).unwrap();
        assert_eq!(v["error"]["code"], error_code::HEADER_MISMATCH);
        assert!(
            v["error"]["message"]
                .as_str()
                .unwrap_or_default()
                .contains(missing),
            "the rejection must name {missing}: {v}"
        );
    }
}

/// The default. A deployment that did not ask for the modern wire refuses it —
/// and says what it does serve, because that is what the client retries against.
#[tokio::test]
async fn a_legacy_listener_refuses_a_modern_request_and_names_what_it_serves() {
    let (url, _dir) = start(WireMode::Legacy).await;

    let (status, v) = post_modern(&url, &modern_call(1, "echo"), None).await;

    assert_eq!(status, 400);
    assert_eq!(v["error"]["code"], error_code::UNSUPPORTED_PROTOCOL_VERSION);
    assert_eq!(v["error"]["data"]["requested"], SPEC_2026_07_28);
    assert_eq!(
        v["error"]["data"]["supported"],
        json!(["2025-11-25"]),
        "a legacy listener must not advertise a revision it will then refuse: {v}"
    );
}

/// A dual listener still answers the old handshake unchanged — that is what
/// makes it a migration path rather than a cutover.
#[tokio::test]
async fn a_dual_listener_still_serves_the_legacy_handshake() {
    let (url, _dir) = start(WireMode::Dual).await;

    let resp = client()
        .post(&url)
        .header("content-type", "application/json")
        .body(r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"clientInfo":{"name":"old"}}}"#)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.headers()
            .get("mcp-protocol-version")
            .and_then(|v| v.to_str().ok()),
        Some("2025-11-25")
    );
    let v: Value = serde_json::from_str(&resp.text().await.unwrap()).unwrap();
    assert_eq!(v["result"]["protocolVersion"], "2025-11-25");
}

/// A legacy client has no fall-forward mechanism, so the error it gets from a
/// modern-only listener may be the only diagnostic a human ever sees. It has to
/// name the revisions and how to speak them.
#[tokio::test]
async fn a_modern_only_listener_refuses_initialize_with_an_actionable_message() {
    let (url, _dir) = start(WireMode::Modern).await;

    let resp = client()
        .post(&url)
        .header("content-type", "application/json")
        .body(r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 400);
    let v: Value = serde_json::from_str(&resp.text().await.unwrap()).unwrap();
    let message = v["error"]["message"].as_str().unwrap_or_default();
    assert!(message.contains(SPEC_2026_07_28), "got: {message}");
    assert!(
        message.contains(meta_key::PROTOCOL_VERSION),
        "it must say how to speak the wire it does serve: {message}"
    );
}

/// `server/discover` is how a modern client learns what a server speaks, and the
/// revision requires every server to implement it. What it reports must be what
/// the listener will actually serve.
#[tokio::test]
async fn server_discover_reports_the_revisions_this_listener_serves() {
    for (mode, expected) in [
        (WireMode::Modern, json!(["2026-07-28"])),
        (WireMode::Dual, json!(["2026-07-28", "2025-11-25"])),
    ] {
        let (url, _dir) = start(mode).await;
        let body = json!({
            "jsonrpc": "2.0",
            "id": "discover-1",
            "method": "server/discover",
            "params": { "_meta": { meta_key::PROTOCOL_VERSION: SPEC_2026_07_28 } }
        });

        let resp = client()
            .post(&url)
            .header("content-type", "application/json")
            .header(header::PROTOCOL_VERSION, SPEC_2026_07_28)
            .header(header::METHOD, "server/discover")
            .body(body.to_string())
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), 200, "mode {mode:?}");
        let v: Value = serde_json::from_str(&resp.text().await.unwrap()).unwrap();
        let result = &v["result"];
        assert_eq!(result["supportedVersions"], expected, "mode {mode:?}: {v}");
        assert_eq!(result["resultType"], "complete");
        // The revision requires caching hints on this result. Zero meets that
        // without promising a lifetime the gateway's tool surface could outlive.
        assert_eq!(result["ttlMs"], 0, "mode {mode:?}: {v}");
        assert_eq!(result["cacheScope"], "private", "mode {mode:?}: {v}");
        assert_eq!(result["capabilities"]["tools"], json!({}));
        assert_eq!(result["_meta"][meta_key::SERVER_INFO]["name"], "mcpdef");
        assert!(
            result["instructions"]
                .as_str()
                .unwrap_or_default()
                .contains("ledger"),
            "the instructions should say what governance a caller is getting: {v}"
        );
        // No `Mcp-Name`: `server/discover` has no name field to mirror, and
        // requiring one would refuse a conforming client.
    }
}

/// `tools/list` exists in both eras, so its result takes the shape of the one
/// the request was sent in. A modern client gets what its revision requires of
/// a complete list result — a `resultType` and caching hints — and a legacy
/// client gets exactly what it always has, on the same endpoint, because
/// `2025-11-25` defines none of those fields.
#[tokio::test]
async fn a_modern_tools_list_carries_caching_hints_and_a_legacy_one_is_unchanged() {
    for mode in [WireMode::Legacy, WireMode::Dual, WireMode::Modern] {
        let (url, _dir) = start(mode).await;

        if mode.serves_modern() {
            let (status, v) = post_modern(&url, &modern_request(1, "tools/list"), None).await;
            assert_eq!(status, 200, "mode {mode:?}: {v}");
            let result = &v["result"];
            assert_eq!(result["resultType"], "complete", "mode {mode:?}: {v}");
            assert_eq!(result["ttlMs"], 0, "mode {mode:?}: {v}");
            assert_eq!(result["cacheScope"], "private", "mode {mode:?}: {v}");
            // The shape follows the era; what is offered does not. The allowlist
            // names `echo` alone, so the mock's `delete_repo` stays hidden.
            let names: Vec<&str> = result["tools"]
                .as_array()
                .map(|tools| tools.iter().filter_map(|t| t["name"].as_str()).collect())
                .unwrap_or_default();
            assert_eq!(names, ["echo"], "mode {mode:?}: {v}");
        }

        if mode.serves_legacy() {
            // No `_meta` and no mirrored headers: what a 2025-11-25 client sends.
            let resp = client()
                .post(&url)
                .header("content-type", "application/json")
                .body(r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#)
                .send()
                .await
                .unwrap();
            assert_eq!(resp.status(), 200, "mode {mode:?}");
            let v: Value = serde_json::from_str(&resp.text().await.unwrap()).unwrap();
            let keys: Vec<&str> = v["result"]
                .as_object()
                .map(|r| r.keys().map(String::as_str).collect())
                .unwrap_or_default();
            assert_eq!(
                keys,
                ["tools"],
                "mode {mode:?}: a legacy result carries no `resultType`, `ttlMs` or \
                 `cacheScope`, exactly as before: {v}"
            );
        }
    }
}

/// stdio has no listener to classify a request, and a modern client on it is
/// owed the same shape. The gateway reads the era off each message itself, so
/// one process answers both eras, each in its own.
#[tokio::test]
async fn on_stdio_each_tools_list_is_answered_in_the_era_it_was_sent_in() {
    /// Hand one message straight to the gateway, as stdio does.
    async fn result_of(gw: &mut Gateway, msg: Value) -> Value {
        let msg: Message = serde_json::from_value(msg).unwrap();
        gw.handle(msg).await.unwrap().unwrap().result.unwrap()
    }
    let (mut gw, _dir) = gateway(WireMode::Dual).await;

    let modern = result_of(&mut gw, modern_request(1, "tools/list")).await;
    assert_eq!(modern["resultType"], "complete", "got: {modern}");
    assert_eq!(modern["ttlMs"], 0, "got: {modern}");
    assert_eq!(modern["cacheScope"], "private", "got: {modern}");

    let legacy = result_of(
        &mut gw,
        json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/list" }),
    )
    .await;
    assert_eq!(
        legacy,
        json!({ "tools": modern["tools"] }),
        "the same tools, and nothing a 2025-11-25 client has not always had"
    );
}

/// A method the gateway does not serve is `404` with `-32601` on the modern
/// wire, as the revision requires, so a client can tell it from a missing
/// endpoint by the body. The legacy wire asks no status of it: `200`.
#[tokio::test]
async fn a_method_mcpdef_does_not_serve_is_404_on_the_modern_wire_and_200_on_the_legacy() {
    let (url, _dir) = start(WireMode::Dual).await;

    let (status, body) = post_modern(&url, &modern_request(7, "logging/setLevel"), None).await;
    assert_eq!(status, 404);
    assert_eq!(body["id"], 7);
    assert_eq!(body["error"]["code"], -32601);

    let resp = client()
        .post(&url)
        .header("content-type", "application/json")
        .body(r#"{"jsonrpc":"2.0","id":8,"method":"logging/setLevel","params":{"level":"debug"}}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let v: Value = serde_json::from_str(&resp.text().await.unwrap()).unwrap();
    assert_eq!(v["error"]["code"], -32601);

    // Any other error is still `200`: only an unserved method is not found.
    let (status, body) = post_modern(&url, &modern_request(9, "completion/complete"), None).await;
    assert_eq!(status, 200);
    assert_eq!(body["error"]["code"], -32602);
}
