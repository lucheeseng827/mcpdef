// SPDX-License-Identifier: Apache-2.0
//! Integration tests for the downstream Streamable HTTP listener (`mcpdef run
//! --http`): a real client reaches mcpdef over HTTP, `initialize` / `tools/call`
//! round-trip, a notification gets `202`, a cross-site `Origin` is rejected
//! `403`, and `GET` is `405`. The upstream is the real stdio mock.

use mcpdef::listener::{serve_http_on, HttpConfig};
use mcpdef::Gateway;
use mcpdef_audit::Ledger;
use mcpdef_policy::{Policy, ServerPolicy};
use mcpdef_transport::StdioChild;
use serde_json::Value;
use tokio::net::TcpListener;

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

/// A loopback client that does NOT route through any ambient proxy (the test
/// env sets HTTPS_PROXY, which would otherwise hijack the 127.0.0.1 request).
fn client() -> reqwest::Client {
    reqwest::Client::builder().no_proxy().build().unwrap()
}

/// Start a listener on an ephemeral loopback port; returns its `/mcp` URL and the
/// tempdir guard (kept alive so the audit file outlives the server).
async fn start(allowed_origins: Vec<String>) -> (String, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let ledger = Ledger::open(dir.path().join("audit.log")).unwrap();
    let mut gw = Gateway::new(allow_echo(), ledger, "agent:test");
    gw.add_upstream("mock", spawn_mock()).await.unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let cfg = HttpConfig {
        listen: addr.to_string(),
        allowed_origins,
        max_inflight: None,
    };
    // No OAuth verifier — these tests cover the unauthenticated listener.
    tokio::spawn(serve_http_on(listener, gw, cfg, None));
    (format!("http://{addr}/mcp"), dir)
}

#[tokio::test]
async fn post_initialize_and_tools_call_round_trip() {
    let (url, _dir) = start(vec![]).await;
    let c = client();

    // initialize → the gateway answers as the server.
    let resp = c
        .post(&url)
        .header("content-type", "application/json")
        .body(r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"clientInfo":{"name":"test"}}}"#)
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
    assert_eq!(v["result"]["serverInfo"]["name"], "mcpdef");

    // tools/call echo → forwarded to the mock, isError:false.
    let resp = c
        .post(&url)
        .body(r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"echo","arguments":{"msg":"hi"}}}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let v: Value = serde_json::from_str(&resp.text().await.unwrap()).unwrap();
    assert_eq!(v["result"]["isError"], false);
}

#[tokio::test]
async fn notification_gets_202_and_bad_origin_gets_403_and_get_gets_405() {
    let (url, _dir) = start(vec![]).await;
    let c = client();

    // A notification (no id) → 202 Accepted, no body.
    let resp = c
        .post(&url)
        .body(r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 202);

    // A cross-site browser Origin → 403 (DNS-rebinding defense).
    let resp = c
        .post(&url)
        .header("origin", "https://evil.example.com")
        .body(r#"{"jsonrpc":"2.0","id":3,"method":"initialize","params":{}}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);

    // A loopback Origin is allowed (would be a real browser on localhost).
    let resp = c
        .post(&url)
        .header("origin", "http://localhost:1234")
        .body(r#"{"jsonrpc":"2.0","id":4,"method":"initialize","params":{}}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // No server→client GET stream is offered → 405.
    let resp = c.get(&url).send().await.unwrap();
    assert_eq!(resp.status(), 405);
}

#[tokio::test]
async fn explicit_allowed_origin_passes() {
    let (url, _dir) = start(vec!["https://app.example.com".to_string()]).await;
    let resp = client()
        .post(&url)
        .header("origin", "https://app.example.com")
        .body(r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
}
