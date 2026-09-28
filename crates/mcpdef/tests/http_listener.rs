// SPDX-License-Identifier: Apache-2.0
//! Integration tests for the downstream Streamable HTTP listener (`mcpdef run
//! --http`): a real client reaches mcpdef over HTTP, `initialize` / `tools/call`
//! round-trip, a notification gets `202`, a cross-site `Origin` is rejected
//! `403`, and `GET` is `405`. The upstream is the real stdio mock.

use mcpdef::listener::{serve_http_on, HttpConfig};
use mcpdef::Gateway;
use mcpdef_audit::{read_all, Ledger, Record};
use mcpdef_core::Message;
use mcpdef_policy::{Policy, ServerPolicy};
use mcpdef_transport::{StdioChild, Transport, TransportError};
use serde_json::{json, Value};
use std::collections::VecDeque;
use std::path::Path;
use std::time::{Duration, Instant};
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

/// An upstream in process: it answers `tools/call` for `slow_tool` after `delay`,
/// and everything else at once.
struct SlowUpstream {
    delay: Duration,
    replies: VecDeque<(Message, bool)>,
}

#[async_trait::async_trait]
impl Transport for SlowUpstream {
    async fn send(&mut self, msg: Message) -> Result<(), TransportError> {
        // A notification gets no reply.
        let Some(id) = msg.id.clone() else {
            return Ok(());
        };
        let (result, slow) = match msg.method.as_deref().unwrap_or_default() {
            "initialize" => (
                json!({
                    "protocolVersion": "2025-11-25",
                    "capabilities": { "tools": {} },
                    "serverInfo": { "name": "slow-upstream", "version": "0.0.0" }
                }),
                false,
            ),
            "tools/list" => (
                json!({ "tools": [
                    { "name": "slow_tool", "inputSchema": { "type": "object" } },
                    { "name": "fast_tool", "inputSchema": { "type": "object" } }
                ] }),
                false,
            ),
            "tools/call" => {
                let tool = msg
                    .params
                    .as_ref()
                    .and_then(|p| p["name"].as_str())
                    .unwrap_or_default()
                    .to_string();
                let slow = tool == "slow_tool";
                (
                    json!({ "content": [{ "type": "text", "text": tool }] }),
                    slow,
                )
            }
            _ => (json!({}), false),
        };
        self.replies.push_back((Message::result(id, result), slow));
        Ok(())
    }

    async fn recv(&mut self) -> Result<Option<Message>, TransportError> {
        let Some((reply, slow)) = self.replies.pop_front() else {
            return Ok(None);
        };
        if slow {
            tokio::time::sleep(self.delay).await;
        }
        Ok(Some(reply))
    }
}

/// The ledger's records so far, none before the first is written.
fn records(path: &Path) -> Vec<Record> {
    match path.exists() {
        true => read_all(path).unwrap(),
        false => Vec::new(),
    }
}

/// A client that gives up mid-call must not take the call's audit record with
/// it, and the call keeps its in-flight slot until it really ends.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_call_is_audited_even_when_its_client_disconnects() {
    let dir = tempfile::tempdir().unwrap();
    let audit = dir.path().join("audit.log");
    let mut policy = Policy::new();
    policy.insert(
        "slow",
        ServerPolicy {
            allow_tools: Some(vec!["slow_tool".into(), "fast_tool".into()]),
            deny: vec![],
        },
    );
    let mut gw = Gateway::new(policy, Ledger::open(&audit).unwrap(), "agent:test");
    let upstream = SlowUpstream {
        delay: Duration::from_millis(1_000),
        replies: VecDeque::new(),
    };
    gw.add_upstream("slow", Box::new(upstream)).await.unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let cfg = HttpConfig {
        listen: addr.to_string(),
        allowed_origins: vec![],
        max_inflight: Some(1),
    };
    tokio::spawn(serve_http_on(listener, gw, cfg, None));
    let url = format!("http://{addr}/mcp");
    let call = |id: u32, tool: &str| {
        json!({
            "jsonrpc": "2.0", "id": id, "method": "tools/call",
            "params": { "name": tool, "arguments": {} }
        })
        .to_string()
    };
    let post = |client: &reqwest::Client, body: String| {
        client
            .post(&url)
            .header("content-type", "application/json")
            .body(body)
            .send()
    };

    let impatient = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_millis(200))
        .build()
        .unwrap();
    let gave_up = post(&impatient, call(1, "slow_tool")).await;
    assert!(gave_up.is_err_and(|e| e.is_timeout()));
    assert!(
        records(&audit).is_empty(),
        "the upstream has not answered yet"
    );

    // The abandoned call still holds the only slot.
    let shed = post(&client(), call(2, "fast_tool")).await.unwrap();
    assert_eq!(shed.status(), 503);

    // Once the upstream answers, the call is audited, and its slot comes back.
    let deadline = Instant::now() + Duration::from_secs(5);
    while records(&audit).is_empty() {
        assert!(
            Instant::now() < deadline,
            "the abandoned call was never audited"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let recs = records(&audit);
    assert_eq!(recs.len(), 1);
    assert_eq!(
        (recs[0].tool.as_deref(), recs[0].decision.as_str()),
        (Some("slow_tool"), "allow")
    );
    let after = post(&client(), call(3, "fast_tool")).await.unwrap();
    assert_eq!(after.status(), 200);
    let v: Value = serde_json::from_str(&after.text().await.unwrap()).unwrap();
    assert_eq!(v["result"]["content"][0]["text"], "fast_tool");
}
