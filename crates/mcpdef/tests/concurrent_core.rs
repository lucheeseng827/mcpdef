// SPDX-License-Identifier: Apache-2.0
//! The concurrent gateway core: calls run through one gateway at once, over
//! HTTP and over stdio, and a slow upstream holds up only the calls sent to it.
//!
//! The gate every PR runs: while one upstream holds a 2 s call, calls to the
//! others complete within 100 ms.

use mcpdef::listener::{serve_http_on, HttpConfig};
use mcpdef::{serve_stdio_on, Gateway};
use mcpdef_audit::{verify, Ledger, Record};
use mcpdef_auth::Principal;
use mcpdef_core::wire::WireMode;
use mcpdef_core::{method, Id, Message};
use mcpdef_policy::{Policy, ServerPolicy};
use mcpdef_transport::{duplex_pair, Duplex, Transport};
use serde_json::json;
use std::path::Path;
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio::sync::mpsc;

/// An in-process upstream offering `tools`. It answers each call on a task of
/// its own, after the call's `delay_ms`, as a real server handling calls in
/// parallel would.
fn upstream(tools: &'static [&'static str]) -> Duplex {
    let (near, mut far) = duplex_pair();
    tokio::spawn(async move {
        let (out, mut replies) = mpsc::unbounded_channel::<Message>();
        loop {
            tokio::select! {
                msg = far.recv() => {
                    let Ok(Some(msg)) = msg else { return };
                    let Some(id) = msg.id.clone() else { continue };
                    match msg.method() {
                        Some(method::INITIALIZE) => {
                            let _ = out.send(Message::result(id, json!({
                                "protocolVersion": "2025-11-25",
                                "capabilities": { "tools": {} },
                                "serverInfo": { "name": "mock", "version": "0" },
                            })));
                        }
                        Some(method::TOOLS_LIST) => {
                            let list: Vec<_> = tools
                                .iter()
                                .map(|t| json!({ "name": t, "inputSchema": { "type": "object" } }))
                                .collect();
                            let _ = out.send(Message::result(id, json!({ "tools": list })));
                        }
                        Some(method::TOOLS_CALL) => {
                            let delay = msg.params.as_ref().and_then(|p| p["arguments"]["delay_ms"].as_u64());
                            let name = msg.tool_name().unwrap_or_default().to_string();
                            let out = out.clone();
                            tokio::spawn(async move {
                                tokio::time::sleep(Duration::from_millis(delay.unwrap_or(0))).await;
                                let _ = out.send(Message::result(id, json!({
                                    "content": [{ "type": "text", "text": name }],
                                    "isError": false,
                                })));
                            });
                        }
                        _ => {
                            let _ = out.send(Message::result(id, json!({})));
                        }
                    }
                }
                Some(reply) = replies.recv() => {
                    if far.send(reply).await.is_err() {
                        return;
                    }
                }
            }
        }
    });
    near
}

type Upstreams = &'static [(&'static str, &'static [&'static str])];

async fn gateway(audit: &Path, upstreams: Upstreams) -> Gateway {
    let mut policy = Policy::new();
    for (id, tools) in upstreams {
        policy.insert(
            *id,
            ServerPolicy {
                allow_tools: Some(tools.iter().map(|t| t.to_string()).collect()),
                deny: vec![],
            },
        );
    }
    let mut gw = Gateway::new(policy, Ledger::open(audit).unwrap(), "agent:baseline");
    for (id, tools) in upstreams {
        gw.add_upstream(*id, Box::new(upstream(tools)))
            .await
            .unwrap();
    }
    gw
}

const SLOW_AND_FAST: Upstreams = &[("slow", &["slow_tool"]), ("fast", &["fast_tool"])];

fn call(id: i64, tool: &str, delay_ms: u64) -> Message {
    Message::request(
        Id::Num(id),
        method::TOOLS_CALL,
        Some(json!({ "name": tool, "arguments": { "delay_ms": delay_ms } })),
    )
}

fn text(reply: &Message) -> &str {
    reply.result.as_ref().unwrap()["content"][0]["text"]
        .as_str()
        .unwrap_or_default()
}

async fn serve_http(gw: Gateway, max_inflight: Option<usize>) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let cfg = HttpConfig {
        listen: addr.to_string(),
        allowed_origins: vec![],
        max_inflight,
        wire: WireMode::default(),
    };
    tokio::spawn(serve_http_on(listener, gw, cfg, None));
    format!("http://{addr}/mcp")
}

fn client() -> reqwest::Client {
    mcpdef_transport::install_crypto_provider();
    reqwest::Client::builder().no_proxy().build().unwrap()
}

async fn post(c: &reqwest::Client, url: &str, msg: &Message) -> reqwest::Result<reqwest::Response> {
    c.post(url)
        .header("content-type", "application/json")
        .body(msg.to_json_line())
        .send()
        .await
}

async fn post_reply(c: &reqwest::Client, url: &str, msg: &Message) -> Message {
    let resp = post(c, url, msg).await.unwrap();
    assert_eq!(resp.status(), 200);
    Message::from_json_line(&resp.text().await.unwrap()).unwrap()
}

fn records(audit: &Path) -> Vec<Record> {
    std::fs::read_to_string(audit)
        .unwrap_or_default()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn over_http_a_slow_upstream_holds_up_only_its_own_calls() {
    let dir = tempfile::tempdir().unwrap();
    let url = serve_http(
        gateway(&dir.path().join("audit.log"), SLOW_AND_FAST).await,
        None,
    )
    .await;
    let c = client();

    let slow = tokio::spawn({
        let (c, url) = (c.clone(), url.clone());
        async move { post_reply(&c, &url, &call(1, "slow_tool", 2_000)).await }
    });
    tokio::time::sleep(Duration::from_millis(100)).await;
    for n in 0..5 {
        let started = Instant::now();
        let reply = post_reply(&c, &url, &call(10 + n, "fast_tool", 0)).await;
        let took = started.elapsed();
        assert_eq!(text(&reply), "fast_tool");
        assert!(
            took < Duration::from_millis(100),
            "call {n} waited {took:?} behind the slow one"
        );
    }
    assert!(!slow.is_finished(), "the slow call is still in flight");
    assert_eq!(text(&slow.await.unwrap()), "slow_tool");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn over_stdio_a_slow_upstream_holds_up_only_its_own_calls() {
    let dir = tempfile::tempdir().unwrap();
    let gw = gateway(&dir.path().join("audit.log"), SLOW_AND_FAST).await;
    let (mut to_gateway, gateway_in) = tokio::io::duplex(64 * 1024);
    let (gateway_out, from_gateway) = tokio::io::duplex(64 * 1024);
    let server =
        tokio::spawn(
            async move { serve_stdio_on(&gw, BufReader::new(gateway_in), gateway_out).await },
        );
    let mut replies = BufReader::new(from_gateway).lines();

    let send = |m: Message| format!("{}\n", m.to_json_line());
    to_gateway
        .write_all(send(call(1, "slow_tool", 2_000)).as_bytes())
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    for n in 0..5 {
        let started = Instant::now();
        to_gateway
            .write_all(send(call(10 + n, "fast_tool", 0)).as_bytes())
            .await
            .unwrap();
        let reply = Message::from_json_line(&replies.next_line().await.unwrap().unwrap()).unwrap();
        let took = started.elapsed();
        assert_eq!(
            (reply.id.clone(), text_owned(&reply)),
            (Some(Id::Num(10 + n)), "fast_tool".into())
        );
        assert!(
            took < Duration::from_millis(100),
            "call {n} waited {took:?} behind the slow one"
        );
    }
    // Closing stdin still lets the slow call finish and answer.
    drop(to_gateway);
    let reply = Message::from_json_line(&replies.next_line().await.unwrap().unwrap()).unwrap();
    assert_eq!(
        (reply.id.clone(), text_owned(&reply)),
        (Some(Id::Num(1)), "slow_tool".into())
    );
    server.await.unwrap().unwrap();
    assert!(replies.next_line().await.unwrap().is_none());
}

fn text_owned(reply: &Message) -> String {
    text(reply).to_string()
}

const MANY: Upstreams = &[(
    "many",
    &["t0", "t1", "t2", "t3", "t4", "t5", "t6", "t7", "anon"],
)];

fn principal(subject: &str) -> Principal {
    Principal {
        subject: subject.into(),
        scopes: vec![],
        roles: vec![],
        client_id: None,
        issuer: "https://auth.example.com".into(),
    }
}

/// The concurrent form of `audit_identity.rs`: callers with different
/// principals, callers with none, and clients renaming themselves, all at once.
/// Every record must carry the identity of the call it records.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn concurrent_callers_each_keep_their_own_identity() {
    let dir = tempfile::tempdir().unwrap();
    let audit = dir.path().join("audit.log");
    // As the HTTP listener serves it: `initialize` may not rename anyone.
    let gw = gateway(&audit, MANY).await.shared_across_clients();

    let mut tasks = Vec::new();
    for round in 0..10 {
        for user in 0..8 {
            let gw = gw.clone();
            tasks.push(tokio::spawn(async move {
                let who = principal(&format!("user{user}"));
                let delay = (user * 7 + round) % 5;
                gw.handle_authed(call(round, &format!("t{user}"), delay as u64), Some(&who))
                    .await
            }));
        }
        let gw = gw.clone();
        tasks.push(tokio::spawn(async move {
            let hello = Message::request(
                Id::Num(99),
                method::INITIALIZE,
                Some(json!({ "clientInfo": { "name": "impostor" } })),
            );
            gw.handle(hello).await.unwrap();
            gw.handle(call(round, "anon", 1)).await
        }));
    }
    for task in tasks {
        task.await.unwrap().unwrap().unwrap();
    }

    let recs = records(&audit);
    assert_eq!(recs.len(), 90);
    for r in &recs {
        let tool = r.tool.as_deref().unwrap();
        let expected = match tool.strip_prefix('t') {
            Some(user) => format!("sub:user{user}"),
            None => "agent:baseline".to_string(),
        };
        assert_eq!(
            r.agent, expected,
            "a record for {tool} carries someone else's identity"
        );
    }
}

/// Many concurrent calls over HTTP, allowed and denied: every one is audited,
/// once, and the chain verifies.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn the_ledger_stays_valid_under_load() {
    let dir = tempfile::tempdir().unwrap();
    let audit = dir.path().join("audit.log");
    let url = serve_http(gateway(&audit, MANY).await, None).await;
    let c = client();

    let calls: Vec<_> = (0..200)
        .map(|n| {
            let (c, url) = (c.clone(), url.clone());
            // One call in five names a tool nobody offers: denied, and audited too.
            let tool = if n % 5 == 0 {
                "missing".to_string()
            } else {
                format!("t{}", n % 8)
            };
            tokio::spawn(async move { post_reply(&c, &url, &call(n, &tool, (n % 3) as u64)).await })
        })
        .collect();
    for call in calls {
        call.await.unwrap();
    }

    let report = verify(&audit).unwrap();
    assert!(report.ok(), "broken at {:?}", report.broken_at);
    assert_eq!(report.records, 200);
    let denied = records(&audit)
        .iter()
        .filter(|r| r.decision == "deny")
        .count();
    assert_eq!(denied, 40);
}

/// A client that gives up mid-call must not take the call's audit record with
/// it, and the call keeps its in-flight slot until it really ends.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_call_is_audited_even_when_its_client_disconnects() {
    let dir = tempfile::tempdir().unwrap();
    let audit = dir.path().join("audit.log");
    let url = serve_http(gateway(&audit, SLOW_AND_FAST).await, Some(1)).await;
    mcpdef_transport::install_crypto_provider();
    let impatient = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_millis(200))
        .build()
        .unwrap();

    let gave_up = post(&impatient, &url, &call(1, "slow_tool", 1_000)).await;
    assert!(gave_up.is_err_and(|e| e.is_timeout()));
    assert!(
        records(&audit).is_empty(),
        "the upstream has not answered yet"
    );

    // The abandoned call still holds the only slot.
    let shed = post(&client(), &url, &call(2, "fast_tool", 0))
        .await
        .unwrap();
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
    assert_eq!(
        text(&post_reply(&client(), &url, &call(3, "fast_tool", 0)).await),
        "fast_tool"
    );
}

/// On stdio a request that fails at the gateway gets an error reply, and the
/// session carries on, rather than the whole session ending with it.
///
/// Since 0.4.0-alpha.1 the failure here, a call to an upstream that is down, is a tool
/// error audited as `upstream-down`, where it was a JSON-RPC `-32603` error.
#[tokio::test]
async fn over_stdio_a_failed_request_gets_an_error_reply() {
    let dir = tempfile::tempdir().unwrap();
    let mut policy = Policy::new();
    for (id, tool) in [("fast", "fast_tool"), ("gone", "gone_tool")] {
        policy.insert(
            id,
            ServerPolicy {
                allow_tools: Some(vec![tool.into()]),
                deny: vec![],
            },
        );
    }
    let ledger = Ledger::open(dir.path().join("audit.log")).unwrap();
    let mut gw = Gateway::new(policy, ledger, "agent:baseline");
    gw.add_upstream("fast", Box::new(upstream(&["fast_tool"])))
        .await
        .unwrap();
    // An upstream that opens, then hangs up.
    let (near, mut far) = duplex_pair();
    let hangs_up = tokio::spawn(async move {
        while let Ok(Some(msg)) = far.recv().await {
            let Some(id) = msg.id.clone() else { continue };
            let listing = msg.method() == Some(method::TOOLS_LIST);
            let reply = if listing {
                Message::result(
                    id,
                    json!({ "tools": [{ "name": "gone_tool", "inputSchema": { "type": "object" } }] }),
                )
            } else {
                Message::result(
                    id,
                    json!({ "protocolVersion": "2025-11-25", "capabilities": {} }),
                )
            };
            far.send(reply).await.unwrap();
            if listing {
                return;
            }
        }
    });
    gw.add_upstream("gone", Box::new(near)).await.unwrap();
    hangs_up.await.unwrap();

    let (mut to_gateway, gateway_in) = tokio::io::duplex(64 * 1024);
    let (gateway_out, from_gateway) = tokio::io::duplex(64 * 1024);
    let server =
        tokio::spawn(
            async move { serve_stdio_on(&gw, BufReader::new(gateway_in), gateway_out).await },
        );
    let mut replies = BufReader::new(from_gateway).lines();
    for (id, tool) in [(1, "gone_tool"), (2, "fast_tool")] {
        let line = format!("{}\n", call(id, tool, 0).to_json_line());
        to_gateway.write_all(line.as_bytes()).await.unwrap();
        let reply = Message::from_json_line(&replies.next_line().await.unwrap().unwrap()).unwrap();
        assert_eq!(reply.id, Some(Id::Num(id)));
        if id == 1 {
            assert_eq!(reply.result.as_ref().unwrap()["isError"], true);
            let message = text(&reply);
            assert!(message.contains("upstream 'gone' is down"), "{message}");
        } else {
            assert_eq!(text(&reply), "fast_tool");
        }
    }
    drop(to_gateway);
    server.await.unwrap().unwrap();
}
