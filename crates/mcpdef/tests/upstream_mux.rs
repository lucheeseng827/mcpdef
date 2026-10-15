// SPDX-License-Identifier: Apache-2.0
//! The upstream mux over a real stdio child that answers out of order.
//!
//! `mock_mcp_server --out-of-order` answers each `tools/call` after its
//! `arguments.delay_ms`, on a thread of its own, so a short call sent second is
//! answered first.

use mcpdef::{handshake_list, Gateway};
use mcpdef_audit::{Ledger, Record};
use mcpdef_core::{method, Id, Message};
use mcpdef_policy::{Policy, ServerPolicy};
use mcpdef_transport::{CallError, StdioChild, UpstreamHandle, DEFAULT_MAX_INFLIGHT};
use serde_json::json;
use std::time::{Duration, Instant};

fn out_of_order_child() -> Box<StdioChild> {
    let bin = env!("CARGO_BIN_EXE_mock_mcp_server").to_string();
    Box::new(StdioChild::spawn(&[bin, "--out-of-order".into()]).unwrap())
}

/// The child, opened on its raw transport and then handed to the mux, as the
/// gateway does it.
async fn open() -> UpstreamHandle {
    let mut child = out_of_order_child();
    handshake_list(&mut *child).await.unwrap();
    UpstreamHandle::spawn("mock", child, DEFAULT_MAX_INFLIGHT)
}

/// `echo`, answered after `delay_ms`, carrying `tag` so its reply is recognisable.
fn echo(id: i64, tag: &str, delay_ms: u64) -> Message {
    Message::request(
        Id::Num(id),
        method::TOOLS_CALL,
        Some(json!({ "name": "echo", "arguments": { "tag": tag, "delay_ms": delay_ms } })),
    )
}

fn text(reply: &Message) -> &str {
    reply.result.as_ref().unwrap()["content"][0]["text"]
        .as_str()
        .unwrap()
}

async fn answered_at(up: UpstreamHandle, request: Message) -> (Message, Instant) {
    let reply = up
        .call(request, Some(Duration::from_secs(10)))
        .await
        .unwrap();
    (reply, Instant::now())
}

#[tokio::test]
async fn an_out_of_order_stdio_upstream_answers_two_slow_calls_correctly_routed() {
    let up = open().await;
    let slow = tokio::spawn(answered_at(up.clone(), echo(1, "slow", 1000)));
    // Only once the slow request is on its way does the fast one follow it.
    while up.inflight() == 0 {
        tokio::task::yield_now().await;
    }
    let fast = tokio::spawn(answered_at(up.clone(), echo(1, "fast", 100)));

    let (fast, fast_at) = fast.await.unwrap();
    let (slow, slow_at) = slow.await.unwrap();
    assert!(text(&slow).contains(r#""tag":"slow""#), "{}", text(&slow));
    assert!(text(&fast).contains(r#""tag":"fast""#), "{}", text(&fast));
    assert_eq!((slow.id, fast.id), (Some(Id::Num(1)), Some(Id::Num(1))));
    assert!(
        fast_at < slow_at,
        "the fast call is answered first, not held behind the slow one"
    );
    assert_eq!(up.inflight(), 0);
}

#[tokio::test]
async fn a_late_stdio_reply_is_dropped_not_handed_to_the_next_call() {
    let up = open().await;
    let limit = Duration::from_millis(100);
    assert_eq!(
        up.call(echo(7, "late", 400), Some(limit)).await,
        Err(CallError::Timeout(limit))
    );
    // The late reply lands while this call, with the same caller id, waits.
    let next = up
        .call(echo(7, "next", 800), Some(Duration::from_secs(10)))
        .await
        .unwrap();
    assert!(text(&next).contains(r#""tag":"next""#), "{}", text(&next));
    assert_eq!(next.id, Some(Id::Num(7)));
}

/// The same, end to end: through the gateway, a timed-out call's reply cannot
/// answer the next call to that upstream.
#[tokio::test]
async fn through_the_gateway_a_late_reply_never_answers_the_next_call() {
    let dir = tempfile::tempdir().unwrap();
    let audit = dir.path().join("audit.log");
    let mut policy = Policy::new();
    policy.insert(
        "mock",
        ServerPolicy {
            allow_tools: Some(vec!["echo".into()]),
            deny: vec![],
        },
    );
    let mut gw = Gateway::new(policy, Ledger::open(&audit).unwrap(), "agent:test")
        .with_upstream_timeout(Some(Duration::from_millis(1000)));
    gw.add_upstream("mock", out_of_order_child()).await.unwrap();

    // Times out at 1 s; its reply arrives at 1.5 s, while the next call waits
    // for its own at about 1.7 s.
    let late = gw.handle(echo(1, "late", 1500)).await.unwrap().unwrap();
    assert!(text(&late).contains("did not respond"), "{}", text(&late));
    let next = gw.handle(echo(2, "next", 700)).await.unwrap().unwrap();
    assert!(text(&next).contains(r#""tag":"next""#), "{}", text(&next));
    assert_eq!(next.id, Some(Id::Num(2)));

    drop(gw);
    let rules: Vec<Option<String>> = std::fs::read_to_string(&audit)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str::<Record>(l).unwrap().rule)
        .collect();
    assert_eq!(rules, [Some("upstream-timeout".to_string()), None]);
}

/// Concurrent calls whose requests and replies are far larger than a pipe's
/// buffer, to the plain mock: it reads one line, writes the whole reply, and
/// only then reads the next line. A transport that stopped reading while it
/// wrote would wait on the child while the child waited on it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn large_concurrent_calls_to_a_line_at_a_time_child_do_not_deadlock() {
    let bin = env!("CARGO_BIN_EXE_mock_mcp_server").to_string();
    let mut child = Box::new(StdioChild::spawn(&[bin]).unwrap());
    handshake_list(&mut *child).await.unwrap();
    let up = UpstreamHandle::spawn("mock", child, DEFAULT_MAX_INFLIGHT);
    let blob = "x".repeat(512 * 1024);
    let calls: Vec<_> = (0..8)
        .map(|n| {
            let (up, blob) = (up.clone(), blob.clone());
            tokio::spawn(async move {
                let request = Message::request(
                    Id::Num(n),
                    method::TOOLS_CALL,
                    Some(json!({ "name": "echo", "arguments": { "n": n, "blob": blob } })),
                );
                up.call(request, Some(Duration::from_secs(20))).await
            })
        })
        .collect();
    for (n, call) in calls.into_iter().enumerate() {
        let reply = call.await.unwrap().expect("no deadlock, and no timeout");
        assert!(text(&reply).contains(&format!("\"n\":{n}")));
        assert!(text(&reply).len() > 512 * 1024);
    }
}
