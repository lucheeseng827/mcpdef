// SPDX-License-Identifier: Apache-2.0
//! Metrics only ever count the governed `tools/call` hot path — never the
//! pin/rug-pull `connect` inspection or `forward_to_primary`'s relay of
//! arbitrary methods — and an unrouted call's caller-controlled tool name is
//! collapsed to a fixed label instead of feeding the Prometheus series set.

use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::Router;
use mcpdef::{Gateway, Metrics};
use mcpdef_audit::Ledger;
use mcpdef_core::{Id, Message};
use mcpdef_policy::Policy;
use mcpdef_transport::HttpClient;
use std::sync::Arc;

fn respond(req: &Message) -> Option<Message> {
    let id = req.id.clone();
    match req.method() {
        Some("initialize") => Some(Message::result(
            id?,
            serde_json::json!({
                "protocolVersion": "2025-11-25",
                "capabilities": { "tools": {} },
                "serverInfo": { "name": "remote-mock", "version": "0" }
            }),
        )),
        Some("notifications/initialized") => None,
        Some("tools/list") => Some(Message::result(id?, serde_json::json!({ "tools": [] }))),
        // Anything else (e.g. "resources/list") goes through forward_to_primary.
        _ => id.map(|i| Message::error(i, -32601, "method not found")),
    }
}

async fn modern(body: String) -> Response {
    let Ok(msg) = Message::from_json_line(body.trim()) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    match respond(&msg) {
        Some(resp) => {
            let mut r = (
                [(header::CONTENT_TYPE, "application/json")],
                resp.to_json_line(),
            )
                .into_response();
            if msg.method() == Some("initialize") {
                r.headers_mut()
                    .insert("mcp-session-id", HeaderValue::from_static("s1"));
            }
            r
        }
        None => StatusCode::ACCEPTED.into_response(),
    }
}

async fn spawn() -> String {
    let app = Router::new().route("/mcp", post(modern));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    format!("http://{addr}")
}

async fn gateway_with_metrics(dir: &std::path::Path) -> (Gateway, Arc<Metrics>) {
    let base = spawn().await;
    let audit = dir.join("audit.log");
    let ledger = Ledger::open(&audit).unwrap();
    let metrics = Arc::new(Metrics::new(1));
    let mut gw = Gateway::new(Policy::new(), ledger, "agent:test").with_metrics(metrics.clone());
    let upstream = HttpClient::streamable(format!("{base}/mcp")).unwrap();
    gw.add_upstream("remote", Box::new(upstream)).await.unwrap();
    (gw, metrics)
}

#[tokio::test]
async fn forwarded_non_tool_call_is_audited_but_not_metered() {
    let dir = tempfile::tempdir().unwrap();
    let (mut gw, metrics) = gateway_with_metrics(dir.path()).await;

    gw.handle(Message::request(Id::Num(2), "resources/list", None))
        .await
        .unwrap();

    // forward_to_primary's Allow is audited (ledger), but mcpdef_tools_calls_total
    // is a tools/call-only counter — nothing should have been recorded.
    assert!(
        !metrics.render_prometheus().contains("resources/list"),
        "a forwarded non-tools/call method must not appear in tool-call metrics"
    );
    assert_eq!(metrics.snapshot_json()["total"], serde_json::json!(0));
}

#[tokio::test]
async fn unrouted_tool_call_collapses_to_a_fixed_metrics_label() {
    let dir = tempfile::tempdir().unwrap();
    let (mut gw, metrics) = gateway_with_metrics(dir.path()).await;

    // Two distinct, caller-controlled "tool names" hitting the unknown-tool gate.
    for name in ["../../etc/passwd", "not-a-real-tool-xyz"] {
        gw.handle(Message::request(
            Id::Num(3),
            "tools/call",
            Some(serde_json::json!({ "name": name, "arguments": {} })),
        ))
        .await
        .unwrap();
    }

    let rendered = metrics.render_prometheus();
    assert!(
        !rendered.contains("not-a-real-tool-xyz") && !rendered.contains("passwd"),
        "an attacker-chosen tool name must never become a Prometheus label value"
    );
    // Both calls collapse onto the same (unrouted, "(unknown)", deny, unknown-tool)
    // series instead of allocating one series per distinct bogus name.
    assert!(
        rendered.contains("tool=\"(unknown)\"") && rendered.contains("} 2\n"),
        "both unrouted calls must collapse onto one fixed-label series:\n{rendered}"
    );
}
