// SPDX-License-Identifier: Apache-2.0
//! Gateway-over-HTTP bridge test: a stdio-style client (the gateway's `handle`
//! API) fronting a **Streamable HTTP** upstream. Proves the gateway's governance
//! (tools/list filtering, allow/deny, audit) is identical regardless of upstream
//! transport — the point of the transport-mux design (ROADMAP Phase 1 / 1.5).

use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::Router;
use mcpdef::Gateway;
use mcpdef_audit::{verify, Ledger};
use mcpdef_core::{Id, Message};
use mcpdef_policy::{Policy, ServerPolicy};
use mcpdef_transport::HttpClient;

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
        Some("tools/list") => Some(Message::result(
            id?,
            serde_json::json!({ "tools": [{ "name": "echo" }, { "name": "delete_repo" }] }),
        )),
        Some("tools/call") => {
            let name = req.tool_name().unwrap_or_default();
            Some(Message::result(
                id?,
                serde_json::json!({ "content": [{ "type": "text", "text": name }], "isError": false }),
            ))
        }
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

#[tokio::test]
async fn gateway_bridges_to_a_streamable_http_upstream() {
    let base = spawn().await;
    let dir = tempfile::tempdir().unwrap();
    let audit = dir.path().join("audit.log");

    let mut policy = Policy::new();
    policy.insert(
        "remote",
        ServerPolicy {
            allow_tools: Some(vec!["echo".into()]),
            deny: vec!["delete_*".into()],
        },
    );

    let ledger = Ledger::open(&audit).unwrap();
    let mut gw = Gateway::new(policy, ledger, "agent:test");

    let upstream = HttpClient::streamable(format!("{base}/mcp")).unwrap();
    gw.add_upstream("remote", Box::new(upstream)).await.unwrap();
    assert_eq!(gw.upstream_count(), 1);

    // tools/list hides the denied delete_repo.
    let list = gw
        .handle(Message::request(Id::Num(2), "tools/list", None))
        .await
        .unwrap()
        .unwrap();
    let names: Vec<String> = list.result.unwrap()["tools"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|t| t["name"].as_str().map(String::from))
        .collect();
    assert!(names.contains(&"echo".to_string()));
    assert!(!names.contains(&"delete_repo".to_string()));

    // Allowed call is forwarded over HTTP and returned.
    let allow = gw
        .handle(Message::request(
            Id::Num(3),
            "tools/call",
            Some(serde_json::json!({ "name": "echo", "arguments": {} })),
        ))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(allow.id, Some(Id::Num(3)));
    assert_eq!(allow.result.unwrap()["isError"], serde_json::json!(false));

    // Denied call is blocked before the HTTP round-trip.
    let deny = gw
        .handle(Message::request(
            Id::Num(4),
            "tools/call",
            Some(serde_json::json!({ "name": "delete_repo", "arguments": {} })),
        ))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(deny.result.unwrap()["isError"], serde_json::json!(true));

    drop(gw);
    let report = verify(&audit).unwrap();
    assert!(report.ok());
    assert_eq!(report.records, 2); // one allow + one deny
}
