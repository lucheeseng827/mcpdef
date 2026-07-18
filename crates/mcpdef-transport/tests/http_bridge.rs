// SPDX-License-Identifier: Apache-2.0
//! HTTP transport integration tests (ROADMAP Phase 1 Streamable HTTP + Phase 1.5
//! legacy HTTP+SSE bridge). A small axum app mocks both wire formats so we can
//! exercise `HttpClient` end-to-end: modern request/response, the legacy
//! GET-SSE → `endpoint` → POST flow, the dual-transport probe that falls back to
//! legacy on a 405, and `Last-Event-ID` resumption across a dropped stream.

use axum::extract::State;
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::sse::{Event, Sse};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
use futures_util::{stream, Stream, StreamExt};
use mcpdef_core::{Id, Message};
use mcpdef_transport::{HttpClient, Transport};
use std::convert::Infallible;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio_stream::wrappers::BroadcastStream;

#[derive(Clone)]
struct AppState {
    tx: tokio::sync::broadcast::Sender<String>,
    seq: Arc<AtomicU64>,
}

/// The MCP server logic shared by both wire formats: echoes the request id and
/// exposes `echo` + `delete_repo` tools (matching the stdio mock).
fn respond(req: &Message) -> Option<Message> {
    let id = req.id.clone();
    match req.method() {
        Some("initialize") => Some(Message::result(
            id?,
            serde_json::json!({
                "protocolVersion": "2025-11-25",
                "capabilities": { "tools": {} },
                "serverInfo": { "name": "mock", "version": "0" }
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
                serde_json::json!({
                    "content": [{ "type": "text", "text": name }],
                    "isError": false
                }),
            ))
        }
        Some("ping") => Some(Message::result(id?, serde_json::json!({}))),
        _ => id.map(|i| Message::error(i, -32601, "method not found")),
    }
}

fn notif(n: u64) -> String {
    format!(r#"{{"jsonrpc":"2.0","method":"notifications/message","params":{{"n":{n}}}}}"#)
}

// ── Streamable HTTP (modern): POST returns a single JSON response ──
async fn modern_mcp(body: String) -> Response {
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
                    .insert("mcp-session-id", HeaderValue::from_static("sess-123"));
            }
            r
        }
        None => StatusCode::ACCEPTED.into_response(),
    }
}

// ── Legacy HTTP+SSE: GET opens the stream and emits `endpoint`, then forwards
//    broadcast messages; POST publishes the response onto the broadcast. ──
async fn legacy_sse(
    State(st): State<AppState>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let rx = st.tx.subscribe();
    let seq = st.seq.clone();
    let endpoint =
        stream::once(async { Ok(Event::default().event("endpoint").data("/legacy/messages")) });
    let messages = BroadcastStream::new(rx).map(move |item| {
        let payload = item.unwrap_or_default();
        let id = seq.fetch_add(1, Ordering::SeqCst) + 1;
        Ok(Event::default()
            .event("message")
            .id(id.to_string())
            .data(payload))
    });
    Sse::new(endpoint.chain(messages))
}

async fn legacy_post(State(st): State<AppState>, body: String) -> StatusCode {
    if let Ok(msg) = Message::from_json_line(body.trim()) {
        if let Some(resp) = respond(&msg) {
            let _ = st.tx.send(resp.to_json_line());
        }
    }
    StatusCode::ACCEPTED
}

// ── Resumption probe: first GET emits one message then closes; the reconnect
//    (carrying Last-Event-ID) emits the next message. ──
async fn resume_sse(headers: HeaderMap) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let leid = headers
        .get("last-event-id")
        .and_then(|v| v.to_str().ok())
        .map(String::from);
    let mut evs: Vec<Result<Event, Infallible>> = vec![Ok(Event::default()
        .event("endpoint")
        .data("/resume/messages"))];
    match leid.as_deref() {
        None => evs.push(Ok(Event::default().event("message").id("1").data(notif(1)))),
        Some("1") => evs.push(Ok(Event::default().event("message").id("2").data(notif(2)))),
        _ => {}
    }
    Sse::new(stream::iter(evs))
}

fn build_app() -> Router {
    let (tx, _rx) = tokio::sync::broadcast::channel::<String>(64);
    let state = AppState {
        tx,
        seq: Arc::new(AtomicU64::new(0)),
    };
    Router::new()
        .route("/mcp", post(modern_mcp))
        .route("/legacy", get(legacy_sse))
        .route("/legacy/messages", post(legacy_post))
        .route("/resume", get(resume_sse))
        .route("/resume/messages", post(|| async { StatusCode::ACCEPTED }))
        .with_state(state)
}

async fn spawn_app() -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, build_app()).await.unwrap();
    });
    format!("http://{addr}")
}

async fn recv_msg(c: &mut HttpClient) -> Message {
    tokio::time::timeout(Duration::from_secs(5), c.recv())
        .await
        .expect("recv timed out")
        .expect("transport error")
        .expect("stream closed unexpectedly")
}

fn init() -> Message {
    Message::request(
        Id::Num(1),
        "initialize",
        Some(serde_json::json!({ "clientInfo": { "name": "t" } })),
    )
}

#[tokio::test]
async fn streamable_http_request_response() {
    let base = spawn_app().await;
    let mut c = HttpClient::streamable(format!("{base}/mcp")).unwrap();

    c.send(init()).await.unwrap();
    let resp = recv_msg(&mut c).await;
    assert!(resp.is_response());
    assert_eq!(resp.result.unwrap()["serverInfo"]["name"], "mock");

    c.send(Message::notification("notifications/initialized", None))
        .await
        .unwrap();
    c.send(Message::request(
        Id::Num(2),
        "tools/call",
        Some(serde_json::json!({ "name": "echo", "arguments": { "x": 1 } })),
    ))
    .await
    .unwrap();
    let r = recv_msg(&mut c).await;
    assert_eq!(r.id, Some(Id::Num(2)));
    assert_eq!(r.result.unwrap()["isError"], serde_json::json!(false));
}

#[tokio::test]
async fn legacy_sse_bridge_request_response() {
    let base = spawn_app().await;
    let mut c = HttpClient::legacy_sse(format!("{base}/legacy")).unwrap();

    // send() connects the SSE stream, reads `endpoint`, and POSTs the request;
    // the response arrives back over the held-open SSE stream.
    c.send(init()).await.unwrap();
    let resp = recv_msg(&mut c).await;
    assert!(resp.is_response());
    assert_eq!(resp.result.unwrap()["serverInfo"]["name"], "mock");
}

#[tokio::test]
async fn streamable_probe_falls_back_to_legacy() {
    let base = spawn_app().await;
    // Point the *streamable* client at the legacy endpoint: the POST probe gets a
    // 405, so it must fall back to the GET-SSE legacy bridge automatically.
    let mut c = HttpClient::streamable(format!("{base}/legacy")).unwrap();

    c.send(init()).await.unwrap();
    let resp = recv_msg(&mut c).await;
    assert!(
        resp.is_response(),
        "fallback should deliver the response via the legacy SSE stream"
    );
    assert_eq!(resp.result.unwrap()["serverInfo"]["name"], "mock");
}

#[tokio::test]
async fn legacy_sse_resumes_with_last_event_id() {
    let base = spawn_app().await;
    let mut c = HttpClient::legacy_sse(format!("{base}/resume")).unwrap();

    // First send connects (endpoint + message id:1, then the server closes).
    c.send(init()).await.unwrap();
    let m1 = recv_msg(&mut c).await;
    assert_eq!(m1.params.unwrap()["n"], serde_json::json!(1));

    // The reader reconnects with Last-Event-ID:1; the server replays message id:2.
    let m2 = recv_msg(&mut c).await;
    assert_eq!(m2.params.unwrap()["n"], serde_json::json!(2));

    // After id:2 the server replays nothing on further reconnects; the reader
    // exhausts its bounded retries and surfaces a terminal signal rather than
    // blocking recv() forever.
    let terminal = tokio::time::timeout(Duration::from_secs(5), c.recv())
        .await
        .expect("third recv timed out — give-up must not hang");
    assert!(
        matches!(terminal, Err(_) | Ok(None)),
        "expected a terminal close after retries, got {terminal:?}"
    );
}

// ── SSRF / egress guard (end-to-end through HttpClient::send) ────────────────

use mcpdef_transport::{EgressPolicy, TransportError};

#[tokio::test]
async fn ssrf_blocks_cloud_metadata_upstream() {
    // The single highest-value SSRF target is always blocked, before any connect,
    // even under the permissive default policy.
    let mut c = HttpClient::streamable("http://169.254.169.254/mcp").unwrap();
    let err = c.send(init()).await.unwrap_err();
    assert!(
        matches!(err, TransportError::Egress(_)),
        "metadata upstream must be blocked, got {err:?}"
    );
}

#[tokio::test]
async fn ssrf_blocks_plaintext_public_upstream() {
    // A public IP over plain HTTP leaks creds — refused by default.
    let mut c = HttpClient::streamable("http://8.8.8.8/mcp").unwrap();
    let err = c.send(init()).await.unwrap_err();
    assert!(matches!(err, TransportError::Egress(_)), "got {err:?}");
}

#[tokio::test]
async fn ssrf_hardened_policy_blocks_loopback_upstream() {
    // A real loopback mock is up, but the hardened policy refuses private/loopback
    // destinations — so the guard, not the server, terminates the call.
    let base = spawn_app().await;
    let mut c = HttpClient::streamable(format!("{base}/mcp"))
        .unwrap()
        .with_egress(EgressPolicy::hardened());
    let err = c.send(init()).await.unwrap_err();
    assert!(
        matches!(err, TransportError::Egress(_)),
        "hardened policy must block loopback, got {err:?}"
    );
}

#[tokio::test]
async fn default_policy_allows_loopback_upstream() {
    // The default policy permits loopback so MCPdef can front local MCP servers —
    // this is the same flow the other tests rely on, asserted explicitly.
    let base = spawn_app().await;
    let mut c = HttpClient::streamable(format!("{base}/mcp")).unwrap();
    assert!(c.send(init()).await.is_ok());
}
